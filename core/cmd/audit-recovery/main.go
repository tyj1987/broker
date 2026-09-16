// The recovery identity verifies independently provisioned checkpoints. It never
// mints a checkpoint, signs an anchor, publishes to the store, or receives keys.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const recoveryConfig = "/etc/secret-broker/audit/recovery.json"
const nodeRuntime = "/opt/secret-broker/runtime/node/bin/node"
const checkDeadline = 65 * time.Second
const checkInterval = 30 * time.Second
const maxOutput = 1024

var errUnavailable = errors.New("recovery unavailable")

type report struct {
	Status   string `json:"status"`
	Anchors  int64  `json:"anchors_verified"`
	Sequence int64  `json:"sequence"`
	Match    bool   `json:"checkpoint_match"`
}

type dependencies struct {
	prepare func() (string, error)
	check   func(context.Context, string) ([]byte, error)
	notify  func(string) error
	wait    func(context.Context) error
	output  io.Writer
}

// Require the exact canonical success record. Unknown, duplicate, missing or
// additional fields and extra records cannot masquerade as a successful check.
func parseReport(raw []byte) (report, error) {
	var result report
	if len(raw) == 0 || len(raw) > maxOutput || json.Unmarshal(raw, &result) != nil ||
		result.Status != "checkpoint_verified" || !result.Match || result.Sequence < 1 ||
		result.Sequence > 1000000 || result.Anchors != result.Sequence {
		return report{}, errUnavailable
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return report{}, errUnavailable
	}
	return result, nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > maxOutput-b.buffer.Len() {
		b.overflow = true
		return 0, errUnavailable
	}
	return b.buffer.Write(p)
}

func execute(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	if ctx == nil || command == nil || ctx.Err() != nil {
		return nil, errUnavailable
	}
	var out boundedOutput
	command.Stdout = &out
	command.Stderr = io.Discard // Never reflect child exceptions, paths or input.
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil || out.overflow || ctx.Err() != nil {
		return nil, errUnavailable
	}
	return out.buffer.Bytes(), nil
}

func nodeCommand(ctx context.Context, script string) *exec.Cmd {
	command := exec.CommandContext(ctx, nodeRuntime, "--jitless", "--disable-proto=throw", "--no-addons",
		script, "--config", recoveryConfig)
	command.Dir = filepath.Dir(filepath.Dir(script))
	// Do not inherit NODE_OPTIONS, NODE_PATH, credentials, proxies or a shell.
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	return command
}

func notifySocket(address, message string) error {
	if len(address) < 2 || len(address) > 107 || strings.ContainsRune(address, 0) ||
		(address[0] != '/' && address[0] != '@') {
		return errUnavailable
	}
	connection, err := net.DialTimeout("unixgram", address, time.Second)
	if err != nil {
		return errUnavailable
	}
	defer connection.Close()
	if connection.SetWriteDeadline(time.Now().Add(time.Second)) != nil {
		return errUnavailable
	}
	n, err := connection.Write([]byte(message))
	if err != nil || n != len(message) {
		return errUnavailable
	}
	return nil
}

func waitInterval(ctx context.Context) error { return waitDuration(ctx, checkInterval) }

func waitDuration(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func run(ctx context.Context, args []string, d dependencies) (int, string) {
	if len(args) != 2 || args[0] != "--config" || args[1] != recoveryConfig {
		return 64, "usage_invalid"
	}
	if ctx == nil || d.prepare == nil || d.check == nil || d.notify == nil || d.wait == nil || d.output == nil {
		return 70, "runtime_invalid"
	}
	ready := false
	var lastSequence int64 // Process-local only; external durable state remains authoritative.
	for ctx.Err() == nil {
		// Revalidate immutable executable boundaries before every new child.
		script, err := d.prepare()
		if err != nil {
			return 78, "identity_or_release_invalid"
		}
		checkCtx, cancel := context.WithTimeout(ctx, checkDeadline)
		raw, err := d.check(checkCtx, script)
		expired := checkCtx.Err() != nil
		cancel()
		if ctx.Err() != nil {
			return 0, ""
		}
		if err != nil || expired {
			return 69, "check_failed"
		}
		value, err := parseReport(raw)
		if err != nil {
			return 70, "response_invalid"
		}
		if value.Sequence < lastSequence {
			return 69, "sequence_regressed"
		}
		line, _ := json.Marshal(value)
		line = append(line, '\n')
		if n, err := d.output.Write(line); err != nil || n != len(line) {
			return 70, "output_failed"
		}
		if ctx.Err() != nil {
			return 0, ""
		}
		message := "WATCHDOG=1\nSTATUS=Independent recovery checkpoint verified"
		if !ready {
			message = "READY=1\n" + message
		}
		if err := d.notify(message); err != nil {
			return 70, "notification_failed"
		}
		lastSequence = value.Sequence
		ready = true
		if err := d.wait(ctx); err != nil {
			if ctx.Err() != nil {
				return 0, ""
			}
			return 70, "interval_failed"
		}
	}
	return 0, ""
}

func defaultDependencies() dependencies {
	address := os.Getenv("NOTIFY_SOCKET")
	return dependencies{
		prepare: prepareRecovery,
		check: func(ctx context.Context, script string) ([]byte, error) {
			return execute(ctx, nodeCommand(ctx, script))
		},
		notify: func(message string) error { return notifySocket(address, message) },
		wait:   waitInterval, output: os.Stdout,
	}
}

func runMain(args []string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, reason := run(ctx, args, defaultDependencies())
	if reason != "" {
		_, _ = fmt.Fprintf(stderr, "audit_recovery_failed=%s\n", reason)
	}
	return code
}

func main() { os.Exit(runMain(os.Args[1:], os.Stderr)) }
