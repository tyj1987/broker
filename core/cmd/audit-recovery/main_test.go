package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const success = `{"status":"checkpoint_verified","anchors_verified":3,"sequence":3,"checkpoint_match":true}`

func validDependencies(ctx context.Context, cancel context.CancelFunc) dependencies {
	return dependencies{prepare: func() (string, error) { return "fixed-script", nil },
		check:  func(context.Context, string) ([]byte, error) { return []byte(success), nil },
		notify: func(string) error { return nil }, wait: func(context.Context) error { cancel(); return ctx.Err() }, output: io.Discard}
}
func TestRunSuccessAndReread(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := validDependencies(ctx, cancel)
	count := 0
	ready := 0
	var output bytes.Buffer
	d.output = &output
	d.prepare = func() (string, error) { count++; return "script", nil }
	d.notify = func(s string) error {
		if strings.Contains(s, "READY=1") {
			ready++
		}
		if !strings.Contains(s, "WATCHDOG=1") {
			t.Fatal("no watchdog")
		}
		return nil
	}
	d.wait = func(context.Context) error {
		if count == 3 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	code, reason := run(ctx, []string{"--config", recoveryConfig}, d)
	if code != 0 || reason != "" || count != 3 || ready != 1 || strings.Count(output.String(), "checkpoint_verified") != 3 {
		t.Fatalf("bad loop: %d %s %d %d", code, reason, count, ready)
	}
}
func TestRunFailures(t *testing.T) {
	cases := []struct {
		name, reason string
		code         int
		mutate       func(*dependencies)
	}{
		{"prepare", "identity_or_release_invalid", 78, func(d *dependencies) { d.prepare = func() (string, error) { return "", errors.New("private detail") } }},
		{"check", "check_failed", 69, func(d *dependencies) {
			d.check = func(context.Context, string) ([]byte, error) { return nil, errors.New("private detail") }
		}},
		{"invalid", "response_invalid", 70, func(d *dependencies) {
			d.check = func(context.Context, string) ([]byte, error) { return []byte("private detail"), nil }
		}},
		{"output", "output_failed", 70, func(d *dependencies) { d.output = failWriter{} }},
		{"short output", "output_failed", 70, func(d *dependencies) { d.output = shortWriter{} }},
		{"notify", "notification_failed", 70, func(d *dependencies) { d.notify = func(string) error { return errors.New("private detail") } }},
		{"wait", "interval_failed", 70, func(d *dependencies) { d.wait = func(context.Context) error { return errors.New("private detail") } }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			d := validDependencies(ctx, cancel)
			tc.mutate(&d)
			code, reason := run(ctx, []string{"--config", recoveryConfig}, d)
			if code != tc.code || reason != tc.reason {
				t.Fatalf("%d %s", code, reason)
			}
		})
	}
	t.Run("failure after ready exits", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		d := validDependencies(ctx, cancel)
		calls := 0
		d.check = func(context.Context, string) ([]byte, error) {
			calls++
			if calls == 2 {
				return nil, errUnavailable
			}
			return []byte(success), nil
		}
		d.wait = func(context.Context) error { return nil }
		if code, _ := run(ctx, []string{"--config", recoveryConfig}, d); code != 69 || calls != 2 {
			t.Fatal("failure was ignored")
		}
	})
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errUnavailable }

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }
func TestRunArgumentsAndDependencies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := validDependencies(ctx, cancel)
	for _, args := range [][]string{nil, {"--config"}, {"--config", "/tmp/private"}, {"--config", recoveryConfig, "extra"}, {"--other", recoveryConfig}} {
		if code, _ := run(ctx, args, d); code != 64 {
			t.Fatal("args accepted")
		}
	}
	for i := 0; i < 6; i++ {
		copy := d
		switch i {
		case 0:
			copy.prepare = nil
		case 1:
			copy.check = nil
		case 2:
			copy.notify = nil
		case 3:
			copy.wait = nil
		case 4:
			copy.output = nil
		case 5:
			ctx = nil
		}
		if code, _ := run(ctx, []string{"--config", recoveryConfig}, copy); code != 70 {
			t.Fatal("dependency accepted")
		}
	}
}
func TestCancellationAndNoPrematureReadiness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := validDependencies(ctx, cancel)
	called := false
	d.notify = func(string) error { called = true; return nil }
	d.check = func(context.Context, string) ([]byte, error) { cancel(); return []byte(success), nil }
	if code, _ := run(ctx, []string{"--config", recoveryConfig}, d); code != 0 || called {
		t.Fatal("cancelled check became ready")
	}
	if code, _ := run(ctx, []string{"--config", recoveryConfig}, d); code != 0 {
		t.Fatal("pre-abort failure")
	}
	if waitInterval(ctx) == nil {
		t.Fatal("wait ignored cancellation")
	}
}
func TestReportStrictness(t *testing.T) {
	if _, err := parseReport([]byte(success + "\n")); err != nil {
		t.Fatal(err)
	}
	cases := []string{"", "null", "{}", strings.Repeat("x", 1025), success + success, strings.Replace(success, `"sequence":3`, `"sequence":3,"sequence":3`, 1), strings.Replace(success, `"checkpoint_verified"`, `"verified"`, 1), strings.Replace(success, `"checkpoint_match":true`, `"checkpoint_match":false`, 1), strings.Replace(success, `"anchors_verified":3`, `"anchors_verified":2`, 1), strings.ReplaceAll(success, ":3", ":0"), strings.ReplaceAll(success, ":3", ":1000001"), strings.Replace(success, `"sequence":3`, `"sequence":3.5`, 1), strings.Replace(success, `"sequence":3`, `"sequence":3,"extra":true`, 1)}
	for _, input := range cases {
		if _, err := parseReport([]byte(input)); err == nil {
			t.Fatalf("accepted %.80s", input)
		}
	}
}
func TestNodeCommandHasNoInheritedAuthority(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "--inspect")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic")
	cmd := nodeCommand(context.Background(), "/fixed/recovery-runtime/bin/check.js")
	if cmd.Path != nodeRuntime || cmd.Dir != "/fixed/recovery-runtime" {
		t.Fatal("wrong path")
	}
	b, _ := json.Marshal(cmd.Args)
	if !strings.Contains(string(b), "--jitless") || !strings.Contains(string(b), "--no-addons") || !strings.Contains(string(b), recoveryConfig) {
		t.Fatal("flags missing")
	}
	if strings.Contains(strings.Join(cmd.Env, " "), "NODE_OPTIONS") || strings.Contains(strings.Join(cmd.Env, " "), "synthetic") {
		t.Fatal("inherited env")
	}
}
func TestChildHelper(t *testing.T) {
	switch os.Getenv("RECOVERY_TEST_CHILD") {
	case "ok":
		io.WriteString(os.Stdout, success)
		os.Exit(0)
	case "fail":
		io.WriteString(os.Stderr, "synthetic-private-detail")
		os.Exit(1)
	case "large":
		io.WriteString(os.Stdout, strings.Repeat("x", 2048))
		os.Exit(0)
	case "hang":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
}
func TestRealChildBoundaries(t *testing.T) {
	for _, mode := range []string{"ok", "fail", "large", "hang"} {
		t.Run(mode, func(t *testing.T) {
			limit := 3 * time.Second
			if mode == "hang" {
				limit = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestChildHelper$")
			cmd.Env = append(os.Environ(), "RECOVERY_TEST_CHILD="+mode, "GORACE=atexit_sleep_ms=0")
			output, err := execute(ctx, cmd)
			if mode == "ok" {
				if err != nil || string(output) != success {
					t.Fatal("success lost")
				}
			} else if err == nil || output != nil {
				t.Fatal("unsafe child accepted")
			}
		})
	}
	if _, err := execute(nil, nil); err == nil {
		t.Fatal("nil command")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := execute(ctx, exec.Command("not-used")); err == nil {
		t.Fatal("aborted command")
	}
	ctx = context.Background()
	if _, err := execute(ctx, exec.Command("/nonexistent-recovery-test")); err == nil {
		t.Fatal("missing command")
	}
}
func TestNotifyUsesRealUnixDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	socket, err := net.ListenPacket("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err = notifySocket(path, "READY=1\nWATCHDOG=1"); err != nil {
		t.Fatal(err)
	}
	socket.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 100)
	n, _, err := socket.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "READY=1\nWATCHDOG=1" {
		t.Fatal("notify mismatch")
	}
	for _, bad := range []string{"", "x", "relative", "/bad\x00path", strings.Repeat("x", 108), filepath.Join(t.TempDir(), "absent")} {
		if notifySocket(bad, "READY=1") == nil {
			t.Fatal("notify accepted")
		}
	}
}

func TestDefaultWiringAndEntryFailure(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	d := defaultDependencies()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.check(ctx, "/not-read"); err == nil {
		t.Fatal("aborted default check")
	}
	if d.notify("READY=1") == nil || d.wait(ctx) == nil {
		t.Fatal("default boundary")
	}
	var stderr bytes.Buffer
	if code := runMain([]string{"--wrong", "synthetic-private-detail"}, &stderr); code != 64 || stderr.String() != "audit_recovery_failed=usage_invalid\n" {
		t.Fatal("unsafe entry failure")
	}
	if waitDuration(context.Background(), 0) != nil {
		t.Fatal("elapsed wait")
	}
}
