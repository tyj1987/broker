//go:build linux

package auditstore

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
)

func TestServeRuntimeUsesProtectedUnixSocketAndKernelPeerIdentity(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 || uid == ^uint32(0) {
		t.Skip("test requires a non-root Linux user")
	}
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auditanchor.NewEnvelopeVerifier(config.StreamID, trustedSigningKeys(config))
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{health: Health{
		Status: "ready", LockContract: "verified", MirrorState: "in_sync",
		CommonSequence: 0, ReasonCode: "ok",
	}}
	runtime := &Runtime{StreamID: config.StreamID, Repository: repository, Verifier: verifier}

	directory := t.TempDir()
	if err = os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "store.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeRuntime(ctx, runtime, uid, uid+1, socketPath) }()

	var health Health
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		health, err = QueryHealth(context.Background(), socketPath, config.StreamID)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || health.Status != "ready" || health.CommonSequence != 0 {
		cancel()
		t.Fatalf("QueryHealth() = %#v, %v", health, err)
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode().Perm() != 0o660 || info.Mode()&os.ModeSocket == 0 {
		cancel()
		t.Fatalf("socket info = %#v, %v", info, err)
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop")
	}
	if _, err = os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket was not removed: %v", err)
	}
}

func TestListenServiceSocketRejectsSecondActiveInstance(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "store.sock")
	first, err := listenServiceSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err = listenServiceSocket(path); err != ErrServiceSocketInvalid {
		t.Fatalf("second listener error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("first listener path changed: %#v, %v", info, err)
	}
}

func TestListenServiceSocketRejectsActiveSocketWithoutManagedLock(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "store.sock")
	raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err = listenServiceSocket(path); err != ErrServiceSocketInvalid {
		t.Fatalf("active socket error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("active socket path changed: %#v, %v", info, err)
	}
}

func TestManagedUnixListenerDoesNotDeleteReplacementPath(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "store.sock")
	moved := filepath.Join(directory, "moved.sock")
	listener, err := listenServiceSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, moved); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "replacement" {
		t.Fatalf("replacement = %q, %v", value, err)
	}
}

func TestListenServiceSocketReclaimsOnlyStaleSocket(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "store.sock")
	raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	raw.SetUnlinkOnClose(false)
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := listenServiceSocket(path)
	if err != nil {
		t.Fatalf("stale socket was not reclaimed: %v", err)
	}
	defer listener.Close()
}

func TestListenServiceSocketRejectsUnsafeParentAndExistingPath(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := listenServiceSocket(filepath.Join(directory, "store.sock")); err != ErrServiceSocketInvalid {
		t.Fatalf("unsafe parent error = %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "store.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenServiceSocket(path); err != ErrServiceSocketInvalid {
		t.Fatalf("existing file error = %v", err)
	}
	if _, err := listenServiceSocket(filepath.Join(directory, "other.sock")); err != ErrServiceSocketInvalid {
		t.Fatalf("wrong basename error = %v", err)
	}
}
