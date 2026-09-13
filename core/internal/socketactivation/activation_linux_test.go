//go:build linux

package socketactivation

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestListenerAcceptsOneExactSystemdSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	command := exec.Command(os.Args[0], "-test.run=TestActivationHelper")
	command.ExtraFiles = []*os.File{file}
	command.Env = append(os.Environ(), "BROKER_ACTIVATION_HELPER=1", "BROKER_EXPECTED_PATH="+path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v: %s", err, output)
	}
	if strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("helper output: %q", output)
	}
}

func TestActivationHelper(t *testing.T) {
	if os.Getenv("BROKER_ACTIVATION_HELPER") != "1" {
		return
	}
	_ = os.Setenv("LISTEN_PID", fmt.Sprint(os.Getpid()))
	_ = os.Setenv("LISTEN_FDS", "1")
	_ = os.Setenv("LISTEN_FDNAMES", "github-signer")
	listener, err := Listener("github-signer", os.Getenv("BROKER_EXPECTED_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" || os.Getenv("LISTEN_FDNAMES") != "" {
		t.Fatal("activation environment retained")
	}
	fmt.Print("ok")
	os.Exit(0)
}

func TestListenerRejectsInvalidEnvironmentAndClearsIt(t *testing.T) {
	t.Setenv("LISTEN_PID", fmt.Sprint(os.Getpid()))
	t.Setenv("LISTEN_FDS", "2")
	t.Setenv("LISTEN_FDNAMES", "github-signer")
	if listener, err := Listener("github-signer", "/run/example.sock"); err == nil || listener != nil {
		t.Fatal("accepted multiple sockets")
	}
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" || os.Getenv("LISTEN_FDNAMES") != "" {
		t.Fatal("activation environment retained")
	}
}
