//go:build linux

package socketactivation

import (
	"errors"
	"net"
	"os"
	"strconv"
)

var ErrInvalid = errors.New("socket activation is invalid")

const firstActivationDescriptor = uintptr(3)

// Listener accepts exactly one named systemd socket. Activation variables are
// always removed before returning so they cannot be inherited by child code.
func Listener(expectedName, expectedPath string) (net.Listener, error) {
	listenPID := os.Getenv("LISTEN_PID")
	listenFDs := os.Getenv("LISTEN_FDS")
	listenNames := os.Getenv("LISTEN_FDNAMES")
	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")
	pid, err := strconv.Atoi(listenPID)
	if err != nil || pid != os.Getpid() || listenFDs != "1" || listenNames != expectedName ||
		expectedName == "" || expectedPath == "" {
		return nil, ErrInvalid
	}
	file := os.NewFile(firstActivationDescriptor, expectedName)
	if file == nil {
		return nil, ErrInvalid
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, ErrInvalid
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok || unixListener.Addr() == nil || unixListener.Addr().Network() != "unix" ||
		unixListener.Addr().String() != expectedPath {
		_ = listener.Close()
		return nil, ErrInvalid
	}
	return listener, nil
}
