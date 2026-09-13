//go:build linux

package auditmirror

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOSPeerAuthorizerUsesKernelUnixCredentials(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		t.Skip("test requires a non-root process identity")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "mirror.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		authorizer, createErr := NewOSPeerAuthorizer(uid)
		if createErr != nil {
			done <- createErr
			return
		}
		done <- authorizer.AuthorizePeer(context.Background(), connection)
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = <-done; err != nil {
		t.Fatal(err)
	}

	denied, _ := NewOSPeerAuthorizer(uid + 1)
	if err = denied.AuthorizePeer(context.Background(), client); err == nil {
		t.Fatal("wrong peer uid accepted")
	}
	if authorizer, err := NewOSPeerAuthorizer(0); authorizer != nil || err == nil {
		t.Fatalf("root authorizer = %#v, %v", authorizer, err)
	}
}

func TestOSDialerAuthenticatesWorkerBeforeReturningConnection(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		t.Skip("test requires a non-root process identity")
	}
	path := filepath.Join(t.TempDir(), "mirror.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		connection, _ := listener.AcceptUnix()
		accepted <- connection
	}()
	dial, err := newOSDialerForPath(uid, path)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dial(context.Background(), "unix", path)
	if err != nil || connection == nil {
		t.Fatalf("dial = %#v, %v", connection, err)
	}
	_ = connection.Close()
	serverConnection := <-accepted
	_ = serverConnection.Close()

	accepted = make(chan *net.UnixConn, 1)
	go func() {
		connection, _ := listener.AcceptUnix()
		accepted <- connection
	}()
	deniedDial, _ := newOSDialerForPath(uid+1, path)
	if connection, err = deniedDial(context.Background(), "unix", path); connection != nil || err == nil {
		t.Fatalf("wrong uid dial = %#v, %v", connection, err)
	}
	serverConnection = <-accepted
	_ = serverConnection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err = serverConnection.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("unauthenticated client wrote before rejection: %v", err)
	}
	_ = serverConnection.Close()

	if connection, err = dial(context.Background(), "tcp", path); connection != nil || err == nil {
		t.Fatalf("wrong transport dial = %#v, %v", connection, err)
	}
	if _, err = newOSDialerForPath(0, path); err == nil {
		t.Fatal("root worker uid accepted")
	}
}

func TestUnixCredentialHelperRejectsNonUnixConnection(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if credentials, err := unixPeerCredentials(left); credentials != nil || err == nil {
		t.Fatalf("credentials = %#v, %v", credentials, err)
	}
}
