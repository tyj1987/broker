//go:build linux

package githubsigner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxPeerAuthorizer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires a non-root process identity")
	}
	authorizer, err := NewOSPeerAuthorizer(uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	listener, err := net.Listen("unix", filepath.Join(directory, "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	errorsChannel := make(chan error, 1)
	go func() {
		connection, acceptError := listener.Accept()
		if acceptError != nil {
			errorsChannel <- acceptError
			return
		}
		accepted <- connection
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var serverConnection net.Conn
	select {
	case serverConnection = <-accepted:
		defer serverConnection.Close()
	case err := <-errorsChannel:
		t.Fatal(err)
	}
	if err := authorizer.AuthorizePeer(context.Background(), serverConnection); err != nil {
		t.Fatal(err)
	}
	denied, err := NewOSPeerAuthorizer(uint32(os.Getuid() + 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := denied.AuthorizePeer(context.Background(), serverConnection); err == nil {
		t.Fatal("wrong uid was authorized")
	}
	if err := authorizer.AuthorizePeer(context.Background(), &memoryConn{}); err == nil {
		t.Fatal("non-unix connection was authorized")
	}
}

func TestLinuxPeerAuthorizerRejectsRootUID(t *testing.T) {
	if _, err := NewOSPeerAuthorizer(0); err == nil {
		t.Fatal("root broker uid was accepted")
	}
}
