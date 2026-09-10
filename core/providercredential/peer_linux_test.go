//go:build linux

package providercredential

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
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { connection, _ := listener.Accept(); accepted <- connection }()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverConnection := <-accepted
	defer serverConnection.Close()
	if err := authorizer.AuthorizePeer(context.Background(), serverConnection); err != nil {
		t.Fatal(err)
	}
	denied, err := NewOSPeerAuthorizer(uint32(os.Getuid() + 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := denied.AuthorizePeer(context.Background(), serverConnection); err == nil {
		t.Fatal("wrong uid authorized")
	}
	if err := authorizer.AuthorizePeer(context.Background(), newMemoryConn("")); err == nil {
		t.Fatal("non-unix authorized")
	}
}

func TestLinuxPeerAuthorizerRejectsRootUID(t *testing.T) {
	if _, err := NewOSPeerAuthorizer(0); err == nil {
		t.Fatal("root uid accepted")
	}
}
