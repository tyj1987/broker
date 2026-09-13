//go:build linux

package auditstore

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
	uid := uint32(os.Getuid())
	authorizer, err := NewOSPeerAuthorizer(uid, uid+1)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptError := listener.Accept()
		if acceptError == nil {
			accepted <- connection
		}
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	serverConnection := <-accepted
	defer serverConnection.Close()
	role, err := authorizer.AuthorizePeer(context.Background(), serverConnection)
	if err != nil || role != ExporterRole {
		t.Fatalf("role = %q, error = %v", role, err)
	}
	if _, err := authorizer.AuthorizePeer(context.Background(), &memoryConn{}); err == nil {
		t.Fatal("non-unix connection was authorized")
	}
}

func TestLinuxPeerAuthorizerRejectsUnsafeIdentities(t *testing.T) {
	for _, pair := range [][2]uint32{{0, 1}, {1, 0}, {1, 1}} {
		if authorizer, err := NewOSPeerAuthorizer(pair[0], pair[1]); err == nil || authorizer != nil {
			t.Fatalf("unsafe identities were accepted: %#v", pair)
		}
	}
}
