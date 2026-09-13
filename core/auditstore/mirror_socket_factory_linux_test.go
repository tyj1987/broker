//go:build linux

package auditstore

import (
	"context"
	"testing"
)

func TestAuthenticatedMirrorFactoryBuildsFixedPathLinuxClient(t *testing.T) {
	binding := mirrorFactoryBinding(t)
	client, err := (AuthenticatedMirrorClientFactory{WorkerUID: 1002}).NewMirror(context.Background(), binding)
	if err != nil || client == nil {
		t.Fatalf("NewMirror() = %#v, %v", client, err)
	}
}
