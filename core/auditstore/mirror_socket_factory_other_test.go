//go:build !linux

package auditstore

import (
	"context"
	"errors"
	"testing"
)

func TestAuthenticatedMirrorFactoryFailsClosedOutsideLinux(t *testing.T) {
	binding := mirrorFactoryBinding(t)
	client, err := (AuthenticatedMirrorClientFactory{WorkerUID: 1002}).NewMirror(context.Background(), binding)
	if client != nil || !errors.Is(err, ErrServiceIdentityUnavailable) {
		t.Fatalf("NewMirror() = %#v, %v", client, err)
	}
}
