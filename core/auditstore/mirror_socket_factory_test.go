package auditstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tyj1987/broker/core/auditmirror"
)

func mirrorFactoryBinding(t *testing.T) auditmirror.Binding {
	t.Helper()
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := mirrorBinding(config)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestAuthenticatedMirrorFactoryRejectsInvalidInvocation(t *testing.T) {
	binding := mirrorFactoryBinding(t)
	for _, test := range []struct {
		ctx     context.Context
		factory AuthenticatedMirrorClientFactory
	}{
		{nil, AuthenticatedMirrorClientFactory{WorkerUID: 1002}},
		{context.Background(), AuthenticatedMirrorClientFactory{}},
	} {
		client, err := test.factory.NewMirror(test.ctx, binding)
		if client != nil || !errors.Is(err, ErrServiceIdentityUnavailable) {
			t.Fatalf("NewMirror() = %#v, %v", client, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := (AuthenticatedMirrorClientFactory{WorkerUID: 1002}).NewMirror(cancelled, binding)
	if client != nil || !errors.Is(err, ErrServiceIdentityUnavailable) {
		t.Fatalf("cancelled NewMirror() = %#v, %v", client, err)
	}
}
