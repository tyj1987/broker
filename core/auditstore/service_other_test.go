//go:build !linux

package auditstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tyj1987/broker/core/auditanchor"
)

func TestListenServiceSocketFailsClosedOffLinux(t *testing.T) {
	if _, err := listenServiceSocket(DefaultSocketPath); !errors.Is(err, ErrServiceSocketInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestServeRuntimeFailsClosedOffLinux(t *testing.T) {
	if err := ServeRuntime(context.Background(), nil, 1001, 1002, DefaultSocketPath); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatalf("nil runtime error = %v", err)
	}
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{StreamID: config.StreamID, Repository: &fakeRepository{}, Verifier: &auditanchor.EnvelopeVerifier{}}
	if err = ServeRuntime(context.Background(), runtime, 1001, 1002, DefaultSocketPath); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatalf("platform error = %v", err)
	}
}
