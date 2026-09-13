package auditmirrorworker

import (
	"context"
	"errors"
	"testing"
)

type recordingFactory struct {
	client  COSClient
	err     error
	binding COSProviderBinding
	cancel  context.CancelFunc
}

func (factory *recordingFactory) NewCOS(_ context.Context, binding COSProviderBinding) (COSClient, error) {
	factory.binding = binding
	if factory.cancel != nil {
		factory.cancel()
	}
	return factory.client, factory.err
}

func TestRuntimePassesOnlyClonedProviderBinding(t *testing.T) {
	_, fake, privateKey, body := workerHarness(t)
	config := workerConfig(privateKey)
	factory := &recordingFactory{client: fake}
	runtime, err := NewRuntime(context.Background(), config, factory)
	if err != nil || runtime == nil || runtime.Binding().StreamID() != config.StreamID {
		t.Fatalf("runtime = %#v, %v", runtime, err)
	}
	if factory.binding != (COSProviderBinding{Bucket: config.Bucket, Region: config.Region, ProviderProfileID: config.ProfileID}) {
		t.Fatalf("factory binding = %#v", factory.binding)
	}
	config.TrustedKeys["worker-key"].PublicKey.X.SetInt64(1)
	metadata, _, verifyErr := runtime.verifier.Verify(body)
	if verifyErr != nil || metadata.Sequence != 1 {
		t.Fatalf("runtime retained mutable caller configuration: %#v, %v", metadata, verifyErr)
	}
}

func TestRuntimeFailsClosedOnConfigFactoryAndCancellation(t *testing.T) {
	_, fake, privateKey, _ := workerHarness(t)
	valid := workerConfig(privateKey)
	if runtime, err := NewRuntime(context.Background(), Config{}, &recordingFactory{client: fake}); runtime != nil || !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("invalid config = %#v, %v", runtime, err)
	}
	if runtime, err := NewRuntime(context.Background(), valid, nil); runtime != nil || !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("nil factory = %#v, %v", runtime, err)
	}
	if runtime, err := NewRuntime(context.Background(), valid, &recordingFactory{err: errors.New("provider detail")}); runtime != nil || !errors.Is(err, ErrIdentityUnavailable) || err.Error() == "provider detail" {
		t.Fatalf("factory error = %#v, %v", runtime, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if runtime, err := NewRuntime(canceled, valid, &recordingFactory{client: fake}); runtime != nil || !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("early cancellation = %#v, %v", runtime, err)
	}
	late, cancelLate := context.WithCancel(context.Background())
	if runtime, err := NewRuntime(late, valid, &recordingFactory{client: fake, cancel: cancelLate}); runtime != nil || !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("late cancellation = %#v, %v", runtime, err)
	}
	if client, err := (UnavailableCOSClientFactory{}).NewCOS(context.Background(), COSProviderBinding{}); client != nil || !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("unavailable factory = %#v, %v", client, err)
	}
}
