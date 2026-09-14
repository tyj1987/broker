package auditstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
)

type runtimeCloudClient struct{}

func (*runtimeCloudClient) InspectBucketWORM(context.Context, string) (auditanchor.OSSBucketWORMState, error) {
	return auditanchor.OSSBucketWORMState{Status: "Locked", RetentionDays: 365, VersioningState: "Disabled"}, nil
}

func (*runtimeCloudClient) InspectObjectLock(context.Context, string) (auditanchor.COSObjectLockState, error) {
	return auditanchor.COSObjectLockState{Enabled: true, VersioningState: "Enabled"}, nil
}

func (*runtimeCloudClient) ReadObject(context.Context, string, string) ([]byte, error) {
	return nil, auditanchor.ErrImmutableObjectNotFound
}

func (*runtimeCloudClient) ReadObjectRetention(context.Context, string, string) (auditanchor.COSObjectRetention, error) {
	return auditanchor.COSObjectRetention{}, auditanchor.ErrImmutableObjectNotFound
}

func (*runtimeCloudClient) ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error) {
	return auditanchor.ObjectKeyPage{}, nil
}

type runtimeOSSClient struct{ *runtimeCloudClient }

func (*runtimeOSSClient) CreateObject(context.Context, auditanchor.OSSCreateObjectRequest) (auditanchor.ObjectCreateResult, error) {
	return auditanchor.ObjectCreateResult{Status: "created"}, nil
}

type runtimeMirrorClient struct{ binding auditmirror.Binding }

func (client *runtimeMirrorClient) Inspect(_ context.Context, request auditmirror.InspectRequest) (auditmirror.LockState, error) {
	if !request.ValidFor(client.binding) {
		return auditmirror.LockState{}, auditmirror.ErrContractRejected
	}
	return auditmirror.LockState{
		Compliance: true, Versioning: true, RetentionDays: auditmirror.RetentionDays,
		TrustGeneration: client.binding.TrustGeneration(),
	}, nil
}

func (*runtimeMirrorClient) Create(context.Context, auditmirror.CreateRequest) (auditmirror.CreateResult, error) {
	return auditmirror.CreateResult{Status: "created"}, nil
}

func (*runtimeMirrorClient) Read(context.Context, auditmirror.ReadRequest) (auditmirror.ReadResult, error) {
	return auditmirror.ReadResult{}, auditmirror.ErrNotFound
}

func (*runtimeMirrorClient) List(context.Context, auditmirror.ListRequest) (auditmirror.ListResult, error) {
	return auditmirror.ListResult{}, nil
}

func (*runtimeMirrorClient) Retention(context.Context, auditmirror.ReadRequest) (auditmirror.RetentionResult, error) {
	return auditmirror.RetentionResult{}, auditmirror.ErrNotFound
}

type recordingPrimaryFactory struct {
	ossBinding ProviderBinding
	oss        OSSCloudClient
	ossErr     error
}

func (factory *recordingPrimaryFactory) NewOSS(_ context.Context, binding ProviderBinding) (OSSCloudClient, error) {
	factory.ossBinding = binding
	return factory.oss, factory.ossErr
}

type recordingMirrorFactory struct {
	binding auditmirror.Binding
	client  auditmirror.Client
	err     error
	onCall  func()
}

func (factory *recordingMirrorFactory) NewMirror(_ context.Context, binding auditmirror.Binding) (auditmirror.Client, error) {
	factory.binding = binding
	if client, ok := factory.client.(*runtimeMirrorClient); ok {
		client.binding = binding
	}
	if factory.onCall != nil {
		factory.onCall()
	}
	return factory.client, factory.err
}

func TestNewRuntimeBuildsBoundedDualCloudRepository(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	cloud := &runtimeCloudClient{}
	primary := &recordingPrimaryFactory{oss: &runtimeOSSClient{cloud}}
	mirror := &recordingMirrorFactory{client: &runtimeMirrorClient{}}
	runtime, err := NewRuntime(context.Background(), config, primary, mirror)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if runtime.Repository == nil || runtime.Verifier == nil ||
		runtime.StreamID != config.StreamID || primary.ossBinding != config.OSS ||
		mirror.binding.StreamID() != config.StreamID || mirror.binding.ProfileID() != config.COS.ProviderProfileID {
		t.Fatalf("runtime = %#v, primary = %#v, mirror = %#v", runtime, primary, mirror)
	}
	config.TrustedKeys[0].PublicKey.X.SetInt64(0)
	health, err := runtime.Repository.Health(context.Background())
	if err != nil || health.Status != "ready" || health.CommonSequence != 0 {
		t.Fatalf("Health() = %#v, %v", health, err)
	}
}

func TestNewRuntimeFailsClosedWithoutExplicitIdentityFactory(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		ctx     context.Context
		config  ServiceConfig
		primary PrimaryClientFactory
		mirror  MirrorClientFactory
		err     error
	}{
		"nil context":         {nil, config, &recordingPrimaryFactory{}, &recordingMirrorFactory{}, ErrServiceRuntimeInvalid},
		"nil primary":         {context.Background(), config, nil, &recordingMirrorFactory{}, ErrServiceRuntimeInvalid},
		"nil mirror":          {context.Background(), config, &recordingPrimaryFactory{}, nil, ErrServiceRuntimeInvalid},
		"invalid config":      {context.Background(), ServiceConfig{}, &recordingPrimaryFactory{}, &recordingMirrorFactory{}, ErrServiceConfigInvalid},
		"unavailable primary": {context.Background(), config, UnavailablePrimaryClientFactory{}, &recordingMirrorFactory{}, ErrServiceIdentityUnavailable},
		"oss error":           {context.Background(), config, &recordingPrimaryFactory{ossErr: errors.New("provider detail")}, &recordingMirrorFactory{}, ErrServiceIdentityUnavailable},
		"oss nil":             {context.Background(), config, &recordingPrimaryFactory{}, &recordingMirrorFactory{}, ErrServiceIdentityUnavailable},
		"mirror unavailable":  {context.Background(), config, &recordingPrimaryFactory{oss: &runtimeOSSClient{&runtimeCloudClient{}}}, UnavailableMirrorClientFactory{}, ErrServiceIdentityUnavailable},
		"mirror error":        {context.Background(), config, &recordingPrimaryFactory{oss: &runtimeOSSClient{&runtimeCloudClient{}}}, &recordingMirrorFactory{err: errors.New("provider detail")}, ErrServiceIdentityUnavailable},
		"mirror nil":          {context.Background(), config, &recordingPrimaryFactory{oss: &runtimeOSSClient{&runtimeCloudClient{}}}, &recordingMirrorFactory{}, ErrServiceIdentityUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRuntime(test.ctx, test.config, test.primary, test.mirror); !errors.Is(err, test.err) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewRuntime(canceled, config, &recordingPrimaryFactory{}, &recordingMirrorFactory{}); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatalf("canceled error = %v", err)
	}
	unavailable := UnavailableMirrorClientFactory{}
	binding, err := mirrorBinding(config)
	if err != nil {
		t.Fatal(err)
	}
	if client, err := unavailable.NewMirror(context.Background(), binding); client != nil || !errors.Is(err, ErrServiceIdentityUnavailable) {
		t.Fatalf("unavailable COS factory = %#v, %v", client, err)
	}
	lateContext, lateCancel := context.WithCancel(context.Background())
	lateMirror := &recordingMirrorFactory{
		client: &runtimeMirrorClient{},
		onCall: lateCancel,
	}
	if _, err := NewRuntime(
		lateContext, config,
		&recordingPrimaryFactory{oss: &runtimeOSSClient{&runtimeCloudClient{}}},
		lateMirror,
	); !errors.Is(err, ErrServiceIdentityUnavailable) {
		t.Fatalf("late mirror factory success error = %v", err)
	}
}
