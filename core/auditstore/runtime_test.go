package auditstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tyj1987/broker/core/auditanchor"
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
type runtimeCOSClient struct{ *runtimeCloudClient }

func (*runtimeOSSClient) CreateObject(context.Context, auditanchor.OSSCreateObjectRequest) (auditanchor.ObjectCreateResult, error) {
	return auditanchor.ObjectCreateResult{Status: "created"}, nil
}

func (*runtimeCOSClient) CreateObject(context.Context, auditanchor.COSCreateObjectRequest) (auditanchor.ObjectCreateResult, error) {
	return auditanchor.ObjectCreateResult{Status: "created"}, nil
}

type recordingCloudFactory struct {
	ossBinding ProviderBinding
	cosBinding ProviderBinding
	oss        OSSCloudClient
	cos        COSCloudClient
	ossErr     error
	cosErr     error
}

func (factory *recordingCloudFactory) NewOSS(_ context.Context, binding ProviderBinding) (OSSCloudClient, error) {
	factory.ossBinding = binding
	return factory.oss, factory.ossErr
}

func (factory *recordingCloudFactory) NewCOS(_ context.Context, binding ProviderBinding) (COSCloudClient, error) {
	factory.cosBinding = binding
	return factory.cos, factory.cosErr
}

func TestNewRuntimeBuildsBoundedDualCloudRepository(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	cloud := &runtimeCloudClient{}
	factory := &recordingCloudFactory{
		oss: &runtimeOSSClient{cloud}, cos: &runtimeCOSClient{cloud},
	}
	runtime, err := NewRuntime(context.Background(), config, factory)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if runtime.Repository == nil || runtime.Verifier == nil ||
		runtime.StreamID != config.StreamID || factory.ossBinding != config.OSS || factory.cosBinding != config.COS {
		t.Fatalf("runtime = %#v, factory = %#v", runtime, factory)
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
		factory CloudClientFactory
		err     error
	}{
		"nil context":    {nil, config, &recordingCloudFactory{}, ErrServiceRuntimeInvalid},
		"nil factory":    {context.Background(), config, nil, ErrServiceRuntimeInvalid},
		"invalid config": {context.Background(), ServiceConfig{}, &recordingCloudFactory{}, ErrServiceConfigInvalid},
		"unavailable":    {context.Background(), config, UnavailableCloudClientFactory{}, ErrServiceIdentityUnavailable},
		"oss error":      {context.Background(), config, &recordingCloudFactory{ossErr: errors.New("provider detail")}, ErrServiceIdentityUnavailable},
		"oss nil":        {context.Background(), config, &recordingCloudFactory{}, ErrServiceIdentityUnavailable},
		"cos error":      {context.Background(), config, &recordingCloudFactory{oss: &runtimeOSSClient{&runtimeCloudClient{}}, cosErr: errors.New("provider detail")}, ErrServiceIdentityUnavailable},
		"cos nil":        {context.Background(), config, &recordingCloudFactory{oss: &runtimeOSSClient{&runtimeCloudClient{}}}, ErrServiceIdentityUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRuntime(test.ctx, test.config, test.factory); !errors.Is(err, test.err) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewRuntime(canceled, config, &recordingCloudFactory{}); !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatalf("canceled error = %v", err)
	}
	unavailable := UnavailableCloudClientFactory{}
	if client, err := unavailable.NewCOS(context.Background(), config.COS); client != nil || !errors.Is(err, ErrServiceIdentityUnavailable) {
		t.Fatalf("unavailable COS factory = %#v, %v", client, err)
	}
}
