package auditcos

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirrorworker"
	"github.com/tyj1987/broker/core/tencentcredential"
)

type factoryCredentialProvider struct {
	credential tencentcredential.TemporaryCredential
	err        error
	calls      int
}

func (provider *factoryCredentialProvider) Credential(context.Context) (tencentcredential.TemporaryCredential, error) {
	provider.calls++
	return provider.credential, provider.err
}

type factoryCOSClient struct{}

func (*factoryCOSClient) InspectObjectLock(context.Context, string) (auditanchor.COSObjectLockState, error) {
	return auditanchor.COSObjectLockState{}, nil
}
func (*factoryCOSClient) CreateVersionedObject(context.Context, auditanchor.COSCreateObjectRequest) (auditmirrorworker.COSCreateResult, error) {
	return auditmirrorworker.COSCreateResult{}, nil
}
func (*factoryCOSClient) ResolveObjectVersion(context.Context, string, string) (string, error) {
	return "", nil
}
func (*factoryCOSClient) ReadObjectVersion(context.Context, string, string, string) ([]byte, error) {
	return nil, nil
}
func (*factoryCOSClient) ReadObjectRetentionVersion(context.Context, string, string, string) (auditanchor.COSObjectRetention, error) {
	return auditanchor.COSObjectRetention{}, nil
}
func (*factoryCOSClient) ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error) {
	return auditanchor.ObjectKeyPage{}, nil
}

func validFactoryCredential(now time.Time) tencentcredential.TemporaryCredential {
	return tencentcredential.TemporaryCredential{
		SecretID: "temporary-secret-id", SecretKey: "temporary-secret-key",
		Token: "temporary-security-token", Expiration: now.Add(time.Hour), RoleName: "audit-mirror-role",
	}
}

func TestCVMRoleCOSClientFactoryProbesExactRoleAndBuildsBoundClient(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)
	binding := auditmirrorworker.COSProviderBinding{
		Bucket: cosSDKTestBucket, Region: cosSDKTestRegion, ProviderProfileID: "tencent-mirror-production",
	}
	provider := &factoryCredentialProvider{credential: validFactoryCredential(now)}
	client := &factoryCOSClient{}
	built := 0
	factory, err := newCVMRoleCOSClientFactory(binding, "audit-mirror-role", provider,
		func(bucket, region string, actual cosCredentialProvider, timeout time.Duration) (auditmirrorworker.COSClient, error) {
			built++
			if bucket != binding.Bucket || region != binding.Region || actual != provider || timeout != cosRequestTimeout {
				t.Fatal("builder received an unbound input")
			}
			return client, nil
		}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actual, err := factory.NewCOS(context.Background(), binding)
	if err != nil || actual != client || provider.calls != 1 || built != 1 {
		t.Fatalf("client=%#v err=%v probes=%d builds=%d", actual, err, provider.calls, built)
	}
}

func TestCVMRoleCOSClientFactoryFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC)
	binding := auditmirrorworker.COSProviderBinding{
		Bucket: cosSDKTestBucket, Region: cosSDKTestRegion, ProviderProfileID: "tencent-mirror-production",
	}
	validProvider := &factoryCredentialProvider{credential: validFactoryCredential(now)}
	validBuilder := func(string, string, cosCredentialProvider, time.Duration) (auditmirrorworker.COSClient, error) {
		return &factoryCOSClient{}, nil
	}
	for name, mutate := range map[string]func(*auditmirrorworker.COSProviderBinding, *string, *cosCredentialProvider, *cosClientBuilder, *func() time.Time){
		"bucket": func(value *auditmirrorworker.COSProviderBinding, _ *string, _ *cosCredentialProvider, _ *cosClientBuilder, _ *func() time.Time) {
			value.Bucket = "BAD"
		},
		"region": func(value *auditmirrorworker.COSProviderBinding, _ *string, _ *cosCredentialProvider, _ *cosClientBuilder, _ *func() time.Time) {
			value.Region = "BAD"
		},
		"profile": func(value *auditmirrorworker.COSProviderBinding, _ *string, _ *cosCredentialProvider, _ *cosClientBuilder, _ *func() time.Time) {
			value.ProviderProfileID = "bad profile"
		},
		"role": func(_ *auditmirrorworker.COSProviderBinding, value *string, _ *cosCredentialProvider, _ *cosClientBuilder, _ *func() time.Time) {
			*value = "bad role"
		},
		"provider": func(_ *auditmirrorworker.COSProviderBinding, _ *string, value *cosCredentialProvider, _ *cosClientBuilder, _ *func() time.Time) {
			*value = nil
		},
		"builder": func(_ *auditmirrorworker.COSProviderBinding, _ *string, _ *cosCredentialProvider, value *cosClientBuilder, _ *func() time.Time) {
			*value = nil
		},
		"clock": func(_ *auditmirrorworker.COSProviderBinding, _ *string, _ *cosCredentialProvider, _ *cosClientBuilder, value *func() time.Time) {
			*value = nil
		},
	} {
		t.Run("constructor_"+name, func(t *testing.T) {
			expected, role, provider, builder, clock := binding, "audit-mirror-role", cosCredentialProvider(validProvider), cosClientBuilder(validBuilder), func() time.Time { return now }
			mutate(&expected, &role, &provider, &builder, &clock)
			if factory, err := newCVMRoleCOSClientFactory(expected, role, provider, builder, clock); factory != nil || !errors.Is(err, ErrImmutableSDKRequestRejected) {
				t.Fatalf("factory=%#v err=%v", factory, err)
			}
		})
	}

	factory := func(provider cosCredentialProvider, builder cosClientBuilder) *CVMRoleCOSClientFactory {
		value, err := newCVMRoleCOSClientFactory(binding, "audit-mirror-role", provider, builder, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, value := range map[string]struct {
		factory *CVMRoleCOSClientFactory
		ctx     context.Context
		binding auditmirrorworker.COSProviderBinding
	}{
		"nil_factory":   {factory: nil, ctx: context.Background(), binding: binding},
		"nil_context":   {factory: factory(validProvider, validBuilder), ctx: nil, binding: binding},
		"cancelled":     {factory: factory(validProvider, validBuilder), ctx: ctx, binding: binding},
		"wrong_binding": {factory: factory(validProvider, validBuilder), ctx: context.Background(), binding: auditmirrorworker.COSProviderBinding{Bucket: binding.Bucket, Region: binding.Region, ProviderProfileID: "other-profile"}},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := value.factory.NewCOS(value.ctx, value.binding)
			if client != nil || !errors.Is(err, ErrImmutableSDKRequestRejected) {
				t.Fatalf("client=%#v err=%v", client, err)
			}
		})
	}

	providers := map[string]*factoryCredentialProvider{
		"provider_error": {err: errors.New("detail")},
		"wrong_role": {credential: func() tencentcredential.TemporaryCredential {
			value := validFactoryCredential(now)
			value.RoleName = "other-role"
			return value
		}()},
		"expired": {credential: func() tencentcredential.TemporaryCredential {
			value := validFactoryCredential(now)
			value.Expiration = now
			return value
		}()},
	}
	for name, provider := range providers {
		t.Run(name, func(t *testing.T) {
			client, err := factory(provider, validBuilder).NewCOS(context.Background(), binding)
			if client != nil || !errors.Is(err, ErrImmutableSDKUnavailable) {
				t.Fatalf("client=%#v err=%v", client, err)
			}
		})
	}
	for name, builder := range map[string]cosClientBuilder{
		"builder_error": func(string, string, cosCredentialProvider, time.Duration) (auditmirrorworker.COSClient, error) {
			return nil, errors.New("detail")
		},
		"nil_client": func(string, string, cosCredentialProvider, time.Duration) (auditmirrorworker.COSClient, error) {
			return nil, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := factory(&factoryCredentialProvider{credential: validFactoryCredential(now)}, builder).NewCOS(context.Background(), binding)
			if client != nil || !errors.Is(err, ErrImmutableSDKUnavailable) {
				t.Fatalf("client=%#v err=%v", client, err)
			}
		})
	}
}

func TestPublicCVMRoleCOSClientFactoryValidatesWithoutNetworkAccess(t *testing.T) {
	binding := auditmirrorworker.COSProviderBinding{
		Bucket: cosSDKTestBucket, Region: cosSDKTestRegion, ProviderProfileID: "tencent-mirror-production",
	}
	factory, err := NewCVMRoleCOSClientFactory(binding, "audit-mirror-role")
	if err != nil || factory == nil {
		t.Fatalf("factory=%#v err=%v", factory, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if client, err := factory.NewCOS(ctx, binding); client != nil || !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("client=%#v err=%v", client, err)
	}
	if factory, err := NewCVMRoleCOSClientFactory(binding, "bad role"); factory != nil || !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("factory=%#v err=%v", factory, err)
	}
}
