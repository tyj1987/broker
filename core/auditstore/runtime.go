package auditstore

import (
	"context"
	"errors"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
)

var (
	ErrServiceIdentityUnavailable = errors.New("audit store workload identity unavailable")
	ErrServiceRuntimeInvalid      = errors.New("audit store service runtime is invalid")
)

type OSSCloudClient interface {
	auditanchor.OSSImmutableClient
	ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error)
}

type COSCloudClient interface {
	auditanchor.COSImmutableClient
	ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error)
}

// CloudClientFactory is the only point allowed to exchange a workload identity
// for provider clients. It receives non-secret, prevalidated bindings and must
// not fall back to account keys, shared credential files or caller-controlled
// endpoints.
type CloudClientFactory interface {
	NewOSS(context.Context, ProviderBinding) (OSSCloudClient, error)
	NewCOS(context.Context, ProviderBinding) (COSCloudClient, error)
}

type Runtime struct {
	StreamID   string
	Repository Repository
	Verifier   *auditanchor.EnvelopeVerifier
}

func NewRuntime(ctx context.Context, config ServiceConfig, factory CloudClientFactory) (*Runtime, error) {
	if ctx == nil || ctx.Err() != nil || factory == nil {
		return nil, ErrServiceRuntimeInvalid
	}
	safeConfig, err := cloneServiceConfig(config)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	keys := trustedSigningKeys(safeConfig)
	verifier, err := auditanchor.NewEnvelopeVerifier(safeConfig.StreamID, keys)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	ossClient, err := factory.NewOSS(ctx, safeConfig.OSS)
	if err != nil || ossClient == nil || ctx.Err() != nil {
		return nil, ErrServiceIdentityUnavailable
	}
	cosClient, err := factory.NewCOS(ctx, safeConfig.COS)
	if err != nil || cosClient == nil || ctx.Err() != nil {
		return nil, ErrServiceIdentityUnavailable
	}
	writer, err := auditanchor.NewImmutableObjectWriter(auditanchor.ImmutableObjectWriterConfig{
		OSSBucket: safeConfig.OSS.Bucket, COSBucket: safeConfig.COS.Bucket,
		Prefix: safeConfig.Prefix, StreamID: safeConfig.StreamID,
		TrustedKeys: keys, Now: time.Now,
	}, ossClient, cosClient)
	if err != nil {
		return nil, ErrServiceRuntimeInvalid
	}
	repository, err := NewDualCloudRepository(DualCloudRepositoryConfig{
		StreamID: safeConfig.StreamID, Prefix: safeConfig.Prefix,
		OSSBucket: safeConfig.OSS.Bucket, COSBucket: safeConfig.COS.Bucket,
		ListPageSize: safeConfig.ListPageSize, MaxListPages: safeConfig.MaxListPages,
	}, writer, ossClient, cosClient, verifier)
	if err != nil {
		return nil, ErrServiceRuntimeInvalid
	}
	return &Runtime{StreamID: safeConfig.StreamID, Repository: repository, Verifier: verifier}, nil
}

// UnavailableCloudClientFactory keeps the checked-in command fail closed until
// a reviewed workload-identity implementation is selected explicitly.
type UnavailableCloudClientFactory struct{}

func (UnavailableCloudClientFactory) NewOSS(context.Context, ProviderBinding) (OSSCloudClient, error) {
	return nil, ErrServiceIdentityUnavailable
}

func (UnavailableCloudClientFactory) NewCOS(context.Context, ProviderBinding) (COSCloudClient, error) {
	return nil, ErrServiceIdentityUnavailable
}
