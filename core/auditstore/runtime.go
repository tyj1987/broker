package auditstore

import (
	"context"
	"errors"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
)

var (
	ErrServiceIdentityUnavailable = errors.New("audit store workload identity unavailable")
	ErrServiceRuntimeInvalid      = errors.New("audit store service runtime is invalid")
)

type OSSCloudClient interface {
	auditanchor.OSSImmutableClient
	ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error)
}

// PrimaryClientFactory is the only point in this process allowed to exchange
// its workload identity for an Alibaba OSS client. It receives a non-secret,
// prevalidated binding and must
// not fall back to account keys, shared credential files or caller-controlled
// endpoints.
type PrimaryClientFactory interface {
	NewOSS(context.Context, ProviderBinding) (OSSCloudClient, error)
}

// MirrorClientFactory connects to a separately authenticated, provider-neutral
// mirror worker. It never returns a COS SDK client or COS credential to this
// process.
type MirrorClientFactory interface {
	NewMirror(context.Context, auditmirror.Binding) (auditmirror.Client, error)
}

type Runtime struct {
	StreamID   string
	Repository Repository
	Verifier   *auditanchor.EnvelopeVerifier
}

func NewRuntime(
	ctx context.Context,
	config ServiceConfig,
	primaryFactory PrimaryClientFactory,
	mirrorFactory MirrorClientFactory,
) (*Runtime, error) {
	if ctx == nil || ctx.Err() != nil || primaryFactory == nil || mirrorFactory == nil {
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
	binding, err := mirrorBinding(safeConfig)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	ossClient, err := primaryFactory.NewOSS(ctx, safeConfig.OSS)
	if err != nil || ossClient == nil || ctx.Err() != nil {
		return nil, ErrServiceIdentityUnavailable
	}
	mirrorClient, err := mirrorFactory.NewMirror(ctx, binding)
	if err != nil || mirrorClient == nil || ctx.Err() != nil {
		return nil, ErrServiceIdentityUnavailable
	}
	cosClient, err := newMirrorCOSAdapter(safeConfig, mirrorClient, verifier)
	if err != nil {
		return nil, err
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

// UnavailablePrimaryClientFactory keeps the checked-in command fail closed
// until a reviewed Alibaba workload-identity implementation is selected.
type UnavailablePrimaryClientFactory struct{}

func (UnavailablePrimaryClientFactory) NewOSS(context.Context, ProviderBinding) (OSSCloudClient, error) {
	return nil, ErrServiceIdentityUnavailable
}

// UnavailableMirrorClientFactory prevents the checked-in command from
// selecting a cross-cloud transport before that trust boundary is approved.
type UnavailableMirrorClientFactory struct{}

func (UnavailableMirrorClientFactory) NewMirror(context.Context, auditmirror.Binding) (auditmirror.Client, error) {
	return nil, ErrServiceIdentityUnavailable
}
