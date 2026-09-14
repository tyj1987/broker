package auditcos

import (
	"context"
	"regexp"
	"time"

	"github.com/tyj1987/broker/core/auditmirrorworker"
	"github.com/tyj1987/broker/core/tencentcredential"
)

const (
	cvmCredentialProbeTimeout = 2 * time.Second
	cosRequestTimeout         = 15 * time.Second
)

var cosProfileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type cosClientBuilder func(string, string, cosCredentialProvider, time.Duration) (auditmirrorworker.COSClient, error)

// CVMRoleCOSClientFactory binds one mirror-worker configuration to one named
// CVM CAM role. Construction does not contact metadata; NewCOS proves the
// workload credential before returning a client.
type CVMRoleCOSClientFactory struct {
	expected auditmirrorworker.COSProviderBinding
	roleName string
	provider cosCredentialProvider
	build    cosClientBuilder
	clock    func() time.Time
}

func NewCVMRoleCOSClientFactory(
	expected auditmirrorworker.COSProviderBinding,
	roleName string,
) (*CVMRoleCOSClientFactory, error) {
	provider, err := tencentcredential.NewCVMRoleProvider(roleName, cvmCredentialProbeTimeout)
	if err != nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	return newCVMRoleCOSClientFactory(expected, roleName, provider, buildCVMRoleCOSClient, time.Now)
}

func newCVMRoleCOSClientFactory(
	expected auditmirrorworker.COSProviderBinding,
	roleName string,
	provider cosCredentialProvider,
	build cosClientBuilder,
	clock func() time.Time,
) (*CVMRoleCOSClientFactory, error) {
	if !validCOSBucketAndRegion(expected.Bucket, expected.Region) ||
		!cosProfileIDPattern.MatchString(expected.ProviderProfileID) ||
		!cosRoleNamePattern.MatchString(roleName) || provider == nil || build == nil || clock == nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	return &CVMRoleCOSClientFactory{
		expected: expected,
		roleName: roleName,
		provider: provider,
		build:    build,
		clock:    clock,
	}, nil
}

func (factory *CVMRoleCOSClientFactory) NewCOS(
	ctx context.Context,
	binding auditmirrorworker.COSProviderBinding,
) (auditmirrorworker.COSClient, error) {
	if factory == nil || ctx == nil || ctx.Err() != nil || binding != factory.expected ||
		factory.provider == nil || factory.build == nil || factory.clock == nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	credential, err := factory.provider.Credential(ctx)
	if err != nil || ctx.Err() != nil || credential.RoleName != factory.roleName ||
		!validSigningCredential(credential, factory.clock()) {
		return nil, ErrImmutableSDKUnavailable
	}
	client, err := factory.build(binding.Bucket, binding.Region, factory.provider, cosRequestTimeout)
	if err != nil || client == nil || ctx.Err() != nil {
		return nil, ErrImmutableSDKUnavailable
	}
	return client, nil
}

func buildCVMRoleCOSClient(
	bucket, region string,
	provider cosCredentialProvider,
	timeout time.Duration,
) (auditmirrorworker.COSClient, error) {
	transport, err := newCOSNetworkTransport(timeout)
	if err != nil {
		return nil, err
	}
	return newCVMRoleCOSSDKImmutableClient(bucket, region, provider, transport, time.Now, timeout)
}

var _ auditmirrorworker.COSClientFactory = (*CVMRoleCOSClientFactory)(nil)
