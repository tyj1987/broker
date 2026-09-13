package auditmirrorworker

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
)

var ErrIdentityUnavailable = errors.New("audit mirror worker identity is unavailable")

type COSProviderBinding struct {
	Bucket            string
	Region            string
	ProviderProfileID string
}

type COSClientFactory interface {
	NewCOS(context.Context, COSProviderBinding) (COSClient, error)
}

type UnavailableCOSClientFactory struct{}

func (UnavailableCOSClientFactory) NewCOS(context.Context, COSProviderBinding) (COSClient, error) {
	return nil, ErrIdentityUnavailable
}

func NewRuntime(ctx context.Context, config Config, factory COSClientFactory) (*Backend, error) {
	if ctx == nil || ctx.Err() != nil || factory == nil {
		return nil, ErrIdentityUnavailable
	}
	safeConfig, err := cloneConfig(config)
	if err != nil {
		return nil, ErrConfigInvalid
	}
	binding := COSProviderBinding{
		Bucket: safeConfig.Bucket, Region: safeConfig.Region, ProviderProfileID: safeConfig.ProfileID,
	}
	client, err := factory.NewCOS(ctx, binding)
	if err != nil || client == nil || ctx.Err() != nil {
		return nil, ErrIdentityUnavailable
	}
	backend, err := NewBackend(safeConfig, client)
	if err != nil {
		return nil, ErrConfigInvalid
	}
	return backend, nil
}

func cloneConfig(config Config) (Config, error) {
	if !bucketPattern.MatchString(config.Bucket) || !bucketPattern.MatchString(config.Region) ||
		len(config.TrustedKeys) < 1 || len(config.TrustedKeys) > 16 {
		return Config{}, ErrConfigInvalid
	}
	cloned := config
	cloned.TrustedKeys = make(map[string]auditanchor.TrustedSigningKey, len(config.TrustedKeys))
	for keyID, key := range config.TrustedKeys {
		der, err := x509.MarshalPKIXPublicKey(key.PublicKey)
		if err != nil {
			return Config{}, ErrConfigInvalid
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok {
			return Config{}, ErrConfigInvalid
		}
		cloned.TrustedKeys[keyID] = auditanchor.TrustedSigningKey{
			PublicKey: publicKey, ValidFromSequence: key.ValidFromSequence,
			ValidThroughSequence: key.ValidThroughSequence,
		}
	}
	generation, err := auditanchor.TrustedKeyGeneration(cloned.TrustedKeys)
	if err != nil {
		return Config{}, ErrConfigInvalid
	}
	if _, err = auditmirror.NewBinding(cloned.StreamID, cloned.Prefix, cloned.ProfileID, generation); err != nil {
		return Config{}, ErrConfigInvalid
	}
	return cloned, nil
}

var _ COSClientFactory = UnavailableCOSClientFactory{}
