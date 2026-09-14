package auditanchor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"regexp"

	"github.com/tyj1987/broker/core/internal/trustedconfig"
)

const (
	SignerServiceConfigVersion  = 1
	MaxSignerServiceConfigBytes = 32 * 1024
	signerServiceConfigPath     = "/etc/secret-broker/audit/signer.json"
	signerServiceConfigDir      = "/etc/secret-broker/audit"
)

var (
	ErrSignerServiceConfigInvalid = errors.New("audit signer service configuration is invalid")
	signerRoleNamePattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.@_-]{0,63}$`)
	signerKMSEndpointPattern      = regexp.MustCompile(`^kst-[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.cryptoservice\.kms\.aliyuncs\.com$`)
	signerKeyIDPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{2,255}$`)
	signerDigestPattern           = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var signerServiceConfigKeys = []string{
	"version", "provider_profile_id", "state_profile_id", "ecs_ram_role_name",
	"kms_endpoint", "kms_ca_sha256", "kms_allowed_cidrs", "algorithm", "key_id",
	"key_version_id", "stream_id", "public_key_spki_der_base64", "public_key_sha256",
}

// SignerServiceConfig contains public authority metadata only. Credentials,
// private keys, arbitrary endpoints and state-store connection material are not
// accepted by its exact JSON grammar.
type SignerServiceConfig struct {
	Version           int
	ProviderProfileID string
	StateProfileID    string
	ECSRAMRoleName    string
	KMSEndpoint       string
	// KMSCASHA256 is the lowercase SHA-256 of the single instance CA's DER bytes.
	KMSCASHA256     string
	KMSAllowedCIDRs []netip.Prefix
	Anchor          Config
	KeyVersionID    string
	PublicKey       *ecdsa.PublicKey
	PublicKeySHA256 string
}

type signerServiceConfigWire struct {
	Version                int      `json:"version"`
	ProviderProfileID      string   `json:"provider_profile_id"`
	StateProfileID         string   `json:"state_profile_id"`
	ECSRAMRoleName         string   `json:"ecs_ram_role_name"`
	KMSEndpoint            string   `json:"kms_endpoint"`
	KMSCASHA256            string   `json:"kms_ca_sha256"`
	KMSAllowedCIDRs        []string `json:"kms_allowed_cidrs"`
	Algorithm              string   `json:"algorithm"`
	KeyID                  string   `json:"key_id"`
	KeyVersionID           string   `json:"key_version_id"`
	StreamID               string   `json:"stream_id"`
	PublicKeySPKIDERBase64 string   `json:"public_key_spki_der_base64"`
	PublicKeySHA256        string   `json:"public_key_sha256"`
}

func ParseSignerServiceConfig(reader io.Reader) (SignerServiceConfig, error) {
	if reader == nil {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	value, err := io.ReadAll(io.LimitReader(reader, MaxSignerServiceConfigBytes+1))
	if err != nil || len(value) == 0 || len(value) > MaxSignerServiceConfigBytes {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	var wire signerServiceConfigWire
	if decodeExactObject(value, &wire, signerServiceConfigKeys) != nil ||
		len(wire.KMSAllowedCIDRs) < 1 || len(wire.KMSAllowedCIDRs) > 8 {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}

	encodedKey, err := base64.StdEncoding.Strict().DecodeString(wire.PublicKeySPKIDERBase64)
	if err != nil || len(encodedKey) == 0 || len(encodedKey) > 512 ||
		base64.StdEncoding.EncodeToString(encodedKey) != wire.PublicKeySPKIDERBase64 {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	parsedKey, err := x509.ParsePKIXPublicKey(encodedKey)
	publicKey, isP256 := parsedKey.(*ecdsa.PublicKey)
	if err != nil || !isP256 || !validP256PublicKey(publicKey) {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	digest := sha256.Sum256(encodedKey)
	if hex.EncodeToString(digest[:]) != wire.PublicKeySHA256 {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}

	allowedCIDRs := make([]netip.Prefix, 0, len(wire.KMSAllowedCIDRs))
	seenCIDRs := make(map[netip.Prefix]struct{}, len(wire.KMSAllowedCIDRs))
	for _, encoded := range wire.KMSAllowedCIDRs {
		prefix, parseErr := netip.ParsePrefix(encoded)
		if parseErr != nil || prefix.String() != encoded || prefix != prefix.Masked() ||
			!safeSignerKMSPrefix(prefix) {
			return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
		}
		if _, duplicate := seenCIDRs[prefix]; duplicate {
			return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
		}
		seenCIDRs[prefix] = struct{}{}
		allowedCIDRs = append(allowedCIDRs, prefix)
	}

	return ValidateSignerServiceConfig(SignerServiceConfig{
		Version: wire.Version, ProviderProfileID: wire.ProviderProfileID,
		StateProfileID: wire.StateProfileID, ECSRAMRoleName: wire.ECSRAMRoleName,
		KMSEndpoint: wire.KMSEndpoint, KMSCASHA256: wire.KMSCASHA256,
		KMSAllowedCIDRs: allowedCIDRs,
		Anchor:          Config{Algorithm: wire.Algorithm, KeyID: wire.KeyID, StreamID: wire.StreamID},
		KeyVersionID:    wire.KeyVersionID, PublicKey: publicKey, PublicKeySHA256: wire.PublicKeySHA256,
	})
}

func LoadSignerServiceConfigFile(path string) (SignerServiceConfig, error) {
	if path != signerServiceConfigPath {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	value, err := trustedconfig.ReadFileAt(path, signerServiceConfigDir, 0, MaxSignerServiceConfigBytes)
	if err != nil {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	return ParseSignerServiceConfig(bytes.NewReader(value))
}

func ValidateSignerServiceConfig(config SignerServiceConfig) (SignerServiceConfig, error) {
	if config.Version != SignerServiceConfigVersion || !idPattern.MatchString(config.ProviderProfileID) ||
		!idPattern.MatchString(config.StateProfileID) || config.ProviderProfileID == config.StateProfileID ||
		!signerRoleNamePattern.MatchString(config.ECSRAMRoleName) ||
		!signerKMSEndpointPattern.MatchString(config.KMSEndpoint) ||
		!signerDigestPattern.MatchString(config.KMSCASHA256) ||
		!validConfig(config.Anchor) || config.Anchor.Algorithm != "ecdsa-p256-sha256" ||
		!signerKeyIDPattern.MatchString(config.Anchor.KeyID) ||
		!kmsKeyVersionPattern.MatchString(config.KeyVersionID) ||
		!signerDigestPattern.MatchString(config.PublicKeySHA256) ||
		len(config.KMSAllowedCIDRs) < 1 || len(config.KMSAllowedCIDRs) > 8 {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	clonedKey, validKey := cloneP256PublicKey(config.PublicKey)
	if !validKey {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	encodedKey, err := x509.MarshalPKIXPublicKey(clonedKey)
	keyDigest := sha256.Sum256(encodedKey)
	if err != nil || hex.EncodeToString(keyDigest[:]) != config.PublicKeySHA256 {
		return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
	}
	clonedCIDRs := append([]netip.Prefix(nil), config.KMSAllowedCIDRs...)
	seen := make(map[netip.Prefix]struct{}, len(clonedCIDRs))
	for _, prefix := range clonedCIDRs {
		if prefix != prefix.Masked() || !safeSignerKMSPrefix(prefix) {
			return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
		}
		if _, duplicate := seen[prefix]; duplicate {
			return SignerServiceConfig{}, ErrSignerServiceConfigInvalid
		}
		seen[prefix] = struct{}{}
	}
	config.PublicKey = clonedKey
	config.KMSAllowedCIDRs = clonedCIDRs
	return config, nil
}

func safeSignerKMSPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || !safeSignerKMSAddress(prefix.Addr()) {
		return false
	}
	if prefix.Addr().Is4() {
		return prefix.Bits() >= 24
	}
	return prefix.Bits() >= 64
}

func safeSignerKMSAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsPrivate() && !address.IsUnspecified() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() &&
		!address.IsMulticast()
}
