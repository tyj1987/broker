package githubsigner

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"

	"github.com/tyj1987/broker/core/internal/trustedconfig"
)

const (
	ServiceConfigVersion     = 3
	MaxServiceConfigBytes    = 32 * 1024
	serviceConfigPath        = "/etc/secret-broker/providers/github-signer.json"
	serviceConfigDir         = "/etc/secret-broker/providers"
	kmsCACertificatePath     = "/etc/secret-broker/providers/github-kms-ca.pem"
	maxKMSCACertificateBytes = 32 * 1024
)

var ErrServiceConfigInvalid = errors.New("github signer service configuration is invalid")

type ServiceConfig struct {
	Version                   int
	ProviderProfileID         string
	KMSRoleName               string
	KMSEndpoint               string
	KMSCASHA256               string
	KMSAllowedCIDRs           []netip.Prefix
	Bindings                  []Binding
	SigningAuthorities        []SigningAuthority
	AuthorityGenerationSHA256 string
}

type serviceConfigWire struct {
	Version           int           `json:"version"`
	ProviderProfileID string        `json:"provider_profile_id"`
	KMSRoleName       string        `json:"kms_role_name"`
	KMSEndpoint       string        `json:"kms_endpoint"`
	KMSCASHA256       string        `json:"kms_ca_sha256"`
	KMSAllowedCIDRs   []string      `json:"kms_allowed_cidrs"`
	Bindings          []bindingWire `json:"bindings"`
}

type bindingWire struct {
	AccountRef       string `json:"account_ref"`
	Environment      string `json:"environment"`
	ClientID         string `json:"client_id"`
	KMSKeyID         string `json:"kms_key_id"`
	KMSKeyVersionID  string `json:"kms_key_version_id"`
	PublicKeySPKIDER string `json:"public_key_spki_der_base64"`
	PublicKeySHA256  string `json:"public_key_sha256"`
}

// SigningAuthority binds one GitHub identity tuple to one exact, non-exportable
// KMS key version and a pinned public key used to verify every returned signature.
type SigningAuthority struct {
	Binding         Binding
	KMSKeyID        string
	KMSKeyVersionID string
	PublicKey       *rsa.PublicKey
	PublicKeySHA256 string
}

func ParseServiceConfig(reader io.Reader) (ServiceConfig, error) {
	if reader == nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	value, err := io.ReadAll(io.LimitReader(reader, MaxServiceConfigBytes+1))
	if err != nil || len(value) == 0 || len(value) > MaxServiceConfigBytes ||
		rejectDuplicateKeys(value) != nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(value, &raw) != nil || !exactNonNullKeys(raw,
		"version", "provider_profile_id", "kms_role_name", "kms_endpoint", "kms_ca_sha256",
		"kms_allowed_cidrs", "bindings") {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	var rawBindings []json.RawMessage
	if json.Unmarshal(raw["bindings"], &rawBindings) != nil || len(rawBindings) < 1 || len(rawBindings) > 64 {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	for _, binding := range rawBindings {
		var object map[string]json.RawMessage
		if json.Unmarshal(binding, &object) != nil || !exactNonNullKeys(object,
			"account_ref", "environment", "client_id", "kms_key_id", "kms_key_version_id",
			"public_key_spki_der_base64", "public_key_sha256") {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
	}
	var wire serviceConfigWire
	if decodeStrict(value, &wire) != nil || wire.Version != ServiceConfigVersion ||
		!clientIDPattern.MatchString(wire.ProviderProfileID) ||
		!kmsRoleNamePattern.MatchString(wire.KMSRoleName) ||
		!kmsDedicatedEndpointPattern.MatchString(wire.KMSEndpoint) ||
		!publicKeyDigestPattern.MatchString(wire.KMSCASHA256) ||
		len(wire.KMSAllowedCIDRs) < 1 || len(wire.KMSAllowedCIDRs) > 8 {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	allowedCIDRs := make([]netip.Prefix, 0, len(wire.KMSAllowedCIDRs))
	seenCIDRs := make(map[netip.Prefix]struct{}, len(wire.KMSAllowedCIDRs))
	for _, encoded := range wire.KMSAllowedCIDRs {
		prefix, parseErr := netip.ParsePrefix(encoded)
		if parseErr != nil || prefix != prefix.Masked() || prefix.String() != encoded || !safeKMSPrefix(prefix) {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
		if _, duplicate := seenCIDRs[prefix]; duplicate {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
		seenCIDRs[prefix] = struct{}{}
		allowedCIDRs = append(allowedCIDRs, prefix)
	}
	bindings := make([]Binding, 0, len(wire.Bindings))
	authorities := make([]SigningAuthority, 0, len(wire.Bindings))
	for _, binding := range wire.Bindings {
		boundIdentity := Binding{
			AccountRef: binding.AccountRef, Environment: binding.Environment, ClientID: binding.ClientID,
		}
		publicKeyDER, decodeErr := base64.StdEncoding.Strict().DecodeString(binding.PublicKeySPKIDER)
		parsedKey, parseErr := x509.ParsePKIXPublicKey(publicKeyDER)
		publicKey, isRSA := parsedKey.(*rsa.PublicKey)
		publicKeyDigest := sha256.Sum256(publicKeyDER)
		if decodeErr != nil || parseErr != nil || !isRSA || !validKMSRSAKey(publicKey) ||
			publicKey.E != 65537 || !kmsKeyIDPattern.MatchString(binding.KMSKeyID) ||
			!kmsKeyVersionIDPattern.MatchString(binding.KMSKeyVersionID) ||
			!publicKeyDigestPattern.MatchString(binding.PublicKeySHA256) ||
			hex.EncodeToString(publicKeyDigest[:]) != binding.PublicKeySHA256 {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
		bindings = append(bindings, boundIdentity)
		authorities = append(authorities, SigningAuthority{
			Binding: boundIdentity, KMSKeyID: binding.KMSKeyID, KMSKeyVersionID: binding.KMSKeyVersionID,
			PublicKey: publicKey, PublicKeySHA256: binding.PublicKeySHA256,
		})
	}
	if _, err = NewBindingSet(bindings); err != nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	digest := sha256.Sum256(value)
	return ServiceConfig{
		Version: wire.Version, ProviderProfileID: wire.ProviderProfileID,
		KMSRoleName: wire.KMSRoleName, KMSEndpoint: wire.KMSEndpoint, KMSCASHA256: wire.KMSCASHA256,
		KMSAllowedCIDRs: allowedCIDRs, Bindings: bindings,
		SigningAuthorities:        authorities,
		AuthorityGenerationSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

func LoadKMSCACertificateFile(expectedSHA256 string) ([]byte, error) {
	if !publicKeyDigestPattern.MatchString(expectedSHA256) {
		return nil, ErrServiceConfigInvalid
	}
	value, err := trustedconfig.ReadFileAt(
		kmsCACertificatePath, serviceConfigDir, 0, maxKMSCACertificateBytes,
	)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	digest := sha256.Sum256(value)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, ErrServiceConfigInvalid
	}
	return value, nil
}

func LoadServiceConfigFile(path string) (ServiceConfig, error) {
	if path != serviceConfigPath {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	value, err := trustedconfig.ReadFileAt(path, serviceConfigDir, 0, MaxServiceConfigBytes)
	if err != nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	return ParseServiceConfig(bytes.NewReader(value))
}

func exactNonNullKeys(object map[string]json.RawMessage, expected ...string) bool {
	if object == nil || len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		value, present := object[key]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}
