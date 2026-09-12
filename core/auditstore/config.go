package auditstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"

	"github.com/tyj1987/broker/core/auditanchor"
)

const (
	ServiceConfigVersion  = 1
	MaxServiceConfigBytes = 32 * 1024
)

var (
	ErrServiceConfigInvalid = errors.New("audit store service configuration is invalid")
	regionPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
)

// ProviderBinding contains only non-secret identifiers. Provider endpoints,
// credential material and credential-file or command references are not part
// of the accepted configuration grammar.
type ProviderBinding struct {
	Bucket            string
	Region            string
	ProviderProfileID string
}

type TrustedKeyBinding struct {
	KeyID                string
	PublicKey            *ecdsa.PublicKey
	ValidFromSequence    int64
	ValidThroughSequence int64
}

type ServiceConfig struct {
	Version      int
	StreamID     string
	Prefix       string
	OSS          ProviderBinding
	COS          ProviderBinding
	TrustedKeys  []TrustedKeyBinding
	ListPageSize int
	MaxListPages int
}

type providerBindingWire struct {
	Bucket            string `json:"bucket"`
	Region            string `json:"region"`
	ProviderProfileID string `json:"provider_profile_id"`
}

type trustedKeyBindingWire struct {
	KeyID                string `json:"key_id"`
	PublicKeySPKIBase64  string `json:"public_key_spki_base64"`
	ValidFromSequence    int64  `json:"valid_from_sequence"`
	ValidThroughSequence int64  `json:"valid_through_sequence"`
}

type serviceConfigWire struct {
	Version      int                     `json:"version"`
	StreamID     string                  `json:"stream_id"`
	Prefix       string                  `json:"prefix"`
	OSS          providerBindingWire     `json:"oss"`
	COS          providerBindingWire     `json:"cos"`
	TrustedKeys  []trustedKeyBindingWire `json:"trusted_keys"`
	ListPageSize int                     `json:"list_page_size"`
	MaxListPages int                     `json:"max_list_pages"`
}

func ParseServiceConfig(reader io.Reader) (ServiceConfig, error) {
	if reader == nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	value, err := io.ReadAll(io.LimitReader(reader, MaxServiceConfigBytes+1))
	if err != nil || len(value) == 0 || len(value) > MaxServiceConfigBytes ||
		rejectDuplicateJSONKeys(value) != nil ||
		!exactObjectKeys(value, "version", "stream_id", "prefix", "oss", "cos", "trusted_keys", "list_page_size", "max_list_pages") {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(value, &raw) != nil ||
		!exactNonNullObjectKeys(value, "version", "stream_id", "prefix", "oss", "cos", "trusted_keys", "list_page_size", "max_list_pages") ||
		!exactNonNullObjectKeys(raw["oss"], "bucket", "region", "provider_profile_id") ||
		!exactNonNullObjectKeys(raw["cos"], "bucket", "region", "provider_profile_id") {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	if isJSONNull(raw["trusted_keys"]) {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	var rawKeys []json.RawMessage
	if json.Unmarshal(raw["trusted_keys"], &rawKeys) != nil || len(rawKeys) < 1 || len(rawKeys) > 16 {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	for _, rawKey := range rawKeys {
		if !exactNonNullObjectKeys(rawKey, "key_id", "public_key_spki_base64", "valid_from_sequence", "valid_through_sequence") {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
	}

	var wire serviceConfigWire
	if decodeStrict(value, &wire) != nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	config := ServiceConfig{
		Version: wire.Version, StreamID: wire.StreamID, Prefix: wire.Prefix,
		OSS: ProviderBinding{
			Bucket: wire.OSS.Bucket, Region: wire.OSS.Region,
			ProviderProfileID: wire.OSS.ProviderProfileID,
		},
		COS: ProviderBinding{
			Bucket: wire.COS.Bucket, Region: wire.COS.Region,
			ProviderProfileID: wire.COS.ProviderProfileID,
		},
		ListPageSize: wire.ListPageSize, MaxListPages: wire.MaxListPages,
		TrustedKeys: make([]TrustedKeyBinding, 0, len(wire.TrustedKeys)),
	}
	for _, key := range wire.TrustedKeys {
		publicKey, parseErr := parseP256SPKI(key.PublicKeySPKIBase64)
		if parseErr != nil {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
		config.TrustedKeys = append(config.TrustedKeys, TrustedKeyBinding{
			KeyID: key.KeyID, PublicKey: publicKey,
			ValidFromSequence:    key.ValidFromSequence,
			ValidThroughSequence: key.ValidThroughSequence,
		})
	}
	return cloneServiceConfig(config)
}

func LoadServiceConfigFile(path string) (ServiceConfig, error) {
	if path == "" {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	file, err := openTrustedServiceConfig(path)
	if err != nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	defer file.Close()
	config, err := ParseServiceConfig(file)
	if err != nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	return config, nil
}

func exactNonNullObjectKeys(value []byte, expected ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(value, &object) != nil || len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		field, ok := object[key]
		if !ok || isJSONNull(field) {
			return false
		}
	}
	return true
}

func isJSONNull(value []byte) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func exactObjectKeys(value []byte, expected ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(value, &object) != nil || len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func parseP256SPKI(encoded string) (*ecdsa.PublicKey, error) {
	if encoded == "" || len(encoded) > 512 {
		return nil, ErrServiceConfigInvalid
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(der) != encoded {
		return nil, ErrServiceConfigInvalid
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || publicKey.Curve != elliptic.P256() || publicKey.X == nil ||
		publicKey.Y == nil || !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, ErrServiceConfigInvalid
	}
	return publicKey, nil
}

func cloneServiceConfig(config ServiceConfig) (ServiceConfig, error) {
	if !validServiceConfig(config) {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	cloned := config
	cloned.TrustedKeys = make([]TrustedKeyBinding, 0, len(config.TrustedKeys))
	for _, key := range config.TrustedKeys {
		der, err := x509.MarshalPKIXPublicKey(key.PublicKey)
		if err != nil {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
		cloned.TrustedKeys = append(cloned.TrustedKeys, TrustedKeyBinding{
			KeyID: key.KeyID, PublicKey: publicKey,
			ValidFromSequence:    key.ValidFromSequence,
			ValidThroughSequence: key.ValidThroughSequence,
		})
	}
	return cloned, nil
}

func validServiceConfig(config ServiceConfig) bool {
	if config.Version != ServiceConfigVersion || !idPattern.MatchString(config.StreamID) ||
		!validRepositoryPrefix(config.Prefix) || !validProviderBinding(config.OSS) ||
		!validProviderBinding(config.COS) || config.OSS.ProviderProfileID == config.COS.ProviderProfileID ||
		config.ListPageSize < 1 || config.ListPageSize > auditanchor.ImmutableListMaxKeys ||
		config.MaxListPages < 1 || config.MaxListPages > maximumCloudListPages ||
		len(config.TrustedKeys) < 1 || len(config.TrustedKeys) > 16 {
		return false
	}
	keys := append([]TrustedKeyBinding(nil), config.TrustedKeys...)
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if !idPattern.MatchString(key.KeyID) || key.PublicKey == nil || key.PublicKey.Curve != elliptic.P256() ||
			key.PublicKey.X == nil || key.PublicKey.Y == nil ||
			!key.PublicKey.Curve.IsOnCurve(key.PublicKey.X, key.PublicKey.Y) ||
			key.ValidFromSequence < 1 || key.ValidFromSequence > MaxSafeInteger ||
			key.ValidThroughSequence < 0 || key.ValidThroughSequence > MaxSafeInteger ||
			(key.ValidThroughSequence != 0 && key.ValidThroughSequence < key.ValidFromSequence) {
			return false
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return false
		}
		seen[key.KeyID] = struct{}{}
	}
	sort.Slice(keys, func(left, right int) bool {
		return keys[left].ValidFromSequence < keys[right].ValidFromSequence
	})
	for index := 1; index < len(keys); index++ {
		previous := keys[index-1]
		if previous.ValidThroughSequence == 0 || previous.ValidThroughSequence >= keys[index].ValidFromSequence {
			return false
		}
	}
	return true
}

func validProviderBinding(binding ProviderBinding) bool {
	return validRepositoryBucket(binding.Bucket) && regionPattern.MatchString(binding.Region) &&
		idPattern.MatchString(binding.ProviderProfileID)
}

func trustedSigningKeys(config ServiceConfig) map[string]auditanchor.TrustedSigningKey {
	keys := make(map[string]auditanchor.TrustedSigningKey, len(config.TrustedKeys))
	for _, key := range config.TrustedKeys {
		keys[key.KeyID] = auditanchor.TrustedSigningKey{
			PublicKey: key.PublicKey, ValidFromSequence: key.ValidFromSequence,
			ValidThroughSequence: key.ValidThroughSequence,
		}
	}
	return keys
}
