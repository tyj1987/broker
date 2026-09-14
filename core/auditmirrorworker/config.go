package auditmirrorworker

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

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
	"github.com/tyj1987/broker/core/internal/trustedconfig"
)

const (
	ConfigVersion   = 2
	MaxConfigBytes  = 32 * 1024
	configDirectory = "/etc/secret-broker/audit"
)

var ErrConfigInvalid = errors.New("audit mirror worker configuration is invalid")

type configWire struct {
	Version     int              `json:"version"`
	StreamID    string           `json:"stream_id"`
	Prefix      string           `json:"prefix"`
	ProfileID   string           `json:"profile_id"`
	Bucket      string           `json:"bucket"`
	Region      string           `json:"region"`
	CVMRoleName string           `json:"cvm_role_name"`
	TrustedKeys []trustedKeyWire `json:"trusted_keys"`
}

var cvmRoleNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type trustedKeyWire struct {
	KeyID                string `json:"key_id"`
	PublicKeySPKIBase64  string `json:"public_key_spki_base64"`
	ValidFromSequence    int64  `json:"valid_from_sequence"`
	ValidThroughSequence int64  `json:"valid_through_sequence"`
}

func ParseConfig(reader io.Reader) (Config, error) {
	if reader == nil {
		return Config{}, ErrConfigInvalid
	}
	value, err := io.ReadAll(io.LimitReader(reader, MaxConfigBytes+1))
	if err != nil || len(value) == 0 || len(value) > MaxConfigBytes || duplicateJSONKey(value) ||
		!exactObject(value, "version", "stream_id", "prefix", "profile_id", "bucket", "region", "cvm_role_name", "trusted_keys") {
		return Config{}, ErrConfigInvalid
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(value, &raw) != nil || bytes.Equal(bytes.TrimSpace(raw["trusted_keys"]), []byte("null")) {
		return Config{}, ErrConfigInvalid
	}
	var rawKeys []json.RawMessage
	if json.Unmarshal(raw["trusted_keys"], &rawKeys) != nil || len(rawKeys) < 1 || len(rawKeys) > 16 {
		return Config{}, ErrConfigInvalid
	}
	for _, key := range rawKeys {
		if !exactObject(key, "key_id", "public_key_spki_base64", "valid_from_sequence", "valid_through_sequence") {
			return Config{}, ErrConfigInvalid
		}
	}
	var wire configWire
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF {
		return Config{}, ErrConfigInvalid
	}
	config := Config{
		StreamID: wire.StreamID, Prefix: wire.Prefix, ProfileID: wire.ProfileID,
		Bucket: wire.Bucket, Region: wire.Region, CVMRoleName: wire.CVMRoleName,
		TrustedKeys: make(map[string]auditanchor.TrustedSigningKey, len(wire.TrustedKeys)),
	}
	if wire.Version != ConfigVersion {
		return Config{}, ErrConfigInvalid
	}
	for _, key := range wire.TrustedKeys {
		if _, duplicate := config.TrustedKeys[key.KeyID]; duplicate {
			return Config{}, ErrConfigInvalid
		}
		publicKey, parseErr := parseP256SPKI(key.PublicKeySPKIBase64)
		if parseErr != nil {
			return Config{}, ErrConfigInvalid
		}
		config.TrustedKeys[key.KeyID] = auditanchor.TrustedSigningKey{
			PublicKey: publicKey, ValidFromSequence: key.ValidFromSequence,
			ValidThroughSequence: key.ValidThroughSequence,
		}
	}
	generation, err := auditanchor.TrustedKeyGeneration(config.TrustedKeys)
	if err != nil || !bucketPattern.MatchString(config.Bucket) || !bucketPattern.MatchString(config.Region) ||
		!cvmRoleNamePattern.MatchString(config.CVMRoleName) {
		return Config{}, ErrConfigInvalid
	}
	if _, err = auditmirror.NewBinding(config.StreamID, config.Prefix, config.ProfileID, generation); err != nil {
		return Config{}, ErrConfigInvalid
	}
	return config, nil
}

func LoadConfigFile(path string) (Config, error) {
	value, err := trustedconfig.ReadFileAt(path, configDirectory, 0, MaxConfigBytes)
	if err != nil {
		return Config{}, ErrConfigInvalid
	}
	return ParseConfig(bytes.NewReader(value))
}

func parseP256SPKI(encoded string) (*ecdsa.PublicKey, error) {
	if encoded == "" || len(encoded) > 512 {
		return nil, ErrConfigInvalid
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(der) != encoded {
		return nil, ErrConfigInvalid
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil ||
		!publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, ErrConfigInvalid
	}
	return publicKey, nil
}

func exactObject(value []byte, expected ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(value, &object) != nil || object == nil || len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		field, exists := object[key]
		if !exists || bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return false
		}
	}
	return true
}

func duplicateJSONKey(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	return walkJSON(decoder) != nil || func() bool {
		_, err := decoder.Token()
		return err != io.EOF
	}()
}

func walkJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok {
				return ErrConfigInvalid
			}
			if _, exists := seen[key]; exists {
				return ErrConfigInvalid
			}
			seen[key] = struct{}{}
			if err = walkJSON(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err = walkJSON(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrConfigInvalid
	}
	_, err = decoder.Token()
	return err
}
