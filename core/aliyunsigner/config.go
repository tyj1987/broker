package aliyunsigner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/tyj1987/broker/core/internal/trustedconfig"
)

const (
	ServiceConfigVersion  = 1
	MaxServiceConfigBytes = 32 * 1024
	serviceConfigPath     = "/etc/secret-broker/providers/aliyun-signer.json"
	serviceConfigDir      = "/etc/secret-broker/providers"
)

var ErrServiceConfigInvalid = errors.New("aliyun signer service configuration is invalid")

type ServiceConfig struct {
	Version                   int
	ProviderProfileID         string
	Bindings                  []Binding
	AuthorityGenerationSHA256 string
}

type serviceConfigWire struct {
	Version           int           `json:"version"`
	ProviderProfileID string        `json:"provider_profile_id"`
	Bindings          []bindingWire `json:"bindings"`
}

type bindingWire struct {
	AccountRef  string `json:"account_ref"`
	Environment string `json:"environment"`
	ResourceRef string `json:"resource_ref"`
	RegionID    string `json:"region_id"`
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
	if json.Unmarshal(value, &raw) != nil || !exactNonNullKeys(raw, "version", "provider_profile_id", "bindings") {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	var rawBindings []json.RawMessage
	if json.Unmarshal(raw["bindings"], &rawBindings) != nil || len(rawBindings) < 1 || len(rawBindings) > 64 {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	for _, binding := range rawBindings {
		var object map[string]json.RawMessage
		if json.Unmarshal(binding, &object) != nil ||
			!exactNonNullKeys(object, "account_ref", "environment", "resource_ref", "region_id") {
			return ServiceConfig{}, ErrServiceConfigInvalid
		}
	}
	var wire serviceConfigWire
	if decodeStrict(value, &wire) != nil || wire.Version != ServiceConfigVersion ||
		!accountRefPattern.MatchString(wire.ProviderProfileID) {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	bindings := make([]Binding, 0, len(wire.Bindings))
	for _, binding := range wire.Bindings {
		bindings = append(bindings, Binding{
			AccountRef: binding.AccountRef, Environment: binding.Environment,
			ResourceRef: binding.ResourceRef, RegionID: binding.RegionID,
		})
	}
	if _, err = NewBindingSet(bindings); err != nil {
		return ServiceConfig{}, ErrServiceConfigInvalid
	}
	digest := sha256.Sum256(value)
	return ServiceConfig{
		Version: wire.Version, ProviderProfileID: wire.ProviderProfileID, Bindings: bindings,
		AuthorityGenerationSHA256: hex.EncodeToString(digest[:]),
	}, nil
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
