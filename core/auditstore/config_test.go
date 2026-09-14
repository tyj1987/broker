package auditstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testServicePublicKey() *ecdsa.PublicKey {
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func canonicalConfigPublicKey(publicKey *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func validServiceConfigJSON() string {
	return fmt.Sprintf(`{
  "version": 1,
  "stream_id": "broker-production",
  "prefix": "audit-anchors/v1",
  "oss": {"bucket":"broker-audit-primary","region":"cn-hangzhou","provider_profile_id":"aliyun-audit-account"},
  "cos": {"bucket":"broker-audit-mirror-1250000000","region":"ap-guangzhou","provider_profile_id":"tencent-dr-account"},
  "trusted_keys": [{"key_id":"audit-key-2026","public_key_spki_base64":%q,"valid_from_sequence":1,"valid_through_sequence":0}],
  "list_page_size": 1000,
  "max_list_pages": 128
}`, canonicalConfigPublicKey(testServicePublicKey()))
}

func TestParseServiceConfigAcceptsOnlyStrictNonSecretSchema(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatalf("ParseServiceConfig() error = %v", err)
	}
	if config.Version != 1 || config.StreamID != "broker-production" ||
		config.OSS.ProviderProfileID != "aliyun-audit-account" ||
		config.COS.ProviderProfileID != "tencent-dr-account" || len(config.TrustedKeys) != 1 {
		t.Fatalf("config = %#v", config)
	}
	config.TrustedKeys[0].PublicKey.X.SetInt64(0)
	again, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil || again.TrustedKeys[0].PublicKey.X.Sign() == 0 {
		t.Fatal("parsed public keys must not share mutable coordinates")
	}
}

func TestParseServiceConfigRejectsAmbiguousOrSensitiveInputs(t *testing.T) {
	valid := validServiceConfigJSON()
	cases := map[string]string{
		"empty":             "",
		"unknown root":      strings.Replace(valid, `"max_list_pages": 128`, `"max_list_pages": 128, "credential_file":"/tmp/key"`, 1),
		"provider endpoint": strings.Replace(valid, `"provider_profile_id":"aliyun-audit-account"`, `"provider_profile_id":"aliyun-audit-account","endpoint":"https://example.invalid"`, 1),
		"access key":        strings.Replace(valid, `"provider_profile_id":"aliyun-audit-account"`, `"provider_profile_id":"aliyun-audit-account","access_key":"forbidden"`, 1),
		"missing root field": strings.Replace(valid, `  "prefix": "audit-anchors/v1",
`, "", 1),
		"duplicate root field":  strings.Replace(valid, `"version": 1`, `"version": 1, "version": 1`, 1),
		"same identity profile": strings.Replace(valid, "tencent-dr-account", "aliyun-audit-account", 1),
		"bad public key":        strings.Replace(valid, canonicalConfigPublicKey(testServicePublicKey()), "not-base64", 1),
		"bad region":            strings.Replace(valid, "cn-hangzhou", "https://oss.invalid", 1),
		"bad prefix":            strings.Replace(valid, "audit-anchors/v1", "audit-anchors/../v1", 1),
		"page size zero":        strings.Replace(valid, `"list_page_size": 1000`, `"list_page_size": 0`, 1),
		"too many pages":        strings.Replace(valid, `"max_list_pages": 128`, `"max_list_pages": 513`, 1),
		"key starts at zero":    strings.Replace(valid, `"valid_from_sequence":1`, `"valid_from_sequence":0`, 1),
		"missing key field":     strings.Replace(valid, `,"valid_through_sequence":0`, "", 1),
		"unknown key field":     strings.Replace(valid, `"valid_through_sequence":0`, `"valid_through_sequence":0,"private_key":"forbidden"`, 1),
		"null version":          strings.Replace(valid, `"version": 1`, `"version": null`, 1),
		"null stream":           strings.Replace(valid, `"stream_id": "broker-production"`, `"stream_id": null`, 1),
		"null prefix":           strings.Replace(valid, `"prefix": "audit-anchors/v1"`, `"prefix": null`, 1),
		"null provider":         strings.Replace(valid, `"oss": {"bucket":"broker-audit-primary","region":"cn-hangzhou","provider_profile_id":"aliyun-audit-account"}`, `"oss": null`, 1),
		"null provider bucket":  strings.Replace(valid, `"bucket":"broker-audit-primary"`, `"bucket":null`, 1),
		"null provider region":  strings.Replace(valid, `"region":"cn-hangzhou"`, `"region":null`, 1),
		"null provider profile": strings.Replace(valid, `"provider_profile_id":"aliyun-audit-account"`, `"provider_profile_id":null`, 1),
		"null keys":             strings.Replace(valid, `"trusted_keys": [{"key_id":"audit-key-2026","public_key_spki_base64":`+fmt.Sprintf("%q", canonicalConfigPublicKey(testServicePublicKey()))+`,"valid_from_sequence":1,"valid_through_sequence":0}]`, `"trusted_keys": null`, 1),
		"null key id":           strings.Replace(valid, `"key_id":"audit-key-2026"`, `"key_id":null`, 1),
		"null key material":     strings.Replace(valid, `"public_key_spki_base64":`+fmt.Sprintf("%q", canonicalConfigPublicKey(testServicePublicKey())), `"public_key_spki_base64":null`, 1),
		"null key start":        strings.Replace(valid, `"valid_from_sequence":1`, `"valid_from_sequence":null`, 1),
		"null key end":          strings.Replace(valid, `"valid_through_sequence":0`, `"valid_through_sequence":null`, 1),
		"null page size":        strings.Replace(valid, `"list_page_size": 1000`, `"list_page_size": null`, 1),
		"null page limit":       strings.Replace(valid, `"max_list_pages": 128`, `"max_list_pages": null`, 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseServiceConfig(strings.NewReader(value)); !errors.Is(err, ErrServiceConfigInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := ParseServiceConfig(strings.NewReader(strings.Repeat(" ", MaxServiceConfigBytes+1))); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestServiceConfigRejectsDuplicateAndOverlappingKeyEpochs(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	duplicate := config.TrustedKeys[0]
	config.TrustedKeys = append(config.TrustedKeys, duplicate)
	if _, err := cloneServiceConfig(config); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("duplicate error = %v", err)
	}
	config.TrustedKeys[1].KeyID = "audit-key-next"
	config.TrustedKeys[0].ValidThroughSequence = 5
	config.TrustedKeys[1].ValidFromSequence = 5
	config.TrustedKeys[1].ValidThroughSequence = 0
	if _, err := cloneServiceConfig(config); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("overlap error = %v", err)
	}
	config.TrustedKeys[1].ValidFromSequence = 6
	if _, err := cloneServiceConfig(config); err != nil {
		t.Fatalf("non-overlapping epochs error = %v", err)
	}
}

func TestLoadServiceConfigFileRejectsMissingEmptyAndSymlinkedFiles(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "store.json")
	if err := os.WriteFile(validPath, []byte(validServiceConfigJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServiceConfigFile(validPath); runtime.GOOS == "linux" {
		if !errors.Is(err, ErrServiceConfigInvalid) {
			t.Fatalf("untrusted Linux path error = %v", err)
		}
	} else if err != nil {
		t.Fatalf("LoadServiceConfigFile() error = %v", err)
	}
	for _, path := range []string{"", filepath.Join(directory, "missing.json"), directory} {
		if _, err := LoadServiceConfigFile(path); !errors.Is(err, ErrServiceConfigInvalid) {
			t.Fatalf("path %q error = %v", path, err)
		}
	}
	emptyPath := filepath.Join(directory, "empty.json")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServiceConfigFile(emptyPath); !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("empty error = %v", err)
	}
	linkPath := filepath.Join(directory, "linked.json")
	if err := os.Symlink(validPath, linkPath); err == nil {
		if _, err := LoadServiceConfigFile(linkPath); !errors.Is(err, ErrServiceConfigInvalid) {
			t.Fatalf("symlink error = %v", err)
		}
	}
}
