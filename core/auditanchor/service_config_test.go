package auditanchor

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func validSignerServiceConfigJSON(t *testing.T) string {
	t.Helper()
	key := testKMSKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	digest := sha256.Sum256(der)
	value, err := json.Marshal(map[string]any{
		"version":                    1,
		"provider_profile_id":        "alibaba-kms-audit-production",
		"state_profile_id":           "audit-sequence-state-production",
		"ecs_ram_role_name":          "broker-audit-kms",
		"kms_endpoint":               "kst-audit01.cryptoservice.kms.aliyuncs.com",
		"kms_ca_sha256":              strings.Repeat("a", 64),
		"kms_allowed_cidrs":          []string{"10.42.7.8/32", "fd00:42::8/128"},
		"algorithm":                  "ecdsa-p256-sha256",
		"key_id":                     "kms-audit-key-1",
		"key_version_id":             testKMSKeyVersionID,
		"stream_id":                  "production-audit",
		"public_key_spki_der_base64": base64.StdEncoding.EncodeToString(der),
		"public_key_sha256":          hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return string(value)
}

func TestParseSignerServiceConfigBindsNonSecretAuthority(t *testing.T) {
	config, err := ParseSignerServiceConfig(strings.NewReader(validSignerServiceConfigJSON(t)))
	if err != nil {
		t.Fatalf("parse signer config: %v", err)
	}
	if config.Version != SignerServiceConfigVersion || config.ProviderProfileID != "alibaba-kms-audit-production" ||
		config.StateProfileID != "audit-sequence-state-production" || config.ECSRAMRoleName != "broker-audit-kms" ||
		config.KMSEndpoint != "kst-audit01.cryptoservice.kms.aliyuncs.com" ||
		config.KMSCASHA256 != strings.Repeat("a", 64) || config.KeyVersionID != testKMSKeyVersionID ||
		config.PublicKeySHA256 == "" || config.PublicKey == nil {
		t.Fatalf("unexpected config: %#v", config)
	}
	if config.Anchor != (Config{Algorithm: "ecdsa-p256-sha256", KeyID: "kms-audit-key-1", StreamID: "production-audit"}) {
		t.Fatalf("unexpected anchor binding: %#v", config.Anchor)
	}
	wantCIDRs := []netip.Prefix{netip.MustParsePrefix("10.42.7.8/32"), netip.MustParsePrefix("fd00:42::8/128")}
	if len(config.KMSAllowedCIDRs) != len(wantCIDRs) || config.KMSAllowedCIDRs[0] != wantCIDRs[0] || config.KMSAllowedCIDRs[1] != wantCIDRs[1] {
		t.Fatalf("unexpected KMS CIDRs: %#v", config.KMSAllowedCIDRs)
	}

	cloned, err := ValidateSignerServiceConfig(config)
	if err != nil {
		t.Fatalf("validate signer config: %v", err)
	}
	config.KMSAllowedCIDRs[0] = netip.MustParsePrefix("10.0.0.1/32")
	config.PublicKey.X.SetInt64(1)
	if cloned.KMSAllowedCIDRs[0] != wantCIDRs[0] || cloned.PublicKey.X.Int64() == 1 {
		t.Fatal("validated signer configuration aliases caller-owned data")
	}
}

func TestParseSignerServiceConfigRejectsUnsafeOrCredentialFields(t *testing.T) {
	valid := validSignerServiceConfigJSON(t)
	tests := map[string]string{
		"wrong version":        strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"shared state profile": strings.Replace(valid, `"state_profile_id":"audit-sequence-state-production"`, `"state_profile_id":"alibaba-kms-audit-production"`, 1),
		"wrong algorithm":      strings.Replace(valid, `"algorithm":"ecdsa-p256-sha256"`, `"algorithm":"ed25519"`, 1),
		"unsafe key version":   strings.Replace(valid, `"key_version_id":"`+testKMSKeyVersionID+`"`, `"key_version_id":"version.with.dot"`, 1),
		"public endpoint":      strings.Replace(valid, `kst-audit01.cryptoservice.kms.aliyuncs.com`, `kms.cn-hangzhou.aliyuncs.com`, 1),
		"public network":       strings.Replace(valid, `10.42.7.8/32`, `8.8.8.8/32`, 1),
		"broad network":        strings.Replace(valid, `10.42.7.8/32`, `10.42.0.0/16`, 1),
		"bad public key hash":  strings.Replace(valid, `"public_key_sha256":"`, `"public_key_sha256":"0`, 1),
		"null role":            strings.Replace(valid, `"ecs_ram_role_name":"broker-audit-kms"`, `"ecs_ram_role_name":null`, 1),
		"unknown credential":   strings.TrimSuffix(valid, "}") + `,"access_key_secret":"forbidden"}`,
		"duplicate version":    strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSignerServiceConfig(strings.NewReader(value)); err == nil {
				t.Fatal("unsafe signer configuration was accepted")
			}
		})
	}
	if _, err := ParseSignerServiceConfig(nil); err == nil {
		t.Fatal("nil signer configuration was accepted")
	}
	if _, err := ParseSignerServiceConfig(bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxSignerServiceConfigBytes+1))); err == nil {
		t.Fatal("oversized signer configuration was accepted")
	}
}

func TestLoadSignerServiceConfigRequiresFixedPath(t *testing.T) {
	if _, err := LoadSignerServiceConfigFile(t.TempDir() + "/signer.json"); err == nil {
		t.Fatal("non-production signer config path was accepted")
	}
}
