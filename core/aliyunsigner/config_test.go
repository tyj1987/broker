package aliyunsigner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const validConfig = `{"version":1,"provider_profile_id":"aliyun-isolated-readonly","bindings":[{"account_ref":"aliyun-test","environment":"staging","resource_ref":"readonly-account","region_id":"cn-hangzhou"}]}`

func TestParseServiceConfigBindsGenerationToExactBytes(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("ParseServiceConfig: %v", err)
	}
	digest := sha256.Sum256([]byte(validConfig))
	if config.AuthorityGenerationSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("generation is not the exact configuration digest")
	}
	if config.ProviderProfileID != "aliyun-isolated-readonly" || len(config.Bindings) != 1 ||
		config.Bindings[0].RegionID != "cn-hangzhou" {
		t.Fatalf("unexpected config: %#v", config)
	}
	changed, err := ParseServiceConfig(strings.NewReader(validConfig + "\n"))
	if err != nil || changed.AuthorityGenerationSHA256 == config.AuthorityGenerationSHA256 {
		t.Fatal("byte-level configuration change did not change generation")
	}
}

func TestParseServiceConfigRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	cases := []string{
		``, `null`, `[]`,
		`{"version":1,"version":1,"provider_profile_id":"profile","bindings":[]}`,
		`{"version":1,"provider_profile_id":"profile","bindings":[],"access_key":"value"}`,
		`{"version":1,"provider_profile_id":null,"bindings":[]}`,
		`{"version":2,"provider_profile_id":"profile","bindings":[{"account_ref":"a","environment":"staging","resource_ref":"r","region_id":"cn-hangzhou"}]}`,
		`{"version":1,"provider_profile_id":"profile","bindings":[{"account_ref":"a","environment":"staging","resource_ref":"r","region_id":"cn-hangzhou","secret":"value"}]}`,
		`{"version":1,"provider_profile_id":"profile","bindings":[{"account_ref":"a","environment":"staging","resource_ref":"r","region_id":"cn-hangzhou"},{"account_ref":"a","environment":"staging","resource_ref":"r","region_id":"cn-hangzhou"}]}`,
	}
	for _, value := range cases {
		if _, err := ParseServiceConfig(strings.NewReader(value)); err == nil {
			t.Fatalf("accepted invalid configuration: %q", value)
		}
	}
	if _, err := ParseServiceConfig(nil); err == nil {
		t.Fatal("accepted nil reader")
	}
	oversized := strings.Repeat("x", MaxServiceConfigBytes+1)
	if _, err := ParseServiceConfig(strings.NewReader(oversized)); err == nil {
		t.Fatal("accepted oversized configuration")
	}
}

func TestLoadServiceConfigRejectsNonProductionPath(t *testing.T) {
	if _, err := LoadServiceConfigFile("aliyun-signer.json"); err == nil {
		t.Fatal("accepted non-production path")
	}
}
