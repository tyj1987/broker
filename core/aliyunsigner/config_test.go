package aliyunsigner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const validConfig = `{"version":2,"provider_profile_id":"aliyun-isolated-readonly","ecs_ram_role_name":"broker-isolated-readonly","bindings":[{"account_ref":"aliyun-test","environment":"staging","resource_ref":"readonly-account","region_id":"cn-hangzhou"}]}`

func TestParseServiceConfigBindsGenerationToExactBytes(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("ParseServiceConfig: %v", err)
	}
	digest := sha256.Sum256([]byte(validConfig))
	if config.AuthorityGenerationSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("generation is not the exact configuration digest")
	}
	if config.ProviderProfileID != "aliyun-isolated-readonly" || config.ECSRAMRoleName != "broker-isolated-readonly" || len(config.Bindings) != 1 ||
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
		`{"version":2,"version":2,"provider_profile_id":"profile","bindings":[]}`,
		strings.Replace(validConfig, `"bindings":`, `"access_key":"value","bindings":`, 1),
		strings.Replace(validConfig, `"provider_profile_id":"aliyun-isolated-readonly"`, `"provider_profile_id":null`, 1),
		strings.Replace(validConfig, `"version":2`, `"version":1`, 1),
		strings.Replace(validConfig, `"region_id":"cn-hangzhou"`, `"region_id":"cn-hangzhou","secret":"value"`, 1),
		strings.Replace(validConfig, `"ecs_ram_role_name":"broker-isolated-readonly"`, `"ecs_ram_role_name":null`, 1),
		strings.Replace(validConfig, `"ecs_ram_role_name":"broker-isolated-readonly"`, `"ecs_ram_role_name":"bad role"`, 1),
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
