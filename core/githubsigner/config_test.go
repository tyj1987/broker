package githubsigner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const validConfig = `{"version":1,"provider_profile_id":"github-isolated-readonly","bindings":[{"account_ref":"github-test","environment":"staging","client_id":"123456"}]}`

func TestParseServiceConfigBindsGenerationToExactBytes(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validConfig))
	if err != nil {
		t.Fatalf("ParseServiceConfig: %v", err)
	}
	digest := sha256.Sum256([]byte(validConfig))
	if config.AuthorityGenerationSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("generation is not the exact configuration digest")
	}
	if config.ProviderProfileID != "github-isolated-readonly" || len(config.Bindings) != 1 ||
		config.Bindings[0].ClientID != "123456" {
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
		`{"version":1,"provider_profile_id":"profile","bindings":[],"private_key":"value"}`,
		`{"version":1,"provider_profile_id":null,"bindings":[]}`,
		`{"version":2,"provider_profile_id":"profile","bindings":[{"account_ref":"a","environment":"staging","client_id":"123"}]}`,
		`{"version":1,"provider_profile_id":"profile","bindings":[{"account_ref":"a","environment":"staging","client_id":"123","token":"value"}]}`,
		`{"version":1,"provider_profile_id":"profile","bindings":[{"account_ref":"a","environment":"staging","client_id":"123"},{"account_ref":"a","environment":"staging","client_id":"123"}]}`,
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
	if _, err := LoadServiceConfigFile("github-signer.json"); err == nil {
		t.Fatal("accepted non-production path")
	}
}
