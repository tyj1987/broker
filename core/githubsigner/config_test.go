package githubsigner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func validConfig(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	return fmt.Sprintf(`{"version":2,"provider_profile_id":"github-isolated-readonly","bindings":[{"account_ref":"github-test","environment":"staging","client_id":"123456","kms_key_id":"key/example","kms_key_version_id":"v1","public_key_spki_der_base64":"%s","public_key_sha256":"%s"}]}`,
		base64.StdEncoding.EncodeToString(der), hex.EncodeToString(digest[:]))
}

func TestParseServiceConfigBindsGenerationToExactBytes(t *testing.T) {
	encoded := validConfig(t)
	config, err := ParseServiceConfig(strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("ParseServiceConfig: %v", err)
	}
	digest := sha256.Sum256([]byte(encoded))
	if config.AuthorityGenerationSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("generation is not the exact configuration digest")
	}
	if config.ProviderProfileID != "github-isolated-readonly" || len(config.Bindings) != 1 ||
		config.Bindings[0].ClientID != "123456" {
		t.Fatalf("unexpected config: %#v", config)
	}
	if len(config.SigningAuthorities) != 1 || config.SigningAuthorities[0].PublicKey.N.BitLen() != 2048 {
		t.Fatal("signing authority was not parsed")
	}
	changed, err := ParseServiceConfig(strings.NewReader(encoded + "\n"))
	if err != nil || changed.AuthorityGenerationSHA256 == config.AuthorityGenerationSHA256 {
		t.Fatal("byte-level configuration change did not change generation")
	}
}

func TestParseServiceConfigRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	valid := validConfig(t)
	cases := []string{
		``, `null`, `[]`,
		`{"version":2,"version":2,"provider_profile_id":"profile","bindings":[]}`,
		strings.Replace(valid, `"bindings":`, `"private_key":"value","bindings":`, 1),
		strings.Replace(valid, `"provider_profile_id":"github-isolated-readonly"`, `"provider_profile_id":null`, 1),
		strings.Replace(valid, `"version":2`, `"version":1`, 1),
		strings.Replace(valid, `"kms_key_id":"key/example"`, `"kms_key_id":"key/example","token":"value"`, 1),
		strings.Replace(valid, `"public_key_sha256":"`, `"public_key_sha256":"0`, 1),
		strings.Replace(valid, `"kms_key_version_id":"v1"`, `"kms_key_version_id":null`, 1),
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
