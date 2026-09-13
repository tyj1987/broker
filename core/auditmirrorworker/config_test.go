package auditmirrorworker

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validConfigJSON(t *testing.T) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(map[string]any{
		"version": ConfigVersion, "stream_id": "broker-production", "prefix": "audit-anchors/v1",
		"profile_id": "tencent-mirror-production", "bucket": "broker-audit-mirror-1250000000",
		"region": "ap-singapore", "trusted_keys": []map[string]any{{
			"key_id": "worker-key", "public_key_spki_base64": base64.StdEncoding.EncodeToString(der),
			"valid_from_sequence": 1, "valid_through_sequence": 0,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestParseConfigAcceptsOnlyBoundNonSecretConfiguration(t *testing.T) {
	config, err := ParseConfig(bytes.NewReader(validConfigJSON(t)))
	if err != nil || config.StreamID != "broker-production" || config.Region != "ap-singapore" ||
		config.Bucket != "broker-audit-mirror-1250000000" || len(config.TrustedKeys) != 1 {
		t.Fatalf("config = %#v, %v", config, err)
	}
}

func TestParseConfigFailsClosed(t *testing.T) {
	valid := validConfigJSON(t)
	mutated := func(change func(map[string]any)) []byte {
		clone := map[string]any{}
		if err := json.Unmarshal(valid, &clone); err != nil {
			t.Fatal(err)
		}
		change(clone)
		value, _ := json.Marshal(clone)
		return value
	}
	tests := map[string][]byte{
		"empty":               nil,
		"oversized":           bytes.Repeat([]byte(" "), MaxConfigBytes+1),
		"unknown":             mutated(func(value map[string]any) { value["endpoint"] = "https://example.invalid" }),
		"secret":              mutated(func(value map[string]any) { value["credential"] = "forbidden" }),
		"version":             mutated(func(value map[string]any) { value["version"] = float64(2) }),
		"stream":              mutated(func(value map[string]any) { value["stream_id"] = "../bad" }),
		"prefix":              mutated(func(value map[string]any) { value["prefix"] = "../bad" }),
		"profile":             mutated(func(value map[string]any) { value["profile_id"] = "bad profile" }),
		"bucket":              mutated(func(value map[string]any) { value["bucket"] = "BAD" }),
		"region":              mutated(func(value map[string]any) { value["region"] = "BAD" }),
		"null-keys":           mutated(func(value map[string]any) { value["trusted_keys"] = nil }),
		"empty-keys":          mutated(func(value map[string]any) { value["trusted_keys"] = []any{} }),
		"duplicate-top-level": []byte(`{"version":1,"version":1}`),
		"duplicate-key-field": bytes.Replace(valid, []byte(`"key_id":"worker-key"`), []byte(`"key_id":"worker-key","key_id":"worker-key"`), 1),
		"bad-spki": mutated(func(value map[string]any) {
			value["trusted_keys"].([]any)[0].(map[string]any)["public_key_spki_base64"] = "not-base64"
		}),
		"duplicate-key-id": mutated(func(value map[string]any) {
			keys := value["trusted_keys"].([]any)
			value["trusted_keys"] = append(keys, keys[0])
		}),
		"overlapping-epochs": mutated(func(value map[string]any) {
			keys := value["trusted_keys"].([]any)
			second := map[string]any{}
			for key, field := range keys[0].(map[string]any) {
				second[key] = field
			}
			second["key_id"] = "second-key"
			second["valid_from_sequence"] = float64(2)
			value["trusted_keys"] = append(keys, second)
		}),
		"trailing": append(append([]byte{}, valid...), []byte("\n{}")...),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if config, err := ParseConfig(bytes.NewReader(value)); !errors.Is(err, ErrConfigInvalid) || config.TrustedKeys != nil {
				t.Fatalf("config = %#v, %v", config, err)
			}
		})
	}
	if config, err := ParseConfig(nil); !errors.Is(err, ErrConfigInvalid) || config.TrustedKeys != nil {
		t.Fatalf("nil config = %#v, %v", config, err)
	}
	if config, err := LoadConfigFile("/tmp/mirror-worker.json"); !errors.Is(err, ErrConfigInvalid) || config.TrustedKeys != nil {
		t.Fatalf("untrusted file = %#v, %v", config, err)
	}
	if !strings.Contains(ErrConfigInvalid.Error(), "configuration") {
		t.Fatal("stable configuration error is missing")
	}
}
