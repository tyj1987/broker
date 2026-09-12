package auditchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
)

func sealTestEvent(t *testing.T, fields map[string]any, previous [digestBytes]byte) []byte {
	t.Helper()
	event := make(map[string]any, len(fields)+2)
	for name, value := range fields {
		event[name] = value
	}
	event["prev_hash"] = hex.EncodeToString(previous[:])
	unsigned, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	canonical := jsontext.Value(unsigned)
	if err := canonical.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	event["hash"] = hex.EncodeToString(digest[:])
	sealed, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func digestFromEvent(t *testing.T, raw []byte) [digestBytes]byte {
	t.Helper()
	var event struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	var digest [digestBytes]byte
	decoded, err := hex.DecodeString(event.Hash)
	if err != nil || len(decoded) != len(digest) {
		t.Fatalf("invalid test digest: %v", err)
	}
	copy(digest[:], decoded)
	return digest
}

func TestCanonicalEventAcceptsValidEvent(t *testing.T) {
	raw := sealTestEvent(t, map[string]any{
		"action": "read",
		"nested": map[string]any{"values": []any{nil, true, -0.0, 1e-7}},
	}, GenesisHash)
	want := digestFromEvent(t, raw)
	got, previous, err := canonicalEvent(raw, DefaultLimits().MaxDepth)
	if err != nil || got != want || previous != GenesisHash {
		t.Fatalf("canonicalEvent() = (%x, %x, %v)", got, previous, err)
	}
}

func TestCanonicalEventRejectsMalformedInput(t *testing.T) {
	valid := sealTestEvent(t, map[string]any{"action": "read"}, GenesisHash)
	tests := map[string][]byte{
		"not object":       []byte(`[]`),
		"invalid utf8":     append([]byte(`{"value":"`), 0xff, '"', '}'),
		"duplicate key":    []byte(`{"prev_hash":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("0", 64) + `","x":1,"x":1}`),
		"lone surrogate":   []byte(`{"prev_hash":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("0", 64) + `","x":"\ud800"}`),
		"missing hash":     []byte(`{"prev_hash":"` + strings.Repeat("0", 64) + `"}`),
		"missing previous": []byte(`{"hash":"` + strings.Repeat("0", 64) + `"}`),
		"uppercase digest": []byte(`{"prev_hash":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("A", 64) + `"}`),
		"wrong digest":     []byte(`{"prev_hash":"` + strings.Repeat("0", 64) + `","hash":"` + strings.Repeat("1", 64) + `"}`),
		"trailing value":   append(append([]byte{}, valid...), []byte(` {}`)...),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := canonicalEvent(raw, DefaultLimits().MaxDepth); !errors.Is(err, ErrChainInvalid) {
				t.Fatalf("error = %v, want ErrChainInvalid", err)
			}
		})
	}
}

func TestCanonicalEventEnforcesDepth(t *testing.T) {
	raw := sealTestEvent(t, map[string]any{"nested": map[string]any{"deeper": true}}, GenesisHash)
	if _, _, err := canonicalEvent(raw, 1); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("error = %v, want ErrChainInvalid", err)
	}
	if _, _, err := canonicalEvent(raw, 0); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("zero-depth error = %v, want ErrChainInvalid", err)
	}
}

func TestDecodeDigestRejectsInvalidTargets(t *testing.T) {
	var target [digestBytes]byte
	for _, raw := range [][]byte{[]byte(`null`), []byte(`"short"`), []byte(`"` + strings.Repeat("g", 64) + `"`)} {
		if err := decodeDigest(raw, &target); !errors.Is(err, ErrChainInvalid) {
			t.Fatalf("decodeDigest(%s) = %v", raw, err)
		}
	}
	if err := decodeDigest([]byte(`"`+strings.Repeat("0", 64)+`"`), nil); !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("nil target error = %v", err)
	}
}
