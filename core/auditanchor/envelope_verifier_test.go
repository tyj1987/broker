package auditanchor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestTrustedKeyGenerationIsDeterministicAndBoundToCompleteTrust(t *testing.T) {
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]TrustedSigningKey{
		"key-b": {PublicKey: &second.PublicKey, ValidFromSequence: 10},
		"key-a": {PublicKey: &writerPrivateKey.PublicKey, ValidFromSequence: 1, ValidThroughSequence: 9},
	}
	first, err := TrustedKeyGeneration(keys)
	if err != nil || first == ([32]byte{}) {
		t.Fatalf("generation = %x, %v", first, err)
	}
	reordered := map[string]TrustedSigningKey{"key-a": keys["key-a"], "key-b": keys["key-b"]}
	again, err := TrustedKeyGeneration(reordered)
	if err != nil || again != first {
		t.Fatal("map iteration order changed trust generation")
	}
	changed := map[string]TrustedSigningKey{"key-a": keys["key-a"], "key-b": keys["key-b"]}
	value := changed["key-b"]
	value.ValidThroughSequence = 20
	changed["key-b"] = value
	different, err := TrustedKeyGeneration(changed)
	if err != nil || different == first {
		t.Fatal("trust epoch change did not change generation")
	}
	if invalid, err := TrustedKeyGeneration(nil); err == nil || invalid != ([32]byte{}) {
		t.Fatalf("invalid generation = %x, %v", invalid, err)
	}
	overlap := map[string]TrustedSigningKey{
		"key-a": keys["key-a"],
		"key-b": {PublicKey: &second.PublicKey, ValidFromSequence: 9},
	}
	if invalid, err := TrustedKeyGeneration(overlap); err == nil || invalid != ([32]byte{}) {
		t.Fatalf("overlapping generation = %x, %v", invalid, err)
	}
	if verifier, err := NewEnvelopeVerifier("broker-production", overlap); err == nil || verifier != nil {
		t.Fatal("overlapping verifier trust was accepted")
	}
}

func TestEnvelopeVerifierReturnsCanonicalBoundMetadata(t *testing.T) {
	config := validWriterTestConfig()
	verifier, err := NewEnvelopeVerifier(config.StreamID, config.TrustedKeys)
	if err != nil {
		t.Fatal(err)
	}
	value := validEnvelopeJSON(t)
	metadata, canonical, err := verifier.Verify(value)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.StreamID != config.StreamID || metadata.Sequence != 1 ||
		metadata.PreviousAnchorDigest != stringsOf('0', 64) || metadata.PayloadDigest == "" ||
		metadata.CapturedAt.IsZero() || bytes.Equal(value, canonical) {
		t.Fatalf("unexpected verified envelope: %#v", metadata)
	}
	if _, secondCanonical, err := verifier.Verify(canonical); err != nil || !bytes.Equal(canonical, secondCanonical) {
		t.Fatal("canonical envelope did not verify idempotently")
	}
}

func TestEnvelopeVerifierClonesTrustAndRejectsTampering(t *testing.T) {
	config := validWriterTestConfig()
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).Set(writerPrivateKey.PublicKey.X),
		Y:     new(big.Int).Set(writerPrivateKey.PublicKey.Y),
	}
	config.TrustedKeys = map[string]TrustedSigningKey{
		writerKeyID: {PublicKey: publicKey, ValidFromSequence: 1},
	}
	verifier, err := NewEnvelopeVerifier(config.StreamID, config.TrustedKeys)
	if err != nil {
		t.Fatal(err)
	}
	publicKey.X.SetInt64(1)
	if _, _, err := verifier.Verify(validEnvelopeJSON(t)); err != nil {
		t.Fatal("caller mutation changed verifier trust")
	}
	if _, _, err := verifier.Verify(tamperEnvelopeSignature(t, validEnvelopeJSON(t))); err == nil {
		t.Fatal("tampered signature was accepted")
	}
}

func TestEnvelopeVerifierRejectsInvalidConfigurationAndEpoch(t *testing.T) {
	valid := validWriterTestConfig()
	invalidKeys := map[string]TrustedSigningKey{
		writerKeyID: {PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, ValidFromSequence: 1},
	}
	for _, test := range []struct {
		stream string
		keys   map[string]TrustedSigningKey
	}{
		{"", valid.TrustedKeys},
		{valid.StreamID, nil},
		{valid.StreamID, invalidKeys},
	} {
		if verifier, err := NewEnvelopeVerifier(test.stream, test.keys); err == nil || verifier != nil {
			t.Fatal("invalid verifier configuration was accepted")
		}
	}

	future := map[string]TrustedSigningKey{
		writerKeyID: {PublicKey: &writerPrivateKey.PublicKey, ValidFromSequence: 2},
	}
	verifier, err := NewEnvelopeVerifier(valid.StreamID, future)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifier.Verify(validEnvelopeJSON(t)); err == nil {
		t.Fatal("out-of-epoch envelope was accepted")
	}
}
