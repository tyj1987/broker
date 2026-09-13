package auditanchor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

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
