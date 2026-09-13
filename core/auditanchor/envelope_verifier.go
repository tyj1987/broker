package auditanchor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"time"
)

// EnvelopeMetadata is the bounded, non-secret subset of a validated audit
// anchor envelope needed by the independently isolated storage workload.
type EnvelopeMetadata struct {
	StreamID             string
	Sequence             int64
	PreviousAnchorDigest string
	PayloadDigest        string
	CapturedAt           time.Time
}

// EnvelopeVerifier verifies canonical audit-anchor envelopes against a fixed
// stream and a sequence-bounded P-256 trust set. It never signs an envelope and
// has no provider or storage capability.
type EnvelopeVerifier struct {
	streamID    string
	trustedKeys map[string]TrustedSigningKey
}

func NewEnvelopeVerifier(streamID string, trustedKeys map[string]TrustedSigningKey) (*EnvelopeVerifier, error) {
	cloned, valid := cloneTrustedSigningKeys(trustedKeys)
	if !idPattern.MatchString(streamID) || !valid {
		return nil, errors.New("audit anchor envelope verifier configuration is invalid")
	}
	return &EnvelopeVerifier{streamID: streamID, trustedKeys: cloned}, nil
}

// Verify rejects malformed, non-canonical, wrong-stream, out-of-epoch and
// incorrectly signed envelopes. The returned bytes are the canonical form and
// are safe to pass to the immutable writer or bounded local protocol.
func (verifier *EnvelopeVerifier) Verify(value []byte) (EnvelopeMetadata, []byte, error) {
	if verifier == nil || !idPattern.MatchString(verifier.streamID) || len(verifier.trustedKeys) == 0 {
		return EnvelopeMetadata{}, nil, ErrObjectWriteRejected
	}
	envelope, canonical, err := parseStoredEnvelope(value)
	if err != nil || envelope.Payload.StreamID != verifier.streamID ||
		!verifyStoredEnvelopeSignatureWithTrust(verifier.streamID, verifier.trustedKeys, envelope) {
		return EnvelopeMetadata{}, nil, ErrObjectWriteRejected
	}
	return EnvelopeMetadata{
		StreamID:             envelope.Payload.StreamID,
		Sequence:             envelope.Payload.Sequence,
		PreviousAnchorDigest: envelope.Payload.PreviousAnchorDigest,
		PayloadDigest:        envelope.PayloadDigest,
		CapturedAt:           envelope.Payload.CapturedAt,
	}, canonical, nil
}

func cloneTrustedSigningKeys(source map[string]TrustedSigningKey) (map[string]TrustedSigningKey, bool) {
	if len(source) < 1 || len(source) > 16 {
		return nil, false
	}
	cloned := make(map[string]TrustedSigningKey, len(source))
	for keyID, trustedKey := range source {
		if !idPattern.MatchString(keyID) || !validP256PublicKey(trustedKey.PublicKey) ||
			trustedKey.ValidFromSequence < 1 ||
			(trustedKey.ValidThroughSequence != 0 && trustedKey.ValidThroughSequence < trustedKey.ValidFromSequence) {
			return nil, false
		}
		trustedKey.PublicKey = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).Set(trustedKey.PublicKey.X),
			Y:     new(big.Int).Set(trustedKey.PublicKey.Y),
		}
		cloned[keyID] = trustedKey
	}
	return cloned, true
}
