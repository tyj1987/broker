package auditanchor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
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

// TrustedKeyGeneration returns a deterministic digest of the complete trust
// set. It lets isolated workloads prove that their independently loaded
// verifier configuration is identical without exposing key material over IPC.
func TrustedKeyGeneration(trustedKeys map[string]TrustedSigningKey) ([sha256.Size]byte, error) {
	cloned, valid := cloneTrustedSigningKeys(trustedKeys)
	if !valid {
		return [sha256.Size]byte{}, errors.New("audit anchor trust generation is invalid")
	}
	type generationKey struct {
		KeyID                string `json:"key_id"`
		PublicKeySPKIBase64  string `json:"public_key_spki_base64"`
		ValidFromSequence    int64  `json:"valid_from_sequence"`
		ValidThroughSequence int64  `json:"valid_through_sequence"`
	}
	ordered := make([]string, 0, len(cloned))
	for keyID := range cloned {
		ordered = append(ordered, keyID)
	}
	sort.Slice(ordered, func(left, right int) bool {
		leftKey, rightKey := cloned[ordered[left]], cloned[ordered[right]]
		if leftKey.ValidFromSequence == rightKey.ValidFromSequence {
			return ordered[left] < ordered[right]
		}
		return leftKey.ValidFromSequence < rightKey.ValidFromSequence
	})
	canonical := make([]generationKey, 0, len(ordered))
	for _, keyID := range ordered {
		trustedKey := cloned[keyID]
		der, err := x509.MarshalPKIXPublicKey(trustedKey.PublicKey)
		if err != nil {
			return [sha256.Size]byte{}, errors.New("audit anchor trust generation is invalid")
		}
		canonical = append(canonical, generationKey{
			KeyID: keyID, PublicKeySPKIBase64: base64.StdEncoding.EncodeToString(der),
			ValidFromSequence:    trustedKey.ValidFromSequence,
			ValidThroughSequence: trustedKey.ValidThroughSequence,
		})
	}
	value, err := json.Marshal(canonical)
	if err != nil || len(value) == 0 {
		return [sha256.Size]byte{}, errors.New("audit anchor trust generation is invalid")
	}
	return sha256.Sum256(value), nil
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
	type epoch struct {
		keyID string
		key   TrustedSigningKey
	}
	epochs := make([]epoch, 0, len(cloned))
	for keyID, trustedKey := range cloned {
		epochs = append(epochs, epoch{keyID: keyID, key: trustedKey})
	}
	sort.Slice(epochs, func(left, right int) bool {
		if epochs[left].key.ValidFromSequence == epochs[right].key.ValidFromSequence {
			return epochs[left].keyID < epochs[right].keyID
		}
		return epochs[left].key.ValidFromSequence < epochs[right].key.ValidFromSequence
	})
	for index := 1; index < len(epochs); index++ {
		previous := epochs[index-1].key
		if previous.ValidThroughSequence == 0 ||
			previous.ValidThroughSequence >= epochs[index].key.ValidFromSequence {
			return nil, false
		}
	}
	return cloned, true
}
