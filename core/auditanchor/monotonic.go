package auditanchor

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
)

const DefaultStateAttempts = 4

var (
	ErrAnchorRejected   = errors.New("audit anchor rejected")
	ErrStateUnavailable = errors.New("audit anchor state unavailable")
)

// AnchorState is the minimum public state required to prevent a signer from
// issuing two different chain heads for one stream sequence. It contains no
// audit event body or credential material.
type AnchorState struct {
	StreamID      string
	Sequence      int64
	PayloadDigest [sha256.Size]byte
}

// AnchorStateStore must provide linearizable compare-and-swap semantics. A
// production implementation belongs to the independently administered signer
// workload and must persist outside the Broker host.
type AnchorStateStore interface {
	Load(context.Context, string) (AnchorState, bool, error)
	CompareAndSwap(context.Context, string, *AnchorState, AnchorState) (bool, error)
}

// MonotonicAuthorizer enforces contiguous, non-forking audit anchors. A retry
// of the exact same sequence and payload is idempotent; gaps, rewinds and
// conflicting payloads fail closed.
type MonotonicAuthorizer struct {
	Config      Config
	Store       AnchorStateStore
	MaxAttempts int
}

func NewMonotonicAuthorizer(config Config, store AnchorStateStore) (*MonotonicAuthorizer, error) {
	if !validConfig(config) || store == nil {
		return nil, errors.New("audit anchor authorizer configuration is invalid")
	}
	return &MonotonicAuthorizer{Config: config, Store: store, MaxAttempts: DefaultStateAttempts}, nil
}

func (authorizer *MonotonicAuthorizer) AuthorizeAnchor(ctx context.Context, request SignRequest) error {
	if authorizer == nil || ctx == nil || !validConfig(authorizer.Config) || authorizer.Store == nil ||
		authorizer.MaxAttempts < 1 || authorizer.MaxAttempts > 16 ||
		!validAuthorizedRequest(authorizer.Config, request) {
		return ErrAnchorRejected
	}

	for attempt := 0; attempt < authorizer.MaxAttempts; attempt++ {
		current, exists, err := authorizer.Store.Load(ctx, authorizer.Config.StreamID)
		if err != nil {
			return ErrStateUnavailable
		}
		if (exists && !validStoredState(authorizer.Config.StreamID, current)) ||
			(!exists && current != (AnchorState{})) {
			return ErrStateUnavailable
		}

		if exists && request.Sequence == current.Sequence {
			if request.PayloadDigest == current.PayloadDigest {
				return nil
			}
			return ErrAnchorRejected
		}
		if (!exists && request.Sequence != 1) ||
			(exists && (request.Sequence != current.Sequence+1 || request.PreviousDigest != current.PayloadDigest)) {
			return ErrAnchorRejected
		}

		next := AnchorState{
			StreamID: authorizer.Config.StreamID, Sequence: request.Sequence,
			PayloadDigest: request.PayloadDigest,
		}
		var expected *AnchorState
		if exists {
			copy := current
			expected = &copy
		}
		stored, err := authorizer.Store.CompareAndSwap(ctx, authorizer.Config.StreamID, expected, next)
		if err != nil {
			return ErrStateUnavailable
		}
		if stored {
			return nil
		}
	}
	return ErrStateUnavailable
}

func validStoredState(streamID string, state AnchorState) bool {
	return state.StreamID == streamID && state.Sequence > 0 && state.PayloadDigest != [sha256.Size]byte{}
}

func validAuthorizedRequest(config Config, request SignRequest) bool {
	if request.Algorithm != config.Algorithm || request.KeyID != config.KeyID ||
		request.StreamID != config.StreamID || request.Sequence < 1 ||
		request.PayloadDigest == [sha256.Size]byte{} {
		return false
	}
	if (request.Sequence == 1 && request.PreviousDigest != [sha256.Size]byte{}) ||
		(request.Sequence > 1 && request.PreviousDigest == [sha256.Size]byte{}) {
		return false
	}
	expectedInput := []byte(SignatureContext + "\x00" + config.Algorithm + "\x00" + config.KeyID + "\x00" +
		config.StreamID + "\x00" + strconv.FormatInt(request.Sequence, 10) + "\x00" +
		encodeDigest(request.PreviousDigest) + "\x00" + encodeDigest(request.PayloadDigest))
	return equalBytes(request.SigningInput, expectedInput) && request.Digest == sha256.Sum256(expectedInput)
}

func encodeDigest(digest [sha256.Size]byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, sha256.Size*2)
	for index, value := range digest {
		encoded[index*2] = alphabet[value>>4]
		encoded[index*2+1] = alphabet[value&0x0f]
	}
	return string(encoded)
}
