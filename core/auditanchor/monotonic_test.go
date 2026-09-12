package auditanchor

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"testing"
)

type memoryStateStore struct {
	mu        sync.Mutex
	state     AnchorState
	exists    bool
	loadErr   error
	storeErr  error
	conflicts int
}

func (store *memoryStateStore) Load(context.Context, string) (AnchorState, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state, store.exists, store.loadErr
}

func (store *memoryStateStore) CompareAndSwap(_ context.Context, streamID string, expected *AnchorState, next AnchorState) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.storeErr != nil {
		return false, store.storeErr
	}
	if store.conflicts > 0 {
		store.conflicts--
		return false, nil
	}
	if expected == nil {
		if store.exists {
			return false, nil
		}
	} else if !store.exists || store.state != *expected {
		return false, nil
	}
	if next.StreamID != streamID {
		return false, errors.New("wrong stream")
	}
	store.state, store.exists = next, true
	return true, nil
}

func anchorRequest(sequence int64, previous, payload byte) SignRequest {
	request := SignRequest{
		Algorithm: testConfig.Algorithm, KeyID: testConfig.KeyID,
		StreamID: testConfig.StreamID, Sequence: sequence,
	}
	for index := range request.PreviousDigest {
		request.PreviousDigest[index] = previous
		request.PayloadDigest[index] = payload
	}
	request.SigningInput = []byte(SignatureContext + "\x00" + request.Algorithm + "\x00" + request.KeyID + "\x00" +
		request.StreamID + "\x00" + strconv.FormatInt(request.Sequence, 10) + "\x00" +
		encodeDigest(request.PreviousDigest) + "\x00" + encodeDigest(request.PayloadDigest))
	request.Digest = sha256.Sum256(request.SigningInput)
	return request
}

func TestMonotonicAuthorizerAcceptsContiguousAndIdempotentAnchors(t *testing.T) {
	store := &memoryStateStore{}
	authorizer, err := NewMonotonicAuthorizer(testConfig, store)
	if err != nil {
		t.Fatal(err)
	}
	first := anchorRequest(1, 0, 0x11)
	if err := authorizer.AuthorizeAnchor(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := authorizer.AuthorizeAnchor(context.Background(), first); err != nil {
		t.Fatalf("exact retry was rejected: %v", err)
	}
	second := anchorRequest(2, 0x11, 0x22)
	if err := authorizer.AuthorizeAnchor(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if store.state.Sequence != 2 || store.state.PayloadDigest != second.PayloadDigest {
		t.Fatal("contiguous state was not committed")
	}
}

func TestMonotonicAuthorizerRejectsForksGapsAndRewinds(t *testing.T) {
	store := &memoryStateStore{}
	authorizer, _ := NewMonotonicAuthorizer(testConfig, store)
	first := anchorRequest(1, 0, 0x11)
	if err := authorizer.AuthorizeAnchor(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]SignRequest{
		"same sequence different payload": anchorRequest(1, 0, 0x12),
		"gap":                             anchorRequest(3, 0x11, 0x33),
		"wrong predecessor":               anchorRequest(2, 0x44, 0x22),
	} {
		t.Run(name, func(t *testing.T) {
			if err := authorizer.AuthorizeAnchor(context.Background(), request); !errors.Is(err, ErrAnchorRejected) {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestMonotonicAuthorizerConcurrentForkHasSingleWinner(t *testing.T) {
	store := &memoryStateStore{}
	authorizer, _ := NewMonotonicAuthorizer(testConfig, store)
	requests := []SignRequest{anchorRequest(1, 0, 0x11), anchorRequest(1, 0, 0x22)}
	start := make(chan struct{})
	results := make(chan error, len(requests))
	for _, request := range requests {
		request := request
		go func() {
			<-start
			results <- authorizer.AuthorizeAnchor(context.Background(), request)
		}()
	}
	close(start)
	accepted, rejected := 0, 0
	for range requests {
		err := <-results
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrAnchorRejected):
			rejected++
		default:
			t.Fatalf("unexpected error %v", err)
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("fork result accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestMonotonicAuthorizerRetriesCASAndFailsClosed(t *testing.T) {
	request := anchorRequest(1, 0, 0x11)
	store := &memoryStateStore{conflicts: 2}
	authorizer, _ := NewMonotonicAuthorizer(testConfig, store)
	if err := authorizer.AuthorizeAnchor(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	for name, failingStore := range map[string]*memoryStateStore{
		"load error":    {loadErr: errors.New("canary-load")},
		"store error":   {storeErr: errors.New("canary-store")},
		"cas exhausted": {conflicts: DefaultStateAttempts},
		"invalid state": {
			exists: true,
			state:  AnchorState{StreamID: "other", Sequence: 1, PayloadDigest: request.PayloadDigest},
		},
		"unexpected absent state": {
			state: AnchorState{StreamID: testConfig.StreamID, Sequence: 1, PayloadDigest: request.PayloadDigest},
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, _ := NewMonotonicAuthorizer(testConfig, failingStore)
			if err := candidate.AuthorizeAnchor(context.Background(), request); !errors.Is(err, ErrStateUnavailable) {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestMonotonicAuthorizerValidatesConfigurationAndRequests(t *testing.T) {
	if _, err := NewMonotonicAuthorizer(Config{}, &memoryStateStore{}); err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	if _, err := NewMonotonicAuthorizer(testConfig, nil); err == nil {
		t.Fatal("nil store was accepted")
	}
	authorizer, _ := NewMonotonicAuthorizer(testConfig, &memoryStateStore{})
	for name, mutate := range map[string]func(*SignRequest){
		"algorithm":         func(value *SignRequest) { value.Algorithm = "ed25519" },
		"key":               func(value *SignRequest) { value.KeyID = "other" },
		"stream":            func(value *SignRequest) { value.StreamID = "other" },
		"sequence":          func(value *SignRequest) { value.Sequence = 0 },
		"payload":           func(value *SignRequest) { value.PayloadDigest = [sha256.Size]byte{} },
		"first predecessor": func(value *SignRequest) { value.PreviousDigest[0] = 1 },
		"input":             func(value *SignRequest) { value.SigningInput = []byte("wrong") },
		"digest":            func(value *SignRequest) { value.Digest[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			request := anchorRequest(1, 0, 0x11)
			mutate(&request)
			if err := authorizer.AuthorizeAnchor(context.Background(), request); !errors.Is(err, ErrAnchorRejected) {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
	if err := authorizer.AuthorizeAnchor(nil, anchorRequest(1, 0, 0x11)); !errors.Is(err, ErrAnchorRejected) {
		t.Fatalf("nil context returned %v", err)
	}
	authorizer.MaxAttempts = 0
	if err := authorizer.AuthorizeAnchor(context.Background(), anchorRequest(1, 0, 0x11)); !errors.Is(err, ErrAnchorRejected) {
		t.Fatalf("invalid attempts returned %v", err)
	}
}
