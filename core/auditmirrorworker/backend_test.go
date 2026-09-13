package auditmirrorworker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
)

var workerNow = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

type fakeCOS struct {
	state         auditanchor.COSObjectLockState
	create        COSCreateResult
	body          []byte
	retention     auditanchor.COSObjectRetention
	versionID     string
	page          auditanchor.ObjectKeyPage
	err           error
	readErr       error
	retentionErr  error
	createInput   auditanchor.COSCreateObjectRequest
	reads         int
	puts          int
	bodies        map[string][]byte
	retentions    map[string]auditanchor.COSObjectRetention
	putStarted    chan struct{}
	putRelease    chan struct{}
	inspectHook   func()
	putHook       func()
	readHook      func()
	retainHook    func()
	resolveHook   func()
	readVersion   string
	retainVersion string
}

func (fake *fakeCOS) InspectObjectLock(context.Context, string) (auditanchor.COSObjectLockState, error) {
	if fake.inspectHook != nil {
		fake.inspectHook()
	}
	return fake.state, fake.err
}
func (fake *fakeCOS) CreateVersionedObject(_ context.Context, request auditanchor.COSCreateObjectRequest) (COSCreateResult, error) {
	fake.createInput = request
	fake.puts++
	if fake.putStarted != nil {
		fake.putStarted <- struct{}{}
	}
	if fake.putRelease != nil {
		<-fake.putRelease
	}
	if fake.putHook != nil {
		fake.putHook()
	}
	return fake.create, fake.err
}
func (fake *fakeCOS) ResolveObjectVersion(_ context.Context, _, key string) (string, error) {
	if fake.resolveHook != nil {
		fake.resolveHook()
	}
	if fake.bodies != nil {
		if _, exists := fake.bodies[key]; !exists {
			return "", auditanchor.ErrImmutableObjectNotFound
		}
	}
	return fake.versionID, fake.err
}
func (fake *fakeCOS) ReadObjectVersion(_ context.Context, _ string, key, versionID string) ([]byte, error) {
	fake.reads++
	fake.readVersion = versionID
	if fake.readHook != nil {
		fake.readHook()
	}
	if fake.readErr != nil {
		return nil, fake.readErr
	}
	if fake.bodies != nil {
		value, exists := fake.bodies[key]
		if !exists {
			return nil, auditanchor.ErrImmutableObjectNotFound
		}
		return bytes.Clone(value), fake.err
	}
	return bytes.Clone(fake.body), fake.err
}
func (fake *fakeCOS) ReadObjectRetentionVersion(_ context.Context, _ string, key, versionID string) (auditanchor.COSObjectRetention, error) {
	fake.retainVersion = versionID
	if fake.retainHook != nil {
		fake.retainHook()
	}
	if fake.retentionErr != nil {
		return auditanchor.COSObjectRetention{}, fake.retentionErr
	}
	if fake.retentions != nil {
		value, exists := fake.retentions[key]
		if !exists {
			return auditanchor.COSObjectRetention{}, auditanchor.ErrImmutableObjectNotFound
		}
		return value, fake.err
	}
	return fake.retention, fake.err
}
func (fake *fakeCOS) ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error) {
	return fake.page, fake.err
}

func workerConfig(privateKey *ecdsa.PrivateKey) Config {
	return Config{
		StreamID: "broker-production", Prefix: "audit-anchors/v1",
		ProfileID: "tencent-mirror-production", Bucket: "broker-audit-mirror-1250000000",
		Region: "ap-singapore",
		TrustedKeys: map[string]auditanchor.TrustedSigningKey{"worker-key": {
			PublicKey: &privateKey.PublicKey, ValidFromSequence: 1,
		}},
	}
}

func workerEnvelope(t *testing.T, privateKey *ecdsa.PrivateKey, sequence int64) []byte {
	return workerEnvelopeAt(t, privateKey, sequence, "2026-09-13T11:59:00.000Z")
}

func workerEnvelopeAt(t *testing.T, privateKey *ecdsa.PrivateKey, sequence int64, capturedAt string) []byte {
	t.Helper()
	previous := strings.Repeat("0", 64)
	if sequence > 1 {
		previous = strings.Repeat("b", 64)
	}
	payload := map[string]any{
		"purpose": auditanchor.Purpose, "version": 1, "stream_id": "broker-production",
		"sequence": sequence, "captured_at": capturedAt,
		"chain_head": strings.Repeat("a", 64), "event_count": sequence * 4,
		"file_count": 1, "previous_anchor_digest": previous,
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(canonicalPayload)
	signingInput := []byte(auditanchor.SignatureContext + "\x00ecdsa-p256-sha256\x00worker-key\x00broker-production\x00" +
		strconv.FormatInt(sequence, 10) + "\x00" + previous + "\x00" + hex.EncodeToString(payloadDigest[:]))
	signingDigest := sha256.Sum256(signingInput)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, signingDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(map[string]any{
		"version": 1, "payload": payload, "payload_digest": hex.EncodeToString(payloadDigest[:]),
		"signature": map[string]any{"algorithm": "ecdsa-p256-sha256", "key_id": "worker-key", "value": base64.RawURLEncoding.EncodeToString(signature)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func workerHarness(t *testing.T) (*Backend, *fakeCOS, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := workerEnvelope(t, privateKey, 1)
	fake := &fakeCOS{
		state:  auditanchor.COSObjectLockState{Enabled: true, VersioningState: "Enabled"},
		create: COSCreateResult{Status: "created", VersionID: "version-1"}, body: body, versionID: "version-1",
		retention: auditanchor.COSObjectRetention{Mode: auditanchor.COSComplianceMode, RetainUntil: workerNow.Add(365*24*time.Hour + auditmirror.RetentionGrace)},
	}
	backend, err := newBackend(workerConfig(privateKey), fake, func() time.Time { return workerNow })
	if err != nil {
		t.Fatal(err)
	}
	return backend, fake, privateKey, body
}

func TestBackendExecutesCompleteBoundMirrorContract(t *testing.T) {
	backend, fake, _, body := workerHarness(t)
	ctx := context.Background()
	inspect, _ := auditmirror.NewInspectRequest(backend.Binding())
	state, err := backend.Inspect(ctx, inspect)
	if err != nil || !state.Compliance || !state.Versioning || state.RetentionDays != 365 || state.TrustGeneration != backend.Binding().TrustGeneration() {
		t.Fatalf("inspect = %#v, %v", state, err)
	}
	create, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow)
	created, err := backend.Create(ctx, create)
	if err != nil || created.Status != "created" || fake.reads != 1 ||
		fake.readVersion != "version-1" || fake.retainVersion != "version-1" {
		t.Fatalf("create = %#v, %v", created, err)
	}
	if fake.createInput.Bucket != workerConfig(&ecdsa.PrivateKey{}).Bucket || fake.createInput.Key != backend.objectKey(1) ||
		fake.createInput.ContentType != "application/json" || fake.createInput.StorageClass != "STANDARD" ||
		fake.createInput.LockMode != auditanchor.COSComplianceMode || fake.createInput.RetainUntil != create.ExpectedRetainUntil() ||
		!bytes.Equal(fake.createInput.Body, body) {
		t.Fatalf("unexpected create request: %#v", fake.createInput)
	}
	read, _ := auditmirror.NewReadRequest(backend.Binding(), 1)
	got, err := backend.Read(ctx, read)
	if err != nil || !bytes.Equal(got.Envelope, body) || fake.readVersion != fake.versionID {
		t.Fatalf("read = %#v, %v", got, err)
	}
	fake.page = auditanchor.ObjectKeyPage{Keys: []string{backend.objectKey(1)}, Truncated: true, NextAfter: backend.objectKey(1)}
	list, _ := auditmirror.NewListRequest(backend.Binding(), 0, 1)
	page, err := backend.List(ctx, list)
	if err != nil || len(page.Sequences) != 1 || page.Sequences[0] != 1 || !page.Truncated || page.NextAfter != 1 {
		t.Fatalf("list = %#v, %v", page, err)
	}
	retention, err := backend.Retention(ctx, read)
	if err != nil || retention.Mode != auditanchor.COSComplianceMode || retention.RetainUntil != fake.retention.RetainUntil ||
		fake.retainVersion != fake.versionID {
		t.Fatalf("retention = %#v, %v", retention, err)
	}
}

func TestBackendRejectsInvalidConstructionAndRequests(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	valid := workerConfig(privateKey)
	fake := &fakeCOS{}
	for name, mutate := range map[string]func(*Config){
		"stream": func(value *Config) { value.StreamID = "../bad" },
		"bucket": func(value *Config) { value.Bucket = "BAD" },
		"region": func(value *Config) { value.Region = "BAD" },
		"trust":  func(value *Config) { value.TrustedKeys = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if backend, err := NewBackend(config, fake); backend != nil || !errors.Is(err, auditmirror.ErrContractRejected) {
				t.Fatalf("backend = %#v, %v", backend, err)
			}
		})
	}
	if backend, err := NewBackend(valid, nil); backend != nil || !errors.Is(err, auditmirror.ErrContractRejected) {
		t.Fatalf("nil client backend = %#v, %v", backend, err)
	}
	second, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	overlap := valid
	overlap.TrustedKeys = map[string]auditanchor.TrustedSigningKey{
		"worker-key": {PublicKey: &privateKey.PublicKey, ValidFromSequence: 1},
		"other-key":  {PublicKey: &second.PublicKey, ValidFromSequence: 2},
	}
	if backend, err := NewBackend(overlap, fake); backend != nil || !errors.Is(err, auditmirror.ErrContractRejected) {
		t.Fatalf("overlapping trust backend = %#v, %v", backend, err)
	}
	backend, _, _, _ := workerHarness(t)
	otherGeneration := sha256.Sum256([]byte("other"))
	other, _ := auditmirror.NewBinding("other", "audit-anchors/v1", "tencent-mirror-production", otherGeneration)
	inspect, _ := auditmirror.NewInspectRequest(other)
	if _, err := backend.Inspect(context.Background(), inspect); !errors.Is(err, auditmirror.ErrContractRejected) {
		t.Fatalf("mismatched inspect error = %v", err)
	}
	if backend.Binding() == (auditmirror.Binding{}) || (*Backend)(nil).Binding() != (auditmirror.Binding{}) {
		t.Fatal("binding exposure is invalid")
	}
}

func TestBackendFailsClosedOnMirrorDivergence(t *testing.T) {
	backend, fake, privateKey, body := workerHarness(t)
	create, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow)
	read, _ := auditmirror.NewReadRequest(backend.Binding(), 1)
	list, _ := auditmirror.NewListRequest(backend.Binding(), 0, 2)

	fake.body = append(bytes.Clone(body), ' ')
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("divergent create error = %v", err)
	}
	fake.body = workerEnvelope(t, privateKey, 2)
	if _, err := backend.Read(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("wrong sequence read error = %v", err)
	}
	fake.err = auditanchor.ErrImmutableObjectNotFound
	if _, err := backend.Read(context.Background(), read); !errors.Is(err, auditmirror.ErrNotFound) {
		t.Fatalf("not found read error = %v", err)
	}
	if _, err := backend.Retention(context.Background(), read); !errors.Is(err, auditmirror.ErrNotFound) {
		t.Fatalf("not found retention error = %v", err)
	}
	fake.err = nil
	fake.readErr = auditanchor.ErrImmutableObjectNotFound
	if _, err := backend.Read(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("resolved version disappeared error = %v", err)
	}
	fake.readErr = nil
	fake.retentionErr = auditanchor.ErrImmutableObjectNotFound
	if _, err := backend.Retention(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("resolved retention disappeared error = %v", err)
	}
	fake.retentionErr = nil
	fake.versionID = "null"
	if _, err := backend.Read(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("null version read error = %v", err)
	}
	if _, err := backend.Retention(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("null version retention error = %v", err)
	}
	fake.versionID = "version-1"
	fake.page = auditanchor.ObjectKeyPage{Keys: []string{backend.objectKey(1), backend.objectKey(3)}}
	if _, err := backend.List(context.Background(), list); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("gapped list error = %v", err)
	}
	fake.page = auditanchor.ObjectKeyPage{Keys: []string{backend.objectKey(1)}, Truncated: true, NextAfter: backend.objectKey(2)}
	if _, err := backend.List(context.Background(), list); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("bad cursor list error = %v", err)
	}
}

func TestBackendFailsClosedOnControlsAndCancellation(t *testing.T) {
	backend, fake, _, body := workerHarness(t)
	inspect, _ := auditmirror.NewInspectRequest(backend.Binding())
	create, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow)
	read, _ := auditmirror.NewReadRequest(backend.Binding(), 1)

	fake.state.Enabled = false
	if _, err := backend.Inspect(context.Background(), inspect); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("disabled lock error = %v", err)
	}
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) || fake.puts != 0 {
		t.Fatalf("disabled create error = %v, puts=%d", err, fake.puts)
	}
	fake.state.Enabled = true
	fake.state.VersioningState = "Suspended"
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) || fake.puts != 0 {
		t.Fatalf("suspended create error = %v, puts=%d", err, fake.puts)
	}
	fake.state.VersioningState = "Enabled"
	fake.retention.Mode = "GOVERNANCE"
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("weak create retention error = %v", err)
	}
	if _, err := backend.Retention(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("weak retention error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := backend.Read(canceled, read); !errors.Is(err, auditmirror.ErrContractRejected) {
		t.Fatalf("canceled read error = %v", err)
	}
	if _, err := (*Backend)(nil).Read(context.Background(), read); !errors.Is(err, auditmirror.ErrContractRejected) {
		t.Fatalf("nil backend read error = %v", err)
	}
}

func TestBackendRejectsProviderFailuresAndMalformedResults(t *testing.T) {
	backend, fake, _, body := workerHarness(t)
	inspect, _ := auditmirror.NewInspectRequest(backend.Binding())
	create, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow)
	read, _ := auditmirror.NewReadRequest(backend.Binding(), 1)
	list, _ := auditmirror.NewListRequest(backend.Binding(), 0, 2)

	fake.err = errors.New("provider detail")
	if _, err := backend.Inspect(context.Background(), inspect); !errors.Is(err, auditmirror.ErrUnavailable) || strings.Contains(err.Error(), "provider detail") {
		t.Fatalf("provider inspect error = %v", err)
	}
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("provider create error = %v", err)
	}
	if _, err := backend.List(context.Background(), list); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("provider list error = %v", err)
	}
	if _, err := backend.Retention(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("provider retention error = %v", err)
	}

	fake.err = nil
	fake.state.VersioningState = "Suspended"
	if _, err := backend.Inspect(context.Background(), inspect); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("suspended versioning error = %v", err)
	}
	fake.state.VersioningState = "Enabled"
	fake.create.Status = "updated"
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("invalid create status error = %v", err)
	}
	fake.create.Status = "created"
	for _, versionID := range []string{"", "null", "bad/version", strings.Repeat("a", 257)} {
		fake.create.VersionID = versionID
		if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
			t.Fatalf("invalid version ID %q error = %v", versionID, err)
		}
	}
	fake.create.Status = "exists"
	fake.create.VersionID = "version-1"
	fake.retention = auditanchor.COSObjectRetention{Mode: auditanchor.COSComplianceMode, RetainUntil: create.ExpectedRetainUntil().Add(-time.Second)}
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("short retention error = %v", err)
	}
	fake.retention.RetainUntil = create.ExpectedRetainUntil()
	if result, err := backend.Create(context.Background(), create); err != nil || result.Status != "exists" {
		t.Fatalf("idempotent create = %#v, %v", result, err)
	}
	fake.retention.RetainUntil = time.Time{}
	if _, err := backend.Retention(context.Background(), read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("zero retention error = %v", err)
	}
}

func TestBackendRejectsOverlongRetentionForCreatedAndExisting(t *testing.T) {
	for _, status := range []string{"created", "exists"} {
		t.Run(status, func(t *testing.T) {
			backend, fake, _, body := workerHarness(t)
			fake.create.Status = status
			create, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow)
			fake.retention.RetainUntil = create.ExpectedRetainUntil().Add(time.Second)
			if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
				t.Fatalf("overlong %s retention error = %v", status, err)
			}
		})
	}
}

func TestBackendWriteQueueHonorsCancellationBeforeProvider(t *testing.T) {
	backend, fake, _, body := workerHarness(t)
	fake.putStarted = make(chan struct{}, 1)
	fake.putRelease = make(chan struct{})
	create, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow)
	firstDone := make(chan error, 1)
	go func() {
		_, err := backend.Create(context.Background(), create)
		firstDone <- err
	}()
	select {
	case <-fake.putStarted:
	case <-time.After(time.Second):
		t.Fatal("first create did not reach provider")
	}
	queued, cancel := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() {
		_, err := backend.Create(queued, create)
		secondDone <- err
	}()
	cancel()
	select {
	case err := <-secondDone:
		if !errors.Is(err, auditmirror.ErrContractRejected) || fake.puts != 1 {
			t.Fatalf("queued create = %v, puts=%d", err, fake.puts)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("queued create ignored cancellation")
	}
	close(fake.putRelease)
	if err := <-firstDone; err != nil {
		t.Fatalf("first create error = %v", err)
	}
}

func TestBackendLateCancellationTakesPrecedenceOverNotFound(t *testing.T) {
	backend, fake, _, _ := workerHarness(t)
	read, _ := auditmirror.NewReadRequest(backend.Binding(), 1)
	readContext, cancelRead := context.WithCancel(context.Background())
	fake.err = auditanchor.ErrImmutableObjectNotFound
	fake.resolveHook = cancelRead
	if _, err := backend.Read(readContext, read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("late canceled read error = %v", err)
	}
	fake.resolveHook = nil
	retentionContext, cancelRetention := context.WithCancel(context.Background())
	fake.resolveHook = cancelRetention
	if _, err := backend.Retention(retentionContext, read); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("late canceled retention error = %v", err)
	}
}

func TestBackendValidatesListKeysAndCursors(t *testing.T) {
	backend, fake, _, _ := workerHarness(t)
	request, _ := auditmirror.NewListRequest(backend.Binding(), 1, 2)
	fake.page = auditanchor.ObjectKeyPage{Keys: []string{backend.objectKey(2)}}
	result, err := backend.List(context.Background(), request)
	if err != nil || result.Truncated || result.NextAfter != 0 || len(result.Sequences) != 1 || result.Sequences[0] != 2 {
		t.Fatalf("final page = %#v, %v", result, err)
	}
	for _, key := range []string{
		"wrong/00000000000000000002.json",
		backend.prefix + "2.json",
		backend.prefix + "00000000000000000000.json",
		backend.prefix + "99999999999999999999.json",
	} {
		fake.page = auditanchor.ObjectKeyPage{Keys: []string{key}}
		if _, err := backend.List(context.Background(), request); !errors.Is(err, auditmirror.ErrUnavailable) {
			t.Fatalf("invalid key %q error = %v", key, err)
		}
	}
	if sequence, ok := (*Backend)(nil).sequenceForKey("anything"); ok || sequence != 0 {
		t.Fatalf("nil key parse = %d, %v", sequence, ok)
	}
}

func TestBackendRejectsUntrustedOrStaleCreateBeforeProvider(t *testing.T) {
	backend, fake, privateKey, body := workerHarness(t)
	stale, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow.Add(-auditmirror.MaxIssuedAtSkew-time.Second))
	if _, err := backend.Create(context.Background(), stale); !errors.Is(err, auditmirror.ErrContractRejected) || fake.createInput.Key != "" {
		t.Fatalf("stale create = %#v, %v", fake.createInput, err)
	}
	futureBody := workerEnvelopeAt(t, privateKey, 1, "2026-09-13T12:01:00.000Z")
	untrusted, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, futureBody, workerNow)
	if _, err := backend.Create(context.Background(), untrusted); !errors.Is(err, auditmirror.ErrContractRejected) {
		t.Fatalf("untrusted create error = %v", err)
	}
}

func TestBackendRequiresVerifiedRetainedPredecessor(t *testing.T) {
	backend, fake, privateKey, _ := workerHarness(t)
	previous := workerEnvelope(t, privateKey, 1)
	var previousEnvelope map[string]any
	if json.Unmarshal(previous, &previousEnvelope) != nil {
		t.Fatal("previous fixture decode failed")
	}
	previousDigest := previousEnvelope["payload_digest"].(string)

	payload := map[string]any{
		"purpose": auditanchor.Purpose, "version": 1, "stream_id": "broker-production",
		"sequence": int64(2), "captured_at": "2026-09-13T11:59:30.000Z",
		"chain_head": strings.Repeat("c", 64), "event_count": int64(8),
		"file_count": int64(1), "previous_anchor_digest": previousDigest,
	}
	canonicalPayload, _ := json.Marshal(payload)
	payloadDigest := sha256.Sum256(canonicalPayload)
	signingInput := []byte(auditanchor.SignatureContext + "\x00ecdsa-p256-sha256\x00worker-key\x00broker-production\x002\x00" +
		previousDigest + "\x00" + hex.EncodeToString(payloadDigest[:]))
	signingDigest := sha256.Sum256(signingInput)
	signature, _ := ecdsa.SignASN1(rand.Reader, privateKey, signingDigest[:])
	current, _ := json.Marshal(map[string]any{
		"version": 1, "payload": payload, "payload_digest": hex.EncodeToString(payloadDigest[:]),
		"signature": map[string]any{"algorithm": "ecdsa-p256-sha256", "key_id": "worker-key", "value": base64.RawURLEncoding.EncodeToString(signature)},
	})
	create, _ := auditmirror.NewCreateRequest(backend.Binding(), 2, current, workerNow)
	previousKey, currentKey := backend.objectKey(1), backend.objectKey(2)
	fake.bodies = map[string][]byte{previousKey: previous, currentKey: current}
	fake.retentions = map[string]auditanchor.COSObjectRetention{
		previousKey: {Mode: auditanchor.COSComplianceMode, RetainUntil: workerNow.Add(365 * 24 * time.Hour)},
		currentKey:  {Mode: auditanchor.COSComplianceMode, RetainUntil: create.ExpectedRetainUntil()},
	}
	if result, err := backend.Create(context.Background(), create); err != nil || result.Status != "created" {
		t.Fatalf("linked create = %#v, %v", result, err)
	}
	fake.createInput = auditanchor.COSCreateObjectRequest{}
	value := fake.retentions[previousKey]
	value.RetainUntil = workerNow.Add(300 * 24 * time.Hour)
	fake.retentions[previousKey] = value
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) || fake.createInput.Key != "" {
		t.Fatalf("weak predecessor retention = %#v, %v", fake.createInput, err)
	}
	value.RetainUntil = workerNow.Add(365 * 24 * time.Hour)
	fake.retentions[previousKey] = value
	tamperPrevious := func(t *testing.T, mutate func(map[string]any)) []byte {
		t.Helper()
		var envelope map[string]any
		if err := json.Unmarshal(previous, &envelope); err != nil {
			t.Fatal(err)
		}
		mutate(envelope)
		value, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	invalidPredecessors := map[string][]byte{
		"noncanonical": append(bytes.Clone(previous), ' '),
		"wrong-signature": tamperPrevious(t, func(envelope map[string]any) {
			envelope["signature"].(map[string]any)["value"] = strings.Repeat("A", 96)
		}),
		"wrong-sequence": workerEnvelope(t, privateKey, 3),
		"payload-digest-mismatch": tamperPrevious(t, func(envelope map[string]any) {
			envelope["payload_digest"] = strings.Repeat("0", 64)
		}),
	}
	for name, invalid := range invalidPredecessors {
		t.Run(name, func(t *testing.T) {
			fake.bodies[previousKey] = invalid
			putsBefore := fake.puts
			if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) || fake.puts != putsBefore {
				t.Fatalf("invalid predecessor = puts %d -> %d, %v", putsBefore, fake.puts, err)
			}
		})
	}
	delete(fake.bodies, previousKey)
	if _, err := backend.Create(context.Background(), create); !errors.Is(err, auditmirror.ErrUnavailable) {
		t.Fatalf("missing predecessor error = %v", err)
	}
}

func TestBackendCreateChecksCancellationAtEveryProviderBoundary(t *testing.T) {
	for _, phase := range []struct {
		name     string
		wantPuts int
		install  func(*fakeCOS, context.CancelFunc)
	}{
		{"inspect", 0, func(fake *fakeCOS, cancel context.CancelFunc) { fake.inspectHook = cancel }},
		{"put", 1, func(fake *fakeCOS, cancel context.CancelFunc) { fake.putHook = cancel }},
		{"readback", 1, func(fake *fakeCOS, cancel context.CancelFunc) { fake.readHook = cancel }},
		{"retention", 1, func(fake *fakeCOS, cancel context.CancelFunc) { fake.retainHook = cancel }},
	} {
		t.Run(phase.name, func(t *testing.T) {
			backend, fake, _, body := workerHarness(t)
			ctx, cancel := context.WithCancel(context.Background())
			phase.install(fake, cancel)
			request, _ := auditmirror.NewCreateRequest(backend.Binding(), 1, body, workerNow)
			if _, err := backend.Create(ctx, request); !errors.Is(err, auditmirror.ErrUnavailable) || fake.puts != phase.wantPuts {
				t.Fatalf("create error = %v, puts=%d", err, fake.puts)
			}
		})
	}
}
