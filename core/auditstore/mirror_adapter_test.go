package auditstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
)

type recordingMirrorClient struct {
	binding             auditmirror.Binding
	inspect             auditmirror.LockState
	create              auditmirror.CreateResult
	read                auditmirror.ReadResult
	list                auditmirror.ListResult
	retention           auditmirror.RetentionResult
	err                 error
	sequence            int64
	envelope            []byte
	after               int64
	limit               int
	onCall              func()
	now                 func() time.Time
	persist             bool
	expectedRetainUntil time.Time
}

type mirrorWriterOSS struct{ body []byte }

func (*mirrorWriterOSS) InspectBucketWORM(context.Context, string) (auditanchor.OSSBucketWORMState, error) {
	return auditanchor.OSSBucketWORMState{Status: "Locked", RetentionDays: 365, VersioningState: "Disabled"}, nil
}
func (store *mirrorWriterOSS) CreateObject(_ context.Context, request auditanchor.OSSCreateObjectRequest) (auditanchor.ObjectCreateResult, error) {
	if store.body != nil && !bytes.Equal(store.body, request.Body) {
		return auditanchor.ObjectCreateResult{}, auditanchor.ErrObjectConflict
	}
	store.body = bytes.Clone(request.Body)
	return auditanchor.ObjectCreateResult{Status: "created"}, nil
}
func (store *mirrorWriterOSS) ReadObject(context.Context, string, string) ([]byte, error) {
	if store.body == nil {
		return nil, auditanchor.ErrImmutableObjectNotFound
	}
	return bytes.Clone(store.body), nil
}

func (client *recordingMirrorClient) Inspect(_ context.Context, request auditmirror.InspectRequest) (auditmirror.LockState, error) {
	if !request.ValidFor(client.binding) {
		return auditmirror.LockState{}, auditmirror.ErrContractRejected
	}
	if client.onCall != nil {
		client.onCall()
	}
	return client.inspect, client.err
}
func (client *recordingMirrorClient) Create(_ context.Context, request auditmirror.CreateRequest) (auditmirror.CreateResult, error) {
	now := time.Now().UTC()
	if client.now != nil {
		now = client.now().UTC()
	}
	if !request.ValidAt(client.binding, now) {
		return auditmirror.CreateResult{}, auditmirror.ErrContractRejected
	}
	client.sequence, client.envelope = request.Sequence(), request.Envelope()
	client.expectedRetainUntil = request.ExpectedRetainUntil()
	if client.persist {
		client.read.Envelope = request.Envelope()
		client.retention = auditmirror.RetentionResult{
			Mode: auditanchor.COSComplianceMode, RetainUntil: request.ExpectedRetainUntil(),
		}
	}
	if client.onCall != nil {
		client.onCall()
	}
	return client.create, client.err
}
func (client *recordingMirrorClient) Read(_ context.Context, request auditmirror.ReadRequest) (auditmirror.ReadResult, error) {
	if !request.ValidFor(client.binding) {
		return auditmirror.ReadResult{}, auditmirror.ErrContractRejected
	}
	client.sequence = request.Sequence()
	if client.onCall != nil {
		client.onCall()
	}
	return client.read, client.err
}
func (client *recordingMirrorClient) List(_ context.Context, request auditmirror.ListRequest) (auditmirror.ListResult, error) {
	if !request.ValidFor(client.binding) {
		return auditmirror.ListResult{}, auditmirror.ErrContractRejected
	}
	client.after, client.limit = request.After(), request.Limit()
	if client.onCall != nil {
		client.onCall()
	}
	return client.list, client.err
}
func (client *recordingMirrorClient) Retention(_ context.Context, request auditmirror.ReadRequest) (auditmirror.RetentionResult, error) {
	if !request.ValidFor(client.binding) {
		return auditmirror.RetentionResult{}, auditmirror.ErrContractRejected
	}
	client.sequence = request.Sequence()
	if client.onCall != nil {
		client.onCall()
	}
	return client.retention, client.err
}

func newMirrorAdapterHarness(t *testing.T) (*mirrorCOSAdapter, *recordingMirrorClient, ServiceConfig) {
	t.Helper()
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auditanchor.NewEnvelopeVerifier(config.StreamID, trustedSigningKeys(config))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := mirrorBinding(config)
	if err != nil {
		t.Fatal(err)
	}
	client := &recordingMirrorClient{binding: binding}
	client.inspect = auditmirror.LockState{
		Compliance: true, Versioning: true, RetentionDays: 365,
		TrustGeneration: binding.TrustGeneration(),
	}
	client.create.Status = "created"
	client.retention = auditmirror.RetentionResult{Mode: auditanchor.COSComplianceMode, RetainUntil: time.Date(2027, 9, 13, 0, 0, 0, 0, time.UTC)}
	adapter, err := newMirrorCOSAdapter(config, client, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, client, config
}

func signedMirrorEnvelope(t *testing.T, sequence int64) []byte {
	t.Helper()
	previous := strings.Repeat("0", 64)
	payload := map[string]any{
		"purpose": auditanchor.Purpose, "version": 1, "stream_id": "broker-production", "sequence": sequence,
		"captured_at": "2026-09-12T11:59:00.000Z", "chain_head": strings.Repeat("a", 64),
		"event_count": sequence, "file_count": 1, "previous_anchor_digest": previous,
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonicalPayload)
	keyID := "audit-key-2026"
	input := []byte(auditanchor.SignatureContext + "\x00ecdsa-p256-sha256\x00" + keyID +
		"\x00broker-production\x00" + strconv.FormatInt(sequence, 10) + "\x00" + previous +
		"\x00" + hex.EncodeToString(digest[:]))
	signingDigest := sha256.Sum256(input)
	privateKey := &ecdsa.PrivateKey{PublicKey: *testServicePublicKey(), D: big.NewInt(1)}
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, signingDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	envelope := map[string]any{
		"version": 1, "payload": payload, "payload_digest": hex.EncodeToString(digest[:]),
		"signature": map[string]any{"algorithm": "ecdsa-p256-sha256", "key_id": keyID, "value": base64.RawURLEncoding.EncodeToString(signature)},
	}
	value, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestMirrorAdapterTranslatesOnlyTypedBoundCapabilities(t *testing.T) {
	adapter, client, config := newMirrorAdapterHarness(t)
	ctx := context.Background()
	if state, err := adapter.InspectObjectLock(ctx, config.COS.Bucket); err != nil || !state.Enabled || state.VersioningState != "Enabled" {
		t.Fatalf("inspect = %#v, %v", state, err)
	}
	body := signedMirrorEnvelope(t, 1)
	request := auditanchor.COSCreateObjectRequest{
		Bucket: config.COS.Bucket, Key: adapter.objectKey(1), Body: body,
		ContentType: "application/json", StorageClass: "STANDARD",
		LockMode:    auditanchor.COSComplianceMode,
		RetainUntil: time.Now().UTC().Add(365*24*time.Hour + auditmirror.RetentionGrace),
	}
	if result, err := adapter.CreateObject(ctx, request); err != nil || result.Status != "created" ||
		client.sequence != 1 || !bytes.Equal(client.envelope, body) ||
		!client.expectedRetainUntil.Equal(request.RetainUntil) {
		t.Fatalf("create = %#v, %v", result, err)
	}
	client.read.Envelope = body
	if value, err := adapter.ReadObject(ctx, config.COS.Bucket, adapter.objectKey(1)); err != nil || !bytes.Equal(value, body) {
		t.Fatalf("read = %q, %v", value, err)
	}
	client.list = auditmirror.ListResult{Sequences: []int64{2, 3}, NextAfter: 3, Truncated: true}
	page, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, adapter.objectKey(1), 2)
	if err != nil || client.after != 1 || client.limit != 2 || len(page.Keys) != 2 || page.NextAfter != adapter.objectKey(3) {
		t.Fatalf("list = %#v, %v", page, err)
	}
	if retention, err := adapter.ReadObjectRetention(ctx, config.COS.Bucket, adapter.objectKey(1)); err != nil || retention != (auditanchor.COSObjectRetention{Mode: client.retention.Mode, RetainUntil: client.retention.RetainUntil}) {
		t.Fatalf("retention = %#v, %v", retention, err)
	}
}

func TestImmutableWriterFirstCreateRoundTripsExactMirrorRetention(t *testing.T) {
	adapter, client, config := newMirrorAdapterHarness(t)
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	client.persist = true
	client.create.Status = "created"
	writer, err := auditanchor.NewImmutableObjectWriter(auditanchor.ImmutableObjectWriterConfig{
		OSSBucket: config.OSS.Bucket, COSBucket: config.COS.Bucket,
		Prefix: config.Prefix, StreamID: config.StreamID,
		TrustedKeys: trustedSigningKeys(config), Now: func() time.Time { return now },
	}, &mirrorWriterOSS{}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := writer.Write(context.Background(), signedMirrorEnvelope(t, 1))
	expected := now.Add(365*24*time.Hour + auditanchor.AuditObjectRetentionGrace)
	if err != nil || receipt.MirrorState != "created" || !receipt.RetainUntil.Equal(expected) ||
		!client.expectedRetainUntil.Equal(expected) {
		t.Fatalf("first create = %#v, worker retain=%v, err=%v", receipt, client.expectedRetainUntil, err)
	}
}

func TestMirrorAdapterRejectsUnboundOrInvalidInputsAndResults(t *testing.T) {
	adapter, client, config := newMirrorAdapterHarness(t)
	ctx := context.Background()
	body := signedMirrorEnvelope(t, 1)
	validCreate := auditanchor.COSCreateObjectRequest{
		Bucket: config.COS.Bucket, Key: adapter.objectKey(1), Body: body, ContentType: "application/json",
		StorageClass: "STANDARD", LockMode: auditanchor.COSComplianceMode,
		RetainUntil: time.Now().UTC().Add(365*24*time.Hour + auditmirror.RetentionGrace),
	}
	for name, mutate := range map[string]func(*auditanchor.COSCreateObjectRequest){
		"bucket":       func(value *auditanchor.COSCreateObjectRequest) { value.Bucket = "other-bucket" },
		"key":          func(value *auditanchor.COSCreateObjectRequest) { value.Key = "other/00000000000000000001.json" },
		"content type": func(value *auditanchor.COSCreateObjectRequest) { value.ContentType = "text/plain" },
		"storage":      func(value *auditanchor.COSCreateObjectRequest) { value.StorageClass = "ARCHIVE" },
		"lock":         func(value *auditanchor.COSCreateObjectRequest) { value.LockMode = "GOVERNANCE" },
		"tamper":       func(value *auditanchor.COSCreateObjectRequest) { value.Body = append(bytes.Clone(value.Body), ' ') },
		"retention too short": func(value *auditanchor.COSCreateObjectRequest) {
			value.RetainUntil = time.Now().UTC().Add(time.Hour)
		},
		"retention too long": func(value *auditanchor.COSCreateObjectRequest) {
			value.RetainUntil = time.Now().UTC().Add(366 * 24 * time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := validCreate
			mutate(&request)
			if _, err := adapter.CreateObject(ctx, request); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	client.inspect.RetentionDays = 1
	if _, err := adapter.InspectObjectLock(ctx, config.COS.Bucket); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("inspect error = %v", err)
	}
	client.list = auditmirror.ListResult{Sequences: []int64{1, 3}}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "", 2); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("list error = %v", err)
	}
	client.retention.Mode = "GOVERNANCE"
	if _, err := adapter.ReadObjectRetention(ctx, config.COS.Bucket, adapter.objectKey(1)); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("retention error = %v", err)
	}
	client.read.Envelope = signedMirrorEnvelope(t, 2)
	if _, err := adapter.ReadObject(ctx, config.COS.Bucket, adapter.objectKey(1)); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("read error = %v", err)
	}
}

func TestMirrorAdapterNormalizesProviderErrorsAndCancellation(t *testing.T) {
	adapter, client, config := newMirrorAdapterHarness(t)
	client.err = errors.New("provider detail")
	if _, err := adapter.ReadObject(context.Background(), config.COS.Bucket, adapter.objectKey(1)); !errors.Is(err, auditanchor.ErrMirrorUnavailable) || strings.Contains(err.Error(), "provider detail") {
		t.Fatalf("error = %v", err)
	}
	client.err = auditmirror.ErrNotFound
	if _, err := adapter.ReadObject(context.Background(), config.COS.Bucket, adapter.objectKey(1)); !errors.Is(err, auditanchor.ErrImmutableObjectNotFound) {
		t.Fatalf("not found error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.ReadObject(canceled, config.COS.Bucket, adapter.objectKey(1)); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("canceled error = %v", err)
	}
}

func TestMirrorAdapterFailsClosedAcrossResponseBoundaries(t *testing.T) {
	adapter, client, config := newMirrorAdapterHarness(t)
	ctx := context.Background()
	body := signedMirrorEnvelope(t, 1)
	create := auditanchor.COSCreateObjectRequest{
		Bucket: config.COS.Bucket, Key: adapter.objectKey(1), Body: body,
		ContentType: "application/json", StorageClass: "STANDARD",
		LockMode:    auditanchor.COSComplianceMode,
		RetainUntil: time.Now().UTC().Add(365*24*time.Hour + auditmirror.RetentionGrace),
	}

	client.err = auditmirror.ErrContractRejected
	if _, err := adapter.InspectObjectLock(ctx, config.COS.Bucket); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("contract error = %v", err)
	}
	client.err = nil
	client.create.Status = "overwritten"
	if _, err := adapter.CreateObject(ctx, create); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("create status error = %v", err)
	}
	client.create.Status = "exists"
	if result, err := adapter.CreateObject(ctx, create); err != nil || result.Status != "exists" {
		t.Fatalf("idempotent create = %#v, %v", result, err)
	}

	client.list = auditmirror.ListResult{Sequences: []int64{1}, Truncated: true, NextAfter: 2}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "", 1); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("pagination cursor error = %v", err)
	}
	client.list = auditmirror.ListResult{Sequences: []int64{1}, NextAfter: 1}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "", 1); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("non-truncated cursor error = %v", err)
	}
	client.list = auditmirror.ListResult{Sequences: []int64{auditmirror.MaxSequence + 1}}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "", 1); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("excessive sequence error = %v", err)
	}
	client.list = auditmirror.ListResult{NextAfter: -1}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "", 1); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("negative cursor error = %v", err)
	}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, "wrong-prefix", "", 1); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("prefix error = %v", err)
	}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "bad-cursor", 1); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("cursor error = %v", err)
	}
	if _, err := adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "", 0); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("limit error = %v", err)
	}

	client.retention = auditmirror.RetentionResult{Mode: auditanchor.COSComplianceMode}
	if _, err := adapter.ReadObjectRetention(ctx, config.COS.Bucket, adapter.objectKey(1)); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("zero retention error = %v", err)
	}
	if _, err := adapter.ReadObjectRetention(ctx, config.COS.Bucket, "bad-key"); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("retention key error = %v", err)
	}
	if _, err := adapter.ReadObject(ctx, config.COS.Bucket, "bad-key"); !errors.Is(err, auditanchor.ErrMirrorInvalid) {
		t.Fatalf("read key error = %v", err)
	}
}

func TestMirrorAdapterRejectsLateSuccessAfterCancellation(t *testing.T) {
	for _, operation := range []string{"inspect", "create", "read", "list", "retention"} {
		t.Run(operation, func(t *testing.T) {
			adapter, client, config := newMirrorAdapterHarness(t)
			body := signedMirrorEnvelope(t, 1)
			client.read.Envelope = body
			client.list = auditmirror.ListResult{}
			ctx, cancel := context.WithCancel(context.Background())
			client.onCall = cancel
			var err error
			switch operation {
			case "inspect":
				_, err = adapter.InspectObjectLock(ctx, config.COS.Bucket)
			case "create":
				_, err = adapter.CreateObject(ctx, auditanchor.COSCreateObjectRequest{
					Bucket: config.COS.Bucket, Key: adapter.objectKey(1), Body: body,
					ContentType: "application/json", StorageClass: "STANDARD",
					LockMode:    auditanchor.COSComplianceMode,
					RetainUntil: time.Now().UTC().Add(365*24*time.Hour + auditmirror.RetentionGrace),
				})
			case "read":
				_, err = adapter.ReadObject(ctx, config.COS.Bucket, adapter.objectKey(1))
			case "list":
				_, err = adapter.ListObjectKeys(ctx, config.COS.Bucket, adapter.prefix, "", 1)
			case "retention":
				_, err = adapter.ReadObjectRetention(ctx, config.COS.Bucket, adapter.objectKey(1))
			}
			if !errors.Is(err, auditanchor.ErrMirrorInvalid) {
				t.Fatalf("late result accepted: %v", err)
			}
		})
	}
}

func TestMirrorAdapterConstructionRejectsInvalidDependencies(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auditanchor.NewEnvelopeVerifier(config.StreamID, trustedSigningKeys(config))
	if err != nil {
		t.Fatal(err)
	}
	if adapter, err := newMirrorCOSAdapter(config, nil, verifier); adapter != nil || !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatalf("nil client = %#v, %v", adapter, err)
	}
	if adapter, err := newMirrorCOSAdapter(config, &recordingMirrorClient{}, nil); adapter != nil || !errors.Is(err, ErrServiceRuntimeInvalid) {
		t.Fatalf("nil verifier = %#v, %v", adapter, err)
	}
	config.TrustedKeys[0].PublicKey = nil
	if adapter, err := newMirrorCOSAdapter(config, &recordingMirrorClient{}, verifier); adapter != nil || !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("bad trust = %#v, %v", adapter, err)
	}
	if binding, err := mirrorBinding(config); binding != (auditmirror.Binding{}) || !errors.Is(err, ErrServiceConfigInvalid) {
		t.Fatalf("bad binding = %#v, %v", binding, err)
	}
}

func TestMirrorTrustGenerationIsStableAndKeyEpochBound(t *testing.T) {
	config, err := ParseServiceConfig(strings.NewReader(validServiceConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	second := config.TrustedKeys[0]
	second.KeyID = "audit-key-2027"
	second.ValidFromSequence = 100
	config.TrustedKeys = append(config.TrustedKeys, second)
	first, err := mirrorTrustGeneration(config.TrustedKeys)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []TrustedKeyBinding{config.TrustedKeys[1], config.TrustedKeys[0]}
	stable, err := mirrorTrustGeneration(reversed)
	if err != nil || stable != first {
		t.Fatal("trust generation must be independent of input order")
	}
	reversed[0].ValidFromSequence++
	changed, err := mirrorTrustGeneration(reversed)
	if err != nil || changed == first {
		t.Fatal("trust generation must bind key epochs")
	}
}
