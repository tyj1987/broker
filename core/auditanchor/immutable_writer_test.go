package auditanchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

var writerNow = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

type fakeOSS struct {
	state        OSSBucketWORMState
	stateErr     error
	create       ObjectCreateResult
	createErr    error
	readBody     []byte
	readErr      error
	request      OSSCreateObjectRequest
	createdBody  []byte
	afterInspect func()
	afterCreate  func()
	afterRead    func()
}

func (fake *fakeOSS) InspectBucketWORM(context.Context, string) (OSSBucketWORMState, error) {
	if fake.afterInspect != nil {
		fake.afterInspect()
	}
	return fake.state, fake.stateErr
}

func (fake *fakeOSS) CreateObject(_ context.Context, request OSSCreateObjectRequest) (ObjectCreateResult, error) {
	fake.request = request
	fake.createdBody = bytes.Clone(request.Body)
	if fake.afterCreate != nil {
		fake.afterCreate()
	}
	return fake.create, fake.createErr
}

func (fake *fakeOSS) ReadObject(context.Context, string, string) ([]byte, error) {
	if fake.afterRead != nil {
		fake.afterRead()
	}
	if fake.readBody != nil {
		return bytes.Clone(fake.readBody), fake.readErr
	}
	return bytes.Clone(fake.createdBody), fake.readErr
}

type fakeCOS struct {
	state          COSObjectLockState
	stateErr       error
	create         ObjectCreateResult
	createErr      error
	readBody       []byte
	readErr        error
	retention      COSObjectRetention
	retentionErr   error
	request        COSCreateObjectRequest
	createdBody    []byte
	afterInspect   func()
	afterCreate    func()
	afterRead      func()
	afterRetention func()
}

func (fake *fakeCOS) InspectObjectLock(context.Context, string) (COSObjectLockState, error) {
	if fake.afterInspect != nil {
		fake.afterInspect()
	}
	return fake.state, fake.stateErr
}

func (fake *fakeCOS) CreateObject(_ context.Context, request COSCreateObjectRequest) (ObjectCreateResult, error) {
	fake.request = request
	fake.createdBody = bytes.Clone(request.Body)
	if fake.afterCreate != nil {
		fake.afterCreate()
	}
	return fake.create, fake.createErr
}

func (fake *fakeCOS) ReadObject(context.Context, string, string) ([]byte, error) {
	if fake.afterRead != nil {
		fake.afterRead()
	}
	if fake.readBody != nil {
		return bytes.Clone(fake.readBody), fake.readErr
	}
	return bytes.Clone(fake.createdBody), fake.readErr
}

func (fake *fakeCOS) ReadObjectRetention(context.Context, string, string) (COSObjectRetention, error) {
	if fake.afterRetention != nil {
		fake.afterRetention()
	}
	if fake.retention.RetainUntil.IsZero() {
		return COSObjectRetention{Mode: COSComplianceMode, RetainUntil: fake.request.RetainUntil}, fake.retentionErr
	}
	return fake.retention, fake.retentionErr
}

func validWriterHarness(t *testing.T) (*ImmutableObjectWriter, *fakeOSS, *fakeCOS) {
	t.Helper()
	oss := &fakeOSS{
		state:  OSSBucketWORMState{Status: "Locked", RetentionDays: 365, VersioningState: "Disabled"},
		create: ObjectCreateResult{Status: "created"},
	}
	cos := &fakeCOS{
		state:  COSObjectLockState{Enabled: true, VersioningState: "Enabled"},
		create: ObjectCreateResult{Status: "created"},
	}
	writer, err := NewImmutableObjectWriter(ImmutableObjectWriterConfig{
		OSSBucket: "broker-audit-primary", COSBucket: "broker-audit-mirror-1250000000",
		Prefix: "audit-anchors/v1", Now: func() time.Time { return writerNow },
	}, oss, cos)
	if err != nil {
		t.Fatalf("NewImmutableObjectWriter() error = %v", err)
	}
	return writer, oss, cos
}

func validEnvelopeJSON(t *testing.T) []byte {
	t.Helper()
	payload := map[string]any{
		"purpose": Purpose, "version": 1, "stream_id": "broker-production", "sequence": 1,
		"captured_at": "2026-09-12T11:59:00.000Z", "chain_head": stringsOf('a', 64),
		"event_count": 4, "file_count": 1, "previous_anchor_digest": stringsOf('0', 64),
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonicalPayload)
	envelope := map[string]any{
		"version": 1, "payload": payload, "payload_digest": hex.EncodeToString(digest[:]),
		"signature": map[string]any{
			"algorithm": "ecdsa-p256-sha256", "key_id": "audit-anchor-key-2026-01",
			"value": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 64)),
		},
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func stringsOf(value byte, count int) string { return string(bytes.Repeat([]byte{value}, count)) }

func TestImmutableObjectWriterCreatesBothLockedCopies(t *testing.T) {
	writer, oss, cos := validWriterHarness(t)
	body := validEnvelopeJSON(t)
	parsed, _, parseErr := parseStoredEnvelope(body)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	receipt, err := writer.Write(context.Background(), body)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	wantKey := "audit-anchors/v1/broker-production/00000000000000000001-" +
		parsed.PayloadDigest + ".json"
	if receipt.Key != wantKey || receipt.PrimaryState != "created" || receipt.MirrorState != "created" {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	if !oss.request.ForbidOverwrite || oss.request.ContentType != "application/json" ||
		oss.request.Bucket != "broker-audit-primary" || oss.request.Key != wantKey {
		t.Fatalf("unexpected OSS request: %#v", oss.request)
	}
	if cos.request.LockMode != COSComplianceMode || cos.request.StorageClass != "STANDARD" ||
		cos.request.ContentType != "application/json" || cos.request.Key != wantKey ||
		!cos.request.RetainUntil.Equal(writerNow.Add(365*24*time.Hour+objectRetentionGrace)) {
		t.Fatalf("unexpected COS request: %#v", cos.request)
	}
	if !bytes.Equal(oss.createdBody, cos.createdBody) || bytes.Contains(oss.createdBody, []byte{'\n'}) {
		t.Fatal("stored envelope was not identically canonicalized")
	}
	if sha256.Sum256(oss.createdBody) != receipt.BodySHA256 {
		t.Fatal("receipt body digest does not match stored object")
	}
}

func TestImmutableObjectWriterAcceptsVerifiedIdempotentRetry(t *testing.T) {
	writer, oss, cos := validWriterHarness(t)
	body := validEnvelopeJSON(t)
	_, canonical, err := parseStoredEnvelope(body)
	if err != nil {
		t.Fatal(err)
	}
	oss.create.Status = "exists"
	oss.readBody = canonical
	cos.create.Status = "exists"
	cos.readBody = canonical
	cos.retention = COSObjectRetention{
		Mode:        COSComplianceMode,
		RetainUntil: time.Date(2027, 9, 12, 11, 59, 0, 0, time.UTC),
	}
	receipt, err := writer.Write(context.Background(), body)
	if err != nil {
		t.Fatalf("Write() retry error = %v", err)
	}
	if receipt.PrimaryState != "exists" || receipt.MirrorState != "exists" {
		t.Fatalf("unexpected retry receipt: %#v", receipt)
	}
}

func TestImmutableObjectWriterRejectsInvalidConfigurationAndRequest(t *testing.T) {
	writer, _, _ := validWriterHarness(t)
	validOSS := &fakeOSS{}
	validCOS := &fakeCOS{}
	for _, config := range []ImmutableObjectWriterConfig{
		{},
		{OSSBucket: "UPPER", COSBucket: "mirror-bucket", Prefix: "audit/v1", Now: time.Now},
		{OSSBucket: "primary-bucket", COSBucket: "bad_bucket", Prefix: "audit/v1", Now: time.Now},
		{OSSBucket: "primary-bucket", COSBucket: "mirror-bucket", Prefix: "../audit", Now: time.Now},
		{OSSBucket: "primary-bucket", COSBucket: "mirror-bucket", Prefix: "audit//v1", Now: time.Now},
	} {
		if _, err := NewImmutableObjectWriter(config, validOSS, validCOS); !errors.Is(err, ErrObjectWriteRejected) {
			t.Fatalf("NewImmutableObjectWriter(%#v) error = %v", config, err)
		}
	}
	validConfig := ImmutableObjectWriterConfig{OSSBucket: "primary-bucket", COSBucket: "mirror-bucket", Prefix: "audit/v1", Now: time.Now}
	if _, err := NewImmutableObjectWriter(validConfig, nil, validCOS); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("nil OSS error = %v", err)
	}
	if _, err := NewImmutableObjectWriter(validConfig, validOSS, nil); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("nil COS error = %v", err)
	}

	validBody := validEnvelopeJSON(t)
	duplicateKey := bytes.Replace(validBody, []byte("{\n  \"payload\""), []byte("{\n  \"version\": 1,\n  \"payload\""), 1)
	invalidBodies := [][]byte{nil, []byte("{}"), []byte("[]"), append(validBody, []byte("{}")...), duplicateKey}
	tooLarge := make([]byte, AuditObjectMaxBytes+1)
	invalidBodies = append(invalidBodies, tooLarge)
	for _, body := range invalidBodies {
		if _, err := writer.Write(context.Background(), body); !errors.Is(err, ErrObjectWriteRejected) {
			t.Fatalf("Write(invalid) error = %v", err)
		}
	}
	if _, err := writer.Write(nil, validEnvelopeJSON(t)); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("Write(nil context) error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writer.Write(cancelled, validEnvelopeJSON(t)); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("Write(cancelled) error = %v", err)
	}
	broken := *writer
	broken.config.Now = func() time.Time { return time.Time{} }
	if _, err := broken.Write(context.Background(), validEnvelopeJSON(t)); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("Write(invalid clock) error = %v", err)
	}
	broken.config.Now = func() time.Time { return time.Date(2026, 9, 12, 11, 58, 0, 0, time.UTC) }
	if _, err := broken.Write(context.Background(), validEnvelopeJSON(t)); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("Write(clock before envelope) error = %v", err)
	}
}

func TestImmutableObjectWriterRejectsEnvelopeTampering(t *testing.T) {
	writer, _, _ := validWriterHarness(t)
	valid := validEnvelopeJSON(t)
	var envelope map[string]any
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	tests := []func(map[string]any){
		func(value map[string]any) { value["extra"] = true },
		func(value map[string]any) { delete(value["payload"].(map[string]any), "event_count") },
		func(value map[string]any) { value["payload_digest"] = stringsOf('0', 64) },
		func(value map[string]any) { value["signature"].(map[string]any)["value"] = "bad" },
		func(value map[string]any) { value["signature"].(map[string]any)["algorithm"] = "hmac-sha256" },
		func(value map[string]any) { value["payload"].(map[string]any)["stream_id"] = "../bad" },
		func(value map[string]any) { value["payload"].(map[string]any)["captured_at"] = "not-a-time" },
		func(value map[string]any) { value["payload"].(map[string]any)["sequence"] = 2 },
	}
	for index, mutate := range tests {
		var candidate map[string]any
		if err := json.Unmarshal(valid, &candidate); err != nil {
			t.Fatal(err)
		}
		mutate(candidate)
		body, _ := json.Marshal(candidate)
		if _, err := writer.Write(context.Background(), body); !errors.Is(err, ErrObjectWriteRejected) {
			t.Fatalf("tamper case %d error = %v", index, err)
		}
	}
}

func TestImmutableObjectWriterStopsAfterCancellationAtEveryProviderBoundary(t *testing.T) {
	tests := []struct {
		name   string
		attach func(*fakeOSS, *fakeCOS, func())
	}{
		{"OSS inspect", func(oss *fakeOSS, _ *fakeCOS, cancel func()) { oss.afterInspect = cancel }},
		{"OSS create", func(oss *fakeOSS, _ *fakeCOS, cancel func()) { oss.afterCreate = cancel }},
		{"OSS read", func(oss *fakeOSS, _ *fakeCOS, cancel func()) { oss.afterRead = cancel }},
		{"COS inspect", func(_ *fakeOSS, cos *fakeCOS, cancel func()) { cos.afterInspect = cancel }},
		{"COS create", func(_ *fakeOSS, cos *fakeCOS, cancel func()) { cos.afterCreate = cancel }},
		{"COS read", func(_ *fakeOSS, cos *fakeCOS, cancel func()) { cos.afterRead = cancel }},
		{"COS retention", func(_ *fakeOSS, cos *fakeCOS, cancel func()) { cos.afterRetention = cancel }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer, oss, cos := validWriterHarness(t)
			ctx, cancel := context.WithCancel(context.Background())
			test.attach(oss, cos, cancel)
			if _, err := writer.Write(ctx, validEnvelopeJSON(t)); !errors.Is(err, ErrObjectWriteRejected) {
				t.Fatalf("Write() error = %v", err)
			}
		})
	}
}

func TestImmutableObjectWriterFailsClosedAtPrimaryBoundary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeOSS)
		want   error
	}{
		{"inspect unavailable", func(fake *fakeOSS) { fake.stateErr = errors.New("provider detail") }, ErrPrimaryUnavailable},
		{"worm unlocked", func(fake *fakeOSS) { fake.state.Status = "InProgress" }, ErrPrimaryInvalid},
		{"retention wrong", func(fake *fakeOSS) { fake.state.RetentionDays = 30 }, ErrPrimaryInvalid},
		{"versioning invalidates create-only", func(fake *fakeOSS) { fake.state.VersioningState = "Enabled" }, ErrPrimaryInvalid},
		{"create unavailable", func(fake *fakeOSS) { fake.createErr = errors.New("provider detail") }, ErrPrimaryUnavailable},
		{"create response invalid", func(fake *fakeOSS) { fake.create.Status = "overwritten" }, ErrPrimaryInvalid},
		{"read unavailable", func(fake *fakeOSS) { fake.readErr = errors.New("provider detail") }, ErrPrimaryUnavailable},
		{"content conflict", func(fake *fakeOSS) { fake.readBody = []byte("different") }, ErrObjectConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer, oss, _ := validWriterHarness(t)
			test.mutate(oss)
			if _, err := writer.Write(context.Background(), validEnvelopeJSON(t)); !errors.Is(err, test.want) {
				t.Fatalf("Write() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestImmutableObjectWriterFailsClosedAtMirrorBoundary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fakeCOS)
		want   error
	}{
		{"inspect unavailable", func(fake *fakeCOS) { fake.stateErr = errors.New("provider detail") }, ErrMirrorUnavailable},
		{"object lock disabled", func(fake *fakeCOS) { fake.state.Enabled = false }, ErrMirrorInvalid},
		{"versioning disabled", func(fake *fakeCOS) { fake.state.VersioningState = "Suspended" }, ErrMirrorInvalid},
		{"create unavailable", func(fake *fakeCOS) { fake.createErr = errors.New("provider detail") }, ErrMirrorUnavailable},
		{"create response invalid", func(fake *fakeCOS) { fake.create.Status = "overwritten" }, ErrMirrorInvalid},
		{"read unavailable", func(fake *fakeCOS) { fake.readErr = errors.New("provider detail") }, ErrMirrorUnavailable},
		{"content conflict", func(fake *fakeCOS) { fake.readBody = []byte("different") }, ErrObjectConflict},
		{"retention unavailable", func(fake *fakeCOS) { fake.retentionErr = errors.New("provider detail") }, ErrMirrorUnavailable},
		{"retention mode wrong", func(fake *fakeCOS) {
			fake.retention = COSObjectRetention{Mode: "GOVERNANCE", RetainUntil: writerNow.Add(400 * 24 * time.Hour)}
		}, ErrMirrorInvalid},
		{"retention too short", func(fake *fakeCOS) {
			fake.retention = COSObjectRetention{Mode: COSComplianceMode, RetainUntil: writerNow.Add(300 * 24 * time.Hour)}
		}, ErrMirrorInvalid},
		{"retention not UTC", func(fake *fakeCOS) {
			fake.retention = COSObjectRetention{Mode: COSComplianceMode, RetainUntil: writerNow.Add(400 * 24 * time.Hour).In(time.FixedZone("offset", 3600))}
		}, ErrMirrorInvalid},
		{"created retention mismatch", func(fake *fakeCOS) {
			fake.retention = COSObjectRetention{Mode: COSComplianceMode, RetainUntil: writerNow.Add(366 * 24 * time.Hour)}
		}, ErrMirrorInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer, _, cos := validWriterHarness(t)
			test.mutate(cos)
			if _, err := writer.Write(context.Background(), validEnvelopeJSON(t)); !errors.Is(err, test.want) {
				t.Fatalf("Write() error = %v, want %v", err, test.want)
			}
		})
	}
}
