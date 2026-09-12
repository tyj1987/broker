package auditanchor

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
	"math/big"
	"strconv"
	"testing"
	"time"
)

var writerNow = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

const (
	writerKeyID     = "audit-anchor-key-2026-01"
	nextWriterKeyID = "audit-anchor-key-2026-02"
)

var (
	writerPrivateKey     = deterministicPrivateKey(42)
	nextWriterPrivateKey = deterministicPrivateKey(43)
)

func deterministicPrivateKey(value int64) *ecdsa.PrivateKey {
	privateKey := &ecdsa.PrivateKey{D: big.NewInt(value)}
	privateKey.PublicKey.Curve = elliptic.P256()
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKey.D.Bytes())
	return privateKey
}

type fakeOSS struct {
	state        OSSBucketWORMState
	stateErr     error
	create       ObjectCreateResult
	createErr    error
	readBody     []byte
	readErr      error
	readBodies   map[string][]byte
	readErrors   map[string]error
	readKeys     []string
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

func (fake *fakeOSS) ReadObject(_ context.Context, _, key string) ([]byte, error) {
	fake.readKeys = append(fake.readKeys, key)
	if fake.afterRead != nil {
		fake.afterRead()
	}
	if err, ok := fake.readErrors[key]; ok {
		return nil, err
	}
	if body, ok := fake.readBodies[key]; ok {
		return bytes.Clone(body), nil
	}
	if fake.readBody != nil {
		return bytes.Clone(fake.readBody), fake.readErr
	}
	return bytes.Clone(fake.createdBody), fake.readErr
}

type fakeCOS struct {
	state           COSObjectLockState
	stateErr        error
	create          ObjectCreateResult
	createErr       error
	readBody        []byte
	readErr         error
	readBodies      map[string][]byte
	readErrors      map[string]error
	readKeys        []string
	retention       COSObjectRetention
	retentionErr    error
	retentions      map[string]COSObjectRetention
	retentionErrors map[string]error
	retentionKeys   []string
	request         COSCreateObjectRequest
	createdBody     []byte
	afterInspect    func()
	afterCreate     func()
	afterRead       func()
	afterRetention  func()
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

func (fake *fakeCOS) ReadObject(_ context.Context, _, key string) ([]byte, error) {
	fake.readKeys = append(fake.readKeys, key)
	if fake.afterRead != nil {
		fake.afterRead()
	}
	if err, ok := fake.readErrors[key]; ok {
		return nil, err
	}
	if body, ok := fake.readBodies[key]; ok {
		return bytes.Clone(body), nil
	}
	if fake.readBody != nil {
		return bytes.Clone(fake.readBody), fake.readErr
	}
	return bytes.Clone(fake.createdBody), fake.readErr
}

func (fake *fakeCOS) ReadObjectRetention(_ context.Context, _, key string) (COSObjectRetention, error) {
	fake.retentionKeys = append(fake.retentionKeys, key)
	if fake.afterRetention != nil {
		fake.afterRetention()
	}
	if err, ok := fake.retentionErrors[key]; ok {
		return COSObjectRetention{}, err
	}
	if retention, ok := fake.retentions[key]; ok {
		return retention, nil
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
	writer, err := NewImmutableObjectWriter(validWriterTestConfig(), oss, cos)
	if err != nil {
		t.Fatalf("NewImmutableObjectWriter() error = %v", err)
	}
	return writer, oss, cos
}

func validWriterTestConfig() ImmutableObjectWriterConfig {
	return ImmutableObjectWriterConfig{
		OSSBucket: "broker-audit-primary", COSBucket: "broker-audit-mirror-1250000000",
		Prefix: "audit-anchors/v1", StreamID: "broker-production",
		TrustedKeys: map[string]TrustedSigningKey{writerKeyID: {
			PublicKey: &writerPrivateKey.PublicKey, ValidFromSequence: 1,
		}},
		Now: func() time.Time { return writerNow },
	}
}

func validEnvelopeJSON(t *testing.T) []byte {
	t.Helper()
	return envelopeJSON(t, 1, stringsOf('0', 64), "2026-09-12T11:59:00.000Z")
}

func envelopeJSON(t *testing.T, sequence int64, previousDigest, capturedAt string) []byte {
	return envelopeJSONWithKey(t, sequence, previousDigest, capturedAt, writerKeyID, writerPrivateKey)
}

func envelopeJSONWithKey(t *testing.T, sequence int64, previousDigest, capturedAt, keyID string, privateKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	payload := map[string]any{
		"purpose": Purpose, "version": 1, "stream_id": "broker-production", "sequence": sequence,
		"captured_at": capturedAt, "chain_head": stringsOf('a', 64),
		"event_count": sequence * 4, "file_count": 1, "previous_anchor_digest": previousDigest,
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonicalPayload)
	signingInput := []byte(SignatureContext + "\x00ecdsa-p256-sha256\x00" + keyID +
		"\x00broker-production\x00" + strconv.FormatInt(sequence, 10) + "\x00" + previousDigest +
		"\x00" + hex.EncodeToString(digest[:]))
	signingDigest := sha256.Sum256(signingInput)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, signingDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	envelope := map[string]any{
		"version": 1, "payload": payload, "payload_digest": hex.EncodeToString(digest[:]),
		"signature": map[string]any{
			"algorithm": "ecdsa-p256-sha256", "key_id": keyID,
			"value": base64.RawURLEncoding.EncodeToString(signature),
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
	receipt, err := writer.Write(context.Background(), body)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	wantKey := "audit-anchors/v1/broker-production/00000000000000000001.json"
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

func TestImmutableObjectWriterRequiresIdenticalRetainedPredecessor(t *testing.T) {
	writer, oss, cos := validWriterHarness(t)
	previousBody := validEnvelopeJSON(t)
	previous, previousCanonical, err := parseStoredEnvelope(previousBody)
	if err != nil {
		t.Fatal(err)
	}
	currentBody := envelopeJSON(t, 2, previous.PayloadDigest, "2026-09-12T11:59:30.000Z")
	previousKey := "audit-anchors/v1/broker-production/00000000000000000001.json"
	currentKey := "audit-anchors/v1/broker-production/00000000000000000002.json"
	oss.readBodies = map[string][]byte{previousKey: previousCanonical}
	cos.readBodies = map[string][]byte{previousKey: previousCanonical}
	cos.retentions = map[string]COSObjectRetention{
		previousKey: {
			Mode:        COSComplianceMode,
			RetainUntil: previous.Payload.CapturedAt.Add(AuditObjectRetentionDays * 24 * time.Hour),
		},
	}

	receipt, err := writer.Write(context.Background(), currentBody)
	if err != nil {
		t.Fatalf("Write(sequence 2) error = %v", err)
	}
	if receipt.Key != currentKey || !equalStrings(oss.readKeys, []string{previousKey, currentKey}) ||
		!equalStrings(cos.readKeys, []string{previousKey, currentKey}) ||
		!equalStrings(cos.retentionKeys, []string{previousKey, currentKey}) {
		t.Fatalf("unexpected predecessor/current calls: receipt=%#v oss=%v cos=%v retention=%v", receipt, oss.readKeys, cos.readKeys, cos.retentionKeys)
	}
}

func TestImmutableObjectWriterFailsClosedOnInvalidPredecessor(t *testing.T) {
	previous, previousCanonical, err := parseStoredEnvelope(validEnvelopeJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	previousKey := "audit-anchors/v1/broker-production/00000000000000000001.json"
	validRetention := COSObjectRetention{
		Mode:        COSComplianceMode,
		RetainUntil: previous.Payload.CapturedAt.Add(AuditObjectRetentionDays * 24 * time.Hour),
	}
	tests := []struct {
		name   string
		mutate func(*fakeOSS, *fakeCOS, *string)
		want   error
	}{
		{"primary missing", func(oss *fakeOSS, _ *fakeCOS, _ *string) { oss.readErrors[previousKey] = ErrImmutableObjectNotFound }, ErrPrimaryInvalid},
		{"primary unavailable", func(oss *fakeOSS, _ *fakeCOS, _ *string) { oss.readErrors[previousKey] = errors.New("provider detail") }, ErrPrimaryUnavailable},
		{"primary not canonical", func(oss *fakeOSS, _ *fakeCOS, _ *string) { oss.readBodies[previousKey] = validEnvelopeJSON(t) }, ErrPrimaryInvalid},
		{"primary signature invalid", func(oss *fakeOSS, _ *fakeCOS, _ *string) {
			oss.readBodies[previousKey] = tamperEnvelopeSignature(t, previousCanonical)
		}, ErrPrimaryInvalid},
		{"predecessor digest mismatch", func(_ *fakeOSS, _ *fakeCOS, digest *string) { *digest = stringsOf('b', 64) }, ErrPrimaryInvalid},
		{"mirror missing", func(_ *fakeOSS, cos *fakeCOS, _ *string) { cos.readErrors[previousKey] = ErrImmutableObjectNotFound }, ErrMirrorInvalid},
		{"mirror unavailable", func(_ *fakeOSS, cos *fakeCOS, _ *string) { cos.readErrors[previousKey] = errors.New("provider detail") }, ErrMirrorUnavailable},
		{"mirror conflict", func(_ *fakeOSS, cos *fakeCOS, _ *string) { cos.readBodies[previousKey] = []byte("different") }, ErrObjectConflict},
		{"retention unavailable", func(_ *fakeOSS, cos *fakeCOS, _ *string) {
			cos.retentionErrors[previousKey] = errors.New("provider detail")
		}, ErrMirrorUnavailable},
		{"retention mode", func(_ *fakeOSS, cos *fakeCOS, _ *string) {
			value := validRetention
			value.Mode = "GOVERNANCE"
			cos.retentions[previousKey] = value
		}, ErrMirrorInvalid},
		{"retention too short", func(_ *fakeOSS, cos *fakeCOS, _ *string) {
			value := validRetention
			value.RetainUntil = value.RetainUntil.Add(-time.Second)
			cos.retentions[previousKey] = value
		}, ErrMirrorInvalid},
		{"retention not UTC", func(_ *fakeOSS, cos *fakeCOS, _ *string) {
			value := validRetention
			value.RetainUntil = value.RetainUntil.In(time.FixedZone("offset", 3600))
			cos.retentions[previousKey] = value
		}, ErrMirrorInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer, oss, cos := validWriterHarness(t)
			oss.readBodies = map[string][]byte{previousKey: previousCanonical}
			oss.readErrors = map[string]error{}
			cos.readBodies = map[string][]byte{previousKey: previousCanonical}
			cos.readErrors = map[string]error{}
			cos.retentions = map[string]COSObjectRetention{previousKey: validRetention}
			cos.retentionErrors = map[string]error{}
			predecessorDigest := previous.PayloadDigest
			test.mutate(oss, cos, &predecessorDigest)
			currentBody := envelopeJSON(t, 2, predecessorDigest, "2026-09-12T11:59:30.000Z")
			if _, err := writer.Write(context.Background(), currentBody); !errors.Is(err, test.want) {
				t.Fatalf("Write() error = %v, want %v", err, test.want)
			}
			if oss.request.Key != "" || cos.request.Key != "" {
				t.Fatalf("write occurred after predecessor failure: oss=%q cos=%q", oss.request.Key, cos.request.Key)
			}
		})
	}
}

func TestImmutableObjectWriterStopsOnPredecessorCancellation(t *testing.T) {
	previous, previousCanonical, err := parseStoredEnvelope(validEnvelopeJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	previousKey := "audit-anchors/v1/broker-production/00000000000000000001.json"
	tests := []struct {
		name   string
		attach func(*fakeOSS, *fakeCOS, func())
	}{
		{"primary read", func(oss *fakeOSS, _ *fakeCOS, cancel func()) { oss.afterRead = cancel }},
		{"mirror read", func(_ *fakeOSS, cos *fakeCOS, cancel func()) { cos.afterRead = cancel }},
		{"retention read", func(_ *fakeOSS, cos *fakeCOS, cancel func()) { cos.afterRetention = cancel }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer, oss, cos := validWriterHarness(t)
			oss.readBodies = map[string][]byte{previousKey: previousCanonical}
			cos.readBodies = map[string][]byte{previousKey: previousCanonical}
			cos.retentions = map[string]COSObjectRetention{previousKey: {
				Mode: COSComplianceMode, RetainUntil: previous.Payload.CapturedAt.Add(AuditObjectRetentionDays * 24 * time.Hour),
			}}
			ctx, cancel := context.WithCancel(context.Background())
			test.attach(oss, cos, cancel)
			currentBody := envelopeJSON(t, 2, previous.PayloadDigest, "2026-09-12T11:59:30.000Z")
			if _, err := writer.Write(ctx, currentBody); !errors.Is(err, ErrObjectWriteRejected) {
				t.Fatalf("Write() error = %v", err)
			}
			if oss.request.Key != "" || cos.request.Key != "" {
				t.Fatal("write occurred after predecessor cancellation")
			}
		})
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func tamperEnvelopeSignature(t *testing.T, body []byte) []byte {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	signature := envelope["signature"].(map[string]any)
	decoded, err := base64.RawURLEncoding.DecodeString(signature["value"].(string))
	if err != nil || len(decoded) == 0 {
		t.Fatalf("invalid test signature: %v", err)
	}
	decoded[0] ^= 0x01
	signature["value"] = base64.RawURLEncoding.EncodeToString(decoded)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
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
	validConfig := validWriterTestConfig()
	if _, err := NewImmutableObjectWriter(validConfig, nil, validCOS); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("nil OSS error = %v", err)
	}
	if _, err := NewImmutableObjectWriter(validConfig, validOSS, nil); !errors.Is(err, ErrObjectWriteRejected) {
		t.Fatalf("nil COS error = %v", err)
	}
	invalidKey := writerPrivateKey.PublicKey
	invalidKey.X = big.NewInt(1)
	invalidKey.Y = big.NewInt(1)
	invalidConfigs := []ImmutableObjectWriterConfig{
		func() ImmutableObjectWriterConfig {
			value := validWriterTestConfig()
			value.StreamID = ""
			return value
		}(),
		func() ImmutableObjectWriterConfig {
			value := validWriterTestConfig()
			value.TrustedKeys = nil
			return value
		}(),
		func() ImmutableObjectWriterConfig {
			value := validWriterTestConfig()
			value.TrustedKeys = map[string]TrustedSigningKey{"bad key": {
				PublicKey: &writerPrivateKey.PublicKey, ValidFromSequence: 1,
			}}
			return value
		}(),
		func() ImmutableObjectWriterConfig {
			value := validWriterTestConfig()
			value.TrustedKeys = map[string]TrustedSigningKey{writerKeyID: {ValidFromSequence: 1}}
			return value
		}(),
		func() ImmutableObjectWriterConfig {
			value := validWriterTestConfig()
			value.TrustedKeys = map[string]TrustedSigningKey{writerKeyID: {
				PublicKey: &invalidKey, ValidFromSequence: 1,
			}}
			return value
		}(),
		func() ImmutableObjectWriterConfig {
			value := validWriterTestConfig()
			key := value.TrustedKeys[writerKeyID]
			key.ValidFromSequence = 0
			value.TrustedKeys[writerKeyID] = key
			return value
		}(),
		func() ImmutableObjectWriterConfig {
			value := validWriterTestConfig()
			key := value.TrustedKeys[writerKeyID]
			key.ValidFromSequence = 2
			key.ValidThroughSequence = 1
			value.TrustedKeys[writerKeyID] = key
			return value
		}(),
		func() ImmutableObjectWriterConfig { value := validWriterTestConfig(); value.Now = nil; return value }(),
	}
	for _, config := range invalidConfigs {
		if _, err := NewImmutableObjectWriter(config, validOSS, validCOS); !errors.Is(err, ErrObjectWriteRejected) {
			t.Fatalf("invalid trust configuration error = %v", err)
		}
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

func TestImmutableObjectWriterVerifiesSignatureTrustBeforeStoreAccess(t *testing.T) {
	validBody := validEnvelopeJSON(t)
	tests := []struct {
		name       string
		configure  func(*ImmutableObjectWriterConfig)
		mutateBody func(map[string]any)
	}{
		{"signature tampered", nil, func(value map[string]any) {
			signature := value["signature"].(map[string]any)
			encoded := signature["value"].(string)
			if encoded[len(encoded)-1] == 'A' {
				signature["value"] = encoded[:len(encoded)-1] + "B"
			} else {
				signature["value"] = encoded[:len(encoded)-1] + "A"
			}
		}},
		{"algorithm mismatch", nil, func(value map[string]any) { value["signature"].(map[string]any)["algorithm"] = "ed25519" }},
		{"unknown key", nil, func(value map[string]any) { value["signature"].(map[string]any)["key_id"] = "unknown-key" }},
		{"key not active", func(config *ImmutableObjectWriterConfig) {
			key := config.TrustedKeys[writerKeyID]
			key.ValidFromSequence = 2
			config.TrustedKeys[writerKeyID] = key
		}, nil},
		{"stream mismatch", func(config *ImmutableObjectWriterConfig) { config.StreamID = "other-production" }, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validWriterTestConfig()
			if test.configure != nil {
				test.configure(&config)
			}
			body := bytes.Clone(validBody)
			if test.mutateBody != nil {
				var envelope map[string]any
				if err := json.Unmarshal(body, &envelope); err != nil {
					t.Fatal(err)
				}
				test.mutateBody(envelope)
				body, _ = json.Marshal(envelope)
			}
			oss := &fakeOSS{}
			cos := &fakeCOS{}
			writer, err := NewImmutableObjectWriter(config, oss, cos)
			if err != nil {
				t.Fatalf("NewImmutableObjectWriter() error = %v", err)
			}
			if _, err := writer.Write(context.Background(), body); !errors.Is(err, ErrObjectWriteRejected) {
				t.Fatalf("Write() error = %v", err)
			}
			if oss.request.Key != "" || cos.request.Key != "" {
				t.Fatal("untrusted envelope reached a store")
			}
		})
	}
}

func TestImmutableObjectWriterEnforcesSigningKeySequenceEpochs(t *testing.T) {
	config := validWriterTestConfig()
	config.TrustedKeys = map[string]TrustedSigningKey{
		writerKeyID: {
			PublicKey: &writerPrivateKey.PublicKey, ValidFromSequence: 1, ValidThroughSequence: 1,
		},
		nextWriterKeyID: {
			PublicKey: &nextWriterPrivateKey.PublicKey, ValidFromSequence: 2,
		},
	}
	oldEnvelope, _, err := parseStoredEnvelope(envelopeJSONWithKey(
		t, 1, stringsOf('0', 64), "2026-09-12T11:58:00.000Z", writerKeyID, writerPrivateKey,
	))
	if err != nil || !verifyStoredEnvelopeSignature(config, oldEnvelope) {
		t.Fatalf("old key was not accepted inside its epoch: %v", err)
	}
	expiredEnvelope, _, err := parseStoredEnvelope(envelopeJSONWithKey(
		t, 2, oldEnvelope.PayloadDigest, "2026-09-12T11:59:00.000Z", writerKeyID, writerPrivateKey,
	))
	if err != nil {
		t.Fatal(err)
	}
	if verifyStoredEnvelopeSignature(config, expiredEnvelope) {
		t.Fatal("old key was accepted after its sequence epoch")
	}
	rotatedEnvelope, _, err := parseStoredEnvelope(envelopeJSONWithKey(
		t, 2, oldEnvelope.PayloadDigest, "2026-09-12T11:59:00.000Z", nextWriterKeyID, nextWriterPrivateKey,
	))
	if err != nil || !verifyStoredEnvelopeSignature(config, rotatedEnvelope) {
		t.Fatalf("new key was not accepted inside its epoch: %v", err)
	}
}

func TestImmutableObjectWriterClonesTrustConfiguration(t *testing.T) {
	config := validWriterTestConfig()
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(), X: new(big.Int).Set(writerPrivateKey.X), Y: new(big.Int).Set(writerPrivateKey.Y),
	}
	config.TrustedKeys = map[string]TrustedSigningKey{writerKeyID: {
		PublicKey: publicKey, ValidFromSequence: 1,
	}}
	writer, err := NewImmutableObjectWriter(config, &fakeOSS{
		state:  OSSBucketWORMState{Status: "Locked", RetentionDays: 365, VersioningState: "Disabled"},
		create: ObjectCreateResult{Status: "created"},
	}, &fakeCOS{
		state:  COSObjectLockState{Enabled: true, VersioningState: "Enabled"},
		create: ObjectCreateResult{Status: "created"},
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(config.TrustedKeys, writerKeyID)
	publicKey.X.SetInt64(0)
	if _, err := writer.Write(context.Background(), validEnvelopeJSON(t)); err != nil {
		t.Fatalf("external trust-map mutation affected writer: %v", err)
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

func TestImmutableObjectWriterValidatesBothStoreControlsBeforeWriting(t *testing.T) {
	writer, oss, cos := validWriterHarness(t)
	cos.state.VersioningState = "Suspended"
	if _, err := writer.Write(context.Background(), validEnvelopeJSON(t)); !errors.Is(err, ErrMirrorInvalid) {
		t.Fatalf("Write() error = %v", err)
	}
	if oss.request.Key != "" || cos.request.Key != "" {
		t.Fatalf("write occurred before both stores were validated: oss=%q cos=%q", oss.request.Key, cos.request.Key)
	}
}
