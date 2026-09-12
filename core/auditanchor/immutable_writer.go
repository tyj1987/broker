package auditanchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	AuditObjectRetentionDays = 365
	AuditObjectMaxBytes      = 16 * 1024
	COSComplianceMode        = "COMPLIANCE"
	objectRetentionGrace     = 5 * time.Minute
)

var (
	ErrObjectWriteRejected = errors.New("audit anchor object write rejected")
	ErrPrimaryUnavailable  = errors.New("audit anchor primary store unavailable")
	ErrPrimaryInvalid      = errors.New("audit anchor primary store response invalid")
	ErrMirrorUnavailable   = errors.New("audit anchor mirror store unavailable")
	ErrMirrorInvalid       = errors.New("audit anchor mirror store response invalid")
	ErrObjectConflict      = errors.New("audit anchor immutable object conflict")
)

var (
	objectPrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/-]{0,126}[a-z0-9]$`)
	bucketPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	timestampPattern    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	signaturePattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

type OSSBucketWORMState struct {
	Status          string
	RetentionDays   int
	VersioningState string
}

type COSObjectLockState struct {
	Enabled         bool
	VersioningState string
}

type ObjectCreateResult struct {
	Status string
}

type OSSCreateObjectRequest struct {
	Bucket          string
	Key             string
	Body            []byte
	ContentType     string
	ForbidOverwrite bool
}

type COSCreateObjectRequest struct {
	Bucket       string
	Key          string
	Body         []byte
	ContentType  string
	StorageClass string
	LockMode     string
	RetainUntil  time.Time
}

type COSObjectRetention struct {
	Mode        string
	RetainUntil time.Time
}

// OSSImmutableClient is a narrow transport boundary. The production adapter
// must map CreateObject to PutObject with x-oss-forbid-overwrite=true and map a
// duplicate key to Status "exists". It must not expose delete, copy, ACL or
// retention-policy mutation operations to this workload.
type OSSImmutableClient interface {
	InspectBucketWORM(context.Context, string) (OSSBucketWORMState, error)
	CreateObject(context.Context, OSSCreateObjectRequest) (ObjectCreateResult, error)
	ReadObject(context.Context, string, string) ([]byte, error)
}

// COSImmutableClient is a narrow transport boundary. The production adapter
// must apply the requested per-object COMPLIANCE retention during PutObject
// and map an immutable duplicate key to Status "exists".
type COSImmutableClient interface {
	InspectObjectLock(context.Context, string) (COSObjectLockState, error)
	CreateObject(context.Context, COSCreateObjectRequest) (ObjectCreateResult, error)
	ReadObject(context.Context, string, string) ([]byte, error)
	ReadObjectRetention(context.Context, string, string) (COSObjectRetention, error)
}

type ImmutableObjectWriterConfig struct {
	OSSBucket string
	COSBucket string
	Prefix    string
	Now       func() time.Time
}

type ImmutableObjectReceipt struct {
	Key          string
	BodySHA256   [sha256.Size]byte
	RetainUntil  time.Time
	PrimaryState string
	MirrorState  string
}

type ImmutableObjectWriter struct {
	config ImmutableObjectWriterConfig
	oss    OSSImmutableClient
	cos    COSImmutableClient
}

func NewImmutableObjectWriter(config ImmutableObjectWriterConfig, oss OSSImmutableClient, cos COSImmutableClient) (*ImmutableObjectWriter, error) {
	if !validWriterConfig(config) || oss == nil || cos == nil {
		return nil, ErrObjectWriteRejected
	}
	return &ImmutableObjectWriter{config: config, oss: oss, cos: cos}, nil
}

func validWriterConfig(config ImmutableObjectWriterConfig) bool {
	return bucketPattern.MatchString(config.OSSBucket) && bucketPattern.MatchString(config.COSBucket) &&
		objectPrefixPattern.MatchString(config.Prefix) && !strings.Contains(config.Prefix, "//") &&
		!strings.Contains(config.Prefix, "..") && config.Now != nil
}

func (writer *ImmutableObjectWriter) Write(ctx context.Context, envelopeJSON []byte) (ImmutableObjectReceipt, error) {
	if writer == nil || ctx == nil || writer.oss == nil || writer.cos == nil ||
		!validWriterConfig(writer.config) || ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	envelope, canonical, err := parseStoredEnvelope(envelopeJSON)
	if err != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	now := writer.config.Now().UTC()
	if now.IsZero() || now.Year() < 2020 || now.Year() > 9998 || now.Before(envelope.Payload.CapturedAt) {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	retainUntil := now.Add(AuditObjectRetentionDays*24*time.Hour + objectRetentionGrace)
	key := fmt.Sprintf("%s/%s/%020d-%s.json", writer.config.Prefix, envelope.Payload.StreamID,
		envelope.Payload.Sequence, envelope.PayloadDigest)
	bodyDigest := sha256.Sum256(canonical)

	primaryState, err := writer.oss.InspectBucketWORM(ctx, writer.config.OSSBucket)
	if err != nil {
		return ImmutableObjectReceipt{}, ErrPrimaryUnavailable
	}
	if ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	if primaryState.Status != "Locked" || primaryState.RetentionDays != AuditObjectRetentionDays ||
		primaryState.VersioningState != "Disabled" {
		return ImmutableObjectReceipt{}, ErrPrimaryInvalid
	}
	primaryResult, err := writer.oss.CreateObject(ctx, OSSCreateObjectRequest{
		Bucket: writer.config.OSSBucket, Key: key, Body: bytes.Clone(canonical),
		ContentType: "application/json", ForbidOverwrite: true,
	})
	if err != nil {
		return ImmutableObjectReceipt{}, ErrPrimaryUnavailable
	}
	if ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	if !validCreateStatus(primaryResult.Status) {
		return ImmutableObjectReceipt{}, ErrPrimaryInvalid
	}
	primaryBody, err := writer.oss.ReadObject(ctx, writer.config.OSSBucket, key)
	if err != nil {
		return ImmutableObjectReceipt{}, ErrPrimaryUnavailable
	}
	if ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	if !bytes.Equal(primaryBody, canonical) {
		return ImmutableObjectReceipt{}, ErrObjectConflict
	}

	mirrorState, err := writer.cos.InspectObjectLock(ctx, writer.config.COSBucket)
	if err != nil {
		return ImmutableObjectReceipt{}, ErrMirrorUnavailable
	}
	if ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	if !mirrorState.Enabled || mirrorState.VersioningState != "Enabled" {
		return ImmutableObjectReceipt{}, ErrMirrorInvalid
	}
	mirrorResult, err := writer.cos.CreateObject(ctx, COSCreateObjectRequest{
		Bucket: writer.config.COSBucket, Key: key, Body: bytes.Clone(canonical),
		ContentType: "application/json", StorageClass: "STANDARD",
		LockMode: COSComplianceMode, RetainUntil: retainUntil,
	})
	if err != nil {
		return ImmutableObjectReceipt{}, ErrMirrorUnavailable
	}
	if ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	if !validCreateStatus(mirrorResult.Status) {
		return ImmutableObjectReceipt{}, ErrMirrorInvalid
	}
	mirrorBody, err := writer.cos.ReadObject(ctx, writer.config.COSBucket, key)
	if err != nil {
		return ImmutableObjectReceipt{}, ErrMirrorUnavailable
	}
	if ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	if !bytes.Equal(mirrorBody, canonical) {
		return ImmutableObjectReceipt{}, ErrObjectConflict
	}
	retention, err := writer.cos.ReadObjectRetention(ctx, writer.config.COSBucket, key)
	if err != nil {
		return ImmutableObjectReceipt{}, ErrMirrorUnavailable
	}
	if ctx.Err() != nil {
		return ImmutableObjectReceipt{}, ErrObjectWriteRejected
	}
	minimumRetention := envelope.Payload.CapturedAt.Add(AuditObjectRetentionDays * 24 * time.Hour)
	if retention.Mode != COSComplianceMode || retention.RetainUntil.Location() != time.UTC ||
		retention.RetainUntil.Before(minimumRetention) ||
		(mirrorResult.Status == "created" && !retention.RetainUntil.Equal(retainUntil)) {
		return ImmutableObjectReceipt{}, ErrMirrorInvalid
	}

	return ImmutableObjectReceipt{
		Key: key, BodySHA256: bodyDigest, RetainUntil: retention.RetainUntil,
		PrimaryState: primaryResult.Status, MirrorState: mirrorResult.Status,
	}, nil
}

func validCreateStatus(status string) bool { return status == "created" || status == "exists" }

type storedEnvelope struct {
	Version       int             `json:"version"`
	Payload       storedPayload   `json:"payload"`
	PayloadDigest string          `json:"payload_digest"`
	Signature     storedSignature `json:"signature"`
}

type storedPayload struct {
	Purpose              string    `json:"purpose"`
	Version              int       `json:"version"`
	StreamID             string    `json:"stream_id"`
	Sequence             int64     `json:"sequence"`
	CapturedAtRaw        string    `json:"captured_at"`
	ChainHead            string    `json:"chain_head"`
	EventCount           int64     `json:"event_count"`
	FileCount            int64     `json:"file_count"`
	PreviousAnchorDigest string    `json:"previous_anchor_digest"`
	CapturedAt           time.Time `json:"-"`
}

type storedSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

func parseStoredEnvelope(value []byte) (storedEnvelope, []byte, error) {
	if len(value) == 0 || len(value) > AuditObjectMaxBytes {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	if err := rejectDuplicateJSONKeys(value); err != nil {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	var envelope storedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return storedEnvelope{}, nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	if envelope.Version != 1 || envelope.Payload.Version != 1 ||
		envelope.Payload.Purpose != Purpose || !idPattern.MatchString(envelope.Payload.StreamID) ||
		envelope.Payload.Sequence < 1 || envelope.Payload.EventCount < 0 || envelope.Payload.FileCount < 0 ||
		!validHexDigest(envelope.PayloadDigest) || !validHexDigest(envelope.Payload.ChainHead) ||
		!validHexDigest(envelope.Payload.PreviousAnchorDigest) ||
		(envelope.Payload.Sequence == 1 && envelope.Payload.PreviousAnchorDigest != strings.Repeat("0", 64)) ||
		(envelope.Payload.Sequence > 1 && envelope.Payload.PreviousAnchorDigest == strings.Repeat("0", 64)) ||
		(envelope.Payload.EventCount == 0 &&
			(envelope.Payload.ChainHead != strings.Repeat("0", 64) || envelope.Payload.FileCount != 0)) ||
		(envelope.Payload.EventCount > 0 &&
			(envelope.Payload.ChainHead == strings.Repeat("0", 64) || envelope.Payload.FileCount < 1)) ||
		!supportedSignature(envelope.Signature) {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	capturedAt, err := time.Parse("2006-01-02T15:04:05.000Z", envelope.Payload.CapturedAtRaw)
	if err != nil || !timestampPattern.MatchString(envelope.Payload.CapturedAtRaw) {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	envelope.Payload.CapturedAt = capturedAt.UTC()

	var generic map[string]any
	genericDecoder := json.NewDecoder(bytes.NewReader(value))
	genericDecoder.UseNumber()
	if err := genericDecoder.Decode(&generic); err != nil {
		return storedEnvelope{}, nil, err
	}
	payload, ok := generic["payload"].(map[string]any)
	signature, signatureOK := generic["signature"].(map[string]any)
	if !ok || !signatureOK || !hasExactJSONKeys(generic, "version", "payload", "payload_digest", "signature") ||
		!hasExactJSONKeys(payload, "purpose", "version", "stream_id", "sequence", "captured_at", "chain_head", "event_count", "file_count", "previous_anchor_digest") ||
		!hasExactJSONKeys(signature, "algorithm", "key_id", "value") {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil {
		return storedEnvelope{}, nil, err
	}
	payloadDigest := sha256.Sum256(canonicalPayload)
	if hex.EncodeToString(payloadDigest[:]) != envelope.PayloadDigest {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	canonical, err := json.Marshal(generic)
	if err != nil || len(canonical) > AuditObjectMaxBytes {
		return storedEnvelope{}, nil, ErrObjectWriteRejected
	}
	return envelope, canonical, nil
}

func rejectDuplicateJSONKeys(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrObjectWriteRejected
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrObjectWriteRejected
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrObjectWriteRejected
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrObjectWriteRejected
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrObjectWriteRejected
		}
	default:
		return ErrObjectWriteRejected
	}
	return nil
}

func hasExactJSONKeys(value map[string]any, expected ...string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func validHexDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func supportedSignature(signature storedSignature) bool {
	if _, ok := supportedAlgorithms[signature.Algorithm]; !ok || !idPattern.MatchString(signature.KeyID) ||
		len(signature.Value) < 43 || len(signature.Value) > 4096 ||
		!signaturePattern.MatchString(signature.Value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature.Value)
	return err == nil && len(decoded) >= MinSignatureBytes && len(decoded) <= MaxSignatureBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) == signature.Value
}
