// Package auditmirrorworker implements the independently isolated Tencent COS
// mirror capability. It accepts only auditmirror's typed contract and never
// exposes a cloud endpoint, credential, object key or retention mutation to the
// audit-store process.
package auditmirrorworker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
)

var (
	bucketPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	versionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$`)
)

type COSCreateResult struct {
	Status    string
	VersionID string
}

type COSClient interface {
	InspectObjectLock(context.Context, string) (auditanchor.COSObjectLockState, error)
	CreateVersionedObject(context.Context, auditanchor.COSCreateObjectRequest) (COSCreateResult, error)
	ResolveObjectVersion(context.Context, string, string) (string, error)
	ReadObjectVersion(context.Context, string, string, string) ([]byte, error)
	ReadObjectRetentionVersion(context.Context, string, string, string) (auditanchor.COSObjectRetention, error)
	ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error)
}

type Config struct {
	StreamID    string
	Prefix      string
	ProfileID   string
	Bucket      string
	Region      string
	TrustedKeys map[string]auditanchor.TrustedSigningKey
}

type Backend struct {
	binding  auditmirror.Binding
	bucket   string
	prefix   string
	client   COSClient
	verifier *auditanchor.EnvelopeVerifier
	now      func() time.Time
	writes   chan struct{}
}

func NewBackend(config Config, client COSClient) (*Backend, error) {
	return newBackend(config, client, time.Now)
}

func newBackend(config Config, client COSClient, now func() time.Time) (*Backend, error) {
	if client == nil || now == nil || !bucketPattern.MatchString(config.Bucket) ||
		!bucketPattern.MatchString(config.Region) ||
		auditmirror.RetentionDays != auditanchor.AuditObjectRetentionDays ||
		auditmirror.RetentionGrace != auditanchor.AuditObjectRetentionGrace {
		return nil, auditmirror.ErrContractRejected
	}
	generation, err := auditanchor.TrustedKeyGeneration(config.TrustedKeys)
	if err != nil {
		return nil, auditmirror.ErrContractRejected
	}
	binding, err := auditmirror.NewBinding(config.StreamID, config.Prefix, config.ProfileID, generation)
	if err != nil {
		return nil, auditmirror.ErrContractRejected
	}
	verifier, err := auditanchor.NewEnvelopeVerifier(config.StreamID, config.TrustedKeys)
	if err != nil {
		return nil, auditmirror.ErrContractRejected
	}
	return &Backend{
		binding: binding, bucket: config.Bucket,
		prefix: config.Prefix + "/" + config.StreamID + "/",
		client: client, verifier: verifier, now: now, writes: make(chan struct{}, 1),
	}, nil
}

func (backend *Backend) Binding() auditmirror.Binding {
	if backend == nil {
		return auditmirror.Binding{}
	}
	return backend.binding
}

func (backend *Backend) Inspect(ctx context.Context, request auditmirror.InspectRequest) (auditmirror.LockState, error) {
	if !backend.valid(ctx) || !request.ValidFor(backend.binding) {
		return auditmirror.LockState{}, auditmirror.ErrContractRejected
	}
	state, err := backend.client.InspectObjectLock(ctx, backend.bucket)
	if err != nil || ctx.Err() != nil {
		return auditmirror.LockState{}, auditmirror.ErrUnavailable
	}
	if !state.Enabled || state.VersioningState != "Enabled" {
		return auditmirror.LockState{}, auditmirror.ErrUnavailable
	}
	return auditmirror.LockState{
		Compliance: true, Versioning: true, RetentionDays: auditmirror.RetentionDays,
		TrustGeneration: backend.binding.TrustGeneration(),
	}, nil
}

func (backend *Backend) Create(ctx context.Context, request auditmirror.CreateRequest) (auditmirror.CreateResult, error) {
	if !backend.valid(ctx) {
		return auditmirror.CreateResult{}, auditmirror.ErrContractRejected
	}
	now := backend.now().UTC()
	if !request.ValidAt(backend.binding, now) {
		return auditmirror.CreateResult{}, auditmirror.ErrContractRejected
	}
	metadata, canonical, err := backend.verifier.Verify(request.Envelope())
	if err != nil || metadata.StreamID != backend.binding.StreamID() ||
		metadata.Sequence != request.Sequence() || !bytes.Equal(canonical, request.Envelope()) ||
		metadata.CapturedAt.After(request.IssuedAt()) {
		return auditmirror.CreateResult{}, auditmirror.ErrContractRejected
	}
	select {
	case backend.writes <- struct{}{}:
		defer func() { <-backend.writes }()
	case <-ctx.Done():
		return auditmirror.CreateResult{}, auditmirror.ErrContractRejected
	}
	operationContext, cancel := context.WithTimeout(ctx, auditmirror.MaxMirrorWriteDuration)
	defer cancel()
	controls, err := backend.client.InspectObjectLock(operationContext, backend.bucket)
	if err != nil || operationContext.Err() != nil || !controls.Enabled || controls.VersioningState != "Enabled" {
		return auditmirror.CreateResult{}, auditmirror.ErrUnavailable
	}
	if !backend.validPredecessor(operationContext, metadata) {
		return auditmirror.CreateResult{}, auditmirror.ErrUnavailable
	}
	key := backend.objectKey(request.Sequence())
	result, err := backend.client.CreateVersionedObject(operationContext, auditanchor.COSCreateObjectRequest{
		Bucket: backend.bucket, Key: key, Body: canonical, ContentType: "application/json",
		StorageClass: "STANDARD", LockMode: auditanchor.COSComplianceMode,
		RetainUntil: request.ExpectedRetainUntil(),
	})
	if err != nil || operationContext.Err() != nil || (result.Status != "created" && result.Status != "exists") ||
		!validVersionID(result.VersionID) {
		return auditmirror.CreateResult{}, auditmirror.ErrUnavailable
	}
	stored, err := backend.client.ReadObjectVersion(operationContext, backend.bucket, key, result.VersionID)
	if err != nil || operationContext.Err() != nil || !bytes.Equal(stored, canonical) || !backend.validEnvelope(stored, request.Sequence()) {
		return auditmirror.CreateResult{}, auditmirror.ErrUnavailable
	}
	retention, err := backend.client.ReadObjectRetentionVersion(operationContext, backend.bucket, key, result.VersionID)
	if err != nil || operationContext.Err() != nil || retention.Mode != auditanchor.COSComplianceMode ||
		retention.RetainUntil.Location() != time.UTC || !retention.RetainUntil.Equal(request.ExpectedRetainUntil()) {
		return auditmirror.CreateResult{}, auditmirror.ErrUnavailable
	}
	return auditmirror.CreateResult{Status: result.Status}, nil
}

func (backend *Backend) Read(ctx context.Context, request auditmirror.ReadRequest) (auditmirror.ReadResult, error) {
	if !backend.valid(ctx) || !request.ValidFor(backend.binding) {
		return auditmirror.ReadResult{}, auditmirror.ErrContractRejected
	}
	key := backend.objectKey(request.Sequence())
	versionID, err := backend.client.ResolveObjectVersion(ctx, backend.bucket, key)
	if err != nil || ctx.Err() != nil || !validVersionID(versionID) {
		if errors.Is(err, auditanchor.ErrImmutableObjectNotFound) && ctx.Err() == nil {
			return auditmirror.ReadResult{}, auditmirror.ErrNotFound
		}
		return auditmirror.ReadResult{}, auditmirror.ErrUnavailable
	}
	value, err := backend.client.ReadObjectVersion(ctx, backend.bucket, key, versionID)
	if ctx.Err() != nil {
		return auditmirror.ReadResult{}, auditmirror.ErrUnavailable
	}
	if err != nil || !backend.validEnvelope(value, request.Sequence()) {
		return auditmirror.ReadResult{}, auditmirror.ErrUnavailable
	}
	return auditmirror.ReadResult{Envelope: bytes.Clone(value)}, nil
}

func (backend *Backend) List(ctx context.Context, request auditmirror.ListRequest) (auditmirror.ListResult, error) {
	if !backend.valid(ctx) || !request.ValidFor(backend.binding) {
		return auditmirror.ListResult{}, auditmirror.ErrContractRejected
	}
	after := ""
	if request.After() > 0 {
		after = backend.objectKey(request.After())
	}
	page, err := backend.client.ListObjectKeys(ctx, backend.bucket, backend.prefix, after, request.Limit())
	if err != nil || ctx.Err() != nil || len(page.Keys) > request.Limit() ||
		(page.Truncated && (len(page.Keys) == 0 || page.NextAfter != page.Keys[len(page.Keys)-1])) ||
		(!page.Truncated && page.NextAfter != "") {
		return auditmirror.ListResult{}, auditmirror.ErrUnavailable
	}
	result := auditmirror.ListResult{Sequences: make([]int64, 0, len(page.Keys)), Truncated: page.Truncated}
	previous := request.After()
	for _, key := range page.Keys {
		sequence, ok := backend.sequenceForKey(key)
		if !ok || previous >= auditmirror.MaxSequence || sequence != previous+1 {
			return auditmirror.ListResult{}, auditmirror.ErrUnavailable
		}
		result.Sequences = append(result.Sequences, sequence)
		previous = sequence
	}
	if page.Truncated {
		result.NextAfter = previous
	}
	return result, nil
}

func (backend *Backend) Retention(ctx context.Context, request auditmirror.ReadRequest) (auditmirror.RetentionResult, error) {
	if !backend.valid(ctx) || !request.ValidFor(backend.binding) {
		return auditmirror.RetentionResult{}, auditmirror.ErrContractRejected
	}
	key := backend.objectKey(request.Sequence())
	versionID, err := backend.client.ResolveObjectVersion(ctx, backend.bucket, key)
	if err != nil || ctx.Err() != nil || !validVersionID(versionID) {
		if errors.Is(err, auditanchor.ErrImmutableObjectNotFound) && ctx.Err() == nil {
			return auditmirror.RetentionResult{}, auditmirror.ErrNotFound
		}
		return auditmirror.RetentionResult{}, auditmirror.ErrUnavailable
	}
	value, err := backend.client.ReadObjectRetentionVersion(ctx, backend.bucket, key, versionID)
	if ctx.Err() != nil {
		return auditmirror.RetentionResult{}, auditmirror.ErrUnavailable
	}
	if err != nil || value.Mode != auditanchor.COSComplianceMode ||
		value.RetainUntil.IsZero() || value.RetainUntil.Location() != time.UTC {
		return auditmirror.RetentionResult{}, auditmirror.ErrUnavailable
	}
	return auditmirror.RetentionResult{Mode: value.Mode, RetainUntil: value.RetainUntil}, nil
}

func (backend *Backend) valid(ctx context.Context) bool {
	return backend != nil && backend.client != nil && backend.verifier != nil && backend.now != nil &&
		backend.writes != nil && ctx != nil && ctx.Err() == nil
}

func (backend *Backend) validEnvelope(value []byte, sequence int64) bool {
	metadata, canonical, err := backend.verifier.Verify(value)
	return err == nil && metadata.StreamID == backend.binding.StreamID() && metadata.Sequence == sequence &&
		bytes.Equal(canonical, value)
}

func (backend *Backend) validPredecessor(ctx context.Context, metadata auditanchor.EnvelopeMetadata) bool {
	if metadata.Sequence == 1 {
		return true
	}
	key := backend.objectKey(metadata.Sequence - 1)
	versionID, err := backend.client.ResolveObjectVersion(ctx, backend.bucket, key)
	if err != nil || ctx.Err() != nil || !validVersionID(versionID) {
		return false
	}
	value, err := backend.client.ReadObjectVersion(ctx, backend.bucket, key, versionID)
	if err != nil || ctx.Err() != nil {
		return false
	}
	previous, canonical, err := backend.verifier.Verify(value)
	if err != nil || !bytes.Equal(value, canonical) || previous.StreamID != metadata.StreamID ||
		previous.Sequence != metadata.Sequence-1 || previous.PayloadDigest != metadata.PreviousAnchorDigest {
		return false
	}
	retention, err := backend.client.ReadObjectRetentionVersion(ctx, backend.bucket, key, versionID)
	return err == nil && ctx.Err() == nil && retention.Mode == auditanchor.COSComplianceMode &&
		retention.RetainUntil.Location() == time.UTC &&
		!retention.RetainUntil.Before(previous.CapturedAt.Add(time.Duration(auditmirror.RetentionDays)*24*time.Hour))
}

func validVersionID(value string) bool {
	return value != "null" && versionIDPattern.MatchString(value)
}

func (backend *Backend) objectKey(sequence int64) string {
	return backend.prefix + fmt.Sprintf("%020d.json", sequence)
}

func (backend *Backend) sequenceForKey(key string) (int64, bool) {
	if backend == nil || !strings.HasPrefix(key, backend.prefix) {
		return 0, false
	}
	encoded := strings.TrimPrefix(key, backend.prefix)
	if len(encoded) != 25 || !strings.HasSuffix(encoded, ".json") {
		return 0, false
	}
	sequence, err := strconv.ParseInt(strings.TrimSuffix(encoded, ".json"), 10, 64)
	return sequence, err == nil && sequence > 0 && sequence <= auditmirror.MaxSequence &&
		key == backend.objectKey(sequence)
}

var _ auditmirror.Client = (*Backend)(nil)
