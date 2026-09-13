package auditstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
	"github.com/tyj1987/broker/core/auditmirror"
)

type mirrorCOSAdapter struct {
	bucket   string
	prefix   string
	binding  auditmirror.Binding
	client   auditmirror.Client
	verifier *auditanchor.EnvelopeVerifier
}

func newMirrorCOSAdapter(
	config ServiceConfig,
	client auditmirror.Client,
	verifier *auditanchor.EnvelopeVerifier,
) (*mirrorCOSAdapter, error) {
	if client == nil || verifier == nil || auditmirror.RetentionGrace != auditanchor.AuditObjectRetentionGrace {
		return nil, ErrServiceRuntimeInvalid
	}
	generation, err := mirrorTrustGeneration(config.TrustedKeys)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	binding, err := auditmirror.NewBinding(
		config.StreamID, config.Prefix, config.COS.ProviderProfileID, generation,
	)
	if err != nil {
		return nil, ErrServiceConfigInvalid
	}
	return &mirrorCOSAdapter{
		bucket: config.COS.Bucket, prefix: config.Prefix + "/" + config.StreamID + "/",
		binding: binding, client: client, verifier: verifier,
	}, nil
}

func mirrorBinding(config ServiceConfig) (auditmirror.Binding, error) {
	generation, err := mirrorTrustGeneration(config.TrustedKeys)
	if err != nil {
		return auditmirror.Binding{}, ErrServiceConfigInvalid
	}
	binding, err := auditmirror.NewBinding(
		config.StreamID, config.Prefix, config.COS.ProviderProfileID, generation,
	)
	if err != nil {
		return auditmirror.Binding{}, ErrServiceConfigInvalid
	}
	return binding, nil
}

func mirrorTrustGeneration(keys []TrustedKeyBinding) ([sha256.Size]byte, error) {
	trustedKeys := make(map[string]auditanchor.TrustedSigningKey, len(keys))
	for _, key := range keys {
		if key.PublicKey == nil {
			return [sha256.Size]byte{}, ErrServiceConfigInvalid
		}
		if _, duplicate := trustedKeys[key.KeyID]; duplicate {
			return [sha256.Size]byte{}, ErrServiceConfigInvalid
		}
		trustedKeys[key.KeyID] = auditanchor.TrustedSigningKey{
			PublicKey:         key.PublicKey,
			ValidFromSequence: key.ValidFromSequence, ValidThroughSequence: key.ValidThroughSequence,
		}
	}
	generation, err := auditanchor.TrustedKeyGeneration(trustedKeys)
	if err != nil {
		return [sha256.Size]byte{}, ErrServiceConfigInvalid
	}
	return generation, nil
}

func (adapter *mirrorCOSAdapter) InspectObjectLock(ctx context.Context, bucket string) (auditanchor.COSObjectLockState, error) {
	if !adapter.validCall(ctx, bucket) {
		return auditanchor.COSObjectLockState{}, auditanchor.ErrMirrorInvalid
	}
	request, err := auditmirror.NewInspectRequest(adapter.binding)
	if err != nil {
		return auditanchor.COSObjectLockState{}, auditanchor.ErrMirrorInvalid
	}
	state, err := adapter.client.Inspect(ctx, request)
	if err != nil {
		return auditanchor.COSObjectLockState{}, mapMirrorError(err)
	}
	if ctx.Err() != nil || !state.Compliance || !state.Versioning ||
		state.RetentionDays != auditmirror.RetentionDays ||
		state.TrustGeneration != adapter.binding.TrustGeneration() {
		return auditanchor.COSObjectLockState{}, auditanchor.ErrMirrorInvalid
	}
	return auditanchor.COSObjectLockState{Enabled: true, VersioningState: "Enabled"}, nil
}

func (adapter *mirrorCOSAdapter) CreateObject(ctx context.Context, request auditanchor.COSCreateObjectRequest) (auditanchor.ObjectCreateResult, error) {
	if !adapter.validCall(ctx, request.Bucket) || request.ContentType != "application/json" ||
		request.StorageClass != "STANDARD" || request.LockMode != auditanchor.COSComplianceMode ||
		request.RetainUntil.Location() != time.UTC || request.RetainUntil.IsZero() {
		return auditanchor.ObjectCreateResult{}, auditanchor.ErrMirrorInvalid
	}
	sequence, ok := adapter.sequenceForKey(request.Key)
	metadata, canonical, err := adapter.verifier.Verify(request.Body)
	issuedAt := request.RetainUntil.Add(-time.Duration(auditmirror.RetentionDays)*24*time.Hour - auditmirror.RetentionGrace)
	if !ok || err != nil || metadata.StreamID != adapter.binding.StreamID() ||
		metadata.Sequence != sequence || !bytes.Equal(canonical, request.Body) ||
		issuedAt.Before(metadata.CapturedAt) {
		return auditanchor.ObjectCreateResult{}, auditanchor.ErrMirrorInvalid
	}
	typed, err := auditmirror.NewCreateRequest(adapter.binding, sequence, canonical, issuedAt)
	if err != nil {
		return auditanchor.ObjectCreateResult{}, auditanchor.ErrMirrorInvalid
	}
	result, err := adapter.client.Create(ctx, typed)
	if err != nil {
		return auditanchor.ObjectCreateResult{}, mapMirrorError(err)
	}
	if ctx.Err() != nil || (result.Status != "created" && result.Status != "exists") {
		return auditanchor.ObjectCreateResult{}, auditanchor.ErrMirrorInvalid
	}
	return auditanchor.ObjectCreateResult{Status: result.Status}, nil
}

func (adapter *mirrorCOSAdapter) ReadObject(ctx context.Context, bucket, key string) ([]byte, error) {
	if !adapter.validCall(ctx, bucket) {
		return nil, auditanchor.ErrMirrorInvalid
	}
	sequence, ok := adapter.sequenceForKey(key)
	if !ok {
		return nil, auditanchor.ErrMirrorInvalid
	}
	request, err := auditmirror.NewReadRequest(adapter.binding, sequence)
	if err != nil {
		return nil, auditanchor.ErrMirrorInvalid
	}
	result, err := adapter.client.Read(ctx, request)
	if err != nil {
		return nil, mapMirrorError(err)
	}
	metadata, canonical, err := adapter.verifier.Verify(result.Envelope)
	if ctx.Err() != nil || err != nil || metadata.StreamID != adapter.binding.StreamID() ||
		metadata.Sequence != sequence || !bytes.Equal(canonical, result.Envelope) {
		return nil, auditanchor.ErrMirrorInvalid
	}
	return bytes.Clone(canonical), nil
}

func (adapter *mirrorCOSAdapter) ReadObjectRetention(ctx context.Context, bucket, key string) (auditanchor.COSObjectRetention, error) {
	if !adapter.validCall(ctx, bucket) {
		return auditanchor.COSObjectRetention{}, auditanchor.ErrMirrorInvalid
	}
	sequence, ok := adapter.sequenceForKey(key)
	if !ok {
		return auditanchor.COSObjectRetention{}, auditanchor.ErrMirrorInvalid
	}
	request, err := auditmirror.NewReadRequest(adapter.binding, sequence)
	if err != nil {
		return auditanchor.COSObjectRetention{}, auditanchor.ErrMirrorInvalid
	}
	result, err := adapter.client.Retention(ctx, request)
	if err != nil {
		return auditanchor.COSObjectRetention{}, mapMirrorError(err)
	}
	if ctx.Err() != nil || result.Mode != auditanchor.COSComplianceMode ||
		result.RetainUntil.Location() != time.UTC || result.RetainUntil.IsZero() {
		return auditanchor.COSObjectRetention{}, auditanchor.ErrMirrorInvalid
	}
	return auditanchor.COSObjectRetention{Mode: result.Mode, RetainUntil: result.RetainUntil}, nil
}

func (adapter *mirrorCOSAdapter) ListObjectKeys(
	ctx context.Context,
	bucket, prefix, after string,
	limit int,
) (auditanchor.ObjectKeyPage, error) {
	if !adapter.validCall(ctx, bucket) || prefix != adapter.prefix {
		return auditanchor.ObjectKeyPage{}, auditanchor.ErrMirrorInvalid
	}
	afterSequence := int64(0)
	if after != "" {
		var ok bool
		afterSequence, ok = adapter.sequenceForKey(after)
		if !ok {
			return auditanchor.ObjectKeyPage{}, auditanchor.ErrMirrorInvalid
		}
	}
	request, err := auditmirror.NewListRequest(adapter.binding, afterSequence, limit)
	if err != nil {
		return auditanchor.ObjectKeyPage{}, auditanchor.ErrMirrorInvalid
	}
	result, err := adapter.client.List(ctx, request)
	if err != nil {
		return auditanchor.ObjectKeyPage{}, mapMirrorError(err)
	}
	if ctx.Err() != nil || len(result.Sequences) > limit || result.NextAfter < 0 ||
		result.NextAfter > auditmirror.MaxSequence ||
		(result.Truncated && (len(result.Sequences) == 0 || result.NextAfter != result.Sequences[len(result.Sequences)-1])) ||
		(!result.Truncated && result.NextAfter != 0) {
		return auditanchor.ObjectKeyPage{}, auditanchor.ErrMirrorInvalid
	}
	page := auditanchor.ObjectKeyPage{Keys: make([]string, 0, len(result.Sequences)), Truncated: result.Truncated}
	previous := afterSequence
	for _, sequence := range result.Sequences {
		if previous >= auditmirror.MaxSequence || sequence < 1 || sequence > auditmirror.MaxSequence ||
			sequence != previous+1 {
			return auditanchor.ObjectKeyPage{}, auditanchor.ErrMirrorInvalid
		}
		page.Keys = append(page.Keys, adapter.objectKey(sequence))
		previous = sequence
	}
	if result.Truncated {
		page.NextAfter = adapter.objectKey(result.NextAfter)
	}
	return page, nil
}

func (adapter *mirrorCOSAdapter) validCall(ctx context.Context, bucket string) bool {
	return adapter != nil && ctx != nil && ctx.Err() == nil && adapter.client != nil &&
		adapter.verifier != nil && bucket == adapter.bucket
}

func (adapter *mirrorCOSAdapter) objectKey(sequence int64) string {
	return adapter.prefix + fmt.Sprintf("%020d.json", sequence)
}

func (adapter *mirrorCOSAdapter) sequenceForKey(key string) (int64, bool) {
	if adapter == nil || !strings.HasPrefix(key, adapter.prefix) {
		return 0, false
	}
	encoded := strings.TrimPrefix(key, adapter.prefix)
	if len(encoded) != 25 || !strings.HasSuffix(encoded, ".json") {
		return 0, false
	}
	sequence, err := strconv.ParseInt(strings.TrimSuffix(encoded, ".json"), 10, 64)
	return sequence, err == nil && sequence > 0 && sequence <= auditmirror.MaxSequence &&
		key == adapter.objectKey(sequence)
}

func mapMirrorError(err error) error {
	switch {
	case errors.Is(err, auditmirror.ErrNotFound):
		return auditanchor.ErrImmutableObjectNotFound
	case errors.Is(err, auditmirror.ErrContractRejected):
		return auditanchor.ErrMirrorInvalid
	default:
		return auditanchor.ErrMirrorUnavailable
	}
}
