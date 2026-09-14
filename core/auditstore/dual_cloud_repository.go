package auditstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
)

const (
	DefaultCloudListPageSize = 1000
	DefaultCloudListMaxPages = 128
	maximumCloudListPages    = 512
)

var repositoryPrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/-]{0,126}[a-z0-9]$`)

type AnchorPublisher interface {
	Write(context.Context, []byte) (auditanchor.ImmutableObjectReceipt, error)
}

type PrimaryAnchorStore interface {
	InspectBucketWORM(context.Context, string) (auditanchor.OSSBucketWORMState, error)
	ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error)
	ReadObject(context.Context, string, string) ([]byte, error)
}

type MirrorAnchorStore interface {
	InspectObjectLock(context.Context, string) (auditanchor.COSObjectLockState, error)
	ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error)
	ReadObject(context.Context, string, string) ([]byte, error)
	ReadObjectRetention(context.Context, string, string) (auditanchor.COSObjectRetention, error)
}

type DualCloudRepositoryConfig struct {
	StreamID     string
	Prefix       string
	OSSBucket    string
	COSBucket    string
	ListPageSize int
	MaxListPages int
}

// DualCloudRepository derives its state from immutable provider objects on
// every operation. It intentionally has no local head file or memory-backed
// authoritative checkpoint, so a workload restart cannot silently rewind the
// sequence. One primary-only tail object is repairable; every other listing or
// content divergence fails closed.
type DualCloudRepository struct {
	config    DualCloudRepositoryConfig
	prefix    string
	publisher AnchorPublisher
	primary   PrimaryAnchorStore
	mirror    MirrorAnchorStore
	verifier  EnvelopeVerifier
	operation chan struct{}
}

func NewDualCloudRepository(
	config DualCloudRepositoryConfig,
	publisher AnchorPublisher,
	primary PrimaryAnchorStore,
	mirror MirrorAnchorStore,
	verifier EnvelopeVerifier,
) (*DualCloudRepository, error) {
	if config.ListPageSize == 0 {
		config.ListPageSize = DefaultCloudListPageSize
	}
	if config.MaxListPages == 0 {
		config.MaxListPages = DefaultCloudListMaxPages
	}
	if !idPattern.MatchString(config.StreamID) || !validRepositoryPrefix(config.Prefix) ||
		!validRepositoryBucket(config.OSSBucket) || !validRepositoryBucket(config.COSBucket) ||
		config.ListPageSize < 1 || config.ListPageSize > auditanchor.ImmutableListMaxKeys ||
		config.MaxListPages < 1 || config.MaxListPages > maximumCloudListPages ||
		publisher == nil || primary == nil || mirror == nil || verifier == nil {
		return nil, errors.New("dual-cloud audit repository configuration is invalid")
	}
	repository := &DualCloudRepository{
		config: config, prefix: config.Prefix + "/" + config.StreamID + "/",
		publisher: publisher, primary: primary, mirror: mirror, verifier: verifier,
		operation: make(chan struct{}, 1),
	}
	repository.operation <- struct{}{}
	return repository, nil
}

func validRepositoryPrefix(prefix string) bool {
	return repositoryPrefixPattern.MatchString(prefix) && !strings.Contains(prefix, "//") &&
		!strings.Contains(prefix, "..")
}

func validRepositoryBucket(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 ||
		!((bucket[0] >= 'a' && bucket[0] <= 'z') || (bucket[0] >= '0' && bucket[0] <= '9')) {
		return false
	}
	for index, character := range bucket {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '-' && index > 0 && index < len(bucket)-1 {
			continue
		}
		return false
	}
	return true
}

func (repository *DualCloudRepository) Publish(ctx context.Context, request PublishRequest) (PublishResult, error) {
	if err := repository.acquire(ctx); err != nil {
		return PublishResult{}, err
	}
	defer repository.release()
	if !repository.validCall(ctx) || request.Metadata.Sequence < 1 || request.Metadata.Sequence > MaxSafeInteger ||
		request.Metadata.StreamID != repository.config.StreamID ||
		request.ExpectedPreviousDigest != request.Metadata.PreviousAnchorDigest {
		return PublishResult{}, ErrRepositoryInvalid
	}
	verified, canonical, err := repository.verifier.Verify(request.Envelope)
	if err != nil || !sameMetadata(verified, request.Metadata) || !bytes.Equal(canonical, request.Envelope) {
		return PublishResult{}, ErrRepositoryInvalid
	}
	snapshot, _, err := repository.snapshot(ctx)
	if err != nil {
		return PublishResult{}, err
	}
	sequence := request.Metadata.Sequence
	if sequence <= snapshot.commonSequence {
		current, _, readErr := repository.readPair(ctx, sequence)
		if readErr != nil {
			return PublishResult{}, readErr
		}
		if bytes.Equal(current, canonical) {
			return PublishResult{Status: "published"}, nil
		}
		currentMetadata, _, verifyErr := repository.verifier.Verify(current)
		if verifyErr != nil || currentMetadata.PreviousAnchorDigest != request.ExpectedPreviousDigest {
			return PublishResult{}, ErrRepositoryInvalid
		}
		return PublishResult{Status: "conflict", Current: bytes.Clone(current)}, nil
	}
	if sequence != snapshot.commonSequence+1 {
		return PublishResult{}, ErrRepositoryInvalid
	}
	previousDigest := genesisDigest
	if snapshot.commonSequence > 0 {
		_, previousMetadata, readErr := repository.readPair(ctx, snapshot.commonSequence)
		if readErr != nil {
			return PublishResult{}, readErr
		}
		previousDigest = previousMetadata.PayloadDigest
	}
	if request.ExpectedPreviousDigest != previousDigest {
		return PublishResult{}, ErrRepositoryInvalid
	}
	if snapshot.primarySequence == sequence {
		primary, primaryErr := repository.readPrimary(ctx, sequence)
		if primaryErr != nil {
			return PublishResult{}, primaryErr
		}
		if !bytes.Equal(primary, canonical) {
			primaryMetadata, _, verifyErr := repository.verifier.Verify(primary)
			if verifyErr != nil || primaryMetadata.PreviousAnchorDigest != request.ExpectedPreviousDigest {
				return PublishResult{}, ErrRepositoryInvalid
			}
			// A conflict is safe for callers to treat as already published only
			// after the existing immutable primary object has been mirrored and
			// read back. Re-publish the original bytes, never the losing request.
			if _, err = repository.publisher.Write(ctx, primary); err != nil {
				return PublishResult{}, mapPublisherError(err)
			}
			if ctx.Err() != nil {
				return PublishResult{}, ErrRepositoryUnavailable
			}
			repaired, _, repairErr := repository.readPair(ctx, sequence)
			if repairErr != nil {
				return PublishResult{}, repairErr
			}
			if !bytes.Equal(repaired, primary) {
				return PublishResult{}, ErrRepositoryInvalid
			}
			return PublishResult{Status: "conflict", Current: bytes.Clone(primary)}, nil
		}
	}
	if _, err = repository.publisher.Write(ctx, canonical); err != nil {
		return PublishResult{}, mapPublisherError(err)
	}
	if ctx.Err() != nil {
		return PublishResult{}, ErrRepositoryUnavailable
	}
	written, _, err := repository.readPair(ctx, sequence)
	if err != nil || !bytes.Equal(written, canonical) {
		if err != nil {
			return PublishResult{}, err
		}
		return PublishResult{}, ErrRepositoryInvalid
	}
	return PublishResult{Status: "published"}, nil
}

func (repository *DualCloudRepository) ReadHead(ctx context.Context) (Head, error) {
	if err := repository.acquire(ctx); err != nil {
		return Head{}, err
	}
	defer repository.release()
	if !repository.validCall(ctx) {
		return Head{}, ErrRepositoryInvalid
	}
	snapshot, _, err := repository.snapshot(ctx)
	if err != nil {
		return Head{}, err
	}
	if snapshot.commonSequence == 0 {
		return Head{}, nil
	}
	current, currentMetadata, err := repository.readPair(ctx, snapshot.commonSequence)
	if err != nil {
		return Head{}, err
	}
	result := Head{Current: bytes.Clone(current)}
	if snapshot.commonSequence > 1 {
		previous, previousMetadata, previousErr := repository.readPair(ctx, snapshot.commonSequence-1)
		if previousErr != nil || currentMetadata.PreviousAnchorDigest != previousMetadata.PayloadDigest {
			if previousErr != nil {
				return Head{}, previousErr
			}
			return Head{}, ErrRepositoryInvalid
		}
		result.Previous = bytes.Clone(previous)
	} else if currentMetadata.PreviousAnchorDigest != genesisDigest {
		return Head{}, ErrRepositoryInvalid
	}
	return result, nil
}

func (repository *DualCloudRepository) ReadPage(ctx context.Context, after, through int64, limit int) ([][]byte, error) {
	if err := repository.acquire(ctx); err != nil {
		return nil, err
	}
	defer repository.release()
	if !repository.validCall(ctx) || after < 0 || through < 1 || after >= through ||
		through > MaxSafeInteger || limit < 1 || limit > MaxPageSize {
		return nil, ErrRepositoryInvalid
	}
	snapshot, _, err := repository.snapshot(ctx)
	if err != nil || through > snapshot.commonSequence {
		if err != nil {
			return nil, err
		}
		return nil, ErrRepositoryInvalid
	}
	end := through
	if end > after+int64(limit) {
		end = after + int64(limit)
	}
	previousDigest := genesisDigest
	if after > 0 {
		_, previousMetadata, readErr := repository.readPair(ctx, after)
		if readErr != nil {
			return nil, readErr
		}
		previousDigest = previousMetadata.PayloadDigest
	}
	anchors := make([][]byte, 0, end-after)
	for sequence := after + 1; sequence <= end; sequence++ {
		anchor, metadata, readErr := repository.readPair(ctx, sequence)
		if readErr != nil || metadata.PreviousAnchorDigest != previousDigest {
			if readErr != nil {
				return nil, readErr
			}
			return nil, ErrRepositoryInvalid
		}
		anchors = append(anchors, bytes.Clone(anchor))
		previousDigest = metadata.PayloadDigest
	}
	return anchors, nil
}

func (repository *DualCloudRepository) Health(ctx context.Context) (Health, error) {
	if err := repository.acquire(ctx); err != nil {
		return Health{}, err
	}
	defer repository.release()
	if !repository.validCall(ctx) {
		return Health{}, ErrRepositoryInvalid
	}
	snapshot, reason, err := repository.snapshot(ctx)
	if err != nil {
		lockContract := "verified"
		if strings.HasPrefix(reason, "primary_lock_") {
			lockContract = "unverified"
		}
		return Health{
			Status: "blocked", LockContract: lockContract, MirrorState: "invalid",
			CommonSequence: snapshot.commonSequence, ReasonCode: reason,
		}, nil
	}
	if snapshot.primarySequence == snapshot.commonSequence+1 {
		primary, readErr := repository.readPrimary(ctx, snapshot.primarySequence)
		primaryMetadata, _, verifyErr := repository.verifier.Verify(primary)
		previousDigest := genesisDigest
		if snapshot.commonSequence > 0 {
			_, previousMetadata, previousErr := repository.readPair(ctx, snapshot.commonSequence)
			if previousErr != nil {
				readErr = previousErr
			} else {
				previousDigest = previousMetadata.PayloadDigest
			}
		}
		if readErr != nil || verifyErr != nil || primaryMetadata.PreviousAnchorDigest != previousDigest {
			return Health{
				Status: "blocked", LockContract: "verified", MirrorState: "invalid",
				CommonSequence: snapshot.commonSequence, ReasonCode: "anchor_invalid",
			}, nil
		}
		return Health{
			Status: "repair_required", LockContract: "verified", MirrorState: "lagging",
			CommonSequence: snapshot.commonSequence, ReasonCode: "mirror_lagging",
		}, nil
	}
	if snapshot.commonSequence > 0 {
		if _, _, err = repository.readPair(ctx, snapshot.commonSequence); err != nil {
			return Health{
				Status: "blocked", LockContract: "verified", MirrorState: "invalid",
				CommonSequence: snapshot.commonSequence, ReasonCode: "anchor_invalid",
			}, nil
		}
	}
	return Health{
		Status: "ready", LockContract: "verified", MirrorState: "in_sync",
		CommonSequence: snapshot.commonSequence, ReasonCode: "ok",
	}, nil
}

type cloudSnapshot struct {
	commonSequence  int64
	primarySequence int64
}

func (repository *DualCloudRepository) snapshot(ctx context.Context) (cloudSnapshot, string, error) {
	primaryState, err := repository.primary.InspectBucketWORM(ctx, repository.config.OSSBucket)
	if err != nil {
		return cloudSnapshot{}, "primary_lock_unavailable", mapCloudError(err)
	}
	if ctx.Err() != nil {
		return cloudSnapshot{}, "primary_lock_unavailable", ErrRepositoryUnavailable
	}
	if primaryState.Status != "Locked" || primaryState.RetentionDays != auditanchor.AuditObjectRetentionDays ||
		primaryState.VersioningState != "Disabled" {
		return cloudSnapshot{}, "primary_lock_invalid", ErrRepositoryInvalid
	}
	mirrorState, err := repository.mirror.InspectObjectLock(ctx, repository.config.COSBucket)
	if err != nil {
		return cloudSnapshot{}, "mirror_lock_unavailable", mapCloudError(err)
	}
	if ctx.Err() != nil {
		return cloudSnapshot{}, "mirror_lock_unavailable", ErrRepositoryUnavailable
	}
	if !mirrorState.Enabled || mirrorState.VersioningState != "Enabled" {
		return cloudSnapshot{}, "mirror_lock_invalid", ErrRepositoryInvalid
	}
	primaryKeys, err := repository.listKeys(ctx, repository.primary, repository.config.OSSBucket)
	if err != nil {
		return cloudSnapshot{}, listReason("primary", err), err
	}
	mirrorKeys, err := repository.listKeys(ctx, repository.mirror, repository.config.COSBucket)
	if err != nil {
		return cloudSnapshot{}, listReason("mirror", err), err
	}
	common := len(mirrorKeys)
	if len(primaryKeys) < common || len(primaryKeys)-common > 1 {
		return cloudSnapshot{}, "listing_diverged", ErrRepositoryInvalid
	}
	for index := range mirrorKeys {
		if primaryKeys[index] != mirrorKeys[index] {
			return cloudSnapshot{}, "listing_diverged", ErrRepositoryInvalid
		}
	}
	return cloudSnapshot{commonSequence: int64(common), primarySequence: int64(len(primaryKeys))}, "ok", nil
}

type objectKeyLister interface {
	ListObjectKeys(context.Context, string, string, string, int) (auditanchor.ObjectKeyPage, error)
}

func (repository *DualCloudRepository) listKeys(ctx context.Context, lister objectKeyLister, bucket string) ([]string, error) {
	keys := make([]string, 0)
	after := ""
	for pageNumber := 0; pageNumber < repository.config.MaxListPages; pageNumber++ {
		page, err := lister.ListObjectKeys(ctx, bucket, repository.prefix, after, repository.config.ListPageSize)
		if err != nil {
			return nil, mapCloudError(err)
		}
		if ctx.Err() != nil {
			return nil, ErrRepositoryUnavailable
		}
		if len(page.Keys) > repository.config.ListPageSize ||
			(page.Truncated && (len(page.Keys) == 0 || page.NextAfter != page.Keys[len(page.Keys)-1])) ||
			(!page.Truncated && page.NextAfter != "") {
			return nil, ErrRepositoryInvalid
		}
		for _, key := range page.Keys {
			expected := repository.objectKey(int64(len(keys) + 1))
			if key != expected || key <= after {
				return nil, ErrRepositoryInvalid
			}
			keys = append(keys, key)
			after = key
		}
		if !page.Truncated {
			return keys, nil
		}
	}
	return nil, ErrRepositoryInvalid
}

func (repository *DualCloudRepository) readPrimary(ctx context.Context, sequence int64) ([]byte, error) {
	value, err := repository.primary.ReadObject(ctx, repository.config.OSSBucket, repository.objectKey(sequence))
	if err != nil {
		return nil, mapCloudError(err)
	}
	if ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	metadata, canonical, err := repository.verifier.Verify(value)
	if err != nil || metadata.StreamID != repository.config.StreamID || metadata.Sequence != sequence ||
		!bytes.Equal(value, canonical) {
		return nil, ErrRepositoryInvalid
	}
	return bytes.Clone(canonical), nil
}

func (repository *DualCloudRepository) readPair(ctx context.Context, sequence int64) ([]byte, auditanchor.EnvelopeMetadata, error) {
	primary, err := repository.readPrimary(ctx, sequence)
	if err != nil {
		return nil, auditanchor.EnvelopeMetadata{}, err
	}
	key := repository.objectKey(sequence)
	mirror, err := repository.mirror.ReadObject(ctx, repository.config.COSBucket, key)
	if err != nil {
		return nil, auditanchor.EnvelopeMetadata{}, mapCloudError(err)
	}
	if ctx.Err() != nil {
		return nil, auditanchor.EnvelopeMetadata{}, ErrRepositoryUnavailable
	}
	if !bytes.Equal(primary, mirror) {
		return nil, auditanchor.EnvelopeMetadata{}, ErrRepositoryInvalid
	}
	metadata, canonical, err := repository.verifier.Verify(mirror)
	if err != nil || metadata.StreamID != repository.config.StreamID || metadata.Sequence != sequence ||
		!bytes.Equal(primary, canonical) {
		return nil, auditanchor.EnvelopeMetadata{}, ErrRepositoryInvalid
	}
	retention, err := repository.mirror.ReadObjectRetention(ctx, repository.config.COSBucket, key)
	if err != nil {
		return nil, auditanchor.EnvelopeMetadata{}, mapCloudError(err)
	}
	if ctx.Err() != nil {
		return nil, auditanchor.EnvelopeMetadata{}, ErrRepositoryUnavailable
	}
	minimum := metadata.CapturedAt.Add(auditanchor.AuditObjectRetentionDays * 24 * time.Hour)
	if retention.Mode != auditanchor.COSComplianceMode || retention.RetainUntil.Location() != time.UTC ||
		retention.RetainUntil.Before(minimum) {
		return nil, auditanchor.EnvelopeMetadata{}, ErrRepositoryInvalid
	}
	return bytes.Clone(canonical), metadata, nil
}

func (repository *DualCloudRepository) objectKey(sequence int64) string {
	return repository.prefix + fmt.Sprintf("%020d.json", sequence)
}

func (repository *DualCloudRepository) acquire(ctx context.Context) error {
	if repository == nil || ctx == nil || repository.operation == nil {
		return ErrRepositoryInvalid
	}
	if ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	select {
	case <-ctx.Done():
		return ErrRepositoryUnavailable
	case <-repository.operation:
		if ctx.Err() != nil {
			repository.release()
			return ErrRepositoryUnavailable
		}
		return nil
	}
}

func (repository *DualCloudRepository) release() {
	repository.operation <- struct{}{}
}

func (repository *DualCloudRepository) validCall(ctx context.Context) bool {
	return repository != nil && ctx != nil && ctx.Err() == nil && repository.publisher != nil &&
		repository.primary != nil && repository.mirror != nil && repository.verifier != nil
}

func sameMetadata(left, right auditanchor.EnvelopeMetadata) bool {
	return left.StreamID == right.StreamID && left.Sequence == right.Sequence &&
		left.PreviousAnchorDigest == right.PreviousAnchorDigest && left.PayloadDigest == right.PayloadDigest &&
		left.CapturedAt.Equal(right.CapturedAt)
}

func mapCloudError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, auditanchor.ErrImmutableSDKUnavailable) {
		return ErrRepositoryUnavailable
	}
	if errors.Is(err, auditanchor.ErrImmutableSDKRequestRejected) ||
		errors.Is(err, auditanchor.ErrImmutableSDKResponseInvalid) ||
		errors.Is(err, auditanchor.ErrImmutableObjectNotFound) || errors.Is(err, ErrRepositoryInvalid) {
		return ErrRepositoryInvalid
	}
	return ErrRepositoryUnavailable
}

func mapPublisherError(err error) error {
	if errors.Is(err, auditanchor.ErrPrimaryUnavailable) || errors.Is(err, auditanchor.ErrMirrorUnavailable) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ErrRepositoryUnavailable
	}
	return ErrRepositoryInvalid
}

func listReason(cloud string, err error) string {
	if errors.Is(err, ErrRepositoryUnavailable) {
		return cloud + "_list_unavailable"
	}
	return cloud + "_list_invalid"
}
