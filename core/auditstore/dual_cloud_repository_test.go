package auditstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/auditanchor"
)

const (
	repositoryPrefix    = "audit-anchors/v1"
	repositoryOSSBucket = "broker-audit-primary"
	repositoryCOSBucket = "broker-audit-mirror-1250000000"
)

type fakeCloudStore struct {
	objects             map[string][]byte
	retentions          map[string]auditanchor.COSObjectRetention
	primaryState        auditanchor.OSSBucketWORMState
	mirrorState         auditanchor.COSObjectLockState
	primaryErr          error
	mirrorErr           error
	listErr             error
	readErr             error
	retentionErr        error
	invalidPage         func(auditanchor.ObjectKeyPage) auditanchor.ObjectKeyPage
	listCalls           int
	lastListAfter       string
	afterPrimaryInspect func()
	afterMirrorInspect  func()
	afterList           func()
	afterRead           func()
	afterRetention      func()
}

func newFakeCloudStore() *fakeCloudStore {
	return &fakeCloudStore{
		objects:      make(map[string][]byte),
		retentions:   make(map[string]auditanchor.COSObjectRetention),
		primaryState: auditanchor.OSSBucketWORMState{Status: "Locked", RetentionDays: 365, VersioningState: "Disabled"},
		mirrorState:  auditanchor.COSObjectLockState{Enabled: true, VersioningState: "Enabled"},
	}
}

func (store *fakeCloudStore) InspectBucketWORM(context.Context, string) (auditanchor.OSSBucketWORMState, error) {
	if store.afterPrimaryInspect != nil {
		store.afterPrimaryInspect()
	}
	return store.primaryState, store.primaryErr
}

func (store *fakeCloudStore) InspectObjectLock(context.Context, string) (auditanchor.COSObjectLockState, error) {
	if store.afterMirrorInspect != nil {
		store.afterMirrorInspect()
	}
	return store.mirrorState, store.mirrorErr
}

func (store *fakeCloudStore) ListObjectKeys(_ context.Context, _ string, prefix, after string, limit int) (auditanchor.ObjectKeyPage, error) {
	store.listCalls++
	store.lastListAfter = after
	if store.afterList != nil {
		store.afterList()
	}
	if store.listErr != nil {
		return auditanchor.ObjectKeyPage{}, store.listErr
	}
	keys := make([]string, 0)
	for key := range store.objects {
		if strings.HasPrefix(key, prefix) && key > after {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	page := auditanchor.ObjectKeyPage{}
	if len(keys) > limit {
		page.Keys = append(page.Keys, keys[:limit]...)
		page.Truncated = true
		page.NextAfter = page.Keys[len(page.Keys)-1]
	} else {
		page.Keys = append(page.Keys, keys...)
	}
	if store.invalidPage != nil {
		page = store.invalidPage(page)
	}
	return page, nil
}

func (store *fakeCloudStore) ReadObject(_ context.Context, _ string, key string) ([]byte, error) {
	if store.afterRead != nil {
		store.afterRead()
	}
	if store.readErr != nil {
		return nil, store.readErr
	}
	value, ok := store.objects[key]
	if !ok {
		return nil, auditanchor.ErrImmutableObjectNotFound
	}
	return bytes.Clone(value), nil
}

func (store *fakeCloudStore) ReadObjectRetention(_ context.Context, _ string, key string) (auditanchor.COSObjectRetention, error) {
	if store.afterRetention != nil {
		store.afterRetention()
	}
	if store.retentionErr != nil {
		return auditanchor.COSObjectRetention{}, store.retentionErr
	}
	value, ok := store.retentions[key]
	if !ok {
		return auditanchor.COSObjectRetention{}, auditanchor.ErrImmutableSDKResponseInvalid
	}
	return value, nil
}

type fakeAnchorPublisher struct {
	primary    *fakeCloudStore
	mirror     *fakeCloudStore
	err        error
	calls      int
	afterWrite func(string, []byte)
}

type observedContext struct {
	context.Context
	doneObserved chan struct{}
}

func (ctx observedContext) Done() <-chan struct{} {
	select {
	case ctx.doneObserved <- struct{}{}:
	default:
	}
	return ctx.Context.Done()
}

func (publisher *fakeAnchorPublisher) Write(_ context.Context, value []byte) (auditanchor.ImmutableObjectReceipt, error) {
	publisher.calls++
	if publisher.err != nil {
		return auditanchor.ImmutableObjectReceipt{}, publisher.err
	}
	var envelope fakeEnvelope
	if json.Unmarshal(value, &envelope) != nil {
		return auditanchor.ImmutableObjectReceipt{}, auditanchor.ErrObjectWriteRejected
	}
	key := repositoryObjectKey(envelope.Sequence)
	publisher.primary.objects[key] = bytes.Clone(value)
	publisher.mirror.objects[key] = bytes.Clone(value)
	publisher.mirror.retentions[key] = validRepositoryRetention()
	if publisher.afterWrite != nil {
		publisher.afterWrite(key, value)
	}
	return auditanchor.ImmutableObjectReceipt{Key: key, PrimaryState: "created", MirrorState: "created"}, nil
}

func repositoryObjectKey(sequence int64) string {
	return fmt.Sprintf("%s/%s/%020d.json", repositoryPrefix, testConfig.StreamID, sequence)
}

func validRepositoryRetention() auditanchor.COSObjectRetention {
	return auditanchor.COSObjectRetention{
		Mode: auditanchor.COSComplianceMode, RetainUntil: testNow.Add(366 * 24 * time.Hour),
	}
}

func repositoryEnvelope(t *testing.T, sequence int64, previousDigest, payloadDigest string) []byte {
	t.Helper()
	return testEnvelopeJSON(t, sequence, previousDigest, payloadDigest)
}

func addRepositoryAnchor(t *testing.T, primary, mirror *fakeCloudStore, sequence int64, previousDigest, payloadDigest string) []byte {
	t.Helper()
	value := repositoryEnvelope(t, sequence, previousDigest, payloadDigest)
	key := repositoryObjectKey(sequence)
	primary.objects[key] = bytes.Clone(value)
	mirror.objects[key] = bytes.Clone(value)
	mirror.retentions[key] = validRepositoryRetention()
	return value
}

func newRepositoryHarness(t *testing.T) (*DualCloudRepository, *fakeCloudStore, *fakeCloudStore, *fakeAnchorPublisher) {
	t.Helper()
	primary := newFakeCloudStore()
	mirror := newFakeCloudStore()
	publisher := &fakeAnchorPublisher{primary: primary, mirror: mirror}
	repository, err := NewDualCloudRepository(DualCloudRepositoryConfig{
		StreamID: testConfig.StreamID, Prefix: repositoryPrefix,
		OSSBucket: repositoryOSSBucket, COSBucket: repositoryCOSBucket,
		ListPageSize: 2, MaxListPages: 4,
	}, publisher, primary, mirror, &fakeVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	return repository, primary, mirror, publisher
}

func TestDualCloudRepositoryHeadAndPages(t *testing.T) {
	repository, primary, mirror, _ := newRepositoryHarness(t)
	if head, err := repository.ReadHead(context.Background()); err != nil || len(head.Current) != 0 || len(head.Previous) != 0 {
		t.Fatalf("empty head = %#v, %v", head, err)
	}
	one := addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
	two := addRepositoryAnchor(t, primary, mirror, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))
	three := addRepositoryAnchor(t, primary, mirror, 3, strings.Repeat("b", 64), strings.Repeat("c", 64))
	head, err := repository.ReadHead(context.Background())
	if err != nil || !bytes.Equal(head.Current, three) || !bytes.Equal(head.Previous, two) || primary.listCalls < 2 || mirror.listCalls < 2 {
		t.Fatalf("head = %#v, %v", head, err)
	}
	page, err := repository.ReadPage(context.Background(), 0, 3, 2)
	if err != nil || len(page) != 2 || !bytes.Equal(page[0], one) || !bytes.Equal(page[1], two) {
		t.Fatalf("first page = %#v, %v", page, err)
	}
	page, err = repository.ReadPage(context.Background(), 2, 3, 2)
	if err != nil || len(page) != 1 || !bytes.Equal(page[0], three) {
		t.Fatalf("second page = %#v, %v", page, err)
	}
	health, err := repository.Health(context.Background())
	if err != nil || health != (Health{Status: "ready", LockContract: "verified", MirrorState: "in_sync", CommonSequence: 3, ReasonCode: "ok"}) {
		t.Fatalf("health = %#v, %v", health, err)
	}
}

func TestDualCloudRepositoryPublishesRepairsRetriesAndConflicts(t *testing.T) {
	repository, primary, mirror, publisher := newRepositoryHarness(t)
	one := repositoryEnvelope(t, 1, genesisDigest, strings.Repeat("a", 64))
	oneMetadata, _, _ := (&fakeVerifier{}).Verify(one)
	result, err := repository.Publish(context.Background(), PublishRequest{
		ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: oneMetadata,
	})
	if err != nil || result.Status != "published" || publisher.calls != 1 {
		t.Fatalf("initial publish = %#v, %v, calls=%d", result, err, publisher.calls)
	}
	result, err = repository.Publish(context.Background(), PublishRequest{
		ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: oneMetadata,
	})
	if err != nil || result.Status != "published" || publisher.calls != 1 {
		t.Fatalf("idempotent publish = %#v, %v, calls=%d", result, err, publisher.calls)
	}

	conflict := repositoryEnvelope(t, 1, genesisDigest, strings.Repeat("f", 64))
	conflictMetadata, _, _ := (&fakeVerifier{}).Verify(conflict)
	result, err = repository.Publish(context.Background(), PublishRequest{
		ExpectedPreviousDigest: genesisDigest, Envelope: conflict, Metadata: conflictMetadata,
	})
	if err != nil || result.Status != "conflict" || !bytes.Equal(result.Current, one) {
		t.Fatalf("conflict = %#v, %v", result, err)
	}

	two := repositoryEnvelope(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))
	primary.objects[repositoryObjectKey(2)] = bytes.Clone(two)
	twoMetadata, _, _ := (&fakeVerifier{}).Verify(two)
	health, err := repository.Health(context.Background())
	if err != nil || health.Status != "repair_required" || health.CommonSequence != 1 {
		t.Fatalf("repair health = %#v, %v", health, err)
	}
	result, err = repository.Publish(context.Background(), PublishRequest{
		ExpectedPreviousDigest: strings.Repeat("a", 64), Envelope: two, Metadata: twoMetadata,
	})
	if err != nil || result.Status != "published" || !bytes.Equal(mirror.objects[repositoryObjectKey(2)], two) {
		t.Fatalf("repair publish = %#v, %v", result, err)
	}
}

func TestDualCloudRepositoryRejectsDivergenceAndBrokenChains(t *testing.T) {
	tests := map[string]func(*DualCloudRepository, *fakeCloudStore, *fakeCloudStore){
		"primary_gap": func(_ *DualCloudRepository, primary, mirror *fakeCloudStore) {
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			primary.objects[repositoryObjectKey(3)] = repositoryEnvelope(t, 3, strings.Repeat("b", 64), strings.Repeat("c", 64))
		},
		"mirror_ahead": func(_ *DualCloudRepository, primary, mirror *fakeCloudStore) {
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			mirror.objects[repositoryObjectKey(2)] = repositoryEnvelope(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))
		},
		"primary_two_ahead": func(_ *DualCloudRepository, primary, mirror *fakeCloudStore) {
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			primary.objects[repositoryObjectKey(2)] = repositoryEnvelope(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))
			primary.objects[repositoryObjectKey(3)] = repositoryEnvelope(t, 3, strings.Repeat("b", 64), strings.Repeat("c", 64))
		},
		"content_mismatch": func(_ *DualCloudRepository, primary, mirror *fakeCloudStore) {
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			mirror.objects[repositoryObjectKey(1)] = repositoryEnvelope(t, 1, genesisDigest, strings.Repeat("b", 64))
		},
		"retention_short": func(_ *DualCloudRepository, primary, mirror *fakeCloudStore) {
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			mirror.retentions[repositoryObjectKey(1)] = auditanchor.COSObjectRetention{
				Mode: auditanchor.COSComplianceMode, RetainUntil: testNow.Add(300 * 24 * time.Hour),
			}
		},
		"bad_predecessor": func(_ *DualCloudRepository, primary, mirror *fakeCloudStore) {
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			addRepositoryAnchor(t, primary, mirror, 2, strings.Repeat("f", 64), strings.Repeat("b", 64))
		},
		"page_overrun": func(repository *DualCloudRepository, primary, mirror *fakeCloudStore) {
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			repository.config.MaxListPages = 1
			primary.objects[repositoryObjectKey(2)] = repositoryEnvelope(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))
			mirror.objects[repositoryObjectKey(2)] = bytes.Clone(primary.objects[repositoryObjectKey(2)])
			mirror.retentions[repositoryObjectKey(2)] = validRepositoryRetention()
			primary.objects[repositoryObjectKey(3)] = repositoryEnvelope(t, 3, strings.Repeat("b", 64), strings.Repeat("c", 64))
			mirror.objects[repositoryObjectKey(3)] = bytes.Clone(primary.objects[repositoryObjectKey(3)])
			mirror.retentions[repositoryObjectKey(3)] = validRepositoryRetention()
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			repository, primary, mirror, _ := newRepositoryHarness(t)
			setup(repository, primary, mirror)
			if _, err := repository.ReadHead(context.Background()); !errors.Is(err, ErrRepositoryInvalid) {
				t.Fatalf("ReadHead() error = %v", err)
			}
		})
	}
}

func TestDualCloudRepositoryHealthReducesFailuresToStableCodes(t *testing.T) {
	tests := map[string]struct {
		setup  func(*fakeCloudStore, *fakeCloudStore)
		reason string
		lock   string
	}{
		"primary_lock_unavailable": {func(primary, _ *fakeCloudStore) { primary.primaryErr = errors.New("provider detail") }, "primary_lock_unavailable", "unverified"},
		"primary_lock_invalid":     {func(primary, _ *fakeCloudStore) { primary.primaryState.Status = "InProgress" }, "primary_lock_invalid", "unverified"},
		"mirror_lock_unavailable":  {func(_, mirror *fakeCloudStore) { mirror.mirrorErr = errors.New("provider detail") }, "mirror_lock_unavailable", "verified"},
		"mirror_lock_invalid":      {func(_, mirror *fakeCloudStore) { mirror.mirrorState.Enabled = false }, "mirror_lock_invalid", "verified"},
		"primary_list_unavailable": {func(primary, _ *fakeCloudStore) { primary.listErr = errors.New("provider detail") }, "primary_list_unavailable", "verified"},
		"primary_list_invalid": {func(primary, _ *fakeCloudStore) {
			primary.invalidPage = func(page auditanchor.ObjectKeyPage) auditanchor.ObjectKeyPage {
				page.NextAfter = "unexpected"
				return page
			}
		}, "primary_list_invalid", "verified"},
		"mirror_list_unavailable": {func(_, mirror *fakeCloudStore) { mirror.listErr = errors.New("provider detail") }, "mirror_list_unavailable", "verified"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			repository, primary, mirror, _ := newRepositoryHarness(t)
			test.setup(primary, mirror)
			health, err := repository.Health(context.Background())
			if err != nil || health.Status != "blocked" || health.ReasonCode != test.reason || health.LockContract != test.lock {
				t.Fatalf("health = %#v, %v", health, err)
			}
		})
	}
}

func TestDualCloudRepositoryPublishFailurePaths(t *testing.T) {
	one := repositoryEnvelope(t, 1, genesisDigest, strings.Repeat("a", 64))
	oneMetadata, _, _ := (&fakeVerifier{}).Verify(one)
	two := repositoryEnvelope(t, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))
	twoMetadata, _, _ := (&fakeVerifier{}).Verify(two)

	t.Run("publisher unavailable", func(t *testing.T) {
		repository, _, _, publisher := newRepositoryHarness(t)
		publisher.err = auditanchor.ErrMirrorUnavailable
		_, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: oneMetadata,
		})
		if !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("publish error = %v", err)
		}
	})
	t.Run("publisher invalid", func(t *testing.T) {
		repository, _, _, publisher := newRepositoryHarness(t)
		publisher.err = auditanchor.ErrObjectConflict
		_, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: oneMetadata,
		})
		if !errors.Is(err, ErrRepositoryInvalid) {
			t.Fatalf("publish error = %v", err)
		}
	})
	t.Run("sequence gap", func(t *testing.T) {
		repository, _, _, _ := newRepositoryHarness(t)
		_, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: strings.Repeat("a", 64), Envelope: two, Metadata: twoMetadata,
		})
		if !errors.Is(err, ErrRepositoryInvalid) {
			t.Fatalf("publish error = %v", err)
		}
	})
	t.Run("previous digest mismatch", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("f", 64))
		_, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: strings.Repeat("a", 64), Envelope: two, Metadata: twoMetadata,
		})
		if !errors.Is(err, ErrRepositoryInvalid) {
			t.Fatalf("publish error = %v", err)
		}
	})
	t.Run("partial primary conflict", func(t *testing.T) {
		repository, primary, mirror, publisher := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		conflict := repositoryEnvelope(t, 2, strings.Repeat("a", 64), strings.Repeat("f", 64))
		primary.objects[repositoryObjectKey(2)] = conflict
		result, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: strings.Repeat("a", 64), Envelope: two, Metadata: twoMetadata,
		})
		if err != nil || result.Status != "conflict" || !bytes.Equal(result.Current, conflict) ||
			!bytes.Equal(mirror.objects[repositoryObjectKey(2)], conflict) || publisher.calls != 1 {
			t.Fatalf("publish result = %#v, %v", result, err)
		}
	})
	t.Run("partial primary conflict repair failure", func(t *testing.T) {
		repository, primary, mirror, publisher := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		primary.objects[repositoryObjectKey(2)] = repositoryEnvelope(
			t, 2, strings.Repeat("a", 64), strings.Repeat("f", 64),
		)
		publisher.err = auditanchor.ErrMirrorUnavailable
		result, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: strings.Repeat("a", 64), Envelope: two, Metadata: twoMetadata,
		})
		if !errors.Is(err, ErrRepositoryUnavailable) || result.Status != "" ||
			mirror.objects[repositoryObjectKey(2)] != nil {
			t.Fatalf("publish result = %#v, %v", result, err)
		}
	})
	t.Run("partial primary conflict repair readback mismatch", func(t *testing.T) {
		repository, primary, mirror, publisher := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		primary.objects[repositoryObjectKey(2)] = repositoryEnvelope(
			t, 2, strings.Repeat("a", 64), strings.Repeat("f", 64),
		)
		publisher.afterWrite = func(key string, _ []byte) {
			mirror.objects[key] = bytes.Clone(two)
		}
		result, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: strings.Repeat("a", 64), Envelope: two, Metadata: twoMetadata,
		})
		if !errors.Is(err, ErrRepositoryInvalid) || result.Status != "" {
			t.Fatalf("publish result = %#v, %v", result, err)
		}
	})
	t.Run("partial primary conflict repair cancellation", func(t *testing.T) {
		repository, primary, mirror, publisher := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		primary.objects[repositoryObjectKey(2)] = repositoryEnvelope(
			t, 2, strings.Repeat("a", 64), strings.Repeat("f", 64),
		)
		ctx, cancel := context.WithCancel(context.Background())
		publisher.afterWrite = func(string, []byte) { cancel() }
		result, err := repository.Publish(ctx, PublishRequest{
			ExpectedPreviousDigest: strings.Repeat("a", 64), Envelope: two, Metadata: twoMetadata,
		})
		if !errors.Is(err, ErrRepositoryUnavailable) || result.Status != "" {
			t.Fatalf("publish result = %#v, %v", result, err)
		}
	})
	t.Run("post write mismatch", func(t *testing.T) {
		repository, _, mirror, publisher := newRepositoryHarness(t)
		publisher.afterWrite = func(key string, _ []byte) {
			mirror.objects[key] = repositoryEnvelope(t, 1, genesisDigest, strings.Repeat("f", 64))
		}
		_, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: oneMetadata,
		})
		if !errors.Is(err, ErrRepositoryInvalid) {
			t.Fatalf("publish error = %v", err)
		}
	})
	t.Run("snapshot unavailable", func(t *testing.T) {
		repository, primary, _, _ := newRepositoryHarness(t)
		primary.listErr = errors.New("provider detail")
		_, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: oneMetadata,
		})
		if !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("publish error = %v", err)
		}
	})
	t.Run("existing read unavailable", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		primary.readErr = errors.New("provider detail")
		_, err := repository.Publish(context.Background(), PublishRequest{
			ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: oneMetadata,
		})
		if !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("publish error = %v", err)
		}
	})
}

func TestDualCloudRepositoryReadAndHealthFailurePaths(t *testing.T) {
	t.Run("genesis digest", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, strings.Repeat("f", 64), strings.Repeat("a", 64))
		if _, err := repository.ReadHead(context.Background()); !errors.Is(err, ErrRepositoryInvalid) {
			t.Fatalf("ReadHead() error = %v", err)
		}
	})
	t.Run("previous read", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		addRepositoryAnchor(t, primary, mirror, 2, strings.Repeat("a", 64), strings.Repeat("b", 64))
		delete(mirror.retentions, repositoryObjectKey(1))
		if _, err := repository.ReadHead(context.Background()); !errors.Is(err, ErrRepositoryInvalid) {
			t.Fatalf("ReadHead() error = %v", err)
		}
	})
	t.Run("page chain", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		addRepositoryAnchor(t, primary, mirror, 2, strings.Repeat("f", 64), strings.Repeat("b", 64))
		if _, err := repository.ReadPage(context.Background(), 0, 2, 2); !errors.Is(err, ErrRepositoryInvalid) {
			t.Fatalf("ReadPage() error = %v", err)
		}
	})
	t.Run("health anchor", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		mirror.retentions[repositoryObjectKey(1)] = auditanchor.COSObjectRetention{
			Mode: "GOVERNANCE", RetainUntil: testNow.Add(366 * 24 * time.Hour),
		}
		health, err := repository.Health(context.Background())
		if err != nil || health.Status != "blocked" || health.ReasonCode != "anchor_invalid" {
			t.Fatalf("health = %#v, %v", health, err)
		}
	})
	t.Run("health rejects invalid repair tail", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		primary.objects[repositoryObjectKey(2)] = repositoryEnvelope(
			t, 2, strings.Repeat("f", 64), strings.Repeat("b", 64),
		)
		health, err := repository.Health(context.Background())
		if err != nil || health.Status != "blocked" || health.ReasonCode != "anchor_invalid" {
			t.Fatalf("health = %#v, %v", health, err)
		}
	})
	t.Run("mirror read unavailable", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		mirror.readErr = errors.New("provider detail")
		if _, err := repository.ReadHead(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("ReadHead() error = %v", err)
		}
	})
	t.Run("retention unavailable", func(t *testing.T) {
		repository, primary, mirror, _ := newRepositoryHarness(t)
		addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
		mirror.retentionErr = errors.New("provider detail")
		if _, err := repository.ReadHead(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("ReadHead() error = %v", err)
		}
	})
}

func TestDualCloudRepositoryStopsAfterCancellation(t *testing.T) {
	for name, attach := range map[string]func(*fakeCloudStore, *fakeCloudStore, func()){
		"primary inspect": func(primary, _ *fakeCloudStore, cancel func()) { primary.afterPrimaryInspect = cancel },
		"mirror inspect":  func(_, mirror *fakeCloudStore, cancel func()) { mirror.afterMirrorInspect = cancel },
		"primary list":    func(primary, _ *fakeCloudStore, cancel func()) { primary.afterList = cancel },
		"mirror list":     func(_, mirror *fakeCloudStore, cancel func()) { mirror.afterList = cancel },
		"primary read":    func(primary, _ *fakeCloudStore, cancel func()) { primary.afterRead = cancel },
		"mirror read":     func(_, mirror *fakeCloudStore, cancel func()) { mirror.afterRead = cancel },
		"retention":       func(_, mirror *fakeCloudStore, cancel func()) { mirror.afterRetention = cancel },
	} {
		t.Run(name, func(t *testing.T) {
			repository, primary, mirror, _ := newRepositoryHarness(t)
			addRepositoryAnchor(t, primary, mirror, 1, genesisDigest, strings.Repeat("a", 64))
			ctx, cancel := context.WithCancel(context.Background())
			attach(primary, mirror, cancel)
			if _, err := repository.ReadHead(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("ReadHead() error = %v", err)
			}
		})
	}

	t.Run("publisher", func(t *testing.T) {
		repository, _, _, publisher := newRepositoryHarness(t)
		ctx, cancel := context.WithCancel(context.Background())
		publisher.afterWrite = func(string, []byte) { cancel() }
		one := repositoryEnvelope(t, 1, genesisDigest, strings.Repeat("a", 64))
		metadata, _, _ := (&fakeVerifier{}).Verify(one)
		if _, err := repository.Publish(ctx, PublishRequest{
			ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: metadata,
		}); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("Publish() error = %v", err)
		}
	})
}

func TestDualCloudRepositoryCancelsWhileWaitingForOperation(t *testing.T) {
	repository, primary, _, _ := newRepositoryHarness(t)
	cloudCall := make(chan struct{}, 1)
	primary.afterPrimaryInspect = func() { cloudCall <- struct{}{} }

	// Hold the single operation token so ReadHead must queue before its
	// context is cancelled. observedContext makes the queue point observable
	// without relying on sleeps or scheduler timing.
	<-repository.operation
	doneObserved := make(chan struct{}, 1)
	base, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := repository.ReadHead(observedContext{Context: base, doneObserved: doneObserved})
		done <- err
	}()
	<-doneObserved
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("ReadHead() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadHead did not stop after queued context cancellation")
	}
	select {
	case <-cloudCall:
		t.Fatal("queued cancelled operation reached the cloud store")
	default:
	}
	repository.operation <- struct{}{}
}

func TestDualCloudRepositoryErrorMapping(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, auditanchor.ErrImmutableSDKUnavailable, errors.New("provider detail")} {
		if !errors.Is(mapCloudError(err), ErrRepositoryUnavailable) {
			t.Fatalf("cloud error %v not reduced to unavailable", err)
		}
	}
	for _, err := range []error{
		auditanchor.ErrImmutableSDKRequestRejected, auditanchor.ErrImmutableSDKResponseInvalid,
		auditanchor.ErrImmutableObjectNotFound, ErrRepositoryInvalid,
	} {
		if !errors.Is(mapCloudError(err), ErrRepositoryInvalid) {
			t.Fatalf("cloud error %v not reduced to invalid", err)
		}
	}
	for _, err := range []error{auditanchor.ErrPrimaryUnavailable, auditanchor.ErrMirrorUnavailable, context.Canceled, context.DeadlineExceeded} {
		if !errors.Is(mapPublisherError(err), ErrRepositoryUnavailable) {
			t.Fatalf("publisher error %v not reduced to unavailable", err)
		}
	}
	if !errors.Is(mapPublisherError(auditanchor.ErrObjectConflict), ErrRepositoryInvalid) {
		t.Fatal("publisher conflict was not reduced to invalid")
	}
}

func TestDualCloudRepositoryRejectsInvalidRequestsAndConstruction(t *testing.T) {
	repository, primary, mirror, publisher := newRepositoryHarness(t)
	one := repositoryEnvelope(t, 1, genesisDigest, strings.Repeat("a", 64))
	metadata, _, _ := (&fakeVerifier{}).Verify(one)
	badMetadata := metadata
	badMetadata.PayloadDigest = strings.Repeat("f", 64)
	if _, err := repository.Publish(context.Background(), PublishRequest{ExpectedPreviousDigest: genesisDigest, Envelope: one, Metadata: badMetadata}); !errors.Is(err, ErrRepositoryInvalid) {
		t.Fatalf("metadata mismatch error = %v", err)
	}
	if _, err := repository.ReadPage(context.Background(), 0, 1, 0); !errors.Is(err, ErrRepositoryInvalid) {
		t.Fatalf("invalid page error = %v", err)
	}
	if _, err := repository.ReadPage(context.Background(), 0, 1, 1); !errors.Is(err, ErrRepositoryInvalid) {
		t.Fatalf("missing through sequence error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.ReadHead(cancelled); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("cancelled head error = %v", err)
	}
	if _, err := (*DualCloudRepository)(nil).ReadHead(context.Background()); !errors.Is(err, ErrRepositoryInvalid) {
		t.Fatalf("nil head error = %v", err)
	}

	valid := DualCloudRepositoryConfig{
		StreamID: testConfig.StreamID, Prefix: repositoryPrefix, OSSBucket: repositoryOSSBucket,
		COSBucket: repositoryCOSBucket, ListPageSize: 2, MaxListPages: 4,
	}
	invalid := []DualCloudRepositoryConfig{
		{StreamID: "bad stream", Prefix: repositoryPrefix, OSSBucket: repositoryOSSBucket, COSBucket: repositoryCOSBucket},
		{StreamID: testConfig.StreamID, Prefix: "../audit", OSSBucket: repositoryOSSBucket, COSBucket: repositoryCOSBucket},
		{StreamID: testConfig.StreamID, Prefix: repositoryPrefix, OSSBucket: "BAD", COSBucket: repositoryCOSBucket},
		{StreamID: testConfig.StreamID, Prefix: repositoryPrefix, OSSBucket: repositoryOSSBucket, COSBucket: "bad_underscore"},
		{StreamID: testConfig.StreamID, Prefix: repositoryPrefix, OSSBucket: repositoryOSSBucket, COSBucket: repositoryCOSBucket, ListPageSize: 1001},
		{StreamID: testConfig.StreamID, Prefix: repositoryPrefix, OSSBucket: repositoryOSSBucket, COSBucket: repositoryCOSBucket, MaxListPages: 513},
	}
	for index, config := range invalid {
		if _, err := NewDualCloudRepository(config, publisher, primary, mirror, &fakeVerifier{}); err == nil {
			t.Fatalf("invalid config %d accepted", index)
		}
	}
	for index, dependencies := range []struct {
		publisher AnchorPublisher
		primary   PrimaryAnchorStore
		mirror    MirrorAnchorStore
		verifier  EnvelopeVerifier
	}{
		{nil, primary, mirror, &fakeVerifier{}},
		{publisher, nil, mirror, &fakeVerifier{}},
		{publisher, primary, nil, &fakeVerifier{}},
		{publisher, primary, mirror, nil},
	} {
		if _, err := NewDualCloudRepository(valid, dependencies.publisher, dependencies.primary, dependencies.mirror, dependencies.verifier); err == nil {
			t.Fatalf("invalid dependency set %d accepted", index)
		}
	}
}
