package aliyunsigner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

type controlledClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *controlledClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *controlledClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

type cacheIMDSClient struct {
	mu                sync.Mutex
	clock             *controlledClock
	tokenCalls        int
	credentialCalls   int
	failCredentials   bool
	credentialBlock   chan struct{}
	credentialStarted chan struct{}
	startedOnce       sync.Once
	advanceOnToken    time.Duration
}

func (client *cacheIMDSClient) Do(request *http.Request) (*http.Response, error) {
	switch request.URL.Path {
	case imdsTokenPath:
		client.mu.Lock()
		client.tokenCalls++
		call := client.tokenCalls
		advance := client.advanceOnToken
		client.advanceOnToken = 0
		client.mu.Unlock()
		if advance != 0 {
			client.clock.Advance(advance)
		}
		return response(http.StatusOK, fmt.Sprintf("bound-imds-token-%d", call)), nil
	case imdsRoleCredentialPrefix + "broker-readonly", imdsRoleCredentialPrefix + "broker-secondary":
		client.mu.Lock()
		client.credentialCalls++
		call := client.credentialCalls
		fail := client.failCredentials
		block := client.credentialBlock
		started := client.credentialStarted
		client.mu.Unlock()
		if started != nil {
			client.startedOnce.Do(func() { close(started) })
		}
		if block != nil {
			select {
			case <-request.Context().Done():
				return nil, request.Context().Err()
			case <-block:
			}
		}
		if fail {
			return response(http.StatusTooManyRequests, "limited"), nil
		}
		now := client.clock.Now().UTC()
		body := fmt.Sprintf(
			`{"Code":"Success","AccessKeyId":"STS.CACHE.%d","AccessKeySecret":"temporary-secret-%d","SecurityToken":"temporary-security-token-%d","Expiration":%q,"LastUpdated":%q}`,
			call, call, call, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339),
		)
		return response(http.StatusOK, body), nil
	default:
		return response(http.StatusNotFound, "not found"), nil
	}
}

func (client *cacheIMDSClient) counts() (int, int) {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.tokenCalls, client.credentialCalls
}

func (client *cacheIMDSClient) setCredentialFailure(value bool) {
	client.mu.Lock()
	client.failCredentials = value
	client.mu.Unlock()
}

func newCacheTestProvider(t *testing.T, client *cacheIMDSClient, role string) *IMDSv2CredentialProvider {
	t.Helper()
	provider, err := newTestIMDSv2CredentialProvider(client, role, client.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestIMDSv2CachesCredentialAndRefreshesWithoutRefreshingToken(t *testing.T) {
	clock := &controlledClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &cacheIMDSClient{clock: clock}
	provider := newCacheTestProvider(t, client, "broker-readonly")

	first, err := provider.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.AccessKeySecret = "caller-mutated-value"
	second, err := provider.Credential(context.Background())
	if err != nil || second.AccessKeyID != first.AccessKeyID || second.AccessKeySecret != "temporary-secret-1" {
		t.Fatalf("cached credential = (%q, %v)", second.AccessKeyID, err)
	}
	if tokens, credentials := client.counts(); tokens != 1 || credentials != 1 {
		t.Fatalf("cache hit made network calls: token=%d credential=%d", tokens, credentials)
	}

	clock.Advance(55 * time.Minute)
	refreshed, err := provider.Credential(context.Background())
	if err != nil || refreshed.AccessKeyID == first.AccessKeyID {
		t.Fatalf("refreshed credential = (%q, %v)", refreshed.AccessKeyID, err)
	}
	if tokens, credentials := client.counts(); tokens != 1 || credentials != 2 {
		t.Fatalf("credential refresh did not reuse valid token: token=%d credential=%d", tokens, credentials)
	}
}

func TestIMDSv2CoalescesConcurrentRefreshes(t *testing.T) {
	clock := &controlledClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	block := make(chan struct{})
	started := make(chan struct{})
	client := &cacheIMDSClient{clock: clock, credentialBlock: block, credentialStarted: started}
	provider := newCacheTestProvider(t, client, "broker-readonly")

	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			credential, err := provider.Credential(context.Background())
			if err == nil && credential.AccessKeyID != "STS.CACHE.1" {
				err = fmt.Errorf("unexpected credential")
			}
			results <- err
		}()
	}
	close(start)
	<-started
	close(block)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if tokens, credentials := client.counts(); tokens != 1 || credentials != 1 {
		t.Fatalf("concurrent refresh was not coalesced: token=%d credential=%d", tokens, credentials)
	}
}

func TestIMDSv2CallerCancellationDoesNotCancelSharedRefresh(t *testing.T) {
	clock := &controlledClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	block := make(chan struct{})
	started := make(chan struct{})
	client := &cacheIMDSClient{clock: clock, credentialBlock: block, credentialStarted: started}
	provider := newCacheTestProvider(t, client, "broker-readonly")

	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, err := provider.Credential(firstContext)
		firstResult <- err
	}()
	<-started
	cancelFirst()
	if err := <-firstResult; err == nil {
		t.Fatal("canceled caller received a credential")
	}

	secondResult := make(chan error, 1)
	go func() {
		_, err := provider.Credential(context.Background())
		secondResult <- err
	}()
	close(block)
	if err := <-secondResult; err != nil {
		t.Fatalf("shared refresh was canceled by first caller: %v", err)
	}
	if tokens, credentials := client.counts(); tokens != 1 || credentials != 1 {
		t.Fatalf("caller cancellation started another refresh: token=%d credential=%d", tokens, credentials)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Credential(canceled); err == nil {
		t.Fatal("canceled cache-hit caller received a credential")
	}
	if tokens, credentials := client.counts(); tokens != 1 || credentials != 1 {
		t.Fatal("canceled cache-hit caller made a network request")
	}
}

func TestIMDSv2RefreshFailureClearsCredentialAndBacksOff(t *testing.T) {
	clock := &controlledClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &cacheIMDSClient{clock: clock}
	provider := newCacheTestProvider(t, client, "broker-readonly")
	if _, err := provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}

	clock.Advance(55 * time.Minute)
	client.setCredentialFailure(true)
	if credential, err := provider.Credential(context.Background()); err == nil ||
		credential.AccessKeyID != "" || err.Error() != ErrWorkloadCredentialUnavailable.Error() {
		t.Fatal("refresh failure returned the stale credential")
	}
	beforeToken, beforeCredential := client.counts()
	if _, err := provider.Credential(context.Background()); err == nil {
		t.Fatal("retry cooldown returned a credential")
	}
	if tokens, credentials := client.counts(); tokens != beforeToken || credentials != beforeCredential {
		t.Fatal("retry cooldown made another metadata request")
	}

	clock.Advance(credentialRetryDelay)
	if _, err := provider.Credential(context.Background()); err == nil {
		t.Fatal("failed retry returned a credential")
	}
	if tokens, credentials := client.counts(); tokens != beforeToken+1 || credentials != beforeCredential+1 {
		t.Fatalf("bounded retry requests = token:%d credential:%d", tokens, credentials)
	}
}

func TestIMDSv2ClockRollbackCannotExtendCachedCredential(t *testing.T) {
	clock := &controlledClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &cacheIMDSClient{clock: clock}
	provider := newCacheTestProvider(t, client, "broker-readonly")
	if _, err := provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(-time.Minute)
	if _, err := provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokens, credentials := client.counts(); tokens != 2 || credentials != 2 {
		t.Fatalf("clock rollback reused cached authority: token=%d credential=%d", tokens, credentials)
	}
}

func TestIMDSv2TokenTTLStartsBeforeRequestAndRoleCachesAreIsolated(t *testing.T) {
	initial := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	clock := &controlledClock{now: initial}
	client := &cacheIMDSClient{clock: clock, advanceOnToken: time.Hour}
	primary := newCacheTestProvider(t, client, "broker-readonly")
	if _, err := primary.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !primary.tokenRefreshAt.Equal(initial.Add(imdsTokenLifetime - imdsTokenRefreshSkew)) {
		t.Fatalf("token TTL started after response: %s", primary.tokenRefreshAt)
	}

	secondary := newCacheTestProvider(t, client, "broker-secondary")
	credential, err := secondary.Credential(context.Background())
	if err != nil || credential.RoleName != "broker-secondary" {
		t.Fatalf("secondary role credential = (%q, %v)", credential.RoleName, err)
	}
	if tokens, credentials := client.counts(); tokens != 2 || credentials != 2 {
		t.Fatalf("role instances shared cache: token=%d credential=%d", tokens, credentials)
	}
}

func TestIMDSv2SharedRefreshHasHardTimeout(t *testing.T) {
	clock := &controlledClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &cacheIMDSClient{clock: clock, credentialBlock: make(chan struct{})}
	provider := newCacheTestProvider(t, client, "broker-readonly")
	provider.requestTimeout = 20 * time.Millisecond

	started := time.Now()
	if _, err := provider.Credential(context.Background()); err == nil {
		t.Fatal("timed-out refresh returned a credential")
	}
	if time.Since(started) > time.Second {
		t.Fatal("shared refresh exceeded its hard timeout")
	}
}

func TestIMDSv2WaiterRechecksCredentialAtRefreshBoundary(t *testing.T) {
	clock := &controlledClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &cacheIMDSClient{clock: clock}
	provider := newCacheTestProvider(t, client, "broker-readonly")
	if _, err := provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}

	completedRefresh := &credentialRefresh{done: make(chan struct{})}
	close(completedRefresh.done)
	clock.Advance(55 * time.Minute)
	if credential, err := provider.credentialAfterRefresh(context.Background(), completedRefresh); err == nil ||
		credential.AccessKeyID != "" {
		t.Fatal("delayed waiter received a credential at the refresh boundary")
	}
}

type contextDelayedBody struct {
	ctx     context.Context
	payload []byte
	sent    bool
}

func (body *contextDelayedBody) Read(destination []byte) (int, error) {
	if body.sent {
		return 0, io.EOF
	}
	<-body.ctx.Done()
	body.sent = true
	count := copy(destination, body.payload)
	return count, io.EOF
}

func (*contextDelayedBody) Close() error { return nil }

func TestIMDSv2DoesNotPublishLateSuccessAfterRefreshDeadline(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	calls := 0
	client := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Path == imdsTokenPath {
			return response(http.StatusOK, "bound-imds-v2-token"), nil
		}
		payload := []byte(fmt.Sprintf(
			`{"Code":"Success","AccessKeyId":"STS.LATE","AccessKeySecret":"late-temporary-secret","SecurityToken":"late-temporary-security-token","Expiration":%q,"LastUpdated":%q}`,
			now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339),
		))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       &contextDelayedBody{ctx: request.Context(), payload: payload},
		}, nil
	})
	provider, err := newTestIMDSv2CredentialProvider(&http.Client{Transport: client}, "broker-readonly", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	provider.requestTimeout = 20 * time.Millisecond

	if credential, err := provider.Credential(context.Background()); err == nil || credential.AccessKeyID != "" {
		t.Fatal("late successful response was published after the refresh deadline")
	}
	provider.mu.Lock()
	cached := provider.credential
	provider.mu.Unlock()
	if cached.AccessKeyID != "" || calls != 2 {
		t.Fatalf("late result contaminated cache: credential=%q calls=%d", cached.AccessKeyID, calls)
	}
}
