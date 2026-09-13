package tencentcredential

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func metadataResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func credentialBody(now time.Time, sequence int) string {
	expiration := now.UTC().Add(time.Hour).Truncate(time.Second)
	return fmt.Sprintf(
		`{"TmpSecretId":"TMP.ID.%d","TmpSecretKey":"temporary-secret-%d","ExpiredTime":%d,"Expiration":%q,"Token":"temporary-token-%d","Code":"Success"}`,
		sequence, sequence, expiration.Unix(), expiration.Format(time.RFC3339), sequence,
	)
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

type metadataClient struct {
	mu      sync.Mutex
	clock   *testClock
	calls   int
	fail    bool
	block   chan struct{}
	started chan struct{}
	once    sync.Once
}

func (client *metadataClient) Do(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet || request.URL.Scheme != "http" || request.URL.Host != metadataHost ||
		request.URL.Path != credentialPathPrefix+"broker-readonly" || request.URL.RawQuery != "" ||
		len(request.Header) != 0 {
		return nil, errors.New("unexpected request")
	}
	client.mu.Lock()
	client.calls++
	call, fail, block, started := client.calls, client.fail, client.block, client.started
	client.mu.Unlock()
	if started != nil {
		client.once.Do(func() { close(started) })
	}
	if block != nil {
		select {
		case <-request.Context().Done():
			return nil, request.Context().Err()
		case <-block:
		}
	}
	if fail {
		return metadataResponse(http.StatusTooManyRequests, "credential-canary-must-not-escape"), nil
	}
	return metadataResponse(http.StatusOK, credentialBody(client.clock.Now(), call)), nil
}

func (client *metadataClient) count() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.calls
}

func (client *metadataClient) setFailure(value bool) {
	client.mu.Lock()
	client.fail = value
	client.mu.Unlock()
}

func testProvider(t *testing.T, client httpDoer, clock *testClock) *CVMRoleProvider {
	t.Helper()
	provider, err := newTestCVMRoleProvider(client, "broker-readonly", clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestCVMRoleProviderUsesOnlyFixedRoleRequest(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	client := &metadataClient{clock: clock}
	provider := testProvider(t, client, clock)
	credential, err := provider.Credential(context.Background())
	if err != nil || credential.RoleName != "broker-readonly" || credential.SecretID != "TMP.ID.1" {
		t.Fatalf("credential metadata = (%q, %q, %v)", credential.RoleName, credential.SecretID, err)
	}
	credential.SecretKey = "caller-mutated"
	again, err := provider.Credential(context.Background())
	if err != nil || again.SecretKey == "caller-mutated" || client.count() != 1 {
		t.Fatal("credential cache was mutated by caller")
	}
}

func TestCVMRoleProviderCachesAndCoalescesRefresh(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	block, started := make(chan struct{}), make(chan struct{})
	client := &metadataClient{clock: clock, block: block, started: started}
	provider := testProvider(t, client, clock)

	const callers = 24
	results := make(chan error, callers)
	for range callers {
		go func() {
			credential, err := provider.Credential(context.Background())
			if err == nil && credential.SecretID != "TMP.ID.1" {
				err = errors.New("unexpected credential")
			}
			results <- err
		}()
	}
	<-started
	close(block)
	for range callers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if client.count() != 1 {
		t.Fatalf("concurrent metadata requests = %d", client.count())
	}
	if _, err := provider.Credential(context.Background()); err != nil || client.count() != 1 {
		t.Fatal("cache hit called metadata")
	}
	clock.Advance(55 * time.Minute)
	if refreshed, err := provider.Credential(context.Background()); err != nil || refreshed.SecretID != "TMP.ID.2" {
		t.Fatalf("refreshed credential = (%q, %v)", refreshed.SecretID, err)
	}
}

func TestCVMRoleProviderCancellationDoesNotCancelSharedRefresh(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	block, started := make(chan struct{}), make(chan struct{})
	client := &metadataClient{clock: clock, block: block, started: started}
	provider := testProvider(t, client, clock)
	callerContext, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := provider.Credential(callerContext); first <- err }()
	<-started
	cancel()
	if err := <-first; err == nil {
		t.Fatal("canceled caller received authority")
	}
	second := make(chan error, 1)
	go func() { _, err := provider.Credential(context.Background()); second <- err }()
	close(block)
	if err := <-second; err != nil || client.count() != 1 {
		t.Fatalf("shared refresh result = (%d, %v)", client.count(), err)
	}
}

func TestCVMRoleProviderRefreshFailureClearsCacheAndBacksOff(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &metadataClient{clock: clock}
	provider := testProvider(t, client, clock)
	if _, err := provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(55 * time.Minute)
	client.setFailure(true)
	if credential, err := provider.Credential(context.Background()); err == nil || credential.SecretID != "" ||
		err.Error() != ErrCredentialUnavailable.Error() || strings.Contains(err.Error(), "canary") {
		t.Fatal("refresh failure exposed stale authority or response")
	}
	calls := client.count()
	if _, err := provider.Credential(context.Background()); err == nil || client.count() != calls {
		t.Fatal("retry cooldown made a metadata request")
	}
	clock.Advance(credentialRetryDelay)
	if _, err := provider.Credential(context.Background()); err == nil || client.count() != calls+1 {
		t.Fatal("bounded retry did not occur")
	}
}

func TestCVMRoleProviderRejectsClockRollbackAndLateSuccess(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &metadataClient{clock: clock}
	provider := testProvider(t, client, clock)
	if _, err := provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(-time.Minute)
	if _, err := provider.Credential(context.Background()); err != nil || client.count() != 2 {
		t.Fatal("clock rollback reused cached authority")
	}

	lateClient := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: &lateBody{
			ctx: request.Context(), value: []byte(credentialBody(clock.Now(), 3)),
		}}, nil
	})
	late := testProvider(t, &http.Client{Transport: lateClient}, clock)
	late.requestTimeout = 20 * time.Millisecond
	if credential, err := late.Credential(context.Background()); err == nil || credential.SecretID != "" {
		t.Fatal("late response published authority")
	}
}

type lateBody struct {
	ctx   context.Context
	value []byte
	sent  bool
}

func (body *lateBody) Read(destination []byte) (int, error) {
	if body.sent {
		return 0, io.EOF
	}
	<-body.ctx.Done()
	body.sent = true
	return copy(destination, body.value), io.EOF
}

func (*lateBody) Close() error { return nil }

func TestCVMRoleProviderRejectsMalformedCredentials(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	expiration := now.Add(time.Hour)
	valid := credentialBody(now, 1)
	cases := []string{
		`{"TmpSecretId":"TMP.ID","TmpSecretId":"OTHER","TmpSecretKey":"temporary-secret","ExpiredTime":1,"Expiration":"2026-09-13T01:00:00Z","Token":"temporary-token","Code":"Success"}`,
		strings.Replace(valid, `"Code":"Success"`, `"Code":"Failure"`, 1),
		strings.Replace(valid, fmt.Sprintf(`"ExpiredTime":%d`, expiration.Unix()), `"ExpiredTime":1`, 1),
		strings.Replace(valid, expiration.Format(time.RFC3339), expiration.In(time.FixedZone("offset", 8*60*60)).Format(time.RFC3339), 1),
		strings.Replace(valid, `"Token":"temporary-token-1"`, `"Token":" short "`, 1),
		strings.TrimSuffix(valid, "}") + `,"Unexpected":true}`,
		valid + `{}`,
		strings.Repeat("x", maxMetadataResponseBytes+1),
	}
	for _, body := range cases {
		client := roundTripFunc(func(*http.Request) (*http.Response, error) { return metadataResponse(http.StatusOK, body), nil })
		provider, err := newTestCVMRoleProvider(&http.Client{Transport: client}, "broker-readonly", func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		if credential, err := provider.Credential(context.Background()); err == nil || credential.SecretID != "" {
			t.Fatal("malformed credential was accepted")
		}
	}
}

type resolverStub struct {
	addresses []net.IPAddr
	err       error
}

func (resolver resolverStub) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return resolver.addresses, resolver.err
}

func TestMetadataHTTPClientPinsLinkLocalDestination(t *testing.T) {
	dialed := ""
	client, err := newMetadataHTTPClient(time.Second, resolverStub{addresses: []net.IPAddr{{IP: net.ParseIP("169.254.0.23")}}},
		func(_ context.Context, network, address string) (net.Conn, error) {
			dialed = network + ":" + address
			return nil, ErrCredentialUnavailable
		})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || client.CheckRedirect == nil {
		t.Fatal("unsafe metadata transport settings")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", metadataHost+":80"); err == nil || dialed != "tcp4:169.254.0.23:80" {
		t.Fatalf("pinned dial = %q, %v", dialed, err)
	}
	for _, addresses := range [][]net.IPAddr{
		{{IP: net.ParseIP("10.0.0.1")}},
		{{IP: net.ParseIP("169.254.0.23")}, {IP: net.ParseIP("203.0.113.1")}},
		{{IP: net.ParseIP("fe80::1")}},
	} {
		unsafeClient, err := newMetadataHTTPClient(time.Second, resolverStub{addresses: addresses},
			func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("unsafe address was dialed")
				return nil, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unsafeClient.Transport.(*http.Transport).DialContext(context.Background(), "tcp", metadataHost+":80"); err == nil {
			t.Fatal("unsafe metadata resolution was accepted")
		}
	}
}

func TestCVMRoleProviderConstructorsRejectUnsafeInputs(t *testing.T) {
	if provider, err := NewCVMRoleProvider("broker-readonly", time.Second); err != nil || provider == nil {
		t.Fatal("valid constructor rejected")
	}
	for _, role := range []string{"", "bad role", "../role", strings.Repeat("a", 65)} {
		if provider, err := NewCVMRoleProvider(role, time.Second); err == nil || provider != nil {
			t.Fatal("unsafe role was accepted")
		}
	}
	if client, err := newMetadataHTTPClient(0, net.DefaultResolver, (&net.Dialer{}).DialContext); err == nil || client != nil {
		t.Fatal("unsafe timeout was accepted")
	}
	if client, err := newMetadataHTTPClient(time.Second, nil, (&net.Dialer{}).DialContext); err == nil || client != nil {
		t.Fatal("nil resolver was accepted")
	}
	if provider, err := newTestCVMRoleProvider(nil, "broker-readonly", time.Now); err == nil || provider != nil {
		t.Fatal("nil test client was accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	clock := &testClock{now: time.Now()}
	provider := testProvider(t, &metadataClient{clock: clock}, clock)
	if credential, err := provider.Credential(canceled); err == nil || credential.SecretID != "" {
		t.Fatal("canceled caller received authority")
	}
}

func TestCVMRoleProviderRejectsTransportAndBodyFailures(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	cases := []httpDoer{
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("credential-canary") })},
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })},
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: nil}, nil
		})},
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}}, nil
		})},
	}
	for _, client := range cases {
		provider, err := newTestCVMRoleProvider(client, "broker-readonly", func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		if credential, err := provider.Credential(context.Background()); err == nil || credential.SecretID != "" ||
			strings.Contains(err.Error(), "canary") {
			t.Fatal("transport failure escaped boundary")
		}
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("credential-canary") }
func (failingBody) Close() error             { return errors.New("credential-canary") }

func TestCredentialAfterRefreshRechecksBoundary(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)}
	client := &metadataClient{clock: clock}
	provider := testProvider(t, client, clock)
	if _, err := provider.Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed := &credentialRefresh{done: make(chan struct{})}
	close(completed.done)
	clock.Advance(55 * time.Minute)
	if credential, err := provider.credentialAfterRefresh(context.Background(), completed); err == nil || credential.SecretID != "" {
		t.Fatal("waiter received authority at refresh boundary")
	}
	if credential, err := provider.credentialAfterRefresh(context.Background(), nil); err == nil || credential.SecretID != "" {
		t.Fatal("nil refresh returned authority")
	}
}

func TestRejectDuplicateKeysWalksNestedValues(t *testing.T) {
	valid := []byte(`{"outer":[{"one":1},{"two":2}],"value":"not-a-key"}`)
	if err := rejectDuplicateKeys(valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		[]byte(`{"outer":{"key":1,"key":2}}`),
		[]byte(`{"outer":[}`),
		[]byte(`{"value":1}{"other":2}`),
	} {
		if err := rejectDuplicateKeys(value); err == nil {
			t.Fatal("invalid JSON structure was accepted")
		}
	}
}
