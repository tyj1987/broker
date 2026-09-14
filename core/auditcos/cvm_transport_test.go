package auditcos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/tencentcredential"
)

type staticCOSCredentialProvider struct {
	credential tencentcredential.TemporaryCredential
	err        error
	calls      int
	hook       func(context.Context)
}

func (provider *staticCOSCredentialProvider) Credential(ctx context.Context) (tencentcredential.TemporaryCredential, error) {
	provider.calls++
	if provider.hook != nil {
		provider.hook(ctx)
	}
	return provider.credential, provider.err
}

type cosRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip cosRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type closeRecorder struct {
	closed bool
}

func (*closeRecorder) Read([]byte) (int, error) { return 0, io.EOF }

func (body *closeRecorder) Close() error {
	body.closed = true
	return nil
}

func testCOSCredential(now time.Time) tencentcredential.TemporaryCredential {
	return tencentcredential.TemporaryCredential{
		SecretID: "AKIDTESTONLY", SecretKey: "synthetic-signing-key", Token: "synthetic-session-token",
		Expiration: now.UTC().Add(time.Hour), RoleName: "audit-mirror-role",
	}
}

func testUnsignedCOSRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+expectedCOSBucketHost(cosSDKTestBucket, cosSDKTestRegion)+"/object", nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestCVMRoleAuthorizationTransportSignsOneBoundRequest(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	provider := &staticCOSCredentialProvider{credential: testCOSCredential(now)}
	var signed *http.Request
	downstream := cosRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		signed = request.Clone(request.Context())
		signed.Header = request.Header.Clone()
		header := http.Header{
			"Authorization":        {"echoed"},
			"Set-Cookie":           {"echoed=value"},
			"X-Cos-Security-Token": {"echoed"},
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: header, Body: http.NoBody, Request: request,
		}, nil
	})
	transport := &cvmRoleAuthorizationTransport{
		provider: provider, downstream: downstream,
		expectedHost: expectedCOSBucketHost(cosSDKTestBucket, cosSDKTestRegion), clock: func() time.Time { return now },
	}
	request := testUnsignedCOSRequest(t)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if provider.calls != 1 || signed == nil || signed.URL.Host != transport.expectedHost ||
		signed.Header.Get("Authorization") == "" || signed.Header.Get("X-Cos-Security-Token") == "" {
		t.Fatal("request was not signed through the bound credential provider")
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("X-Cos-Security-Token") != "" {
		t.Fatal("the caller-owned request was mutated")
	}
	if response.Request == nil || response.Request.Header.Get("Authorization") != "" ||
		response.Request.Header.Get("X-Cos-Security-Token") != "" || response.Header.Get("Authorization") != "" ||
		response.Header.Get("Set-Cookie") != "" || response.Header.Get("X-Cos-Security-Token") != "" {
		t.Fatal("signed credential material remained attached to the response")
	}
}

func TestCVMRoleAuthorizationTransportRejectsRequestConfusionBeforeCredentials(t *testing.T) {
	host := expectedCOSBucketHost(cosSDKTestBucket, cosSDKTestRegion)
	mutations := map[string]func(*http.Request){
		"http":              func(request *http.Request) { request.URL.Scheme = "http" },
		"wrong_host":        func(request *http.Request) { request.URL.Host = "other.cos.ap-guangzhou.tencentcos.cn" },
		"port":              func(request *http.Request) { request.URL.Host = host + ":443" },
		"userinfo":          func(request *http.Request) { request.URL.User = url.User("caller") },
		"opaque":            func(request *http.Request) { request.URL.Opaque = "//" + host + "/object" },
		"fragment":          func(request *http.Request) { request.URL.Fragment = "fragment" },
		"raw_path":          func(request *http.Request) { request.URL.RawPath = "/%6fbject" },
		"force_query":       func(request *http.Request) { request.URL.ForceQuery = true },
		"request_uri":       func(request *http.Request) { request.RequestURI = "/object" },
		"host_override":     func(request *http.Request) { request.Host = "other.example" },
		"close":             func(request *http.Request) { request.Close = true },
		"transfer_encoding": func(request *http.Request) { request.TransferEncoding = []string{"chunked"} },
		"trailer":           func(request *http.Request) { request.Trailer = http.Header{"X-Test": {"value"}} },
		"post":              func(request *http.Request) { request.Method = http.MethodPost },
		"authorization":     func(request *http.Request) { request.Header.Set("Authorization", "caller") },
		"proxy_auth":        func(request *http.Request) { request.Header.Set("Proxy-Authorization", "caller") },
		"cookie":            func(request *http.Request) { request.Header.Set("Cookie", "caller=value") },
		"forwarded":         func(request *http.Request) { request.Header.Set("Forwarded", "host=other") },
		"forwarded_host":    func(request *http.Request) { request.Header.Set("X-Forwarded-Host", "other") },
		"security_token":    func(request *http.Request) { request.Header.Set("X-Cos-Security-Token", "caller") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			provider := &staticCOSCredentialProvider{}
			called := false
			transport := &cvmRoleAuthorizationTransport{
				provider: provider,
				downstream: cosRoundTripFunc(func(*http.Request) (*http.Response, error) {
					called = true
					return nil, nil
				}),
				expectedHost: host, clock: time.Now,
			}
			request := testUnsignedCOSRequest(t)
			mutate(request)
			if _, err := transport.RoundTrip(request); !errors.Is(err, ErrImmutableSDKRequestRejected) {
				t.Fatalf("expected request rejection, got %v", err)
			}
			if provider.calls != 0 || called {
				t.Fatal("rejected request reached credentials or network")
			}
		})
	}
}

func TestCVMRoleAuthorizationTransportFailsClosedOnCredentialAndNetworkErrors(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	cases := map[string]*staticCOSCredentialProvider{
		"provider_error": {err: errors.New("sensitive provider detail")},
		"expired": {credential: func() tencentcredential.TemporaryCredential {
			value := testCOSCredential(now)
			value.Expiration = now
			return value
		}()},
		"non_utc": {credential: func() tencentcredential.TemporaryCredential {
			value := testCOSCredential(now)
			value.Expiration = value.Expiration.In(time.FixedZone("test", 3600))
			return value
		}()},
		"missing_role": {credential: func() tencentcredential.TemporaryCredential {
			value := testCOSCredential(now)
			value.RoleName = ""
			return value
		}()},
		"invalid_role": {credential: func() tencentcredential.TemporaryCredential {
			value := testCOSCredential(now)
			value.RoleName = "role name"
			return value
		}()},
		"invalid_key": {credential: func() tencentcredential.TemporaryCredential {
			value := testCOSCredential(now)
			value.SecretKey = "synthetic key"
			return value
		}()},
		"excess_lifetime": {credential: func() tencentcredential.TemporaryCredential {
			value := testCOSCredential(now)
			value.Expiration = now.Add(37 * time.Hour)
			return value
		}()},
	}
	for name, provider := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			transport := &cvmRoleAuthorizationTransport{
				provider: provider,
				downstream: cosRoundTripFunc(func(*http.Request) (*http.Response, error) {
					called = true
					return nil, nil
				}),
				expectedHost: expectedCOSBucketHost(cosSDKTestBucket, cosSDKTestRegion),
				clock:        func() time.Time { return now },
			}
			_, err := transport.RoundTrip(testUnsignedCOSRequest(t))
			if err != ErrImmutableSDKUnavailable || strings.Contains(err.Error(), "provider detail") || called {
				t.Fatal("credential failure was not normalized before network access")
			}
		})
	}

	closed := &closeRecorder{}
	provider := &staticCOSCredentialProvider{credential: testCOSCredential(now)}
	transport := &cvmRoleAuthorizationTransport{
		provider: provider,
		downstream: cosRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: closed, Request: request}, errors.New("network detail")
		}),
		expectedHost: expectedCOSBucketHost(cosSDKTestBucket, cosSDKTestRegion), clock: func() time.Time { return now },
	}
	if _, err := transport.RoundTrip(testUnsignedCOSRequest(t)); err != ErrImmutableSDKUnavailable || !closed.closed {
		t.Fatal("network failure was not normalized and closed")
	}
}

func TestCVMRoleAuthorizationTransportHonorsCancellationAndBoundsResponses(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	provider := &staticCOSCredentialProvider{credential: testCOSCredential(now)}
	provider.hook = func(ctx context.Context) {
		if cancel, ok := ctx.Value(cancelContextKey{}).(context.CancelFunc); ok {
			cancel()
		}
	}
	called := false
	transport := &cvmRoleAuthorizationTransport{
		provider: provider,
		downstream: cosRoundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		}),
		expectedHost: expectedCOSBucketHost(cosSDKTestBucket, cosSDKTestRegion), clock: func() time.Time { return now },
	}
	ctx, cancel := context.WithCancel(context.Background())
	request := testUnsignedCOSRequest(t).WithContext(context.WithValue(ctx, cancelContextKey{}, context.CancelFunc(cancel)))
	if _, err := transport.RoundTrip(request); err != ErrImmutableSDKUnavailable || called {
		t.Fatal("late credential success after cancellation reached the network")
	}

	provider.hook = nil
	transport.downstream = cosRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := bytes.Repeat([]byte("x"), maxCOSWireResponseBytes+1)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	})
	response, err := transport.RoundTrip(testUnsignedCOSRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	var tooLarge *http.MaxBytesError
	if !errors.As(readErr, &tooLarge) {
		t.Fatalf("expected bounded response error, got %v", readErr)
	}
}

type cancelContextKey struct{}

func TestCVMRoleCOSSDKImmutableClientFactory(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	provider := &staticCOSCredentialProvider{credential: testCOSCredential(now)}
	calls := 0
	var signedHost string
	downstream := cosRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		signedHost = request.URL.Host
		if request.Header.Get("Authorization") == "" || request.Header.Get("X-Cos-Security-Token") == "" {
			t.Fatal("SDK request reached the network unsigned")
		}
		body := "<ListVersionsResult><Name>" + cosSDKTestBucket + "</Name><Prefix>" + sdkTestKey +
			"</Prefix><MaxKeys>2</MaxKeys><IsTruncated>false</IsTruncated></ListVersionsResult>"
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), Request: request,
		}, nil
	})
	client, err := newCVMRoleCOSSDKImmutableClient(
		cosSDKTestBucket, cosSDKTestRegion, provider, downstream, func() time.Time { return now }, 5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResolveObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey); !errors.Is(err, ErrImmutableObjectNotFound) {
		t.Fatalf("expected an empty exact-version result, got %v", err)
	}
	if calls != 1 || provider.calls != 1 || signedHost != expectedCOSBucketHost(cosSDKTestBucket, cosSDKTestRegion) {
		t.Fatal("factory did not bind one request to the expected endpoint and credential source")
	}

	downstream = cosRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("synthetic network error")
	})
	calls = 0
	provider.calls = 0
	client, err = newCVMRoleCOSSDKImmutableClient(
		cosSDKTestBucket, cosSDKTestRegion, provider, downstream, func() time.Time { return now }, 5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResolveObjectVersion(context.Background(), cosSDKTestBucket, sdkTestKey); !errors.Is(err, ErrImmutableSDKUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
	if calls != 1 || provider.calls != 1 {
		t.Fatal("SDK retried an uncertain request")
	}
}

func TestCVMRoleCOSSDKImmutableClientFactoryRejectsInvalidConfiguration(t *testing.T) {
	now := time.Date(2026, 9, 15, 1, 2, 3, 0, time.UTC)
	provider := &staticCOSCredentialProvider{credential: testCOSCredential(now)}
	downstream := cosRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	cases := []struct {
		bucket     string
		region     string
		provider   cosCredentialProvider
		downstream http.RoundTripper
		clock      func() time.Time
		timeout    time.Duration
	}{
		{"BAD", cosSDKTestRegion, provider, downstream, time.Now, time.Second},
		{cosSDKTestBucket, "BAD_REGION", provider, downstream, time.Now, time.Second},
		{cosSDKTestBucket, cosSDKTestRegion, nil, downstream, time.Now, time.Second},
		{cosSDKTestBucket, cosSDKTestRegion, provider, nil, time.Now, time.Second},
		{cosSDKTestBucket, cosSDKTestRegion, provider, downstream, nil, time.Second},
		{cosSDKTestBucket, cosSDKTestRegion, provider, downstream, time.Now, 0},
		{cosSDKTestBucket, cosSDKTestRegion, provider, downstream, time.Now, maxCOSRequestTimeout + time.Second},
	}
	for index, testCase := range cases {
		if _, err := newCVMRoleCOSSDKImmutableClient(
			testCase.bucket, testCase.region, testCase.provider, testCase.downstream, testCase.clock, testCase.timeout,
		); !errors.Is(err, ErrImmutableSDKRequestRejected) {
			t.Fatalf("case %d: expected rejection, got %v", index, err)
		}
	}
	if _, err := NewCVMRoleCOSSDKImmutableClient(cosSDKTestBucket, cosSDKTestRegion, nil, time.Second); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("expected nil concrete provider rejection, got %v", err)
	}
	concrete, err := tencentcredential.NewCVMRoleProvider("audit-mirror-role", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewCVMRoleCOSSDKImmutableClient(cosSDKTestBucket, cosSDKTestRegion, concrete, time.Second)
	if err != nil || client == nil {
		t.Fatalf("valid concrete provider construction failed: %v", err)
	}
	if _, err := NewCVMRoleCOSSDKImmutableClient(cosSDKTestBucket, cosSDKTestRegion, concrete, 0); !errors.Is(err, ErrImmutableSDKRequestRejected) {
		t.Fatalf("expected concrete provider timeout rejection, got %v", err)
	}
}

func TestCOSNetworkTransportIsBoundedAndProxyFree(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, maxCOSRequestTimeout + time.Second} {
		if _, err := newCOSNetworkTransport(timeout); !errors.Is(err, ErrImmutableSDKRequestRejected) {
			t.Fatalf("timeout %v: expected rejection, got %v", timeout, err)
		}
	}
	transport, err := newCOSNetworkTransport(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != 0x0303 || transport.ResponseHeaderTimeout != 5*time.Second ||
		transport.TLSHandshakeTimeout != 5*time.Second || transport.MaxConnsPerHost != 2 {
		t.Fatal("network transport is missing a required hardening boundary")
	}
}
