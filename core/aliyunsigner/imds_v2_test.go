package aliyunsigner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestIMDSv2CredentialProviderRequiresTokenBeforeFixedRoleRequest(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	step := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		step++
		switch step {
		case 1:
			if request.Method != http.MethodPut || request.URL.String() != imdsEndpoint+imdsTokenPath ||
				request.Header.Get("X-aliyun-ecs-metadata-token-ttl-seconds") != imdsTokenTTLSeconds ||
				request.Header.Get("X-aliyun-ecs-metadata-token") != "" {
				t.Fatalf("unexpected token request: %s %s %#v", request.Method, request.URL, request.Header)
			}
			return response(200, "bound-imds-v2-token"), nil
		case 2:
			if request.Method != http.MethodGet || request.URL.String() != imdsEndpoint+imdsRoleCredentialPrefix+"broker-readonly" ||
				request.Header.Get("X-aliyun-ecs-metadata-token") != "bound-imds-v2-token" {
				t.Fatalf("unexpected credential request: %s %s %#v", request.Method, request.URL, request.Header)
			}
			return response(200, `{"Code":"Success","AccessKeyId":"STS.TEST","AccessKeySecret":"temporary-secret","SecurityToken":"temporary-security-token","Expiration":"2026-09-13T01:00:00Z","LastUpdated":"2026-09-13T00:00:00Z"}`), nil
		default:
			t.Fatal("unexpected IMDS request")
			return nil, nil
		}
	})}
	provider, err := newTestIMDSv2CredentialProvider(client, "broker-readonly", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	credential, err := provider.Credential(context.Background())
	if err != nil || step != 2 || credential.RoleName != "broker-readonly" || credential.AccessKeyID != "STS.TEST" {
		t.Fatalf("Credential = (%#v, %v), step=%d", credential, err, step)
	}
}

func TestIMDSv2CredentialProviderNeverFallsBack(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodPut {
			t.Fatal("provider attempted a non-IMDSv2 request")
		}
		return response(http.StatusForbidden, "denied"), nil
	})}
	provider, err := newTestIMDSv2CredentialProvider(client, "broker-readonly", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Credential(context.Background()); err == nil || requests != 1 {
		t.Fatalf("Credential err=%v requests=%d", err, requests)
	}
}

func TestIMDSv2CredentialProviderRejectsUnsafeCredentials(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	bodies := []string{
		`{"Code":"Success","AccessKeyId":"STS.TEST","AccessKeySecret":"temporary-secret","SecurityToken":"","Expiration":"2026-09-13T01:00:00Z","LastUpdated":"2026-09-13T00:00:00Z"}`,
		`{"Code":"Success","AccessKeyId":"STS.TEST","AccessKeySecret":"temporary-secret","SecurityToken":"temporary-security-token","Expiration":"2026-09-13T00:00:30Z","LastUpdated":"2026-09-13T00:00:00Z"}`,
		`{"Code":"Success","AccessKeyId":"STS.TEST","AccessKeySecret":"temporary-secret","SecurityToken":"temporary-security-token","Expiration":"2026-09-13T01:00:00Z","LastUpdated":"2026-09-13T00:00:00Z","Unexpected":"field"}`,
		`{"Code":"Success","AccessKeyId":"STS.FIRST","accesskeyid":"STS.OVERRIDE","AccessKeySecret":"temporary-secret","SecurityToken":"temporary-security-token","Expiration":"2026-09-13T01:00:00Z","LastUpdated":"2026-09-13T00:00:00Z"}`,
		`{"Code":"Success","AccessKeyId":"STS.TEST","AccessKeySecret":"temporary-secret","SecurityToken":"temporary-security-token","Expiration":"2026-09-13T01:00:00Z"}`,
		`{"Code":"Success","AccessKeyId":"STS.TEST","AccessKeySecret":"temporary-secret","SecurityToken":"temporary-security-token","Expiration":"2026-09-13T01:00:00Z","LastUpdated":null}`,
		`{"Code":"Success","AccessKeyId":"STS.TEST","AccessKeySecret":"temporary-secret","SecurityToken":"temporary-security-token","Expiration":"2026-09-13T01:00:00Z","LastUpdated":"2026-09-10T00:00:00Z"}`,
	}
	for _, body := range bodies {
		calls := 0
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return response(200, "bound-imds-v2-token"), nil
			}
			return response(200, body), nil
		})}
		provider, err := newTestIMDSv2CredentialProvider(client, "broker-readonly", func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		if _, err = provider.Credential(context.Background()); err == nil {
			t.Fatalf("accepted unsafe credential response: %s", body)
		}
	}
}

func TestNewIMDSv2HTTPClientDisablesRedirectAndProxy(t *testing.T) {
	client, err := newIMDSv2HTTPClient(2 * time.Second)
	if err != nil || client.CheckRedirect == nil {
		t.Fatal("secure IMDS client was not created")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("IMDS client can use a proxy")
	}
	if err = client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v", err)
	}
}

func TestIMDSv2ConstructorsAndNonceRejectInvalidInputs(t *testing.T) {
	if provider, err := NewIMDSv2CredentialProvider("broker-readonly", 2*time.Second); err != nil || provider == nil {
		t.Fatalf("production provider = (%#v, %v)", provider, err)
	}
	if provider, err := NewIMDSv2CredentialProvider("bad role", 2*time.Second); err == nil || provider != nil {
		t.Fatal("accepted invalid role")
	}
	if client, err := newIMDSv2HTTPClient(0); err == nil || client != nil {
		t.Fatal("accepted invalid timeout")
	}
	if provider, err := newTestIMDSv2CredentialProvider(nil, "broker-readonly", time.Now); err == nil || provider != nil {
		t.Fatal("accepted nil test client")
	}
	first, err := randomNonce()
	if err != nil || !noncePattern.MatchString(first) {
		t.Fatalf("random nonce = %q, %v", first, err)
	}
	second, err := randomNonce()
	if err != nil || first == second {
		t.Fatal("random nonce was not unique")
	}
}

func TestIMDSv2RejectsTransportAndResponseFailures(t *testing.T) {
	tests := []struct {
		name string
		run  roundTripFunc
	}{
		{"transport", func(*http.Request) (*http.Response, error) { return nil, errors.New("network") }},
		{"oversized token", func(*http.Request) (*http.Response, error) { return response(200, strings.Repeat("x", 4097)), nil }},
		{"control token", func(*http.Request) (*http.Response, error) { return response(200, "unsafe\ntoken"), nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, err := newTestIMDSv2CredentialProvider(&http.Client{Transport: test.run}, "broker-readonly", time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = provider.Credential(context.Background()); err == nil {
				t.Fatal("accepted failed token exchange")
			}
		})
	}

	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(200, "bound-imds-v2-token"), nil
		}
		return response(http.StatusForbidden, "denied"), nil
	})}
	provider, err := newTestIMDSv2CredentialProvider(client, "broker-readonly", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Credential(context.Background()); err == nil || calls != 2 {
		t.Fatal("accepted denied credential response")
	}
}
