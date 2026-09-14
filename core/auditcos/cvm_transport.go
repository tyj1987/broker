package auditcos

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	tencentcos "github.com/tencentyun/cos-go-sdk-v5"
	"github.com/tyj1987/broker/core/tencentcredential"
)

const (
	cosEndpointSuffix       = "tencentcos.cn"
	maxCOSRequestTimeout    = 30 * time.Second
	maxCOSWireResponseBytes = AuditObjectMaxBytes + 256*1024
	minimumSigningLifetime  = 30 * time.Second
)

type cosCredentialProvider interface {
	Credential(context.Context) (tencentcredential.TemporaryCredential, error)
}

var cosRoleNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// NewCVMRoleCOSSDKImmutableClient creates a fixed-bucket COS client whose
// requests can be signed only with the explicitly configured CVM CAM role.
// It does not use the COS SDK's role discovery or default credential chain.
func NewCVMRoleCOSSDKImmutableClient(
	bucket, region string,
	provider *tencentcredential.CVMRoleProvider,
	timeout time.Duration,
) (*COSSDKImmutableClient, error) {
	if provider == nil {
		return nil, ErrImmutableSDKRequestRejected
	}
	transport, err := newCOSNetworkTransport(timeout)
	if err != nil {
		return nil, err
	}
	return newCVMRoleCOSSDKImmutableClient(bucket, region, provider, transport, time.Now, timeout)
}

func newCVMRoleCOSSDKImmutableClient(
	bucket, region string,
	provider cosCredentialProvider,
	downstream http.RoundTripper,
	clock func() time.Time,
	timeout time.Duration,
) (*COSSDKImmutableClient, error) {
	host := expectedCOSBucketHost(bucket, region)
	if !validCOSBucketAndRegion(bucket, region) || provider == nil ||
		downstream == nil || clock == nil || timeout <= 0 || timeout > maxCOSRequestTimeout || host == "" {
		return nil, ErrImmutableSDKRequestRejected
	}
	endpoint := &url.URL{Scheme: "https", Host: host}
	authorization := &cvmRoleAuthorizationTransport{
		provider: provider, downstream: downstream, expectedHost: host, clock: clock,
	}
	sdkClient := tencentcos.NewClient(&tencentcos.BaseURL{BucketURL: endpoint}, &http.Client{
		Transport: authorization,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrImmutableSDKRequestRejected
		},
	})
	// Retrying an uncertain immutable write can create an ambiguous result.
	// The mirror state machine owns reconciliation instead of the provider SDK.
	sdkClient.Conf.RetryOpt.Count = 1
	sdkClient.Conf.RetryOpt.Interval = 0
	sdkClient.Conf.RetryOpt.AutoSwitchHost = false
	return NewCOSSDKImmutableClient(bucket, region, sdkClient)
}

func newCOSNetworkTransport(timeout time.Duration) (*http.Transport, error) {
	if timeout <= 0 || timeout > maxCOSRequestTimeout {
		return nil, ErrImmutableSDKRequestRejected
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		MaxConnsPerHost:       2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}, nil
}

type cvmRoleAuthorizationTransport struct {
	provider     cosCredentialProvider
	downstream   http.RoundTripper
	expectedHost string
	clock        func() time.Time
}

func (transport *cvmRoleAuthorizationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !validUnsignedCOSRequest(transport, request) {
		return nil, ErrImmutableSDKRequestRejected
	}
	credential, err := transport.provider.Credential(request.Context())
	if err != nil || request.Context().Err() != nil || !validSigningCredential(credential, transport.clock()) {
		return nil, ErrImmutableSDKUnavailable
	}
	authorizer := &tencentcos.AuthorizationTransport{
		SecretID: credential.SecretID, SecretKey: credential.SecretKey,
		SessionToken: credential.Token, Transport: transport.downstream,
	}
	response, err := authorizer.RoundTrip(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrImmutableSDKUnavailable
	}
	if response == nil || response.Body == nil {
		return nil, ErrImmutableSDKUnavailable
	}
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Cookie2", "Set-Cookie", "X-Cos-Security-Token",
	} {
		response.Header.Del(name)
	}
	response.Body = http.MaxBytesReader(nil, response.Body, maxCOSWireResponseBytes)
	response.Request = sanitizedResponseRequest(response.Request)
	return response, nil
}

func validUnsignedCOSRequest(transport *cvmRoleAuthorizationTransport, request *http.Request) bool {
	if transport == nil || transport.provider == nil || transport.downstream == nil || transport.clock == nil ||
		transport.expectedHost == "" || request == nil || request.Context() == nil || request.Context().Err() != nil ||
		request.URL == nil || request.URL.Scheme != "https" || request.URL.Host != transport.expectedHost ||
		request.URL.Hostname() != transport.expectedHost || request.URL.Port() != "" || request.URL.User != nil ||
		request.URL.Opaque != "" || request.URL.Fragment != "" || request.URL.RawPath != "" || request.URL.ForceQuery ||
		request.RequestURI != "" || request.Close || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 ||
		(request.Host != "" && request.Host != transport.expectedHost) ||
		(request.Method != http.MethodGet && request.Method != http.MethodPut) {
		return false
	}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Cookie2", "Host",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Cos-Security-Token",
	} {
		if len(request.Header.Values(name)) != 0 {
			return false
		}
	}
	return true
}

func validSigningCredential(credential tencentcredential.TemporaryCredential, now time.Time) bool {
	return safeSigningPart(credential.SecretID, 3, 256) && safeSigningPart(credential.SecretKey, 8, 4096) &&
		safeSigningPart(credential.Token, 8, 8192) && cosRoleNamePattern.MatchString(credential.RoleName) &&
		!credential.Expiration.IsZero() && credential.Expiration.Location() == time.UTC &&
		credential.Expiration.After(now.UTC().Add(minimumSigningLifetime)) &&
		!credential.Expiration.After(now.UTC().Add(36*time.Hour))
}

func safeSigningPart(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(character rune) bool { return character < 0x21 || character > 0x7e }) < 0
}

func sanitizedResponseRequest(request *http.Request) *http.Request {
	if request == nil {
		return nil
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Del("Authorization")
	clone.Header.Del("Proxy-Authorization")
	clone.Header.Del("Cookie")
	clone.Header.Del("Cookie2")
	clone.Header.Del("X-Cos-Security-Token")
	clone.Body = nil
	clone.GetBody = nil
	clone.Form = nil
	clone.PostForm = nil
	clone.MultipartForm = nil
	clone.Trailer = nil
	clone.TransferEncoding = nil
	return clone
}

var _ http.RoundTripper = (*cvmRoleAuthorizationTransport)(nil)
