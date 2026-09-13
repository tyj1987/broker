package tencentcredential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	metadataHost              = "metadata.tencentyun.com"
	metadataEndpoint          = "http://metadata.tencentyun.com"
	credentialPathPrefix      = "/latest/meta-data/cam/security-credentials/"
	maxMetadataResponseBytes  = 16 * 1024
	credentialRefreshSkew     = 5 * time.Minute
	credentialRetryDelay      = time.Second
	minimumCredentialLifetime = time.Minute
	maximumCredentialLifetime = 36 * time.Hour
)

var (
	ErrCredentialUnavailable = errors.New("tencent workload credential unavailable")
	roleNamePattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type TemporaryCredential struct {
	SecretID   string
	SecretKey  string
	Token      string
	Expiration time.Time
	RoleName   string
}

type Provider interface {
	Credential(context.Context) (TemporaryCredential, error)
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// CVMRoleProvider reads one explicitly configured CVM CAM role. It does not
// discover roles and never falls back to environment, profile, or static keys.
type CVMRoleProvider struct {
	client         httpDoer
	roleName       string
	clock          func() time.Time
	requestTimeout time.Duration

	mu             sync.Mutex
	credential     TemporaryCredential
	loadedAt       time.Time
	refreshAfter   time.Duration
	retryNotBefore time.Time
	refresh        *credentialRefresh
}

type credentialRefresh struct {
	done chan struct{}
	err  error
}

func NewCVMRoleProvider(roleName string, timeout time.Duration) (*CVMRoleProvider, error) {
	client, err := newMetadataHTTPClient(timeout, net.DefaultResolver, (&net.Dialer{Timeout: timeout}).DialContext)
	if err != nil || !roleNamePattern.MatchString(roleName) {
		return nil, ErrCredentialUnavailable
	}
	return &CVMRoleProvider{client: client, roleName: roleName, clock: time.Now, requestTimeout: timeout}, nil
}

func newTestCVMRoleProvider(client httpDoer, roleName string, clock func() time.Time) (*CVMRoleProvider, error) {
	if client == nil || clock == nil || !roleNamePattern.MatchString(roleName) {
		return nil, ErrCredentialUnavailable
	}
	return &CVMRoleProvider{client: client, roleName: roleName, clock: clock, requestTimeout: 2 * time.Second}, nil
}

func newMetadataHTTPClient(
	timeout time.Duration,
	resolver ipResolver,
	dial func(context.Context, string, string) (net.Conn, error),
) (*http.Client, error) {
	if timeout <= 0 || timeout > 5*time.Second || resolver == nil || dial == nil {
		return nil, ErrCredentialUnavailable
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(metadataHost, "80") {
			return nil, ErrCredentialUnavailable
		}
		addresses, err := resolver.LookupIPAddr(ctx, metadataHost)
		if err != nil || len(addresses) == 0 {
			return nil, ErrCredentialUnavailable
		}
		var selected net.IP
		for _, candidate := range addresses {
			ipv4 := candidate.IP.To4()
			if ipv4 == nil || !ipv4.IsLinkLocalUnicast() {
				return nil, ErrCredentialUnavailable
			}
			if selected == nil {
				selected = append(net.IP(nil), ipv4...)
			}
		}
		return dial(ctx, "tcp4", net.JoinHostPort(selected.String(), "80"))
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func (provider *CVMRoleProvider) Credential(ctx context.Context) (TemporaryCredential, error) {
	if provider == nil || provider.client == nil || provider.clock == nil || ctx == nil ||
		provider.requestTimeout <= 0 || provider.requestTimeout > 5*time.Second ||
		!roleNamePattern.MatchString(provider.roleName) || contextCanceled(ctx) {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}

	provider.mu.Lock()
	now := provider.clock()
	if provider.credentialUsableLocked(now) {
		credential := provider.credential
		provider.mu.Unlock()
		if contextCanceled(ctx) {
			return TemporaryCredential{}, ErrCredentialUnavailable
		}
		return credential, nil
	}
	if provider.refresh == nil && now.UTC().Before(provider.retryNotBefore) {
		provider.mu.Unlock()
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	refresh := provider.refresh
	if refresh == nil {
		refresh = &credentialRefresh{done: make(chan struct{})}
		provider.refresh = refresh
		go provider.runRefresh(refresh)
	}
	provider.mu.Unlock()

	select {
	case <-ctx.Done():
		return TemporaryCredential{}, ErrCredentialUnavailable
	case <-refresh.done:
		return provider.credentialAfterRefresh(ctx, refresh)
	}
}

func (provider *CVMRoleProvider) credentialAfterRefresh(ctx context.Context, refresh *credentialRefresh) (TemporaryCredential, error) {
	if contextCanceled(ctx) || refresh == nil || refresh.err != nil {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	provider.mu.Lock()
	if !provider.credentialUsableLocked(provider.clock()) {
		provider.mu.Unlock()
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	credential := provider.credential
	provider.mu.Unlock()
	if contextCanceled(ctx) {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	return credential, nil
}

func (provider *CVMRoleProvider) runRefresh(refresh *credentialRefresh) {
	ctx, cancel := context.WithTimeout(context.Background(), provider.requestTimeout)
	defer cancel()
	credential, err := provider.requestCredential(ctx)
	if err == nil && contextCanceled(ctx) {
		err = ErrCredentialUnavailable
	}

	provider.mu.Lock()
	if err == nil {
		now := provider.clock()
		refreshAfter := credential.Expiration.UTC().Add(-credentialRefreshSkew).Sub(now.UTC())
		if refreshAfter <= 0 {
			err = ErrCredentialUnavailable
		} else {
			provider.credential = credential
			provider.loadedAt = now
			provider.refreshAfter = refreshAfter
			provider.retryNotBefore = time.Time{}
		}
	}
	if err != nil {
		provider.credential = TemporaryCredential{}
		provider.loadedAt = time.Time{}
		provider.refreshAfter = 0
		provider.retryNotBefore = provider.clock().UTC().Add(credentialRetryDelay)
	}
	refresh.err = err
	provider.refresh = nil
	close(refresh.done)
	provider.mu.Unlock()
}

func (provider *CVMRoleProvider) credentialUsableLocked(now time.Time) bool {
	elapsed := now.Sub(provider.loadedAt)
	return provider.credential.SecretID != "" && provider.refreshAfter > 0 && elapsed >= 0 &&
		elapsed < provider.refreshAfter && now.UTC().Before(provider.credential.Expiration)
}

func (provider *CVMRoleProvider) requestCredential(ctx context.Context) (TemporaryCredential, error) {
	requestURL := metadataEndpoint + credentialPathPrefix + url.PathEscape(provider.roleName)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	response, err := provider.client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(value) == 0 || len(value) > maxMetadataResponseBytes || rejectDuplicateKeys(value) != nil {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	var wire struct {
		SecretID    string      `json:"TmpSecretId"`
		SecretKey   string      `json:"TmpSecretKey"`
		ExpiredTime json.Number `json:"ExpiredTime"`
		Expiration  string      `json:"Expiration"`
		Token       string      `json:"Token"`
		Code        string      `json:"Code"`
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Code != "Success" ||
		!safeCredentialPart(wire.SecretID, 3, 256) || !safeCredentialPart(wire.SecretKey, 8, 4096) ||
		!safeCredentialPart(wire.Token, 8, 8192) {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	expiredUnix, err := strconv.ParseInt(string(wire.ExpiredTime), 10, 64)
	expiration, timeErr := time.Parse(time.RFC3339, wire.Expiration)
	now := provider.clock().UTC()
	if err != nil || timeErr != nil || expiredUnix <= 0 || expiration.Nanosecond() != 0 ||
		wire.Expiration != expiration.UTC().Format(time.RFC3339) || expiration.Unix() != expiredUnix ||
		expiration.Before(now.Add(minimumCredentialLifetime)) ||
		expiration.After(now.Add(maximumCredentialLifetime)) {
		return TemporaryCredential{}, ErrCredentialUnavailable
	}
	return TemporaryCredential{
		SecretID: wire.SecretID, SecretKey: wire.SecretKey, Token: wire.Token,
		Expiration: expiration.UTC(), RoleName: provider.roleName,
	}, nil
}

func rejectDuplicateKeys(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrCredentialUnavailable
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrCredentialUnavailable
			}
			if _, duplicate := keys[key]; duplicate {
				return ErrCredentialUnavailable
			}
			keys[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrCredentialUnavailable
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	expected := json.Delim('}')
	if delimiter == '[' {
		expected = ']'
	}
	if closing != expected {
		return ErrCredentialUnavailable
	}
	return nil
}

func safeCredentialPart(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) < 0
}

func contextCanceled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
