package aliyunsigner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	imdsEndpoint             = "http://100.100.100.200"
	imdsTokenPath            = "/latest/api/token"
	imdsRoleCredentialPrefix = "/latest/meta-data/ram/security-credentials/"
	imdsTokenTTLSeconds      = "21600"
	maxIMDSResponseBytes     = 16 * 1024
	minimumCredentialLife    = time.Minute
	maximumCredentialLife    = 24 * time.Hour
)

var imdsCredentialKeys = []string{
	"Code", "AccessKeyId", "AccessKeySecret", "SecurityToken", "Expiration", "LastUpdated",
}

var ErrWorkloadCredentialUnavailable = errors.New("workload credential unavailable")

type TemporaryCredential struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
	Expiration      time.Time
	RoleName        string
}

type CredentialProvider interface {
	Credential(context.Context) (TemporaryCredential, error)
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// IMDSv2CredentialProvider deliberately has no IMDSv1 or default-credential
// fallback. The fixed link-local endpoint is never read from configuration.
type IMDSv2CredentialProvider struct {
	client   httpDoer
	roleName string
	clock    func() time.Time
}

func NewIMDSv2CredentialProvider(roleName string, timeout time.Duration) (*IMDSv2CredentialProvider, error) {
	client, err := newIMDSv2HTTPClient(timeout)
	if err != nil || !roleNamePattern.MatchString(roleName) {
		return nil, ErrWorkloadCredentialUnavailable
	}
	return &IMDSv2CredentialProvider{client: client, roleName: roleName, clock: time.Now}, nil
}

func newIMDSv2HTTPClient(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 || timeout > 5*time.Second {
		return nil, ErrWorkloadCredentialUnavailable
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DisableKeepAlives:   false,
			MaxIdleConns:        2,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func newTestIMDSv2CredentialProvider(client httpDoer, roleName string, clock func() time.Time) (*IMDSv2CredentialProvider, error) {
	if client == nil || clock == nil || !roleNamePattern.MatchString(roleName) {
		return nil, ErrWorkloadCredentialUnavailable
	}
	return &IMDSv2CredentialProvider{client: client, roleName: roleName, clock: clock}, nil
}

func (provider *IMDSv2CredentialProvider) Credential(ctx context.Context) (TemporaryCredential, error) {
	if provider == nil || provider.client == nil || provider.clock == nil || ctx == nil ||
		!roleNamePattern.MatchString(provider.roleName) {
		return TemporaryCredential{}, ErrWorkloadCredentialUnavailable
	}
	token, err := provider.requestToken(ctx)
	if err != nil {
		return TemporaryCredential{}, ErrWorkloadCredentialUnavailable
	}
	credential, err := provider.requestCredential(ctx, token)
	if err != nil {
		return TemporaryCredential{}, ErrWorkloadCredentialUnavailable
	}
	return credential, nil
}

func (provider *IMDSv2CredentialProvider) requestToken(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, imdsEndpoint+imdsTokenPath, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("X-aliyun-ecs-metadata-token-ttl-seconds", imdsTokenTTLSeconds)
	response, err := provider.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrWorkloadCredentialUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	token := strings.TrimSpace(string(value))
	if err != nil || len(value) > 4096 || len(token) < 8 || len(token) > 4096 || hasControl(token) {
		return "", ErrWorkloadCredentialUnavailable
	}
	return token, nil
}

func (provider *IMDSv2CredentialProvider) requestCredential(ctx context.Context, token string) (TemporaryCredential, error) {
	path := imdsRoleCredentialPrefix + url.PathEscape(provider.roleName)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsEndpoint+path, nil)
	if err != nil {
		return TemporaryCredential{}, err
	}
	request.Header.Set("X-aliyun-ecs-metadata-token", token)
	response, err := provider.client.Do(request)
	if err != nil {
		return TemporaryCredential{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return TemporaryCredential{}, ErrWorkloadCredentialUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, maxIMDSResponseBytes+1))
	if err != nil || len(value) == 0 || len(value) > maxIMDSResponseBytes || rejectDuplicateKeys(value) != nil {
		return TemporaryCredential{}, ErrWorkloadCredentialUnavailable
	}
	var wire struct {
		Code            string `json:"Code"`
		AccessKeyID     string `json:"AccessKeyId"`
		AccessKeySecret string `json:"AccessKeySecret"`
		SecurityToken   string `json:"SecurityToken"`
		Expiration      string `json:"Expiration"`
		LastUpdated     string `json:"LastUpdated"`
	}
	if decodeStrict(value, &wire) != nil || !hasExactObjectKeys(value, imdsCredentialKeys, nil) ||
		wire.Code != "Success" ||
		!safeCredentialPart(wire.AccessKeyID, 3, 256) ||
		!safeCredentialPart(wire.AccessKeySecret, 8, 4096) ||
		!safeCredentialPart(wire.SecurityToken, 8, 8192) {
		return TemporaryCredential{}, ErrWorkloadCredentialUnavailable
	}
	expiration, err := time.Parse(time.RFC3339, wire.Expiration)
	lastUpdated, updatedErr := time.Parse(time.RFC3339, wire.LastUpdated)
	now := provider.clock().UTC()
	if err != nil || updatedErr != nil || lastUpdated.Before(now.Add(-maximumCredentialLife)) ||
		lastUpdated.After(now.Add(MaxClockSkew)) ||
		lastUpdated.After(expiration) || expiration.Before(now.Add(minimumCredentialLife)) ||
		expiration.After(now.Add(maximumCredentialLife)) {
		return TemporaryCredential{}, ErrWorkloadCredentialUnavailable
	}
	return TemporaryCredential{
		AccessKeyID: wire.AccessKeyID, AccessKeySecret: wire.AccessKeySecret,
		SecurityToken: wire.SecurityToken, Expiration: expiration, RoleName: provider.roleName,
	}, nil
}

func safeCredentialPart(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !hasControl(value) && strings.TrimSpace(value) == value
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0
}
