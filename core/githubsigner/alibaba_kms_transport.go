package githubsigner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/tyj1987/broker/core/aliyunsigner"
)

const (
	alibabaKMSAction           = "AsymmetricSign"
	alibabaKMSAPIVersion       = "2016-01-20"
	alibabaSignatureAlgorithm  = "ACS3-HMAC-SHA256"
	alibabaEmptyPayloadSHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	maxAlibabaKMSResponseBytes = 16 * 1024
)

var alibabaVPCDNSServers = [...]string{"100.100.2.136:53", "100.100.2.138:53"}

var ErrAlibabaKMSTransportFailed = errors.New("alibaba kms transport failed")

type alibabaKMSHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// AlibabaKMSClient calls exactly one dedicated-gateway operation using an
// explicitly supplied, short-lived ECS RAM role credential provider.
type AlibabaKMSClient struct {
	credentials aliyunsigner.CredentialProvider
	client      alibabaKMSHTTPDoer
	endpoint    string
	roleName    string
	clock       func() time.Time
	nonce       func() (string, error)
}

func NewAlibabaKMSClient(
	credentials aliyunsigner.CredentialProvider,
	endpoint string,
	roleName string,
	caPEM []byte,
	expectedCASHA256 string,
	allowedCIDRs []netip.Prefix,
	timeout time.Duration,
) (*AlibabaKMSClient, error) {
	if credentials == nil || !kmsDedicatedEndpointPattern.MatchString(endpoint) ||
		!kmsRoleNamePattern.MatchString(roleName) ||
		!publicKeyDigestPattern.MatchString(expectedCASHA256) || timeout <= 0 || timeout > 5*time.Second ||
		!validKMSAllowedCIDRs(allowedCIDRs) {
		return nil, ErrAlibabaKMSTransportFailed
	}
	digest := sha256.Sum256(caPEM)
	if hex.EncodeToString(digest[:]) != expectedCASHA256 {
		return nil, ErrAlibabaKMSTransportFailed
	}
	rootCAs, err := parseExclusiveCARoots(caPEM)
	if err != nil {
		return nil, ErrAlibabaKMSTransportFailed
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	resolver, err := newAlibabaVPCResolver(dialer, timeout/2)
	if err != nil {
		return nil, ErrAlibabaKMSTransportFailed
	}
	dialContext := newPinnedKMSDialContext(endpoint, allowedCIDRs, resolver, dialer)
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 * 1024,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
			ServerName: endpoint,
		},
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return newTestAlibabaKMSClient(credentials, endpoint, roleName, client, time.Now, randomKMSNonce)
}

type kmsResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type kmsDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type alibabaVPCResolver struct {
	dialer         kmsDialer
	attemptTimeout time.Duration
	servers        [2]string
	lookup         func(context.Context, *net.Resolver, string, string) ([]netip.Addr, error)
}

func newAlibabaVPCResolver(dialer kmsDialer, attemptTimeout time.Duration) (*alibabaVPCResolver, error) {
	if dialer == nil || attemptTimeout <= 0 || attemptTimeout > 2500*time.Millisecond {
		return nil, ErrAlibabaKMSTransportFailed
	}
	return &alibabaVPCResolver{
		dialer: dialer, attemptTimeout: attemptTimeout, servers: alibabaVPCDNSServers,
		lookup: func(ctx context.Context, resolver *net.Resolver, network, host string) ([]netip.Addr, error) {
			return resolver.LookupNetIP(ctx, network, host)
		},
	}, nil
}

func (resolver *alibabaVPCResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) ([]netip.Addr, error) {
	if resolver == nil || resolver.dialer == nil || resolver.lookup == nil || ctx == nil ||
		resolver.attemptTimeout <= 0 || resolver.attemptTimeout > 2500*time.Millisecond ||
		network != "ip" || host == "" {
		return nil, ErrAlibabaKMSTransportFailed
	}
	if resolver.servers[0] == "" || resolver.servers[1] == "" || resolver.servers[0] == resolver.servers[1] {
		return nil, ErrAlibabaKMSTransportFailed
	}
	for _, server := range resolver.servers {
		if ctx.Err() != nil {
			return nil, ErrAlibabaKMSTransportFailed
		}
		pinnedServer := server
		attemptContext, cancel := context.WithTimeout(ctx, resolver.attemptTimeout)
		addresses, err := resolver.lookup(attemptContext, &net.Resolver{
			PreferGo: true, StrictErrors: true,
			Dial: func(dialContext context.Context, dialNetwork, _ string) (net.Conn, error) {
				if dialContext == nil ||
					(dialNetwork != "udp" && dialNetwork != "udp4" && dialNetwork != "tcp" && dialNetwork != "tcp4") {
					return nil, ErrAlibabaKMSTransportFailed
				}
				return resolver.dialer.DialContext(dialContext, dialNetwork, pinnedServer)
			},
		}, network, host)
		cancel()
		if err == nil && len(addresses) > 0 {
			return addresses, nil
		}
	}
	return nil, ErrAlibabaKMSTransportFailed
}

func newPinnedKMSDialContext(
	expectedHost string,
	allowedCIDRs []netip.Prefix,
	resolver kmsResolver,
	dialer kmsDialer,
) func(context.Context, string, string) (net.Conn, error) {
	pinned := append([]netip.Prefix(nil), allowedCIDRs...)
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		if ctx == nil || resolver == nil || dialer == nil ||
			(network != "tcp" && network != "tcp4" && network != "tcp6") {
			return nil, ErrAlibabaKMSTransportFailed
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != expectedHost || port != "443" {
			return nil, ErrAlibabaKMSTransportFailed
		}
		addresses, err := resolver.LookupNetIP(ctx, "ip", expectedHost)
		if err != nil || len(addresses) == 0 || len(addresses) > 16 {
			return nil, ErrAlibabaKMSTransportFailed
		}
		for _, candidate := range addresses {
			if !safeKMSNetworkAddress(candidate) || !addressInPrefixes(candidate, pinned) {
				return nil, ErrAlibabaKMSTransportFailed
			}
		}
		var lastError error
		for _, candidate := range addresses {
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			lastError = dialErr
		}
		_ = lastError
		return nil, ErrAlibabaKMSTransportFailed
	}
}

func validKMSAllowedCIDRs(prefixes []netip.Prefix) bool {
	if len(prefixes) < 1 || len(prefixes) > 8 {
		return false
	}
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if prefix != prefix.Masked() || !safeKMSPrefix(prefix) {
			return false
		}
		if _, duplicate := seen[prefix]; duplicate {
			return false
		}
		seen[prefix] = struct{}{}
	}
	return true
}

func safeKMSPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || !safeKMSNetworkAddress(prefix.Addr()) {
		return false
	}
	if prefix.Addr().Is4() {
		return prefix.Bits() >= 24
	}
	return prefix.Bits() >= 64
}

func addressInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func safeKMSNetworkAddress(address netip.Addr) bool {
	return address.IsValid() && address.IsPrivate() && !address.IsUnspecified() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() &&
		!address.IsMulticast()
}

func newTestAlibabaKMSClient(
	credentials aliyunsigner.CredentialProvider,
	endpoint string,
	roleName string,
	client alibabaKMSHTTPDoer,
	clock func() time.Time,
	nonce func() (string, error),
) (*AlibabaKMSClient, error) {
	if credentials == nil || client == nil || clock == nil || nonce == nil ||
		!kmsDedicatedEndpointPattern.MatchString(endpoint) || !kmsRoleNamePattern.MatchString(roleName) {
		return nil, ErrAlibabaKMSTransportFailed
	}
	return &AlibabaKMSClient{
		credentials: credentials, client: client, endpoint: endpoint, roleName: roleName,
		clock: clock, nonce: nonce,
	}, nil
}

func parseExclusiveCARoots(value []byte) (*x509.CertPool, error) {
	if len(value) == 0 || len(value) > maxKMSCACertificateBytes {
		return nil, ErrAlibabaKMSTransportFailed
	}
	pool := x509.NewCertPool()
	rest := value
	count := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrAlibabaKMSTransportFailed
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || count >= 4 {
			return nil, ErrAlibabaKMSTransportFailed
		}
		pool.AddCert(certificate)
		count++
		rest = remaining
	}
	if count == 0 {
		return nil, ErrAlibabaKMSTransportFailed
	}
	return pool, nil
}

func (client *AlibabaKMSClient) SignDigest(ctx context.Context, input KMSDigestInput) (KMSDigestOutput, error) {
	if client == nil || client.credentials == nil || client.client == nil || client.clock == nil ||
		client.nonce == nil || ctx == nil || !kmsKeyIDPattern.MatchString(input.KeyID) ||
		!kmsKeyVersionIDPattern.MatchString(input.KeyVersionID) ||
		input.Algorithm != KMSAlgorithmRSA_PKCS1_SHA_256 || input.MessageType != KMSMessageTypeDigest {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	if ctx.Err() != nil {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	credential, err := client.credentials.Credential(ctx)
	now := client.clock().UTC()
	if err != nil || credential.RoleName != client.roleName ||
		!validKMSTemporaryCredential(credential, now) || ctx.Err() != nil {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	nonce, err := client.nonce()
	if err != nil || !validKMSNonce(nonce) {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	query := url.Values{
		"Algorithm":    {input.Algorithm},
		"Digest":       {base64.StdEncoding.EncodeToString(input.Digest[:])},
		"KeyId":        {input.KeyID},
		"KeyVersionId": {input.KeyVersionID},
	}.Encode()
	date := now.Format("2006-01-02T15:04:05Z")
	headers := []struct{ name, value string }{
		{"host", client.endpoint},
		{"x-acs-action", alibabaKMSAction},
		{"x-acs-content-sha256", alibabaEmptyPayloadSHA256},
		{"x-acs-date", date},
		{"x-acs-security-token", credential.SecurityToken},
		{"x-acs-signature-nonce", nonce},
		{"x-acs-version", alibabaKMSAPIVersion},
	}
	var canonicalHeaders strings.Builder
	signedNames := make([]string, 0, len(headers))
	for _, header := range headers {
		canonicalHeaders.WriteString(header.name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(header.value)
		canonicalHeaders.WriteByte('\n')
		signedNames = append(signedNames, header.name)
	}
	signedHeaders := strings.Join(signedNames, ";")
	canonicalRequest := "POST\n/\n" + query + "\n" + canonicalHeaders.String() + "\n" +
		signedHeaders + "\n" + alibabaEmptyPayloadSHA256
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := alibabaSignatureAlgorithm + "\n" + hex.EncodeToString(canonicalDigest[:])
	mac := hmac.New(sha256.New, []byte(credential.AccessKeySecret))
	_, _ = mac.Write([]byte(stringToSign))
	authorization := alibabaSignatureAlgorithm + " Credential=" + credential.AccessKeyID +
		",SignedHeaders=" + signedHeaders + ",Signature=" + hex.EncodeToString(mac.Sum(nil))

	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "https://"+client.endpoint+"/?"+query, http.NoBody,
	)
	if err != nil {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	request.Host = client.endpoint
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", authorization)
	for _, header := range headers[1:] {
		request.Header.Set(header.name, header.value)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	defer response.Body.Close()
	if ctx.Err() != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" ||
		!isJSONMediaType(response.Header.Get("Content-Type")) {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, maxAlibabaKMSResponseBytes+1))
	if err != nil || ctx.Err() != nil || len(value) == 0 || len(value) > maxAlibabaKMSResponseBytes ||
		rejectDuplicateKeys(value) != nil {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	var wire struct {
		KeyID        string `json:"KeyId"`
		KeyVersionID string `json:"KeyVersionId"`
		Value        string `json:"Value"`
		RequestID    string `json:"RequestId"`
	}
	var object map[string]json.RawMessage
	if decodeStrict(value, &wire) != nil || json.Unmarshal(value, &object) != nil ||
		!exactNonNullKeys(object, "KeyId", "KeyVersionId", "Value", "RequestId") ||
		wire.KeyID != input.KeyID || wire.KeyVersionID != input.KeyVersionID ||
		!safeKMSValue(wire.RequestID, 8, 256) || !safeKMSValue(wire.Value, 16, 8192) {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.Value)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != wire.Value ||
		len(signature) < MinSignatureBytes || len(signature) > MaxSignatureBytes {
		return KMSDigestOutput{}, ErrAlibabaKMSTransportFailed
	}
	return KMSDigestOutput{
		KeyID: input.KeyID, KeyVersionID: input.KeyVersionID,
		Algorithm: input.Algorithm, Signature: append([]byte(nil), signature...),
	}, nil
}

func validKMSTemporaryCredential(credential aliyunsigner.TemporaryCredential, now time.Time) bool {
	return safeKMSValue(credential.AccessKeyID, 3, 256) &&
		safeKMSValue(credential.AccessKeySecret, 8, 4096) &&
		safeKMSValue(credential.SecurityToken, 8, 8192) &&
		credential.Expiration.After(now.Add(time.Minute)) &&
		!credential.Expiration.After(now.Add(24*time.Hour))
}

func safeKMSValue(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) < 0
}

func validKMSNonce(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func randomKMSNonce() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func isJSONMediaType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" {
		return false
	}
	for name, parameter := range parameters {
		if strings.ToLower(name) != "charset" || !strings.EqualFold(parameter, "utf-8") {
			return false
		}
	}
	return true
}
