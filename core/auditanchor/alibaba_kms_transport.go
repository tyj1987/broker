package auditanchor

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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tyj1987/broker/core/aliyunsigner"
)

const (
	MaxAlibabaKMSResponseBytes = 16 * 1024
	alibabaKMSAction           = "AsymmetricSign"
	alibabaKMSAPIVersion       = "2016-01-20"
	alibabaSignatureAlgorithm  = "ACS3-HMAC-SHA256"
	alibabaEmptyPayloadHash    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var (
	ErrAlibabaKMSTransportUnavailable = errors.New("Alibaba KMS transport unavailable")
	alibabaKMSNoncePattern            = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
	alibabaKMSResponseKeys            = []string{"KeyId", "KeyVersionId", "Value", "RequestId"}
)

type alibabaKMSHTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type alibabaKMSIPResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// AlibabaKMSHTTPClient sends only the fixed AsymmetricSign operation. It uses
// short-lived ECS RAM role credentials and never accepts caller-controlled
// methods, paths, headers or endpoints.
type AlibabaKMSHTTPClient struct {
	endpoint    string
	roleName    string
	credentials aliyunsigner.CredentialProvider
	client      alibabaKMSHTTPDoer
	clock       func() time.Time
	nonce       func() (string, error)
}

// NewAlibabaKMSHTTPClient creates a dedicated-gateway client with a single
// pinned instance CA and address-constrained DNS resolution. The caller must
// supply an ECS IMDSv2 role provider; no default or static credential chain is
// consulted.
func NewAlibabaKMSHTTPClient(
	config SignerServiceConfig,
	credentials *aliyunsigner.IMDSv2CredentialProvider,
	caPEM []byte,
	timeout time.Duration,
) (*AlibabaKMSHTTPClient, error) {
	validated, err := ValidateSignerServiceConfig(config)
	if err != nil || credentials == nil {
		return nil, ErrAlibabaKMSTransportUnavailable
	}
	client, err := newAlibabaKMSHTTPTransport(
		validated.KMSEndpoint, caPEM, validated.KMSCASHA256, validated.KMSAllowedCIDRs,
		timeout, net.DefaultResolver, (&net.Dialer{Timeout: timeout}).DialContext,
	)
	if err != nil {
		return nil, ErrAlibabaKMSTransportUnavailable
	}
	return &AlibabaKMSHTTPClient{
		endpoint: validated.KMSEndpoint, roleName: validated.ECSRAMRoleName,
		credentials: credentials, client: client, clock: time.Now, nonce: randomAlibabaKMSNonce,
	}, nil
}

func newAlibabaKMSHTTPTransport(
	endpoint string,
	caPEM []byte,
	caSHA256 string,
	allowedCIDRs []netip.Prefix,
	timeout time.Duration,
	resolver alibabaKMSIPResolver,
	dial func(context.Context, string, string) (net.Conn, error),
) (*http.Client, error) {
	if !signerKMSEndpointPattern.MatchString(endpoint) || !signerDigestPattern.MatchString(caSHA256) ||
		len(allowedCIDRs) < 1 || len(allowedCIDRs) > 8 || timeout <= 0 || timeout > 5*time.Second ||
		resolver == nil || dial == nil {
		return nil, ErrAlibabaKMSTransportUnavailable
	}
	for _, prefix := range allowedCIDRs {
		if prefix != prefix.Masked() || !safeSignerKMSPrefix(prefix) {
			return nil, ErrAlibabaKMSTransportUnavailable
		}
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > 16*1024 {
		return nil, ErrAlibabaKMSTransportUnavailable
	}
	certificateDER := append([]byte(nil), block.Bytes...)
	certificate, err := x509.ParseCertificate(certificateDER)
	digest := sha256.Sum256(certificateDER)
	if err != nil || certificate == nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
		hex.EncodeToString(digest[:]) != caSHA256 {
		return nil, ErrAlibabaKMSTransportUnavailable
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: endpoint, RootCAs: roots,
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, TLSClientConfig: tlsConfig,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2,
		IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: timeout,
		ResponseHeaderTimeout: timeout, ExpectContinueTimeout: time.Second,
		MaxResponseHeaderBytes: 16 * 1024,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(endpoint, "443") {
			return nil, ErrAlibabaKMSTransportUnavailable
		}
		addresses, err := resolver.LookupIPAddr(ctx, endpoint)
		if err != nil || len(addresses) == 0 || len(addresses) > 8 {
			return nil, ErrAlibabaKMSTransportUnavailable
		}
		var selected netip.Addr
		for _, candidate := range addresses {
			parsed, ok := netip.AddrFromSlice(candidate.IP)
			parsed = parsed.Unmap()
			if !ok || candidate.Zone != "" || !addressAllowedByPrefixes(parsed, allowedCIDRs) {
				return nil, ErrAlibabaKMSTransportUnavailable
			}
			if !selected.IsValid() {
				selected = parsed
			}
		}
		dialNetwork := "tcp6"
		if selected.Is4() {
			dialNetwork = "tcp4"
		}
		return dial(ctx, dialNetwork, net.JoinHostPort(selected.String(), "443"))
	}
	return &http.Client{
		Timeout: timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func addressAllowedByPrefixes(address netip.Addr, allowed []netip.Prefix) bool {
	if !address.IsValid() || !safeSignerKMSAddress(address) {
		return false
	}
	for _, prefix := range allowed {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func newTestAlibabaKMSHTTPClient(
	endpoint string,
	roleName string,
	credentials aliyunsigner.CredentialProvider,
	client alibabaKMSHTTPDoer,
	clock func() time.Time,
	nonce func() (string, error),
) *AlibabaKMSHTTPClient {
	return &AlibabaKMSHTTPClient{
		endpoint: endpoint, roleName: roleName, credentials: credentials,
		client: client, clock: clock, nonce: nonce,
	}
}

func (client *AlibabaKMSHTTPClient) Sign(ctx context.Context, input AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error) {
	if client == nil || ctx == nil || client.credentials == nil || client.client == nil ||
		client.clock == nil || client.nonce == nil ||
		!signerKMSEndpointPattern.MatchString(client.endpoint) ||
		!signerRoleNamePattern.MatchString(client.roleName) || !validAlibabaKMSSignInput(input) {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	if ctx.Err() != nil {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}

	now := client.clock().UTC()
	credential, err := client.credentials.Credential(ctx)
	if err != nil || !validAlibabaTemporaryCredential(credential, client.roleName, now) {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	nonce, err := client.nonce()
	if err != nil || !alibabaKMSNoncePattern.MatchString(nonce) {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}

	query := url.Values{}
	query.Set("Algorithm", input.Algorithm)
	query.Set("Digest", base64.StdEncoding.EncodeToString(input.Digest))
	query.Set("KeyId", input.KeyID)
	query.Set("KeyVersionId", input.KeyVersionID)
	encodedQuery := query.Encode()
	date := now.Format("2006-01-02T15:04:05Z")
	headers := []struct{ name, value string }{
		{"host", client.endpoint},
		{"x-acs-action", alibabaKMSAction},
		{"x-acs-content-sha256", alibabaEmptyPayloadHash},
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
	canonicalRequest := "POST\n/\n" + encodedQuery + "\n" + canonicalHeaders.String() + "\n" +
		signedHeaders + "\n" + alibabaEmptyPayloadHash
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := alibabaSignatureAlgorithm + "\n" + hex.EncodeToString(canonicalDigest[:])
	mac := hmac.New(sha256.New, []byte(credential.AccessKeySecret))
	_, _ = mac.Write([]byte(stringToSign))
	authorization := alibabaSignatureAlgorithm + " Credential=" + credential.AccessKeyID +
		",SignedHeaders=" + signedHeaders + ",Signature=" + hex.EncodeToString(mac.Sum(nil))

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+client.endpoint+"/?"+encodedQuery, nil)
	if err != nil {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	request.Host = client.endpoint
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", authorization)
	for _, header := range headers[1:] {
		request.Header.Set(header.name, header.value)
	}
	response, err := client.client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	if response.StatusCode != http.StatusOK || !validJSONContentType(response.Header.Get("Content-Type")) {
		_ = response.Body.Close()
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, MaxAlibabaKMSResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(value) == 0 || len(value) > MaxAlibabaKMSResponseBytes {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	var wire struct {
		KeyID        string `json:"KeyId"`
		KeyVersionID string `json:"KeyVersionId"`
		Value        string `json:"Value"`
		RequestID    string `json:"RequestId"`
	}
	if decodeExactObject(value, &wire, alibabaKMSResponseKeys) != nil ||
		wire.KeyID != input.KeyID || wire.KeyVersionID != input.KeyVersionID ||
		!safeAlibabaField(wire.RequestID, 1, 256) {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.Value)
	if err != nil || len(signature) < 8 || len(signature) > 80 ||
		base64.StdEncoding.EncodeToString(signature) != wire.Value {
		return AlibabaKMSSignResponse{}, ErrAlibabaKMSTransportUnavailable
	}
	return AlibabaKMSSignResponse{
		KeyID: wire.KeyID, KeyVersionID: wire.KeyVersionID, Signature: append([]byte(nil), signature...),
	}, nil
}

func validAlibabaKMSSignInput(input AlibabaKMSSignRequest) bool {
	return signerKeyIDPattern.MatchString(input.KeyID) && kmsKeyVersionPattern.MatchString(input.KeyVersionID) &&
		input.Algorithm == AlibabaKMSAsymmetricSignAlgorithm && len(input.Digest) == sha256.Size
}

func validAlibabaTemporaryCredential(credential aliyunsigner.TemporaryCredential, roleName string, now time.Time) bool {
	return credential.RoleName == roleName &&
		safeAlibabaField(credential.AccessKeyID, 3, 256) &&
		safeAlibabaField(credential.AccessKeySecret, 8, 4096) &&
		safeAlibabaField(credential.SecurityToken, 8, 8192) &&
		credential.Expiration.After(now.Add(time.Minute)) && !credential.Expiration.After(now.Add(24*time.Hour))
}

func safeAlibabaField(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) < 0
}

func validJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || strings.ToLower(mediaType) != "application/json" || len(parameters) > 1 {
		return false
	}
	charset, present := parameters["charset"]
	return !present || strings.EqualFold(charset, "utf-8")
}

func randomAlibabaKMSNonce() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
