package auditanchor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/aliyunsigner"
)

type kmsCredentialProviderFunc func(context.Context) (aliyunsigner.TemporaryCredential, error)

func (provider kmsCredentialProviderFunc) Credential(ctx context.Context) (aliyunsigner.TemporaryCredential, error) {
	return provider(ctx)
}

type kmsHTTPDoerFunc func(*http.Request) (*http.Response, error)

func (doer kmsHTTPDoerFunc) Do(request *http.Request) (*http.Response, error) { return doer(request) }

type kmsResolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (resolver kmsResolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return resolver(ctx, host)
}

func TestAlibabaKMSHTTPClientBuildsExactAsymmetricSignRequest(t *testing.T) {
	now := time.Date(2026, time.September, 15, 1, 2, 3, 0, time.UTC)
	credential := aliyunsigner.TemporaryCredential{
		AccessKeyID: "temporary-access-id", AccessKeySecret: "temporary-access-secret",
		SecurityToken: "temporary-security-token", Expiration: now.Add(time.Hour), RoleName: "broker-audit-kms",
	}
	digest := sha256.Sum256([]byte("anchor"))
	signature := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	client := newTestAlibabaKMSHTTPClient(
		"kst-example.cryptoservice.kms.aliyuncs.com", "broker-audit-kms",
		kmsCredentialProviderFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) { return credential, nil }),
		kmsHTTPDoerFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPost || request.URL.Scheme != "https" ||
				request.URL.Host != "kst-example.cryptoservice.kms.aliyuncs.com" || request.URL.Path != "/" {
				t.Fatalf("unexpected request target: %s %s", request.Method, request.URL.String())
			}
			query := request.URL.Query()
			if query.Get("KeyId") != "key-123" || query.Get("KeyVersionId") != "version-123" ||
				query.Get("Algorithm") != AlibabaKMSAsymmetricSignAlgorithm ||
				query.Get("Digest") != base64.StdEncoding.EncodeToString(digest[:]) || len(query) != 4 {
				t.Fatalf("unexpected request query: %#v", query)
			}
			for name, expected := range map[string]string{
				"X-Acs-Action": "AsymmetricSign", "X-Acs-Version": "2016-01-20",
				"X-Acs-Date": "2026-09-15T01:02:03Z", "X-Acs-Signature-Nonce": "fixed-nonce",
				"X-Acs-Security-Token": credential.SecurityToken,
			} {
				if request.Header.Get(name) != expected {
					t.Fatalf("unexpected %s", name)
				}
			}
			const expectedAuthorization = "ACS3-HMAC-SHA256 Credential=temporary-access-id," +
				"SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version," +
				"Signature=01b04095e586ca16bd529347c4bd2c267a80858252b9e82e4cf1e4fa0438196b"
			if request.Header.Get("Authorization") != expectedAuthorization ||
				strings.Contains(request.Header.Get("Authorization"), credential.AccessKeySecret) {
				t.Fatalf("authorization header mismatch")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(
				`{"KeyId":"key-123","KeyVersionId":"version-123","Value":"` + base64.StdEncoding.EncodeToString(signature) + `","RequestId":"request-123"}`,
			))}, nil
		}), func() time.Time { return now }, func() (string, error) { return "fixed-nonce", nil },
	)

	response, err := client.Sign(context.Background(), AlibabaKMSSignRequest{
		KeyID: "key-123", KeyVersionID: "version-123", Algorithm: AlibabaKMSAsymmetricSignAlgorithm, Digest: digest[:],
	})
	if err != nil || response.KeyID != "key-123" || response.KeyVersionID != "version-123" || string(response.Signature) != string(signature) {
		t.Fatalf("unexpected response: %#v %v", response, err)
	}
}

func TestAlibabaKMSHTTPTransportAndPinnedSignerEndToEnd(t *testing.T) {
	now := time.Date(2026, time.September, 15, 1, 2, 3, 0, time.UTC)
	key := testKMSKey(t)
	config := Config{Algorithm: "ecdsa-p256-sha256", KeyID: "kms-audit-key-1", StreamID: "production-audit"}
	request := kmsRequest(config)
	credential := aliyunsigner.TemporaryCredential{
		AccessKeyID: "temporary-access-id", AccessKeySecret: "temporary-access-secret",
		SecurityToken: "temporary-security-token", Expiration: now.Add(time.Hour), RoleName: "broker-audit-kms",
	}
	transport := newTestAlibabaKMSHTTPClient(
		"kst-example.cryptoservice.kms.aliyuncs.com", credential.RoleName,
		kmsCredentialProviderFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) { return credential, nil }),
		kmsHTTPDoerFunc(func(httpRequest *http.Request) (*http.Response, error) {
			digest, err := base64.StdEncoding.DecodeString(httpRequest.URL.Query().Get("Digest"))
			if err != nil || len(digest) != sha256.Size {
				t.Fatal("transport did not encode the exact digest")
			}
			signature, err := ecdsa.SignASN1(rand.Reader, key, digest)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"KeyId":"` + config.KeyID + `","KeyVersionId":"` + testKMSKeyVersionID +
				`","Value":"` + base64.StdEncoding.EncodeToString(signature) + `","RequestId":"request-123"}`
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json;charset=UTF-8"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		}), func() time.Time { return now }, func() (string, error) { return "fixed-nonce", nil },
	)
	signer, err := NewAlibabaKMSSigner(config, testKMSKeyVersionID, &key.PublicKey, transport)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), request)
	if err != nil || !ecdsa.VerifyASN1(&key.PublicKey, request.Digest[:], signature) {
		t.Fatalf("end-to-end KMS signature failed: %v", err)
	}
}

func TestNewAlibabaKMSHTTPClientPinsPrivateGatewayAndCA(t *testing.T) {
	caPEM, caDigest := testKMSCAPEM(t)
	config, err := ParseSignerServiceConfig(strings.NewReader(validSignerServiceConfigJSON(t)))
	if err != nil {
		t.Fatal(err)
	}
	config.KMSCASHA256 = caDigest
	credentialProvider, err := aliyunsigner.NewIMDSv2CredentialProvider(config.ECSRAMRoleName, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewAlibabaKMSHTTPClient(config, credentialProvider, caPEM, 2*time.Second)
	if err != nil || client == nil {
		t.Fatalf("construct KMS client: %v", err)
	}
	httpClient, ok := client.client.(*http.Client)
	if !ok || httpClient.CheckRedirect == nil || httpClient.Timeout != 2*time.Second {
		t.Fatal("KMS HTTP policy is incomplete")
	}
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 ||
		transport.TLSClientConfig.ServerName != config.KMSEndpoint || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("KMS TLS or proxy policy is incomplete")
	}
	redirectRequest, _ := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	if err := httpClient.CheckRedirect(redirectRequest, nil); err != http.ErrUseLastResponse {
		t.Fatal("KMS redirects are not disabled")
	}

	badHash := config
	badHash.KMSCASHA256 = strings.Repeat("b", 64)
	for name, attempt := range map[string]func() (*AlibabaKMSHTTPClient, error){
		"wrong CA pin": func() (*AlibabaKMSHTTPClient, error) {
			return NewAlibabaKMSHTTPClient(badHash, credentialProvider, caPEM, 2*time.Second)
		},
		"multiple certificates": func() (*AlibabaKMSHTTPClient, error) {
			return NewAlibabaKMSHTTPClient(config, credentialProvider, append(append([]byte(nil), caPEM...), caPEM...), 2*time.Second)
		},
		"missing credentials": func() (*AlibabaKMSHTTPClient, error) {
			return NewAlibabaKMSHTTPClient(config, nil, caPEM, 2*time.Second)
		},
		"unsafe timeout": func() (*AlibabaKMSHTTPClient, error) {
			return NewAlibabaKMSHTTPClient(config, credentialProvider, caPEM, 30*time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if value, err := attempt(); err == nil || value != nil {
				t.Fatal("expected constructor rejection")
			}
		})
	}
}

func TestAlibabaKMSHTTPTransportPinsEveryResolvedAddress(t *testing.T) {
	caPEM, caDigest := testKMSCAPEM(t)
	allowed := []netip.Prefix{netip.MustParsePrefix("10.42.7.0/24")}
	resolver := kmsResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.42.7.8")}}, nil
	})
	var dialed string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = network + " " + address
		return nil, io.EOF
	}
	httpClient, err := newAlibabaKMSHTTPTransport("kst-example.cryptoservice.kms.aliyuncs.com", caPEM, caDigest, allowed, 2*time.Second, resolver, dial)
	if err != nil {
		t.Fatal(err)
	}
	transport := httpClient.Transport.(*http.Transport)
	_, _ = transport.DialContext(context.Background(), "tcp", "kst-example.cryptoservice.kms.aliyuncs.com:443")
	if dialed != "tcp4 10.42.7.8:443" {
		t.Fatalf("unexpected pinned dial target: %q", dialed)
	}

	unsafeResolver := kmsResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.42.7.8")}, {IP: net.ParseIP("203.0.113.7")}}, nil
	})
	unsafeClient, err := newAlibabaKMSHTTPTransport("kst-example.cryptoservice.kms.aliyuncs.com", caPEM, caDigest, allowed, 2*time.Second, unsafeResolver, dial)
	if err != nil {
		t.Fatal(err)
	}
	if connection, err := unsafeClient.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "kst-example.cryptoservice.kms.aliyuncs.com:443"); err == nil || connection != nil {
		t.Fatal("mixed safe and unsafe DNS answers must fail closed")
	}
}

func testKMSCAPEM(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test KMS CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(digest[:])
}

func TestAlibabaKMSHTTPClientFailsClosed(t *testing.T) {
	now := time.Date(2026, time.September, 15, 1, 2, 3, 0, time.UTC)
	validCredential := aliyunsigner.TemporaryCredential{
		AccessKeyID: "temporary-access-id", AccessKeySecret: "temporary-access-secret",
		SecurityToken: "temporary-security-token", Expiration: now.Add(time.Hour), RoleName: "broker-audit-kms",
	}
	validRequest := AlibabaKMSSignRequest{KeyID: "key-123", KeyVersionID: "version-123", Algorithm: AlibabaKMSAsymmetricSignAlgorithm, Digest: make([]byte, sha256.Size)}
	validRequest.Digest[0] = 1

	tests := []struct {
		name       string
		credential aliyunsigner.TemporaryCredential
		status     int
		body       string
		request    AlibabaKMSSignRequest
	}{
		{name: "wrong role", credential: func() aliyunsigner.TemporaryCredential {
			value := validCredential
			value.RoleName = "other-role"
			return value
		}(), status: 200, body: `{}`, request: validRequest},
		{name: "expired credential", credential: func() aliyunsigner.TemporaryCredential {
			value := validCredential
			value.Expiration = now
			return value
		}(), status: 200, body: `{}`, request: validRequest},
		{name: "wrong algorithm", credential: validCredential, status: 200, body: `{}`, request: func() AlibabaKMSSignRequest { value := validRequest; value.Algorithm = "RSA_PSS_SHA_256"; return value }()},
		{name: "bad status", credential: validCredential, status: 403, body: `{"Code":"Forbidden"}`, request: validRequest},
		{name: "unknown response field", credential: validCredential, status: 200, body: `{"KeyId":"key-123","KeyVersionId":"version-123","Value":"MA==","RequestId":"request-123","Credential":"forbidden"}`, request: validRequest},
		{name: "duplicate response field", credential: validCredential, status: 200, body: `{"KeyId":"key-123","KeyId":"key-123","KeyVersionId":"version-123","Value":"MA==","RequestId":"request-123"}`, request: validRequest},
		{name: "oversized response", credential: validCredential, status: 200, body: strings.Repeat("x", MaxAlibabaKMSResponseBytes+1), request: validRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			client := newTestAlibabaKMSHTTPClient(
				"kst-example.cryptoservice.kms.aliyuncs.com", "broker-audit-kms",
				kmsCredentialProviderFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) { return test.credential, nil }),
				kmsHTTPDoerFunc(func(*http.Request) (*http.Response, error) {
					called = true
					return &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
				}), func() time.Time { return now }, func() (string, error) { return "fixed-nonce", nil },
			)
			if _, err := client.Sign(context.Background(), test.request); err == nil {
				t.Fatal("expected fail-closed rejection")
			}
			if (test.name == "wrong role" || test.name == "expired credential" || test.name == "wrong algorithm") && called {
				t.Fatal("invalid input reached the KMS transport")
			}
		})
	}
}
