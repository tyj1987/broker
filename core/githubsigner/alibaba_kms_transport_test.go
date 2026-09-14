package githubsigner

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tyj1987/broker/core/aliyunsigner"
)

const testKMSEndpoint = "kst-example123.cryptoservice.kms.aliyuncs.com"

type kmsCredentialFunc func(context.Context) (aliyunsigner.TemporaryCredential, error)

func (function kmsCredentialFunc) Credential(ctx context.Context) (aliyunsigner.TemporaryCredential, error) {
	return function(ctx)
}

type kmsHTTPDoerFunc func(*http.Request) (*http.Response, error)

func (function kmsHTTPDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testKMSCredential(now time.Time) aliyunsigner.TemporaryCredential {
	return aliyunsigner.TemporaryCredential{
		AccessKeyID: "STS.TEST", AccessKeySecret: "test-secret-value",
		SecurityToken: "test-security-token", Expiration: now.Add(time.Hour), RoleName: "broker-github-kms",
	}
}

func testKMSInput() KMSDigestInput {
	var digest [32]byte
	for index := range digest {
		digest[index] = []byte{0xfb, 0xef, 0xff}[index%3]
	}
	return KMSDigestInput{
		KeyID: "key-example", KeyVersionID: "version-1",
		Algorithm: KMSAlgorithmRSA_PKCS1_SHA_256, MessageType: KMSMessageTypeDigest, Digest: digest,
	}
}

func testKMSResponse(input KMSDigestInput) string {
	return string(mustJSON(map[string]string{
		"KeyId": input.KeyID, "KeyVersionId": input.KeyVersionID,
		"Value":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 256)),
		"RequestId": "475f1620-b9d3-4d35-b5c6-3fbdd941423d",
	}))
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func TestAlibabaKMSClientSendsExactSignedRequest(t *testing.T) {
	now := time.Date(2026, time.September, 13, 1, 2, 3, 0, time.UTC)
	credential := testKMSCredential(now)
	input := testKMSInput()
	const nonce = "00112233-4455-4677-8899-aabbccddeeff"
	provider := kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) {
		return credential, nil
	})
	doer := kmsHTTPDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Scheme != "https" ||
			request.URL.Host != testKMSEndpoint || request.URL.Path != "/" || request.Host != testKMSEndpoint {
			t.Fatalf("unexpected target: %s %s host=%q", request.Method, request.URL.String(), request.Host)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || len(body) != 0 {
			t.Fatalf("body = %q, err=%v", body, err)
		}
		encodedDigest := base64.StdEncoding.EncodeToString(input.Digest[:])
		expectedQuery := url.Values{
			"Algorithm": {input.Algorithm}, "Digest": {encodedDigest},
			"KeyId": {input.KeyID}, "KeyVersionId": {input.KeyVersionID},
		}.Encode()
		if request.URL.RawQuery != expectedQuery || !strings.Contains(expectedQuery, "%2B") ||
			!strings.Contains(expectedQuery, "%2F") || !strings.Contains(expectedQuery, "%3D") {
			t.Fatalf("query = %q", request.URL.RawQuery)
		}
		if request.Header.Get("x-acs-action") != alibabaKMSAction ||
			request.Header.Get("x-acs-version") != alibabaKMSAPIVersion ||
			request.Header.Get("x-acs-content-sha256") != alibabaEmptyPayloadSHA256 ||
			request.Header.Get("x-acs-security-token") != credential.SecurityToken ||
			request.Header.Get("x-acs-signature-nonce") != nonce ||
			request.Header.Get("x-acs-date") != "2026-09-13T01:02:03Z" {
			t.Fatalf("unexpected signed headers: %#v", request.Header)
		}
		expectedAuthorization := expectedKMSAuthorization(credential, request.URL.RawQuery, nonce, now)
		if request.Header.Get("Authorization") != expectedAuthorization ||
			!strings.Contains(expectedAuthorization, "x-acs-security-token") {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader(testKMSResponse(input))),
		}, nil
	})
	client, err := newTestAlibabaKMSClient(provider, testKMSEndpoint, credential.RoleName, doer, func() time.Time { return now }, func() (string, error) { return nonce, nil })
	if err != nil {
		t.Fatal(err)
	}
	output, err := client.SignDigest(context.Background(), input)
	if err != nil || output.KeyID != input.KeyID || output.KeyVersionID != input.KeyVersionID ||
		output.Algorithm != input.Algorithm || len(output.Signature) != 256 {
		t.Fatalf("output=%#v err=%v", output, err)
	}
}

func expectedKMSAuthorization(credential aliyunsigner.TemporaryCredential, query, nonce string, now time.Time) string {
	signedHeaders := "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version"
	canonicalHeaders := "host:" + testKMSEndpoint + "\n" +
		"x-acs-action:" + alibabaKMSAction + "\n" +
		"x-acs-content-sha256:" + alibabaEmptyPayloadSHA256 + "\n" +
		"x-acs-date:" + now.Format("2006-01-02T15:04:05Z") + "\n" +
		"x-acs-security-token:" + credential.SecurityToken + "\n" +
		"x-acs-signature-nonce:" + nonce + "\n" +
		"x-acs-version:" + alibabaKMSAPIVersion + "\n"
	canonical := "POST\n/\n" + query + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + alibabaEmptyPayloadSHA256
	digest := sha256.Sum256([]byte(canonical))
	mac := hmac.New(sha256.New, []byte(credential.AccessKeySecret))
	_, _ = mac.Write([]byte(alibabaSignatureAlgorithm + "\n" + hex.EncodeToString(digest[:])))
	return alibabaSignatureAlgorithm + " Credential=" + credential.AccessKeyID +
		",SignedHeaders=" + signedHeaders + ",Signature=" + hex.EncodeToString(mac.Sum(nil))
}

func TestAlibabaKMSClientFailsClosedOnCredentialAndContext(t *testing.T) {
	now := time.Date(2026, 9, 13, 1, 2, 3, 0, time.UTC)
	valid := testKMSCredential(now)
	cases := map[string]func(*aliyunsigner.TemporaryCredential, context.CancelFunc) error{
		"provider error": func(*aliyunsigner.TemporaryCredential, context.CancelFunc) error { return errors.New("canary-secret") },
		"wrong role": func(value *aliyunsigner.TemporaryCredential, _ context.CancelFunc) error {
			value.RoleName = "other"
			return nil
		},
		"expired": func(value *aliyunsigner.TemporaryCredential, _ context.CancelFunc) error {
			value.Expiration = now
			return nil
		},
		"too long": func(value *aliyunsigner.TemporaryCredential, _ context.CancelFunc) error {
			value.Expiration = now.Add(25 * time.Hour)
			return nil
		},
		"missing token": func(value *aliyunsigner.TemporaryCredential, _ context.CancelFunc) error {
			value.SecurityToken = ""
			return nil
		},
		"cancel after provider": func(_ *aliyunsigner.TemporaryCredential, cancel context.CancelFunc) error { cancel(); return nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			provider := kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) {
				credential := valid
				return credential, edit(&credential, cancel)
			})
			client, err := newTestAlibabaKMSClient(provider, testKMSEndpoint, valid.RoleName,
				kmsHTTPDoerFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errors.New("unexpected") }),
				func() time.Time { return now }, func() (string, error) { return "00112233-4455-4677-8899-aabbccddeeff", nil })
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.SignDigest(ctx, testKMSInput())
			if !errors.Is(err, ErrAlibabaKMSTransportFailed) || called || strings.Contains(err.Error(), "canary") {
				t.Fatalf("err=%v called=%v", err, called)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	providerCalled := false
	client, _ := newTestAlibabaKMSClient(kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) {
		providerCalled = true
		return valid, nil
	}), testKMSEndpoint, valid.RoleName, kmsHTTPDoerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unused")
	}), func() time.Time { return now }, func() (string, error) { return "00112233-4455-4677-8899-aabbccddeeff", nil })
	if _, err := client.SignDigest(ctx, testKMSInput()); !errors.Is(err, ErrAlibabaKMSTransportFailed) || providerCalled {
		t.Fatalf("cancelled request err=%v providerCalled=%v", err, providerCalled)
	}
}

func TestAlibabaKMSClientRejectsResponseDrift(t *testing.T) {
	now := time.Date(2026, 9, 13, 1, 2, 3, 0, time.UTC)
	input := testKMSInput()
	valid := testKMSCredential(now)
	validBody := testKMSResponse(input)
	tests := map[string]struct {
		status      int
		contentType string
		encoding    string
		body        string
	}{
		"status":        {http.StatusForbidden, "application/json", "", validBody},
		"type":          {http.StatusOK, "text/plain", "", validBody},
		"encoding":      {http.StatusOK, "application/json", "gzip", validBody},
		"wrong key":     {http.StatusOK, "application/json", "", strings.Replace(validBody, input.KeyID, "key-other", 1)},
		"wrong version": {http.StatusOK, "application/json", "", strings.Replace(validBody, input.KeyVersionID, "version-2", 1)},
		"duplicate":     {http.StatusOK, "application/json", "", strings.Replace(validBody, `"KeyId":`, `"KeyId":"key-example","KeyId":`, 1)},
		"case alias":    {http.StatusOK, "application/json", "", strings.Replace(validBody, `"KeyId":`, `"keyid":"key-example","KeyId":`, 1)},
		"null":          {http.StatusOK, "application/json", "", strings.Replace(validBody, `"RequestId":"475f1620-b9d3-4d35-b5c6-3fbdd941423d"`, `"RequestId":null`, 1)},
		"unknown":       {http.StatusOK, "application/json", "", strings.Replace(validBody, "}", `,"Secret":"canary"}`, 1)},
		"bad base64":    {http.StatusOK, "application/json", "", strings.Replace(validBody, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 256)), "not-base64", 1)},
		"oversized":     {http.StatusOK, "application/json", "", strings.Repeat("x", maxAlibabaKMSResponseBytes+1)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := newTestAlibabaKMSClient(
				kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) { return valid, nil }),
				testKMSEndpoint, valid.RoleName,
				kmsHTTPDoerFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: test.status, Header: http.Header{
						"Content-Type": {test.contentType}, "Content-Encoding": {test.encoding},
					}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
				}), func() time.Time { return now }, func() (string, error) { return "00112233-4455-4677-8899-aabbccddeeff", nil },
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = client.SignDigest(context.Background(), input); !errors.Is(err, ErrAlibabaKMSTransportFailed) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

type cancellingReadCloser struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (reader *cancellingReadCloser) Read(value []byte) (int, error) {
	reader.cancel()
	return reader.reader.Read(value)
}

func (*cancellingReadCloser) Close() error { return nil }

func TestAlibabaKMSClientRejectsCancellationWhileReadingResponse(t *testing.T) {
	now := time.Now().UTC()
	credential := testKMSCredential(now)
	ctx, cancel := context.WithCancel(context.Background())
	client, err := newTestAlibabaKMSClient(
		kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) { return credential, nil }),
		testKMSEndpoint, credential.RoleName,
		kmsHTTPDoerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
				Body: &cancellingReadCloser{reader: strings.NewReader(testKMSResponse(testKMSInput())), cancel: cancel},
			}, nil
		}), func() time.Time { return now }, func() (string, error) { return "00112233-4455-4677-8899-aabbccddeeff", nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.SignDigest(ctx, testKMSInput()); !errors.Is(err, ErrAlibabaKMSTransportFailed) {
		t.Fatalf("err=%v", err)
	}
}

func TestAlibabaKMSClientRejectsInvalidInputAndTransport(t *testing.T) {
	now := time.Now().UTC()
	valid := testKMSCredential(now)
	called := false
	client, err := newTestAlibabaKMSClient(
		kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) { return valid, nil }),
		testKMSEndpoint, valid.RoleName,
		kmsHTTPDoerFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, errors.New("canary-secret") }),
		func() time.Time { return now }, func() (string, error) { return "bad", nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.SignDigest(context.Background(), testKMSInput()); !errors.Is(err, ErrAlibabaKMSTransportFailed) || called {
		t.Fatalf("bad nonce err=%v called=%v", err, called)
	}
	input := testKMSInput()
	input.Algorithm = "RSA_PSS_SHA_256"
	if _, err = client.SignDigest(context.Background(), input); !errors.Is(err, ErrAlibabaKMSTransportFailed) {
		t.Fatalf("bad input err=%v", err)
	}
}

type fakeKMSResolver struct {
	addresses []netip.Addr
	err       error
}

func (resolver fakeKMSResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return resolver.addresses, resolver.err
}

type fakeKMSDialer struct {
	addresses []string
	err       error
}

func TestAlibabaVPCResolverUsesOnlyFixedDNSServers(t *testing.T) {
	if resolver, err := newAlibabaVPCResolver(nil, time.Second); err == nil || resolver != nil {
		t.Fatal("accepted nil DNS dialer")
	}
	if resolver, err := newAlibabaVPCResolver(&fakeKMSDialer{}, 3*time.Second); err == nil || resolver != nil {
		t.Fatal("accepted excessive DNS attempt timeout")
	}
	dialer := &fakeKMSDialer{}
	resolver, err := newAlibabaVPCResolver(dialer, 20*time.Millisecond)
	if err != nil || resolver == nil {
		t.Fatalf("resolver=%#v err=%v", resolver, err)
	}
	attempts := 0
	resolver.lookup = func(ctx context.Context, pinned *net.Resolver, network, host string) ([]netip.Addr, error) {
		attempts++
		connection, dialErr := pinned.Dial(ctx, "udp", "attacker.example:53")
		if dialErr != nil {
			return nil, dialErr
		}
		_ = connection.Close()
		if attempts == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if network != "ip" || host != testKMSEndpoint {
			t.Fatalf("lookup network=%q host=%q", network, host)
		}
		return []netip.Addr{netip.MustParseAddr("10.20.0.4")}, nil
	}
	addresses, err := resolver.LookupNetIP(context.Background(), "ip", testKMSEndpoint)
	if err != nil || len(addresses) != 1 || addresses[0].String() != "10.20.0.4" || attempts != 2 {
		t.Fatalf("addresses=%v attempts=%d err=%v", addresses, attempts, err)
	}
	if len(dialer.addresses) != 2 || dialer.addresses[0] != alibabaVPCDNSServers[0] ||
		dialer.addresses[1] != alibabaVPCDNSServers[1] {
		t.Fatalf("DNS targets=%v", dialer.addresses)
	}
	if addresses, err = resolver.LookupNetIP(context.Background(), "tcp", testKMSEndpoint); !errors.Is(err, ErrAlibabaKMSTransportFailed) || addresses != nil {
		t.Fatalf("invalid lookup addresses=%v err=%v", addresses, err)
	}
}

func TestAlibabaVPCResolverFallsBackAfterDNSResponseTimeout(t *testing.T) {
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	responder, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	go serveTestDNS(responder, [4]byte{10, 20, 0, 4})

	resolver, err := newAlibabaVPCResolver(&net.Dialer{}, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	resolver.servers = [2]string{blackhole.LocalAddr().String(), responder.LocalAddr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addresses, err := resolver.LookupNetIP(ctx, "ip", "kms-gateway.test")
	if err != nil || len(addresses) != 1 || addresses[0].String() != "10.20.0.4" {
		t.Fatalf("addresses=%v err=%v", addresses, err)
	}
}

func serveTestDNS(connection net.PacketConn, answer [4]byte) {
	buffer := make([]byte, 512)
	for {
		length, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		query := append([]byte(nil), buffer[:length]...)
		response, ok := testDNSResponse(query, answer)
		if ok {
			_, _ = connection.WriteTo(response, peer)
		}
	}
}

func testDNSResponse(query []byte, answer [4]byte) ([]byte, bool) {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, false
	}
	offset := 12
	for {
		if offset >= len(query) {
			return nil, false
		}
		labelLength := int(query[offset])
		offset++
		if labelLength == 0 {
			break
		}
		if labelLength > 63 || offset+labelLength > len(query) {
			return nil, false
		}
		offset += labelLength
	}
	if offset+4 > len(query) {
		return nil, false
	}
	questionEnd := offset + 4
	questionType := binary.BigEndian.Uint16(query[offset : offset+2])
	response := append([]byte(nil), query[:questionEnd]...)
	response[2], response[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	if questionType != 1 {
		return response, true
	}
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		answer[0], answer[1], answer[2], answer[3],
	)
	return response, true
}

func (dialer *fakeKMSDialer) DialContext(_ context.Context, _ string, address string) (net.Conn, error) {
	dialer.addresses = append(dialer.addresses, address)
	if dialer.err != nil {
		return nil, dialer.err
	}
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}

func TestPinnedKMSDialContextRejectsInvalidResolutionAndDial(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	cases := []struct {
		name      string
		network   string
		address   string
		resolver  fakeKMSResolver
		dialError error
	}{
		{"network", "udp", testKMSEndpoint + ":443", fakeKMSResolver{}, nil},
		{"port", "tcp", testKMSEndpoint + ":80", fakeKMSResolver{}, nil},
		{"resolution error", "tcp", testKMSEndpoint + ":443", fakeKMSResolver{err: errors.New("dns")}, nil},
		{"empty resolution", "tcp", testKMSEndpoint + ":443", fakeKMSResolver{}, nil},
		{"too many", "tcp", testKMSEndpoint + ":443", fakeKMSResolver{addresses: bytesToPrivateAddresses(17)}, nil},
		{"dial error", "tcp", testKMSEndpoint + ":443", fakeKMSResolver{addresses: []netip.Addr{netip.MustParseAddr("10.20.0.4")}}, errors.New("dial")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dialer := &fakeKMSDialer{err: test.dialError}
			dial := newPinnedKMSDialContext(testKMSEndpoint, allowed, test.resolver, dialer)
			connection, err := dial(context.Background(), test.network, test.address)
			if !errors.Is(err, ErrAlibabaKMSTransportFailed) || connection != nil {
				t.Fatalf("connection=%v err=%v", connection, err)
			}
		})
	}
}

func bytesToPrivateAddresses(count int) []netip.Addr {
	values := make([]netip.Addr, 0, count)
	for index := 1; index <= count; index++ {
		values = append(values, netip.AddrFrom4([4]byte{10, 20, 0, byte(index)}))
	}
	return values
}

func TestPinnedKMSDialContextRejectsDNSDrift(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	for name, addresses := range map[string][]netip.Addr{
		"public":   {netip.MustParseAddr("203.0.113.10")},
		"metadata": {netip.MustParseAddr("100.100.100.200")},
		"mixed":    {netip.MustParseAddr("10.20.0.4"), netip.MustParseAddr("10.21.0.4")},
	} {
		t.Run(name, func(t *testing.T) {
			dialer := &fakeKMSDialer{}
			dial := newPinnedKMSDialContext(testKMSEndpoint, allowed, fakeKMSResolver{addresses: addresses}, dialer)
			if connection, err := dial(context.Background(), "tcp", testKMSEndpoint+":443"); !errors.Is(err, ErrAlibabaKMSTransportFailed) || connection != nil || len(dialer.addresses) != 0 {
				t.Fatalf("connection=%v err=%v dialed=%v", connection, err, dialer.addresses)
			}
		})
	}
	dialer := &fakeKMSDialer{}
	dial := newPinnedKMSDialContext(testKMSEndpoint, allowed,
		fakeKMSResolver{addresses: []netip.Addr{netip.MustParseAddr("10.20.0.4")}}, dialer)
	connection, err := dial(context.Background(), "tcp", testKMSEndpoint+":443")
	if err != nil || connection == nil || len(dialer.addresses) != 1 || dialer.addresses[0] != "10.20.0.4:443" {
		t.Fatalf("connection=%v err=%v dialed=%v", connection, err, dialer.addresses)
	}
	_ = connection.Close()
	if connection, err = dial(context.Background(), "tcp", "other.example:443"); !errors.Is(err, ErrAlibabaKMSTransportFailed) || connection != nil {
		t.Fatalf("wrong host connection=%v err=%v", connection, err)
	}
}

func TestNewAlibabaKMSClientPinsCAAndTransport(t *testing.T) {
	caPEM := testCAPEM(t)
	digest := sha256.Sum256(caPEM)
	now := time.Now().UTC()
	provider := kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) {
		return testKMSCredential(now), nil
	})
	client, err := NewAlibabaKMSClient(provider, testKMSEndpoint, "broker-github-kms", caPEM,
		hex.EncodeToString(digest[:]), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, ok := client.client.(*http.Client)
	if !ok || httpClient.CheckRedirect == nil || httpClient.Timeout != time.Second {
		t.Fatal("unexpected HTTP client")
	}
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.ServerName != testKMSEndpoint ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("transport is not pinned")
	}
	if err = httpClient.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect error=%v", err)
	}
	for name, edit := range map[string]func(*string, *[]byte, *[]netip.Prefix){
		"wrong hash": func(hash *string, _ *[]byte, _ *[]netip.Prefix) { *hash = strings.Repeat("0", 64) },
		"non ca":     func(_ *string, value *[]byte, _ *[]netip.Prefix) { *value = []byte("not a certificate") },
		"public cidr": func(_ *string, _ *[]byte, prefixes *[]netip.Prefix) {
			*prefixes = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}
		},
		"broad private cidr": func(_ *string, _ *[]byte, prefixes *[]netip.Prefix) {
			*prefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			hash := hex.EncodeToString(digest[:])
			certificate := append([]byte(nil), caPEM...)
			prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
			edit(&hash, &certificate, &prefixes)
			if name == "non ca" {
				changed := sha256.Sum256(certificate)
				hash = hex.EncodeToString(changed[:])
			}
			if result, err := NewAlibabaKMSClient(provider, testKMSEndpoint, "broker-github-kms", certificate, hash, prefixes, time.Second); err == nil || result != nil {
				t.Fatal("accepted invalid transport configuration")
			}
		})
	}
}

func TestAlibabaKMSTLSRejectsWrongAuthorityHostnameAndExpiry(t *testing.T) {
	caPEM, caCertificate, caKey := testCertificateAuthority(t)
	digest := sha256.Sum256(caPEM)
	now := time.Now().UTC()
	provider := kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) {
		return testKMSCredential(now), nil
	})
	client, err := NewAlibabaKMSClient(provider, testKMSEndpoint, "broker-github-kms", caPEM,
		hex.EncodeToString(digest[:]), []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := client.client.(*http.Client)
	clientTLS := httpClient.Transport.(*http.Transport).TLSClientConfig.Clone()
	validServer := testServerCertificate(t, caCertificate, caKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err = runTLSHandshake(clientTLS, validServer); err != nil {
		t.Fatalf("valid handshake: %v", err)
	}
	wrongHost := clientTLS.Clone()
	wrongHost.ServerName = "other.cryptoservice.kms.aliyuncs.com"
	if err = runTLSHandshake(wrongHost, validServer); err == nil {
		t.Fatal("accepted wrong TLS hostname")
	}
	otherPEM, otherCertificate, otherKey := testCertificateAuthority(t)
	_ = otherPEM
	wrongAuthorityServer := testServerCertificate(t, otherCertificate, otherKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err = runTLSHandshake(clientTLS, wrongAuthorityServer); err == nil {
		t.Fatal("accepted wrong TLS authority")
	}
	expiredServer := testServerCertificate(t, caCertificate, caKey, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err = runTLSHandshake(clientTLS, expiredServer); err == nil {
		t.Fatal("accepted expired TLS certificate")
	}
}

func runTLSHandshake(clientConfig *tls.Config, serverCertificate tls.Certificate) error {
	clientConnection, serverConnection := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	_ = clientConnection.SetDeadline(deadline)
	_ = serverConnection.SetDeadline(deadline)
	client := tls.Client(clientConnection, clientConfig)
	server := tls.Server(serverConnection, &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCertificate},
	})
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	clientError := client.Handshake()
	if clientError != nil {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	}
	serverError := <-serverResult
	_ = clientConnection.Close()
	_ = serverConnection.Close()
	if clientError != nil {
		return clientError
	}
	return serverError
}

func TestAlibabaKMSConstructorsRejectInvalidDependencies(t *testing.T) {
	caPEM := testCAPEM(t)
	digest := sha256.Sum256(caPEM)
	hash := hex.EncodeToString(digest[:])
	now := time.Now().UTC()
	provider := kmsCredentialFunc(func(context.Context) (aliyunsigner.TemporaryCredential, error) {
		return testKMSCredential(now), nil
	})
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	tests := []struct {
		name     string
		provider aliyunsigner.CredentialProvider
		endpoint string
		role     string
		prefixes []netip.Prefix
		timeout  time.Duration
	}{
		{"nil provider", nil, testKMSEndpoint, "broker-github-kms", prefixes, time.Second},
		{"public endpoint", provider, "kms.example.com", "broker-github-kms", prefixes, time.Second},
		{"bad role", provider, testKMSEndpoint, "bad role", prefixes, time.Second},
		{"empty cidr", provider, testKMSEndpoint, "broker-github-kms", nil, time.Second},
		{"duplicate cidr", provider, testKMSEndpoint, "broker-github-kms", append(prefixes, prefixes[0]), time.Second},
		{"zero timeout", provider, testKMSEndpoint, "broker-github-kms", prefixes, 0},
		{"long timeout", provider, testKMSEndpoint, "broker-github-kms", prefixes, 6 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewAlibabaKMSClient(test.provider, test.endpoint, test.role, caPEM, hash, test.prefixes, test.timeout)
			if err == nil || client != nil {
				t.Fatal("accepted invalid constructor input")
			}
		})
	}
	if client, err := newTestAlibabaKMSClient(provider, testKMSEndpoint, "broker-github-kms", nil, time.Now, randomKMSNonce); err == nil || client != nil {
		t.Fatal("accepted nil test transport")
	}
}

func TestKMSHelpersRejectMalformedValues(t *testing.T) {
	for index := 0; index < 32; index++ {
		value, err := randomKMSNonce()
		if err != nil || !validKMSNonce(value) {
			t.Fatalf("nonce=%q err=%v", value, err)
		}
	}
	for _, value := range []string{
		"", "00112233-4455-4677-8899-aabbccddeef", "00112233-4455-4677-8899-aabbccddeeff0",
		"00112233_4455-4677-8899-aabbccddeeff", "g0112233-4455-4677-8899-aabbccddeeff",
	} {
		if validKMSNonce(value) {
			t.Fatalf("accepted nonce %q", value)
		}
	}
	for _, mediaType := range []string{"", "text/plain", "application/json; charset=latin1", "application/json; profile=test"} {
		if isJSONMediaType(mediaType) {
			t.Fatalf("accepted media type %q", mediaType)
		}
	}
	caPEM := testCAPEM(t)
	if roots, err := parseExclusiveCARoots(bytes.Repeat(caPEM, 5)); err == nil || roots != nil {
		t.Fatal("accepted too many CA certificates")
	}
	withHeader := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Name": "bad"}, Bytes: []byte{1}})
	if roots, err := parseExclusiveCARoots(withHeader); err == nil || roots != nil {
		t.Fatal("accepted PEM headers")
	}
}

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	value, _, _ := testCertificateAuthority(t)
	return value
}

func testCertificateAuthority(t *testing.T) ([]byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test KMS CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, key
}

func testServerCertificate(
	t *testing.T,
	caCertificate *x509.Certificate,
	caKey *rsa.PrivateKey,
	notBefore time.Time,
	notAfter time.Time,
) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: testKMSEndpoint},
		DNSNames: []string{testKMSEndpoint}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caCertificate.Raw}, PrivateKey: key}
}
