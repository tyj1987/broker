package aliyunsigner

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const signatureV3Algorithm = "ACS3-HMAC-SHA256"

var ErrSignatureV3Failed = errors.New("signature v3 failed")

type SignatureV3Signer struct {
	credentials CredentialProvider
	roleName    string
	bindings    *BindingSet
	clock       func() time.Time
	nonce       func() (string, error)
}

func NewSignatureV3Signer(credentials CredentialProvider, roleName string, configured []Binding) (*SignatureV3Signer, error) {
	bindings, err := NewBindingSet(configured)
	if credentials == nil || !roleNamePattern.MatchString(roleName) || err != nil {
		return nil, ErrSignatureV3Failed
	}
	return &SignatureV3Signer{
		credentials: credentials, roleName: roleName, bindings: bindings,
		clock: time.Now, nonce: randomNonce,
	}, nil
}

func (signer *SignatureV3Signer) Sign(ctx context.Context, request SigningRequest) (SignedRequest, error) {
	if signer == nil || signer.credentials == nil || signer.bindings == nil || signer.clock == nil ||
		signer.nonce == nil || ctx == nil || !validBackendRequest(request) ||
		signer.bindings.AuthorizeBinding(ctx, request) != nil {
		return SignedRequest{}, ErrSignatureV3Failed
	}
	credential, err := signer.credentials.Credential(ctx)
	now := signer.clock().UTC()
	if err != nil || credential.RoleName != signer.roleName ||
		!safeCredentialPart(credential.AccessKeyID, 3, 256) ||
		!safeCredentialPart(credential.AccessKeySecret, 8, 4096) ||
		!safeCredentialPart(credential.SecurityToken, 8, 8192) ||
		credential.Expiration.Before(now.Add(minimumCredentialLife)) ||
		credential.Expiration.After(now.Add(maximumCredentialLife)) {
		return SignedRequest{}, ErrSignatureV3Failed
	}
	nonce, err := signer.nonce()
	if err != nil || !noncePattern.MatchString(nonce) {
		return SignedRequest{}, ErrSignatureV3Failed
	}
	host, action, version, query := fixedRequest(request)
	date := now.Format("2006-01-02T15:04:05Z")
	headers := []struct{ name, value string }{
		{"host", host}, {"x-acs-action", action}, {"x-acs-content-sha256", emptyPayloadHash},
		{"x-acs-date", date}, {"x-acs-security-token", credential.SecurityToken},
		{"x-acs-signature-nonce", nonce}, {"x-acs-version", version},
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
	canonicalRequest := "POST\n/\n" + query + "\n" + canonicalHeaders.String() + "\n" + signedHeaders + "\n" + emptyPayloadHash
	canonicalDigest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := signatureV3Algorithm + "\n" + hex.EncodeToString(canonicalDigest[:])
	mac := hmac.New(sha256.New, []byte(credential.AccessKeySecret))
	_, _ = mac.Write([]byte(stringToSign))
	signature := hex.EncodeToString(mac.Sum(nil))
	bindingDigest := sha256.Sum256([]byte(credential.RoleName + "\x00" + credential.AccessKeyID + "\x00" + credential.SecurityToken + "\x00" + credential.Expiration.UTC().Format(time.RFC3339)))
	return SignedRequest{
		CredentialBinding: base64.RawURLEncoding.EncodeToString(bindingDigest[:]),
		Authorization: signatureV3Algorithm + " Credential=" + credential.AccessKeyID +
			",SignedHeaders=" + signedHeaders + ",Signature=" + signature,
		SecurityToken: credential.SecurityToken, Date: date, SignatureNonce: nonce,
	}, nil
}

func validBackendRequest(request SigningRequest) bool {
	if (request.OperationID != OperationECSInstancesList && request.OperationID != OperationCallerIdentity) ||
		!accountRefPattern.MatchString(request.AccountRef) || !environmentPattern.MatchString(request.Environment) ||
		!accountRefPattern.MatchString(request.ResourceRef) || !regionPattern.MatchString(request.RegionID) ||
		!executionIDPattern.MatchString(request.ExecutionID) || !requestBindingPattern.MatchString(request.RequestBinding) {
		return false
	}
	if request.OperationID == OperationCallerIdentity {
		return request.MaxResults == 0 && request.NextToken == nil
	}
	return request.MaxResults >= 1 && request.MaxResults <= 100 &&
		(request.NextToken == nil || (len(*request.NextToken) <= 2048 && nextTokenPattern.MatchString(*request.NextToken)))
}

func fixedRequest(request SigningRequest) (host, action, version, query string) {
	if request.OperationID == OperationCallerIdentity {
		return "sts.aliyuncs.com", "GetCallerIdentity", "2015-04-01", ""
	}
	values := url.Values{}
	values.Set("MaxResults", strconv.Itoa(request.MaxResults))
	values.Set("RegionId", request.RegionID)
	if request.NextToken != nil {
		values.Set("NextToken", *request.NextToken)
	}
	return "ecs." + request.RegionID + ".aliyuncs.com", "DescribeInstances", "2014-05-26", values.Encode()
}

func randomNonce() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
