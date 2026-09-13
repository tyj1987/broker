package aliyunsigner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type credentialProviderFunc func(context.Context) (TemporaryCredential, error)

func (function credentialProviderFunc) Credential(ctx context.Context) (TemporaryCredential, error) {
	return function(ctx)
}

func validTemporaryCredential() TemporaryCredential {
	return TemporaryCredential{
		AccessKeyID: "STS.TEST", AccessKeySecret: "temporary-secret",
		SecurityToken: "temporary-security-token", RoleName: "broker-readonly",
		Expiration: time.Date(2026, 9, 13, 1, 0, 0, 0, time.UTC),
	}
}

func validBackendSigningRequest() SigningRequest {
	return SigningRequest{
		OperationID: OperationECSInstancesList, AccountRef: "aliyun-test", Environment: "staging",
		ResourceRef: "readonly-account", RegionID: "cn-hangzhou", MaxResults: 10,
		ExecutionID:    "12345678-1234-4123-8123-123456789abc",
		RequestBinding: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

func validBackendBindings() []Binding {
	request := validBackendSigningRequest()
	return []Binding{{
		AccountRef: request.AccountRef, Environment: request.Environment,
		ResourceRef: request.ResourceRef, RegionID: request.RegionID,
	}}
}

func TestSignatureV3SignerMatchesIndependentNodeVector(t *testing.T) {
	provider := credentialProviderFunc(func(context.Context) (TemporaryCredential, error) {
		return validTemporaryCredential(), nil
	})
	signer, err := NewSignatureV3Signer(provider, "broker-readonly", validBackendBindings())
	if err != nil {
		t.Fatal(err)
	}
	signer.clock = func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }
	signer.nonce = func() (string, error) { return "12345678-1234-4123-8123-123456789abc", nil }
	signed, err := signer.Sign(context.Background(), validBackendSigningRequest())
	const expected = "ACS3-HMAC-SHA256 Credential=STS.TEST,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-security-token;x-acs-signature-nonce;x-acs-version,Signature=015cef4d5ef7270680825095d2fff0666923fc7dafe8d3a4abe95866163885e3"
	if err != nil || signed.Authorization != expected || signed.SecurityToken != "temporary-security-token" ||
		!credentialBindingPattern.MatchString(signed.CredentialBinding) {
		t.Fatalf("unexpected signed request: %#v err=%v", signed, err)
	}
}

func TestSignatureV3SignerFailsClosedOnCredentialOrBindingErrors(t *testing.T) {
	provider := credentialProviderFunc(func(context.Context) (TemporaryCredential, error) {
		return validTemporaryCredential(), nil
	})
	signer, err := NewSignatureV3Signer(provider, "broker-readonly", validBackendBindings())
	if err != nil {
		t.Fatal(err)
	}
	signer.clock = func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }
	signer.nonce = func() (string, error) { return "12345678-1234-4123-8123-123456789abc", nil }
	request := validBackendSigningRequest()
	request.AccountRef = "other"
	request.RequestBinding = "bad"
	if _, err = signer.Sign(context.Background(), request); !errors.Is(err, ErrSignatureV3Failed) {
		t.Fatalf("unexpected request error: %v", err)
	}
	signer.credentials = credentialProviderFunc(func(context.Context) (TemporaryCredential, error) {
		credential := validTemporaryCredential()
		credential.SecurityToken = ""
		return credential, nil
	})
	if signed, err := signer.Sign(context.Background(), validBackendSigningRequest()); !errors.Is(err, ErrSignatureV3Failed) ||
		signed.Authorization != "" || signed.SecurityToken != "" {
		t.Fatalf("unsafe result: %#v err=%v", signed, err)
	}
}

func TestSignatureV3SignerBindsTokenAndSupportsCallerIdentity(t *testing.T) {
	credential := validTemporaryCredential()
	provider := credentialProviderFunc(func(context.Context) (TemporaryCredential, error) { return credential, nil })
	signer, err := NewSignatureV3Signer(provider, "broker-readonly", validBackendBindings())
	if err != nil {
		t.Fatal(err)
	}
	signer.clock = func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }
	signer.nonce = func() (string, error) { return "12345678-1234-4123-8123-123456789abc", nil }
	request := validBackendSigningRequest()
	request.OperationID = OperationCallerIdentity
	request.MaxResults = 0
	signed, err := signer.Sign(context.Background(), request)
	if err != nil || !strings.Contains(signed.Authorization, "x-acs-security-token") {
		t.Fatalf("caller identity signature = %#v err=%v", signed, err)
	}
	credential.SecurityToken = "changed-security-token"
	signedChanged, err := signer.Sign(context.Background(), request)
	if err != nil || signedChanged.Authorization == signed.Authorization || signedChanged.CredentialBinding == signed.CredentialBinding {
		t.Fatal("security token was not bound to signature and lease")
	}
}

func TestSignatureV3SignerRejectsConstructorAndRuntimeDrift(t *testing.T) {
	provider := credentialProviderFunc(func(context.Context) (TemporaryCredential, error) {
		return TemporaryCredential{}, errors.New("unavailable")
	})
	if signer, err := NewSignatureV3Signer(nil, "broker-readonly", validBackendBindings()); err == nil || signer != nil {
		t.Fatal("accepted nil credential provider")
	}
	if signer, err := NewSignatureV3Signer(provider, "bad role", validBackendBindings()); err == nil || signer != nil {
		t.Fatal("accepted invalid role")
	}
	signer, err := NewSignatureV3Signer(provider, "broker-readonly", validBackendBindings())
	if err != nil {
		t.Fatal(err)
	}
	signer.clock = func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }
	if _, err = signer.Sign(context.Background(), validBackendSigningRequest()); !errors.Is(err, ErrSignatureV3Failed) {
		t.Fatalf("unexpected provider error: %v", err)
	}
	signer.credentials = credentialProviderFunc(func(context.Context) (TemporaryCredential, error) {
		credential := validTemporaryCredential()
		credential.RoleName = "other-role"
		return credential, nil
	})
	if _, err = signer.Sign(context.Background(), validBackendSigningRequest()); !errors.Is(err, ErrSignatureV3Failed) {
		t.Fatalf("unexpected role drift error: %v", err)
	}
	signer.credentials = credentialProviderFunc(func(context.Context) (TemporaryCredential, error) { return validTemporaryCredential(), nil })
	signer.nonce = func() (string, error) { return "", errors.New("entropy") }
	if _, err = signer.Sign(context.Background(), validBackendSigningRequest()); !errors.Is(err, ErrSignatureV3Failed) {
		t.Fatalf("unexpected nonce error: %v", err)
	}
}
