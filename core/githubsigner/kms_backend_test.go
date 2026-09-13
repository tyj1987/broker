package githubsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
)

type kmsClientFunc func(context.Context, KMSDigestInput) (KMSDigestOutput, error)

func (function kmsClientFunc) SignDigest(ctx context.Context, input KMSDigestInput) (KMSDigestOutput, error) {
	return function(ctx, input)
}

func testKMSAuthority(t *testing.T) (SigningAuthority, *rsa.PrivateKey) {
	return testKMSAuthorityBits(t, 2048)
}

func testKMSAuthorityBits(t *testing.T, bits int) (SigningAuthority, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(der)
	return SigningAuthority{
		Binding:  Binding{AccountRef: "github-test", Environment: "staging", ClientID: "123456"},
		KMSKeyID: "key/example", KMSKeyVersionID: "version-1",
		PublicKey: &key.PublicKey, PublicKeySHA256: hex.EncodeToString(pin[:]),
	}, key
}

func testDigestRequest() DigestRequest {
	return DigestRequest{
		AccountRef: "github-test", Environment: "staging", ClientID: "123456",
		ExecutionID:    "12345678-1234-4123-8123-123456789abc",
		RequestBinding: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Digest:         sha256.Sum256([]byte("header.claims")),
	}
}

func TestKMSDigestSignerUsesExactDigestKeyAndAlgorithm(t *testing.T) {
	authority, key := testKMSAuthority(t)
	client := kmsClientFunc(func(_ context.Context, input KMSDigestInput) (KMSDigestOutput, error) {
		if input.KeyID != authority.KMSKeyID || input.KeyVersionID != authority.KMSKeyVersionID ||
			input.Algorithm != KMSAlgorithmRSA_PKCS1_SHA_256 || input.MessageType != KMSMessageTypeDigest ||
			input.Digest != testDigestRequest().Digest {
			t.Fatalf("unexpected KMS input: %#v", input)
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, input.Digest[:])
		return KMSDigestOutput{
			KeyID: input.KeyID, KeyVersionID: input.KeyVersionID,
			Algorithm: input.Algorithm, Signature: signature,
		}, err
	})
	signer, err := NewKMSDigestSigner(client, []SigningAuthority{authority})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.SignDigest(context.Background(), testDigestRequest())
	if err != nil || len(signature) != key.PublicKey.Size() {
		t.Fatalf("SignDigest = (%d bytes, %v)", len(signature), err)
	}
	digest := testDigestRequest().Digest
	if err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestKMSDigestSignerFailsClosedOnResponseDrift(t *testing.T) {
	authority, key := testKMSAuthority(t)
	tests := map[string]func(*KMSDigestOutput){
		"wrong key":       func(output *KMSDigestOutput) { output.KeyID = "key/other" },
		"wrong version":   func(output *KMSDigestOutput) { output.KeyVersionID = "version-2" },
		"wrong algorithm": func(output *KMSDigestOutput) { output.Algorithm = "RSA_PSS_SHA_256" },
		"bad signature":   func(output *KMSDigestOutput) { output.Signature[0] ^= 1 },
		"short signature": func(output *KMSDigestOutput) { output.Signature = output.Signature[:32] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client := kmsClientFunc(func(_ context.Context, input KMSDigestInput) (KMSDigestOutput, error) {
				signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, input.Digest[:])
				if err != nil {
					return KMSDigestOutput{}, err
				}
				output := KMSDigestOutput{KeyID: input.KeyID, KeyVersionID: input.KeyVersionID, Algorithm: input.Algorithm, Signature: signature}
				mutate(&output)
				return output, nil
			})
			signer, err := NewKMSDigestSigner(client, []SigningAuthority{authority})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = signer.SignDigest(context.Background(), testDigestRequest()); !errors.Is(err, ErrKMSDigestSigningFailed) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestKMSDigestSignerRejectsUnboundOrInvalidConfiguration(t *testing.T) {
	authority, _ := testKMSAuthority(t)
	client := kmsClientFunc(func(context.Context, KMSDigestInput) (KMSDigestOutput, error) {
		return KMSDigestOutput{}, errors.New("unused")
	})
	invalid := authority
	invalid.KMSKeyID = ""
	if signer, err := NewKMSDigestSigner(client, []SigningAuthority{invalid}); err == nil || signer != nil {
		t.Fatal("accepted invalid authority")
	}
	signer, err := NewKMSDigestSigner(client, []SigningAuthority{authority})
	if err != nil {
		t.Fatal(err)
	}
	request := testDigestRequest()
	request.AccountRef = "other"
	if _, err = signer.SignDigest(context.Background(), request); !errors.Is(err, ErrKMSDigestSigningFailed) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKMSDigestSignerRejectsConstructorAndBackendFailures(t *testing.T) {
	authority, _ := testKMSAuthority(t)
	client := kmsClientFunc(func(context.Context, KMSDigestInput) (KMSDigestOutput, error) {
		return KMSDigestOutput{}, errors.New("kms unavailable")
	})
	if signer, err := NewKMSDigestSigner(nil, []SigningAuthority{authority}); err == nil || signer != nil {
		t.Fatal("accepted nil KMS client")
	}
	if signer, err := NewKMSDigestSigner(client, nil); err == nil || signer != nil {
		t.Fatal("accepted empty authority set")
	}
	badPin := authority
	badPin.PublicKeySHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if signer, err := NewKMSDigestSigner(client, []SigningAuthority{badPin}); err == nil || signer != nil {
		t.Fatal("accepted mismatched public key pin")
	}
	weakKey, _ := testKMSAuthorityBits(t, 1024)
	if signer, err := NewKMSDigestSigner(client, []SigningAuthority{weakKey}); err == nil || signer != nil {
		t.Fatal("accepted unsupported RSA key size")
	}
	signer, err := NewKMSDigestSigner(client, []SigningAuthority{authority})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = signer.SignDigest(context.Background(), testDigestRequest()); !errors.Is(err, ErrKMSDigestSigningFailed) {
		t.Fatalf("unexpected KMS error: %v", err)
	}
	if _, err = signer.SignDigest(nil, testDigestRequest()); !errors.Is(err, ErrKMSDigestSigningFailed) {
		t.Fatalf("unexpected nil context error: %v", err)
	}
}
