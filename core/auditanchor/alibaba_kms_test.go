package auditanchor

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"strconv"
	"testing"
)

type kmsClientFunc func(context.Context, AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error)

func (function kmsClientFunc) Sign(ctx context.Context, request AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error) {
	return function(ctx, request)
}

func testDERSignature(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	value, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal signature: %v", err)
	}
	return value
}

func validKMSResponse(t *testing.T, config Config) AlibabaKMSSignResponse {
	t.Helper()
	return AlibabaKMSSignResponse{
		KeyID:       config.KeyID,
		Algorithm:   AlibabaKMSSignAlgorithm,
		MessageType: AlibabaKMSMessageType,
		Signature:   testDERSignature(t, big.NewInt(1), big.NewInt(2)),
	}
}

func kmsRequest(config Config) SignRequest {
	request := anchorRequest(1, 0, 7)
	request.Algorithm, request.KeyID, request.StreamID = config.Algorithm, config.KeyID, config.StreamID
	request.SigningInput = []byte(SignatureContext + "\x00" + request.Algorithm + "\x00" + request.KeyID + "\x00" +
		request.StreamID + "\x00" + strconv.FormatInt(request.Sequence, 10) + "\x00" +
		encodeDigest(request.PreviousDigest) + "\x00" + encodeDigest(request.PayloadDigest))
	request.Digest = sha256.Sum256(request.SigningInput)
	return request
}

func TestAlibabaKMSSignerMapsOnlyBoundDigestAndClonesBuffers(t *testing.T) {
	config := Config{Algorithm: "ecdsa-p256-sha256", KeyID: "kms-audit-key-1", StreamID: "production-audit"}
	request := kmsRequest(config)
	response := validKMSResponse(t, config)
	originalSignature := append([]byte(nil), response.Signature...)

	var captured AlibabaKMSSignRequest
	signer, err := NewAlibabaKMSSigner(config, kmsClientFunc(func(_ context.Context, input AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error) {
		captured = input
		input.Message[0] ^= 0xff
		return response, nil
	}))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signature, err := signer.Sign(context.Background(), request)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if captured.KeyID != config.KeyID || captured.Algorithm != AlibabaKMSSignAlgorithm ||
		captured.MessageType != AlibabaKMSMessageType || len(captured.Message) != 32 {
		t.Fatalf("unexpected KMS request metadata: %#v", captured)
	}
	if request.Digest[0] == captured.Message[0] {
		t.Fatal("test client did not mutate its private request buffer")
	}
	if !bytes.Equal(signature, originalSignature) {
		t.Fatalf("unexpected signature: %x", signature)
	}
	response.Signature[0] ^= 0xff
	if !bytes.Equal(signature, originalSignature) {
		t.Fatal("returned signature aliases the provider response buffer")
	}
}

func TestAlibabaKMSSignerRejectsInvalidConfigurationAndRequests(t *testing.T) {
	baseConfig := Config{Algorithm: "ecdsa-p256-sha256", KeyID: "kms-audit-key-1", StreamID: "production-audit"}
	client := kmsClientFunc(func(context.Context, AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error) {
		t.Fatal("KMS must not be called for a rejected request")
		return AlibabaKMSSignResponse{}, nil
	})

	for name, config := range map[string]Config{
		"wrong algorithm": {Algorithm: "ed25519", KeyID: baseConfig.KeyID, StreamID: baseConfig.StreamID},
		"invalid key":     {Algorithm: baseConfig.Algorithm, KeyID: "../key", StreamID: baseConfig.StreamID},
		"invalid stream":  {Algorithm: baseConfig.Algorithm, KeyID: baseConfig.KeyID, StreamID: "../stream"},
	} {
		t.Run("config "+name, func(t *testing.T) {
			if _, err := NewAlibabaKMSSigner(config, client); !errors.Is(err, ErrKMSRequestRejected) {
				t.Fatalf("expected request rejection, got %v", err)
			}
		})
	}
	if _, err := NewAlibabaKMSSigner(baseConfig, nil); !errors.Is(err, ErrKMSRequestRejected) {
		t.Fatalf("expected nil client rejection, got %v", err)
	}

	request := kmsRequest(baseConfig)
	for name, mutate := range map[string]func(*SignRequest){
		"algorithm": func(value *SignRequest) { value.Algorithm = "ed25519" },
		"key":       func(value *SignRequest) { value.KeyID = "other-key" },
		"stream":    func(value *SignRequest) { value.StreamID = "other-stream" },
		"digest":    func(value *SignRequest) { value.Digest[0] ^= 1 },
		"input":     func(value *SignRequest) { value.SigningInput = []byte("wrong") },
	} {
		t.Run("request "+name, func(t *testing.T) {
			candidate := cloneRequest(request)
			mutate(&candidate)
			signer, err := NewAlibabaKMSSigner(baseConfig, client)
			if err != nil {
				t.Fatalf("new signer: %v", err)
			}
			if _, err = signer.Sign(context.Background(), candidate); !errors.Is(err, ErrKMSRequestRejected) {
				t.Fatalf("expected request rejection, got %v", err)
			}
		})
	}
	var nilSigner *AlibabaKMSSigner
	if _, err := nilSigner.Sign(context.Background(), request); !errors.Is(err, ErrKMSRequestRejected) {
		t.Fatalf("expected nil signer rejection, got %v", err)
	}
	signer, _ := NewAlibabaKMSSigner(baseConfig, client)
	if _, err := signer.Sign(nil, request); !errors.Is(err, ErrKMSRequestRejected) {
		t.Fatalf("expected nil context rejection, got %v", err)
	}
}

func TestAlibabaKMSSignerFailsClosedOnProviderFailures(t *testing.T) {
	config := Config{Algorithm: "ecdsa-p256-sha256", KeyID: "kms-audit-key-1", StreamID: "production-audit"}
	request := kmsRequest(config)

	providerDetail := errors.New("provider detail must not cross boundary")
	tests := map[string]struct {
		response AlibabaKMSSignResponse
		err      error
		expected error
	}{
		"provider error": {err: providerDetail, expected: ErrKMSUnavailable},
		"wrong key": {response: func() AlibabaKMSSignResponse {
			value := validKMSResponse(t, config)
			value.KeyID = "other"
			return value
		}(), expected: ErrKMSResponseInvalid},
		"wrong algorithm": {response: func() AlibabaKMSSignResponse {
			value := validKMSResponse(t, config)
			value.Algorithm = "RSA_PSS_SHA_256"
			return value
		}(), expected: ErrKMSResponseInvalid},
		"wrong message type": {response: func() AlibabaKMSSignResponse {
			value := validKMSResponse(t, config)
			value.MessageType = "RAW"
			return value
		}(), expected: ErrKMSResponseInvalid},
		"empty signature": {response: func() AlibabaKMSSignResponse {
			value := validKMSResponse(t, config)
			value.Signature = nil
			return value
		}(), expected: ErrKMSResponseInvalid},
		"trailing bytes": {response: func() AlibabaKMSSignResponse {
			value := validKMSResponse(t, config)
			value.Signature = append(value.Signature, 0)
			return value
		}(), expected: ErrKMSResponseInvalid},
		"zero component": {response: func() AlibabaKMSSignResponse {
			value := validKMSResponse(t, config)
			value.Signature = testDERSignature(t, big.NewInt(0), big.NewInt(1))
			return value
		}(), expected: ErrKMSResponseInvalid},
		"out of range": {response: func() AlibabaKMSSignResponse {
			value := validKMSResponse(t, config)
			value.Signature = testDERSignature(t, elliptic.P256().Params().N, big.NewInt(1))
			return value
		}(), expected: ErrKMSResponseInvalid},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			signer, err := NewAlibabaKMSSigner(config, kmsClientFunc(func(context.Context, AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error) {
				return test.response, test.err
			}))
			if err != nil {
				t.Fatalf("new signer: %v", err)
			}
			_, err = signer.Sign(context.Background(), request)
			if !errors.Is(err, test.expected) || errors.Is(err, providerDetail) || err.Error() == providerDetail.Error() {
				t.Fatalf("expected stable %v without provider detail, got %v", test.expected, err)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	signer, _ := NewAlibabaKMSSigner(config, kmsClientFunc(func(context.Context, AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error) {
		t.Fatal("KMS must not be called after cancellation")
		return AlibabaKMSSignResponse{}, nil
	}))
	if _, err := signer.Sign(cancelled, request); !errors.Is(err, ErrKMSUnavailable) {
		t.Fatalf("expected unavailable for cancelled context, got %v", err)
	}
}
