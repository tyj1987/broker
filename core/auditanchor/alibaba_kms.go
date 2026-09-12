package auditanchor

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
)

const (
	// AlibabaKMSSignAlgorithm is the only KMS algorithm accepted for the
	// ecdsa-p256-sha256 audit-anchor profile.
	AlibabaKMSSignAlgorithm = "ECDSA_SHA_256"
	// AlibabaKMSMessageType prevents KMS from hashing the already-bound digest
	// a second time.
	AlibabaKMSMessageType = "DIGEST"
)

var (
	ErrKMSRequestRejected = errors.New("audit anchor KMS request rejected")
	ErrKMSUnavailable     = errors.New("audit anchor KMS unavailable")
	ErrKMSResponseInvalid = errors.New("audit anchor KMS response invalid")
)

// AlibabaKMSSignRequest is the provider-neutral boundary implemented by the
// Alibaba Cloud KMS transport. Message contains only the SHA-256 digest of the
// purpose-bound audit anchor input; it never contains an audit body or secret.
type AlibabaKMSSignRequest struct {
	KeyID       string
	Algorithm   string
	MessageType string
	Message     []byte
}

// AlibabaKMSSignResponse retains the response metadata needed to prove that
// the configured key and algorithm were used. Signature must be ASN.1 DER.
type AlibabaKMSSignResponse struct {
	KeyID       string
	Algorithm   string
	MessageType string
	Signature   []byte
}

// AlibabaKMSClient is implemented by a narrow transport around the Alibaba
// Cloud KMS Instance SDK. Keeping the SDK behind this interface makes the
// policy boundary independently testable and prevents provider errors from
// crossing the local signer protocol.
type AlibabaKMSClient interface {
	Sign(context.Context, AlibabaKMSSignRequest) (AlibabaKMSSignResponse, error)
}

// AlibabaKMSSigner maps an already-authorized audit anchor request to the
// exact Alibaba Cloud KMS ECDSA digest-signing operation. Config.KeyID must be
// the immutable globally unique key ID, not an alias, because KMS resolves an
// alias and returns the underlying key ID in its response.
type AlibabaKMSSigner struct {
	config Config
	client AlibabaKMSClient
}

func NewAlibabaKMSSigner(config Config, client AlibabaKMSClient) (*AlibabaKMSSigner, error) {
	if !validConfig(config) || config.Algorithm != "ecdsa-p256-sha256" || client == nil {
		return nil, ErrKMSRequestRejected
	}
	return &AlibabaKMSSigner{config: config, client: client}, nil
}

func (signer *AlibabaKMSSigner) Sign(ctx context.Context, request SignRequest) ([]byte, error) {
	if signer == nil || ctx == nil || signer.client == nil ||
		!validConfig(signer.config) || signer.config.Algorithm != "ecdsa-p256-sha256" ||
		!validAuthorizedRequest(signer.config, request) {
		return nil, ErrKMSRequestRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrKMSUnavailable
	}

	message := make([]byte, sha256.Size)
	copy(message, request.Digest[:])
	response, err := signer.client.Sign(ctx, AlibabaKMSSignRequest{
		KeyID:       signer.config.KeyID,
		Algorithm:   AlibabaKMSSignAlgorithm,
		MessageType: AlibabaKMSMessageType,
		Message:     message,
	})
	if err != nil {
		return nil, ErrKMSUnavailable
	}
	if response.KeyID != signer.config.KeyID || response.Algorithm != AlibabaKMSSignAlgorithm ||
		response.MessageType != AlibabaKMSMessageType || !validP256DERSignature(response.Signature) {
		return nil, ErrKMSResponseInvalid
	}

	signature := make([]byte, len(response.Signature))
	copy(signature, response.Signature)
	return signature, nil
}

func validP256DERSignature(signature []byte) bool {
	var decoded struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(signature, &decoded)
	if err != nil || len(rest) != 0 || decoded.R == nil || decoded.S == nil ||
		decoded.R.Sign() <= 0 || decoded.S.Sign() <= 0 {
		return false
	}
	order := elliptic.P256().Params().N
	return decoded.R.Cmp(order) < 0 && decoded.S.Cmp(order) < 0
}
