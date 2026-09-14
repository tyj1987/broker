package auditanchor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"regexp"
)

const (
	// AlibabaKMSAsymmetricSignAlgorithm is the only KMS algorithm accepted for the
	// ecdsa-p256-sha256 audit-anchor profile.
	AlibabaKMSAsymmetricSignAlgorithm = "ECDSA_SHA_256"
)

var (
	ErrKMSRequestRejected = errors.New("audit anchor KMS request rejected")
	ErrKMSUnavailable     = errors.New("audit anchor KMS unavailable")
	ErrKMSResponseInvalid = errors.New("audit anchor KMS response invalid")
	kmsKeyVersionPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)
)

// AlibabaKMSSignRequest is the provider-neutral boundary implemented by the
// Alibaba Cloud KMS transport. Message contains only the SHA-256 digest of the
// purpose-bound audit anchor input; it never contains an audit body or secret.
type AlibabaKMSSignRequest struct {
	KeyID        string
	KeyVersionID string
	Algorithm    string
	Digest       []byte
}

// AlibabaKMSSignResponse retains the response metadata needed to prove that
// the configured key and algorithm were used. Signature must be ASN.1 DER.
type AlibabaKMSSignResponse struct {
	KeyID        string
	KeyVersionID string
	Signature    []byte
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
	config       Config
	keyVersionID string
	publicKey    *ecdsa.PublicKey
	client       AlibabaKMSClient
}

func NewAlibabaKMSSigner(
	config Config,
	keyVersionID string,
	publicKey *ecdsa.PublicKey,
	client AlibabaKMSClient,
) (*AlibabaKMSSigner, error) {
	clonedKey, validKey := cloneP256PublicKey(publicKey)
	if !validConfig(config) || config.Algorithm != "ecdsa-p256-sha256" ||
		!kmsKeyVersionPattern.MatchString(keyVersionID) || !validKey || client == nil {
		return nil, ErrKMSRequestRejected
	}
	return &AlibabaKMSSigner{
		config: config, keyVersionID: keyVersionID, publicKey: clonedKey, client: client,
	}, nil
}

func (signer *AlibabaKMSSigner) Sign(ctx context.Context, request SignRequest) ([]byte, error) {
	if signer == nil || ctx == nil || signer.client == nil ||
		!validConfig(signer.config) || signer.config.Algorithm != "ecdsa-p256-sha256" ||
		!kmsKeyVersionPattern.MatchString(signer.keyVersionID) || !validP256PublicKey(signer.publicKey) ||
		!validAuthorizedRequest(signer.config, request) {
		return nil, ErrKMSRequestRejected
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrKMSUnavailable
	}

	digest := make([]byte, sha256.Size)
	copy(digest, request.Digest[:])
	response, err := signer.client.Sign(ctx, AlibabaKMSSignRequest{
		KeyID:        signer.config.KeyID,
		KeyVersionID: signer.keyVersionID,
		Algorithm:    AlibabaKMSAsymmetricSignAlgorithm,
		Digest:       digest,
	})
	if err != nil {
		return nil, ErrKMSUnavailable
	}
	if response.KeyID != signer.config.KeyID || response.KeyVersionID != signer.keyVersionID ||
		!validP256DERSignature(response.Signature) ||
		!ecdsa.VerifyASN1(signer.publicKey, request.Digest[:], response.Signature) {
		return nil, ErrKMSResponseInvalid
	}

	signature := make([]byte, len(response.Signature))
	copy(signature, response.Signature)
	return signature, nil
}

func cloneP256PublicKey(publicKey *ecdsa.PublicKey) (*ecdsa.PublicKey, bool) {
	if !validP256PublicKey(publicKey) {
		return nil, false
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(), X: new(big.Int).Set(publicKey.X), Y: new(big.Int).Set(publicKey.Y),
	}, true
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
