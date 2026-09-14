package githubsigner

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
)

const (
	KMSAlgorithmRSA_PKCS1_SHA_256 = "RSA_PKCS1_SHA_256"
	KMSMessageTypeDigest          = "DIGEST"
)

var ErrKMSDigestSigningFailed = errors.New("kms digest signing failed")

type KMSDigestInput struct {
	KeyID        string
	KeyVersionID string
	Algorithm    string
	MessageType  string
	Digest       [32]byte
}

type KMSDigestOutput struct {
	KeyID        string
	KeyVersionID string
	Algorithm    string
	Signature    []byte
}

// KMSDigestClient is the narrow adapter implemented by an authenticated KMS
// workload. It cannot receive a private key or the JWT signing input.
type KMSDigestClient interface {
	SignDigest(context.Context, KMSDigestInput) (KMSDigestOutput, error)
}

type KMSDigestSigner struct {
	client      KMSDigestClient
	authorities map[Binding]SigningAuthority
}

func NewKMSDigestSigner(client KMSDigestClient, configured []SigningAuthority) (*KMSDigestSigner, error) {
	if client == nil || len(configured) == 0 || len(configured) > 64 {
		return nil, ErrKMSDigestSigningFailed
	}
	if _, err := NewBindingSet(authorityBindings(configured)); err != nil {
		return nil, ErrKMSDigestSigningFailed
	}
	authorities := make(map[Binding]SigningAuthority, len(configured))
	for _, authority := range configured {
		if !kmsKeyIDPattern.MatchString(authority.KMSKeyID) ||
			!kmsKeyVersionIDPattern.MatchString(authority.KMSKeyVersionID) ||
			!publicKeyDigestPattern.MatchString(authority.PublicKeySHA256) ||
			!validKMSRSAKey(authority.PublicKey) || authority.PublicKey.E != 65537 {
			return nil, ErrKMSDigestSigningFailed
		}
		publicKeyDER, marshalErr := x509.MarshalPKIXPublicKey(authority.PublicKey)
		publicKeyDigest := sha256.Sum256(publicKeyDER)
		if marshalErr != nil || hex.EncodeToString(publicKeyDigest[:]) != authority.PublicKeySHA256 {
			return nil, ErrKMSDigestSigningFailed
		}
		copyOfKey := &rsa.PublicKey{N: new(big.Int).Set(authority.PublicKey.N), E: authority.PublicKey.E}
		authority.PublicKey = copyOfKey
		authorities[authority.Binding] = authority
	}
	return &KMSDigestSigner{client: client, authorities: authorities}, nil
}

func validKMSRSAKey(publicKey *rsa.PublicKey) bool {
	if publicKey == nil || publicKey.N == nil {
		return false
	}
	bits := publicKey.N.BitLen()
	return bits == 2048 || bits == 3072 || bits == 4096
}

func authorityBindings(authorities []SigningAuthority) []Binding {
	bindings := make([]Binding, 0, len(authorities))
	for _, authority := range authorities {
		bindings = append(bindings, authority.Binding)
	}
	return bindings
}

func (signer *KMSDigestSigner) SignDigest(ctx context.Context, request DigestRequest) ([]byte, error) {
	if signer == nil || signer.client == nil || ctx == nil {
		return nil, ErrKMSDigestSigningFailed
	}
	authority, allowed := signer.authorities[Binding{
		AccountRef: request.AccountRef, Environment: request.Environment, ClientID: request.ClientID,
	}]
	if !allowed || !executionIDPattern.MatchString(request.ExecutionID) ||
		!requestBindingPattern.MatchString(request.RequestBinding) {
		return nil, ErrKMSDigestSigningFailed
	}
	output, err := signer.client.SignDigest(ctx, KMSDigestInput{
		KeyID: authority.KMSKeyID, KeyVersionID: authority.KMSKeyVersionID,
		Algorithm: KMSAlgorithmRSA_PKCS1_SHA_256, MessageType: KMSMessageTypeDigest,
		Digest: request.Digest,
	})
	if err != nil || output.KeyID != authority.KMSKeyID ||
		output.KeyVersionID != authority.KMSKeyVersionID ||
		output.Algorithm != KMSAlgorithmRSA_PKCS1_SHA_256 ||
		len(output.Signature) != authority.PublicKey.Size() ||
		rsa.VerifyPKCS1v15(authority.PublicKey, crypto.SHA256, request.Digest[:], output.Signature) != nil {
		return nil, ErrKMSDigestSigningFailed
	}
	return append([]byte(nil), output.Signature...), nil
}
