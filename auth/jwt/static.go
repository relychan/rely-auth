package jwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/relychan/goutils"
)

// HMACKey represents an HMAC secret key.
type HMACKey struct {
	algorithm jose.SignatureAlgorithm
	hmacKey   []byte
}

var _ SignatureVerifier = (*HMACKey)(nil)

// NewHMACKey creates a new HMAC secret key.
func NewHMACKey(hmacKey []byte, algorithm jose.SignatureAlgorithm) *HMACKey {
	return &HMACKey{
		hmacKey:   hmacKey,
		algorithm: algorithm,
	}
}

// GetSignatureAlgorithms get signature algorithms of the keyset.
func (hk *HMACKey) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	if hk.algorithm == "" {
		return []jose.SignatureAlgorithm{}
	}

	return []jose.SignatureAlgorithm{hk.algorithm}
}

// Equal checks if the target value is equal.
func (hk *HMACKey) Equal(target SignatureVerifier) bool {
	t, ok := target.(*HMACKey)

	return ok && t != nil && bytes.Equal(hk.hmacKey, t.hmacKey)
}

// VerifySignature compares the json web token against a static set of JWT secret key.
func (hk *HMACKey) VerifySignature(
	_ context.Context,
	sig *jose.JSONWebSignature,
) ([]byte, error) {
	return sig.Verify(hk.hmacKey)
}

// PublicKey represents a public key to verify signatures.
type PublicKey struct {
	algorithm jose.SignatureAlgorithm
	// PublicKeys used to verify the JWT. Supported types are *rsa.PublicKey and
	// *ecdsa.PublicKey.
	publicKey crypto.PublicKey
}

var _ SignatureVerifier = (*PublicKey)(nil)

// NewPublicKey creates a new public key.
func NewPublicKey(publicKey crypto.PublicKey, algorithm jose.SignatureAlgorithm) *PublicKey {
	return &PublicKey{
		algorithm: algorithm,
		publicKey: publicKey,
	}
}

// GetSignatureAlgorithms get signature algorithms of the keyset.
func (pk *PublicKey) GetSignatureAlgorithms() []jose.SignatureAlgorithm {
	if pk.algorithm == "" {
		return []jose.SignatureAlgorithm{}
	}

	return []jose.SignatureAlgorithm{pk.algorithm}
}

// Equal checks if the target value is equal.
func (pk *PublicKey) Equal(target SignatureVerifier) bool {
	t, ok := target.(*PublicKey)
	if !ok || t == nil {
		return false
	}

	return goutils.DeepEqual(t.publicKey, pk.publicKey, true)
}

// VerifySignature compares the json web token against a static set of JWT secret key.
func (pk *PublicKey) VerifySignature(
	_ context.Context,
	sig *jose.JSONWebSignature,
) ([]byte, error) {
	return sig.Verify(pk.publicKey)
}

// NewStaticKey creates a JWT secret from static credentials.
func NewStaticKey( //nolint:ireturn
	rawKey []byte,
	algorithm jose.SignatureAlgorithm,
) (SignatureVerifier, error) {
	if len(rawKey) == 0 {
		return nil, ErrJWTAuthKeyRequired
	}

	switch algorithm {
	case jose.HS256, jose.HS384, jose.HS512:
		return NewHMACKey(rawKey, algorithm), nil
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		spkiBlock, _ := pem.Decode(rawKey)

		pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
		if err != nil {
			return nil, err
		}

		rsaPubKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: The public key is not an RSA key", ErrInvalidJWTKey)
		}

		return NewPublicKey(rsaPubKey, algorithm), nil
	case jose.ES256, jose.ES384, jose.ES512:
		spkiBlock, _ := pem.Decode(rawKey)

		pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
		if err != nil {
			return nil, err
		}

		pubKey, ok := pubInterface.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: The public key is not an ECDSA key", ErrInvalidJWTKey)
		}

		return NewPublicKey(pubKey, algorithm), nil
	case jose.EdDSA:
		spkiBlock, _ := pem.Decode(rawKey)

		pubInterface, err := x509.ParsePKIXPublicKey(spkiBlock.Bytes)
		if err != nil {
			return nil, err
		}

		pubKey, ok := pubInterface.(*ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: The public key is not an Ed25519 key", ErrInvalidJWTKey)
		}

		return NewPublicKey(pubKey, algorithm), nil
	default:
		return nil, fmt.Errorf("%w: %s", jose.ErrUnsupportedAlgorithm, algorithm)
	}
}
