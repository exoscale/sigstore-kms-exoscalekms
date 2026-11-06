package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/sigstore/sigstore/pkg/signature"
)

var errCreateKey = errors.New("key creation is not supported, create the key with `exo kms key create <name> --usage sign-verify --key-spec ECC_NIST_P256` and reference it by UUID")

// keySpec holds the hash and signing algorithm the plugin uses for a KMS key spec.
type keySpec struct {
	hash      crypto.Hash
	algorithm v3.SignRequestSigningAlgorithm
}

// keySpecs maps each supported KMS key spec to one hash, like the cosign --signing-algorithm list. RSA uses a string because egoscale has no PKCS1v15 constant yet.
var keySpecs = map[string]keySpec{
	"ECC_NIST_P256": {crypto.SHA256, v3.SignRequestSigningAlgorithmECDSASHA256},
	"ECC_NIST_P384": {crypto.SHA384, v3.SignRequestSigningAlgorithmECDSASHA384},
	"ECC_NIST_P521": {crypto.SHA512, v3.SignRequestSigningAlgorithmECDSASHA512},
	"RSA_3072":      {crypto.SHA256, "RSASSA_PKCS1_V1_5_SHA_256"},
	"RSA_4096":      {crypto.SHA256, "RSASSA_PKCS1_V1_5_SHA_256"},
}

// signerVerifier implements the Sigstore cliplugin SignerVerifier for one Exoscale KMS key.
type signerVerifier struct {
	client *v3.Client
	keyID  v3.UUID
}

// DefaultAlgorithm returns the key spec cosign uses when none is given.
func (*signerVerifier) DefaultAlgorithm() string {
	return "ECC_NIST_P256"
}

// SupportedAlgorithms returns the key specs the plugin signs with.
func (*signerVerifier) SupportedAlgorithms() []string {
	return slices.Sorted(maps.Keys(keySpecs))
}

// CreateKey always fails because keys must exist in Exoscale KMS before cosign uses them.
func (*signerVerifier) CreateKey(context.Context, string) (crypto.PublicKey, error) {
	return nil, errCreateKey
}

// PublicKey fetches the public key from KMS.
func (s *signerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	pub, _, err := s.fetchKey(ctx)
	return pub, err
}

// SignMessage signs the digest passed with WithDigest in KMS, and hashes message only when no digest is passed.
func (s *signerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	_, spec, err := s.fetchKey(ctx)
	if err != nil {
		return nil, err
	}
	digest, _, err := signature.ComputeDigestForSigning(message, spec.hash, []crypto.Hash{spec.hash}, opts...)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Sign(ctx, s.keyID, v3.SignRequest{
		Message:          digest,
		MessageType:      v3.SignRequestMessageTypeDigest,
		SigningAlgorithm: spec.algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("signing with KMS: %w", err)
	}
	return resp.Signature, nil
}

// VerifySignature verifies sig locally against the public key from KMS.
func (s *signerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	pub, spec, err := s.fetchKey(ctx)
	if err != nil {
		return err
	}
	verifier, err := signature.LoadVerifier(pub, spec.hash)
	if err != nil {
		return err
	}
	return verifier.VerifySignature(sig, message, opts...)
}

// CryptoSigner is never called, because the cliplugin handler does not dispatch it.
func (*signerVerifier) CryptoSigner(context.Context, func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	return nil, nil, errors.ErrUnsupported
}

// fetchKey returns the public key from KMS together with the hash and signing algorithm of its key spec.
func (s *signerVerifier) fetchKey(ctx context.Context) (crypto.PublicKey, keySpec, error) {
	resp, err := s.client.GetPublicKey(ctx, s.keyID)
	if err != nil {
		return nil, keySpec{}, fmt.Errorf("getting public key from KMS: %w", err)
	}
	spec, ok := keySpecs[resp.KeySpec]
	if !ok {
		return nil, keySpec{}, fmt.Errorf("key spec %q is not supported, want one of %v", resp.KeySpec, slices.Sorted(maps.Keys(keySpecs)))
	}
	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, keySpec{}, fmt.Errorf("parsing public key: %w", err)
	}
	return pub, spec, nil
}
