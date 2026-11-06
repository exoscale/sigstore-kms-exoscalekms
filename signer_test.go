package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const testKeyID = "6b3f1c8e-2a4d-4e5f-9a1b-3c7d8e9f0a12"

// fakeKMS serves get-public-key and sign for one key and rejects sign requests KMS would reject.
type fakeKMS struct {
	keySpec   string
	key       crypto.Signer
	hash      crypto.Hash
	algorithm v3.SignRequestSigningAlgorithm
	signErr   string // when set, sign answers 403 with this message
	signCalls atomic.Int32
}

// newTestSignerVerifier starts a server for f and returns a signerVerifier that talks to it.
func newTestSignerVerifier(t *testing.T, f *fakeKMS) *signerVerifier {
	t.Helper()
	client, err := v3.NewClient(credentials.NewStaticCredentials("EXOtest", "secret"), v3.ClientOptWithEndpoint(v3.Endpoint(serveFakeKMS(t, f))))
	if err != nil {
		t.Fatal(err)
	}
	return &signerVerifier{client: client, keyID: testKeyID}
}

// serveFakeKMS starts a server for f and returns its URL.
func serveFakeKMS(t *testing.T, f *fakeKMS) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /kms-key/"+testKeyID+"/get-public-key", func(w http.ResponseWriter, _ *http.Request) {
		der, err := x509.MarshalPKIXPublicKey(f.key.Public())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, v3.GetPublicKeyResponse{KeyID: testKeyID, KeySpec: f.keySpec, PublicKey: der, Usage: "sign-verify"})
	})
	mux.HandleFunc("POST /kms-key/"+testKeyID+"/sign", func(w http.ResponseWriter, r *http.Request) {
		f.signCalls.Add(1)
		var req v3.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
			return
		}
		switch {
		case f.signErr != "":
			writeJSON(w, http.StatusForbidden, map[string]string{"message": f.signErr})
		case req.MessageType != v3.SignRequestMessageTypeDigest, req.SigningAlgorithm != f.algorithm, len(req.Message) != f.hash.Size():
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": fmt.Sprintf("unexpected sign request %+v", req)})
		default:
			sig, err := f.key.Sign(rand.Reader, req.Message, f.hash)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, v3.SignResponse{KeySpec: f.keySpec, Signature: sig, SigningAlgorithm: string(req.SigningAlgorithm)})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newECDSAKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newRSAKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSignVerify(t *testing.T) {
	tests := []fakeKMS{
		{keySpec: "ECC_NIST_P256", key: newECDSAKey(t, elliptic.P256()), hash: crypto.SHA256, algorithm: "ECDSA_SHA_256"},
		{keySpec: "ECC_NIST_P384", key: newECDSAKey(t, elliptic.P384()), hash: crypto.SHA384, algorithm: "ECDSA_SHA_384"},
		{keySpec: "ECC_NIST_P521", key: newECDSAKey(t, elliptic.P521()), hash: crypto.SHA512, algorithm: "ECDSA_SHA_512"},
		{keySpec: "RSA_3072", key: newRSAKey(t), hash: crypto.SHA256, algorithm: "RSASSA_PKCS1_V1_5_SHA_256"},
	}
	for i := range tests {
		f := &tests[i]
		t.Run(f.keySpec, func(t *testing.T) {
			sv := newTestSignerVerifier(t, f)
			sig, err := sv.SignMessage(strings.NewReader("hello"))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if err := sv.VerifySignature(bytes.NewReader(sig), strings.NewReader("hello")); err != nil {
				t.Errorf("verify: %v", err)
			}
			if err := sv.VerifySignature(bytes.NewReader(sig), strings.NewReader("tampered")); err == nil {
				t.Error("verify of a tampered message succeeded")
			}
			// cosign verify-blob --key cosign.pub loads the PEM like this.
			cosignVerifier, err := signature.LoadDefaultVerifier(f.key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if err := cosignVerifier.VerifySignature(bytes.NewReader(sig), strings.NewReader("hello")); err != nil {
				t.Errorf("verify with the cosign default verifier: %v", err)
			}
		})
	}
}

func TestSignMessageDigest(t *testing.T) {
	sv := newTestSignerVerifier(t, &fakeKMS{keySpec: "ECC_NIST_P256", key: newECDSAKey(t, elliptic.P256()), hash: crypto.SHA256, algorithm: "ECDSA_SHA_256"})
	digest := sha256.Sum256([]byte("hello"))
	sig, err := sv.SignMessage(strings.NewReader("ignored"), options.WithDigest(digest[:]))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sv.VerifySignature(bytes.NewReader(sig), strings.NewReader("hello")); err != nil {
		t.Errorf("signature is not over the passed digest: %v", err)
	}
}

func TestSignMessageErrors(t *testing.T) {
	tests := []struct {
		name          string
		kms           *fakeKMS
		opts          []signature.SignOption
		wantErr       string
		wantSignCalls int32
	}{
		{
			name:    "hash does not match key spec",
			kms:     &fakeKMS{keySpec: "RSA_3072", key: newRSAKey(t)},
			opts:    []signature.SignOption{options.WithCryptoSignerOpts(crypto.SHA512)},
			wantErr: "unsupported hash algorithm",
		},
		{
			name:    "wrong digest length",
			kms:     &fakeKMS{keySpec: "ECC_NIST_P256", key: newECDSAKey(t, elliptic.P256())},
			opts:    []signature.SignOption{options.WithDigest([]byte("short"))},
			wantErr: "unexpected length of digest",
		},
		{
			name:    "unsupported key spec",
			kms:     &fakeKMS{keySpec: "ECC_EDWARDS25519", key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))},
			wantErr: `key spec "ECC_EDWARDS25519" is not supported`,
		},
		{
			name:          "KMS error",
			kms:           &fakeKMS{keySpec: "ECC_NIST_P256", key: newECDSAKey(t, elliptic.P256()), signErr: "key is disabled"},
			wantErr:       "key is disabled",
			wantSignCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv := newTestSignerVerifier(t, tt.kms)
			_, err := sv.SignMessage(strings.NewReader("hello"), tt.opts...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantErr)
			}
			if got := tt.kms.signCalls.Load(); got != tt.wantSignCalls {
				t.Errorf("sign calls = %d, want %d", got, tt.wantSignCalls)
			}
		})
	}
}

func TestCreateKey(t *testing.T) {
	if _, err := (&signerVerifier{}).CreateKey(t.Context(), "ECC_NIST_P256"); !errors.Is(err, errCreateKey) {
		t.Errorf("err = %v, want %v", err, errCreateKey)
	}
}
