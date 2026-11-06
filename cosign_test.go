//go:build e2e

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// noTlogSigningConfig is what `cosign signing-config create` writes, a signing config without Rekor and TSA.
const noTlogSigningConfig = `{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","rekorTlogConfig":{},"tsaConfig":{}}`

// TestCosign runs the cosign binary on PATH with the plugin against a fake KMS.
func TestCosign(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", filepath.Join(dir, "sigstore-kms-exoscalekms"), ".").CombinedOutput(); err != nil {
		t.Fatalf("building plugin: %v\n%s", err, out)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("EXOSCALE_API_KEY", "EXOtest")
	t.Setenv("EXOSCALE_API_SECRET", "secret")

	writeFile := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("signing-config.json", noTlogSigningConfig)
	writeFile("artifact", "hello")
	writeFile("tampered", "tampered")

	tests := []fakeKMS{
		{keySpec: "ECC_NIST_P256", key: newECDSAKey(t, elliptic.P256()), hash: crypto.SHA256, algorithm: "ECDSA_SHA_256"},
		{keySpec: "ECC_NIST_P384", key: newECDSAKey(t, elliptic.P384()), hash: crypto.SHA384, algorithm: "ECDSA_SHA_384"},
		{keySpec: "ECC_NIST_P521", key: newECDSAKey(t, elliptic.P521()), hash: crypto.SHA512, algorithm: "ECDSA_SHA_512"},
		{keySpec: "RSA_3072", key: newRSAKey(t), hash: crypto.SHA256, algorithm: "RSASSA_PKCS1_V1_5_SHA_256"},
	}
	for i := range tests {
		f := &tests[i]
		t.Run(f.keySpec, func(t *testing.T) {
			t.Setenv("EXOSCALE_API_ENDPOINT", serveFakeKMS(t, f))
			ref := "exoscalekms://ch-gva-2/" + testKeyID
			run := func(args ...string) string {
				t.Helper()
				out, err := cosign(t.Context(), dir, args...)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			run("sign-blob", "--key", ref, "--signing-config", "signing-config.json", "--bundle", "bundle.json", "-y", "artifact")
			writeFile("cosign.pub", run("public-key", "--key", ref))
			run("verify-blob", "--key", "cosign.pub", "--bundle", "bundle.json", "--insecure-ignore-tlog", "artifact")
			run("verify-blob", "--key", ref, "--bundle", "bundle.json", "--insecure-ignore-tlog", "artifact")
			if _, err := cosign(t.Context(), dir, "verify-blob", "--key", "cosign.pub", "--bundle", "bundle.json", "--insecure-ignore-tlog", "tampered"); err == nil {
				t.Error("verify-blob of a tampered artifact succeeded")
			}
		})
	}
}

// cosign runs cosign with args in dir and returns stdout, or an error that includes stderr.
func cosign(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "cosign", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cosign %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out), nil
}
