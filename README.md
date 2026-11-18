# sigstore-kms-exoscalekms

A [Sigstore KMS plugin](https://github.com/sigstore/sigstore/blob/main/pkg/signature/kms/cliplugin/README.md) that lets stock [cosign](https://github.com/sigstore/cosign) sign with keys stored in [Exoscale KMS](https://www.exoscale.com/cloud-security/key-management-service/). The private key never leaves KMS.

## Install

On Linux and macOS, the install script downloads the latest release, checks it against `checksums.txt` and puts the binary in `~/.local/bin`:

```sh
curl -sSfL https://raw.githubusercontent.com/exoscale/sigstore-kms-exoscalekms/main/install.sh | sh
```

Set `BINDIR` to install somewhere else and `VERSION` to pin a release, for example `| BINDIR=/usr/local/bin VERSION=v0.1.1 sh`.

Or download the binary for your platform from the [latest release](https://github.com/exoscale/sigstore-kms-exoscalekms/releases/latest), for example Linux on amd64:

```sh
curl -sSL https://github.com/exoscale/sigstore-kms-exoscalekms/releases/latest/download/sigstore-kms-exoscalekms_linux_amd64.tar.gz \
  | tar -xz -C /usr/local/bin sigstore-kms-exoscalekms
```

Replace `linux_amd64` with `linux_arm64`, `darwin_amd64` or `darwin_arm64`. Windows builds are zip files. Each release has a `checksums.txt`.

Every release asset has a signed [build provenance attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations). Check that a downloaded archive was built by the release workflow of this repository with the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify sigstore-kms-exoscalekms_linux_amd64.tar.gz --repo exoscale/sigstore-kms-exoscalekms
```

With Go installed:

```sh
go install github.com/exoscale/sigstore-kms-exoscalekms@latest
```

cosign looks for the `sigstore-kms-exoscalekms` binary on `PATH` whenever a key reference starts with `exoscalekms://`.

## Configure

| Variable | Purpose |
|---|---|
| `EXOSCALE_API_KEY` | API key with access to `sign` and `get-public-key` on the key |
| `EXOSCALE_API_SECRET` | Secret of the API key |
| `EXOSCALE_ZONE` | Zone used when the key reference has none |
| `EXOSCALE_API_ENDPOINT` | API endpoint used as is instead of the zone endpoint |

## Create a key

The plugin does not create keys, so `cosign generate-key-pair --kms` fails. Create the key with the [exo CLI](https://github.com/exoscale/cli) and note its UUID:

```sh
exo kms key create my-cosign-key --usage sign-verify --key-spec ECC_NIST_P256 --zone ch-gva-2
```

The plugin assumes the key exists and is enabled. A disabled or missing key returns the KMS error.

## Sign and verify

```sh
cosign sign-blob --key exoscalekms://ch-gva-2/<key-uuid> --bundle artifact.sigstore.json artifact
cosign sign --key exoscalekms://ch-gva-2/<key-uuid> <image>

cosign public-key --key exoscalekms://ch-gva-2/<key-uuid> > cosign.pub
cosign verify-blob --key cosign.pub --bundle artifact.sigstore.json artifact
```

Verification with `--key exoscalekms://...` also works. It fetches the public key from KMS and verifies locally, so it never calls the KMS `verify` endpoint. Timestamping and transparency log settings are cosign options and work the same as with any other key.

## Key reference

| Reference | Zone |
|---|---|
| `exoscalekms://<zone>/<key-uuid>` | `<zone>` |
| `exoscalekms:///<key-uuid>` | `EXOSCALE_ZONE` |

The key UUID is the only key identifier. Aliases and key names are not supported.

## Supported key specs

The plugin supports a subset of the [Exoscale KMS signing key specs](https://community.exoscale.com/product/security/kms/overview/#asymmetric-signing-keys). Each supported key spec signs with one fixed algorithm.

| Key spec | Signing algorithm |
|---|---|
| `ECC_NIST_P256` (default) | `ECDSA_SHA_256` |
| `ECC_NIST_P384` | `ECDSA_SHA_384` |
| `ECC_NIST_P521` | `ECDSA_SHA_512` |
| `RSA_3072`, `RSA_4096` | `RSASSA_PKCS1_V1_5_SHA_256` |

The other Exoscale KMS signing key specs, `ECC_EDWARDS25519`, `ML_DSA_65` and `ML_DSA_87`, are not supported.
