#!/bin/sh
# Installs sigstore-kms-exoscalekms from the GitHub releases into BINDIR (default ~/.local/bin).
# Set VERSION to a tag such as v0.1.0 to pin a release instead of the latest.
set -eu

name=sigstore-kms-exoscalekms
repo=exoscale/$name
bindir=${BINDIR:-$HOME/.local/bin}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $os in
  linux | darwin) ;;
  *)
    echo "unsupported OS $os, download the release from https://github.com/$repo/releases" >&2
    exit 1
    ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *)
    echo "unsupported architecture $(uname -m)" >&2
    exit 1
    ;;
esac

if [ -n "${VERSION:-}" ]; then
  url=https://github.com/$repo/releases/download/$VERSION
else
  url=https://github.com/$repo/releases/latest/download
fi
archive=${name}_${os}_${arch}.tar.gz

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
curl -sSfL -o "$archive" "$url/$archive"
curl -sSfL -o checksums.txt "$url/checksums.txt"

grep "  $archive\$" checksums.txt >sum.txt
if command -v sha256sum >/dev/null; then
  sha256sum -c sum.txt
else
  shasum -a 256 -c sum.txt
fi
tar -xzf "$archive" "$name"

mkdir -p "$bindir"
mv "$name" "$bindir/$name"
echo "installed $bindir/$name"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) echo "add $bindir to PATH so cosign finds the plugin" ;;
esac
