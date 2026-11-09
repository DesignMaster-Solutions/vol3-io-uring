#!/bin/sh
# Downloads the release samples and ISFs into sample/work, where the tests read them, and checks every sha256.
# GitHub turns '+' into '.' in asset names, so the files get their kernel version back here.
set -eu
cd "$(dirname "$0")"
base=https://github.com/DesignMaster-Solutions/vol3-io-uring/releases/download/v0.2.0
sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(
  cd "$tmp"
  curl -fsSLO "$base/SHA256SUMS"
  for k in 6.1.0-54-cloud-amd64 6.12.115.deb13.1-cloud-amd64 7.2.11.deb13-cloud-amd64; do
    curl -fsSLO "$base/io-uring-$k.elf.zst"
    curl -fsSLO "$base/$k.json.xz"
  done
  sum -c SHA256SUMS
)
mkdir -p work/isf/linux
put() { # <kernel as named in the asset> <kernel version>
  cp "$tmp/$1.json.xz" "work/isf/linux/$2.json.xz"
  zstd -dqf "$tmp/io-uring-$1.elf.zst" -o "work/io-uring-$2.elf"
  (cd work && sum -c "../expected/io-uring-$2.elf.sha256")
}
put 6.1.0-54-cloud-amd64 6.1.0-54-cloud-amd64
put 6.12.115.deb13.1-cloud-amd64 6.12.115+deb13.1-cloud-amd64
put 7.2.11.deb13-cloud-amd64 7.2.11+deb13-cloud-amd64
