#!/bin/sh
# Downloads the release samples and ISFs into sample/work, where the tests read them, and checks every sha256.
# GitHub turns '+' into '.' in asset names, so the files get their kernel version back here. v0.2.0 has 6.1, 6.12
# and 7.2; v0.3.0 adds 5.10 (the v0.2.0 assets are left as they were).
# Assets come through the releases API (the plain /releases/download/ links answered 504 for hours on 2026-11-09);
# GH_TOKEN, when set (CI), lifts the anonymous API rate limit.
set -eu
cd "$(dirname "$0")"
api=https://api.github.com/repos/DesignMaster-Solutions/vol3-io-uring
sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
get() { # <release> <kernel as named in the asset>...
  rel=$1; shift
  mkdir -p "$tmp/$rel"
  (
    cd "$tmp/$rel"
    dl() { curl -fsSL --retry 8 --retry-delay 15 --retry-all-errors ${GH_TOKEN:+-H "Authorization: Bearer $GH_TOKEN"} "$@"; }
    dl "$api/releases/tags/$rel" > release.json
    files=SHA256SUMS
    for k in "$@"; do files="$files io-uring-$k.elf.zst $k.json.xz"; done
    for f in $files; do
      url=$(python3 -c 'import json, sys
print(next(a["url"] for a in json.load(open("release.json"))["assets"] if a["name"] == sys.argv[1]))' "$f")
      dl -H "Accept: application/octet-stream" -o "$f" "$url"
    done
    sum -c SHA256SUMS
  )
}
get v0.2.0 6.1.0-54-cloud-amd64 6.12.115.deb13.1-cloud-amd64 7.2.11.deb13-cloud-amd64
get v0.3.0 5.10.0-32-cloud-amd64
mkdir -p work/isf/linux
put() { # <release> <kernel as named in the asset> <kernel version>
  cp "$tmp/$1/$2.json.xz" "work/isf/linux/$3.json.xz"
  zstd -dqf "$tmp/$1/io-uring-$2.elf.zst" -o "work/io-uring-$3.elf"
  (cd work && sum -c "../expected/io-uring-$3.elf.sha256")
}
put v0.2.0 6.1.0-54-cloud-amd64 6.1.0-54-cloud-amd64
put v0.2.0 6.12.115.deb13.1-cloud-amd64 6.12.115+deb13.1-cloud-amd64
put v0.2.0 7.2.11.deb13-cloud-amd64 7.2.11+deb13-cloud-amd64
put v0.3.0 5.10.0-32-cloud-amd64 5.10.0-32-cloud-amd64
