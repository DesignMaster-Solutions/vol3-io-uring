#!/bin/bash
# Reproducible build of the io_uring memory sample and its ISF.
# Requirements: Docker (with linux/amd64 emulation). No KVM needed: QEMU runs in TCG mode.
# Env: KVER (Debian kernel, default 6.1.0-54-cloud-amd64), SUITE (Debian suite that ships it), MEM (MB).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HERE/work}"
mkdir -p "$WORK"

docker build -q --platform linux/amd64 -t vol3-iouring-guest "$HERE/guest"
CID=$(docker create --platform linux/amd64 vol3-iouring-guest /init)
docker export "$CID" > "$WORK/rootfs.tar"
docker rm "$CID" >/dev/null

docker build -q --build-arg SUITE="${SUITE:-bookworm}" -t "vol3-iouring-builder-${SUITE:-bookworm}" "$HERE/builder"
docker run --rm -v "$WORK:/work" -e KVER -e MEM -e APT_SOURCE "vol3-iouring-builder-${SUITE:-bookworm}"

K="${KVER:-6.1.0-54-cloud-amd64}"
if [ ! -f "$WORK/isf/linux/$K.json.xz" ]; then
  command -v dwarf2json >/dev/null || { echo "ISF missing and no host dwarf2json (go install github.com/volatilityfoundation/dwarf2json@latest)"; exit 1; }
  dwarf2json linux --elf "$WORK/vmlinux-$K" --system-map "$WORK/System.map-$K" | xz -T0 -6 > "$WORK/isf/linux/$K.json.xz"
fi
