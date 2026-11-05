#!/bin/bash
# Runs inside the builder container with the work directory mounted at /work.
set -euo pipefail
cd /work
KVER="${KVER:-6.1.0-54-cloud-amd64}"
MEM="${MEM:-512}"
OUT="io-uring-$KVER.elf"

if [ ! -f "vmlinux-$KVER" ]; then
  # e.g. APT_SOURCE="deb http://deb.debian.org/debian trixie-backports main" for backported kernels
  [ -n "${APT_SOURCE:-}" ] && echo "$APT_SOURCE" > /etc/apt/sources.list.d/extra.list
  apt-get update -qq
  mkdir -p debs && cd debs
  apt-get download "linux-image-$KVER:amd64" "linux-image-$KVER-dbg:amd64"
  # Debian 7.x splits the kernel image (linux-binary-*) and System.map (linux-base-*) out of linux-image-*
  apt-get download "linux-binary-$KVER:amd64" "linux-base-$KVER:amd64" 2>/dev/null || true
  cd ..
  rm -rf kpkg && mkdir kpkg
  for d in debs/*.deb; do dpkg-deb -x "$d" kpkg; done
  # 6.x: /boot/<file>-$KVER; 7.x: /usr/lib/modules/$KVER/<file>
  pick() { for p in "$@"; do [ -f "$p" ] && { echo "$p"; return; }; done; echo "missing: $*" >&2; exit 1; }
  cp "$(pick "kpkg/boot/vmlinuz-$KVER" "kpkg/usr/lib/modules/$KVER/vmlinuz")" "vmlinuz-$KVER"
  cp "$(pick "kpkg/boot/System.map-$KVER" "kpkg/usr/lib/modules/$KVER/System.map")" "System.map-$KVER"
  cp "$(pick "kpkg/usr/lib/debug/boot/vmlinux-$KVER" "kpkg/usr/lib/debug/lib/modules/$KVER/vmlinux" "kpkg/usr/lib/debug/usr/lib/modules/$KVER/vmlinux")" "vmlinux-$KVER"
  dpkg-deb -f debs/linux-image-$KVER-dbg_*.deb Version > kernel.version
  rm -rf kpkg
fi

echo "[inner] building initramfs from rootfs.tar"
rm -rf /tmp/rootfs && mkdir /tmp/rootfs && tar -xf rootfs.tar -C /tmp/rootfs
(cd /tmp/rootfs && find . -print0 | cpio --null -o -H newc --quiet) | gzip -1 > initramfs.gz
rm -rf /tmp/rootfs

echo "[inner] booting guest (TCG, ${MEM} MB)"
rm -f serial.log qmp.sock "$OUT"
qemu-system-x86_64 -machine q35 -accel tcg -cpu max,la57=off -smp 1 -m "$MEM" \
  -kernel "vmlinuz-$KVER" -initrd initramfs.gz \
  -append "console=ttyS0 rdinit=/init quiet" \
  -display none -serial file:serial.log -monitor none \
  -qmp unix:qmp.sock,server=on,wait=off -no-reboot &
QPID=$!

for i in $(seq 1 900); do
  grep -q GUEST_READY_FOR_DUMP serial.log 2>/dev/null && break
  kill -0 "$QPID" 2>/dev/null || { echo "qemu died"; cat serial.log; exit 1; }
  sleep 2
done
grep -q GUEST_READY_FOR_DUMP serial.log || { echo "timeout waiting for guest"; cat serial.log; exit 1; }
cat serial.log

echo "[inner] dump-guest-memory"
OUT="$OUT" python3 - <<'PY'
import json, socket, time
s = socket.socket(socket.AF_UNIX); s.connect("/work/qmp.sock"); f = s.makefile("rw")
def cmd(c, **a):
    f.write(json.dumps({"execute": c, "arguments": a} if a else {"execute": c}) + "\n"); f.flush()
    while True:
        r = json.loads(f.readline())
        if "return" in r or "error" in r:
            return r
f.readline(); print(cmd("qmp_capabilities"))
print(cmd("stop"))
print(cmd("dump-guest-memory", paging=False, protocol="file:/work/" + __import__("os").environ["OUT"]))
print(cmd("quit"))
PY
wait "$QPID" || true
ls -la "$OUT"

cp serial.log "serial-$KVER.log"
sha256sum "$OUT" | tee "$OUT.sha256"

if [ ! -f "isf/linux/$KVER.json.xz" ]; then
  echo "[inner] dwarf2json ($(cat /usr/local/share/dwarf2json.rev))"
  mkdir -p isf/linux
  # dwarf2json needs more than 8 GB for 6.12 kernels: on failure build_sample.sh retries on the host
  if ! dwarf2json linux --elf "vmlinux-$KVER" --system-map "System.map-$KVER" | xz -T0 -6 > "isf/linux/$KVER.json.xz"; then
    rm -f "isf/linux/$KVER.json.xz"; echo "[inner] dwarf2json failed in the container"
  fi
fi
ls -la isf/linux
echo "[inner] done"
