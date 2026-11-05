# Host-side toolbox (native arch): QEMU in TCG mode, dwarf2json, initramfs tools.
ARG SUITE=bookworm
FROM golang:1.22-bookworm AS d2j
RUN git clone --depth 1 https://github.com/volatilityfoundation/dwarf2json /src/dwarf2json \
 && cd /src/dwarf2json && CGO_ENABLED=0 go build -o /usr/local/bin/dwarf2json . \
 && git -C /src/dwarf2json rev-parse HEAD > /usr/local/share/dwarf2json.rev

FROM debian:${SUITE}
RUN dpkg --add-architecture amd64 && apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 cpio xz-utils zstd python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=d2j /usr/local/bin/dwarf2json /usr/local/bin/dwarf2json
COPY --from=d2j /usr/local/share/dwarf2json.rev /usr/local/share/dwarf2json.rev
COPY inner.sh /usr/local/bin/inner.sh
ENTRYPOINT ["/bin/bash", "/usr/local/bin/inner.sh"]
