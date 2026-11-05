# Guest userland (x86_64), built with --platform linux/amd64 and exported as an initramfs.
FROM alpine:3.20 AS build
RUN apk add --no-cache build-base linux-headers
COPY uring_demo.c /src/
RUN gcc -O1 -static -Wall -Wextra -o /src/uring_demo /src/uring_demo.c

FROM alpine:3.20
COPY --from=build /src/uring_demo /usr/local/bin/uring_demo
COPY init /init
