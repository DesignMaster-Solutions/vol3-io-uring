# vol3-io-uring: io_uring visibility for Volatility 3

io_uring lets a Linux process open and read files, create sockets, connect, send and
receive without the per-operation system calls (`openat`, `connect`, `sendto`, ...) that most
runtime security tools watch. In April 2025 ARMO published
[Curing](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/), a
proof-of-concept rootkit that works only through io_uring, and reported that tools such as
Falco and Microsoft Defender did not see it because they rely on syscall monitoring. Google
[limited io_uring](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html)
in ChromeOS, Android apps and its production servers after 60% of the kernel exploits sent to
its kCTF VRP in the previous year targeted it.

Memory is where this blind spot can be closed. The kernel keeps the full state of every ring
in kernel memory: setup flags, the submission queue entries (SQEs) a process wrote, the
completion queue entries (CQEs) the kernel returned, registered files and buffers, registered
credentials (personalities) and the SQPOLL kernel thread that submits on the process's behalf.
An analyst can read what a process asked io_uring to do even when no syscall trace exists.

Volatility 3 had no io_uring support, in core or in community3. This repository adds it.

## Plugins

| Plugin | What it shows |
|---|---|
| `linux.io_uring.IoUring` | One row per ring: PID, process, fd, `io_ring_ctx` address, setup flags (SQPOLL, IOPOLL, DEFER_TASKRUN, ...), SQ/CQ sizes, head/tail and pending entries, SQPOLL thread (TID, name) and the uid it submits with, counts of registered files, buffers and personalities, restrictions. |
| `linux.io_uring.Sqes` | Every non-empty submission slot still in ring memory, `pending` or already `consumed`: opcode by name (`OPENAT`, `READ`, `SOCKET`, `CONNECT`, `SEND`, `READ_FIXED`, ...), SQE flags, fd and what it points to now (path, socket, `fixed[n]` registered file), address, length, offset, `user_data`, personality, buffer index. For path opcodes it reads the path from process memory, for `CONNECT` the destination address, for `SOCKET` the family and type. It never reads data buffers. |
| `linux.io_uring.Cqes` | Every non-empty completion slot, `pending` (not yet seen by the application) or `consumed`: `user_data`, result (fd, byte count or Linux errno name) and the opcode of the SQE with the same `user_data`. |
| `linux.io_uring.Registered` | Registered files (path or socket, and whether the file is still in the fd table: a process can register a file and close the fd, keeping access invisible to `lsof`), registered buffers (user address and size) and personalities (registered credentials by id, flagged when they differ from the process uid). |

All four take `--pid`. Output from the sample (6.1 kernel):

```
$ vol -p plugins -f io-uring-6.1.0-54-cloud-amd64.elf -s isf linux.io_uring.Registered
PID  Process     RingFD  Kind         Index  Address         Size  Detail                Note
88   uring_demo  3       file         0      0x898ac2736d00  0     /data/registered.txt  not in fd table (closed)
88   uring_demo  3       file         1      0x898ac2736f00  0     socket:[10212]        not in fd table (closed)
88   uring_demo  3       buffer       0      0x410000        4096  1 bvecs
88   uring_demo  3       buffer       1      0x40e000        8192  2 bvecs
88   uring_demo  3       personality  1      0x898adf191f00  0     uid=0 euid=0 gid=0    process uid is 1000
```

Full output of every plugin on both samples: [docs/usage.md](docs/usage.md). Design, validation and
limits: [docs/writeup.md](docs/writeup.md).

## Install and run

```
pip install volatility3          # tested with 2.28.2, the current PyPI release
git clone https://github.com/DesignMaster-Solutions/vol3-io-uring
vol -p vol3-io-uring/plugins -f <memory image> linux.io_uring.IoUring
```

The plugin is one file, `plugins/linux/io_uring.py`, with no dependency beyond Volatility 3.
It needs the usual Linux symbol table (ISF) for the kernel of the image.

## Tested kernels

| Kernel | Sample | Result |
|---|---|---|
| Debian 6.1.0-54-cloud-amd64 (6.1.190, bookworm) | `io-uring-6.1.0-54-cloud-amd64.elf` | all 4 plugins match the guest ground truth (pytest) |
| Debian 6.12.115+deb13.1-cloud-amd64 (trixie) | `io-uring-6.12.115+deb13.1-cloud-amd64.elf` | all 4 plugins match the guest ground truth (pytest) |

Kernel differences handled: `io_mapped_ubuf` stores `ubuf_end` on 6.1 and `len` on 6.10+;
`dummy_ubuf` exists only on older kernels. SQE and CQE are parsed with their UAPI layout
(stable since 5.1), including the 128-byte SQE and 32-byte CQE modes.

Not covered yet: the registered files/buffers layout introduced in 6.13 (`io_rsrc_node`
tables); on those kernels `Registered` warns and shows nothing, the other plugins are expected
to work but were not tested. Rings created with `IORING_SETUP_NO_MMAP` or `NO_SQARRAY` are handled
in code but not in the sample. Provided buffer rings (`io_bl`), linked timeouts and the io-wq
worker threads are not shown. `Target` resolves the fd against the fd table at dump time, which
may differ from the fd table at submission time.

## Memory samples

`sample/` rebuilds everything from scratch with Docker and QEMU (TCG, no KVM): it downloads the
Debian kernel and its debug symbols, builds a static benign workload
([sample/guest/uring_demo.c](sample/guest/uring_demo.c)) into an Alpine initramfs, boots it,
waits for `GUEST_READY_FOR_DUMP` on the serial console and dumps guest memory over QMP. The guest
runs four processes: a TCP listener on 127.0.0.1:4444, a ring that does OPENAT+READ of a file and
SOCKET+CONNECT+SEND to the listener (two completions left unread), an SQPOLL ring, and a ring
with two registered files (fds closed afterwards), two registered buffers and a personality
registered as root before the process drops to uid 1000. Each process prints its ground truth as
`TRUTH {json}` lines on the serial console, kept in `sample/expected/`.

```
sample/build_sample.sh                                                    # 6.1 (bookworm)
SUITE=trixie KVER=6.12.115+deb13.1-cloud-amd64 sample/build_sample.sh     # 6.12
```

QEMU runs with `-cpu max,la57=off`: under TCG `-cpu max` enables 5-level paging, which
Volatility 3 does not translate (`linux.pslist` then returns nothing).

Prebuilt samples and ISFs are in the
[v0.1.0 release](https://github.com/DesignMaster-Solutions/vol3-io-uring/releases/tag/v0.1.0):

| File | sha256 |
|---|---|
| SHA256_TABLE | |

## Tests

```
python -m venv .venv && .venv/bin/pip install volatility3 pytest
.venv/bin/python -m pytest tests          # skips a kernel whose sample is not in sample/work/
tests/mutants/run_mutants.sh              # every mutant must be KILLED
```

`tests/test_plugins.py` runs the real `vol` CLI on each sample and compares every row with the
serial ground truth. `tests/mutants/run_mutants.sh` breaks the plugin one line at a time (SQE/CQE
offset, field order, CQE size, pending logic, pointer tag mask, xarray index, SQPOLL thread id,
head, flag table, sockaddr decoding, closed-file and personality notes) and checks that the suite
fails on each one.

## Status

Built for the 2026 Volatility Plugin Contest. Author: Alan De Bortolo, Design Master Solutions LLC.
License: Volatility Software License 1.0 (same as Volatility 3).
