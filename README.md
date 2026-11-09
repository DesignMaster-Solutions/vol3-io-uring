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
88   uring_demo  3       file         0      0x8cf442505700  0     /data/registered.txt  not in fd table (closed)
88   uring_demo  3       file         1      0x8cf442505600  0     socket:[10212]        not in fd table (closed)
88   uring_demo  3       buffer       0      0x411000        4096  1 bvecs
88   uring_demo  3       buffer       1      0x40f000        8192  2 bvecs
88   uring_demo  3       personality  1      0x8cf45ffc46c0  0     uid=0 euid=0 gid=0    process uid is 1000
```

Full output of every plugin on every sample: [docs/usage.md](docs/usage.md). Design, validation and
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
| Debian 6.1.0-54-cloud-amd64 (6.1.190, bookworm) | `io-uring-6.1.0-54-cloud-amd64.elf` | all 4 plugins match the guest ground truth and the kernel fdinfo (pytest) |
| Debian 6.12.115+deb13.1-cloud-amd64 (trixie) | `io-uring-6.12.115+deb13.1-cloud-amd64.elf` | all 4 plugins match the guest ground truth and the kernel fdinfo (pytest) |
| Debian 7.2.11+deb13-cloud-amd64 (trixie-backports) | `io-uring-7.2.11+deb13-cloud-amd64.elf` | all 4 plugins match the guest ground truth and the kernel fdinfo (pytest) |
| Debian 5.10.0-32-cloud-amd64 (5.10.223, bullseye) | `io-uring-5.10.0-32-cloud-amd64.elf` | all 4 plugins match the guest ground truth; fdinfo checked where 5.10 prints it (see below) |

The 5.10 result is for Debian's 5.10.y, which since 5.10.162 carries the io_uring code of 5.15 (structures close
to 6.1). A 5.10 kernel without that backport (5.10.0 to 5.10.161, or a vendor tree that did not take it) was not
tested and is not claimed. On 5.10:

- The ISF has no `enum io_uring_op` (the enum is anonymous there), so opcode names come from the UAPI numbering in
  the plugin (`UAPI_OPS`, checked by a test against the enum of every ISF that has one).
- `IORING_OP_SOCKET` (5.19) does not exist: the guest's SOCKET SQE completes with `EINVAL`, which `Cqes` shows,
  and the guest gets its socket from `socket(2)` for the CONNECT and SEND that follow.
- The kernel's fdinfo prints no ring indexes, no SQE/CQE lists, and printed `SqThread: -1` for the live SQPOLL
  thread, so on this kernel the queue positions, pending CQEs and SQPOLL thread are checked against the guest
  ground truth only; `UserFiles`, `UserBufs` and `Personalities` are still checked against fdinfo.

Last run: 44 tests passed on the four samples, 2026-11-09, Volatility 3 2.28.2; mutants: 13/13 killed on the
three 6.x/7.x samples (2026-11-05); on 5.10, 13 of 14 killed (2026-11-09, with the new UAPI-table mutant): the
xarray-index mutant survives there because the only xarray in that sample (the personalities, one entry at index 1)
has a single node with shift 0, where the mutant computes the same index; the 6.x/7.x samples kill it.

Kernel differences handled, by member presence: registered files and buffers live in
`file_table.files[]`/`user_bufs[]` up to 6.12 and in `io_rsrc_node` tables (`file_table.data`,
`buf_table`) from 6.13; `io_mapped_ubuf` stores `ubuf_end` on 6.1 and `len` on 6.10+; `dummy_ubuf`
exists only on older kernels; the `restricted` bitfield became `restrictions.op_registered`/`reg_registered`. SQE and CQE are parsed with their UAPI layout
(stable since 5.1), including the 128-byte SQE and 32-byte CQE modes.

Not covered yet: rings created with `IORING_SETUP_NO_MMAP` or `NO_SQARRAY` are handled
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
`TRUTH {json}` lines on the serial console, and copies the kernel's own description of its ring
(`/proc/self/fdinfo/<ring fd>`, written by `io_uring/fdinfo.c`) as `FDINFO` lines; both are kept in
`sample/expected/`.

```
sample/build_sample.sh                                                    # 6.1 (bookworm)
SUITE=trixie KVER=6.12.115+deb13.1-cloud-amd64 sample/build_sample.sh     # 6.12
SUITE=trixie KVER=7.2.11+deb13-cloud-amd64 \
  APT_SOURCE="deb http://deb.debian.org/debian trixie-backports main" sample/build_sample.sh  # 7.2
KVER=5.10.0-32-cloud-amd64 \
  APT_SOURCE="deb [arch=amd64] http://deb.debian.org/debian bullseye main" sample/build_sample.sh  # 5.10
```

About the 5.10 line: the 5.10 sample in the v0.3.0 release reused the Debian 5.10.0-32 kernel
packages that the vol3-keyring builder had already downloaded, and its ISF was generated with
dwarf2json on the host, at the revision the builder pins, because the container ran out of memory
on the debug kernel. On 2026-11-09 that command line was re-run end to end from a clean checkout
(Docker Desktop on an arm64 Mac, 8 GB VM; under 3 minutes): the builder downloaded
`linux-image-5.10.0-32-cloud-amd64` 5.10.223-1 and its `-dbg` package from bullseye, booted and
dumped the guest, and dwarf2json 9f14607 finished inside the container. The ISF it produced is
byte-identical to the released `5.10.0-32-cloud-amd64.json.xz` (sha256 below), and the 14 tests for
5.10 pass on the new dump against its own serial log. The dump itself is not reproducible byte for
byte (addresses and timing change per boot), so the released image stays the reference.

QEMU runs with `-cpu max,la57=off`: under TCG `-cpu max` enables 5-level paging, which
Volatility 3 2.28.2 does not translate (`linux.pslist` then returns nothing).

Prebuilt samples and ISFs are in the
[v0.2.0 release](https://github.com/DesignMaster-Solutions/vol3-io-uring/releases/tag/v0.2.0) (6.1, 6.12, 7.2) and the
[v0.3.0 release](https://github.com/DesignMaster-Solutions/vol3-io-uring/releases/tag/v0.3.0) (5.10):

| File | sha256 |
|---|---|
| `io-uring-6.1.0-54-cloud-amd64.elf.zst` (35.8 MB, 512 MB raw) | `251139ad1a4f613bd0d075d1208201841763f6f889c6bafcd810ff008c13b23d` |
| `io-uring-6.12.115.deb13.1-cloud-amd64.elf.zst` (38.1 MB, 512 MB raw) | `c0661096f43a68aeb5c75f15edce8db53ca6c54b2b4b0cf503cc40421fda9b5d` |
| `io-uring-7.2.11.deb13-cloud-amd64.elf.zst` (44.0 MB, 512 MB raw) | `a036bcbd593821d3fcdf6ea1905d0980d52e37c3b099351df3f4df0c283f6b0f` |
| `6.1.0-54-cloud-amd64.json.xz` (ISF) | `eac7405bd2483d2113134dbe13422ad981c5604dee74d33c8925ac53c8f1b3c2` |
| `6.12.115.deb13.1-cloud-amd64.json.xz` (ISF) | `a0a2de67b04d39cbb9b3747b7b134a99f9cff4108ef23b6ef0387c70fc750abb` |
| `7.2.11.deb13-cloud-amd64.json.xz` (ISF) | `c5df4337632b15b78b07f7536239aad114ae3541647c0ab1ad8c2708b1b9a595` |
| `io-uring-5.10.0-32-cloud-amd64.elf.zst` (v0.3.0, 31.0 MB, 512 MB raw) | `0837dac274f33e1c79d5dba3ccbc2ca540b6d46cbefb14b37e4f2d72564d6576` |
| `5.10.0-32-cloud-amd64.json.xz` (v0.3.0, ISF) | `3f857fb970afdf8301a364fad653bcb96bd5dfa604a77a355a1248ba76a50f47` |

Asset names use `.` where the kernel name has `+` (GitHub rewrites `+`). Uncompressed sha256 of the
images: `sample/expected/*.sha256`. To run the tests on them: `zstd -d` each image into `sample/work/`
as `io-uring-<kernel>.elf` (kernel name with `+`) and put the ISFs in `sample/work/isf/linux/`;
`sample/fetch.sh` does all of it and checks every sha256 (needs `curl`, `zstd` and `python3`).

## Tests

CI runs the first three lines on every push:
[![ci](https://github.com/DesignMaster-Solutions/vol3-io-uring/actions/workflows/ci.yml/badge.svg)](https://github.com/DesignMaster-Solutions/vol3-io-uring/actions/workflows/ci.yml)

```
python -m venv .venv && .venv/bin/pip install volatility3 pytest
sample/fetch.sh                           # the four release samples and ISFs into sample/work/
.venv/bin/python -m pytest tests          # skips a kernel whose sample is not in sample/work/
tests/mutants/run_mutants.sh              # every mutant must be KILLED
```

`tests/test_plugins.py` runs the real `vol` CLI on each sample and compares every row with the
serial ground truth; `tests/test_fdinfo.py` compares queue positions, SQPOLL thread, pending CQEs,
registered files, buffers and personalities with what the kernel itself printed in fdinfo. `tests/mutants/run_mutants.sh` breaks the plugin one line at a time (SQE/CQE
offset, field order, CQE size, pending logic, pointer tag mask, xarray index, SQPOLL thread id,
head, flag table, sockaddr decoding, closed-file and personality notes) and checks that the suite
fails on each one.

## Status

Built for the 2026 Volatility Plugin Contest. Author: Alan De Bortolo, Design Master Solutions LLC.
License: Volatility Software License 1.0, the license of Volatility 3 ([LICENSE.txt](LICENSE.txt)).
