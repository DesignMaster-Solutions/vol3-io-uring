# vol3-io-uring: write-up

## Why

io_uring is a Linux interface in which a process writes requests into a ring shared with the
kernel and reads results from a second ring. One `io_uring_enter` call can submit many
operations, and with `IORING_SETUP_SQPOLL` a kernel thread submits them with no system call at
all. Opening files, reading, writing, creating sockets, connecting, sending and receiving all
exist as io_uring opcodes.

Runtime security tools mostly watch system calls. In April 2025 ARMO released
[Curing](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/), a
proof-of-concept rootkit that talks to its server and runs commands only through io_uring, and
showed that Falco and Microsoft Defender for Endpoint on Linux did not detect it. Google
[restricted io_uring](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html)
in ChromeOS, Android apps and its production servers after 60% of the exploits submitted to its
kCTF VRP targeted io_uring.

When the syscall trace is missing, memory still has the answer. Every ring is a kernel object
(`struct io_ring_ctx`) reachable from the process fd table, and its SQ and CQ live in kernel
pages. Before this project, Volatility 3 could not see any of it: `linux.lsof` shows an
`anon_inode:[io_uring]` and nothing more.

## What the plugins show

* `linux.io_uring.IoUring`: every ring, its setup flags, sizes, queue positions, pending work,
  the SQPOLL kernel thread and the uid it submits with, and how many files, buffers and
  personalities are registered.
* `linux.io_uring.Sqes`: the submissions still in ring memory. The kernel does not clear SQE
  slots after consuming them, so a ring keeps the last `sq_entries` submissions: the closest
  thing to an io_uring command history. Each row has the opcode name, the fd and what it points to,
  and for path and connect opcodes the path or destination read from process memory.
* `linux.io_uring.Cqes`: completions with their result decoded (fd, byte count, errno name) and
  tied back to the submission through `user_data`, `pending` when the application has not read
  them yet.
* `linux.io_uring.Registered`: registered files, flagged when the fd was closed afterwards (the
  process keeps access through the ring and `lsof` no longer shows the file), registered buffers
  and personalities, flagged when the registered credentials differ from the process's current ones
  (registered as root, then dropped to an unprivileged uid).

The plugins are read-only and show metadata: paths, socket addresses, sizes, credentials ids.
They never dump the contents of read/write/send buffers.

## Design

1. Rings are found the way the kernel finds them: for every process, every fd whose
   `file->f_op` is `io_uring_fops`; `file->private_data` is the `io_ring_ctx`. No scanning, no
   signatures. Anonymous structs and unions in `io_ring_ctx` are flattened by Volatility, so
   `ctx.rings`, `ctx.sq_sqes` and `ctx.flags` work across layouts.
2. SQEs and CQEs are parsed from raw bytes with their UAPI layout (`include/uapi/linux/io_uring.h`),
   which has not changed since 5.1, instead of the DWARF unions, whose names vary by kernel.
   `SQE128` and `CQE32` rings use 128-byte and 32-byte slots. Pending SQEs are found through
   `sq_array` (or directly when `NO_SQARRAY` is set), pending CQEs from `cq.head`..`cq.tail`.
3. Opcode names come from the `io_uring_op` enum of the kernel's own symbol table, so a new opcode
   in a new kernel gets its correct name without changing the plugin.
4. Registered files are tagged pointers (`FFS_NOWAIT`/`FFS_ISREG` in the low bits) and are
   masked before use; paths are resolved with Volatility's `LinuxUtilities.path_for_file`, the
   same code `linux.lsof` uses. Personalities are an xarray walked with indices, since the index
   is the personality id.
5. Kernel differences are handled by member presence, not version numbers (`len` vs `ubuf_end`,
   `dummy_ubuf`). A layout the plugin does not know yet produces a warning, not wrong rows.

## Validation

The memory samples are built by `sample/build_sample.sh` from public Debian kernels with debug
symbols and a short benign C program (`sample/guest/uring_demo.c`) that uses raw io_uring
system calls. Every action it takes is printed on the serial console as a JSON `TRUTH` line
(pid, ring fd, flags, each SQE and CQE, registered files, buffers and personality, final head and
tail). The serial logs are versioned in `sample/expected/`.

`tests/test_plugins.py` runs the real `vol` command on each sample and checks every row against
that truth: one row per ring with the right sizes, flags and positions, the SQPOLL thread id, each
SQE's opcode (against the UAPI numbers, not the enum the plugin uses), fd, length, `user_data`,
personality and buffer index, resolved path and address, each CQE's result and pending state,
registered file paths, closed-fd notes, buffer addresses and sizes, personality id and uid.

To show that the tests catch real reading errors, `tests/mutants/run_mutants.sh` applies one-line
breaks to the plugin (SQE offset, SQE field order, CQE size and offset, pending logic, pointer tag
mask, xarray index, SQPOLL thread id, CQ head, setup flag table, sockaddr decoding, the closed-file
and personality notes) and requires the suite to fail on each: 13 of 13 killed on 2026-11-05.

A second, independent truth comes from the kernel itself: the guest copies
`/proc/self/fdinfo/<ring fd>` (written by `io_uring/fdinfo.c`) to the serial console, and
`tests/test_fdinfo.py` checks that the plugins read the same head/tail, SQPOLL thread id, pending
CQEs, registered buffers (address/size), file names and personality uids from the memory image.

Both samples pass (22 tests, 2026-11-05): Debian 6.1 (bookworm) and Debian 6.12 (trixie), Volatility 3 2.28.2.

## Limits

* Kernels 6.13 and later store registered files and buffers in `io_rsrc_node` tables; `Registered`
  warns and shows nothing there. The other plugins were not tested on those kernels.
* SQE slots are overwritten as the ring wraps: only the last `sq_entries` submissions remain.
  Kernels copy SQEs before async execution, so a consumed slot is history, not proof of completion;
  `Cqes` is the place to check results.
* Paths and addresses read from process memory can be paged out (`(paged out)`), and `Target`
  uses the fd table at dump time.
* Not shown yet: provided buffer rings, io-wq worker threads, linked timeouts, `MSG_RING` targets,
  restriction bitmaps in detail.

## Why it should matter to the contest

* Creativity: io_uring is a documented way (ARMO's Curing) to act on a Linux host without the
  syscalls that monitoring relies on; there was no memory-forensics view of it in Volatility 3 or community3.
* Usefulness: an analyst gets, from a memory image, which processes use io_uring, what they asked
  for (paths, destinations, opcodes), whether a SQPOLL thread acts for them, and access kept through
  registered files after the fd was closed or credentials kept after a privilege drop.
* Effort: a reproducible sample pipeline (Docker + QEMU, two Debian LTS kernels, ground truth on
  the serial console) and a mutation script, besides the plugins themselves.
* Clarity of documentation: README, docs/usage.md with the real output of every plugin on both
  samples, and this write-up.
* Completeness: four plugins, two LTS kernels, a reproducible sample with ground truth, tests that
  are shown to fail on wrong reads, no dependency beyond Volatility 3.
