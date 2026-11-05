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

Volatility 3 has no io_uring support today, in core or in community3.

## Planned plugins

| Plugin | What it shows |
|---|---|
| `linux.io_uring.IoUring` | One row per ring: PID, process, fd, setup flags (SQPOLL, IOPOLL, DEFER_TASKRUN, ...), SQ/CQ sizes, head/tail and pending entries, SQPOLL thread and the credentials it runs with, counts of registered files, buffers and personalities, restrictions. |
| `linux.io_uring.Sqes` | The submission queue entries still in ring memory, including slots already consumed but not yet overwritten: opcode (`OPENAT`, `READ`, `WRITE`, `SOCKET`, `CONNECT`, `SEND`, `RECV`, ...), target fd resolved to a path or socket, address, length, `user_data`. The closest thing to an io_uring command history. |
| `linux.io_uring.Cqes` | Completion entries (result code and `user_data`), to tell which operations finished and how. |
| `linux.io_uring.Registered` | Registered files (paths and sockets, including ones already closed in the fd table), registered buffers (user address ranges) and personalities (credentials by id). |

## Memory sample

A reproducible QEMU guest (Debian kernel with debug symbols, symbol table built with
`dwarf2json`) running a small benign workload that exercises the opcodes above against a
listener inside the VM. The build script, the expected output and the hashes will live in
`sample/`.

## Status

In development for the 2026 Volatility Plugin Contest (deadline 31 December 2026). Nothing in
the table above is released yet. This README will list exactly what works, on which kernels it
was tested and what it does not cover.

Author: Alan De Bortolo, Design Master Solutions LLC.
