# vol3-io-uring: io_uring visibility for Volatility 3.
# Copyright (c) 2026 Alan De Bortolo, Design Master Solutions LLC. Licensed under the
# Volatility Software License (VSL) 1.0, the license of Volatility 3.
"""Plugins that show what processes asked the kernel to do through io_uring.

The kernel keeps every ring in memory: a ``struct file`` whose ``f_op`` is
``io_uring_fops`` and whose ``private_data`` is the ``struct io_ring_ctx``. From the
context we read the setup flags, the SQ/CQ rings, the submission entries (SQEs), the
completion entries (CQEs), the SQPOLL thread and the registered files, buffers and
personalities.
"""
import logging
import socket
import struct
from typing import Dict, Iterator, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

# include/uapi/linux/io_uring.h (stable UAPI, not in DWARF because they are #defines)
SETUP_FLAGS = [
    "IOPOLL", "SQPOLL", "SQ_AFF", "CQSIZE", "CLAMP", "ATTACH_WQ", "R_DISABLED", "SUBMIT_ALL",
    "COOP_TASKRUN", "TASKRUN_FLAG", "SQE128", "CQE32", "SINGLE_ISSUER", "DEFER_TASKRUN",
    "NO_MMAP", "REGISTERED_FD_ONLY", "NO_SQARRAY", "HYBRID_IOPOLL",
]
# enum io_uring_op up to 6.1 (include/uapi/linux/io_uring.h), for ISFs without the enum
UAPI_OPS = [
    "NOP", "READV", "WRITEV", "FSYNC", "READ_FIXED", "WRITE_FIXED", "POLL_ADD", "POLL_REMOVE", "SYNC_FILE_RANGE",
    "SENDMSG", "RECVMSG", "TIMEOUT", "TIMEOUT_REMOVE", "ACCEPT", "ASYNC_CANCEL", "LINK_TIMEOUT", "CONNECT",
    "FALLOCATE", "OPENAT", "CLOSE", "FILES_UPDATE", "STATX", "READ", "WRITE", "FADVISE", "MADVISE", "SEND", "RECV",
    "OPENAT2", "EPOLL_CTL", "SPLICE", "PROVIDE_BUFFERS", "REMOVE_BUFFERS", "TEE", "SHUTDOWN", "RENAMEAT", "UNLINKAT",
    "MKDIRAT", "SYMLINKAT", "LINKAT", "MSG_RING", "FSETXATTR", "SETXATTR", "FGETXATTR", "GETXATTR", "SOCKET",
    "URING_CMD", "SEND_ZC", "SENDMSG_ZC",
]
SQE_FLAGS = ["FIXED_FILE", "IO_DRAIN", "IO_LINK", "IO_HARDLINK", "ASYNC", "BUFFER_SELECT", "CQE_SKIP_SUCCESS"]
SETUP_SQE128, SETUP_CQE32, SETUP_NO_SQARRAY = 1 << 10, 1 << 11, 1 << 16
SQE_FIXED_FILE = 1
AT_FDCWD = -100
# Linux errno numbers (the host running Volatility may use different ones, e.g. macOS)
LINUX_ERRNO = {
    1: "EPERM", 2: "ENOENT", 4: "EINTR", 5: "EIO", 9: "EBADF", 11: "EAGAIN", 12: "ENOMEM",
    13: "EACCES", 14: "EFAULT", 16: "EBUSY", 17: "EEXIST", 20: "ENOTDIR", 21: "EISDIR",
    22: "EINVAL", 24: "EMFILE", 28: "ENOSPC", 32: "EPIPE", 95: "EOPNOTSUPP", 97: "EAFNOSUPPORT",
    98: "EADDRINUSE", 99: "EADDRNOTAVAIL", 101: "ENETUNREACH", 104: "ECONNRESET", 107: "ENOTCONN",
    110: "ETIMEDOUT", 111: "ECONNREFUSED", 113: "EHOSTUNREACH", 114: "EALREADY", 115: "EINPROGRESS",
    125: "ECANCELED",
}
AF_NAMES = {1: "AF_UNIX", 2: "AF_INET", 10: "AF_INET6", 16: "AF_NETLINK", 17: "AF_PACKET"}
SOCK_TYPES = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 5: "SOCK_SEQPACKET"}


def decode_flags(value: int, names: List[str]) -> str:
    out = [n for i, n in enumerate(names) if value & (1 << i)]
    rest = value & ~((1 << len(names)) - 1)
    if rest:
        out.append(hex(rest))
    return "|".join(out) if out else "-"


def decode_sockaddr(data: bytes) -> str:
    if len(data) < 2:
        return ""
    family = struct.unpack_from("<H", data)[0]
    if family == 2 and len(data) >= 8:
        port = struct.unpack_from(">H", data, 2)[0]
        return f"{socket.inet_ntoa(data[4:8])}:{port}"
    if family == 10 and len(data) >= 24:
        port = struct.unpack_from(">H", data, 2)[0]
        return f"[{socket.inet_ntop(socket.AF_INET6, data[8:24])}]:{port}"
    if family == 1:
        return "unix:" + data[2:].split(b"\0", 1)[0].decode("utf-8", "replace")
    return AF_NAMES.get(family, f"family {family}")


class IoUring(interfaces.plugins.PluginInterface):
    """Lists io_uring instances (one row per ring) with flags, queue state, SQPOLL thread and registrations."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel",
                                           architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(4, 0, 0)),
            requirements.VersionRequirement(name="linuxutils", component=linux.LinuxUtilities,
                                            version=(2, 0, 0)),
            requirements.ListRequirement(name="pid", description="Filter on specific process IDs",
                                         element_type=int, optional=True),
        ]

    # ---- shared helpers (used by Sqes, Cqes and Registered) ----

    @staticmethod
    def symbol_table(task) -> str:
        return task.vol.type_name.split(constants.BANG)[0]

    @classmethod
    def list_rings(cls, context, kernel_name: str, filter_func=lambda _: False
                   ) -> Iterator[Tuple[interfaces.objects.ObjectInterface, int, interfaces.objects.ObjectInterface]]:
        """Yields (task, ring fd, io_ring_ctx) for every io_uring file in every process fd table."""
        vmlinux = context.modules[kernel_name]
        fops = vmlinux.object_from_symbol("io_uring_fops").vol.offset
        for task in pslist.PsList.list_tasks(context, kernel_name, filter_func, include_threads=False):
            fds = linux.LinuxUtilities.files_descriptors_for_process(context, cls.symbol_table(task), task)
            for fd, filp, _path in fds or []:
                try:
                    if filp.f_op != fops or not filp.private_data:
                        continue
                    ctx = vmlinux.object("io_ring_ctx", offset=filp.private_data, absolute=True)
                except exceptions.InvalidAddressException:
                    continue
                yield task, fd, ctx

    @staticmethod
    def uid(kid) -> int:
        return int(kid.val) if hasattr(kid, "val") else int(kid)

    @classmethod
    def sqpoll_thread(cls, ctx) -> Tuple[Optional[int], str]:
        if not ctx.sq_data:
            return None, ""
        sqd = ctx.sq_data.dereference()
        if sqd.thread and sqd.thread.is_readable():
            th = sqd.thread.dereference()
            return int(th.pid), utility.array_to_string(th.comm)
        return int(sqd.task_pid), "(exited)"

    @staticmethod
    def _ptr_array(context, ctx, base: int, count: int) -> Iterator[Tuple[int, int]]:
        """(index, value) for every non-null 8-byte slot of an in-kernel array."""
        layer = context.layers[ctx.vol.layer_name]
        for i in range(min(count, 1 << 16)):
            try:
                v = struct.unpack("<Q", layer.read(base + i * 8, 8))[0]
            except exceptions.InvalidAddressException:
                continue
            if v:
                yield i, v

    @classmethod
    def _rsrc_slots(cls, context, ctx, kind: str) -> Iterator[Tuple[int, int]]:
        """(index, value) of registered files ('file': tagged struct file *) or buffers ('buf': io_mapped_ubuf *).
        5.x-6.12: ctx->file_table.files[] (io_fixed_file) and ctx->user_bufs[].
        6.13+: ctx->file_table.data / ctx->buf_table (io_rsrc_data), nodes[] of io_rsrc_node holding the pointer."""
        table = ctx.vol.type_name.split(constants.BANG)[0]
        if ctx.has_member("nr_user_files"):
            if kind == "file":
                yield from cls._ptr_array(context, ctx, int(ctx.file_table.files), int(ctx.nr_user_files))
            else:
                dummy = int(ctx.dummy_ubuf) if ctx.has_member("dummy_ubuf") else 0  # 6.1: unset slot marker
                for i, v in cls._ptr_array(context, ctx, int(ctx.user_bufs), int(ctx.nr_user_bufs)):
                    if v != dummy:
                        yield i, v
            return
        data = ctx.file_table.data if kind == "file" else ctx.buf_table
        member = "file_ptr" if kind == "file" else "buf"
        for i, node in cls._ptr_array(context, ctx, int(data.nodes), int(data.nr)):
            n = context.object(table + constants.BANG + "io_rsrc_node", layer_name=ctx.vol.layer_name, offset=node)
            yield i, int(getattr(n, member))

    @classmethod
    def fixed_files(cls, context, ctx) -> List[Tuple[int, interfaces.objects.ObjectInterface]]:
        """Registered (fixed) files as (index, struct file)."""
        table = ctx.vol.type_name.split(constants.BANG)[0]
        return [(i, context.object(table + constants.BANG + "file", layer_name=ctx.vol.layer_name, offset=v & ~0x7))
                for i, v in cls._rsrc_slots(context, ctx, "file") if v & ~0x7]  # FFS_* tag bits

    @classmethod
    def fixed_buffers(cls, context, ctx) -> List[Tuple[int, int, int, int]]:
        """Registered buffers as (index, user address, length, nr_bvecs)."""
        table = ctx.vol.type_name.split(constants.BANG)[0]
        out = []
        for i, v in cls._rsrc_slots(context, ctx, "buf"):
            ub = context.object(table + constants.BANG + "io_mapped_ubuf", layer_name=ctx.vol.layer_name, offset=v)
            # 6.1 stores ubuf_end, 6.10+ stores len
            size = int(ub.len) if ub.has_member("len") else int(ub.ubuf_end) - int(ub.ubuf)
            out.append((i, int(ub.ubuf), size, int(ub.nr_bvecs)))
        return out

    @staticmethod
    def restricted(ctx) -> bool:
        if ctx.has_member("restricted"):  # bitfield up to 6.x
            return bool(ctx.restricted)
        r = ctx.restrictions
        return any(bool(getattr(r, m)) for m in ("registered", "op_registered", "reg_registered") if r.has_member(m))

    @classmethod
    def xarray_items(cls, context, xa, depth: int = 0) -> Iterator[Tuple[int, int]]:
        """Walks a struct xarray yielding (index, entry pointer)."""
        head = int(xa.xa_head)
        if not head:
            return
        if head & 3 != 2 or head < 4096:  # single entry stored at index 0
            yield 0, head
            return
        table = xa.vol.type_name.split(constants.BANG)[0]
        yield from cls._xa_node(context, table, xa.vol.layer_name, head - 2, 0)

    @classmethod
    def _xa_node(cls, context, table, layer, addr, base, depth=0) -> Iterator[Tuple[int, int]]:
        if depth > 8:
            return
        node = context.object(table + constants.BANG + "xa_node", layer_name=layer, offset=addr)
        shift = int(node.shift)
        for off, slot in enumerate(node.slots):
            slot = int(slot)
            if not slot:
                continue
            index = base + (off << shift)
            if slot & 3 == 2 and slot >= 4096 and shift:
                yield from cls._xa_node(context, table, layer, slot - 2, index, depth + 1)
            elif slot & 3 == 0:
                yield index, slot

    @classmethod
    def personalities(cls, context, ctx) -> List[Tuple[int, interfaces.objects.ObjectInterface]]:
        table = ctx.vol.type_name.split(constants.BANG)[0]
        return [(idx, context.object(table + constants.BANG + "cred", layer_name=ctx.vol.layer_name, offset=p))
                for idx, p in cls.xarray_items(context, ctx.personalities)]

    @classmethod
    def ring_state(cls, ctx) -> Dict[str, int]:
        rings = ctx.rings.dereference()
        return {"sq_head": int(rings.sq.head), "sq_tail": int(rings.sq.tail),
                "cq_head": int(rings.cq.head), "cq_tail": int(rings.cq.tail),
                "sq_mask": int(rings.sq_ring_mask), "cq_mask": int(rings.cq_ring_mask)}

    @classmethod
    def opcode_names(cls, context, kernel_name: str) -> Dict[int, str]:
        """IORING_OP_* names from the kernel's enum io_uring_op; kernels whose enum is anonymous (5.10) have none
        in the ISF, and then the UAPI numbering, which is ABI and never reused, names them."""

        try:
            enum = context.modules[kernel_name].get_enumeration("io_uring_op")
            return {v: k.replace("IORING_OP_", "") for k, v in enum.choices.items() if k != "IORING_OP_LAST"}
        except exceptions.SymbolError:
            return dict(enumerate(UAPI_OPS))

    # ---- plugin ----

    def _generator(self):
        filt = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for task, fd, ctx in self.list_rings(self.context, self.config["kernel"], filt):
            try:
                st = self.ring_state(ctx)
                sq_tid, sq_comm = self.sqpoll_thread(ctx)
                creds = ctx.sq_creds.dereference() if ctx.sq_creds else None
                row = (
                    int(task.pid), utility.array_to_string(task.comm), fd, format_hints.Hex(ctx.vol.offset),
                    decode_flags(int(ctx.flags), SETUP_FLAGS), int(ctx.sq_entries), int(ctx.cq_entries),
                    st["sq_head"], st["sq_tail"], (st["sq_tail"] - st["sq_head"]) & 0xFFFFFFFF,
                    st["cq_head"], st["cq_tail"], (st["cq_tail"] - st["cq_head"]) & 0xFFFFFFFF,
                    sq_tid if sq_tid is not None else renderers.NotApplicableValue(),
                    sq_comm or renderers.NotApplicableValue(),
                    self.uid(creds.uid) if creds else renderers.NotApplicableValue(),
                    len(self.fixed_files(self.context, ctx)), len(self.fixed_buffers(self.context, ctx)),
                    len(self.personalities(self.context, ctx)), self.restricted(ctx),
                )
            except exceptions.InvalidAddressException as e:
                vollog.debug(f"ring at fd {fd} of pid {task.pid}: {e}")
                continue
            yield 0, row

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("FD", int), ("Context", format_hints.Hex), ("SetupFlags", str),
             ("SQEntries", int), ("CQEntries", int), ("SQHead", int), ("SQTail", int), ("SQPending", int),
             ("CQHead", int), ("CQTail", int), ("CQPending", int), ("SQPollTID", int), ("SQPollThread", str),
             ("SQPollUID", int), ("RegFiles", int), ("RegBuffers", int), ("Personalities", int),
             ("Restricted", bool)],
            self._generator(),
        )


# ---- SQE / CQE parsing (UAPI layout, identical on every kernel since 5.1) ----

SQE_FMT = struct.Struct("<BBHiQQIIQHHiQ")  # opcode flags ioprio fd off addr len op_flags user_data buf_index personality file_index addr3
CQE_FMT = struct.Struct("<QiI")  # user_data res flags
PATH_OPS = {"OPENAT", "OPENAT2", "STATX", "UNLINKAT", "MKDIRAT", "RENAMEAT", "SYMLINKAT", "LINKAT"}
FD_RESULT_OPS = {"OPENAT", "OPENAT2", "SOCKET", "ACCEPT"}
NO_FD_OPS = {"NOP", "SOCKET"}  # sqe->fd is unused (NOP) or the address family (SOCKET)


class _FileRef:
    """Pointer-like view of a struct file for LinuxUtilities.path_for_file, which expects a `file *`.
    The fixed file table stores tagged pointers (FFS_* low bits), so no Pointer object exists in memory."""

    def __init__(self, filp):
        self._filp = filp

    def __getattr__(self, name):
        return getattr(self._filp, name)

    def __bool__(self):
        return True

    def __int__(self):
        return self._filp.vol.offset

    def __format__(self, spec):
        return format(self._filp.vol.offset, spec)

    def is_readable(self):
        layer = self._filp._context.layers[self._filp.vol.layer_name]
        return self._filp.vol.offset != 0 and layer.is_valid(self._filp.vol.offset, self._filp.vol.size)

    def dereference(self):
        return self._filp


class RingView:
    """Everything the Sqes/Cqes/Registered plugins need about one ring, read once."""

    def __init__(self, context, kernel_name, task, fd, ctx, opnames):
        self.context, self.task, self.fd, self.ctx, self.opnames = context, task, fd, ctx, opnames
        self.pid, self.comm = int(task.pid), utility.array_to_string(task.comm)
        self.layer = context.layers[ctx.vol.layer_name]
        self.flags = int(ctx.flags)
        self.state = IoUring.ring_state(ctx)
        self._proc_layer = None
        self.fd_paths, self.fd_by_file = {}, {}
        for num, filp, path in linux.LinuxUtilities.files_descriptors_for_process(
                context, IoUring.symbol_table(task), task) or []:
            self.fd_paths[num], self.fd_by_file[filp.vol.offset] = path, num
        self.fixed = {}
        for idx, filp in IoUring.fixed_files(context, ctx):
            self.fixed[idx] = (filp, linux.LinuxUtilities.path_for_file(context, task, _FileRef(filp)))

    def opname(self, op: int) -> str:
        return self.opnames.get(op, f"OP_{op}")

    def user_read(self, addr: int, size: int) -> Optional[bytes]:
        if self._proc_layer is None:
            self._proc_layer = self.task.add_process_layer() or ""
        if not self._proc_layer or not addr:
            return None
        try:
            return self.context.layers[self._proc_layer].read(addr, size, pad=False)
        except exceptions.InvalidAddressException:
            return None

    def sqes(self) -> Iterator[Tuple[int, str, tuple]]:
        """Yields (slot, status, fields) for every non-empty SQE slot."""
        size = 128 if self.flags & SETUP_SQE128 else 64
        st, n = self.state, int(self.ctx.sq_entries)
        array = None if self.flags & SETUP_NO_SQARRAY or not self.ctx.has_member("sq_array") else int(self.ctx.sq_array)
        pending = set()
        for i in range(st["sq_head"], st["sq_head"] + ((st["sq_tail"] - st["sq_head"]) & 0xFFFFFFFF)):
            idx = i & st["sq_mask"]
            pending.add(struct.unpack("<I", self.layer.read(array + idx * 4, 4))[0] if array else idx)
        base = int(self.ctx.sq_sqes)
        for slot in range(n):
            raw = self.layer.read(base + slot * size, size, pad=True)
            if not any(raw):
                continue
            yield slot, "pending" if slot in pending else "consumed", SQE_FMT.unpack_from(raw)

    def cqes(self) -> Iterator[Tuple[int, str, tuple]]:
        size = 32 if self.flags & SETUP_CQE32 else 16
        st = self.state
        base = self.ctx.rings + self.context.symbol_space.get_type(
            self.ctx.vol.type_name.split(constants.BANG)[0] + constants.BANG + "io_rings").relative_child_offset("cqes")
        pending = {i & st["cq_mask"] for i in range(st["cq_head"], st["cq_head"] + ((st["cq_tail"] - st["cq_head"]) & 0xFFFFFFFF))}
        for idx in range(int(self.ctx.cq_entries)):
            raw = self.layer.read(base + idx * size, size, pad=True)
            if not any(raw):
                continue
            yield idx, "pending" if idx in pending else "consumed", CQE_FMT.unpack_from(raw)

    def target(self, op: str, fd: int, sqe_flags: int) -> str:
        if sqe_flags & SQE_FIXED_FILE:
            f = self.fixed.get(fd)
            return f"fixed[{fd}] {f[1]}" if f else f"fixed[{fd}] (unset)"
        if fd == AT_FDCWD:
            return "AT_FDCWD"
        if op in NO_FD_OPS:
            return "-"
        return self.fd_paths.get(fd, "(not open now)") if fd >= 0 else "-"

    def detail(self, op: str, fd: int, off: int, addr: int, length: int) -> str:
        """Metadata only: paths and socket addresses, never data buffers."""
        if op in PATH_OPS:
            data = self.user_read(addr, 256)
            return "path=" + data.split(b"\0", 1)[0].decode("utf-8", "replace") if data else "path=(paged out)"
        if op == "CONNECT":
            data = self.user_read(addr, min(off or 16, 128))
            return "addr=" + decode_sockaddr(data) if data else "addr=(paged out)"
        if op == "SOCKET":
            return f"{AF_NAMES.get(fd, fd)} {SOCK_TYPES.get(off & 0xF, off)}"
        return ""


class _RingPlugin(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return IoUring.get_requirements()[:1] + [
            requirements.VersionRequirement(name="io_uring", component=IoUring, version=(1, 0, 0)),
        ] + IoUring.get_requirements()[1:]

    def rings(self) -> Iterator[RingView]:
        kname = self.config["kernel"]
        opnames = IoUring.opcode_names(self.context, kname)
        filt = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for task, fd, ctx in IoUring.list_rings(self.context, kname, filt):
            try:
                yield RingView(self.context, kname, task, fd, ctx, opnames)
            except exceptions.InvalidAddressException as e:
                vollog.debug(f"ring at fd {fd} of pid {task.pid}: {e}")


class Sqes(_RingPlugin):
    """Lists submission queue entries still in ring memory (pending and already consumed)."""

    def _generator(self):
        for r in self.rings():
            for slot, status, s in r.sqes():
                opcode, flags, _prio, fd, off, addr, length, _opf, user_data, buf_index, pers = s[:11]
                op = r.opname(opcode)
                yield 0, (r.pid, r.comm, r.fd, slot, status, op, decode_flags(flags, SQE_FLAGS), fd,
                          r.target(op, fd, flags), format_hints.Hex(addr), length, off,
                          format_hints.Hex(user_data), pers, buf_index, r.detail(op, fd, off, addr, length))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("RingFD", int), ("Slot", int), ("Status", str), ("Opcode", str),
             ("SQEFlags", str), ("FD", int), ("Target", str), ("Addr", format_hints.Hex), ("Len", int),
             ("Off", int), ("UserData", format_hints.Hex), ("Personality", int), ("BufIndex", int),
             ("Detail", str)],
            self._generator(),
        )


class Cqes(_RingPlugin):
    """Lists completion queue entries (result and user_data), matched to the SQE that produced them."""

    def _generator(self):
        for r in self.rings():
            ops = {s[8]: r.opname(s[0]) for _slot, _st, s in r.sqes()}
            for idx, status, (user_data, res, flags) in r.cqes():
                op = ops.get(user_data, "?")
                if res < 0:
                    text = LINUX_ERRNO.get(-res, f"errno {-res}")
                elif op in FD_RESULT_OPS:
                    text = f"fd {res}"
                else:
                    text = str(res)
                yield 0, (r.pid, r.comm, r.fd, idx, status, format_hints.Hex(user_data), op, res, text, flags)

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("RingFD", int), ("Index", int), ("Status", str),
             ("UserData", format_hints.Hex), ("Opcode", str), ("Res", int), ("Result", str), ("Flags", int)],
            self._generator(),
        )


class Registered(_RingPlugin):
    """Lists registered files (including ones closed in the fd table), buffers and personalities."""

    def _generator(self):
        for r in self.rings():
            for idx, (filp, path) in sorted(r.fixed.items()):
                fdnum = r.fd_by_file.get(filp.vol.offset)
                note = f"also fd {fdnum}" if fdnum is not None else "not in fd table (closed)"
                yield 0, (r.pid, r.comm, r.fd, "file", idx, format_hints.Hex(filp.vol.offset), 0, path, note)
            for idx, addr, size, nbv in IoUring.fixed_buffers(self.context, r.ctx):
                yield 0, (r.pid, r.comm, r.fd, "buffer", idx, format_hints.Hex(addr), size, f"{nbv} bvecs", "")
            task_uid = IoUring.uid(r.task.cred.uid)
            for pid_, cred in IoUring.personalities(self.context, r.ctx):
                uid, euid = IoUring.uid(cred.uid), IoUring.uid(cred.euid)
                note = f"process uid is {task_uid}" if uid != task_uid else ""
                yield 0, (r.pid, r.comm, r.fd, "personality", pid_, format_hints.Hex(cred.vol.offset), 0,
                          f"uid={uid} euid={euid} gid={IoUring.uid(cred.gid)}", note)

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("RingFD", int), ("Kind", str), ("Index", int),
             ("Address", format_hints.Hex), ("Size", int), ("Detail", str), ("Note", str)],
            self._generator(),
        )
