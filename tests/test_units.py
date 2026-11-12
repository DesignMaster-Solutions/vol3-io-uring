import os
import pathlib
import sys

_plugins = os.environ.get("PLUGINS", str(pathlib.Path(__file__).resolve().parent.parent / "plugins"))
sys.path.insert(0, str(pathlib.Path(_plugins) / "linux"))  # PLUGINS lets the mutant runner swap the module
import io_uring  # noqa: E402


def test_decode_flags():
    assert io_uring.decode_flags(0, io_uring.SETUP_FLAGS) == "-"
    assert io_uring.decode_flags(2, io_uring.SETUP_FLAGS) == "SQPOLL"
    assert io_uring.decode_flags((1 << 13) | 1, io_uring.SETUP_FLAGS) == "IOPOLL|DEFER_TASKRUN"
    assert io_uring.decode_flags(1 << 30, io_uring.SQE_FLAGS) == hex(1 << 30)


def test_decode_sockaddr():
    assert io_uring.decode_sockaddr(bytes([2, 0, 0x11, 0x5C, 127, 0, 0, 1]) + bytes(8)) == "127.0.0.1:4444"
    v6 = bytes([10, 0, 0, 80]) + bytes(4) + bytes(15) + b"\x01" + bytes(4)
    assert io_uring.decode_sockaddr(v6) == "[::1]:80"
    assert io_uring.decode_sockaddr(b"\x01\x00/run/x.sock\x00") == "unix:/run/x.sock"
    assert io_uring.decode_sockaddr(b"\x02") == ""


def test_sqe_layout_is_uapi():
    assert io_uring.SQE_FMT.size == 56 and io_uring.CQE_FMT.size == 16


class _Node:
    def __init__(self, shift, slots):
        self.shift, self.slots = shift, slots + [0] * (64 - len(slots))


class _Ctx:
    """Fake context: context.object() returns the xa_node stored at that address."""

    def __init__(self, nodes):
        self.nodes = nodes

    def object(self, _type, layer_name, offset):
        return self.nodes[offset]


def test_xarray_two_level_indices():
    # root (shift 6) -> slot 1 is an internal node (tag 2) whose slot 2 holds entry 0x5000: index 1*64 + 2
    nodes = {0x1000: _Node(6, [0x7000, 0x2002]), 0x2000: _Node(0, [0, 0, 0x5000, 0x6000])}
    items = list(io_uring.IoUring._xa_node(_Ctx(nodes), "t", "l", 0x1000, 0))
    assert items == [(0, 0x7000), (66, 0x5000), (67, 0x6000)]


def test_buffer_span():
    span = io_uring.buffer_span
    assert span("SEND", 20, 20) == ("out", 20, "")
    assert span("WRITE", 20, 7) == ("out", 20, "short: kernel took 7 of 20")
    assert span("SEND", 20, -32) == ("out", 20, "failed: EPIPE")
    assert span("SEND", 20, None) == ("out", 20, "no completion in ring")
    assert span("READ", 64, 38) == ("in", 38, "")  # only what the kernel filled, not the whole buffer
    assert span("RECV", 64, 64) == ("in", 64, "")
    assert span("READ", 64, 0) == ("in", 0, "nothing received")
    assert span("READ", 64, -9) == ("in", 0, "failed: EBADF")
    assert span("READ_FIXED", 64, None) == ("in", 64, "no completion in ring: whole buffer shown")
    assert span("CONNECT", 16, 0) == ("", 0, "")  # not a data buffer


def test_printable():
    assert io_uring.printable(b"hi\n") == "hi\\n"
    assert io_uring.printable(b"a\\b\t\r") == "a\\\\b\\t\\r"
    assert io_uring.printable(bytes([0, 0x7F, 0xFF, 0x20, 0x7E])) == "\\x00\\x7f\\xff ~"
