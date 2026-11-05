import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "plugins" / "linux"))
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
