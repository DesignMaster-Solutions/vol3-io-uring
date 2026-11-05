"""Plugins checked against the kernel's own description of each ring (io_uring/fdinfo.c), not our program's."""
import re

import pytest


def section(lines, header):
    """Indented lines that follow `header:` until the next unindented key."""
    out, inside = [], False
    for ln in lines:
        if ln.startswith(header + ":"):
            inside = True
            continue
        if inside:
            if ln[:1] in (" ", "\t"):
                out.append(ln.strip())
            else:
                break
    return out


def value(lines, key):
    for ln in lines:
        if ln.startswith(key + ":"):
            return ln.split(":", 1)[1].strip()
    raise KeyError(key)


@pytest.fixture
def rings(sample):
    if not sample.fdinfo:
        pytest.skip("this sample's serial log has no FDINFO lines")
    return sample.fdinfo


def test_ring_state_matches_fdinfo(sample, rings):
    rows = {(r["PID"], r["FD"]): r for r in sample.vol("IoUring")}
    assert set(rows) == set(rings)
    for key, lines in rings.items():
        r = rows[key]
        assert (r["SQHead"], r["SQTail"], r["CQHead"], r["CQTail"]) == tuple(
            int(value(lines, k)) for k in ("SqHead", "SqTail", "CqHead", "CqTail"))
        assert r["SQEntries"] - 1 == int(value(lines, "SqMask"), 16)
        sqt = int(value(lines, "SqThread"))
        assert r["SQPollTID"] == (None if sqt == -1 else sqt)
        assert (r["RegFiles"], r["RegBuffers"]) == (int(value(lines, "UserFiles")), int(value(lines, "UserBufs")))


def test_pending_cqes_match_fdinfo(sample, rings):
    rows = sample.vol("Cqes")
    for (pid, fd), lines in rings.items():
        kernel = [tuple(int(x) for x in re.match(r"(\d+): user_data:(\d+), res:(-?\d+), flag:(\d+)", ln).groups())
                  for ln in section(lines, "CQEs")]
        ours = [(r["Index"], r["UserData"], r["Res"], r["Flags"]) for r in rows
                if r["PID"] == pid and r["RingFD"] == fd and r["Status"] == "pending"]
        assert ours == kernel


def test_registered_matches_fdinfo(sample, rings):
    rows = sample.vol("Registered")
    for (pid, fd), lines in rings.items():
        mine = [r for r in rows if r["PID"] == pid and r["RingFD"] == fd]
        bufs = [f"{i}: {hex(r['Address'])}/{r['Size']}" for i, r in
                enumerate(r for r in mine if r["Kind"] == "buffer")]
        assert bufs == section(lines, "UserBufs")
        names = [ln.split(": ", 1)[1] for ln in section(lines, "UserFiles")]
        files = [r["Detail"] for r in mine if r["Kind"] == "file"]
        assert len(files) == len(names)
        for path, name in zip(files, names):  # fdinfo prints the dentry name, or the protocol for sockets
            assert path.endswith("/" + name) or (name in ("TCP", "UDP", "UNIX") and path.startswith("socket:"))
        pers = section(lines, "Personalities")
        ids = [int(x) for x in pers if x.isdigit()]
        uids = [int(x.split()[1]) for x in pers if x.startswith("Uid:")]
        got = [r for r in mine if r["Kind"] == "personality"]
        assert [r["Index"] for r in got] == ids
        assert [int(r["Detail"].split()[0].split("=")[1]) for r in got] == uids
