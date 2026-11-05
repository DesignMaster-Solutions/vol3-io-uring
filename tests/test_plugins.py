"""Every plugin row is checked against the ground truth the guest printed on its serial console."""

# Opcode numbers from include/uapi/linux/io_uring.h, an oracle independent from the ISF enum the plugin uses.
UAPI_OPS = {0: "NOP", 4: "READ_FIXED", 16: "CONNECT", 18: "OPENAT", 22: "READ", 23: "WRITE", 26: "SEND", 45: "SOCKET"}


def rows_for(rows, **kw):
    return [r for r in rows if all(r[k] == v for k, v in kw.items())]


def state(sample, pid):
    return next(t for t in sample.of("state") if t["pid"] == pid)


def test_ioring_one_row_per_ring(sample):
    rows = sample.vol("IoUring")
    rings = sample.of("ring")
    assert len(rings) == 3
    assert sorted((r["PID"], r["FD"]) for r in rows) == sorted((t["pid"], t["fd"]) for t in rings)
    for t in rings:
        (r,) = rows_for(rows, PID=t["pid"], FD=t["fd"])
        assert r["SQEntries"] == t["sq_entries"] and r["CQEntries"] == t["cq_entries"]
        assert ("SQPOLL" in r["SetupFlags"]) == bool(t["flags"] & 2)
        st = state(sample, t["pid"])
        assert (r["SQHead"], r["SQTail"], r["CQHead"], r["CQTail"]) == (
            st["sq_head"], st["sq_tail"], st["cq_head"], st["cq_tail"])
        assert r["CQPending"] == st["cq_tail"] - st["cq_head"]


def test_ioring_sqpoll_thread_and_registrations(sample):
    rows = sample.vol("IoUring")
    (sq,) = sample.of("sqpoll")
    (r,) = rows_for(rows, PID=sq["pid"])
    assert r["SQPollTID"] == sq["tid"] and r["SQPollThread"] == sq["comm"] and r["SQPollUID"] == 0
    (reg,) = sample.of("registered")
    (r,) = rows_for(rows, PID=reg["pid"])
    assert (r["RegFiles"], r["RegBuffers"], r["Personalities"]) == (len(reg["files"]), len(reg["bufs"]), 1)
    assert [x["PID"] for x in rows if x["SQPollTID"] is not None] == [sq["pid"]]


def test_sqes_match_submissions(sample):
    rows = sample.vol("Sqes")
    sqes = sample.of("sqe")
    assert len(rows) == len(sqes)
    for t in sqes:
        (r,) = rows_for(rows, PID=t["pid"], RingFD=t["fd"], Slot=t["slot"])
        assert r["Opcode"] == UAPI_OPS[t["opcode"]]
        assert (r["UserData"], r["FD"], r["Len"], r["Personality"], r["BufIndex"]) == (
            t["user_data"], t["sqe_fd"], t["len"], t["personality"], t["buf_index"])
        assert ("FIXED_FILE" in r["SQEFlags"]) == bool(t["flags"] & 1)
        st = state(sample, t["pid"])
        assert st["sq_head"] == st["sq_tail"] and r["Status"] == "consumed"  # the guest left no SQE unsubmitted


def test_sqes_resolve_paths_and_addresses(sample):
    rows = sample.vol("Sqes")
    (io,) = [t for t in sample.of("files") if "socket_fd" in t]
    (op,) = rows_for(rows, PID=io["pid"], Opcode="OPENAT")
    assert op["Target"] == "AT_FDCWD" and op["Detail"] == f"path={io['path']}"
    (rd,) = rows_for(rows, PID=io["pid"], Opcode="READ")
    assert rd["Target"] == io["path"]
    (cn,) = rows_for(rows, PID=io["pid"], Opcode="CONNECT")
    assert cn["Detail"] == "addr=127.0.0.1:4444" and cn["Target"].startswith("socket:")
    (sk,) = rows_for(rows, PID=io["pid"], Opcode="SOCKET")
    assert sk["Detail"] == "AF_INET SOCK_STREAM" and sk["Target"] == "-"
    (reg,) = sample.of("registered")
    (fx,) = rows_for(rows, PID=reg["pid"], Opcode="READ_FIXED")
    assert fx["Target"] == f"fixed[0] {reg['files'][0]}"


def test_cqes_match_completions_and_pending(sample):
    rows = sample.vol("Cqes")
    cqes = sample.of("cqe")
    assert len(rows) == len(cqes)
    ops = {(t["pid"], t["user_data"]): UAPI_OPS[t["opcode"]] for t in sample.of("sqe")}
    for t in cqes:
        (r,) = rows_for(rows, PID=t["pid"], RingFD=t["fd"], Index=t["index"])
        assert (r["UserData"], r["Res"], r["Flags"]) == (t["user_data"], t["res"], t["flags"])
        assert r["Opcode"] == ops[(t["pid"], t["user_data"])]
        st = state(sample, t["pid"])
        pending = st["cq_head"] <= t["index"] < st["cq_tail"]  # no wrap in the sample
        assert r["Status"] == ("pending" if pending else "consumed")
    assert len(rows_for(rows, Status="pending")) == sum(
        state(sample, t["pid"])["cq_tail"] - state(sample, t["pid"])["cq_head"] for t in sample.of("ring"))


def test_registered_files_buffers_personality(sample):
    rows = sample.vol("Registered")
    (reg,) = sample.of("registered")
    files = rows_for(rows, PID=reg["pid"], Kind="file")
    assert [r["Index"] for r in files] == [0, 1]
    assert files[0]["Detail"] == reg["files"][0] and files[1]["Detail"].startswith("socket:")
    assert all(r["Note"] == "not in fd table (closed)" for r in files)  # the guest closed both fds
    bufs = rows_for(rows, PID=reg["pid"], Kind="buffer")
    assert [[r["Address"], r["Size"]] for r in bufs] == reg["bufs"]
    (pers,) = rows_for(rows, PID=reg["pid"], Kind="personality")
    (closed,) = sample.of("closed")
    assert pers["Index"] == reg["personality"]
    assert pers["Detail"].startswith(f"uid={reg['personality_uid']} ")
    assert pers["Note"] == f"process uid is {closed['uid_now']}"
    assert {r["PID"] for r in rows} == {reg["pid"]}
