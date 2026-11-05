#!/bin/bash
# Proves the tests catch reading errors: each mutant is a one-line break of plugins/linux/io_uring.py
# (offset, mask, flag, status logic). The suite must FAIL on every mutant. Usage: tests/mutants/run_mutants.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PY:-$ROOT/.venv/bin/python}"
SRC="$ROOT/plugins/linux/io_uring.py"
MUTANTS=(
  's/SQE_FMT.unpack_from(raw)/SQE_FMT.unpack_from(raw, 4)/'
  's/user_data, buf_index, pers = s\[:11\]/user_data, pers, buf_index = s[:11]/'
  's/size = 32 if self.flags \& SETUP_CQE32 else 16/size = 32/'
  's/CQE_FMT.unpack_from(raw)/CQE_FMT.unpack_from(raw, 8)/'
  's/"pending" if idx in pending else "consumed"/"consumed" if idx in pending else "pending"/'
  's/offset=v \& ~0x7)/offset=v \& ~0x1)/'
  's/index = base + (off << shift)/index = base + off/'
  's/return int(th.pid), utility.array_to_string(th.comm)/return int(th.tgid), utility.array_to_string(th.comm)/'
  's/"cq_head": int(rings.cq.head)/"cq_head": int(rings.cq.tail)/'
  's/"SQPOLL", "SQ_AFF"/"SQ_AFF", "SQPOLL"/'
  's/if op == "CONNECT":/if op == "CONNECTX":/'
  's/note = f"also fd {fdnum}" if fdnum is not None else "not in fd table (closed)"/note = ""/'
  's/note = f"process uid is {task_uid}" if uid != task_uid else ""/note = ""/'
)
fail=0
for m in "${MUTANTS[@]}"; do
  D=$(mktemp -d); mkdir -p "$D/linux"; sed "$m" "$SRC" > "$D/linux/io_uring.py"
  if cmp -s "$SRC" "$D/linux/io_uring.py"; then echo "NOT APPLIED  $m"; fail=1; continue; fi
  if PLUGINS="$D" "$PY" -m pytest -q -x "$ROOT/tests" >"$D/log" 2>&1; then
    echo "SURVIVED     $m"; fail=1
  else
    echo "KILLED       $m  ($(grep -m1 -oE 'FAILED [^ ]+|[0-9]+ failed' "$D/log"))"
  fi
  rm -rf "$D"
done
exit $fail
