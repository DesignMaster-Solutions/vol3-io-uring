"""Fixtures: run the plugins with the real vol CLI on each memory sample and parse the serial ground truth.

A sample is sample/work/io-uring-<KVER>.elf + sample/work/isf/linux/<KVER>.json.xz, with the truth printed by
the guest in sample/expected/serial-<KVER>.log. Samples that are not present are skipped with a message.
Env: VOL (vol binary), PLUGINS (plugin dir, default ./plugins; point it at a mutated copy to see tests fail).
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORK = pathlib.Path(os.environ.get("SAMPLE_WORK", ROOT / "sample" / "work"))
EXPECTED = ROOT / "sample" / "expected"
PLUGINS = os.environ.get("PLUGINS", str(ROOT / "plugins"))
VOL = os.environ.get("VOL") or shutil.which("vol") or str(pathlib.Path(sys.executable).parent / "vol")
KERNELS = sorted(p.name[len("serial-"):-len(".log")] for p in EXPECTED.glob("serial-*.log"))


def truth(kver):
    rows = []
    for line in (EXPECTED / f"serial-{kver}.log").read_text(errors="replace").splitlines():
        if line.startswith("TRUTH "):
            rows.append(json.loads(line[6:]))
    return rows


class Sample:
    def __init__(self, kver):
        self.kver = kver
        self.dump = WORK / f"io-uring-{kver}.elf"
        self.truth = truth(kver)
        self._cache = {}

    def of(self, kind):
        return [t for t in self.truth if t["kind"] == kind]

    def vol(self, plugin):
        if plugin not in self._cache:
            (WORK / ".volcache").mkdir(exist_ok=True)  # private symbol cache: ~/.cache/volatility3 is shared
            cmd = [VOL, "-q", "--cache-path", str(WORK / ".volcache"), "-r", "json", "-p", PLUGINS, "-f", str(self.dump), "-s", str(WORK / "isf"),
                   f"linux.io_uring.{plugin}"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            assert out.returncode == 0, out.stderr[-3000:]
            self._cache[plugin] = json.loads(out.stdout)
        return self._cache[plugin]


_samples = {}


@pytest.fixture(scope="session", params=KERNELS)
def sample(request):
    kver = request.param
    if not (WORK / f"io-uring-{kver}.elf").exists():
        pytest.skip(f"memory sample io-uring-{kver}.elf not in {WORK}: run sample/build_sample.sh or fetch "
                    "the release asset (see README)")
    return _samples.setdefault(kver, Sample(kver))
