"""Every bench script finds the modules it imports, run as it is run: alone, from anywhere.

Bench modules import each other by bare name (`from run import Harness`), each putting bench/,
suites/ and tools/ on sys.path itself. Grouped into subdirectories, twelve of them pointed at the
repository root instead, and `python bench/suites/timesplit.py` failed on `run`; the suite and
the harness set the path themselves, so nothing noticed (review 98, 2026-10-20). Each script is
loaded here in a fresh process, outside bench/, with only src/ on the path.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from support import ROOT as REPO

BENCH = REPO / "bench"
SCRIPTS = sorted(
    p
    for folder in ("suites", "tools", "model")
    for p in [BENCH / "run.py", *BENCH.glob(f"{folder}/*.py")]
    if p.name != "__init__.py"
)
SCRIPTS = sorted(set(SCRIPTS))
#: Bench modules, by the bare name they import each other under.
OWN = frozenset(p.stem for p in SCRIPTS)

_LOAD = r"""
import runpy, sys
try:
    runpy.run_path(sys.argv[1], run_name="bench_import_check")
except ModuleNotFoundError as error:
    print("MISSING", error.name)
"""


class TestBenchImports:
    @pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.relative_to(BENCH).as_posix())
    def test_a_bench_script_loads_its_own_modules(self, script, tmp_path) -> None:
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        done = subprocess.run(
            [sys.executable, "-c", _LOAD, str(script)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        missing = [
            line.split()[1] for line in done.stdout.splitlines() if line.startswith("MISSING ")
        ]
        # A third-party tool the bench image installs (guarddog, numpy) is not this test's
        # business; a bench module that cannot be found is.
        assert not [m for m in missing if m.split(".")[0] in OWN], (missing, done.stderr[-400:])
