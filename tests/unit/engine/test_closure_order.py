"""The install-hook closures stop at a limit, so the order they walk in decides what they keep.

That order came from a set of hook paths, which Python iterates by hash, and string hashes change
with every process (PYTHONHASHSEED). A package with two entry points and more files than the limit
kept one branch in one run and the other in the next, and the intent layer's facts flipped with
it (review 98 #23: npm/hive-plus-2.10.2 kept lib/ under some seeds and es/ under others). Each
closure is computed here in fresh processes under different seeds, past its limit, and must agree.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from support import ROOT as REPO

_PROGRAM = r"""
import json, sys, types
from cordon_scanner.engine.closure import ImportClosure
from cordon_scanner.engine.engine import JS_CLOSURE_LIMIT, Engine

def unit(path, text):
    return types.SimpleNamespace(path=path, content=types.SimpleNamespace(text=text, is_binary=False))

js = []
for branch in ("lib", "es"):
    js.append(unit(f"{branch}/index.js", 'require("./m0")'))
    js += [unit(f"{branch}/m{i}.js", f'require("./m{i + 1}")') for i in range(300)]
found_js = Engine._hook_js_closure(js, {"lib/index.js", "es/index.js"})

py = {}
for branch in ("x", "y"):
    py[f"{branch}/hook.py"] = "\n".join(f"import m{i}" for i in range(300))
    py.update({f"{branch}/m{i}.py": "" for i in range(300)})
found_py = ImportClosure.resolve({"x/hook.py", "y/hook.py"}, py)

print(json.dumps({"js": sorted(found_js), "py": sorted(found_py), "js_limit": JS_CLOSURE_LIMIT}))
"""


class TestClosureOrder:
    @staticmethod
    def closures(seed: int) -> dict[str, list[str]]:
        env = {**os.environ, "PYTHONHASHSEED": str(seed), "PYTHONPATH": str(REPO / "src")}
        done = subprocess.run(
            [sys.executable, "-c", _PROGRAM], env=env, capture_output=True, text=True, check=True
        )
        result: dict[str, list[str]] = json.loads(done.stdout)
        return result

    def test_the_same_files_under_every_hash_seed(self) -> None:
        runs = [self.closures(seed) for seed in range(6)]
        # Both walks reach their limit, or this proves nothing about the order.
        assert len(runs[0]["js"]) >= 500
        assert len(runs[0]["py"]) >= 500
        assert all(run == runs[0] for run in runs[1:])
