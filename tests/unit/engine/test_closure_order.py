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
from cordon_scanner.engine.engine import Engine
from cordon_scanner.engine.pipeline.hooks import Hooks
from cordon_scanner.engine.pipeline.constants import JS_CLOSURE_LIMIT

def unit(path, text):
    return types.SimpleNamespace(path=path, content=types.SimpleNamespace(text=text, is_binary=False))

js = []
for branch in ("lib", "es"):
    js.append(unit(f"{branch}/index.js", 'require("./m0")'))
    js += [unit(f"{branch}/m{i}.js", f'require("./m{i + 1}")') for i in range(300)]
found_js = Hooks.hook_js_closure(js, {"lib/index.js", "es/index.js"})

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


class TestEveryEntryIsFollowed:
    """5E-1 (programme 5E): the JS closure missed files a reached entry names (measured on a3b9c5f1:
    13 blocked malware and 5 false alarms whose finding sat in such a file). A `bin` entry's relative
    requires were never followed, since the closure was seeded from the library entries only, and a
    minified `from"./x.js"` (no space) or a bare `import"./x.js"` did not match the reference."""

    @staticmethod
    def unit(path: str, text: str):  # type: ignore[no-untyped-def]
        import types

        return types.SimpleNamespace(
            path=path, content=types.SimpleNamespace(text=text, is_binary=False)
        )

    def test_minified_imports_are_followed(self) -> None:
        from cordon_scanner.engine.pipeline.hooks import Hooks

        units = [
            self.unit(
                "dist/index.js",
                'import{a}from"./chunk.js";import"./side.js";export*from"./more.js"',
            ),
            self.unit("dist/chunk.js", ""),
            self.unit("dist/side.js", ""),
            self.unit("dist/more.js", ""),
            self.unit("dist/unnamed.js", ""),
        ]
        found = Hooks.hook_js_closure(units, {"dist/index.js"})
        assert found == {"dist/chunk.js", "dist/side.js", "dist/more.js"}

    def test_the_main_and_bin_entries_requires_are_in_the_library_closure(
        self, tmp_path, monkeypatch
    ) -> None:
        import io
        import tarfile

        from cordon_scanner import Scanner
        from cordon_scanner.engine.pipeline import hooks
        from cordon_scanner.foundation.config.settings import Config

        files = {
            "package/package.json": json.dumps(
                {
                    "name": "entry-probe",
                    "version": "1.0.0",
                    "main": "index.js",
                    "bin": {"probe": "bin/cli.js"},
                }
            ),
            "package/index.js": 'import{a}from"./dist/chunk.js";\nexport default a;\n',
            "package/dist/chunk.js": "export const a = 1;\n",
            "package/bin/cli.js": 'const h = require("../lib/helper");\nh();\n',
            "package/lib/helper.js": "module.exports = () => 0;\n",
        }
        archive = tmp_path / "entry-probe-1.0.0.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        seen = []
        original = hooks.Hooks.lifted_inherit
        monkeypatch.setattr(
            hooks.Hooks,
            "lifted_inherit",
            staticmethod(lambda ctx: seen.append(original(ctx)) or seen[-1]),
        )
        Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(archive)
        closure = {p.split("!", 1)[-1] for ctx in seen for p in ctx.library_closure_paths}
        assert "package/lib/helper.js" in closure  # a bin entry's relative require
        assert "package/dist/chunk.js" in closure  # the main's minified import
