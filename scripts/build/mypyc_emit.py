#!/usr/bin/env python3
"""Emit the C for the engine modules mypyc compiles, and the manifest `cordon_build` builds it from.

mypyc is the one generator Cordon's wheels are built with, and it runs only in the release wheel job,
installed with `--require-hashes` from `requirements-build.txt`. Its own driver, `mypycify`, expects
setuptools to compile what it emits. Here nothing is compiled: `setuptools.Extension` and the two
distutils pieces mypycify reads are stand-ins that record each extension, and the records are
written as the manifest `CORDON_BUILD_MYPYC` names. `cordon_build` then compiles them with the
platform compiler and its own hardening flags, the same way as the project's own C, so mypyc adds
no build tool to the release. The shared module mypyc emits for a group is placed inside the
package (`--group`), never at the top of site-packages.

    python scripts/build/mypyc_emit.py --group cordon_scanner._native.engine \\
        build/mypyc/ext.json src/cordon_scanner/.../threads.py src/cordon_scanner/.../scan.py

Deterministic for the same tree (measured: two emits, byte-identical). mypy's cache is written to
MYPY_CACHE_DIR, which this sets under build/ when unset, so the working tree is left clean.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import sysconfig
import types
from pathlib import Path
from typing import Any


class Stand:
    """The setuptools and distutils pieces `mypycify` touches, recording instead of building."""

    made: list[dict[str, Any]] = []  # noqa: RUF012 - one emit per process

    class Extension:
        def __init__(
            self,
            name: str,
            sources: list[str],
            include_dirs: tuple[str, ...] = (),
            extra_compile_args: tuple[str, ...] = (),
            **_: Any,
        ) -> None:
            Stand.made.append(
                {
                    "name": name,
                    "sources": list(sources),
                    "include_dirs": list(include_dirs),
                    "args": list(extra_compile_args),
                }
            )

    class CCompiler:  # mypycify wraps CCompiler.spawn; nothing here spawns
        def spawn(self, *_: Any, **__: Any) -> None:
            raise RuntimeError("cordon: mypyc_emit compiles nothing")

    class Unix:  # mypycify reads only compiler_type, to choose its warning flags
        compiler_type = "msvc" if os.name == "nt" else "unix"

    class BuildExt:  # mypycify patches setuptools' copy step; no setuptools build runs
        def copy_extensions_to_source(self) -> None:
            raise RuntimeError("cordon: mypyc_emit compiles nothing")

    @staticmethod
    def module(name: str, **attrs: Any) -> types.ModuleType:
        made = types.ModuleType(name)
        made.__dict__.update(attrs)
        sys.modules[name] = made
        return made

    @staticmethod
    def install() -> None:
        cc = Stand.module(
            "distutils.ccompiler",
            CCompiler=Stand.CCompiler,
            new_compiler=lambda *_, **__: Stand.Unix(),
        )
        sc = Stand.module(
            "distutils.sysconfig",
            get_config_vars=sysconfig.get_config_vars,
            get_config_var=sysconfig.get_config_var,
            customize_compiler=lambda _: None,
        )
        Stand.module("distutils", ccompiler=cc, sysconfig=sc)
        build_ext = Stand.module("setuptools.command.build_ext", build_ext=Stand.BuildExt)
        Stand.module(
            "setuptools",
            Extension=Stand.Extension,
            command=Stand.module("setuptools.command", build_ext=build_ext),
        )


class Emit:
    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "--group", required=True, help="the shared module's place in the package"
        )
        parser.add_argument("manifest", type=Path)
        parser.add_argument("modules", nargs="+")
        args = parser.parse_args()
        os.environ.setdefault("MYPY_CACHE_DIR", str(Path("build") / "mypy-cache"))
        Stand.install()
        import mypy.version
        import mypyc.build

        mypyc.build.mypycify(
            args.modules, opt_level="3", debug_level="1", target_dir="build", group_name=args.group
        )
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(
            json.dumps({"mypy": mypy.version.__version__, "extensions": Stand.made}, indent=1),
            encoding="utf-8",
        )
        print("mypy", mypy.version.__version__, "extensions", [e["name"] for e in Stand.made])
        return 0


if __name__ == "__main__":
    raise SystemExit(Emit.main())
