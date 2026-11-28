"""A context for the guarded-install tests that checks nothing itself: the verdict is given and what
the tool would have run is recorded."""

from __future__ import annotations

import io
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from cordon_scanner.cli.commands.install.context import InstallContext
from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallVerdict,
    PackageFile,
    Subprocesses,
)
from cordon_scanner.sources.install.registries import InstallRegistries


class GuardKit:
    """A context that checks nothing itself: the verdict is given, and what it ran is recorded."""

    class Context(InstallContext):
        verdict_blocks = False
        code = 0
        requirements = ""
        ran: list[tuple[list[str], Path | None, dict[str, str] | None]]
        checked: list[InstallPlan]

        def check(self, plan: InstallPlan, scratch: Path) -> InstallVerdict:
            assert scratch.is_dir(), "the scan is given a directory to fetch into"
            self.checked.append(plan)
            for file in plan.files:
                (scratch / file.filename).write_bytes(b"")
            blocking = {}
            if self.verdict_blocks:
                finding = SimpleNamespace(
                    rule_id="MAL.TEST.001", severity="critical", message="bad", location=None
                )
                blocking = {"bad.tgz": (finding,)}
            return InstallVerdict(plan, blocking)

        def run(  # type: ignore[override]
            self, argv: Any, cwd: Path | None = None, env: dict[str, str] | None = None
        ) -> int:
            self.ran.append((list(argv), cwd, env))
            for word in argv:
                if str(word).endswith("cordon-requirements.txt") and Path(word).is_file():
                    self.requirements = Path(word).read_text(encoding="utf-8")
            return self.code

    @classmethod
    def context(cls, *, blocks: bool = False, code: int = 0) -> Context:
        context = cls.Context(
            config=None,  # type: ignore[arg-type]
            scan=lambda directory: (),
            registries=InstallRegistries(),
            cache=None,
            out=io.StringIO(),
        )
        context.verdict_blocks = blocks
        context.code = code
        context.ran = []
        context.checked = []
        return context

    @staticmethod
    def said(context: Context) -> str:
        return context.out.getvalue()  # type: ignore[attr-defined,no-any-return]

    @staticmethod
    def file(name: str = "pkg", algorithm: str = "sha256") -> PackageFile:
        return PackageFile(
            "test", name, "1.0", f"https://example.invalid/{name}.tgz", algorithm, b"\x01" * 32
        )

    @staticmethod
    def stub(monkeypatch: pytest.MonkeyPatch, owner: Any, name: str, value: Any) -> None:
        monkeypatch.setattr(owner, name, staticmethod(value))

    @staticmethod
    def subprocess_says(
        monkeypatch: pytest.MonkeyPatch, code: int, out: str = "", err: str = ""
    ) -> None:
        def run(argv: Any, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, code, out, err)

        monkeypatch.setattr(Subprocesses, "run", staticmethod(run))
