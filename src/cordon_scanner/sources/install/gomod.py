"""go: every module scanned before go builds, runs or tests code that imports it.

The resolve is go's own and runs no module code: `go mod download` (or `go get` as the person typed
it) writes go.mod and go.sum from the module proxy. It runs in the module, with go.mod and go.sum
saved first and put back if anything blocks. Each module zip's `h1:` line in go.sum is the hash of the
zip's contents (Go's dirhash), which Cordon recomputes over the zip it fetches from the proxy before
scanning it. The command then runs as typed; go checks every module against the same go.sum lines.

`go install <path>@<version>` outside a module resolves in a private module that requires that
version, and installs as typed once the closure is clean.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.hashes import GoModuleHash
from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile, Runner

if TYPE_CHECKING:
    from collections.abc import Sequence


class GoPlanner:
    #: Subcommands that fetch modules, or build, run or test code that imports them.
    GUARDED: ClassVar[frozenset[str]] = frozenset(
        {"get", "install", "build", "run", "test", "mod", "generate", "vet", "list"}
    )
    #: `go mod <verb>` that downloads.
    MOD_VERBS: ClassVar[frozenset[str]] = frozenset({"download", "tidy", "vendor"})
    SAVED: ClassVar[tuple[str, ...]] = ("go.mod", "go.sum")
    PROXY: ClassVar[str] = "https://proxy.golang.org"

    @classmethod
    def module(
        cls, verb: str, args: Sequence[str], runner: Runner, go: str, at: Path
    ) -> InstallPlan:
        """Resolve in the module at `at` (saved first: what to restore is in the manifests)."""
        saved = {n: (at / n).read_bytes() for n in cls.SAVED if (at / n).is_file()}
        if "go.mod" not in saved:
            raise InstallRefused("no go.mod here: go has no module to build")
        # A newer toolchain a module asks for would be fetched and run: resolve with the one installed.
        env = {**os.environ, "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "local")}
        steps = [[go, verb, *args]] if verb == "get" else []
        steps += [
            [go, "mod", "download"],
            [go, "list", "-m", "-f", "{{.Path}} {{.Version}}", "all"],
        ]
        listed = ""
        for argv in steps:
            done = runner(argv, at, env)
            if done.returncode != 0:
                cls.restore(at, saved)
                raise InstallRefused(
                    f"go could not resolve the build:\n{(done.stderr or '').strip()[-2000:]}"
                )
            listed = done.stdout or ""
        build_list = {
            tuple(line.split()[:2]) for line in listed.splitlines() if len(line.split()) == 2
        }
        try:
            text = (at / "go.sum").read_text(encoding="utf-8") if (at / "go.sum").is_file() else ""
            plan = InstallPlan(
                "gomod", [f for f in cls.files(text) if (f.name, f.version) in build_list]
            )
        except (InstallRefused, OSError) as exc:
            cls.restore(at, saved)
            raise (
                exc if isinstance(exc, InstallRefused) else InstallRefused("go wrote no go.sum")
            ) from exc
        plan.manifests = {f"saved:{n}": data for n, data in saved.items()}
        return plan

    @staticmethod
    def restore(at: Path, saved: dict[str, bytes]) -> None:
        for name in GoPlanner.SAVED:
            target = at / name
            if name in saved:
                target.write_bytes(saved[name])
            elif target.is_file():
                target.unlink()

    @classmethod
    def files(cls, go_sum: str) -> list[PackageFile]:
        """Each module zip go.sum vouches for (`path version h1:...`; the `/go.mod` lines are only
        the module's requirements, which go reads without building)."""
        out: dict[str, PackageFile] = {}
        for line in go_sum.splitlines():
            parts = line.split()
            if len(parts) != 3 or parts[1].endswith("/go.mod"):
                continue
            path, version, value = parts
            digest = GoModuleHash.parse(value)
            if digest is None:
                raise InstallRefused(f"go.sum has an unreadable hash for {path} {version}")
            out[f"{path}@{version}"] = PackageFile(
                "gomod",
                path,
                version,
                f"{cls.PROXY}/{cls.escape(path)}/@v/{cls.escape(version)}.zip",
                "h1",
                digest,
            )
        return list(out.values())

    @staticmethod
    def escape(value: str) -> str:
        """The module proxy's case encoding: an upper-case letter is `!` and its lower case."""
        return "".join(f"!{c.lower()}" if c.isupper() else c for c in value)


__all__ = ["GoPlanner"]
