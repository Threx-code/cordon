"""cargo: every crate scanned before cargo compiles it (a `build.rs` or a proc macro runs at compile
time, so `cargo build`, `test`, `run`, `check` are installs too).

The resolve is cargo's own and runs no crate code: `cargo metadata` (or `cargo add`/`update` as the
person typed them) writes `Cargo.lock` from the index. It runs in the project, which keeps path
dependencies and workspaces exactly as cargo sees them; `Cargo.toml` and `Cargo.lock` are saved first
and put back if anything blocks. Each registry crate's `checksum` in the lock is the sha256 of its
`.crate`, which Cordon fetches from crates.io's file host, verifies and scans. The command then runs
with `--locked`, so cargo builds from that lock and checks every crate against the same checksum.

`cargo install <crate>` resolves the crate's dependencies in a private project that depends on exactly
that version, scans the closure, and installs with `cargo install --path <scanned crate> --locked`
using that lock: the binary is built from the scanned bytes.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.sources.install.plan import (
    InstallPlan,
    InstallRefused,
    PackageFile,
    Runner,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class CargoPlanner:
    #: Subcommands that compile (and so run build scripts) or change the lock.
    GUARDED: ClassVar[frozenset[str]] = frozenset(
        {
            "build", "b", "run", "r", "test", "t", "check", "c", "bench", "doc", "d",
            "clippy", "fetch", "add", "update", "generate-lockfile", "vendor", "install",
        }
    )  # fmt: skip
    RESOLVING: ClassVar[frozenset[str]] = frozenset({"add", "update", "generate-lockfile"})
    CRATES_IO: ClassVar[frozenset[str]] = frozenset(
        {
            "registry+https://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io/",
        }
    )
    SAVED: ClassVar[tuple[str, ...]] = ("Cargo.toml", "Cargo.lock")

    @classmethod
    def project(
        cls, verb: str, args: Sequence[str], runner: Runner, cargo: str, project: Path
    ) -> InstallPlan:
        """Resolve in the project (saved first: `saved` in the plan's manifests is what to restore)."""
        saved = {n: (project / n).read_bytes() for n in cls.SAVED if (project / n).is_file()}
        if "Cargo.toml" not in saved:
            raise InstallRefused("no Cargo.toml here: cargo has no project to build")
        argv = (
            [cargo, verb, *args]
            if verb in cls.RESOLVING
            else [cargo, "metadata", "--format-version", "1", "--quiet"]
        )
        done = runner(argv, project, {**os.environ})
        if done.returncode != 0:
            cls.restore(project, saved)
            raise InstallRefused(
                f"cargo could not resolve the build:\n{(done.stderr or '').strip()[-2000:]}"
            )
        lock = project / "Cargo.lock"
        if not lock.is_file():
            cls.restore(project, saved)
            raise InstallRefused("cargo resolved but wrote no Cargo.lock")
        try:
            plan = InstallPlan("cargo", cls.files(lock.read_text(encoding="utf-8")))
        except InstallRefused:
            cls.restore(project, saved)
            raise
        plan.manifests = {f"saved:{n}": data for n, data in saved.items()}
        return plan

    @classmethod
    def install(
        cls, spec: str, version: str, runner: Runner, cargo: str, into: Path
    ) -> InstallPlan:
        """`cargo install <spec>`: the crate's closure, resolved in `into/resolve` (a private project)."""
        resolve = into / "resolve"
        (resolve / "src").mkdir(parents=True)
        (resolve / "src" / "lib.rs").write_text("", encoding="utf-8")
        requirement = f'"={version}"' if version else '"*"'
        (resolve / "Cargo.toml").write_text(
            '[package]\nname = "cordon-install-resolve"\nversion = "0.0.0"\nedition = "2021"\n'
            f"[dependencies]\n{TomlKey.quote(spec)} = {requirement}\n",
            encoding="utf-8",
        )
        done = runner([cargo, "generate-lockfile"], resolve, {**os.environ})
        if done.returncode != 0:
            raise InstallRefused(
                f"cargo could not resolve {spec}:\n{(done.stderr or '').strip()[-2000:]}"
            )
        lock = (resolve / "Cargo.lock").read_text(encoding="utf-8")
        plan = InstallPlan("cargo", cls.files(lock))
        plan.manifests = {"Cargo.lock": lock.encode()}
        return plan

    @staticmethod
    def restore(project: Path, saved: dict[str, bytes]) -> None:
        for name in CargoPlanner.SAVED:
            target = project / name
            if name in saved:
                target.write_bytes(saved[name])
            elif target.is_file():
                target.unlink()

    @classmethod
    def files(cls, text: str) -> list[PackageFile]:
        try:
            document: dict[str, Any] = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise InstallRefused("Cargo.lock could not be read") from exc
        out: list[PackageFile] = []
        for package in document.get("package") or ():
            name, version = str(package.get("name") or ""), str(package.get("version") or "")
            source = package.get("source")
            if source is None:
                continue  # a workspace member or path dependency: the person's own code
            if source not in cls.CRATES_IO:
                raise InstallRefused(
                    f"{name} {version} comes from {str(source)[:100]}: Cordon fetches crates from crates.io only"
                )
            checksum = str(package.get("checksum") or "")
            if len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
                raise InstallRefused(f"{name} {version} has no sha256 checksum in Cargo.lock")
            out.append(
                PackageFile(
                    "cargo",
                    name,
                    version,
                    f"https://static.crates.io/crates/{name}/{name}-{version}.crate",
                    "sha256",
                    bytes.fromhex(checksum),
                    separator=" ",
                )
            )
        return out

    @staticmethod
    def locked(verb: str, args: Sequence[str]) -> list[str]:
        """The person's command with `--locked`, placed before any `--` (whose rest is the program's)."""
        rest = list(args)
        if "--locked" in rest or "--frozen" in rest:
            return [verb, *rest]
        cut = rest.index("--") if "--" in rest else len(rest)
        return [verb, *rest[:cut], "--locked", *rest[cut:]]


class TomlKey:
    @staticmethod
    def quote(value: str) -> str:
        if not value or any(not (c.isalnum() or c in "-_") for c in value):
            raise InstallRefused(f"{value[:80]!r} is not a crate name")
        return value


class CrateArchive:
    """A scanned `.crate` (gzip tar) unpacked for `cargo install --path`: regular files and
    directories only, every path inside the target, nothing else written."""

    MAX_BYTES: ClassVar[int] = 512 << 20

    @classmethod
    def extract(cls, crate: Path, into: Path) -> Path:
        import tarfile

        total = 0
        with tarfile.open(crate, mode="r:gz") as archive:
            for member in archive:
                parts = Path(member.name).parts
                if not parts or member.name.startswith("/") or ".." in parts:
                    raise InstallRefused(
                        f"{crate.name} has a path outside the crate: {member.name[:100]}"
                    )
                target = into.joinpath(*parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue  # links and devices are never written
                total += member.size
                if total > cls.MAX_BYTES:
                    raise InstallRefused(f"{crate.name} unpacks to more than Cordon writes")
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(handle.read())
        roots = [p for p in into.iterdir() if p.is_dir()]
        if len(roots) != 1 or not (roots[0] / "Cargo.toml").is_file():
            raise InstallRefused(
                f"{crate.name} is not a crate (one top directory with a Cargo.toml)"
            )
        return roots[0]


__all__ = ["CargoPlanner", "CrateArchive"]
