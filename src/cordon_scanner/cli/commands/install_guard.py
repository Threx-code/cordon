"""`npm` and `pip`: the package manager, with every package scanned before anything installs.

    cordon npm install express        cordon pip install requests

Everything after the tool's name is the tool's own command line. An install is resolved without
running anything, every file is fetched and checked against its registry hash, the files are scanned
together, and only then installed -- exactly those files, pinned by hash. Any other subcommand
(`npm run test`, `pip list`) is handed to the tool unchanged. Cordon's own options go first and are
spelled `--cordon-fail-on SEVERITY` and `--cordon-config PATH`, so they never collide with the tool's.
The engine is `sources/install_guard.py`.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.foundation.config.settings import Config
    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.sources.install_guard import InstallVerdict, PackageFile


class SdistBlocked(Exception):
    """An sdist pip would have built was blocked by its scan. Carries what to report."""

    def __init__(self, label: str, findings: tuple[object, ...]) -> None:
        super().__init__(label)
        self.label = label
        self.findings = findings


class InstallGuardCommand:
    TOOLS: ClassVar[tuple[str, ...]] = ("npm", "pip")
    PIP_INSTALLS: ClassVar[frozenset[str]] = frozenset({"install"})
    #: pip options that say where or how to install, kept for the pinned install; everything else
    #: (indexes, requirement files, constraints) only shapes the resolve.
    PIP_KEEP_FLAGS: ClassVar[frozenset[str]] = frozenset(
        {
            "--user",
            "--break-system-packages",
            "-q",
            "--quiet",
            "-v",
            "--verbose",
            "--force-reinstall",
        }
    )
    PIP_KEEP_VALUED: ClassVar[frozenset[str]] = frozenset({"-t", "--target", "--prefix", "--root"})

    @classmethod
    def add_parser(cls, sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        for tool in cls.TOOLS:
            parser_ = sub.add_parser(
                tool,
                help=f"run {tool}, scanning every package before anything is installed",
                description=(
                    f"`{PROGRAM} {tool} install ...`: resolve without running anything, fetch and "
                    "verify every file against its registry hash, scan them, and install exactly those "
                    "files only when nothing is malicious. Other subcommands run unchanged. Cordon's "
                    "options go first: --cordon-fail-on SEVERITY, --cordon-config PATH."
                ),
            )
            parser_.add_argument(
                "arguments", nargs=argparse.REMAINDER, help=f"{tool}'s own arguments"
            )

    @classmethod
    def main(cls, tool: str, argv: Sequence[str]) -> int:
        from cordon_scanner.foundation.errors import CordonError
        from cordon_scanner.sources.install_guard import InstallRefused, Subprocesses

        own, rest = cls._own_options(list(argv))
        executable = Subprocesses.executable(tool)
        installs, handler = cls._guarded()[tool]
        if not rest or rest[0] not in installs:
            return cls._passthrough([executable, *rest])
        try:
            return handler(executable, rest, cls._config(own))
        except SdistBlocked as blocked:
            cls._blocked_lines(blocked.label, (), blocked.findings)
            print(
                f"\n{PROGRAM}: nothing was installed; pip never built {blocked.label}.",
                file=sys.stderr,
            )
            return int(ExitCode.FINDINGS)
        except InstallRefused as exc:
            print(f"{PROGRAM}: {exc}\nNothing was installed.", file=sys.stderr)
            return int(ExitCode.SCANNER_ERROR)
        except CordonError:
            raise

    @classmethod
    def _guarded(cls) -> dict[str, tuple[frozenset[str], Callable[[str, list[str], Config], int]]]:
        """Each tool's install subcommands, and what checks them. Anything else runs unchanged."""
        from cordon_scanner.sources.install_guard import NpmPlanner

        return {"npm": (NpmPlanner.INSTALLS, cls._npm), "pip": (cls.PIP_INSTALLS, cls._pip)}

    @staticmethod
    def _own_options(argv: list[str]) -> tuple[dict[str, str], list[str]]:
        """Cordon's `--cordon-*` options, taken off the front of the tool's command line."""
        own: dict[str, str] = {}
        while argv and argv[0].startswith("--cordon-"):
            flag = argv.pop(0)
            key, _, value = flag.partition("=")
            if not value:
                if not argv:
                    raise SystemExit(f"{PROGRAM}: {key} needs a value")
                value = argv.pop(0)
            own[key.removeprefix("--cordon-")] = value
        return own, argv

    @staticmethod
    def _config(own: dict[str, str]) -> Config:
        from cordon_scanner.engine.incoming import Incoming
        from cordon_scanner.foundation.config.settings import Config

        base = Config.from_file(own["config"]) if own.get("config") else None
        return Incoming.config(base, own.get("fail-on"))

    @staticmethod
    def scanner(config: Config) -> Callable[[Path], tuple[Finding, ...]]:
        """One scan of a directory of fetched files: the findings that block, by the incoming-code
        policy (malicious always; `--cordon-fail-on` raises it)."""
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.engine.assembly import ScanAssembly

        def scan(directory: Path) -> tuple[Finding, ...]:
            result = ScanAssembly.engine(config).scan(directory)
            return tuple(f for f in result.active if PolicyGate._fails(f, config.policy))

        return scan

    @staticmethod
    def _passthrough(argv: list[str]) -> int:
        return subprocess.run(argv, check=False).returncode  # noqa: S603 - the tool the person named

    # -- npm -----------------------------------------------------------------------------------

    @classmethod
    def _npm(cls, npm: str, args: list[str], config: Config) -> int:
        from cordon_scanner.intel.registries.registry_request import RegistryRequest
        from cordon_scanner.sources.install_guard import (
            InstallGuard,
            NpmPlanner,
            PrivateDirectory,
            Subprocesses,
        )

        project = Path.cwd()
        plan = NpmPlanner.plan(project, args, Subprocesses.run, npm)
        print(
            f"{PROGRAM}: resolved {len(plan.files)} packages; fetching and scanning them",
            file=sys.stderr,
        )
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = InstallGuard.check(
                plan, cls.scanner(config), RegistryRequest.fetch_bytes, scratch
            )
        if not verdict.ok:
            return cls._report_blocked(verdict)
        for name, data in plan.manifests.items():
            (project / name).write_bytes(data)
        print(
            f"{PROGRAM}: {len(plan.files)} packages passed; installing exactly those",
            file=sys.stderr,
        )
        # `npm ci` installs the lockfile as written and refuses any tarball whose integrity differs:
        # what lands is what was scanned.
        return cls._passthrough([npm, "ci", "--no-audit", "--no-fund"])

    # -- pip -----------------------------------------------------------------------------------

    @classmethod
    def _pip(cls, pip: str, args: list[str], config: Config) -> int:
        from cordon_scanner.intel.registries.registry_request import RegistryRequest
        from cordon_scanner.sources.install_guard import (
            InstallGuard,
            PipPlanner,
            PrivateDirectory,
            Subprocesses,
        )

        plan = PipPlanner.plan(
            args[1:], Subprocesses.run, pip, lambda n, v: cls._scan_sdist(n, v, config)
        )
        print(
            f"{PROGRAM}: resolved {len(plan.files)} files; fetching and scanning them",
            file=sys.stderr,
        )
        with PrivateDirectory.made("cordon-install-") as scratch:
            verdict = InstallGuard.check(
                plan, cls.scanner(config), RegistryRequest.fetch_bytes, scratch
            )
            if not verdict.ok:
                return cls._report_blocked(verdict)
            if not plan.files:
                print(f"{PROGRAM}: nothing to install", file=sys.stderr)
                return int(ExitCode.CLEAN)
            requirements = scratch / "cordon-requirements.txt"
            requirements.write_text(
                "".join(
                    f"{f.name}=={f.version} --hash=sha256:{f.digest.hex()}\n"
                    for f in plan.files
                    if not f.build_only
                ),
                encoding="utf-8",
            )
            print(
                f"{PROGRAM}: {len(plan.files)} files passed; installing exactly those",
                file=sys.stderr,
            )
            return cls._passthrough(
                [
                    pip,
                    "install",
                    "--no-index",
                    "--find-links",
                    str(scratch),
                    "--require-hashes",
                    "--no-deps",
                    "-r",
                    str(requirements),
                    *cls._pip_keep(args[1:]),
                ]
            )

    @classmethod
    def _pip_keep(cls, args: Sequence[str]) -> list[str]:
        kept: list[str] = []
        it = iter(args)
        for arg in it:
            flag = arg.split("=", 1)[0]
            if arg in cls.PIP_KEEP_FLAGS:
                kept.append(arg)
            elif flag in cls.PIP_KEEP_VALUED:
                kept.append(arg if "=" in arg else f"{arg}={next(it, '')}")
        return kept

    @staticmethod
    def _scan_sdist(name: str, version: str, config: Config) -> tuple[str, tuple[str, ...]]:
        """Fetch, verify and scan the sdist pip would build; its version if it passes."""
        from cordon_scanner.intel.registries.registry_client import RegistryClient, RegistryError
        from cordon_scanner.sources.install_guard import (
            BuildRequires,
            InstallRefused,
            PrivateDirectory,
        )

        try:
            archive = RegistryClient.package_archive("pypi", name, version or None)
        except RegistryError as exc:
            raise InstallRefused(
                f"{name} needs a source build and its sdist could not be fetched: {exc}"
            ) from exc
        if archive.filename.endswith(".whl"):
            raise InstallRefused(
                f"{name}=={archive.version} has no wheel for this machine and no sdist"
            )
        with PrivateDirectory.made("cordon-sdist-") as scratch:
            (scratch / archive.filename.replace("/", "_")).write_bytes(archive.data)
            blocking = InstallGuardCommand.scanner(config)(scratch)
        if blocking:
            raise SdistBlocked(f"{name}=={archive.version}", blocking)
        print(
            f"{PROGRAM}: {name}=={archive.version} has no wheel; its sdist was scanned and passed",
            file=sys.stderr,
        )
        return archive.version, BuildRequires.of(archive.filename, archive.data)

    # -- report --------------------------------------------------------------------------------

    @classmethod
    def _report_blocked(cls, verdict: InstallVerdict) -> int:
        by_name: dict[str, PackageFile] = {f.filename: f for f in verdict.plan.files}
        print(f"\n{PROGRAM}: install BLOCKED", file=sys.stderr)
        for filename, findings in verdict.blocking.items():
            file = by_name.get(filename)
            label = file.label if file else filename
            cls._blocked_lines(label, file.required_by if file else (), findings)
        print("\nNothing was installed, and nothing from these packages ran.", file=sys.stderr)
        return int(ExitCode.FINDINGS)

    @staticmethod
    def _blocked_lines(label: str, required_by: Sequence[str], findings: Sequence[object]) -> None:
        via = f"  (required by {', '.join(required_by[:3])})" if required_by else ""
        print(f"\n  {label}{via}", file=sys.stderr)
        for finding in findings:
            rule = getattr(finding, "rule_id", "")
            severity = getattr(finding, "severity", "")
            location = getattr(getattr(finding, "location", None), "path", "")
            print(f"    {severity!s:<8} {rule}  {location}", file=sys.stderr)
            print(f"             {getattr(finding, 'message', '')}", file=sys.stderr)


__all__ = ["InstallGuardCommand", "SdistBlocked"]
