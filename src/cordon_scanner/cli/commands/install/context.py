"""What every guarded install shares: Cordon's own options, the scan, the trusted registries, the
verdict cache, and how a blocked or passed install is reported."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, TextIO

from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.foundation.config.settings import Config
    from cordon_scanner.foundation.models import Finding
    from cordon_scanner.sources.install.cache import VerdictCache
    from cordon_scanner.sources.install.plan import InstallPlan, InstallVerdict, Scanner
    from cordon_scanner.sources.install.registries import InstallRegistries


class SdistBlocked(Exception):
    """Source code a package manager would have built was blocked by its scan. Carries what to report."""

    def __init__(self, label: str, findings: tuple[object, ...]) -> None:
        super().__init__(label)
        self.label = label
        self.findings = findings


@dataclass
class InstallContext:
    config: Config
    scan: Scanner
    registries: InstallRegistries
    cache: VerdictCache | None
    out: TextIO = sys.stderr

    #: Cordon's own options, before the tool's arguments: `--cordon-<name> VALUE`.
    OPTIONS: ClassVar[frozenset[str]] = frozenset(
        {"fail-on", "config", "registry-token", "no-cache"}
    )
    FLAGS: ClassVar[frozenset[str]] = frozenset({"no-cache"})

    @classmethod
    def options(cls, argv: list[str]) -> tuple[dict[str, list[str]], list[str]]:
        """Cordon's `--cordon-*` options, taken off the front of the tool's command line."""
        own: dict[str, list[str]] = {}
        while argv and argv[0].startswith("--cordon-"):
            flag = argv.pop(0)
            key, equals, value = flag.removeprefix("--cordon-").partition("=")
            if key not in cls.OPTIONS:
                raise SystemExit(f"{PROGRAM}: unknown option --cordon-{key}")
            if key in cls.FLAGS:
                own.setdefault(key, []).append("1")
                continue
            if not equals:
                if not argv:
                    raise SystemExit(f"{PROGRAM}: --cordon-{key} needs a value")
                value = argv.pop(0)
            own.setdefault(key, []).append(value)
        return own, argv

    @classmethod
    def made(cls, own: dict[str, list[str]]) -> InstallContext:
        from cordon_scanner.engine.incoming import Incoming
        from cordon_scanner.foundation.config.settings import Config
        from cordon_scanner.sources.install.cache import VerdictCache
        from cordon_scanner.sources.install.registries import InstallRegistries
        from cordon_scanner.version import __version__

        base = Config.from_file(own["config"][-1]) if own.get("config") else None
        config = Incoming.config(base, next(reversed(own.get("fail-on") or []), None))
        cache = (
            None
            if own.get("no-cache")
            else VerdictCache.default(f"{__version__}|{config.policy!r}")
        )
        return cls(
            config,
            cls.scanner(config),
            InstallRegistries.configured(own.get("registry-token") or ()),
            cache,
        )

    @staticmethod
    def scanner(config: Config) -> Scanner:
        """One scan of a directory of fetched files: the findings that block, by the incoming-code
        policy (malicious always; `--cordon-fail-on` raises it)."""
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.engine.assembly import ScanAssembly

        def scan(directory: Path) -> tuple[Finding, ...]:
            result = ScanAssembly.engine(config).scan(directory)
            return tuple(f for f in result.active if PolicyGate._fails(f, config.policy))

        return scan

    def check(self, plan: InstallPlan, scratch: Path) -> InstallVerdict:
        from cordon_scanner.sources.install.guard import InstallGuard

        count = len(plan.files)
        noun = "package" if count == 1 else "packages"
        print(f"{PROGRAM}: resolved {count} {noun}; fetching and scanning them", file=self.out)
        verdict = InstallGuard.check(plan, self.scan, self.registries.fetch, scratch, self.cache)
        if verdict.ok:
            remembered = f" ({verdict.remembered} remembered clean)" if verdict.remembered else ""
            print(
                f"{PROGRAM}: {count} {noun} passed{remembered}; installing exactly those",
                file=self.out,
            )
        return verdict

    @staticmethod
    def run(argv: Sequence[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> int:
        return subprocess.run(list(argv), cwd=cwd, env=env, check=False).returncode  # noqa: S603

    @staticmethod
    def write(project: Path, plan: InstallPlan) -> None:
        """The resolve's files into the project, after a clean scan (`saved:` entries are backups)."""
        for name, data in plan.manifests.items():
            if not name.startswith("saved:"):
                target = project / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)

    def blocked(self, verdict: InstallVerdict) -> int:
        by_name = {f.filename: f for f in verdict.plan.files}
        print(f"\n{PROGRAM}: install BLOCKED", file=self.out)
        for filename, findings in verdict.blocking.items():
            file = by_name.get(filename)
            label = file.label if file else filename
            self.lines(label, file.required_by if file else (), findings)
        print("\nNothing was installed, and nothing from these packages ran.", file=self.out)
        found = [f for group in verdict.blocking.values() for f in group]
        if found and all(str(getattr(f, "category", "")) == "vulnerable" for f in found):
            print(
                "None of this is malware: these are known critical vulnerabilities. Install a "
                "fixed version, or name a reviewed exception in a config passed with "
                "--cordon-config.",
                file=self.out,
            )
        return int(ExitCode.FINDINGS)

    def lines(self, label: str, required_by: Sequence[str], findings: Sequence[object]) -> None:
        via = f"  (required by {', '.join(required_by[:3])})" if required_by else ""
        print(f"\n  {label}{via}", file=self.out)
        for finding in findings:
            rule = getattr(finding, "rule_id", "")
            severity = getattr(finding, "severity", "")
            location = getattr(getattr(finding, "location", None), "path", "")
            print(f"    {severity!s:<8} {rule}  {location}", file=self.out)
            print(f"             {getattr(finding, 'message', '')}", file=self.out)


__all__ = ["InstallContext", "SdistBlocked"]
