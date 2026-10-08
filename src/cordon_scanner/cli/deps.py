"""`cordon-scanner deps [TARGET]`: the dependency graph, and what was found about each package.

The scan already resolves every lockfile into one graph and attaches advisory, typosquat, registry
and integrity findings to the package they concern. This shows that graph the way a reviewer reads
it -- direct dependencies first, each with the transitive packages it brings in -- and puts each
package's findings beside it, so "what does this project depend on, and which of those is a
problem" is one command rather than a JSON query.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from cordon_scanner.core.errors import CordonError, ExitCode
from cordon_scanner.core.models import Dependency, Finding, ScanResult


@dataclass(frozen=True, slots=True)
class PackageReport:
    dependency: Dependency
    findings: tuple[Finding, ...]

    def as_dict(self) -> dict[str, object]:
        d = self.dependency
        return {
            "purl": d.purl,
            "ecosystem": d.ecosystem,
            "name": d.name,
            "version": d.version,
            "direct": d.direct,
            "depth": d.depth,
            "scope": d.scope.value,
            "parents": list(d.parents),
            "declared_in": d.declared_in,
            "license": d.license,
            "findings": [
                {"rule_id": f.rule_id, "severity": f.severity.name.lower(), "message": f.message}
                for f in self.findings
            ],
        }


class DependencyView:
    """A scan result reorganised around its dependencies."""

    def __init__(self, result: ScanResult) -> None:
        by_package: dict[str, list[Finding]] = defaultdict(list)
        for finding in result.active:
            if finding.location.package:
                by_package[finding.location.package].append(finding)
        self.reports = [
            PackageReport(
                d, tuple(sorted(by_package.get(d.purl, ()), key=lambda f: -f.severity.value))
            )
            for d in sorted(
                result.dependencies, key=lambda d: (not d.direct, d.depth, d.ecosystem, d.name)
            )
        ]
        self.complete = result.complete

    def children(self) -> dict[tuple[str, str], list[PackageReport]]:
        """Each package's reports, keyed by the ecosystem and name of a parent that brought it in.

        A lockfile records parents by package name, so the key is the name within its ecosystem.
        """
        out: dict[tuple[str, str], list[PackageReport]] = defaultdict(list)
        for report in self.reports:
            for parent in report.dependency.parents:
                out[(report.dependency.ecosystem, parent.lower())].append(report)
        return out

    def render_text(self, *, direct_only: bool) -> list[str]:
        if not self.reports:
            return ["no dependencies found: no lockfile or manifest this scanner reads"]
        flagged = sum(1 for r in self.reports if r.findings)
        lines = [
            f"{len(self.reports)} package(s), {flagged} with findings{'' if self.complete else ' (scan incomplete)'}",
            "",
        ]
        children = self.children()
        shown: set[str] = set()

        def emit(report: PackageReport, depth: int) -> None:
            d = report.dependency
            if d.purl in shown or depth > 12:
                return
            shown.add(d.purl)
            marks = ", ".join(f"{f.severity.name.lower()} {f.rule_id}" for f in report.findings)
            scope = "" if d.scope.value == "runtime" else f" [{d.scope.value}]"
            lines.append(
                f"{'  ' * depth}{d.ecosystem}:{d.name}@{d.version or '?'}{scope}{f'  <- {marks}' if marks else ''}"
            )
            if not direct_only:
                for child in children.get((d.ecosystem, d.name.lower()), ()):
                    emit(child, depth + 1)

        for report in self.reports:
            if report.dependency.direct:
                emit(report, 0)
        if not direct_only:
            # Packages no direct dependency reaches in the graph (a lockfile without parent links).
            for report in self.reports:
                emit(report, 0)
        return lines


class DepsCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        deps = sub.add_parser("deps", help="dependency graph and per-package findings")
        deps.add_argument("target", nargs="?", default=".", help="path to scan (default: .)")
        deps.add_argument("--format", choices=("text", "json"), default="text")
        deps.add_argument(
            "--direct-only", action="store_true", help="list direct dependencies only"
        )
        deps.add_argument(
            "--exclude",
            action="append",
            default=[],
            metavar="GLOB",
            help="skip matching paths, as `scan --exclude` does (repeatable)",
        )
        deps.add_argument(
            "--online",
            action="store_true",
            help="also ask registries (withdrawal, hashes, provenance)",
        )

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import ConfigResolver

        target = Path(args.target)
        if not target.exists():
            raise CordonError(
                f"target does not exist: {target}", hint="Pass a directory or lockfile path."
            )
        config = ConfigResolver.resolve(
            root=target if target.is_dir() else target.parent, offline=not args.online
        )
        if args.exclude:
            config = config.with_overrides(exclude=(*config.exclude, *args.exclude))
        view = DependencyView(Scanner(config).scan(target))
        if args.format == "json":
            payload = [
                r.as_dict() for r in view.reports if r.dependency.direct or not args.direct_only
            ]
            print(json.dumps({"complete": view.complete, "dependencies": payload}, indent=2))
        else:
            print("\n".join(view.render_text(direct_only=args.direct_only)))
        return int(ExitCode.CLEAN if view.complete else ExitCode.SCANNER_ERROR)
