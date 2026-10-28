"""The package tools: a package, a list of packages, an install command, and a package's advisories."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from cordon_scanner.mcp.packages import (
    InstallCommand,
    Lockfiles,
    PackageError,
    PackageSpec,
)
from cordon_scanner.mcp.results import Results, ScanSummary
from cordon_scanner.mcp.runner import CancelToken
from cordon_scanner.mcp.tools.base import (
    MAX_PACKAGES,
    Args,
    Outcome,
    Scans,
    Settings,
    ToolError,
)
from cordon_scanner.mcp.untrusted import Untrusted


class PackageTools:
    @staticmethod
    def spec(args: dict[str, Any]) -> PackageSpec:
        try:
            return PackageSpec.of(
                str(Args.text(args, "ecosystem", required=True)),
                str(Args.text(args, "name", required=True, limit=214)),
                Args.text(args, "version", limit=128),
            )
        except PackageError as exc:
            raise ToolError(str(exc)) from exc

    @staticmethod
    def specs(args: dict[str, Any]) -> list[PackageSpec]:
        raw = args.get("packages")
        if not isinstance(raw, list) or not raw:
            raise ToolError("packages must be a non-empty list")
        if len(raw) > MAX_PACKAGES:
            raise ToolError(f"at most {MAX_PACKAGES} packages per call")
        specs: list[PackageSpec] = []
        for entry in raw:
            if not isinstance(entry, dict):
                raise ToolError(
                    "each package is an object with ecosystem, name and optionally version"
                )
            version = entry.get("version")
            if version is not None and not isinstance(version, str):
                raise ToolError("version must be a string")
            try:
                specs.append(
                    PackageSpec.of(
                        str(entry.get("ecosystem", "")), str(entry.get("name", "")), version
                    )
                )
            except PackageError as exc:
                raise ToolError(str(exc)) from exc
        return specs

    @staticmethod
    def check(
        settings: Settings,
        specs: list[PackageSpec],
        token: CancelToken,
        *,
        online: bool,
        max_findings: int,
        subject: dict[str, Any],
    ) -> ScanSummary:
        """The verdict a project depending on these releases would get; with online, also a scan
        of each published release's own code."""
        notes: list[str] = []
        parts: list[ScanSummary] = []
        try:
            files = Lockfiles.write(specs)
        except PackageError as exc:
            raise ToolError(str(exc)) from exc
        with tempfile.TemporaryDirectory(prefix="cordon-mcp-") as work:
            root = Path(work)
            Scans.write_tree(root, files)
            parts.append(
                Scans.scan(
                    settings,
                    str(root),
                    token,
                    online=False,
                    severity="info",
                    max_findings=max_findings,
                    subject=subject,
                    cache=False,
                    package_only=True,
                )
            )
        for spec in specs:
            if spec.note:
                notes.append(f"{spec.label}: {spec.note}")
            if not spec.version:
                notes.append(
                    f"{spec.label}: no version given, so only what the name alone shows was checked"
                )
        if online:
            for spec in specs:
                purl = spec.purl
                if purl is None:
                    notes.append(
                        f"{spec.label}: its published archive cannot be fetched for a code scan"
                    )
                    continue
                try:
                    parts.append(
                        Scans.scan(
                            settings,
                            purl,
                            token,
                            online=True,
                            max_findings=max_findings,
                            subject={"package": purl},
                            cache=False,
                        )
                    )
                except ToolError as exc:
                    notes.append(f"{spec.label}: the published code was not scanned: {exc}")
                    parts.append(ScanSummary("incomplete", "not scanned", {}, [], 0, False))
        else:
            notes.append(
                "offline check: known malicious and vulnerable releases, typosquats and hallucinated "
                "names. The published code itself was not read (online would fetch and scan it)."
            )
        merged = Results.merge(parts, max_findings=max_findings, subject=subject)
        merged.notes = list(dict.fromkeys(notes + merged.notes))
        return merged

    @staticmethod
    def check_package(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        spec = PackageTools.spec(args)
        return Scans.outcome(
            PackageTools.check(
                settings,
                [spec],
                token,
                online=online,
                max_findings=Args.max_findings(settings, args),
                subject={"package": spec.label},
            )
        )

    @staticmethod
    def check_packages(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        specs = PackageTools.specs(args)
        return Scans.outcome(
            PackageTools.check(
                settings,
                specs,
                token,
                online=online,
                max_findings=Args.max_findings(settings, args),
                subject={"packages": [s.label for s in specs]},
            )
        )

    @staticmethod
    def check_install_command(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        online = Args.online(settings, args)
        command = Args.text(args, "command", required=True, limit=16_000) or ""
        try:
            parsed = InstallCommand.parse(command)
        except PackageError as exc:
            raise ToolError(str(exc)) from exc
        notes = [f"not checked: {u}" for u in parsed.unchecked] + [
            f"warning: {w}" for w in parsed.warnings
        ]
        parts: list[ScanSummary] = []
        shell = PackageTools.shell_risk(command)
        if shell:
            parts.append(shell)
        subject = {"command": command[:500], "packages": [s.label for s in parsed.packages]}
        if parsed.packages:
            parts.append(
                PackageTools.check(
                    settings,
                    parsed.packages,
                    token,
                    online=online,
                    max_findings=Args.max_findings(settings, args),
                    subject=subject,
                )
            )
        if not parts:
            summary = ScanSummary(
                "pass" if not parsed.unchecked else "incomplete",
                "no package installs found in the command",
                {},
                [],
                0,
                not parsed.unchecked,
                notes,
                Untrusted.tree(subject),
            )
            return Scans.outcome(summary)
        merged = Results.merge(
            parts, max_findings=Args.max_findings(settings, args), subject=subject
        )
        merged.notes = list(dict.fromkeys(notes + merged.notes))
        if parsed.warnings and merged.verdict == "pass":
            merged.verdict = "warn"
            merged.summary += "; the command changes where packages come from (see notes)"
        if parsed.unchecked and merged.verdict == "pass":
            merged.verdict = "incomplete"
        return Scans.outcome(merged)

    @staticmethod
    def shell_risk(command: str) -> ScanSummary | None:
        """What the scanner's agent-command classifier says about the command as a whole: piping a
        download into a shell, decoding and running, and the other fetch-and-run shapes."""
        from cordon_scanner.detect.agents import configuration

        verdict = configuration.CommandClassifier.classify(command)
        if verdict is None:
            return None
        finding = {
            "rule_id": "CORDON.MCP.COMMAND.001",
            "severity": "high",
            "confidence": "high",
            "category": "suspicious",
            "message": f"The command itself is dangerous to run: {Untrusted.text(str(verdict), 600)}",
            "remediation": "Do not run it. Install the package by name from its registry instead.",
        }
        counts = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
        return ScanSummary("block", "the command fetches and runs code", counts, [finding], 1, True)

    @staticmethod
    def get_package_advisories(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase

        spec = PackageTools.spec(args)
        database = AdvisoryDatabase.bundled()
        records = database.for_package(spec.ecosystem, spec.name)
        entries = [
            {
                "id": a.identifier,
                "aliases": list(a.aliases[:10]),
                "malicious": a.malicious,
                "severity": a.severity or ("critical" if a.malicious else ""),
                "summary": a.summary,
                "affects_this_version": a.affects(spec.version) if spec.version else None,
                "affected_versions": list(a.versions[:50]),
                "introduced": a.introduced,
                "fixed": a.fixed,
                "last_affected": a.last_affected,
                "reference": a.reference,
            }
            for a in records[:300]
        ]
        affecting = [e for e in entries if e["affects_this_version"]]
        structured = {
            "package": spec.label,
            "records": len(records),
            "affecting_this_version": len(affecting) if spec.version else None,
            "malicious_records": sum(1 for e in entries if e["malicious"]),
            "fixed_in": sorted({str(e["fixed"]) for e in affecting if e["fixed"]}),
            "advisories": entries,
        }
        head = f"{spec.label}: {len(records)} advisory record(s)"
        if spec.version:
            head += f", {len(affecting)} affecting this version"
        return Scans.data(structured, head)
