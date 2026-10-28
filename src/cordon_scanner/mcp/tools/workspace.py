"""The workspace tools: scans of a path, secrets, release and baseline comparisons, dependency
reviews and graphs, the repository's description, bills of materials and suppressions."""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.mcp.runner import CancelToken
from cordon_scanner.mcp.tools.base import (
    SEVERITY_ENUM,
    Args,
    Outcome,
    Scans,
    Settings,
    ToolError,
)
from cordon_scanner.mcp.untrusted import Untrusted


class WorkspaceTools:
    @staticmethod
    def scan_path(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        target = Args.path(settings, args)
        extra: list[str] = []
        for glob in Args.strings(args, "include"):
            extra.append(f"--include={glob}")
        for glob in Args.strings(args, "exclude"):
            extra.append(f"--exclude={glob}")
        since = Args.text(args, "changed_since", limit=200)
        if since:
            extra += ["--git-diff", Args.revision(since, "changed_since")]
        for key, flag in (
            ("staged", "--staged"),
            ("tracked_only", "--tracked"),
            ("history", "--history"),
            ("reachability", "--reachability"),
        ):
            if Args.flag(args, key):
                extra.append(flag)
        fail_on = args.get("fail_on")
        if fail_on is not None:
            if fail_on not in SEVERITY_ENUM:
                raise ToolError(f"fail_on must be one of {', '.join(SEVERITY_ENUM)}")
            extra += ["--fail-on", str(fail_on)]
        return Scans.outcome(
            Scans.scan(
                settings,
                str(target),
                token,
                online=online,
                severity=Args.severity(args),
                extra=extra,
                max_findings=Args.max_findings(settings, args),
                subject={"path": str(target)},
            )
        )

    @staticmethod
    def find_secrets(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        target = Args.path(settings, args)
        verify = Args.flag(args, "verify")
        if verify and not settings.allow_online:
            raise ToolError(
                "verify asks each credential's issuer whether it works, and online checks are off for this server"
            )
        extra = ["--detector", "secrets"]
        if Args.flag(args, "history"):
            extra.append("--history")
        if verify:
            extra.append("--verify-secrets")
        return Scans.outcome(
            Scans.scan(
                settings,
                str(target),
                token,
                online=verify,
                extra=extra,
                max_findings=Args.max_findings(settings, args),
                subject={"path": str(target)},
                notes=["secret values are never returned: evidence is masked"],
            )
        )

    @staticmethod
    def compare_releases(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        target = Args.path(settings, args)
        previous = Args.path(settings, args, "previous_path")
        return Scans.outcome(
            Scans.scan(
                settings,
                str(target),
                token,
                online=False,
                extra=["--compare-with", str(previous)],
                max_findings=Args.max_findings(settings, args),
                subject={"path": str(target), "previous": str(previous)},
            )
        )

    @staticmethod
    def compare_with_baseline(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        target = Args.path(settings, args)
        baseline = Args.path(settings, args, "baseline")
        return Scans.outcome(
            Scans.scan(
                settings,
                str(target),
                token,
                online=False,
                severity=Args.severity(args),
                extra=["--baseline", str(baseline)],
                max_findings=Args.max_findings(settings, args),
                subject={"path": str(target), "baseline": str(baseline)},
                notes=["findings recorded in the baseline are left out: these are the new ones"],
            )
        )

    @staticmethod
    def review_dependency_changes(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        online = Args.online(settings, args)
        target = Args.path(settings, args)
        base = Args.revision(Args.text(args, "base", required=True, limit=200) or "", "base")
        argv = ["review", str(target), "--base", base, "--format", "json", "--quiet"]
        if online:
            argv.append("--online")
        document, _ = Scans.run_json(settings, argv, token)
        return Scans.data(Scans.document(document, "review"), f"Dependency changes since {base}")

    @staticmethod
    def list_dependencies(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        target = Args.path(settings, args)
        argv = ["deps", str(target), "--format", "json"]
        if Args.flag(args, "direct_only"):
            argv.append("--direct-only")
        if online:
            argv.append("--online")
        document, _ = Scans.run_json(settings, argv, token)
        return Scans.data(Scans.document(document, "dependencies"), "Dependency graph")

    @staticmethod
    def describe_repository(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        target = Args.path(settings, args)
        document, _ = Scans.run_json(
            settings, ["inventory", str(target), "--format", "json"], token, ok=(0,)
        )
        return Scans.data(Scans.document(document, "inventory"), "What the repository is")

    @staticmethod
    def generate_sbom(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        target = Args.path(settings, args)
        fmt = args.get("format", "cyclonedx")
        if fmt not in ("cyclonedx", "spdx"):
            raise ToolError("format must be cyclonedx or spdx")
        argv = ["sbom", "generate", str(target), "--format", str(fmt)]
        if Args.flag(args, "ai"):
            if fmt != "cyclonedx":
                raise ToolError("the AI bill of materials is CycloneDX 1.6; use format cyclonedx")
            argv.append("--ai")
        if Args.flag(args, "vulnerabilities"):
            argv.append("--vulnerabilities")
        document, _ = Scans.run_json(settings, argv, token, ok=(0,))
        if len(json.dumps(document)) > 8 << 20:
            raise ToolError(
                "the bill of materials is larger than 8 MB; generate it with `cordon-scanner sbom generate` instead"
            )
        clean = Untrusted.tree(Scans.document(document, "sbom"), 4000)
        return Outcome(clean, json.dumps(clean, ensure_ascii=False))

    @staticmethod
    def list_suppressions(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        target = Args.path(settings, args)
        document, _ = Scans.run_json(
            settings,
            ["suppress", "list", "--root", str(target), "--format", "json"],
            token,
            ok=(0, 1),
        )
        return Scans.data(
            Scans.document(document, "suppressions"), "Suppressions and whether each is in force"
        )
