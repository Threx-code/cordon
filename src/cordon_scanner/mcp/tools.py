"""The tools Cordon's MCP server offers, and what each one runs.

Every tool reads. None installs, executes what it reads, writes into a workspace root or changes any
configuration; all of them are annotated read-only and non-destructive. Tools that reach a registry
or a remote server are annotated open-world and need the server started with `--allow-online`;
tools that read beyond the workspace (the machine's own agents, the host's packages) need
`--allow-machine`. Each tool runs the scanner's own code -- most by running the scanner in a child
process (`runner`), a few by calling the same function the scanner calls -- so an agent gets the
verdict the CLI, CI and the editor would give.

    Args            argument checking, shared by every tool
    Scans           running the scanner and shaping what it returns
    PackageTools    packages, lists of packages, install commands, advisories
    WorkspaceTools  paths in the workspace: scans, secrets, graphs, bills of materials, reviews
    AgentTools      content an agent is about to use: files, skills, MCP servers, extensions
    MachineTools    container images and this machine
    KnowledgeTools  rules, intel and this server
    Catalogue       the tool definitions
"""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar, Final

from cordon_scanner.mcp.extensions import ExtensionError, ExtensionFetcher
from cordon_scanner.mcp.packages import (
    ECOSYSTEMS,
    InstallCommand,
    Lockfiles,
    PackageError,
    PackageSpec,
)
from cordon_scanner.mcp.results import SCAN_OUTPUT, Results, ScanSummary
from cordon_scanner.mcp.runner import CancelToken, Runner, TimedOut
from cordon_scanner.mcp.untrusted import NOTICE, Untrusted
from cordon_scanner.mcp.workspace import OutsideWorkspace, Workspace

MAX_CONTENT: Final = 2 << 20
MAX_FILES: Final = 200
MAX_PACKAGES: Final = 200
SEVERITY_ENUM: Final = ["info", "low", "medium", "high", "critical"]
_REVISION: Final = re.compile(r"[A-Za-z0-9._/@^~{}-]+")


class ToolError(Exception):
    """A tool execution error: reported to the model with isError, so it can correct the call."""


@dataclass(frozen=True, slots=True)
class Settings:
    workspace: Workspace
    runner: Runner
    allow_online: bool = False
    allow_machine: bool = False
    allow_private_network: bool = False
    timeout: float = 600.0
    max_findings: int = 50
    version: str = ""
    jobs: int = 0
    model: str | None = None
    """`--model`: cordon-cloud or a model server's address, passed to every scan."""
    """Worker processes per scan; 0 lets the scanner choose."""


@dataclass(slots=True)
class Outcome:
    structured: dict[str, Any]
    text: str
    is_error: bool = False


Handler = Callable[[Settings, dict[str, Any], CancelToken], Outcome]


@dataclass(frozen=True, slots=True)
class Tool:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler
    output_schema: dict[str, Any] | None = None
    open_world: bool = False
    needs: tuple[str, ...] = ()
    """`online` and/or `machine`: the server flags this tool requires."""

    def definition(self, version: str) -> dict[str, Any]:
        """The tool as `tools/list` describes it, shaped for the negotiated protocol version."""
        out: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
        if version >= "2025-03-26":
            out["annotations"] = {
                "title": self.title,
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": not self.open_world,
                "openWorldHint": self.open_world,
            }
        if version >= "2025-06-18":
            out["title"] = self.title
            if self.output_schema is not None:
                out["outputSchema"] = self.output_schema
        return out


class Args:
    """Checks a tool's arguments; each failure is a ToolError the model can act on."""

    #: Windows device names: a file called `NUL` or `CON.txt` is the device, wherever it is put.
    DEVICES: ClassVar[frozenset[str]] = frozenset(
        {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        | {f"COM{i}" for i in range(10)}
        | {f"LPT{i}" for i in range(10)}
    )

    @staticmethod
    def flag(args: dict[str, Any], key: str) -> bool:
        value = args.get(key, False)
        if not isinstance(value, bool):
            raise ToolError(f"{key} must be true or false")
        return value

    @staticmethod
    def text(
        args: dict[str, Any], key: str, *, required: bool = False, limit: int = 4096
    ) -> str | None:
        value = args.get(key)
        if value is None:
            if required:
                raise ToolError(f"{key} is required")
            return None
        if not isinstance(value, str):
            raise ToolError(f"{key} must be a string")
        if len(value) > limit:
            raise ToolError(f"{key} is longer than {limit} characters")
        return value

    @staticmethod
    def strings(args: dict[str, Any], key: str, limit: int = 50) -> list[str]:
        value = args.get(key) or []
        if not isinstance(value, list) or not all(
            isinstance(v, str) and 0 < len(v) <= 512 for v in value
        ):
            raise ToolError(f"{key} must be a list of strings")
        if len(value) > limit:
            raise ToolError(f"{key} holds more than {limit} entries")
        return value

    @staticmethod
    def max_findings(settings: Settings, args: dict[str, Any]) -> int:
        value = args.get("max_findings", settings.max_findings)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 500:
            raise ToolError("max_findings must be an integer from 1 to 500")
        return value

    @staticmethod
    def severity(args: dict[str, Any], default: str = "low") -> str:
        value = args.get("severity", default)
        if value not in SEVERITY_ENUM:
            raise ToolError(f"severity must be one of {', '.join(SEVERITY_ENUM)}")
        return str(value)

    @staticmethod
    def online(settings: Settings, args: dict[str, Any]) -> bool:
        wanted = Args.flag(args, "online")
        if wanted and not settings.allow_online:
            raise ToolError(
                "online checks are turned off for this server. Ask the user to start it with "
                "--allow-online, or call again without online for the offline check."
            )
        return wanted

    @staticmethod
    def path(settings: Settings, args: dict[str, Any], key: str = "path") -> Path:
        try:
            return settings.workspace.resolve(Args.text(args, key) or ".")
        except OutsideWorkspace as exc:
            raise ToolError(str(exc)) from exc

    @staticmethod
    def relative(value: str) -> PurePosixPath:
        """A relative path for content a caller supplied: no root, no `..`, no backslashes, and
        nothing Windows reads differently -- a drive (`C:/x` is absolute there), a stream
        (`a:b`), a device name (`CON`, `NUL.txt`) or a part ending in a dot or space."""
        if (
            not value
            or len(value) > 255
            or "//" in value
            or any(c in value for c in '\\\x00:*?"<>|')
        ):
            raise ToolError(f"not a usable relative path: {value[:80]!r}")
        if any(ord(c) < 32 for c in value):
            raise ToolError("a path may not contain control characters")
        for part in value.split("/"):
            stem = part.split(".", 1)[0].upper()
            if stem in Args.DEVICES or (part and part[-1] in ". " and part not in (".", "..")):
                raise ToolError(f"{part!r} is not a usable file name on every system")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or any(part in ("..", "") for part in path.parts)
            or value.startswith("~")
        ):
            raise ToolError(
                f"{value!r} must be a relative path inside the checked content, without '..'"
            )
        return path

    @staticmethod
    def revision(value: str, key: str) -> str:
        if not _REVISION.fullmatch(value) or value.startswith("-"):
            raise ToolError(f"{key} must be a git revision such as origin/main or HEAD~3")
        return value

    @staticmethod
    def content(args: dict[str, Any], key: str = "content") -> str:
        return Args.text(args, key, required=True, limit=MAX_CONTENT) or ""


class Scans:
    """Runs the scanner and shapes what it returns."""

    @staticmethod
    def run_json(
        settings: Settings, args: list[str], token: CancelToken, *, ok: tuple[int, ...] = (0, 1, 4)
    ) -> tuple[Any, int]:
        try:
            run = settings.runner.run(args, timeout=settings.timeout, token=token)
        except TimedOut as exc:
            raise ToolError(str(exc)) from exc
        if run.exit_code not in ok:
            lines = run.stderr.strip().splitlines()
            detail = Untrusted.text(lines[-1] if lines else "", 600)
            raise ToolError(f"the scanner stopped with exit code {run.exit_code}: {detail}")
        if run.truncated:
            raise ToolError(
                "the scanner's output passed the 64 MB the server returns; narrow the request"
            )
        try:
            return run.json(), run.exit_code
        except ValueError as exc:
            raise ToolError("the scanner did not produce JSON output") from exc

    @staticmethod
    def scan(
        settings: Settings,
        target: str,
        token: CancelToken,
        *,
        online: bool,
        max_findings: int,
        severity: str = "low",
        extra: list[str] | None = None,
        subject: dict[str, Any] | None = None,
        notes: list[str] | None = None,
        cache: bool = True,
        package_only: bool = False,
    ) -> ScanSummary:
        args = [
            "scan",
            target,
            "--format",
            "json",
            "--progress",
            "never",
            "--no-color",
            "--severity",
            severity,
        ]
        if online:
            args.append("--online")
        elif not settings.model:
            args.append("--offline")
        if settings.model:
            # Cordon's own model scores the packages the scan holds; only features are sent.
            args += ["--model", settings.model]
        if settings.jobs:
            args += ["--jobs", str(settings.jobs)]
        if not cache:
            args.append("--no-cache")
        args += extra or []
        document, code = Scans.run_json(settings, args, token)
        return Results.summarise(
            document,
            code,
            max_findings=max_findings,
            subject=subject,
            notes=notes,
            package_only=package_only,
        )

    @staticmethod
    def outcome(summary: ScanSummary) -> Outcome:
        return Outcome(summary.structured(), summary.text())

    @staticmethod
    def data(structured: dict[str, Any], heading: str) -> Outcome:
        clean = Untrusted.tree(structured)
        return Outcome(clean, f"{heading}\n{NOTICE}\n\n" + json.dumps(clean, ensure_ascii=False))

    @staticmethod
    def document(value: Any, key: str) -> dict[str, Any]:
        return value if isinstance(value, dict) else {key: value}

    @staticmethod
    def write_tree(root: Path, files: dict[str, str]) -> None:
        for relative, content in files.items():
            target = root / Args.relative(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

    @staticmethod
    def files(
        settings: Settings,
        files: dict[str, str],
        token: CancelToken,
        args: dict[str, Any],
        subject: dict[str, Any],
        online: bool = False,
    ) -> ScanSummary:
        """Content a caller supplied, written into a private temporary directory and scanned there."""
        with tempfile.TemporaryDirectory(prefix="cordon-mcp-") as work:
            root = Path(work) / "content"
            root.mkdir()
            Scans.write_tree(root, files)
            return Scans.scan(
                settings,
                str(root),
                token,
                online=online,
                severity=Args.severity(args),
                max_findings=Args.max_findings(settings, args),
                subject=subject,
                cache=False,
            )


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
        from cordon_scanner.detect import agent_config

        verdict = agent_config.CommandClassifier.classify(command)
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
        from cordon_scanner.intel.advisories import AdvisoryDatabase

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


class AgentTools:
    CONFIG_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "command",
            "args",
            "env",
            "url",
            "type",
            "headers",
            "cwd",
            "transport",
            "serverUrl",
            "httpUrl",
            "disabled",
            "timeout",
        }
    )

    @staticmethod
    def scan_file_content(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        name = str(Args.relative(Args.text(args, "filename", required=True, limit=255) or ""))
        content = Args.content(args)
        hidden = Untrusted.hidden_count(content)
        summary = Scans.files(
            settings,
            {name: content},
            token,
            args,
            {"filename": name, "bytes": len(content.encode())},
        )
        if hidden:
            summary.notes.append(
                f"the content holds {hidden} invisible or direction-changing character(s)"
            )
        return Scans.outcome(summary)

    @staticmethod
    def check_agent_file(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        name = str(Args.relative(Args.text(args, "path", required=True, limit=255) or ""))
        return Scans.outcome(
            Scans.files(settings, {name: Args.content(args)}, token, args, {"agent_file": name})
        )

    @staticmethod
    def check_skill(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        name = Args.text(args, "name", required=True, limit=100) or ""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name):
            raise ToolError("name must be a skill directory name: letters, digits, '.', '_' or '-'")
        files = args.get("files")
        if not isinstance(files, dict) or not files:
            raise ToolError("files must map each file's path inside the skill to its content")
        if len(files) > MAX_FILES:
            raise ToolError(f"at most {MAX_FILES} files per skill")
        total = 0
        tree: dict[str, str] = {}
        for relative, content in files.items():
            if not isinstance(content, str):
                raise ToolError(f"{relative}: content must be a string")
            total += len(content)
            if total > 8 * MAX_CONTENT:
                raise ToolError("the skill's files are larger than 16 MB together")
            tree[f".claude/skills/{name}/{Args.relative(str(relative))}"] = content
        if not any(PurePosixPath(k).name == "SKILL.md" for k in tree):
            raise ToolError("a skill needs its SKILL.md among the files")
        return Scans.outcome(
            Scans.files(settings, tree, token, args, {"skill": name, "files": sorted(files)})
        )

    @staticmethod
    def check_mcp_server(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        name = Args.text(args, "name", required=True, limit=100) or ""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@/-]{0,99}", name):
            raise ToolError(
                "name must be the server's key: letters, digits, '.', '_', '@', '/' or '-'"
            )
        config = args.get("config")
        remote = isinstance(config, dict) and any(
            config.get(k) for k in ("url", "serverUrl", "httpUrl")
        )
        if not isinstance(config, dict) or not (config.get("command") or remote):
            raise ToolError("config is the server's entry: a command (with args) or a url")
        unknown = set(config) - AgentTools.CONFIG_KEYS
        if unknown:
            raise ToolError(f"unrecognised config keys: {', '.join(sorted(unknown))}")
        body = json.dumps({"mcpServers": {name: config}}, indent=2)
        if len(body) > MAX_CONTENT:
            raise ToolError("config is larger than 2 MB")
        parts = [
            Scans.files(
                settings, {".mcp.json": body}, token, args, {"mcp_server": name}, online=online
            )
        ]
        words = [str(config.get("command") or "")]
        words += [str(a) for a in config.get("args") or [] if isinstance(a, str | int | float)]
        launch = " ".join(words).strip()
        notes: list[str] = []
        if launch and config.get("command"):
            try:
                parsed = InstallCommand.parse(launch)
            except PackageError:
                parsed = None
            if parsed and parsed.packages:
                parts.append(
                    PackageTools.check(
                        settings,
                        parsed.packages,
                        token,
                        online=online,
                        max_findings=Args.max_findings(settings, args),
                        subject={"launches": [s.label for s in parsed.packages]},
                    )
                )
                notes.append("launches " + ", ".join(s.label for s in parsed.packages))
                if any(not s.version for s in parsed.packages):
                    notes.append(
                        "the launched package is not pinned to a version: every start can run a different release"
                    )
        image = AgentTools.container_image(config)
        if image is not None:
            notes.append(f"launches the container image {image}")
            if not re.search(r"@sha256:[0-9a-f]{64}$", image) and not re.search(
                r":(?!latest$)[^/:@]+$", image
            ):
                notes.append(
                    "the image is not pinned to a tag or digest: every start can run a different image"
                )
            if online:
                try:
                    parts.append(
                        Scans.scan(
                            settings,
                            MachineTools.image_purl(image),
                            token,
                            online=True,
                            severity=Args.severity(args),
                            max_findings=Args.max_findings(settings, args),
                            subject={"image": image},
                            cache=False,
                        )
                    )
                except ToolError as exc:
                    notes.append(f"the image was not scanned: {exc}")
                    parts.append(ScanSummary("incomplete", "image not scanned", {}, [], 0, False))
            else:
                notes.append(
                    "the image itself is only pulled and scanned online (--allow-online and online)"
                )
        if remote and not online:
            notes.append(
                "a remote server: what it serves now is only read online (--allow-online and online)"
            )
        merged = Results.merge(
            parts,
            max_findings=Args.max_findings(settings, args),
            subject={"mcp_server": name, "launch": launch[:300]},
        )
        merged.notes = list(dict.fromkeys(notes + merged.notes))
        return Scans.outcome(merged)

    #: `docker`/`podman`/`nerdctl` options that take a value, so the value is not the image.
    CONTAINER_VALUED: ClassVar[frozenset[str]] = frozenset(
        {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish", "--name",
         "--network", "--net", "-u", "--user", "-w", "--workdir", "--entrypoint", "--platform",
         "-l", "--label", "--pull", "--add-host", "--cap-add", "--cap-drop", "--memory", "-m",
         "--cpus", "--restart", "--hostname", "-h", "--device", "--security-opt", "--tmpfs"}
    )  # fmt: skip

    @staticmethod
    def container_image(config: dict[str, Any]) -> str | None:
        """The image a `docker run` (or podman, nerdctl) launch starts, or None."""
        command = PurePosixPath(str(config.get("command") or "")).name.removesuffix(".exe")
        if command not in {"docker", "podman", "nerdctl"}:
            return None
        words = [str(a) for a in config.get("args") or [] if isinstance(a, str | int | float)]
        if "run" not in words:
            return None
        rest = words[words.index("run") + 1 :]
        skip = False
        for word in rest:
            if skip:
                skip = False
                continue
            if word.startswith("-"):
                skip = word in AgentTools.CONTAINER_VALUED and "=" not in word
                continue
            return word if MachineTools.IMAGE.match(word) else None
        return None

    @staticmethod
    def check_mcp_tools(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        from cordon_scanner.detect.agents import McpServerSource

        tools = args.get("tools")
        if not isinstance(tools, list) or not tools or len(tools) > 1000:
            raise ToolError(
                "tools must be a list of 1 to 1000 tool definitions, as tools/list returns them"
            )
        findings: list[dict[str, Any]] = []
        for entry in tools:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise ToolError("each tool needs at least a name")
            texts: list[tuple[str, str]] = [("description", str(entry.get("description") or ""))]
            schema = entry.get("inputSchema")
            if isinstance(schema, dict):
                texts += AgentTools.schema_descriptions(schema, "inputSchema")
            for where, text in texts:
                if not text:
                    continue
                if len(text) > MAX_CONTENT:
                    raise ToolError(f"{entry['name']}: a description is longer than 2 MB")
                reason = McpServerSource._poisoned_description(text)
                if reason:
                    tool = Untrusted.text(entry["name"], 100)
                    findings.append(
                        {
                            "rule_id": "SUSPECT.AGENT.MCP_TOOL_POISONING.001",
                            "severity": "high",
                            "confidence": "high",
                            "category": "suspicious",
                            "path": Untrusted.text(f"{entry['name']}:{where}", 300),
                            "message": f"Tool {tool!r} {reason} in its {where}: a description that steers "
                            "the agent rather than describing the tool (tool poisoning).",
                            "remediation": "Do not add this server, or remove the tool, until its description is fixed.",
                        }
                    )
        counts = {"critical": 0, "high": len(findings), "medium": 0, "low": 0, "info": 0}
        summary = ScanSummary(
            "block" if findings else "pass",
            f"{len(findings)} poisoned description(s) in {len(tools)} tool(s)"
            if findings
            else f"{len(tools)} tool description(s), none steering the agent",
            counts,
            findings[: Args.max_findings(settings, args)],
            len(findings),
            True,
            ["checked with the test the scanner applies to every MCP server it reads"],
            {"server": Untrusted.text(args.get("server") or "", 200)},
        )
        return Scans.outcome(summary)

    @staticmethod
    def schema_descriptions(
        schema: dict[str, Any], where: str, depth: int = 0
    ) -> list[tuple[str, str]]:
        """Every description inside a tool's input schema: parameter descriptions steer agents too."""
        if depth > 8:
            return []
        out: list[tuple[str, str]] = []
        if isinstance(schema.get("description"), str) and depth:
            out.append((where, schema["description"]))
        for key in ("properties", "$defs", "definitions"):
            children = schema.get(key)
            if isinstance(children, dict):
                for child, sub in list(children.items())[:500]:
                    if isinstance(sub, dict):
                        out += AgentTools.schema_descriptions(sub, f"{where}.{child}", depth + 1)
        items = schema.get("items")
        if isinstance(items, dict):
            out += AgentTools.schema_descriptions(items, f"{where}[]", depth + 1)
        return out

    @staticmethod
    def check_ide_extension(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        path_arg = Args.text(args, "path")
        identifier = Args.text(args, "id", limit=260)
        if bool(path_arg) == bool(identifier):
            raise ToolError(
                "give either path (a .vsix in the workspace) or id (publisher.name), not both"
            )
        if path_arg:
            target = Args.path(settings, args)
            if not target.is_file():
                raise ToolError("path must be a .vsix file")
            return Scans.outcome(
                Scans.scan(
                    settings,
                    str(target),
                    token,
                    online=False,
                    severity=Args.severity(args),
                    max_findings=Args.max_findings(settings, args),
                    subject={"extension": target.name},
                )
            )
        if not settings.allow_online:
            raise ToolError(
                "fetching an extension by id needs the server started with --allow-online; or give the path to a .vsix"
            )
        registry = args.get("registry", "open-vsx")
        if registry not in ("open-vsx", "vscode-marketplace"):
            raise ToolError("registry must be open-vsx or vscode-marketplace")
        with tempfile.TemporaryDirectory(prefix="cordon-mcp-ext-") as work:
            try:
                fetch = (
                    ExtensionFetcher.open_vsx
                    if registry == "open-vsx"
                    else ExtensionFetcher.marketplace
                )
                fetched = fetch(identifier or "", Args.text(args, "version", limit=64), Path(work))
            except ExtensionError as exc:
                raise ToolError(str(exc)) from exc
            summary = Scans.scan(
                settings,
                str(fetched.path),
                token,
                online=True,
                severity=Args.severity(args),
                max_findings=Args.max_findings(settings, args),
                subject={
                    "extension": fetched.identifier,
                    "version": fetched.version,
                    "registry": fetched.registry,
                },
                cache=False,
                notes=[f"integrity: {fetched.integrity}"],
            )
        return Scans.outcome(summary)


class MachineTools:
    IMAGE: ClassVar[re.Pattern[str]] = re.compile(
        r"^[a-z0-9][a-z0-9._/-]{0,254}(?::[A-Za-z0-9_.-]{1,128})?(?:@sha256:[0-9a-f]{64})?$"
    )

    @staticmethod
    def image_purl(image: str) -> str:
        if image.startswith("pkg:"):
            return image
        if not MachineTools.IMAGE.match(image):
            raise ToolError(
                "image must be a reference such as nginx:1.27, ghcr.io/org/app:2 or name@sha256:<digest>"
            )
        name, _, digest = image.partition("@")
        last = name.rsplit("/", 1)[-1]
        repo, tag = (name.rsplit(":", 1)[0], name.rsplit(":", 1)[1]) if ":" in last else (name, "")
        return f"pkg:docker/{repo}@{digest or tag or 'latest'}"

    @staticmethod
    def scan_container_image(
        settings: Settings, args: dict[str, Any], token: CancelToken
    ) -> Outcome:
        if not settings.allow_online:
            raise ToolError(
                "an image is pulled from its registry, and online checks are off for this server (--allow-online)"
            )
        image = (Args.text(args, "image", required=True, limit=400) or "").strip()
        return Scans.outcome(
            Scans.scan(
                settings,
                MachineTools.image_purl(image),
                token,
                online=True,
                severity=Args.severity(args),
                max_findings=Args.max_findings(settings, args),
                subject={"image": image},
                cache=False,
            )
        )

    @staticmethod
    def scan_machine(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        online = Args.online(settings, args)
        extra = ["--host"]
        if Args.flag(args, "include_home"):
            extra += ["--home", str(Path.home())]
        return Scans.outcome(
            Scans.scan(
                settings,
                "/",
                token,
                online=online,
                severity=Args.severity(args),
                extra=extra,
                max_findings=Args.max_findings(settings, args),
                subject={"machine": "this computer's installed packages"},
            )
        )

    @staticmethod
    def list_local_agents(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        document, _ = Scans.run_json(settings, ["agent", "inventory"], token, ok=(0, 1))
        found = Scans.document(document, "inventory")
        found.pop("device", None)
        return Scans.data(
            found,
            "AI agents, MCP servers and editor extensions configured on this machine (nothing was sent anywhere)",
        )


class KnowledgeTools:
    @staticmethod
    def rules() -> tuple[list[Any], list[Any]]:
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.rules.loader import RuleLoader

        pack_rules = [compiled.rule for pack in RuleLoader.load_builtin() for compiled in pack]
        return pack_rules, list(
            RuleCatalogue.from_detectors(Registry(allow_third_party=False).detectors())
        )

    @staticmethod
    def entry(rule: Any, origin: str) -> dict[str, Any]:
        return {
            "id": rule.id,
            "title": rule.title,
            "severity": str(rule.severity),
            "confidence": str(rule.confidence),
            "category": str(rule.category),
            "origin": origin,
        }

    @staticmethod
    def explain_rule(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        rule_id = (Args.text(args, "rule_id", required=True, limit=200) or "").strip()
        pack_rules, declared = KnowledgeTools.rules()
        for rule in pack_rules:
            if rule.id == rule_id:
                entry = {
                    **KnowledgeTools.entry(rule, "pack"),
                    "message": rule.message,
                    "remediation": rule.remediation,
                    "references": list(rule.references),
                    "version": rule.version,
                    "rulepack": rule.rulepack,
                    "languages": list(rule.languages),
                    "enabled": rule.enabled,
                }
                return Scans.data(entry, f"{rule.id}: {rule.title}")
        for declared_rule in declared:
            if declared_rule.id == rule_id:
                entry = {
                    **KnowledgeTools.entry(declared_rule, f"detector:{declared_rule.detector}"),
                    "message": declared_rule.message,
                    "remediation": declared_rule.remediation,
                    "references": list(declared_rule.references),
                }
                return Scans.data(entry, f"{declared_rule.id}: {declared_rule.title}")
        raise ToolError(f"no rule {rule_id!r}; search_rules lists them")

    @staticmethod
    def search_rules(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        query = (Args.text(args, "query", limit=200) or "").lower()
        category = Args.text(args, "category", limit=60)
        minimum = args.get("min_severity")
        if minimum is not None and minimum not in SEVERITY_ENUM:
            raise ToolError(f"min_severity must be one of {', '.join(SEVERITY_ENUM)}")
        limit = args.get("limit", 50)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ToolError("limit must be an integer from 1 to 500")
        pack_rules, declared = KnowledgeTools.rules()
        entries = [KnowledgeTools.entry(r, "pack") for r in pack_rules]
        entries += [KnowledgeTools.entry(r, f"detector:{r.detector}") for r in declared]
        floor = SEVERITY_ENUM.index(minimum) if minimum else 0
        matched = sorted(
            (
                e
                for e in entries
                if (not query or query in e["id"].lower() or query in e["title"].lower())
                and (not category or e["category"] == category)
                and (
                    e["severity"] not in SEVERITY_ENUM
                    or SEVERITY_ENUM.index(e["severity"]) >= floor
                )
            ),
            key=lambda e: e["id"],
        )
        return Scans.data(
            {"total_rules": len(entries), "matched": len(matched), "rules": matched[:limit]},
            f"{len(matched)} rule(s) matched",
        )

    @staticmethod
    def intel_status(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        document, _ = Scans.run_json(settings, ["intel", "status", "--json"], token, ok=(0, 1))
        return Scans.data(Scans.document(document, "intel"), "Threat-intel source, serial and age")

    @staticmethod
    def server_status(settings: Settings, args: dict[str, Any], token: CancelToken) -> Outcome:
        try:
            run = settings.runner.run(["whoami"], timeout=30, token=token)
            # Signed in or not, never who: the identity would go to the model and its provider.
            cloud = "signed in" if run.exit_code == 0 else "not signed in"
        except TimedOut:
            cloud = "unknown (timed out)"
        structured = {
            "server": "cordon-scanner",
            "version": settings.version,
            "workspace_roots": settings.workspace.describe(),
            "online_allowed": settings.allow_online,
            "machine_reads_allowed": settings.allow_machine,
            "private_network_allowed": settings.allow_private_network,
            "scan_timeout_seconds": settings.timeout,
            "cordon_cloud": cloud,
            "ecosystems": list(ECOSYSTEMS),
            "tools": [t.name for t in Catalogue.available(settings)],
        }
        return Scans.data(structured, "Cordon MCP server status")


class Catalogue:
    """The tool definitions, in a fixed order (the specification asks for a deterministic list)."""

    ONLINE: ClassVar[dict[str, Any]] = {
        "type": "boolean",
        "default": False,
        "description": "Also ask the public registries (fetch and scan the published code, newest "
        "intel). Needs the server started with --allow-online.",
    }
    SEVERITY: ClassVar[dict[str, Any]] = {
        "enum": SEVERITY_ENUM,
        "default": "low",
        "description": "Report findings at or above this severity.",
    }
    PATH: ClassVar[dict[str, Any]] = {
        "type": "string",
        "description": "A path inside the workspace (relative paths are taken from the first root).",
    }
    MAX: ClassVar[dict[str, Any]] = {
        "type": "integer",
        "minimum": 1,
        "maximum": 500,
        "description": "Most findings to return (default 50).",
    }
    PACKAGE: ClassVar[dict[str, Any]] = {
        "ecosystem": {
            "enum": list(ECOSYSTEMS),
            "description": "The registry: npm, pypi, cargo, gomod, maven (group:artifact), nuget, composer, "
            "rubygems, pub, hex, cran, swift.",
        },
        "name": {
            "type": "string",
            "description": "The package name exactly as published (Maven: group:artifact; Go: module path).",
        },
        "version": {
            "type": "string",
            "description": "The exact version. Without it only the name is checked (typosquat, hallucinated "
            "name, malware-only name).",
        },
    }
    DATA: ClassVar[dict[str, Any]] = {"type": "object"}

    @staticmethod
    def schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": False,
        }

    @classmethod
    def build(cls) -> list[Tool]:
        s, on, sev, path, mx, pkg, data = (
            cls.schema,
            cls.ONLINE,
            cls.SEVERITY,
            cls.PATH,
            cls.MAX,
            cls.PACKAGE,
            cls.DATA,
        )
        strings = {"type": "array", "items": {"type": "string"}}
        return [
            Tool(
                "check_package",
                "Check a package before installing it",
                "Before installing or recommending a package, ask whether it is safe: known malicious releases, "
                "known vulnerabilities (with the version that fixes them), typosquats of popular packages and "
                "names AI assistants are documented to invent. With online, also fetch the published release, "
                "verify it against the registry's digest and scan its code (install scripts, obfuscation, "
                "credential theft, what changed since the previous release). Verdict block means do not install.",
                s({**pkg, "online": on, "max_findings": mx}, ["ecosystem", "name"]),
                PackageTools.check_package,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "check_packages",
                "Check many packages at once",
                "check_package for up to 200 packages in one call, across ecosystems: for a dependency list, a "
                "plan of what to add, or everything a generated project would install.",
                s(
                    {
                        "packages": {
                            "type": "array",
                            "maxItems": MAX_PACKAGES,
                            "items": s(pkg, ["ecosystem", "name"]),
                        },
                        "online": on,
                        "max_findings": mx,
                    },
                    ["packages"],
                ),
                PackageTools.check_packages,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "check_install_command",
                "Check a shell install command before running it",
                "Before running a command that installs software -- npm/yarn/pnpm/bun install or add, npx, "
                "pip/uv/poetry/pipx/uvx, cargo, gem/bundle, go get/install, dotnet add package, composer require "
                "-- pass the command. Every package it names is checked as check_package does; a custom registry "
                "or index, a URL, git or local source, and fetch-and-run shapes such as curl | sh are reported. "
                "Verdict block means do not run it.",
                s(
                    {
                        "command": {
                            "type": "string",
                            "description": "The command exactly as it would be run.",
                        },
                        "online": on,
                        "max_findings": mx,
                    },
                    ["command"],
                ),
                PackageTools.check_install_command,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "get_package_advisories",
                "List a package's advisories",
                "Every advisory Cordon holds for a package -- malicious-release records and vulnerabilities, "
                "with affected and fixed versions -- and, given a version, which affect it and the versions that "
                "fix them. For choosing a safe version to upgrade to.",
                s(pkg, ["ecosystem", "name"]),
                PackageTools.get_package_advisories,
                data,
            ),
            Tool(
                "scan_path",
                "Scan a directory, file or archive",
                "Scan part of the workspace with every Cordon detector: malicious and vulnerable dependencies, "
                "install-time behaviour, obfuscated or credential-stealing code, secrets, CI/CD pipelines, "
                "Dockerfiles and infrastructure code, AI agent instruction files, skills, hooks and MCP "
                "configuration, and editor files that run when a folder opens. Archives (.tgz, .whl, .zip, "
                ".vsix, .jar) are opened, never extracted to disk or run.",
                s(
                    {
                        "path": path,
                        "severity": sev,
                        "include": {**strings, "description": "Only paths matching these globs."},
                        "exclude": {**strings, "description": "Skip paths matching these globs."},
                        "changed_since": {
                            "type": "string",
                            "description": "Only files that differ from this git revision (e.g. origin/main).",
                        },
                        "staged": {
                            "type": "boolean",
                            "description": "Scan what is staged in git, not the working tree.",
                        },
                        "tracked_only": {
                            "type": "boolean",
                            "description": "Only files git tracks.",
                        },
                        "history": {
                            "type": "boolean",
                            "description": "Also read git history for secrets removed from the tree.",
                        },
                        "reachability": {
                            "type": "boolean",
                            "description": "Mark vulnerabilities in dependencies no first-party code imports.",
                        },
                        "fail_on": {
                            "enum": SEVERITY_ENUM,
                            "description": "Block at or above this severity instead of the configured policy.",
                        },
                        "online": on,
                        "max_findings": mx,
                    }
                ),
                WorkspaceTools.scan_path,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "find_secrets",
                "Find committed secrets",
                "Find credentials in the workspace -- API keys, tokens, private keys, connection strings -- and, "
                "with history, in git history the tree no longer shows. Values are never returned. With verify "
                "(online), each credential's own issuer is asked whether it still works.",
                s(
                    {
                        "path": path,
                        "history": {"type": "boolean"},
                        "verify": {"type": "boolean"},
                        "max_findings": mx,
                    }
                ),
                WorkspaceTools.find_secrets,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "scan_file_content",
                "Check a file's content before writing or using it",
                "Scan content that is not on disk yet -- a generated Dockerfile, CI workflow, package.json, "
                "requirements file, shell script or config -- as if it were at filename in a repository. Nothing "
                "is written into the workspace.",
                s(
                    {
                        "filename": {
                            "type": "string",
                            "description": "Relative path the content would have, e.g. .github/workflows/ci.yml.",
                        },
                        "content": {"type": "string"},
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["filename", "content"],
                ),
                AgentTools.scan_file_content,
                SCAN_OUTPUT,
            ),
            Tool(
                "check_agent_file",
                "Check an AI agent instruction file",
                "Before following or saving an agent instruction file -- CLAUDE.md, AGENTS.md, GEMINI.md, "
                ".cursorrules, .cursor/rules/*, .github/copilot-instructions.md, .windsurfrules, .clinerules, a "
                "slash command, an agent definition, hooks or settings -- check it for prompt injection, hidden "
                "characters, instructions to fetch and run code, credential access, concealment from the user and "
                "approval being switched off.",
                s(
                    {
                        "path": {
                            "type": "string",
                            "description": "Where the file lives in a repository, e.g. AGENTS.md or .claude/settings.json.",
                        },
                        "content": {"type": "string"},
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["path", "content"],
                ),
                AgentTools.check_agent_file,
                SCAN_OUTPUT,
            ),
            Tool(
                "check_skill",
                "Check an agent skill before loading it",
                "Before installing or loading an agent skill, pass its files (SKILL.md and any scripts or "
                "references). Checked for malicious instructions, droppers, fake prerequisites, credential theft, "
                "remote instructions and scripts that fetch and run code.",
                s(
                    {
                        "name": {"type": "string", "description": "The skill's directory name."},
                        "files": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                            "description": "Path inside the skill -> content. Must include SKILL.md.",
                        },
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["name", "files"],
                ),
                AgentTools.check_skill,
                SCAN_OUTPUT,
            ),
            Tool(
                "check_mcp_server",
                "Check an MCP server before adding it",
                "Before adding an MCP server to an agent's configuration, pass its entry (command and args, or "
                "url). Checked for dangerous launch commands, unpinned or malicious packages it launches (npx, "
                "uvx, pipx, bunx...), secrets in its environment, plain-HTTP or tunnelled endpoints and approval "
                "bypasses. With online, the launched package's published code is scanned and a remote server's "
                "live tool descriptions are read.",
                s(
                    {
                        "name": {
                            "type": "string",
                            "description": "The server's key in the configuration.",
                        },
                        "config": {
                            "type": "object",
                            "description": "The server's entry: command, args, env, or url, type, headers.",
                        },
                        "online": on,
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["name", "config"],
                ),
                AgentTools.check_mcp_server,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "check_mcp_tools",
                "Check MCP tool descriptions for poisoning",
                "Pass the tools an MCP server lists (name, description, inputSchema). Each description and "
                "parameter description is checked for tool poisoning: steering the agent's use of other tools, "
                "asking it to hide things from the user, pointing it at credential files, tags addressed to the "
                "model and invisible characters.",
                s(
                    {
                        "server": {"type": "string"},
                        "tools": {"type": "array", "items": {"type": "object"}},
                        "max_findings": mx,
                    },
                    ["tools"],
                ),
                AgentTools.check_mcp_tools,
                SCAN_OUTPUT,
            ),
            Tool(
                "check_ide_extension",
                "Check an editor extension before installing it",
                "Check a VS Code-compatible extension: a .vsix in the workspace (path), or by id (publisher.name) "
                "fetched from Open VSX -- verified against its published SHA-256 -- or the VS Code Marketplace. "
                "Checked for malicious code, obfuscation, credential theft, activation on every start and "
                "known-malicious or impersonating extensions.",
                s(
                    {
                        "path": path,
                        "id": {"type": "string", "description": "publisher.name"},
                        "version": {"type": "string"},
                        "registry": {
                            "enum": ["open-vsx", "vscode-marketplace"],
                            "default": "open-vsx",
                        },
                        "severity": sev,
                        "max_findings": mx,
                    }
                ),
                AgentTools.check_ide_extension,
                SCAN_OUTPUT,
                open_world=True,
            ),
            Tool(
                "scan_container_image",
                "Scan a container image",
                "Pull an image from its registry (never run it) and scan its OS and language packages for known "
                "vulnerabilities and malicious releases, and its files for secrets and malware. Needs --allow-online.",
                s(
                    {
                        "image": {
                            "type": "string",
                            "description": "e.g. nginx:1.27, ghcr.io/org/app:2, name@sha256:<digest>",
                        },
                        "severity": sev,
                        "max_findings": mx,
                    },
                    ["image"],
                ),
                MachineTools.scan_container_image,
                SCAN_OUTPUT,
                open_world=True,
                needs=("online",),
            ),
            Tool(
                "review_dependency_changes",
                "Review what a dependency update adds",
                "What a branch changes in its dependencies since a git revision: packages added, removed and "
                "upgraded, and for each upgrade, with online, what the new release adds over the old (install "
                "hooks, network or execution, obfuscation, binaries, a new publisher).",
                s(
                    {
                        "path": path,
                        "base": {"type": "string", "description": "e.g. origin/main"},
                        "online": on,
                    },
                    ["base"],
                ),
                WorkspaceTools.review_dependency_changes,
                data,
                open_world=True,
            ),
            Tool(
                "compare_releases",
                "Compare two releases of a package",
                "What one release of a package adds over an earlier one, both on disk: a new install hook, new "
                "network or execution capability, new obfuscation or binaries.",
                s(
                    {"path": path, "previous_path": path, "max_findings": mx},
                    ["path", "previous_path"],
                ),
                WorkspaceTools.compare_releases,
                SCAN_OUTPUT,
            ),
            Tool(
                "list_dependencies",
                "List the dependency graph",
                "Every dependency the workspace resolves, direct and transitive, with versions, where each is "
                "declared and its advisory, malware, integrity and licence status.",
                s({"path": path, "direct_only": {"type": "boolean"}, "online": on}),
                WorkspaceTools.list_dependencies,
                data,
                open_world=True,
            ),
            Tool(
                "describe_repository",
                "Describe what the repository is",
                "The ecosystems, projects, manifests and lockfiles, languages, CI systems, containers, "
                "infrastructure code and hooks Cordon finds, with the evidence for each.",
                s({"path": path}),
                WorkspaceTools.describe_repository,
                data,
            ),
            Tool(
                "generate_sbom",
                "Generate a software or AI bill of materials",
                "A CycloneDX or SPDX bill of materials from the resolved dependency graph; with ai, the AI bill "
                "of materials (agent instruction files, skills, MCP servers, models and AI SDKs); with "
                "vulnerabilities, the advisory matches embedded, exploited ones marked.",
                s(
                    {
                        "path": path,
                        "format": {"enum": ["cyclonedx", "spdx"], "default": "cyclonedx"},
                        "ai": {"type": "boolean"},
                        "vulnerabilities": {"type": "boolean"},
                    }
                ),
                WorkspaceTools.generate_sbom,
                data,
            ),
            Tool(
                "compare_with_baseline",
                "Show only new findings",
                "Scan and leave out every finding recorded in a baseline file: what a change introduced.",
                s(
                    {"path": path, "baseline": path, "severity": sev, "max_findings": mx},
                    ["baseline"],
                ),
                WorkspaceTools.compare_with_baseline,
                SCAN_OUTPUT,
            ),
            Tool(
                "list_suppressions",
                "List suppressions",
                "Every suppression in the repository's configuration, who approved it, when it expires and "
                "whether it is in force.",
                s({"path": path}),
                WorkspaceTools.list_suppressions,
                data,
            ),
            Tool(
                "list_local_agents",
                "List this machine's AI agents and MCP servers",
                "The AI agents, MCP servers and editor extensions configured on this computer, with what Cordon "
                "finds about each. Nothing is sent anywhere. Needs the server started with --allow-machine.",
                s({}),
                MachineTools.list_local_agents,
                data,
                needs=("machine",),
            ),
            Tool(
                "scan_machine",
                "Scan this machine's installed packages",
                "The operating system's packages and the language packages installed outside any project, "
                "matched for known vulnerabilities and malicious releases. Needs --allow-machine.",
                s(
                    {
                        "include_home": {
                            "type": "boolean",
                            "description": "Also read this user's own installs (pipx, ~/.local, cargo install).",
                        },
                        "online": on,
                        "severity": sev,
                        "max_findings": mx,
                    }
                ),
                MachineTools.scan_machine,
                SCAN_OUTPUT,
                open_world=True,
                needs=("machine",),
            ),
            Tool(
                "explain_rule",
                "Explain a finding's rule",
                "What a rule detects, why it matters, how to fix what it reports and who documents the threat, "
                "for a rule_id from any finding.",
                s({"rule_id": {"type": "string"}}, ["rule_id"]),
                KnowledgeTools.explain_rule,
                data,
            ),
            Tool(
                "search_rules",
                "Search Cordon's rules",
                "Find rules by words in their id or title, category and minimum severity.",
                s(
                    {
                        "query": {"type": "string"},
                        "category": {"type": "string"},
                        "min_severity": {"enum": SEVERITY_ENUM},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                    }
                ),
                KnowledgeTools.search_rules,
                data,
            ),
            Tool(
                "intel_status",
                "Threat-intel freshness",
                "Where Cordon's threat intelligence comes from, its serial and its age, without fetching anything.",
                s({}),
                KnowledgeTools.intel_status,
                data,
            ),
            Tool(
                "server_status",
                "This server's settings",
                "The directories this server may read, whether online checks and machine-wide reads are allowed, "
                "the scan deadline, the Cordon Cloud sign-in and the tools available.",
                s({}),
                KnowledgeTools.server_status,
                data,
            ),
        ]

    @staticmethod
    def available(settings: Settings) -> list[Tool]:
        """The tools this server offers: one whose server flag is off is not listed at all."""
        enabled = {"online": settings.allow_online, "machine": settings.allow_machine}
        return [t for t in TOOLS if all(enabled[n] for n in t.needs)]


TOOLS: Final[list[Tool]] = Catalogue.build()


@dataclass(slots=True)
class Registry:
    settings: Settings
    tools: dict[str, Tool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.tools = {t.name: t for t in Catalogue.available(self.settings)}
