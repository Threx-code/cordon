"""What every MCP tool shares: its definition (Tool), the server's settings, the outcome it returns
and the error it raises, argument checking (Args), and running the scanner and shaping what it
returns (Scans)."""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar, Final

from cordon_scanner.mcp.results import Results, ScanSummary
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
    """Worker processes per scan; 0 lets the scanner choose."""
    model: str | None = None
    """`--model`: cordon-cloud or a model server's address, passed to every scan."""


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
