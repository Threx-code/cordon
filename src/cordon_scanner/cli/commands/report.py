"""`report convert`: re-render a saved JSON result in another format, without scanning again."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding


class ReportCommand:
    MAX_RESULT_BYTES = 256 * 1024 * 1024
    """Ceiling on a document `report convert` will read.

    The command is pointed at a file by a human, but that file may have come
    from a scan of somebody else's repository, so it is not trusted to be
    well-formed or small."""

    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        report = sub.add_parser(
            "report", help="re-render a saved JSON result in another format"
        ).add_subparsers(dest="report_command", metavar="<action>")
        convert = report.add_parser("convert", help="render a saved result")
        convert.add_argument("path", help="a result written with --format json")
        convert.add_argument(
            "--format",
            "-f",
            default="text",
            help="text|json|sarif|junit|markdown|github",
        )
        convert.add_argument("--output", "-o", default=None, help="write to a file")

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        """Re-render a saved JSON result in another format.

        Exists so a single scan can produce every format anybody needs without
        being re-run. A pipeline that wants SARIF for code scanning, markdown
        for a pull-request comment and JUnit for its test reporter otherwise
        scans three times, and three scans of a moving working tree are not
        guaranteed to agree.

        Documented in the interface specification and never implemented.
        """
        import json as _json

        from cordon_scanner.engine.cache import ScanCache
        from cordon_scanner.engine.registry import Registry
        from cordon_scanner.foundation.results import Repository, ScanResult, ScanStats
        from cordon_scanner.report.base import ReportOptions

        if (args.report_command or "convert") != "convert":
            raise ConfigError(f"unknown report action: {args.report_command}")

        source = Path(args.path)
        if not source.is_file():
            # ConfigError, not CordonError. The user named a path that is not
            # there; that is exit 3, "fix your invocation", not exit 2, "this is
            # a bug in cordon".
            raise ConfigError(
                f"result file not found: {source}",
                hint=f"Produce one with `{PROGRAM} scan . --format json:result.json`.",
            )

        size = source.stat().st_size
        if size > cls.MAX_RESULT_BYTES:
            raise ConfigError(
                f"{source} is {size} bytes, over the {cls.MAX_RESULT_BYTES} byte limit",
                hint="A result document this large is not one this command produced.",
            )

        try:
            payload = _json.loads(source.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"{source}: not a readable JSON result: {exc}") from exc
        except RecursionError as exc:
            # A deeply nested document exhausts the decoder's stack. Reported as
            # the malformed input it is: it reached the top-level handler as
            # "internal error", exit 2, which blames the tool for a file
            # somebody else wrote.
            raise ConfigError(
                f"{source}: JSON is nested too deeply to decode",
                hint="A result document this deeply nested is not one this command produced.",
            ) from exc

        try:
            findings = tuple(
                cls._reredact(ScanCache.finding_from_dict(f)) for f in payload["findings"]
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ConfigError(
                f"{source}: not a cordon result document",
                hint=f"Produce one with `{PROGRAM} scan . --format json:result.json`.",
            ) from exc

        repository = payload.get("repository") or {}
        result = ScanResult(
            findings=findings,
            repository=Repository(root=str(repository.get("root", "."))),
            stats=ScanStats(files_scanned=int(payload.get("stats", {}).get("files_scanned", 0))),
            complete=bool(payload.get("complete", True)),
            schema_version=int(payload.get("schema_version", 1)),
            engine_version=str(payload.get("engine_version", "")),
            rulepack_version=str(payload.get("rulepack_version", "")),
            rulepack_hash=str(payload.get("rulepack_hash", "")),
            config_hash=str(payload.get("config_hash", "")),
        )

        reporter = Registry().reporter(args.format)
        opts = ReportOptions(color=False, verbose=False)
        chunks = reporter.render(result, opts)
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("wb") as handle:
                for chunk in chunks:
                    handle.write(chunk)
            print(f"wrote {destination}")
        else:
            for chunk in chunks:
                sys.stdout.buffer.write(chunk)
        return int(ExitCode.CLEAN)

    @staticmethod
    def _reredact(finding: Finding) -> Finding:
        """Re-apply masking to a snippet that came from a document, not a scan.

        `report convert` reconstructs findings from JSON and hands them to a
        reporter, and the snippet was taken verbatim. The common CI shape is an
        unprivileged job that scans and uploads `cordon-result.json` and a
        privileged job that renders it into a pull-request comment -- so
        whoever controls the first job controls exactly the text that reaches
        the second, which is the input the escaping fix is defending against and
        a way to smuggle unredacted key material into a wider audience.

        Masked rather than trusted: the document records no redaction mode that
        can be believed, and re-masking already-masked text is a no-op.
        """
        from dataclasses import replace as _replace

        from cordon_scanner.foundation.models import RedactionMode
        from cordon_scanner.foundation.text.redact import Redactor

        snippet = finding.evidence.snippet
        if not snippet:
            return finding
        return _replace(
            finding,
            evidence=_replace(
                finding.evidence,
                snippet=Redactor.redact(snippet, RedactionMode.MASKED),
                redaction=RedactionMode.MASKED,
            ),
        )


__all__ = ["ReportCommand"]
