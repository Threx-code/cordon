"""Command-line interface.

The CLI is a thin shell over the SDK. Every command resolves configuration,
calls into the engine, and renders a result; none of them contain detection
logic. That keeps the SDK and the CLI honest about being the same product, and
it means a bug can only exist in one of them.

Two design commitments show up throughout.

**There is no escape hatch.** No ``--force``, no ``--no-verify``, no flag that
runs the scan and exits zero regardless. The only way to accept a finding is a
suppression, which is reviewable, expiring and recorded in the output. A tool
with a bypass flag is a tool whose bypass flag ends up in the pipeline.

**Failures are typed.** Exit codes distinguish findings from scanner faults from
configuration mistakes, because a pipeline that cannot tell them apart is one
that will eventually be configured to ignore all three.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.cli.progress import TerminalProgress, should_show
from cordon_scanner.core.audit import AuditLog
from cordon_scanner.core.errors import ConfigError, CordonError, ExitCode
from cordon_scanner.core.models import Confidence, Severity
from cordon_scanner.version import PROGRAM as PROGRAM_NAME
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.core.models import Finding, Rule, ScanResult
    from cordon_scanner.core.progress import Progress
    from cordon_scanner.rules.loader import RulePack, RuleTestFailure
    from cordon_scanner.sources.base import FileSource

EPILOG = """\
exit codes:
  0  clean          the scan completed and nothing met the failure policy
  1  findings       the scan completed and something met the failure policy
  2  scanner error  cordon itself failed
  3  config error   invalid configuration, policy, or a forbidden override
  4  incomplete     the scan was degraded and --fail-on-incomplete was set

  A plain `if cordon-scanner scan .` is correct with no flags, and any non-zero code
  fails safe. The distinctions above matter because a pipeline that cannot tell
  "the scanner broke" from "your code is bad" gets configured to ignore both.
"""


class CommandLine:
    """The command line: argument definitions and the commands behind them.

    One class because the two halves have to agree and nothing else checks that
    they do. A flag defined here and read nowhere is dead; a flag read here and
    defined nowhere is a crash on the invocation that uses it. That second one
    shipped: the guard wrote hooks calling `cordon scan --staged` while no such
    flag existed, so every installed hook failed and blocked every commit.

    Exit codes are the contract. 0 clean, 1 findings, 2 a bug in cordon, 3 a
    mistake in the invocation, 4 an incomplete scan. The distinction between 2
    and 3 is deliberate: it tells the user whether to fix their command or file
    a report, and getting it wrong accuses the wrong party.
    """

    PROGRAM = PROGRAM_NAME
    """The installed command, and the name in every usage and error line.

    Not `cordon`. That name is taken on PyPI by an unrelated project which
    declares both a top-level `cordon` package and a `cordon` console script, so
    installing both into one environment has pip write two distributions into
    the same directory and leaves whichever landed last. The import package is
    `cordon_scanner` for the same reason, and both now match the distribution
    name, which was already `cordon-scanner` and was already free.
    """

    MAX_RESULT_BYTES = 256 * 1024 * 1024
    """Ceiling on a document `report convert` will read.

    The command is pointed at a file by a human, but that file may have come
    from a scan of somebody else's repository, so it is not trusted to be
    well-formed or small."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog=cls.PROGRAM,
            description="Language-agnostic software supply-chain security scanner.",
            epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--version", action="version", version=f"{cls.PROGRAM} {__version__}")

        sub = parser.add_subparsers(dest="command", metavar="<command>")

        # -- scan ------------------------------------------------------------
        scan = sub.add_parser(
            "scan",
            help="scan a directory, file or archive",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=EPILOG,
        )
        scan.add_argument("target", nargs="?", default=".", help="path to scan (default: .)")

        selection = scan.add_argument_group("selection")
        selection.add_argument(
            "--include",
            action="append",
            metavar="GLOB",
            help="restrict to matching paths (repeatable)",
        )
        selection.add_argument(
            "--exclude", action="append", metavar="GLOB", help="skip matching paths (repeatable)"
        )

        git_mode = selection.add_mutually_exclusive_group()
        git_mode.add_argument(
            "--staged",
            action="store_true",
            help="scan the content staged in git, not the working tree (for pre-commit hooks)",
        )
        git_mode.add_argument(
            "--tracked",
            action="store_true",
            help="scan only files git tracks, skipping build output and ignored paths",
        )
        git_mode.add_argument(
            "--git-diff",
            metavar="REF",
            help="scan only files that differ from REF",
        )

        rules = scan.add_argument_group("detectors and rules")
        rules.add_argument(
            "--detector",
            action="append",
            metavar="ID",
            help="run only these detectors (repeatable)",
        )
        rules.add_argument(
            "--no-detector",
            action="append",
            metavar="ID",
            help="disable a detector (organisation policy may forbid this)",
        )
        rules.add_argument(
            "--rules", action="append", metavar="PATH", help="additional rule pack (repeatable)"
        )
        rules.add_argument(
            "--advisories",
            metavar="PATH",
            help=(
                "advisory database to use instead of the bundled one, as JSON. "
                "How an air-gapped site stays current without network access."
            ),
        )

        policy = scan.add_argument_group("policy and output")
        policy.add_argument(
            "--severity", metavar="LEVEL", help="report at or above: info|low|medium|high|critical"
        )
        policy.add_argument(
            "--confidence", metavar="LEVEL", help="report at or above: low|medium|high|confirmed"
        )
        policy.add_argument(
            "--fail-on", metavar="LEVEL", help="fail the build at or above this severity"
        )
        policy.add_argument(
            "--fail-on-incomplete", action="store_true", help="treat a degraded scan as a failure"
        )
        policy.add_argument(
            "--baseline",
            metavar="PATH",
            help="treat findings recorded in this file as already-known",
        )
        policy.add_argument("--config", metavar="PATH", help="repository configuration file")
        policy.add_argument("--policy", metavar="PATH", help="organisation policy file")
        policy.add_argument(
            "--format",
            "-f",
            action="append",
            metavar="FMT[:PATH]",
            help=(
                "text|json|sarif|junit|markdown|github. Repeatable. "
                "Append :PATH to write that format to a file, "
                "for example --format sarif:cordon.sarif"
            ),
        )
        policy.add_argument(
            "--output",
            "-o",
            metavar="PATH",
            help="write to a file (only valid with a single --format)",
        )
        policy.add_argument(
            "--evidence",
            metavar="MODE",
            choices=["none", "masked", "hash_only"],
            help=(
                "none|masked|hash_only (default: masked). The stricter of this "
                "and each rule's own policy wins, so `none` only takes effect "
                "for rules that permit it -- no shipped rule does."
            ),
        )

        execution = scan.add_argument_group("execution")
        execution.add_argument(
            "--timeout", type=float, metavar="SECONDS", help="total wall-clock budget"
        )
        execution.add_argument(
            "--no-cache", action="store_true", help="ignore and do not write the incremental cache"
        )
        execution.add_argument(
            "--cache-dir", metavar="PATH", help="where to keep the incremental cache"
        )
        execution.add_argument(
            "--jobs",
            "-j",
            type=int,
            metavar="N",
            help="worker processes (0 or unset means automatic)",
        )
        execution.add_argument(
            "--offline",
            action="store_true",
            default=None,
            help="forbid all network access (the default)",
        )
        execution.add_argument(
            "--allow-network",
            action="store_true",
            help=(
                "permit the one network operation there is: fetching a --policy "
                "URL, which must carry a #sha256= digest. Never used for scanning"
            ),
        )
        execution.add_argument("--quiet", "-q", action="store_true", help="findings only")
        execution.add_argument("--verbose", "-v", action="store_true", help="more detail")
        execution.add_argument("--no-color", action="store_true", help="disable colour")
        execution.add_argument(
            "--audit-log",
            metavar="PATH",
            help=(
                "append one JSON line per scan recording what ran and what was "
                "suppressed; never file content"
            ),
        )
        execution.add_argument(
            "--progress",
            choices=("auto", "always", "never"),
            default="auto",
            help=(
                "show a live progress line on stderr; auto means only when "
                "stderr is an interactive terminal"
            ),
        )

        # -- inventory -------------------------------------------------------
        inventory = sub.add_parser(
            "inventory", help="print what the repository is, and the evidence for it"
        )
        inventory.add_argument("target", nargs="?", default=".")
        inventory.add_argument("--format", "-f", default="text", choices=["text", "json"])

        # -- rules -----------------------------------------------------------
        rules_cmd = sub.add_parser("rules", help="inspect and validate rule packs")
        rules_sub = rules_cmd.add_subparsers(dest="rules_command", metavar="<action>")
        rules_sub.add_parser("list", help="list every loaded rule")
        rules_sub.add_parser("test", help="run every rule's declared samples")
        diff = rules_sub.add_parser(
            "diff", help="compare rule packs and report removal or weakening"
        )
        diff.add_argument("before", help="a pack file, or a directory of packs")
        diff.add_argument(
            "after",
            nargs="?",
            default=None,
            help="the pack to compare; defaults to the packs built into this install",
        )

        show = rules_sub.add_parser("show", help="show one rule in full")
        show.add_argument("rule_id")

        # -- guard -----------------------------------------------------------
        guard_cmd = sub.add_parser("guard", help="scanner self-integrity and git hook installation")
        guard_sub = guard_cmd.add_subparsers(dest="guard_command", metavar="<action>")
        for action, description in (
            ("verify", "check that the guard is intact"),
            ("install", "install fail-closed git hooks"),
            ("update", "regenerate the guard hash manifest"),
        ):
            parser_ = guard_sub.add_parser(action, help=description)
            parser_.add_argument("path", nargs="?", default=".")
            if action == "install":
                parser_.add_argument(
                    "--force",
                    action="store_true",
                    help=(
                        "replace a pre-existing non-cordon hook. Without this such a "
                        "hook is preserved and a backup is written beside it"
                    ),
                )

        # -- config ----------------------------------------------------------
        config_cmd = sub.add_parser("config", help="check configuration")
        config_sub = config_cmd.add_subparsers(dest="config_command", metavar="<action>")
        validate = config_sub.add_parser("validate", help="validate a configuration file")
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

        baseline = sub.add_parser(
            "baseline",
            help="record known findings so a tool can be adopted incrementally",
        ).add_subparsers(dest="baseline_command")
        create = baseline.add_parser("create", help="record the current findings")
        create.add_argument("target", nargs="?", default=".")
        create.add_argument(
            "--output", "-o", default="cordon-baseline.json", help="where to write it"
        )
        create.add_argument("--policy", metavar="PATH", default=None)
        compare = baseline.add_parser("compare", help="report findings outside the baseline")
        compare.add_argument("target", nargs="?", default=".")
        compare.add_argument(
            "baseline_file", nargs="?", default="cordon-baseline.json", metavar="BASELINE"
        )
        compare.add_argument("--policy", metavar="PATH", default=None)

        bundle = sub.add_parser(
            "bundle",
            help="build and verify an offline bundle for an air-gapped install",
        ).add_subparsers(dest="bundle_command")
        bundle_create = bundle.add_parser("create", help="build a bundle from a directory")
        bundle_create.add_argument("source", help="directory holding the files to bundle")
        bundle_create.add_argument("--output", "-o", required=True, metavar="PATH")
        bundle_verify = bundle.add_parser("verify", help="check a bundle against its manifest")
        bundle_verify.add_argument("bundle_file", metavar="BUNDLE")
        bundle_install = bundle.add_parser("install", help="verify a bundle, then extract it")
        bundle_install.add_argument("bundle_file", metavar="BUNDLE")
        bundle_install.add_argument("--into", required=True, metavar="DIR")

        validate.add_argument("path", nargs="?", default=None)
        validate.add_argument("--policy", metavar="PATH")
        explain = config_sub.add_parser("explain", help="show effective settings and their origin")
        explain.add_argument("path", nargs="?", default=None)
        explain.add_argument("--policy", metavar="PATH")

        return parser

    # ---------------------------------------------------------------------------
    # Commands
    # ---------------------------------------------------------------------------

    @classmethod
    def cmd_scan(cls, args: argparse.Namespace) -> int:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import ConfigResolver
        from cordon_scanner.core.models import RedactionMode
        from cordon_scanner.core.policy import PolicyGate
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.report.base import ReportOptions

        target = Path(args.target)
        if not target.exists():
            raise CordonError(
                f"target does not exist: {target}",
                hint="Pass a directory, file or archive path.",
            )

        # A mistyped flag value is the user's mistake, not ours, and the difference
        # is visible in the exit code: 3 says "fix your invocation", 2 says "this is
        # a bug in cordon". Letting a bare ValueError escape reported the second for
        # a `--severity extreme` typo, which is both the wrong code and an
        # accusation against the wrong party.
        overrides: dict[str, Any] = {}
        try:
            if args.severity:
                overrides["severity_threshold"] = Severity.parse(args.severity)
            if args.confidence:
                overrides["confidence_threshold"] = Confidence.parse(args.confidence)
            if args.evidence:
                overrides["evidence"] = RedactionMode(args.evidence)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        if args.exclude:
            overrides["exclude"] = tuple(args.exclude)
        if args.include:
            overrides["include"] = tuple(args.include)
        if args.rules:
            overrides["extra_rule_paths"] = tuple(args.rules)

        config = ConfigResolver.resolve(
            root=target if target.is_dir() else target.parent,
            config_path=args.config,
            policy_path=args.policy,
            allow_network=args.allow_network,
            **overrides,
        )

        if args.no_detector:
            detectors = dict(config.detectors)
            for name in args.no_detector:
                detectors[name] = False
            config = config.with_overrides(detectors=detectors)

        if args.timeout is not None:
            config = config.with_overrides(limits=config.limits.merged(total_timeout=args.timeout))
        if args.no_cache:
            config = config.with_overrides(use_cache=False)
        if args.cache_dir:
            config = config.with_overrides(cache_dir=args.cache_dir)
        if args.jobs is not None:
            config = config.with_overrides(limits=config.limits.merged(max_workers=args.jobs))

        if args.fail_on or args.fail_on_incomplete:
            from dataclasses import replace as _replace

            policy = config.policy
            if args.fail_on:
                try:
                    policy = _replace(policy, fail_on_severity=Severity.parse(args.fail_on))
                except ValueError as exc:
                    raise ConfigError(f"--fail-on: {exc}") from exc
            if args.fail_on_incomplete:
                policy = _replace(policy, fail_on_incomplete=True)
            config = config.with_overrides(policy=policy)

        # Re-check the organisation ceiling against the configuration the scan
        # will actually run with. Every override above edits a Config that
        # `resolve()` already validated, so without this the ceiling applies to
        # an intermediate value and not to the real one -- which is how
        # `--no-detector capability` turned a failing build into a passing one
        # against a policy requiring that detector.
        config.recheck_constraints()

        selected = None
        if args.detector:
            selected = Registry(allow_third_party=config.allow_plugins).detectors(
                only=args.detector
            )

        if args.advisories:
            # Replaces the bundled database rather than adding to it. An
            # organisation that supplies its own is stating what it considers
            # authoritative, and silently merging a shipped list into it would
            # produce findings it did not choose to act on.
            from cordon_scanner.detect.advisory import AdvisoryDetector
            from cordon_scanner.intel.advisories import AdvisoryDatabase

            database = AdvisoryDatabase.from_file(args.advisories)
            base = selected or Registry(allow_third_party=config.allow_plugins).detectors()
            selected = tuple([d for d in base if d.id != "advisory"] + [AdvisoryDetector(database)])

        source = cls._git_source(args, target)

        # Checked before the scan, not after it. An audit log that turns out to
        # be unwritable once the work is done leaves an operator with a scan
        # they cannot attest to; failing here makes it a corrected command line.
        audit = AuditLog.prepare(args.audit_log) if args.audit_log else None

        # stderr, never stdout: a report is written to stdout when --output is
        # not given, and a progress line there corrupts the JSON or SARIF a
        # pipeline is parsing.
        progress: Progress | None = None
        if should_show(sys.stderr, args.progress, quiet=args.quiet):
            progress = TerminalProgress(sys.stderr, color=cls._use_color(args.no_color))

        result = Scanner(config, detectors=selected, source=source, progress=progress).scan(target)

        if args.baseline:
            from dataclasses import replace as _replace

            from cordon_scanner.core.policy import Baseline

            baseline = Baseline.from_file(args.baseline)
            applied = baseline.apply(result.findings)
            silenced = [
                f
                for f in applied
                if f.suppressed is not None and f.suppressed.approved_by == "baseline"
            ]
            findings = list(applied)
            if silenced:
                # Announced in every scan, not merely absent. A fingerprint is a
                # pure function of values the committer controls, so an attacker
                # can compute the one their payload will produce and add it to
                # the baseline in the same commit. That cannot be prevented
                # without signing, and it can be made loud: the suppression is
                # named in the output of every run that honours it, and the
                # finding is one no reporting threshold can hide.
                findings.append(cls._baseline_notice(silenced, Path(args.baseline)))
            result = _replace(result, findings=tuple(findings))

        formats = args.format or ["text"]
        opts = ReportOptions(
            color=cls._use_color(args.no_color),
            verbose=args.verbose,
        )
        cls._emit(result, formats, args.output, opts, quiet=args.quiet)

        verdict = PolicyGate.evaluate(result, config.policy)

        if audit is not None:
            # After the verdict, so the recorded exit code is the one the
            # pipeline actually saw. A write failure here is loud rather than
            # swallowed: a scan nobody can attest to should not look like a
            # scan nobody audited.
            try:
                audit.record(
                    result,
                    exit_code=int(verdict.exit_code),
                    target_kind="archive" if target.is_file() else "directory",
                    policy=args.policy or os.environ.get("CORDON_POLICY") or "",
                )
            except OSError as exc:
                print(f"{cls.PROGRAM}: audit log could not be written: {exc}", file=sys.stderr)
                return int(ExitCode.SCANNER_ERROR)

        if not args.quiet and verdict.exit_code is not ExitCode.CLEAN:
            print(f"\nFAILED: {verdict.reason}", file=sys.stderr)
        return int(verdict.exit_code)

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

        from cordon_scanner.core.models import RedactionMode
        from cordon_scanner.core.redact import Redactor

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

    @staticmethod
    def _use_color(disabled: bool) -> bool:
        """Whether to emit colour, by the conventions people already have.

        `--no-color` wins, then `NO_COLOR` (no-color.org: set to anything at
        all means no colour), then `FORCE_COLOR` for the case a terminal test
        cannot answer -- a CI log viewer that renders escapes, or a capture
        being piped into something that wants them. Without `FORCE_COLOR`
        there is no way to get coloured output that is not a terminal, which
        is what rendering this project's own README image needs.
        """
        if disabled or os.environ.get("NO_COLOR") is not None:
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        return sys.stdout.isatty()

    @staticmethod
    def _baseline_notice(silenced: Sequence[Finding], path: Path) -> Finding:
        """One always-reported finding naming what the baseline is hiding."""
        from cordon_scanner.core.models import (
            Category,
            Confidence,
            Evidence,
            EvidenceKind,
            Explanation,
            Finding,
            Location,
            RedactionMode,
            RiskScore,
            Severity,
        )

        rules = sorted({f.rule_id for f in silenced})
        listed = ", ".join(rules[:8]) + (" and others" if len(rules) > 8 else "")
        return Finding(
            rule_id="POLICY.BASELINE.APPLIED",
            category=Category.POLICY,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=(
                f"{len(silenced)} finding(s) were suppressed by {path.name}: {listed}. "
                f"A baseline records debt somebody chose to carry, and its entries are "
                f"computable by whoever can commit to this repository, so what it "
                f"hides is stated here on every run."
            ),
            location=Location(path=path.name),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(",".join(rules).encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=(
                "Review the baseline. Every entry names the rule and the path it "
                "silences, so a new one is legible in a diff."
            ),
            explanation=Explanation(
                summary="Reported so that a baseline never hides its own contents.",
                matched_rule="POLICY.BASELINE.APPLIED",
            ),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector="engine",
            always_report=True,
        )

    @classmethod
    def _git_source(cls, args: argparse.Namespace, target: Path) -> FileSource | None:
        """Build the file source for a git mode, or None for the working tree.

        Every failure here is a hard error rather than a fallback. Falling back to
        the working tree when `--staged` cannot be honoured is the worst available
        outcome: the hook reports success having scanned the wrong bytes, which is
        precisely the bypass staged mode exists to close.
        """
        if not (args.staged or args.tracked or args.git_diff):
            return None

        from cordon_scanner.core.errors import SourceError
        from cordon_scanner.sources.git import GitIndexSource, GitPathSource, GitRepository

        flag = "--staged" if args.staged else "--tracked" if args.tracked else "--git-diff"

        info = GitRepository.discover(target)
        if info is None:
            raise ConfigError(
                f"{flag} needs a git repository, and {target} is not inside one",
                hint="Run inside a repository, or scan without the flag.",
            )

        repository = GitRepository(info.root)

        if args.staged:
            paths = repository.staged_files()
            if not paths:
                # Not an error. A pre-commit hook fires on every commit, including
                # ones that stage nothing this scanner can read, and failing there
                # would teach people to pass --no-verify.
                print("cordon: nothing is staged; no files were scanned", file=sys.stderr)
            return GitIndexSource(repository, paths)

        if args.tracked:
            return GitPathSource(repository.tracked_files(), mode="tracked")

        try:
            changed = repository.changed_files(args.git_diff)
        except SourceError as exc:
            # A ref that does not exist is the user's mistake, not a bug in
            # cordon, and the exit code has to say which. SourceError carries 2,
            # meaning "report this to the maintainers"; a typed ref belongs in 3,
            # meaning "fix your invocation".
            raise ConfigError(
                f"--git-diff: {exc.message}",
                hint=f"Check that {args.git_diff!r} names a commit this repository has.",
            ) from exc
        return GitPathSource(changed, mode=f"diff vs {args.git_diff}", empty_is_normal=True)

    @classmethod
    def _emit(
        cls,
        result: ScanResult,
        formats: Sequence[str],
        single_output: str | None,
        opts: object,
        *,
        quiet: bool,
    ) -> None:
        """Render each requested format to its destination.

        A destination is attached to its format with a colon:
        ``--format sarif:cordon.sarif``. Positional pairing between two repeatable
        flags was tried first and is genuinely error-prone: with
        ``-f text -f sarif -o cordon.sarif`` the natural reading is that SARIF goes
        to the file, while positional pairing sends the *text* report there. That
        produced an unparseable SARIF file, and it did so silently, because writing
        a report to a path always succeeds.

        ``--output`` remains as a shorthand for the single-format case, and is
        refused when it would be ambiguous.
        """
        from cordon_scanner.core.registry import Registry

        registry = Registry()
        targets: list[tuple[str, str | None]] = []

        for entry in formats:
            name, sep, path = entry.partition(":")
            targets.append((name, path if sep and path else None))

        if single_output is not None:
            named = [name for name, path in targets if path is None]
            if len(named) != 1:
                raise ConfigError(
                    "--output is ambiguous with more than one --format",
                    hint=(
                        "Attach the destination to its format instead, for example:\n"
                        "  --format text --format sarif:cordon.sarif"
                    ),
                )
            targets = [(name, single_output if path is None else path) for name, path in targets]

        for name, destination in targets:
            reporter = registry.reporter(name)

            if destination:
                out_path = Path(destination)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with out_path.open("wb") as handle:
                    for chunk in reporter.render(result, opts):
                        handle.write(chunk)
                if not quiet:
                    print(f"wrote {name} report to {path}", file=sys.stderr)
            else:
                buffer = sys.stdout.buffer
                for chunk in reporter.render(result, opts):
                    buffer.write(chunk)
                buffer.flush()

    @classmethod
    def cmd_inventory(cls, args: argparse.Namespace) -> int:
        import json

        from cordon_scanner import Scanner

        inventory = Scanner().inventory(args.target)

        if args.format == "json":
            print(json.dumps(inventory.to_dict(), indent=2, sort_keys=True))
            return int(ExitCode.CLEAN)

        print(f"{inventory.root}")
        print(f"{inventory.file_count} files, {inventory.total_bytes:,} bytes\n")

        if inventory.languages:
            print("languages")
            for stat in inventory.languages:
                evidence = ", ".join(stat.evidence[:4])
                print(
                    f"  {stat.language:<14}{stat.share * 100:5.1f}%  {stat.files:>5} files   {evidence}"
                )
            print()

        if inventory.hooks:
            # Listed prominently because execution context is the largest multiplier
            # in the risk model: these are the paths where ordinary capabilities
            # become mechanisms.
            print("install and build hooks (code that runs before any other control)")
            for hook in inventory.hooks:
                print(f"  {hook.kind:<10}{hook.path}")
            print()

        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_rules(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.core.config import ConfigResolver
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.rules.loader import RuleLoader, RuleSet, RuleTester

        packs = RuleLoader.load_builtin()
        rule_set = RuleSet(packs)
        declared = RuleCatalogue.from_detectors(Registry().detectors())
        disabled_ids = ConfigResolver.resolve(root=".").disabled_rules
        action = args.rules_command or "list"

        if action == "list":
            total = len(rule_set) + len(declared)
            print(f"{total} rules: {len(rule_set)} from {len(packs)} pack(s), ")
            print(f"{len(declared)} declared by detectors\n")
            for pack in packs:
                print(f"{pack.id} {pack.version}  ({pack.license})")
                for compiled in pack:
                    rule = compiled.rule
                    marker = " " if rule.enabled else "-"
                    print(
                        f" {marker} {rule.id:<34} {rule.severity!s:<9}"
                        f"{rule.confidence!s:<10}{rule.title}"
                    )
                print()

            # Listed separately, and labelled, because these do not carry the
            # loader's guarantees: no mandatory samples, no provenance
            # requirement, no independent version. Hiding the difference would
            # be worse than the omission this fixes.
            if declared:
                print("declared by detectors (not pack rules)")
                for declared_rule in declared:
                    marker = "-" if declared_rule.id in disabled_ids else " "
                    print(
                        f" {marker} {declared_rule.id:<34} {declared_rule.severity!s:<9}"
                        f"{declared_rule.confidence!s:<10}{declared_rule.title}"
                    )
                print()
            return int(ExitCode.CLEAN)

        if action == "test":
            failures: list[RuleTestFailure] = []
            for pack in packs:
                failures.extend(RuleTester.run(pack))
            if failures:
                print(f"{len(failures)} rule sample(s) failed\n", file=sys.stderr)
                for failure in failures:
                    print(f"  {failure.rule_id} [{failure.kind}] {failure.detail}", file=sys.stderr)
                    print(f"    sample: {failure.sample}", file=sys.stderr)
                return int(ExitCode.FINDINGS)
            testable = sum(1 for r in rule_set if r.rule.tests.positive or r.rule.tests.negative)
            print(f"all samples passed ({testable} rules with inline samples)")
            return int(ExitCode.CLEAN)

        if action == "diff":
            return cls._rules_diff(args, packs)

        if action == "show":
            found = rule_set.get(args.rule_id)
            if found is None:
                match = next((r for r in declared if r.id == args.rule_id), None)
                if match is not None:
                    print(f"{match.id}  (declared by the {match.detector!r} detector)")
                    print(f"{match.title}\n")
                    print(f"category    {match.category}")
                    print(f"severity    {match.severity}")
                    print(f"confidence  {match.confidence}")
                    if match.message:
                        print(f"\n{match.message}")
                    if match.remediation:
                        print(f"\nremediation\n  {match.remediation}")
                    print(
                        "\nThis rule is declared in Python rather than in a YAML pack, "
                        "so it does not\ncarry the pack guarantees: no mandatory test "
                        "samples, no provenance requirement,\nno independent version. "
                        "It can be disabled with `rules.disabled` in configuration."
                    )
                    return int(ExitCode.CLEAN)
                raise CordonError(f"no such rule: {args.rule_id}")
            rule = found.rule
            print(f"{rule.id}  {rule.version}  ({rule.rulepack})")
            print(f"{rule.title}\n")
            print(f"category    {rule.category}")
            print(f"severity    {rule.severity}")
            print(f"confidence  {rule.confidence}")
            print(f"match       {rule.match_kind}")
            if rule.languages:
                print(f"languages   {', '.join(rule.languages)}")
            if rule.capability:
                print(f"capability  {rule.capability}")
            if rule.provenance:
                protection = " (protected)" if rule.provenance.protected else ""
                print(f"provenance  {rule.provenance.kind}{protection}")
            print(f"\n{rule.message}\n")
            if rule.remediation:
                print(f"remediation\n  {rule.remediation}\n")
            return int(ExitCode.CLEAN)

        raise ConfigError(f"unknown rules action: {action}")

    @classmethod
    def cmd_guard(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.core.guard import Guard

        action = args.guard_command or "verify"
        root = Path(getattr(args, "path", "."))

        if action == "install":
            installed = Guard.install_hooks(root, force=getattr(args, "force", False))
            for hook in installed:
                print(f"installed .git/hooks/{hook}")
            print(
                f"\nHooks live in .git/hooks, which git does not track, so no commit, "
                f"branch\nswitch, merge or `git clean` removes them. Each fails closed: "
                f"if {cls.PROGRAM}\ncannot run, the operation is refused rather than allowed."
            )
            return int(ExitCode.CLEAN)

        if action == "update":
            manifest = Guard.write_manifest(root)
            print(f"wrote {manifest}")
            print(
                "\nCommit this file. Its only purpose is to be reviewed: an attacker who\n"
                "edits a guard can regenerate it in the same commit, and no self-hosted\n"
                "check can prevent that. What it guarantees is that the change cannot be\n"
                "silent."
            )
            return int(ExitCode.CLEAN)

        if action == "verify":
            report = Guard.verify(root)
            if report.ok:
                print("guard intact")
                return int(ExitCode.CLEAN)
            for problem in report.problems:
                print(f"{problem.status}: {problem.detail}", file=sys.stderr)
                print(f"  fix: {problem.remediation}", file=sys.stderr)
            return int(ExitCode.FINDINGS)

        raise ConfigError(f"unknown guard action: {action}")

    @classmethod
    def _rules_diff(cls, args: argparse.Namespace, packs: Sequence[RulePack]) -> int:
        """Compare two rule sets and report removal or weakening.

        `RuleProvenance.protected` exists solely so that this command "fails
        when one is removed or weakened without an explicit review trailer".
        The command had no implementation, so `provenance: incident` guaranteed
        nothing at all.

        A rule derived from a real incident is the easiest kind to lose: it
        often looks arbitrary out of context -- an opaque string constant with
        no obvious meaning is exactly what a well-intentioned cleanup deletes,
        and a refactor that reorganises a rule set can drop one while the diff
        appears to show nothing but an improvement.

        Weakening means: disabled, severity lowered, or confidence lowered.
        Those are the changes that reduce what a rule does while leaving it
        present, and they do not read as removal in a text diff.
        """
        from cordon_scanner.rules.loader import RuleLoader

        loader = RuleLoader()

        def load(path_text: str) -> tuple[RulePack, ...]:
            path = Path(path_text)
            if path.is_dir():
                return loader.load_dir(path)
            if path.is_file():
                return (loader.load_file(path),)
            raise CordonError(f"no such pack: {path}")

        before = {r.rule.id: r.rule for pack in load(args.before) for r in pack.rules}
        after_packs = load(args.after) if args.after else packs
        after = {r.rule.id: r.rule for pack in after_packs for r in pack.rules}

        removed = sorted(set(before) - set(after))
        added = sorted(set(after) - set(before))
        weakened: list[tuple[str, str]] = []

        for rule_id in sorted(set(before) & set(after)):
            was, now = before[rule_id], after[rule_id]
            if was.enabled and not now.enabled:
                weakened.append((rule_id, "disabled"))
            if now.severity < was.severity:
                weakened.append((rule_id, f"severity {was.severity} -> {now.severity}"))
            if now.confidence < was.confidence:
                weakened.append((rule_id, f"confidence {was.confidence} -> {now.confidence}"))

        for rule_id in added:
            print(f"  added     {rule_id}")
        for rule_id in removed:
            marker = "PROTECTED " if cls._protected(before[rule_id]) else ""
            print(f"  removed   {marker}{rule_id}")
        for rule_id, how in weakened:
            marker = "PROTECTED " if cls._protected(after[rule_id]) else ""
            print(f"  weakened  {marker}{rule_id}: {how}")

        if not (added or removed or weakened):
            print("no rule changes")
            return int(ExitCode.CLEAN)

        protected = [r for r in removed if cls._protected(before[r])]
        protected += [r for r, _ in weakened if cls._protected(after[r])]
        if protected:
            print(
                f"\n{len(protected)} protected rule(s) removed or weakened: "
                f"{', '.join(sorted(set(protected)))}",
                file=sys.stderr,
            )
            print(
                "  A rule marked `provenance: incident` matched something that "
                "actually arrived.\n  Removing or weakening one needs an explicit "
                "review, not a refactor that happens to drop it.",
                file=sys.stderr,
            )
            return int(ExitCode.FINDINGS)

        return int(ExitCode.CLEAN)

    @staticmethod
    def _protected(rule: Rule) -> bool:
        provenance = getattr(rule, "provenance", None)
        return bool(provenance and getattr(provenance, "protected", False))

    @classmethod
    def cmd_report(cls, args: argparse.Namespace) -> int:
        """Re-render a saved JSON result in another format.

        Exists so a single scan can produce every format anybody needs without
        being re-run. A pipeline that wants SARIF for code scanning, markdown
        for a pull-request comment and JUnit for its test reporter otherwise
        scans three times, and three scans of a moving working tree are not
        guaranteed to agree.

        Documented in the interface specification and never implemented.
        """
        import json as _json

        from cordon_scanner.core.cache import ScanCache
        from cordon_scanner.core.models import Repository, ScanResult, ScanStats
        from cordon_scanner.core.registry import Registry
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
                hint="Produce one with `cordon scan . --format json:result.json`.",
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
                hint="Produce one with `cordon scan . --format json:result.json`.",
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

    @classmethod
    def cmd_bundle(cls, args: argparse.Namespace) -> int:
        """Build, check, or install an offline bundle.

        `verify` fails closed. An air-gapped operator who is told a bundle is
        merely questionable will install it, because they carried it across a
        room to do exactly that, and the alternative is going back for another
        one. So there is no questionable: it verifies or it is refused.
        """
        from cordon_scanner.core.bundle import Bundle

        action = getattr(args, "bundle_command", None)
        if action is None:
            print(f"{cls.PROGRAM}: bundle needs create, verify or install", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        if action == "create":
            source = Path(args.source)
            if not source.is_dir():
                raise ConfigError(f"{source} is not a directory")
            files = [
                (str(p.relative_to(source)).replace(os.sep, "/"), p)
                for p in sorted(source.rglob("*"))
                if p.is_file() and not p.is_symlink()
            ]
            written = Bundle.create(Path(args.output), files=files)
            print(f"wrote {written} ({len(files)} file(s))")
            print(
                "This proves internal consistency. Sign it before it crosses the air gap, "
                "or the far end can check only that it is the bundle its own manifest describes."
            )
            return int(ExitCode.CLEAN)

        report = Bundle.verify(Path(args.bundle_file))
        if action == "verify":
            if report.ok:
                print(report.summary())
                return int(ExitCode.CLEAN)
            print(f"{cls.PROGRAM}: bundle REFUSED", file=sys.stderr)
            for problem in report.problems:
                print(f"  {problem}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        # install
        if not report.ok:
            print(f"{cls.PROGRAM}: bundle REFUSED; nothing was written", file=sys.stderr)
            for problem in report.problems:
                print(f"  {problem}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        into = Path(args.into)
        Bundle.install(Path(args.bundle_file), into)
        print(f"installed {report.checked} file(s) into {into}")
        if not report.signed:
            print(
                "No signature was present, so who produced this bundle is unverified.",
                file=sys.stderr,
            )
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_baseline(cls, args: argparse.Namespace) -> int:
        """Create or compare a baseline.

        Baselines exist so the tool can be adopted into an existing codebase
        without demanding the whole backlog be fixed on day one. The
        alternative -- turn it on, get four hundred findings, turn it off -- is
        the most common way a security tool fails to be adopted at all.

        `compare` never writes. Refreshing a baseline has to be a separate,
        deliberate act, or the command run in CI to detect new findings would
        also be the command that absorbs them.
        """
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import ConfigResolver
        from cordon_scanner.core.policy import Baseline

        target = Path(args.target)
        if not target.exists():
            raise CordonError(f"target does not exist: {target}")

        config = ConfigResolver.resolve(
            root=target if target.is_dir() else target.parent,
            policy_path=args.policy,
        )
        result = Scanner(config).scan(target)
        action = args.baseline_command or "create"

        if action == "create":
            # Malicious findings are recorded like any other, and refused at
            # apply time. Filtering them out here would make the file look
            # complete while quietly excluding the findings that matter.
            destination = Path(args.output)
            if destination == Path("cordon-baseline.json"):
                root = target if target.is_dir() else target.parent
                destination = root / "cordon-baseline.json"
            written = Baseline.from_result(result).write(destination)
            count = len(result.findings)
            print(f"wrote {written} with {count} finding(s)")
            print(
                "  Review it before committing. Every entry is something this "
                "repository is choosing not to fix yet."
            )
            return int(ExitCode.CLEAN)

        if action == "compare":
            # Resolved against the target, not the working directory. A baseline
            # belongs to the repository it describes, and defaulting to the
            # caller's cwd means `cordon baseline compare ../other-repo` silently
            # compares one repository against another's debt.
            path = Path(args.baseline_file)
            if path == Path("cordon-baseline.json"):
                root = target if target.is_dir() else target.parent
                path = root / "cordon-baseline.json"
            baseline = Baseline.from_file(path)
            added, cleared = baseline.compare(result)

            if cleared:
                print(f"{len(cleared)} baselined finding(s) no longer occur:")
                for fingerprint in cleared[:20]:
                    print(f"  {fingerprint}")
                print("  Regenerate the baseline so it shrinks with the backlog.")

            if not added:
                print("no findings outside the baseline")
                return int(ExitCode.CLEAN)

            print(f"\n{len(added)} finding(s) not in the baseline:")
            for finding in sorted(added, key=lambda f: f.sort_key()):
                print(f"  {finding.severity} {finding.rule_id} at {finding.location}")
            return int(ExitCode.FINDINGS)

        raise ConfigError(f"unknown baseline action: {action}")

    @classmethod
    def cmd_config(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.core.config import Config, ConfigResolver

        action = args.config_command or "validate"

        if action == "validate":
            config = Config.from_file(args.path) if args.path else Config.discover(".")
            if args.policy:
                from cordon_scanner.core.config import ConfigResolver

                org, constraints = ConfigResolver.load_org_policy(args.policy)
                config.clamped_by(org, constraints)
            print("configuration is valid")
            return int(ExitCode.CLEAN)

        if action == "explain":
            config = ConfigResolver.resolve(
                root=".", config_path=args.path, policy_path=args.policy
            )
            print("effective configuration\n")
            print(f"  severity_threshold    {config.severity_threshold}")
            print(f"  confidence_threshold  {config.confidence_threshold}")
            print(f"  evidence              {config.evidence}")
            print(f"  offline               {config.offline}")
            print(f"  fail_on               {config.policy.fail_on_severity}")
            print(
                f"  fail_on_categories    "
                f"{', '.join(sorted(str(c) for c in config.policy.fail_on_categories))}"
            )
            print(
                f"  suppressions          {len(config.suppressions)} "
                f"({len(config.active_suppressions())} active)"
            )
            print(f"  config hash           {config.fingerprint()}")
            if config.provenance:
                print("\norigins")
                for entry in config.explain():
                    print(f"  {entry}")
            return int(ExitCode.CLEAN)

        raise ConfigError(f"unknown config action: {action}")

    @classmethod
    def run(cls, argv: Sequence[str] | None = None) -> int:
        parser = cls.build_parser()
        args = parser.parse_args(argv)

        if not args.command:
            parser.print_help()
            return int(ExitCode.CLEAN)

        commands = {
            "scan": cls.cmd_scan,
            "inventory": cls.cmd_inventory,
            "rules": cls.cmd_rules,
            "config": cls.cmd_config,
            "guard": cls.cmd_guard,
            "baseline": cls.cmd_baseline,
            "bundle": cls.cmd_bundle,
            "report": cls.cmd_report,
        }
        handler = commands.get(args.command)
        if handler is None:
            parser.print_help(sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        try:
            return handler(args)
        except CordonError as exc:
            # Typed errors carry their own exit code, so the caller learns whether
            # this was their mistake or ours.
            print(f"{cls.PROGRAM}: {exc.message}", file=sys.stderr)
            if exc.hint:
                print(f"  {exc.hint}", file=sys.stderr)
            return int(exc.exit_code)
        except KeyboardInterrupt:
            print(f"\n{cls.PROGRAM}: interrupted", file=sys.stderr)
            return int(ExitCode.SCANNER_ERROR)
        except BrokenPipeError:
            # `cordon scan . | head` is a normal thing to do.
            return int(ExitCode.CLEAN)
        except Exception as exc:
            # An untyped exception reaching here is a bug in Cordon, and is reported
            # as one rather than dressed up as a scan result. Reporting it as
            # "findings" would be worse than useless: it would look like the code
            # was bad when the tool was.
            print(f"{cls.PROGRAM}: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
            print(
                "  This is a bug in cordon. Please report it with the command you ran.",
                file=sys.stderr,
            )
            return int(ExitCode.SCANNER_ERROR)


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point.

    A module-level name because that is what a `console_scripts` entry point and
    `python -m cordon` need. It delegates immediately; no logic lives here.
    """
    return CommandLine.run(argv)


__all__ = ["CommandLine", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
