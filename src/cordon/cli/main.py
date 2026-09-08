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
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from cordon.core.errors import ConfigError, CordonError, ExitCode
from cordon.core.models import Confidence, Severity
from cordon.version import __version__

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon.core.models import ScanResult

PROGRAM = "cordon"

EPILOG = """\
exit codes:
  0  clean          the scan completed and nothing met the failure policy
  1  findings       the scan completed and something met the failure policy
  2  scanner error  cordon itself failed
  3  config error   invalid configuration, policy, or a forbidden override
  4  incomplete     the scan was degraded and --fail-on-incomplete was set

  A plain `if cordon scan .` is correct with no flags, and any non-zero code
  fails safe. The distinctions above matter because a pipeline that cannot tell
  "the scanner broke" from "your code is bad" gets configured to ignore both.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Language-agnostic software supply-chain security scanner.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")

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
        "--include", action="append", metavar="GLOB", help="restrict to matching paths (repeatable)"
    )
    selection.add_argument(
        "--exclude", action="append", metavar="GLOB", help="skip matching paths (repeatable)"
    )

    rules = scan.add_argument_group("detectors and rules")
    rules.add_argument(
        "--detector", action="append", metavar="ID", help="run only these detectors (repeatable)"
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
        "--output", "-o", metavar="PATH", help="write to a file (only valid with a single --format)"
    )
    policy.add_argument(
        "--evidence",
        metavar="MODE",
        choices=["none", "masked", "hash_only"],
        help="none|masked|hash_only (default: masked)",
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
        "--jobs", "-j", type=int, metavar="N", help="worker processes (0 or unset means automatic)"
    )
    execution.add_argument(
        "--offline",
        action="store_true",
        default=None,
        help="forbid all network access (the default)",
    )
    execution.add_argument("--quiet", "-q", action="store_true", help="findings only")
    execution.add_argument("--verbose", "-v", action="store_true", help="more detail")
    execution.add_argument("--no-color", action="store_true", help="disable colour")

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
    show = rules_sub.add_parser("show", help="show one rule in full")
    show.add_argument("rule_id")

    # -- config ----------------------------------------------------------
    config_cmd = sub.add_parser("config", help="check configuration")
    config_sub = config_cmd.add_subparsers(dest="config_command", metavar="<action>")
    validate = config_sub.add_parser("validate", help="validate a configuration file")
    validate.add_argument("path", nargs="?", default=None)
    validate.add_argument("--policy", metavar="PATH")
    explain = config_sub.add_parser("explain", help="show effective settings and their origin")
    explain.add_argument("path", nargs="?", default=None)
    explain.add_argument("--policy", metavar="PATH")

    return parser


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    from cordon import Scanner
    from cordon.core.config import resolve
    from cordon.core.models import RedactionMode
    from cordon.core.policy import evaluate
    from cordon.core.registry import Registry
    from cordon.report.base import ReportOptions

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
    overrides: dict[str, object] = {}
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

    config = resolve(
        root=target if target.is_dir() else target.parent,
        config_path=args.config,
        policy_path=args.policy,
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

    selected = None
    if args.detector:
        selected = Registry(allow_third_party=config.allow_plugins).detectors(only=args.detector)

    result = Scanner(config, detectors=selected).scan(target)

    formats = args.format or ["text"]
    opts = ReportOptions(
        color=not args.no_color and sys.stdout.isatty(),
        verbose=args.verbose,
    )
    _emit(result, formats, args.output, opts, quiet=args.quiet)

    verdict = evaluate(result, config.policy)
    if not args.quiet and verdict.exit_code is not ExitCode.CLEAN:
        print(f"\nFAILED: {verdict.reason}", file=sys.stderr)
    return int(verdict.exit_code)


def _emit(
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
    from cordon.core.registry import Registry

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
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("wb") as handle:
                for chunk in reporter.render(result, opts):
                    handle.write(chunk)
            if not quiet:
                print(f"wrote {name} report to {path}", file=sys.stderr)
        else:
            buffer = sys.stdout.buffer
            for chunk in reporter.render(result, opts):
                buffer.write(chunk)
            buffer.flush()


def cmd_inventory(args: argparse.Namespace) -> int:
    import json

    from cordon import Scanner

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


def cmd_rules(args: argparse.Namespace) -> int:
    from cordon.rules.loader import RuleSet, load_builtin_rules, run_rule_tests

    packs = load_builtin_rules()
    rule_set = RuleSet(packs)
    action = args.rules_command or "list"

    if action == "list":
        print(f"{len(rule_set)} rules from {len(packs)} pack(s)\n")
        for pack in packs:
            print(f"{pack.id} {pack.version}  ({pack.license})")
            for compiled in pack:
                rule = compiled.rule
                marker = " " if rule.enabled else "-"
                print(
                    f" {marker} {rule.id:<28} {rule.severity!s:<9}"
                    f"{rule.confidence!s:<10}{rule.title}"
                )
            print()
        return int(ExitCode.CLEAN)

    if action == "test":
        failures = []
        for pack in packs:
            failures.extend(run_rule_tests(pack))
        if failures:
            print(f"{len(failures)} rule sample(s) failed\n", file=sys.stderr)
            for failure in failures:
                print(f"  {failure.rule_id} [{failure.kind}] {failure.detail}", file=sys.stderr)
                print(f"    sample: {failure.sample}", file=sys.stderr)
            return int(ExitCode.FINDINGS)
        testable = sum(1 for r in rule_set if r.rule.tests.positive or r.rule.tests.negative)
        print(f"all samples passed ({testable} rules with inline samples)")
        return int(ExitCode.CLEAN)

    if action == "show":
        compiled = rule_set.get(args.rule_id)
        if compiled is None:
            raise CordonError(f"no such rule: {args.rule_id}")
        rule = compiled.rule
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


def cmd_config(args: argparse.Namespace) -> int:
    from cordon.core.config import Config, resolve

    action = args.config_command or "validate"

    if action == "validate":
        config = Config.from_file(args.path) if args.path else Config.discover(".")
        if args.policy:
            from cordon.core.config import load_org_policy

            org, constraints = load_org_policy(args.policy)
            config.clamped_by(org, constraints)
        print("configuration is valid")
        return int(ExitCode.CLEAN)

    if action == "explain":
        config = resolve(root=".", config_path=args.path, policy_path=args.policy)
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

COMMANDS = {
    "scan": cmd_scan,
    "inventory": cmd_inventory,
    "rules": cmd_rules,
    "config": cmd_config,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return int(ExitCode.CLEAN)

    handler = COMMANDS.get(args.command)
    if handler is None:
        parser.print_help(sys.stderr)
        return int(ExitCode.CONFIG_ERROR)

    try:
        return handler(args)
    except CordonError as exc:
        # Typed errors carry their own exit code, so the caller learns whether
        # this was their mistake or ours.
        print(f"{PROGRAM}: {exc.message}", file=sys.stderr)
        if exc.hint:
            print(f"  {exc.hint}", file=sys.stderr)
        return int(exc.exit_code)
    except KeyboardInterrupt:
        print(f"\n{PROGRAM}: interrupted", file=sys.stderr)
        return int(ExitCode.SCANNER_ERROR)
    except BrokenPipeError:
        # `cordon scan . | head` is a normal thing to do.
        return int(ExitCode.CLEAN)
    except Exception as exc:
        # An untyped exception reaching here is a bug in Cordon, and is reported
        # as one rather than dressed up as a scan result. Reporting it as
        # "findings" would be worse than useless: it would look like the code
        # was bad when the tool was.
        print(f"{PROGRAM}: internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "  This is a bug in cordon. Please report it with the command you ran.",
            file=sys.stderr,
        )
        return int(ExitCode.SCANNER_ERROR)


if __name__ == "__main__":
    raise SystemExit(main())
