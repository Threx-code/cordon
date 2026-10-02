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
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.cli.progress import TerminalProgress, TerminalText
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

EPILOG = f"""\
exit codes:
  0  clean          the scan completed and nothing met the failure policy
  1  findings       the scan completed and something met the failure policy
  2  scanner error  cordon itself failed
  3  config error   invalid configuration, policy, or a forbidden override
  4  incomplete     the scan was degraded and --fail-on-incomplete was set

  A plain `if cordon-scanner scan .` is correct with no flags, and any non-zero code
  fails safe. The distinctions above matter because a pipeline that cannot tell
  "the scanner broke" from "your code is bad" gets configured to ignore both.

tutorials for this version ({__version__}):
  https://github.com/Threx-code/cordon/tree/v{__version__}/tutorials
"""


_NO_DECLARED_VERSION = "0.0.0"
"""Stands for "this target declares no version of its own".

Also the value emitted when nothing better is found, so a document always
carries a version string -- both specifications want one.
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
            help=(
                "forbid all network access, including the signed intel feed (air-gapped "
                "use; CORDON_OFFLINE=1 does the same). The intel's age is still reported"
            ),
        )
        execution.add_argument(
            "--online",
            action="store_true",
            help=(
                "permit the detectors that query a package registry (npm and pypi "
                "only; other ecosystems are reported as unasked). Off by default; "
                "an organisation policy forbidding network access still wins, and a "
                "config found inside the scan target can never set it"
            ),
        )
        execution.add_argument(
            "--compare-with",
            metavar="PATH",
            help=(
                "an earlier release of the same package; report what this one adds -- a new "
                "install hook, new network or execution capability, new obfuscation or binaries. "
                "With --online and a published npm or PyPI artefact, the previous release is "
                "fetched from the registry instead"
            ),
        )
        execution.add_argument(
            "--allow-network",
            action="store_true",
            help=(
                "permit the one network operation there is: fetching a --policy "
                "URL, which must carry a #sha256= digest. Never used for scanning"
            ),
        )
        execution.add_argument(
            "--reachability",
            action="store_true",
            help=(
                "annotate vulnerability findings with import reachability: a vuln "
                "in a transitive dependency no first-party code imports is lowered "
                "and tagged (never dropped). Reads every source file to collect imports"
            ),
        )
        execution.add_argument(
            "--notify",
            metavar="CHANNELS",
            help=(
                "when the gate fails, post one message to each channel: webhook, slack, "
                "teams (comma-separated). URLs come only from CORDON_NOTIFY_WEBHOOK, "
                "CORDON_NOTIFY_SLACK and CORDON_NOTIFY_TEAMS; the webhook is signed with "
                "CORDON_NOTIFY_WEBHOOK_SECRET. A failed delivery never changes the exit code"
            ),
        )
        execution.add_argument(
            "--judge",
            metavar="MODEL",
            default=os.environ.get("CORDON_JUDGE") or None,
            help=(
                "also have a language model judge agent-facing text (instruction files, skills, "
                "MCP tool descriptions, hook commands): cordon-cloud (recommended; `cordon "
                "login`), anthropic[:<model>], openai:<model>, or ollama:<model> to keep "
                "everything on this machine. Off by default; only agent-facing text is sent, and "
                "the report says whether it ran (env: CORDON_JUDGE)"
            ),
        )
        execution.add_argument(
            "--judge-blocks",
            action="store_true",
            help="report a malicious verdict from --judge at HIGH, inside the default gate (default: it warns)",
        )
        execution.add_argument(
            "--judge-max-calls",
            type=int,
            default=200,
            metavar="N",
            help="the most model calls --judge may make in one scan (default 200)",
        )
        execution.add_argument(
            "--clamav",
            metavar="SOCKET",
            default=os.environ.get("CORDON_CLAMAV") or None,
            help=(
                "also hand each file to a local ClamAV daemon: a Unix socket path, or "
                "tcp://127.0.0.1:3310. Off by default; the report says whether it ran. "
                "Never set from a repository's own configuration (env: CORDON_CLAMAV)"
            ),
        )
        execution.add_argument(
            "--upload",
            action="store_true",
            help=(
                "send the results to Cordon Cloud after the scan (K2: an in-toto statement "
                "over the JSON results, signed keylessly with the CI identity when sigstore is "
                "installed). Needs `cordon login` or a CI OIDC token. A failed upload is "
                "reported and never changes the exit code"
            ),
        )
        execution.add_argument(
            "--cloud-policy",
            action="store_true",
            help=(
                "apply the organisation policy and approved suppressions from Cordon Cloud, "
                "verified against the policy key pinned at sign-in. Replaces --policy. If no "
                "current, verified bundle is available the scan does not run (exit 3)"
            ),
        )
        execution.add_argument(
            "--cloud-url",
            metavar="URL",
            default=None,
            help="Cordon Cloud API base (default: CORDON_CLOUD_URL, else https://api.cordon.dev)",
        )
        execution.add_argument(
            "--no-expand",
            action="store_true",
            help=(
                "do not open archives found inside a directory scan. Faster, and the "
                "scan is then marked incomplete if any archive went unopened"
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
        cls._add_baseline_scope(create)
        compare = baseline.add_parser("compare", help="report findings outside the baseline")
        compare.add_argument("target", nargs="?", default=".")
        compare.add_argument(
            "baseline_file", nargs="?", default="cordon-baseline.json", metavar="BASELINE"
        )
        compare.add_argument("--policy", metavar="PATH", default=None)
        cls._add_baseline_scope(compare)

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

        advisories = sub.add_parser(
            "advisories",
            help="manage the vulnerability/malicious-package advisory database",
        ).add_subparsers(dest="advisories_command")
        advisories_sync = advisories.add_parser(
            "sync", help="refresh the local advisory data from OSV's bulk export"
        )
        advisories_sync.add_argument(
            "--only",
            nargs="+",
            metavar="ECOSYSTEM",
            default=None,
            help="sync only these ecosystems (default: all supported)",
        )
        advisories_sync.add_argument(
            "--bundle",
            metavar="URL",
            default=None,
            help=(
                "install a signed advisory bundle from URL instead of building "
                "from OSV; the bundle's Ed25519 signature is verified against the "
                "pinned release key before anything is unpacked"
            ),
        )

        login = sub.add_parser(
            "login", help="sign in to Cordon Cloud through your organisation's SSO (device flow)"
        )
        login.add_argument("--url", default=None, help="Cordon Cloud API base")
        runner = sub.add_parser(
            "runner",
            help="run scan jobs from Cordon Cloud inside your own network (outbound only)",
        )
        runner.add_argument("--url", default=None, help="Cordon Cloud API base")
        runner.add_argument(
            "--allow-host",
            action="append",
            default=[],
            metavar="HOST",
            help="a host the runner may clone or download from (repeat); jobs naming any other are refused",
        )
        runner.add_argument(
            "--label", action="append", default=[], help="a label jobs can target (repeat)"
        )
        runner.add_argument(
            "--git-credential",
            action="append",
            default=[],
            metavar="HOST=ENV",
            help=(
                "clone private repositories on HOST with the credential in environment variable "
                "ENV: a token, or user:token (repeat). For GitLab and Bitbucket, which cannot "
                "mint a token per clone"
            ),
        )
        runner.add_argument(
            "--id", default=None, help="this runner's name (default: the host name)"
        )
        runner.add_argument(
            "--work-dir", default=None, help="where job workspaces are created and removed"
        )
        runner.add_argument("--once", action="store_true", help="take at most one job, then exit")
        agent = sub.add_parser(
            "agent",
            help="this machine's AI agents and MCP servers, for an organisation's MDM (read-only, disclosed)",
        ).add_subparsers(dest="agent_command")
        agent.add_parser(
            "inventory", help="print exactly what `agent report` would send; sends nothing"
        )
        agent_report = agent.add_parser(
            "report", help="send the inventory with the MDM's device token"
        )
        agent_report.add_argument("--url", default=None, help="Cordon Cloud API base")
        sub.add_parser("logout", help="forget the stored Cordon Cloud sign-in")
        sub.add_parser("whoami", help="show the Cordon Cloud sign-in in use")

        intel = sub.add_parser(
            "intel", help="the signed threat-intel feed: how current it is, and refreshing it"
        ).add_subparsers(dest="intel_command")
        intel_status = intel.add_parser(
            "status", help="show the intel's source, serial and age without fetching anything"
        )
        intel_status.add_argument("--json", action="store_true", help="print as JSON")
        intel_update = intel.add_parser(
            "update", help="verify and apply the latest signed feed now"
        )
        intel_update.add_argument("--json", action="store_true", help="print as JSON")

        sbom = sub.add_parser(
            "sbom", help="generate or inspect a bill of materials for a scan target"
        ).add_subparsers(dest="sbom_command")
        sbom_generate = sbom.add_parser(
            "generate", help="write a CycloneDX or SPDX document from the resolved graph"
        )
        sbom_generate.add_argument("target", nargs="?", default=".")
        sbom_generate.add_argument("--format", choices=("cyclonedx", "spdx"), default="cyclonedx")
        sbom_generate.add_argument("--output", "-o", metavar="PATH", default=None)
        sbom_generate.add_argument(
            "--ai",
            action="store_true",
            help=(
                "write the AI bill of materials instead (CycloneDX 1.6): agent instruction, skill "
                "and prompt files, agent settings, MCP servers, models and AI SDKs"
            ),
        )
        sbom_generate.add_argument(
            "--vulnerabilities",
            action="store_true",
            help=(
                "embed the advisory matches (CycloneDX `vulnerabilities`), marking those on "
                "CISA KEV or ENISA EUVD as exploited: the per-release record the EU Cyber "
                "Resilience Act asks a manufacturer to keep"
            ),
        )
        sbom_generate.add_argument(
            "--name",
            metavar="NAME",
            default=None,
            help="root component name (default: directory name)",
        )
        sbom_generate.add_argument(
            "--component-version",
            metavar="VERSION",
            default=_NO_DECLARED_VERSION,
            help=(
                "root component version (default: whatever the target's own manifest "
                "declares, or 0.0.0 when it declares none)"
            ),
        )

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
    def _with_release_diff(
        cls, args: argparse.Namespace, target: Path, result: Any, config: Any, selected: Any
    ) -> Any:
        """The scan result, plus what this release adds over the one before it.

        `--compare-with` names the earlier artefact. Without it, `--online` and a published npm or
        PyPI artefact fetch the previous release from the registry. A comparison that cannot be
        made is said, never silently skipped.
        """
        from dataclasses import replace as _replace

        from cordon_scanner import Scanner
        from cordon_scanner.core import release_diff
        from cordon_scanner.sources import previous as previous_release

        compare_with = getattr(args, "compare_with", None)
        if not compare_with and not (args.online and target.is_file()):
            return result
        with previous_release.PreviousRelease.workspace() as work:
            publisher_change = ""
            try:
                if compare_with:
                    earlier = Path(compare_with)
                    if not earlier.exists():
                        raise CordonError(f"--compare-with: {earlier} does not exist")
                    label = earlier.name
                else:
                    identity = previous_release.PreviousRelease.identify(target)
                    if identity is None:
                        return result
                    found = previous_release.PreviousRelease.fetch_previous(identity, work)
                    if found is None:
                        if not args.quiet:
                            print(
                                f"no earlier release of {identity.name} to compare with",
                                file=sys.stderr,
                            )
                        return result
                    earlier, label, publisher_change = (
                        found.path,
                        found.label,
                        found.publisher_change,
                    )
            except (OSError, ValueError, KeyError) as exc:
                print(f"{cls.PROGRAM}: release comparison skipped: {exc}", file=sys.stderr)
                return result
            old = Scanner(config, detectors=selected).scan(earlier)
        changes = release_diff.ReleaseDiff.compare(
            release_diff.Profile.of(result), release_diff.Profile.of(old), previous=label
        )
        if publisher_change:
            changes.append(
                release_diff.Change(
                    release_diff.RELEASE_NEW_PUBLISHER,
                    Severity.MEDIUM,
                    "package.json",
                    publisher_change
                    + " A new publishing account on an established package is how most "
                    "maintainer-takeover compromises first show.",
                )
            )
        if not args.quiet:
            print(
                f"compared with {label}: "
                + (
                    ", ".join(sorted({c.rule_id.split(".")[2].lower() for c in changes}))
                    if changes
                    else "no new install hooks, capabilities, obfuscation or binaries"
                ),
                file=sys.stderr,
            )
        if not changes:
            return result
        added = release_diff.ReleaseDiff.as_findings(changes, result)
        return _replace(
            result,
            findings=tuple(sorted((*result.findings, *added), key=lambda f: -f.severity.value)),
        )

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
        # The command line is the operator, so this is the one layer allowed to
        # ask for the network. `--offline` is the default and is accepted as an
        # explicit statement of it; `--online` is what the coverage matrix has
        # always told users to pass. Neither overrides an organisation policy:
        # `stricter_of` takes `self.offline or org.offline`.
        if args.online:
            overrides["offline"] = False
        elif args.offline:
            overrides["offline"] = True
        # `--offline` and CORDON_OFFLINE mean no network at all, the air-gapped mode: the intel
        # feed is not fetched either. Without them the scan still never sends anything about
        # the code; it only pulls the public, signed feed.
        from cordon_scanner.intel.feed import FeedClient

        if args.offline or FeedClient.offline_requested():
            overrides["intel_feed"] = False
        if getattr(args, "reachability", False):
            overrides["reachability"] = True
        if getattr(args, "no_expand", False):
            overrides["expand_archives"] = False
        if getattr(args, "clamav", None):
            overrides["clamav"] = args.clamav
        if getattr(args, "judge", None):
            overrides["judge"] = args.judge
            overrides["judge_blocks"] = bool(getattr(args, "judge_blocks", False))
            overrides["judge_max_calls"] = max(1, int(getattr(args, "judge_max_calls", 200)))

        cloud_bundle = None
        policy_path = args.policy
        if getattr(args, "cloud_policy", False):
            if args.policy:
                raise ConfigError(
                    "--cloud-policy and --policy both name the organisation policy",
                    hint="Use one: the cloud bundle is the organisation policy when --cloud-policy is set.",
                )
            cloud_bundle, policy_path = cls._cloud_policy(args)

        config = ConfigResolver.resolve(
            root=target if target.is_dir() else target.parent,
            config_path=args.config,
            policy_path=policy_path,
            allow_network=args.allow_network,
            **overrides,
        )
        if cloud_bundle is not None and cloud_bundle.suppressions:
            config = cls._with_cloud_suppressions(config, cloud_bundle.suppressions)

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

        # Validated before the scan, like the audit log below: an unknown channel is a
        # corrected command line, not a message that silently never arrives.
        channels: tuple[str, ...] = ()
        if getattr(args, "notify", None):
            from cordon_scanner.notify import Notifier

            try:
                channels = Notifier.parse_channels(args.notify)
            except ValueError as exc:
                raise ConfigError(str(exc)) from exc

        source = cls._git_source(args, target)

        # Checked before the scan, not after it. An audit log that turns out to
        # be unwritable once the work is done leaves an operator with a scan
        # they cannot attest to; failing here makes it a corrected command line.
        audit = AuditLog.prepare(args.audit_log) if args.audit_log else None

        # stderr, never stdout: a report is written to stdout when --output is
        # not given, and a progress line there corrupts the JSON or SARIF a
        # pipeline is parsing.
        progress: Progress | None = None
        if TerminalText.should_show(sys.stderr, args.progress, quiet=args.quiet):
            progress = TerminalProgress(sys.stderr, color=cls._use_color(args.no_color))

        result = Scanner(config, detectors=selected, source=source, progress=progress).scan(target)
        result = cls._with_release_diff(args, target, result, config, selected)

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
        if channels and verdict.exit_code in (ExitCode.FINDINGS, ExitCode.INCOMPLETE):
            cls._notify(channels, result, verdict, verbose=args.verbose)
        if getattr(args, "upload", False):
            # The upload carries the verdict as it is; Cordon applies the repository's mode too.
            cls._upload(args, result, verdict, target)
        return cls._gated_exit(verdict, cloud_bundle, result, quiet=args.quiet)

    @classmethod
    def _gated_exit(cls, verdict: Any, bundle: Any, result: ScanResult, *, quiet: bool) -> int:
        """The exit code the pipeline sees: the verdict's, unless the organisation's bundle puts
        this repository's gate in `observe` or `warn`, where a failing verdict is reported and
        recorded but does not fail the build. Without a bundle the verdict stands unchanged."""
        code = int(verdict.exit_code)
        if bundle is None or code == int(ExitCode.CLEAN):
            return code
        from cordon_scanner.notify import Webhooks

        key = Webhooks._target_name(result)
        mode = bundle.gate_mode(key)
        if mode not in ("observe", "warn"):
            return code
        if not quiet:
            print(
                f"{cls.PROGRAM}: {key} is in {mode} mode: the verdict is recorded, the build is not failed",
                file=sys.stderr,
            )
        return int(ExitCode.CLEAN)

    @classmethod
    def _cloud_policy(cls, args: argparse.Namespace) -> tuple[Any, str | None]:
        """Fetch and verify the organisation's bundle; no bundle, no scan."""
        from cordon_scanner.cloud import CloudError, auth, policy
        from cordon_scanner.intel.feed import FeedClient

        try:
            credentials = auth.CloudAuth.current(args.cloud_url)
            bundle = policy.CloudPolicy.fetch(
                credentials, offline=bool(args.offline) or FeedClient.offline_requested()
            )
        except CloudError as exc:
            raise ConfigError(
                f"the organisation policy could not be applied: {exc}",
                hint="Run `cordon login`, or connect once so a current bundle is cached.",
            ) from exc
        if args.verbose:
            print(
                f"{cls.PROGRAM}: organisation policy v{bundle.version} ({bundle.source}, "
                f"key {bundle.key_id}, {len(bundle.suppressions)} approved suppression(s))",
                file=sys.stderr,
            )
        path = policy.CloudPolicy.materialise(bundle)
        return bundle, str(path) if path is not None else None

    @staticmethod
    def _with_cloud_suppressions(config: Any, suppressions: tuple[Any, ...]) -> Any:
        """Add the organisation's approved suppressions, held to the same rules as any other."""
        from cordon_scanner.core.config import ConfigParser

        problems = [
            f"{s.rule} at {s.path}: {problem}"
            for s in suppressions
            if (problem := ConfigParser._suppression_violation(s, config.constraints))
        ]
        if problems:
            raise ConfigError(
                "suppressions in the organisation's policy bundle are not acceptable:\n  - "
                + "\n  - ".join(problems)
            )
        return config.with_overrides(suppressions=(*config.suppressions, *suppressions))

    @classmethod
    def _upload(
        cls, args: argparse.Namespace, result: ScanResult, verdict: Any, target: Path
    ) -> None:
        """Send the results. Reported on stderr, never allowed to change the exit code."""
        from cordon_scanner.cloud import CloudError, auth, results

        try:
            credentials = auth.CloudAuth.current(args.cloud_url)
            ambient = auth.CloudAuth.ambient_identity_token()
            signer = results.SignedResults.sigstore_signer(None) if ambient is not None else None
            receipt = results.SignedResults.upload(
                result,
                credentials,
                exit_code=int(verdict.exit_code),
                reason=str(verdict.reason),
                signer=signer,
                ai_document=results.SignedResults.ai_inventory(target, result),
            )
        except CloudError as exc:
            print(f"{cls.PROGRAM}: upload failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:
            print(
                f"{cls.PROGRAM}: upload failed while signing: {type(exc).__name__}", file=sys.stderr
            )
            return
        if not args.quiet:
            trust = (
                "signed with the CI identity"
                if receipt.signing == "sigstore"
                else "unsigned, vouched for by the sign-in"
            )
            where = f" {receipt.url}" if receipt.url else ""
            print(
                f"{cls.PROGRAM}: uploaded scan {receipt.scan_id} ({trust}){where}", file=sys.stderr
            )

    @classmethod
    def _notify(
        cls, channels: tuple[str, ...], result: ScanResult, verdict: Any, *, verbose: bool
    ) -> None:
        """Post the gate failure. Reported on stderr, never allowed to change the exit code."""
        from cordon_scanner.notify import Notifier

        deliveries = Notifier().send(
            channels, result, reason=str(verdict.reason), exit_code=int(verdict.exit_code)
        )
        for delivery in deliveries:
            if not delivery.ok:
                print(
                    f"{cls.PROGRAM}: notify {delivery.channel} failed: {delivery.error}",
                    file=sys.stderr,
                )
            elif verbose:
                print(f"{cls.PROGRAM}: notified {delivery.channel}", file=sys.stderr)

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
    def _baseline_source(cls, args: argparse.Namespace, target: Path) -> FileSource | None:
        """Tracked files by default, because a baseline is a committed artefact.

        The bug this fixes: `baseline create` walked the working tree, so a
        repository with a local `.env`, a `venv/`, a `node_modules/` or a
        `coverage/` directory got those paths written into a file that is then
        committed. Three things are wrong with that at once.

        The entries cannot be reproduced. A fingerprint over a path no other
        clone has is debt nobody else can see, clear or verify, and `compare`
        reports it as "no longer occurs" on every machine but the one that wrote
        it.

        The baseline misrepresents the repository. A reviewer reading it to find
        out what is being carried is reading findings about files that are not
        part of the project.

        And a secret scanner reading untracked `.env` files by default is the
        wrong default whatever it does with what it finds. Nothing leaks here --
        baseline entries carry a fingerprint, a rule id and a path, never the
        value, and evidence is hash-only throughout -- but the shape of the
        mistake is the one this tool exists to object to elsewhere.

        Unlike `_git_source`, a tree that is not a repository is not an error.
        `--tracked` on `scan` is a promise about which bytes were read and must
        fail rather than quietly widen; this is a default about which files are
        worth recording, and refusing to baseline an unversioned directory would
        be refusing to do the thing that was asked. It says which it did, both
        ways, because a scope a reader has to infer is a scope they will get
        wrong.
        """
        if args.all_files:
            return None

        from cordon_scanner.sources.git import GitPathSource, GitRepository

        info = GitRepository.discover(target)
        if info is None:
            print(
                "cordon: not a git repository; the baseline covers every file under the target",
                file=sys.stderr,
            )
            return None

        paths = GitRepository(info.root).tracked_files()
        print(
            f"cordon: the baseline covers {len(paths)} tracked file(s); "
            "pass --all-files to include paths git ignores",
            file=sys.stderr,
        )
        return GitPathSource(paths, mode="tracked")

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
                    print(f"wrote {name} report to {destination}", file=sys.stderr)
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
                    if match.references:
                        print("\nreferences")
                        for link in match.references:
                            print(f"  {link}")
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
            # Pack rules have carried references since the loader was written
            # and this never printed them, so the one place a reader goes to
            # ask "says who?" answered for neither kind of rule.
            if rule.references:
                print("references")
                for link in rule.references:
                    print(f"  {link}")
                print()
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
    def cmd_login(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.cloud import CloudError, auth

        try:
            code = auth.CloudAuth.start_device_flow(args.url)
            print(
                f"To sign in, open {code.verification_uri} and enter the code {code.user_code}\n"
                f"(or open {code.verification_uri_complete}). Waiting for approval...",
                file=sys.stderr,
            )
            credentials = auth.CloudAuth.finish_device_flow(code, args.url)
        except CloudError as exc:
            print(f"{cls.PROGRAM}: {exc}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        path = auth.CloudAuth.save(credentials)
        keys = len(credentials.policy_keys)
        print(
            f"Signed in to {credentials.org or 'Cordon Cloud'} as {credentials.subject or 'this device'}. "
            f"{keys} policy key(s) pinned. Stored in {path} (mode 0600)."
        )
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_runner(cls, args: argparse.Namespace) -> int:
        import socket

        from cordon_scanner.cloud import CloudEndpoint, CloudError, runner

        token = os.environ.get("CORDON_RUNNER_TOKEN", "")
        if not token:
            raise ConfigError(
                "CORDON_RUNNER_TOKEN is not set",
                hint="Create a runner token in the dashboard and pass it in the environment, never as a flag.",
            )
        if not args.allow_host:
            raise ConfigError(
                "a runner needs at least one --allow-host",
                hint="Name the hosts it may clone from, for example --allow-host github.com.",
            )
        try:
            url = CloudEndpoint.base_url(args.url)
        except CloudError as exc:
            raise ConfigError(str(exc)) from exc
        credentials = []
        for spec in args.git_credential:
            host, _, variable = spec.partition("=")
            if host.lower() not in {h.lower() for h in args.allow_host}:
                raise ConfigError(
                    f"--git-credential names {host!r}, which is not an --allow-host",
                    hint="A credential is only ever sent to a host the runner may clone from.",
                )
            value = os.environ.get(variable, "") if variable else ""
            if not value:
                raise ConfigError(
                    f"--git-credential {spec}: the environment variable {variable or '(none)'} is empty",
                    hint="Pass the credential in the environment, never as a flag.",
                )
            credentials.append(runner.CloudRunner.git_credential(host, value))
        config = runner.RunnerConfig(
            url=url,
            token=token,
            runner_id=args.id or socket.gethostname(),
            allowed_hosts=frozenset(h.lower() for h in args.allow_host),
            labels=tuple(args.label),
            work_dir=Path(args.work_dir) if args.work_dir else Path(tempfile.gettempdir()),
            git_credentials=tuple(credentials),
        )
        print(f"{cls.PROGRAM}: runner {config.runner_id} polling {url}", file=sys.stderr)
        runner.CloudRunner.serve(
            config,
            once=args.once,
            log=lambda line: print(f"{cls.PROGRAM}: {line}", file=sys.stderr),
        )
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_agent(cls, args: argparse.Namespace) -> int:
        import json

        from cordon_scanner.cloud import CloudError, device

        action = getattr(args, "agent_command", None)
        if action not in ("inventory", "report"):
            print(f"{cls.PROGRAM}: agent needs inventory or report", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        payload = device.DeviceInventory.collect()
        if action == "inventory":
            print(json.dumps(payload, indent=2, sort_keys=True))
            return int(ExitCode.CLEAN)
        try:
            receipt = device.DeviceInventory.report(payload, url=args.url)
        except CloudError as exc:
            print(f"{cls.PROGRAM}: {exc}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        inventory = payload["inventory"]
        print(
            f"sent: {len(inventory['tools'])} tool(s), {len(inventory['mcp_servers'])} MCP server(s), "
            f"{len(payload['findings'])} finding(s){f' (receipt {receipt})' if receipt else ''}"
        )
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_logout(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.cloud import auth

        print("Signed out." if auth.CloudAuth.forget() else "Not signed in.")
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_whoami(cls, args: argparse.Namespace) -> int:
        import time

        from cordon_scanner.cloud import auth

        stored = auth.CloudAuth.load()
        if stored is None:
            print("Not signed in. Run `cordon login`.")
            return int(ExitCode.CONFIG_ERROR)
        remaining = int(stored.expires_at - time.time())
        state = (
            f"token valid for {remaining // 60} min"
            if remaining > 0
            else "token expired, renews on next use"
        )
        print(f"{stored.subject or 'this device'} at {stored.org} ({stored.url}); {state}")
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_intel(cls, args: argparse.Namespace) -> int:
        """Report on, or refresh, the signed intel feed.

        `status` never touches the network. `update` is the operator asking for the feed, so it
        is refused under CORDON_OFFLINE rather than quietly doing nothing, and a verification
        failure exits non-zero so a scheduled job notices.
        """
        import json as _json

        from cordon_scanner.intel import feed

        action = getattr(args, "intel_command", None)
        if action not in ("status", "update"):
            print(f"{cls.PROGRAM}: intel needs status or update", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        if action == "update" and feed.FeedClient.offline_requested():
            raise ConfigError("CORDON_OFFLINE is set, so the feed will not be fetched")

        current = feed.FeedClient.status(use_feed=action == "update", max_age=None)
        if args.json:
            print(_json.dumps(current.to_dict(), indent=2, sort_keys=True))
        else:
            age = (
                f"{current.age_seconds // 3600}h {current.age_seconds % 3600 // 60}m"
                if current.age_seconds is not None
                else "unknown"
            )
            print(
                f"source:  {current.source}"
                + (f" (serial {current.serial})" if current.serial else "")
            )
            print(f"age:     {age}" + (" -- STALE" if current.stale else ""))
            print(
                f"feed:    {'enabled' if current.feed_enabled else 'not available in this build'}"
            )
            if current.error:
                print(f"note:    {current.error}")
        if action == "update" and not current.refreshed:
            return int(ExitCode.SCANNER_ERROR)
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_advisories(cls, args: argparse.Namespace) -> int:
        """Refresh the local vulnerability/malicious-package data from OSV.

        Writes to a user cache directory, never into the installed package --
        see `intel/advisories.user_sync_dir`. This is the on-demand
        counterpart to `.github/workflows/refresh-advisories.yml`'s scheduled
        refresh: for an operator who wants current data now rather than
        waiting for the next release to pick up the last scheduled run.
        """
        action = getattr(args, "advisories_command", None)
        if action is None:
            print(f"{cls.PROGRAM}: advisories needs sync", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        if action != "sync":
            raise ConfigError(f"unknown advisories action: {action}")

        import tempfile

        from cordon_scanner.intel import osv_import
        from cordon_scanner.intel.advisories import AdvisoryFiles

        # A signed bundle: fetch and verify a prebuilt database rather than
        # building one from OSV. The two share the same destination and the same
        # per-file digest manifest, so a later scan cannot tell which produced
        # the data -- only that it verified.
        if getattr(args, "bundle", None):
            from cordon_scanner.intel import dbsync

            destination = AdvisoryFiles.user_sync_dir()
            try:
                dbsync.AdvisoryBundle.sync_from_url(args.bundle, destination)
            except dbsync.BundleError as exc:
                raise ConfigError(f"advisories sync: {exc}") from exc
            print(f"installed a verified advisory bundle into {destination}")
            return int(ExitCode.CLEAN)

        requested = args.only or sorted(osv_import.ECOSYSTEM_OSV_NAMES)
        unknown = [e for e in requested if e not in osv_import.ECOSYSTEM_OSV_NAMES]
        if unknown:
            raise ConfigError(
                f"unknown ecosystem(s) for --only: {', '.join(unknown)}",
                hint=f"choose from: {', '.join(sorted(osv_import.ECOSYSTEM_OSV_NAMES))}",
            )
        ecosystems = tuple(sorted(requested))

        print(f"syncing {len(ecosystems)} ecosystem(s) from OSV...")
        with tempfile.TemporaryDirectory(prefix="cordon-osv-") as tmp:
            try:
                result = osv_import.OsvImport.sync_all(ecosystems, tmp_dir=Path(tmp))
            except osv_import.OsvImportError as exc:
                raise ConfigError(f"advisories sync: {exc}") from exc

        destination = AdvisoryFiles.user_sync_dir()
        osv_import.OsvImport.write_output(result, destination)
        for ecosystem in ecosystems:
            count = len(result.per_ecosystem.get(ecosystem, ()))
            print(f"  {ecosystem}: {count:,} advisor(y/ies)")
        print(
            f"synced {result.meta.record_count:,} advisories to {destination}\n"
            f"future scans on this machine will prefer this over the bundled snapshot "
            f"until the next release ships something newer."
        )
        return int(ExitCode.CLEAN)

    @staticmethod
    def _root_component(result: object, target: Path) -> tuple[str | None, str | None]:
        """The name and version the target declares for itself, if it does.

        The shallowest manifest wins, and ties break on path, so a monorepo
        with several manifests names the same one on every run -- an SBOM that
        described a different component depending on directory iteration order
        would not be reproducible.

        A manifest that carries no name contributes nothing: the caller falls
        back to the directory, which is a guess clearly labelled as one.
        """
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.core.limits import Limits
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        repository = getattr(result, "repository", None)
        projects = sorted(
            getattr(repository, "projects", ()) or (),
            key=lambda p: (p.path.count("/"), p.path),
        )
        for project in projects:
            ecosystem = EcosystemRegistry.get(project.ecosystem)
            if ecosystem is None:
                continue
            for manifest_path in project.manifests:
                loaded = FileContent.load(target / manifest_path, manifest_path, Limits())
                if not isinstance(loaded, FileContent):
                    continue
                try:
                    manifest = ecosystem.parse_manifest(loaded)
                except Exception:  # noqa: S112 - an unreadable manifest is one fewer answer
                    continue
                if manifest.parse_error or not manifest.name:
                    continue
                return (manifest.name, manifest.version)
        return (None, None)

    @classmethod
    def _embed_vulnerabilities(cls, document: dict[str, Any], result: Any) -> None:
        """Add the advisory matches to a CycloneDX document, and say when one is exploited."""
        from cordon_scanner.report.vex import EXPLOITED_RULE, VULNERABILITY_RULES, VexReporter

        findings = [
            f for f in result.findings if f.rule_id in VULNERABILITY_RULES and not f.is_suppressed
        ]
        document["vulnerabilities"] = [VexReporter._statement(f) for f in findings]
        exploited = [f for f in findings if f.rule_id == EXPLOITED_RULE]
        document["metadata"]["properties"] = [
            {"name": "cordon:vulnerabilities", "value": str(len(findings))},
            {"name": "cordon:exploited", "value": str(len(exploited))},
        ]
        if exploited:
            print(
                f"{cls.PROGRAM}: {len(exploited)} component vulnerabilit"
                f"{'y is' if len(exploited) == 1 else 'ies are'} exploited in the wild (CISA KEV / "
                f"ENISA EUVD). Under the EU Cyber Resilience Act, an actively exploited "
                f"vulnerability in a product you ship is reportable within 24 hours.",
                file=sys.stderr,
            )

    @classmethod
    def cmd_sbom(cls, args: argparse.Namespace) -> int:
        """Generate a bill of materials from the resolved dependency graph.

        The counterpart to `SUSPECT.SBOM.DRIFT.001` (`detect/sbom.py`), which
        only ever compares an existing document against this same graph.
        Resolves the graph the same way a scan does -- reading lockfiles and
        manifests, never invoking a package manager (`docs/01-ARCHITECTURE.md`
        C4) -- but with no detectors registered, so nothing is matched against
        a rule and this is materially faster than a full scan.
        """
        action = getattr(args, "sbom_command", None)
        if action is None:
            print(f"{cls.PROGRAM}: sbom needs generate", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        if action != "generate":
            raise ConfigError(f"unknown sbom action: {action}")

        from cordon_scanner import Scanner
        from cordon_scanner.report import sbom as sbom_report

        target = Path(args.target)
        if not target.exists():
            raise CordonError(
                f"target does not exist: {target}",
                hint="Pass a directory, file or archive path.",
            )

        if getattr(args, "ai", False) and (args.format != "cyclonedx" or not target.is_dir()):
            raise ConfigError(
                "--ai writes CycloneDX for a directory",
                hint="Pass a repository directory and --format cyclonedx (the default).",
            )
        detectors: tuple[Any, ...] = ()
        if getattr(args, "vulnerabilities", False):
            if args.format != "cyclonedx":
                raise ConfigError(
                    "--vulnerabilities needs --format cyclonedx",
                    hint="SPDX 2.3 has no field for vulnerability status; use a VEX document beside it.",
                )
            from cordon_scanner.detect.advisory import AdvisoryDetector

            detectors = (AdvisoryDetector(),)
        result = Scanner(detectors=detectors).scan(target)
        # The scan has already parsed the target's own manifests, so the
        # directory name is a fallback rather than the answer. A project whose
        # package.json says `{"name": "g", "version": "1.0.0"}` was described in
        # its own SBOM as `scan@0.0.0`, taken from whatever the directory
        # happened to be called.
        declared_name, declared_version = cls._root_component(result, target)
        root_name = args.name or declared_name or target.resolve().name or "target"
        root_version = (
            args.component_version
            if args.component_version != _NO_DECLARED_VERSION
            else (declared_version or _NO_DECLARED_VERSION)
        )

        if getattr(args, "ai", False):
            from cordon_scanner.report import aibom

            document = aibom.AiBom.cyclonedx_document(
                target,
                result.dependencies,
                root_name=root_name,
                root_version=root_version,
                tool_version=__version__,
            )
        elif args.format == "cyclonedx":
            document = sbom_report.SbomDocument.cyclonedx_document(
                result.dependencies,
                root_name=root_name,
                root_version=root_version,
                tool_version=__version__,
            )
            if detectors:
                cls._embed_vulnerabilities(document, result)
        else:
            document = sbom_report.SbomDocument.spdx_document(
                result.dependencies,
                root_name=root_name,
                root_version=root_version,
                tool_version=__version__,
            )

        import json

        payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(payload, encoding="utf-8")
            written = len(document.get("components", ())) + len(document.get("services", ()))
            print(f"wrote {destination} ({written} component(s), {args.format})")
        else:
            sys.stdout.write(payload)

        if not result.complete:
            print(
                f"{cls.PROGRAM}: the scan that produced this graph was incomplete; "
                f"the bill of materials may be missing components",
                file=sys.stderr,
            )
            return int(ExitCode.INCOMPLETE)
        return int(ExitCode.CLEAN)

    @staticmethod
    def _add_baseline_scope(parser: argparse.ArgumentParser) -> None:
        """The one flag that decides which files a baseline is about.

        On `create` and `compare` both, from one definition. A baseline created
        over tracked files and compared against a whole working tree reports
        every ignored file as a new finding, which is the failure the shared
        default exists to prevent -- and two separately declared flags with the
        same name is how two commands come to disagree about one.
        """
        parser.add_argument(
            "--all-files",
            action="store_true",
            help=(
                "include files git ignores; by default a baseline inside a "
                "repository covers tracked files only"
            ),
        )

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
        result = Scanner(config, source=cls._baseline_source(args, target)).scan(target)
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
            "advisories": cls.cmd_advisories,
            "intel": cls.cmd_intel,
            "login": cls.cmd_login,
            "logout": cls.cmd_logout,
            "runner": cls.cmd_runner,
            "agent": cls.cmd_agent,
            "whoami": cls.cmd_whoami,
            "sbom": cls.cmd_sbom,
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

    @staticmethod
    def main(argv: Sequence[str] | None = None) -> int:
        """Console-script entry point.

        A module-level name because that is what a `console_scripts` entry point and
        `python -m cordon` need. It delegates immediately; no logic lives here.
        """
        return CommandLine.run(argv)


__all__ = ["CommandLine"]


if __name__ == "__main__":
    raise SystemExit(CommandLine.main())
