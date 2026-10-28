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
import functools
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.cli.commands.account.login import LoginCommand
from cordon_scanner.cli.commands.advisories import AdvisoriesCommand
from cordon_scanner.cli.commands.baseline import BaselineCommand
from cordon_scanner.cli.commands.bundle import BundleCommand
from cordon_scanner.cli.commands.config import ConfigCommand
from cordon_scanner.cli.commands.guard import GuardCommand
from cordon_scanner.cli.commands.intel import IntelCommand
from cordon_scanner.cli.commands.inventory import InventoryCommand
from cordon_scanner.cli.commands.report import ReportCommand
from cordon_scanner.cli.commands.rules import RulesCommand
from cordon_scanner.cli.commands.runner import RunnerCommand
from cordon_scanner.cli.commands.sbom import SbomCommand
from cordon_scanner.cli.commands.scan.enrichment import ScanEnrichment
from cordon_scanner.cli.dependency_payload import DependencyPayload
from cordon_scanner.cli.help import ColourArgumentParser, GroupHelp, HelpCommand
from cordon_scanner.cli.progress import TerminalProgress, TerminalText
from cordon_scanner.engine.audit import AuditLog
from cordon_scanner.foundation.errors import ConfigError, CordonError, ExitCode
from cordon_scanner.foundation.models import Confidence, Finding, Severity
from cordon_scanner.foundation.renames import Renamed
from cordon_scanner.version import PROGRAM as PROGRAM_NAME
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from cordon_scanner.engine.progress import Progress
    from cordon_scanner.foundation.results import ScanResult
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

    @classmethod
    def build_parser(cls) -> ColourArgumentParser:
        parser = ColourArgumentParser(
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
        scan.add_argument(
            "target",
            nargs="?",
            default=".",
            help=(
                "path to scan (default: .), or a package URL such as pkg:npm/name@1.0.0 "
                "(npm, pypi, cargo, gem, nuget, golang, hex, pub, maven), or a container image as "
                "pkg:docker/nginx@1.27, pulled from its registry; needs --online"
            ),
        )

        host_group = scan.add_argument_group("host")
        host_group.add_argument(
            "--host",
            action="store_true",
            help=(
                "read TARGET as the root of an installed system (default /): its OS packages and the "
                "language packages installed outside any project, matched for known vulnerabilities "
                "and malicious releases (OS packages with --online). Files are not content-scanned"
            ),
        )
        host_group.add_argument(
            "--home",
            metavar="DIR",
            default=None,
            help="with --host, also read this user's own installs (pipx, ~/.local, ~/go/bin, cargo install)",
        )

        secrets_group = scan.add_argument_group("secrets")
        secrets_group.add_argument(
            "--history",
            action="store_true",
            help="also read every blob in git history that is no longer in the tree, for secrets",
        )
        secrets_group.add_argument(
            "--verify-secrets",
            action="store_true",
            help="ask each found credential's own issuer whether it still works (needs --online)",
        )

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
            "--hardening",
            action="store_true",
            help=(
                "report pipeline, container and infrastructure hardening findings at their own "
                "severity instead of recording them at LOW"
            ),
        )
        policy.add_argument(
            "--baseline",
            metavar="PATH",
            help="treat findings recorded in this file as already-known",
        )
        policy.add_argument(
            "--vex",
            metavar="PATH",
            action="append",
            default=None,
            help=(
                "an OpenVEX or CycloneDX VEX document (repeatable): a vulnerability a statement "
                "rules out (not_affected, fixed) is marked suppressed with its justification"
            ),
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
        DependencyPayload.add_argument(execution)
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
            "--model",
            metavar="SERVER",
            default=None,
            help=(
                "also have Cordon's own detection model score the packages this scan holds (a scanned "
                "package archive, archives in the tree, installed node_modules and site-packages): "
                "cordon-cloud (`cordon-scanner login`), or the https:// address of a cordon-model-server "
                "with its token in CORDON_MODEL_TOKEN. Sends features -- counts and hashed identifiers "
                "-- never source"
            ),
        )
        execution.add_argument(
            "--judge",
            metavar="MODEL",
            default=os.environ.get("CORDON_JUDGE") or None,
            help=(
                "also have a language model judge agent-facing text (instruction files, skills, "
                "MCP tool descriptions, hook commands): cordon-cloud (recommended; "
                f"`{cls.PROGRAM} login`), anthropic[:<model>], openai:<model>, or ollama:<model> to keep "
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
            "--registry-token",
            dest="registry_tokens",
            action="append",
            metavar="URL=VARIABLE",
            default=[os.environ["CORDON_REGISTRY_TOKENS"]]
            if os.environ.get("CORDON_REGISTRY_TOKENS")
            else [],
            help=(
                "with --online, ask a private registry about what was resolved from it, presenting "
                "the token held in the environment variable named (repeatable; never the token "
                "itself). Never set from a repository's configuration (env: CORDON_REGISTRY_TOKENS)"
            ),
        )
        execution.add_argument(
            "--keyring",
            dest="keyrings",
            action="append",
            metavar="FILE",
            default=[
                p for p in os.environ.get("CORDON_KEYRINGS", "").split(os.pathsep) if p.strip()
            ],
            help=(
                "with --online, verify a Helm chart's provenance file and an Ansible collection's "
                "signatures against the OpenPGP keys in FILE, as `helm verify --keyring` and "
                "`ansible-galaxy collection verify --keyring` do: armored, binary or a GnuPG keybox "
                "(repeatable). Never set from a repository's own "
                "configuration (env: CORDON_KEYRINGS, separated by the path separator)"
            ),
        )
        execution.add_argument(
            "--rule-file",
            metavar="RULES",
            default=os.environ.get("CORDON_RULE_FILE") or None,
            help="also match every file against a cordon-rule rule file (`builtin` for the pack "
            "shipped with Cordon). Off by default; never set from a repository's own "
            "configuration (env: CORDON_RULE_FILE)",
        )
        execution.add_argument("--yara", dest="rule_file_old", help=argparse.SUPPRESS)
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
                f"installed). Needs `{cls.PROGRAM} login` or a CI OIDC token. A failed upload is "
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

        InventoryCommand.add_parser(sub)

        RulesCommand.add_parser(sub)

        GuardCommand.add_parser(sub)

        ConfigCommand.add_parser(sub)
        ReportCommand.add_parser(sub)

        BaselineCommand.add_parser(sub)

        BundleCommand.add_parser(sub)

        AdvisoriesCommand.add_parser(sub)

        LoginCommand.add_parser(sub)
        RunnerCommand.add_parser(sub)
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
        approve = agent.add_parser(
            "mcp-approve",
            help="record the tools each remote MCP server in the repository serves now (.cordon/mcp-tools.json)",
        )
        approve.add_argument(
            "target", nargs="?", default=".", help="repository directory (default: .)"
        )
        sub.add_parser("logout", help="forget the stored Cordon Cloud sign-in")
        sub.add_parser("whoami", help="show the Cordon Cloud sign-in in use")

        IntelCommand.add_parser(sub)
        SbomCommand.add_parser(sub)

        from cordon_scanner.cli.completion import CompletionCommand
        from cordon_scanner.cli.deps import DepsCommand
        from cordon_scanner.cli.suppressions import SuppressCommand

        DepsCommand.add_parser(sub)
        from cordon_scanner.cli.incoming import IncomingCommand
        from cordon_scanner.cli.review import ReviewCommand

        IncomingCommand.add_parser(sub)

        ReviewCommand.add_parser(sub)
        SuppressCommand.add_parser(sub)
        CompletionCommand.add_parser(sub)
        # `run` hands `mcp` the rest of the command line before this parser sees it; the same
        # options are configured here so help, completion and the command reference show them.
        from cordon_scanner.mcp.server import Server as McpServer

        McpServer.configure(
            sub.add_parser(
                "mcp",
                help="serve Cordon to AI agents over the Model Context Protocol (stdio)",
            )
        )
        help_cmd = sub.add_parser("help", help="this screen, or the help for one command")
        help_cmd.add_argument(
            "topic", nargs="*", metavar="COMMAND", help="a command, or a command and its action"
        )

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
        from cordon_scanner.detect.supply import release_diff
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
                    named = getattr(args, "package_identity", None)
                    identity = (
                        previous_release.Identity(*named)
                        if named and named[0] not in ("npm", "pypi") and named[2]
                        else previous_release.PreviousRelease.identify(target)
                    )
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
    def _with_manifest_confusion(
        cls, args: argparse.Namespace, target: Path, result: ScanResult, config: Any
    ) -> ScanResult:
        """`--online` and a published npm tarball: does the registry describe this tarball?"""
        from dataclasses import replace as _replace

        from cordon_scanner.decide.policy import SuppressionMatcher
        from cordon_scanner.detect.supply.manifest_confusion import ManifestConfusion
        from cordon_scanner.intel.malware.feed import FeedClient

        offline = not args.online or args.offline or FeedClient.offline_requested()
        if offline or not target.is_file():
            return result
        added = list(SuppressionMatcher(config).apply(ManifestConfusion.check(target)))
        if not added:
            return result
        return _replace(
            result,
            findings=tuple(sorted((*result.findings, *added), key=lambda f: -f.severity.value)),
        )

    @classmethod
    def _with_secret_history(
        cls, args: argparse.Namespace, target: Path, result: ScanResult, config: Any
    ) -> ScanResult:
        """`--history` and `--verify-secrets`: findings from git history and from the issuers."""
        from dataclasses import replace as _replace

        if not getattr(args, "history", False) and not getattr(args, "verify_secrets", False):
            return result
        from cordon_scanner.decide.policy import SuppressionMatcher
        from cordon_scanner.detect.secrets.secret_history import (
            HistorySecretScan,
            SecretLiveness,
            SecretValues,
        )
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        root = target if target.is_dir() else target.parent
        added: list[Finding] = []
        history_blobs: dict[tuple[str, str], bytes] = {}
        if getattr(args, "history", False):
            scan = HistorySecretScan(root, config, RuleSet(RuleLoader.load_builtin()))
            added.extend(scan.run())
            history_blobs = scan.blob_contents
        if getattr(args, "verify_secrets", False):
            values = SecretValues(root, history_blobs)
            added.extend(SecretLiveness().verify([*result.findings, *added], values))
            history_blobs.clear()
        if not added:
            return result
        added = list(SuppressionMatcher(config).apply(added))
        findings = tuple(sorted((*result.findings, *added), key=lambda f: -f.severity.value))
        complete = result.complete and not any(f.degrades_coverage for f in added)
        return _replace(result, findings=findings, complete=complete)

    @classmethod
    def _scan_package(cls, args: argparse.Namespace) -> int:
        """`scan pkg:<type>/<name>@<version>`: fetch the published archive, verify it, scan it."""
        from cordon_scanner.foundation.errors import SourceError
        from cordon_scanner.intel.malware.feed import FeedClient
        from cordon_scanner.sources.package import PackageTarget, PackageTargetError

        try:
            package = PackageTarget.parse(str(args.target))
        except PackageTargetError as exc:
            raise ConfigError(
                str(exc), hint="Example: cordon-scanner scan pkg:npm/left-pad@1.3.0 --online"
            ) from exc
        if not args.online or args.offline or FeedClient.offline_requested():
            raise ConfigError(
                f"scanning {package.label} asks its registry for the archive, and this scan is offline",
                hint="Pass --online to fetch it. Nothing about your code is sent; only the package name and version.",
            )
        try:
            with package.fetched() as archive:
                print(
                    f"Fetched {package.label} as {archive.name}; digest verified against the registry.",
                    file=sys.stderr,
                )
                # The purl names the package exactly, so the release comparison need not re-identify
                # it from the archive -- which it can only do for npm and PyPI.
                identity = (package.ecosystem, package.name, package.version or "")
                return cls.cmd_scan(
                    argparse.Namespace(
                        **{**vars(args), "target": str(archive), "package_identity": identity}
                    )
                )
        except PackageTargetError as exc:
            raise SourceError(
                str(exc), hint="Check the name and version exist on the public registry."
            ) from exc

    @classmethod
    def cmd_scan(cls, args: argparse.Namespace) -> int:
        from cordon_scanner import Scanner
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.engine.registry import Registry
        from cordon_scanner.foundation.config.resolver import ConfigResolver
        from cordon_scanner.foundation.models import RedactionMode
        from cordon_scanner.report.base import ReportOptions
        from cordon_scanner.sources.package import PackageTarget

        if PackageTarget.is_package_url(str(args.target)):
            return cls._scan_package(args)
        if getattr(args, "verify_secrets", False) and (not args.online or args.offline):
            raise ConfigError(
                "--verify-secrets sends each found credential to its own issuer, and this scan is offline",
                hint="Add --online. Values go only to the issuer that minted them, never to Cordon.",
            )

        target = Path("/" if getattr(args, "host", False) and args.target == "." else args.target)
        if not target.exists():
            raise CordonError(
                f"target does not exist: {target}",
                hint="Pass a directory, file, archive path, or a package URL such as pkg:npm/name@1.0.0.",
            )
        if getattr(args, "host", False) and not target.is_dir():
            raise ConfigError(f"--host reads a filesystem root, and {target} is not a directory")

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
        from cordon_scanner.intel.malware.feed import FeedClient

        if args.offline or FeedClient.offline_requested():
            overrides["intel_feed"] = False
        if getattr(args, "reachability", False):
            overrides["reachability"] = True
        if getattr(args, "no_expand", False):
            overrides["expand_archives"] = False
        if getattr(args, "clamav", None):
            overrides["clamav"] = args.clamav
        if getattr(args, "keyrings", None):
            overrides["keyrings"] = tuple(args.keyrings)
        if rule_file := Renamed.rule_file(args, cls.PROGRAM):
            overrides["rule_file"] = rule_file
        if getattr(args, "registry_tokens", None):
            from cordon_scanner.intel.registries.private_registries import PrivateRegistries

            try:
                overrides["private_registries"] = tuple(
                    tuple(r) for r in PrivateRegistries.parse(args.registry_tokens)
                )
            except ValueError as exc:
                raise ConfigError(str(exc)) from exc
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

        if args.fail_on or args.fail_on_incomplete or getattr(args, "hardening", False):
            from dataclasses import replace as _replace

            policy = config.policy
            if getattr(args, "hardening", False):
                policy = _replace(policy, hardening=True)
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
            from cordon_scanner.detect.supply.advisory import AdvisoryDetector
            from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase

            database = AdvisoryDatabase.from_file(args.advisories)
            base = selected or Registry(allow_third_party=config.allow_plugins).detectors()
            selected = tuple([d for d in base if d.id != "advisory"] + [AdvisoryDetector(database)])

        # Validated before the scan, like the audit log below: an unknown channel is a
        # corrected command line, not a message that silently never arrives.
        channels: tuple[str, ...] = ()
        if getattr(args, "notify", None):
            from cordon_scanner.notify.notifier import Notifier

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

        if getattr(args, "host", False):
            result = Scanner(config, detectors=selected, progress=progress).scan_host(
                target, args.home
            )
        else:
            result = Scanner(config, detectors=selected, source=source, progress=progress).scan(
                target
            )
            result = cls._with_release_diff(args, target, result, config, selected)
            result = DependencyPayload.applied(args, target, result, config, selected)
            result = cls._with_manifest_confusion(args, target, result, config)
            result = cls._with_secret_history(args, target, result, config)
            result = ScanEnrichment.add_model_findings(args, target, result, config)

        if args.baseline:
            from dataclasses import replace as _replace

            from cordon_scanner.decide.policy import Baseline

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

        if getattr(args, "vex", None):
            from dataclasses import replace as _replace_vex

            from cordon_scanner.decide.vex import VexDocuments, VexError

            try:
                statements = VexDocuments.load(args.vex)
            except VexError as exc:
                raise ConfigError(f"--vex: {exc}") from exc
            ruled = VexDocuments.apply(result.findings, statements)
            count = sum(
                1 for f in ruled if f.suppressed is not None and f.suppressed.approved_by == "vex"
            )
            if count:
                print(
                    f"{cls.PROGRAM}: {count} vulnerability finding(s) marked suppressed by VEX "
                    f"statements; they remain in the report with the statement that ruled them out",
                    file=sys.stderr,
                )
            result = _replace_vex(result, findings=ruled)

        formats = args.format or ["text"]
        # The verdict first: it is a pure function of the result, and the text view prints what
        # fails the gate in full and the rest as one line (`ReportOptions.blocking`).
        verdict = PolicyGate.evaluate(result, config.policy)
        opts = ReportOptions(
            color=cls._use_color(args.no_color),
            verbose=args.verbose,
            blocking=frozenset(f.fingerprint for f in verdict.triggering),
            quiet=args.quiet,
        )
        cls._emit(result, formats, args.output, opts, quiet=args.quiet)

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
        from cordon_scanner.foundation.targets import TargetName

        key = TargetName.of(result)
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
        from cordon_scanner.intel.malware.feed import FeedClient

        try:
            credentials = auth.CloudAuth.current(args.cloud_url)
            bundle = policy.CloudPolicy.fetch(
                credentials, offline=bool(args.offline) or FeedClient.offline_requested()
            )
        except CloudError as exc:
            raise ConfigError(
                f"the organisation policy could not be applied: {exc}",
                hint=f"Run `{cls.PROGRAM} login`, or connect once so a current bundle is cached.",
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
        from cordon_scanner.foundation.config.parser import ConfigParser

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
            # A token for Sigstore's own audience, when the pipeline minted one (GitLab, CircleCI,
            # Buildkite); otherwise sigstore asks the CI for one itself (GitHub Actions).
            signer = (
                results.SignedResults.sigstore_signer(os.environ.get("SIGSTORE_ID_TOKEN") or None)
                if ambient is not None
                else None
            )
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
        except Exception as exc:  # noqa: BLE001
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
        from cordon_scanner.notify.notifier import Notifier

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
        from cordon_scanner.foundation.models import (
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

        from cordon_scanner.foundation.errors import SourceError
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
        from cordon_scanner.engine.registry import Registry

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
    def cmd_agent(cls, args: argparse.Namespace) -> int:
        import json

        from cordon_scanner.cloud import CloudError, device

        action = getattr(args, "agent_command", None)
        if action == "mcp-approve":
            return cls._mcp_approve(Path(args.target))
        if action not in ("inventory", "report"):
            print(f"{cls.PROGRAM}: agent needs inventory, report or mcp-approve", file=sys.stderr)
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
    def _mcp_approve(cls, root: Path) -> int:
        """List every remote MCP server's tools and record their fingerprints. A later `scan
        --online` reports any tool added or changed since (`SUSPECT.MCP.TOOLS_CHANGED.001`)."""
        from cordon_scanner.detect.agents.agents import MCP_PATHS, McpConfigs
        from cordon_scanner.foundation.files.globs import PathGlob
        from cordon_scanner.intel.store.live_mcp import LiveMcp, LiveMcpError, McpApprovals

        if not root.is_dir():
            raise CordonError(f"mcp-approve needs a repository directory: {root}")
        recorded: dict[str, dict[str, Any]] = {}
        failed = 0
        for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)[
            :200_000
        ]:
            relative = path.relative_to(root).as_posix()
            if not any(PathGlob.matches(relative, pattern) for pattern in MCP_PATHS):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for name, server in McpConfigs.mcp_servers(relative, text):
                url = LiveMcp.remote_url(server)
                if url is None or name in recorded:
                    continue
                try:
                    tools = LiveMcp.tools(url)
                except LiveMcpError as exc:
                    failed += 1
                    print(f"{cls.PROGRAM}: {name} ({url}) not read: {exc}", file=sys.stderr)
                    continue
                recorded[name] = McpApprovals.record(url, tools)
                print(f"{name}: {len(tools)} tool(s) recorded from {url}")
        if not recorded:
            print(
                f"{cls.PROGRAM}: no remote MCP server was read; nothing recorded", file=sys.stderr
            )
            return int(ExitCode.SCANNER_ERROR if failed else ExitCode.CLEAN)
        written = McpApprovals.write(root, recorded)
        print(f"wrote {written}: commit it, so a reviewer sees what was approved")
        return int(ExitCode.SCANNER_ERROR if failed else ExitCode.CLEAN)

    @classmethod
    def cmd_logout(cls, args: argparse.Namespace) -> int:
        from cordon_scanner.cloud import auth

        credentials = auth.CloudAuth.load()
        revoked = credentials is not None and auth.CloudAuth.revoke(credentials)
        if not auth.CloudAuth.forget():
            print("Not signed in.")
        elif revoked:
            print("Signed out, here and in Cordon Cloud.")
        else:
            # Said plainly rather than as a plain "Signed out.": a copy of the credential file
            # would still work, and the person signing out is the one who can end it.
            print("Signed out on this machine.")
            print(
                "cordon-scanner: Cordon Cloud could not be told, so this sign-in stays valid until it "
                "expires. End it in the console under Account, CLI sign-ins.",
                file=sys.stderr,
            )
        return int(ExitCode.CLEAN)

    @classmethod
    def cmd_whoami(cls, args: argparse.Namespace) -> int:
        import time

        from cordon_scanner.cloud import auth

        stored = auth.CloudAuth.load()
        if stored is None:
            print(f"Not signed in. Run `{cls.PROGRAM} login`.")
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
    def run(cls, argv: Sequence[str] | None = None) -> int:
        from cordon_scanner.cli.completion import CompletionCommand
        from cordon_scanner.cli.deps import DepsCommand
        from cordon_scanner.cli.incoming import IncomingCommand
        from cordon_scanner.cli.review import ReviewCommand
        from cordon_scanner.cli.suppressions import SuppressCommand
        from cordon_scanner.engine.netguard import NetworkGuard

        # Before anything can connect: with CORDON_PUBLIC_NETWORK_ONLY set, no name this process
        # resolves may lead inside the network (`core.netguard`).
        NetworkGuard.install_if_enabled()
        arguments = list(sys.argv[1:] if argv is None else argv)
        if arguments[:1] == ["mcp"]:
            from cordon_scanner.mcp import main as mcp_main

            return mcp_main(arguments[1:])

        parser = cls.build_parser()
        args = parser.parse_args(argv)

        if not args.command:
            parser.print_help()
            return int(ExitCode.CLEAN)

        group = GroupHelp.missing(args)
        if group is not None:
            GroupHelp.show(parser, group, sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        commands: dict[str, Callable[[argparse.Namespace], int]] = {
            "scan": cls.cmd_scan,
            "inventory": InventoryCommand.run,
            "rules": RulesCommand.run,
            "config": ConfigCommand.run,
            "guard": GuardCommand.run,
            "baseline": BaselineCommand.run,
            "bundle": BundleCommand.run,
            "report": ReportCommand.run,
            "advisories": AdvisoriesCommand.run,
            "intel": IntelCommand.run,
            "login": LoginCommand.run,
            "logout": cls.cmd_logout,
            "runner": RunnerCommand.run,
            "agent": cls.cmd_agent,
            "whoami": cls.cmd_whoami,
            "sbom": SbomCommand.run,
            "deps": DepsCommand.run,
            "review": ReviewCommand.run,
            "clone": IncomingCommand.run_clone,
            "pull": IncomingCommand.run_pull,
            "suppress": SuppressCommand.run,
            "help": functools.partial(HelpCommand.run, parser=parser),
            "completion": functools.partial(
                CompletionCommand.run, parser=parser, program=cls.PROGRAM
            ),
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
        except Exception as exc:  # noqa: BLE001
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
