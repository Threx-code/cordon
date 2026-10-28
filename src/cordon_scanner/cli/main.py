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
from typing import TYPE_CHECKING

from cordon_scanner.cli.commands.account.login import LoginCommand
from cordon_scanner.cli.commands.account.logout import LogoutCommand
from cordon_scanner.cli.commands.account.whoami import WhoamiCommand
from cordon_scanner.cli.commands.advisories import AdvisoriesCommand
from cordon_scanner.cli.commands.agent import AgentCommand
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
from cordon_scanner.cli.commands.scan.command import ScanCommand
from cordon_scanner.cli.dependency_payload import DependencyPayload
from cordon_scanner.cli.help import ColourArgumentParser, GroupHelp, HelpCommand
from cordon_scanner.foundation.errors import CordonError, ExitCode
from cordon_scanner.version import PROGRAM as PROGRAM_NAME
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


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
        AgentCommand.add_parser(sub)
        LogoutCommand.add_parser(sub)
        WhoamiCommand.add_parser(sub)

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
            "scan": ScanCommand.run,
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
            "logout": LogoutCommand.run,
            "runner": RunnerCommand.run,
            "agent": AgentCommand.run,
            "whoami": WhoamiCommand.run,
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
