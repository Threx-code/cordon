"""The command line's parser: one subcommand per command, each defined by its own class in
`cli/commands/`, added in the order the help lists them."""

from __future__ import annotations

import argparse
import sys
from typing import Any, ClassVar

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
from cordon_scanner.cli.commands.notify import NotifyCommand
from cordon_scanner.cli.commands.report import ReportCommand
from cordon_scanner.cli.commands.rules import RulesCommand
from cordon_scanner.cli.commands.runner import RunnerCommand
from cordon_scanner.cli.commands.sbom import SbomCommand
from cordon_scanner.cli.commands.scan.command import ScanCommand
from cordon_scanner.cli.help import ColourArgumentParser
from cordon_scanner.version import PROGRAM, __version__


class VersionAction(argparse.Action):
    """`--version`: the version, and which anchor matcher a rule file runs with (worked out only
    when asked, since it hashes the native binary)."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: object,
        values: object,
        option: str | None = None,
    ) -> None:
        from cordon_scanner.detect.binary.rule_engine.automaton import Automaton

        native = "yes" if Automaton.NATIVE else "no"
        # On stdout, as argparse's own version action prints, so `--version | head -1` still works.
        sys.stdout.write(f"{PROGRAM} {__version__}\nnative: {native}, {Automaton.status()}\n")
        parser.exit()


class CommandParser:
    #: Front ends that drive these commands, found by entry point: `cordon-scanner mcp`.
    FRONT_ENDS: ClassVar[str] = "cordon_scanner.commands"

    @staticmethod
    def front_ends() -> list[Any]:
        """The front ends this distribution ships, by name. Another package's entry point in the
        group is not loaded: the command line is not extended by whatever is installed beside it."""
        from importlib.metadata import entry_points

        found = [
            e
            for e in entry_points(group=CommandParser.FRONT_ENDS)
            if e.dist is not None and e.dist.name == "cordon-scanner"
        ]
        return [e.load() for e in sorted(found, key=lambda e: (e.name, e.value))]

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

    @classmethod
    def build(cls) -> ColourArgumentParser:
        parser = ColourArgumentParser(
            prog=PROGRAM,
            description="Language-agnostic software supply-chain security scanner.",
            epilog=cls.EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            "--version", action=VersionAction, nargs=0, help="show the version and exit"
        )

        sub = parser.add_subparsers(dest="command", metavar="<command>")

        ScanCommand.add_parser(sub, cls.EPILOG)

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
        NotifyCommand.add_parser(sub)
        SbomCommand.add_parser(sub)

        from cordon_scanner.cli.commands.completion import CompletionCommand
        from cordon_scanner.cli.commands.deps import DepsCommand
        from cordon_scanner.cli.commands.suppressions import SuppressCommand

        DepsCommand.add_parser(sub)
        from cordon_scanner.cli.commands.incoming import IncomingCommand
        from cordon_scanner.cli.commands.review import ReviewCommand

        IncomingCommand.add_parser(sub)

        ReviewCommand.add_parser(sub)
        SuppressCommand.add_parser(sub)
        CompletionCommand.add_parser(sub)
        # `run` hands a front end (`mcp`) the rest of the command line before this parser sees it;
        # its options are configured here so help, completion and the command reference show them.
        for front in CommandParser.front_ends():
            front.configure(sub.add_parser(front.NAME, help=front.HELP))
        help_cmd = sub.add_parser("help", help="this screen, or the help for one command")
        help_cmd.add_argument(
            "topic", nargs="*", metavar="COMMAND", help="a command, or a command and its action"
        )

        return parser


__all__ = ["CommandParser"]
