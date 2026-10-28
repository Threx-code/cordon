"""The command line's parser: one subcommand per command, each defined by its own class in
`cli/commands/`, added in the order the help lists them."""

from __future__ import annotations

import argparse

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
from cordon_scanner.cli.help import ColourArgumentParser
from cordon_scanner.version import PROGRAM, __version__


class CommandParser:
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
        parser.add_argument("--version", action="version", version=f"{PROGRAM} {__version__}")

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
        SbomCommand.add_parser(sub)

        from cordon_scanner.cli.commands.deps import DepsCommand
        from cordon_scanner.cli.completion import CompletionCommand
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


__all__ = ["CommandParser"]
