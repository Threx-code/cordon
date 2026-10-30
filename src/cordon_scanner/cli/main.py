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
from cordon_scanner.cli.commands.notify import NotifyCommand
from cordon_scanner.cli.commands.report import ReportCommand
from cordon_scanner.cli.commands.rules import RulesCommand
from cordon_scanner.cli.commands.runner import RunnerCommand
from cordon_scanner.cli.commands.sbom import SbomCommand
from cordon_scanner.cli.commands.scan.command import ScanCommand
from cordon_scanner.cli.help import GroupHelp, HelpCommand
from cordon_scanner.cli.parser import CommandParser
from cordon_scanner.foundation.errors import CordonError, ExitCode
from cordon_scanner.version import PROGRAM as PROGRAM_NAME

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class CommandLine:
    """The command line's dispatch: the handler for each command, and the exit codes.

    Each command is one class in `cli/commands/`, holding its arguments and the code that
    reads them, because the two halves have to agree and nothing else checks that they
    do. A flag defined and read nowhere is dead; a flag read and defined nowhere is a
    crash on the invocation that uses it. That second one shipped: the guard wrote hooks
    calling `cordon scan --staged` while no such flag existed, so every installed hook
    failed and blocked every commit.

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
    def run(cls, argv: Sequence[str] | None = None) -> int:
        from cordon_scanner.cli.commands.completion import CompletionCommand
        from cordon_scanner.cli.commands.deps import DepsCommand
        from cordon_scanner.cli.commands.incoming import IncomingCommand
        from cordon_scanner.cli.commands.review import ReviewCommand
        from cordon_scanner.cli.commands.suppressions import SuppressCommand
        from cordon_scanner.engine.netguard import NetworkGuard

        # Before anything can connect: with CORDON_PUBLIC_NETWORK_ONLY set, no name this process
        # resolves may lead inside the network (`core.netguard`).
        NetworkGuard.install_if_enabled()
        arguments = list(sys.argv[1:] if argv is None else argv)
        for front in CommandParser.front_ends():
            if arguments[:1] == [front.NAME]:
                code: int = front.main(arguments[1:])
                return code

        parser = CommandParser.build()
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
            "notify": NotifyCommand.run,
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
