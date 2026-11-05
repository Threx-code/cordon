"""`notify test`: send each notification channel a message marked as a test, before a real gate
failure is the first one anybody sees."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM


class NotifyCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        notify = sub.add_parser(
            "notify", help="notification channels: send a test message to each"
        ).add_subparsers(dest="notify_command")
        test = notify.add_parser(
            "test",
            help=(
                "send each channel a message marked as a test, print each outcome, and exit "
                "non-zero if any did not arrive"
            ),
        )
        test.add_argument(
            "channels",
            nargs="?",
            default=None,
            help=(
                "webhook, slack, teams (comma-separated); default: notify.channels in the "
                "configuration. URLs come from CORDON_NOTIFY_WEBHOOK, CORDON_NOTIFY_SLACK and "
                "CORDON_NOTIFY_TEAMS"
            ),
        )
        test.add_argument("--config", metavar="PATH", help="the configuration file to read")
        test.add_argument("--policy", metavar="PATH", help="the organisation policy to read")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        from cordon_scanner.foundation.config.resolver import ConfigResolver
        from cordon_scanner.foundation.results import Repository, ScanResult
        from cordon_scanner.notify.notifier import Notifier

        if getattr(args, "notify_command", None) != "test":
            print(f"usage: {PROGRAM} notify test [CHANNELS]", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        config = ConfigResolver.resolve(root=".", config_path=args.config, policy_path=args.policy)
        named = args.channels or ",".join(config.notify_channels)
        if not named:
            raise ConfigError(
                "no channel to test",
                hint="Name one (notify test slack) or set notify.channels in the configuration.",
            )
        try:
            channels = Notifier.parse_channels(named)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        result = ScanResult(findings=(), repository=Repository(root=str(Path.cwd())))
        deliveries = Notifier().send(
            channels,
            result,
            reason="a test message from cordon-scanner notify test",
            exit_code=int(ExitCode.CLEAN),
            gate="passed",
            test=True,
        )
        for delivery in deliveries:
            if delivery.ok:
                print(f"{delivery.channel}: delivered ({delivery.attempts} attempt(s))")
            else:
                print(f"{delivery.channel}: not delivered: {delivery.error}")
        return int(ExitCode.CLEAN) if all(d.ok for d in deliveries) else int(ExitCode.FINDINGS)


__all__ = ["NotifyCommand"]
