"""`whoami`: the Cordon Cloud sign-in in use, and how long its token has left."""

from __future__ import annotations

import argparse

from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.version import PROGRAM


class WhoamiCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        sub.add_parser("whoami", help="show the Cordon Cloud sign-in in use")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
        import time

        from cordon_scanner.cloud import auth

        stored = auth.CloudAuth.load()
        if stored is None:
            print(f"Not signed in. Run `{PROGRAM} login`.")
            return int(ExitCode.CONFIG_ERROR)
        remaining = int(stored.expires_at - time.time())
        state = (
            f"token valid for {remaining // 60} min"
            if remaining > 0
            else "token expired, renews on next use"
        )
        print(f"{stored.subject or 'this device'} at {stored.org} ({stored.url}); {state}")
        return int(ExitCode.CLEAN)


__all__ = ["WhoamiCommand"]
