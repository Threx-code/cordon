"""`logout`: forget the stored Cordon Cloud sign-in, and end it in Cordon Cloud when it can be told."""

from __future__ import annotations

import argparse
import sys

from cordon_scanner.foundation.errors import ExitCode


class LogoutCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        sub.add_parser("logout", help="forget the stored Cordon Cloud sign-in")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
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


__all__ = ["LogoutCommand"]
