"""`login`: sign in to Cordon Cloud through the organisation's SSO, by the device flow."""

from __future__ import annotations

import argparse
import sys

from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.version import PROGRAM


class LoginCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        login = sub.add_parser(
            "login", help="sign in to Cordon Cloud through your organisation's SSO (device flow)"
        )
        login.add_argument("--url", default=None, help="Cordon Cloud API base")

    @staticmethod
    def run(args: argparse.Namespace) -> int:
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
            print(f"{PROGRAM}: {exc}", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        path = auth.CloudAuth.save(credentials)
        keys = len(credentials.policy_keys)
        print(
            f"Signed in to {credentials.org or 'Cordon Cloud'} as {credentials.subject or 'this device'}. "
            f"{keys} policy key(s) pinned. Stored in {path} (mode 0600)."
        )
        return int(ExitCode.CLEAN)


__all__ = ["LoginCommand"]
