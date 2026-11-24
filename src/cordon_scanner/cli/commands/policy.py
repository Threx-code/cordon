"""`policy pull`: fetch the tenant's signed policy bundle from the store and keep it only if it verifies offline.

The bundle is checked against the tenant's pinned root key and the delegation that root signed, never against anything the
server says about itself. A bundle that is expired, signed by a key the root did not delegate, or not the successor of the one
held is refused by name and the bundle already held stays as it was.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.foundation.network.downloads import Download
from cordon_scanner.foundation.network.redirects import NoRedirects
from cordon_scanner.version import PROGRAM

MAX_BYTES = 8 << 20
TIMEOUT_SECONDS = 15.0


class PolicyCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        policy = sub.add_parser("policy", help="the tenant's signed policy bundle").add_subparsers(
            dest="policy_command"
        )
        pull = policy.add_parser(
            "pull", help="fetch the policy bundle and keep it if it verifies offline"
        )
        pull.add_argument("--url", required=True, help="the bundle store's https address")
        pull.add_argument(
            "--root",
            required=True,
            metavar="HEX",
            help="the tenant's root public key, 64 hex characters",
        )
        pull.add_argument(
            "--delegation",
            required=True,
            metavar="FILE",
            help="the delegation the root signed (JSON)",
        )
        pull.add_argument("--tenant", required=True, help="the tenant the bundle is for")
        pull.add_argument(
            "--store", metavar="DIR", help="where the bundle is kept (default: the device store)"
        )

    @staticmethod
    def fetch(url: str, headers: dict[str, str]) -> tuple[int, Mapping[str, str], bytes]:
        """One GET over https, no redirects, a bounded body; the status, the answer's headers and the body."""
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ConfigError("the bundle store must be an https address")
        request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 - https checked above
        opener = urllib.request.build_opener(NoRedirects)
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                return (
                    int(response.status),
                    dict(response.headers),
                    Download.read(response, MAX_BYTES),
                )
        except urllib.error.HTTPError as exc:
            return int(exc.code), dict(exc.headers), b""

    @classmethod
    def run(
        cls, args: argparse.Namespace, fetch: object = None, now: datetime | None = None
    ) -> int:
        from cordon_scanner.cloud.agent.collection_status import STORE_FOLDER
        from cordon_scanner.cloud.auth import CloudAuth
        from cordon_scanner.cloud.bundle_chain import BundleError, BundleRefused
        from cordon_scanner.cloud.bundle_puller import BundlePuller
        from cordon_scanner.cloud.local_runtime import LocalRuntime
        from cordon_scanner.cloud.local_store import LocalStore
        from cordon_scanner.decide.decision.compiler import PolicyCompiler
        from cordon_scanner.decide.decision.policy_source import PolicySource

        if getattr(args, "policy_command", None) != "pull":
            print(f"{PROGRAM}: policy needs pull", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        try:
            root = bytes.fromhex(args.root)
            delegation = json.loads(Path(args.delegation).read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise ConfigError(f"the root key or the delegation could not be read: {exc}") from exc
        if len(root) != 32:
            raise ConfigError("the root key is 32 bytes (64 hex characters)")
        store = LocalStore(
            Path(args.store) if args.store else CloudAuth.config_dir() / STORE_FOLDER
        )
        strict = PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "cordon/strict-baseline",
                    "version": 1,
                    "scope": [args.tenant],
                    "rules": [],
                    "defaults": {"default": "block", "on_incomplete": {"*": "block"}},
                }
            )
        )
        runtime = LocalRuntime(
            root_public=root,
            delegation=delegation,
            tenant=args.tenant,
            baseline=strict,
            store=store,
        )
        runtime.resume(now or datetime.now(UTC))
        puller = BundlePuller(args.url, fetch or cls.fetch, store)  # type: ignore[arg-type]
        try:
            state = puller.pull(runtime, now or datetime.now(UTC))
        except BundleRefused as exc:
            print(f"{PROGRAM}: bundle refused ({exc.name}): {exc}; the bundle held is kept")
            return int(ExitCode.CONFIG_ERROR)
        except BundleError as exc:
            print(f"{PROGRAM}: bundle not taken: {exc}; the bundle held is kept")
            return int(ExitCode.CONFIG_ERROR)
        print(f"policy bundle: {state}")
        return int(ExitCode.CLEAN) if state != "unreachable" else int(ExitCode.SCANNER_ERROR)
