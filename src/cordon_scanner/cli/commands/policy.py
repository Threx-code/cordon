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
        pull.add_argument(
            "--replace-root",
            action="store_true",
            help="trust this root key in place of the one the store first accepted",
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
        from cordon_scanner.cloud.agent.device_runtime import DeviceRuntime
        from cordon_scanner.cloud.auth import CloudAuth
        from cordon_scanner.cloud.bundle_chain import BundleError, BundleRefused
        from cordon_scanner.cloud.bundle_puller import BundlePuller
        from cordon_scanner.cloud.local_runtime import LocalRuntime
        from cordon_scanner.cloud.local_store import LocalStore

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
        pinned = store.blob("pin", "root")
        if pinned is not None and pinned.data != root and not args.replace_root:
            print(
                f"{PROGRAM}: this store trusts another root key; pass --replace-root to change it",
                file=sys.stderr,
            )
            return int(ExitCode.CONFIG_ERROR)
        runtime = LocalRuntime(
            root_public=root,
            delegation=delegation,
            tenant=args.tenant,
            baseline=DeviceRuntime.baseline(args.tenant),
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
        if state in ("new", "unchanged"):
            issued = (now or datetime.now(UTC)).isoformat()
            store.put_blob("pin", "root", root, issued)
            store.put_blob(
                "pin", "delegation", json.dumps(delegation, sort_keys=True).encode(), issued
            )
            store.put_blob("pin", "tenant", args.tenant.encode("utf-8"), issued)
        print(f"policy bundle: {state}")
        return int(ExitCode.CLEAN) if state != "unreachable" else int(ExitCode.SCANNER_ERROR)
