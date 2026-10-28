"""`intel status`, `intel update` and `intel acquire`: the signed threat-intel feed, and the release
history a later offline scan compares a package with."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM


class IntelCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        intel = sub.add_parser(
            "intel", help="the signed threat-intel feed: how current it is, and refreshing it"
        ).add_subparsers(dest="intel_command")
        intel_status = intel.add_parser(
            "status", help="show the intel's source, serial and age without fetching anything"
        )
        intel_status.add_argument("--json", action="store_true", help="print as JSON")
        intel_update = intel.add_parser(
            "update", help="verify and apply the latest signed feed now"
        )
        intel_update.add_argument("--json", action="store_true", help="print as JSON")
        intel_acquire = intel.add_parser(
            "acquire",
            help=(
                "fetch what a later offline scan compares a published package with: the newest "
                "release at least 90 days older, hashed per file (network: registries only)"
            ),
        )
        intel_acquire.add_argument(
            "targets", nargs="+", metavar="ARCHIVE", help="published package archives"
        )
        intel_acquire.add_argument("--json", action="store_true", help="print as JSON")

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        """Report on, or refresh, the signed intel feed.

        `status` never touches the network. `update` is the operator asking for the feed, so it
        is refused under CORDON_OFFLINE rather than quietly doing nothing, and a verification
        failure exits non-zero so a scheduled job notices.
        """
        import json as _json

        from cordon_scanner.intel.malware import feed

        action = getattr(args, "intel_command", None)
        if action not in ("status", "update", "acquire"):
            print(f"{PROGRAM}: intel needs status, update or acquire", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)
        if action == "acquire":
            return cls.acquire(args)
        if action == "update" and feed.FeedClient.offline_requested():
            raise ConfigError("CORDON_OFFLINE is set, so the feed will not be fetched")

        current = feed.FeedClient.status(use_feed=action == "update", max_age=None)
        if args.json:
            print(_json.dumps(current.to_dict(), indent=2, sort_keys=True))
        else:
            age = (
                f"{current.age_seconds // 3600}h {current.age_seconds % 3600 // 60}m"
                if current.age_seconds is not None
                else "unknown"
            )
            print(
                f"source:  {current.source}"
                + (f" (serial {current.serial})" if current.serial else "")
            )
            print(f"age:     {age}" + (" -- STALE" if current.stale else ""))
            print(
                f"feed:    {'enabled' if current.feed_enabled else 'not available in this build'}"
            )
            if current.error:
                print(f"note:    {current.error}")
        # Updated means the intel is now current from either source: the signed feed, or -- in
        # every build until the feed's root is pinned -- OSV's changes since the database was
        # built (`intel/osv_delta`). Only the feed set `refreshed`, so an update that worked
        # exited 2 with nothing to say.
        updated = current.refreshed or current.osv_current
        if action == "update" and not updated:
            if not args.json and not current.error:
                print("note:    no source could refresh the intel", file=sys.stderr)
            return int(ExitCode.SCANNER_ERROR)
        return int(ExitCode.CLEAN)

    @classmethod
    def acquire(cls, args: argparse.Namespace) -> int:
        """`intel acquire`: for each published archive, store its established predecessor.

        The one step of release comparison that uses the network, run when the operator asks,
        and rerun whenever they want it current; the scan that follows reads only the store.
        Refused under CORDON_OFFLINE. A package whose registry cannot answer is reported and
        the rest are still acquired.
        """
        import json as _json

        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.engine.pipeline.history import History
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.intel.malware import feed
        from cordon_scanner.intel.registries.registry_client import RegistryError
        from cordon_scanner.intel.registries.registry_record import RegistryRecord
        from cordon_scanner.intel.registries.release_history import ReleaseHistory
        from cordon_scanner.sources.archive import ArchiveReader

        if feed.FeedClient.offline_requested():
            raise ConfigError("CORDON_OFFLINE is set, so release history will not be fetched")
        results: list[dict[str, object]] = []
        failed = False
        for target in args.targets:
            path = Path(target)
            try:
                data = path.read_bytes()
            except OSError as exc:
                results.append({"target": target, "error": str(exc)})
                failed = True
                continue
            units = [
                FileUnit(content=FileContent.from_bytes(member, payload))
                for member, payload in ArchiveReader.walk_archive(data, path=path.name)
            ]
            distribution = History.history_distribution(units)
            identity = History.history_identity(units, distribution) if distribution else None
            if identity is not None and identity[0] in RegistryRecord.ECOSYSTEMS_READ:
                # The registry's record of this release, for the second review's publisher facts.
                try:
                    RegistryRecord.acquire(*identity)
                except RegistryError as exc:
                    results.append(
                        {"target": target, "release": "@".join(identity[1:]), "error": str(exc)}
                    )
                    failed = True
            if identity is None or identity[0] not in ReleaseHistory.ECOSYSTEMS:
                results.append({"target": target, "skipped": "not a release this can compare"})
                continue
            try:
                baseline = ReleaseHistory.acquire(
                    *identity,
                    current_dependencies=tuple(
                        sorted(ReleaseHistory.declared_dependencies(units, distribution))
                    ),
                )
            except RegistryError as exc:
                results.append(
                    {"target": target, "release": "@".join(identity[1:]), "error": str(exc)}
                )
                failed = True
                continue
            results.append(
                {
                    "target": target,
                    "release": f"{identity[1]}@{identity[2]}",
                    "baseline": baseline.baseline_version,
                    "baseline_published": baseline.baseline_published,
                    "files": len(baseline.files),
                }
            )
        if args.json:
            print(_json.dumps(results, indent=2, sort_keys=True))
        else:
            cls._print_acquired(results)
        return int(ExitCode.SCANNER_ERROR if failed else ExitCode.CLEAN)

    @staticmethod
    def _print_acquired(results: list[dict[str, object]]) -> None:
        for row in results:
            if "error" in row:
                print(f"{row['target']}: could not acquire: {row['error']}")
            elif "skipped" in row:
                print(f"{row['target']}: skipped, {row['skipped']}")
            elif row["baseline"]:
                print(
                    f"{row['release']}: compared with {row['baseline']} "
                    f"({str(row['baseline_published'])[:10]}, {row['files']} files)"
                )
            else:
                print(f"{row['release']}: no release at least 90 days older")


__all__ = ["IntelCommand"]
