"""`advisories sync`: refresh the local vulnerability and malicious-package data."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cordon_scanner.foundation.errors import ConfigError, ExitCode
from cordon_scanner.version import PROGRAM


class AdvisoriesCommand:
    @staticmethod
    def add_parser(sub: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
        advisories = sub.add_parser(
            "advisories",
            help="manage the vulnerability/malicious-package advisory database",
        ).add_subparsers(dest="advisories_command")
        advisories_sync = advisories.add_parser(
            "sync", help="refresh the local advisory data from OSV's bulk export"
        )
        advisories_sync.add_argument(
            "--only",
            nargs="+",
            metavar="ECOSYSTEM",
            default=None,
            help="sync only these ecosystems, or nvd for NVD's data (default: all, and NVD)",
        )
        advisories_sync.add_argument(
            "--os",
            nargs="+",
            metavar="FAMILY",
            default=None,
            help=(
                "also sync these distributions' advisories (debian, ubuntu, alpine, wolfi, "
                "chainguard, rocky, almalinux, redhat, suse, opensuse) so image scans match "
                "operating-system packages offline"
            ),
        )
        advisories_sync.add_argument(
            "--bundle",
            metavar="URL",
            default=None,
            help=(
                "install a signed advisory bundle from URL instead of building "
                "from OSV; the bundle's Ed25519 signature is verified against the "
                "pinned release key before anything is unpacked"
            ),
        )

    @classmethod
    def run(cls, args: argparse.Namespace) -> int:
        """Refresh the local vulnerability/malicious-package data from OSV.

        Writes to a user cache directory, never into the installed package --
        see `intel/advisories.user_sync_dir`. This is the on-demand
        counterpart to `.github/workflows/refresh-advisories.yml`'s scheduled
        refresh: for an operator who wants current data now rather than
        waiting for the next release to pick up the last scheduled run.
        """
        action = getattr(args, "advisories_command", None)
        if action is None:
            print(f"{PROGRAM}: advisories needs sync", file=sys.stderr)
            return int(ExitCode.CONFIG_ERROR)

        if action != "sync":
            raise ConfigError(f"unknown advisories action: {action}")

        import tempfile

        from cordon_scanner.intel.advisories import osv_import
        from cordon_scanner.intel.advisories.advisories import AdvisoryFiles

        # A signed bundle: fetch and verify a prebuilt database rather than
        # building one from OSV. The two share the same destination and the same
        # per-file digest manifest, so a later scan cannot tell which produced
        # the data -- only that it verified.
        if getattr(args, "bundle", None):
            from cordon_scanner.intel.store import dbsync

            destination = AdvisoryFiles.user_sync_dir()
            try:
                dbsync.AdvisoryBundle.sync_from_url(args.bundle, destination)
            except dbsync.BundleError as exc:
                raise ConfigError(f"advisories sync: {exc}") from exc
            print(f"installed a verified advisory bundle into {destination}")
            return int(ExitCode.CLEAN)

        families = getattr(args, "os", None)
        if families:
            cls._sync_families(families)
            if args.only is None:
                return int(ExitCode.CLEAN)

        # NVD (`intel/nvd`): with everything, or by name.
        with_nvd = args.only is None or "nvd" in args.only
        requested = [e for e in (args.only or sorted(osv_import.ECOSYSTEM_OSV_NAMES)) if e != "nvd"]
        unknown = [e for e in requested if e not in osv_import.ECOSYSTEM_OSV_NAMES]
        if unknown:
            raise ConfigError(
                f"unknown ecosystem(s) for --only: {', '.join(unknown)}",
                hint=f"choose from: {', '.join(sorted(osv_import.ECOSYSTEM_OSV_NAMES))}",
            )
        ecosystems = tuple(sorted(requested))
        if not ecosystems:
            return cls._sync_nvd(AdvisoryFiles.user_sync_dir())

        print(f"syncing {len(ecosystems)} ecosystem(s) from OSV...")
        with tempfile.TemporaryDirectory(prefix="cordon-osv-") as tmp:
            try:
                result = osv_import.OsvImport.sync_all(ecosystems, tmp_dir=Path(tmp))
            except osv_import.OsvImportError as exc:
                raise ConfigError(f"advisories sync: {exc}") from exc

        destination = AdvisoryFiles.user_sync_dir()
        osv_import.OsvImport.write_output(result, destination)
        for ecosystem in ecosystems:
            count = len(result.per_ecosystem.get(ecosystem, ()))
            print(f"  {ecosystem}: {count:,} advisor(y/ies)")
        print(
            f"synced {result.meta.record_count:,} advisories to {destination}\n"
            f"future scans on this machine will prefer this over the bundled snapshot "
            f"until the next release ships something newer."
        )
        if with_nvd:
            return cls._sync_nvd(destination)
        return int(ExitCode.CLEAN)

    @staticmethod
    def _sync_families(families: list[str]) -> None:
        """`--os`: each named distribution's advisories, for image scans."""
        import tempfile

        from cordon_scanner.images.distrodb import FAMILIES, DistroDatabase
        from cordon_scanner.intel.advisories import osv_import

        unknown_families = [f for f in families if f not in FAMILIES]
        if unknown_families:
            raise ConfigError(
                f"unknown distribution(s) for --os: {', '.join(unknown_families)}",
                hint=f"choose from: {', '.join(FAMILIES)}",
            )
        with tempfile.TemporaryDirectory(prefix="cordon-osv-os-") as tmp:
            for family in families:
                try:
                    count = DistroDatabase.sync(family, tmp_dir=Path(tmp))
                except osv_import.OsvImportError as exc:
                    raise ConfigError(f"advisories sync --os {family}: {exc}") from exc
                print(f"  {family}: {count:,} package advisor(y/ies)")
        print(f"distribution advisories are in {DistroDatabase.directory()}")

    @classmethod
    def _sync_nvd(cls, destination: Path) -> int:
        """Every NVD record, unfiltered, from NVD's own feeds, each checked against its published
        SHA-256 (`intel/nvd_import`); and, for a CVE NVD gives no range, the ranges its CVE List
        record states (`intel/cve_list`)."""
        from cordon_scanner.intel.advisories import nvd_import
        from cordon_scanner.intel.advisories.nvd import NvdData

        print("syncing NVD's feeds...")
        try:
            built = nvd_import.NvdImport.build(
                nvd_import.NvdImport.years(),
                lambda identifier, rating: True,
                cve_list=nvd_import.NvdImport.cve_list_records(),
            )
        except nvd_import.NvdImportError as exc:
            raise ConfigError(f"advisories sync: NVD: {exc}") from exc
        nvd_import.NvdImport.write(destination, built, filtered=False)
        NvdData.reset()
        print(
            f"synced {len(built.text):,} NVD records across {len(built.products):,} products "
            f"to {destination}"
        )
        return int(ExitCode.CLEAN)


__all__ = ["AdvisoriesCommand"]
