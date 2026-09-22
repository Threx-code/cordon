#!/usr/bin/env python3
"""Refresh the shipped OSV-derived advisory database.

A MAINTENANCE script, same arrangement as `refresh_package_intel.py`: it is
never imported by the scanner and never runs during a scan or a package
build. It runs deliberately, by a maintainer or on a schedule
(`.github/workflows/refresh-advisories.yml`), and its output is a reviewed
artefact that ships with the release.

    python3 scripts/build_advisory_db.py                # every ecosystem
    python3 scripts/build_advisory_db.py --only npm pypi
    python3 scripts/build_advisory_db.py --check         # fetch, report, write nothing

All-or-nothing by ecosystem: a source that fails to download is reported as a
failure, not silently skipped, and does not overwrite that ecosystem's
existing file. See `intel/osv_import.py` for the conversion logic this calls
into -- that module is the reusable half, shared with `cordon-scanner
advisories sync`; this script is the thin CI-facing wrapper around it, in the
same division `intel/osv_import.py`'s own module docstring describes.

**What gets bundled with the release is filtered; what a sync fetches is
not.** `osv_import.sync_ecosystem` returns everything OSV reports, on
purpose -- it is a pure "what does the source say" function, and the
filtering policy belongs at the one call site that decides what ships in a
wheel, not inside the library everything else, including `cordon-scanner
advisories sync`, also calls.

The policy: bundle malicious-package entries and high/critical
vulnerabilities, leave medium/low out. Not a size hack with a cover story --
it is what `policy.fail_on` already defaults to gating a build on
(`README.md`'s own example is `fail_on: [high, {category: malicious}]`), so
the records left out of the wheel are, by the project's own stated default,
the ones least likely to fail a build anyway. Measured at 93,801 records /
84.7 MB unfiltered versus 59,972 / 27 MB filtered -- a 68% reduction for a
category of finding the default policy would not act on. The full set is one
`cordon-scanner advisories sync` away, same as today; `--full` here bypasses
the filter for anyone building their own distribution who wants everything
bundled instead.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cordon_scanner.intel import osv_import  # noqa: E402
from cordon_scanner.intel.advisories import Advisory  # noqa: E402

_HIGH_VALUE_SEVERITIES = frozenset({"high", "critical"})


def _is_high_value(advisory: Advisory) -> bool:
    """Malicious, or a high/critical vulnerability. See the module docstring
    for why this is the bundled-with-the-release cut, not a smaller one."""
    return advisory.malicious or advisory.severity.lower() in _HIGH_VALUE_SEVERITIES


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--only",
        nargs="+",
        choices=sorted(osv_import.ECOSYSTEM_OSV_NAMES),
        metavar="ECOSYSTEM",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fetch and report what a refresh would produce, write nothing",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "bundle every severity instead of the high/critical + malicious "
            "default -- see the module docstring for why the default is filtered"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "src" / "cordon_scanner" / "intel" / "data"),
        metavar="DIR",
        help="where advisories-<ecosystem>.json and advisories-meta.json land",
    )
    args = parser.parse_args()

    ecosystems = tuple(sorted(args.only or osv_import.ECOSYSTEM_OSV_NAMES))
    output_dir = Path(args.output)

    per_ecosystem: dict[str, tuple[Advisory, ...]] = {}
    failed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="cordon-osv-") as tmp:
        tmp_dir = Path(tmp)
        for ecosystem in ecosystems:
            print(f"{ecosystem}:")
            try:
                records = osv_import.sync_ecosystem(ecosystem, tmp_dir=tmp_dir)
            except osv_import.OsvImportError as exc:
                print(f"  FAILED: {exc}", file=sys.stderr)
                failed.append(ecosystem)
                continue
            malicious = sum(1 for a in records if a.malicious)
            ranged = sum(1 for a in records if a.is_range)
            print(
                f"  {len(records):,} advisor(y/ies): {malicious} malicious, "
                f"{len(records) - malicious} vulnerable ({ranged} range-based)"
            )
            if args.full:
                kept = records
            else:
                kept = tuple(a for a in records if _is_high_value(a))
                print(
                    f"  kept {len(kept):,} of {len(records):,} "
                    f"(high/critical + malicious; --full bundles everything)"
                )
            per_ecosystem[ecosystem] = kept

    if failed:
        print(f"\nfailed: {', '.join(failed)}", file=sys.stderr)
        print(
            "nothing was written for a partial run; re-run once every source answers.",
            file=sys.stderr,
        )
        return 1

    if args.check:
        return 0

    total = sum(len(v) for v in per_ecosystem.values())
    from datetime import UTC, datetime

    from cordon_scanner.intel.advisories import DatabaseMeta

    result = osv_import.SyncResult(
        per_ecosystem=per_ecosystem,
        meta=DatabaseMeta(
            built_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            sources=tuple(f"osv:{e}" for e in ecosystems),
            record_count=total,
            filtered=not args.full,
        ),
    )
    osv_import.write_output(result, output_dir)
    print(f"\nwrote {total:,} advisories across {len(per_ecosystem)} ecosystem(s) to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
