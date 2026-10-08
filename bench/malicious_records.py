"""Every known-malicious record Cordon ships, checked end to end.

For each malicious record in the bundled advisory data -- OSV's malicious-packages set, 249,646
records at the time of writing -- a project is written that depends on exactly that release, in
the ecosystem's own lockfile (the same writers the universal conformance tests use), and scanned
offline. The record must come back `malicious`: a dependency record whose malware status says so,
or, for an editor extension, its known-malicious finding. Every record named a version is checked
at each version it names; a record covering every version (`introduced: 0`) at an ordinary release.

Written as batches of up to 2,000 distinct names, one project each, scanned across every core.
The result -- per ecosystem, and each miss with its reason -- goes to
bench/results/malicious-records.json. Run inside Docker only, from the package directory:

    python bench/malicious_records.py
"""

from __future__ import annotations

import gzip
import json
import multiprocessing
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import ClassVar

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
DATA = PACKAGE / "src/cordon_scanner/intel/data"
RESULT = PACKAGE / "bench/results/malicious-records.json"
BATCH = 2000
PLACEHOLDER = re.compile(r"^\d+\.\d+\.\d+-security$")


class Records:
    """The malicious records, as (ecosystem, name, version, identifier) checks."""

    #: An ordinary release for a record that covers every version.
    ANY_VERSION: ClassVar[dict[str, str]] = {"gomod": "v1.0.0", "maven": "1.0.0", "nuget": "1.0.0"}

    @staticmethod
    def load(
        placeholder_only: list[tuple[str, str, str]] | None = None,
    ) -> list[tuple[str, str, str, str]]:
        """The checks; records whose only listed version is npm's placeholder go to `placeholder_only`."""
        placeholder_only = placeholder_only if placeholder_only is not None else []
        checks: list[tuple[str, str, str, str]] = []
        for path in sorted(DATA.glob("advisories-*.json.gz")):
            ecosystem = path.name.removeprefix("advisories-").removesuffix(".json.gz")
            with gzip.open(path) as handle:
                records = json.load(handle)
            for record in records:
                if not isinstance(record, dict) or not record.get("malicious"):
                    continue
                listed = [str(v) for v in record.get("versions") or [] if v]
                # npm's takedown placeholder (`0.0.1-security`) is the empty package npm publishes
                # in a malicious one's place; Cordon does not call it malicious, by design.
                versions = [v for v in listed if not (ecosystem == "npm" and PLACEHOLDER.match(v))]
                if listed and not versions:
                    placeholder_only.append(
                        (ecosystem, str(record["name"]), str(record.get("id", "")))
                    )
                    continue
                if not versions:
                    introduced = str(record.get("introduced") or "0")
                    if (
                        ecosystem == "npm"
                        and PLACEHOLDER.match(introduced)
                        and not record.get("fixed")
                    ):
                        # A range opening at the placeholder names only the placeholder.
                        placeholder_only.append(
                            (ecosystem, str(record["name"]), str(record.get("id", "")))
                        )
                        continue
                    if introduced != "0":
                        versions = [introduced]
                    elif record.get("fixed"):
                        # Every version below the fix: the first one.
                        versions = ["v0.0.0" if ecosystem == "gomod" else "0.0.0"]
                    else:
                        versions = [Records.ANY_VERSION.get(ecosystem, "1.0.0")]
                checks.extend(
                    (ecosystem, str(record["name"]), version, str(record.get("id", "")))
                    for version in versions
                )
        return checks

    @staticmethod
    def batches(checks: list[tuple[str, str, str, str]]) -> list[list[tuple[str, str, str, str]]]:
        """Up to BATCH checks per project, each name once: a lockfile holds one version of a name."""
        by_ecosystem: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
        for check in checks:
            by_ecosystem[check[0]].append(check)
        out: list[list[tuple[str, str, str, str]]] = []
        for items in by_ecosystem.values():
            pending = list(items)
            while pending:
                batch: list[tuple[str, str, str, str]] = []
                seen: set[str] = set()
                rest: list[tuple[str, str, str, str]] = []
                for check in pending:
                    key = check[1].lower()
                    if key in seen or len(batch) >= BATCH:
                        rest.append(check)
                    else:
                        seen.add(key)
                        batch.append(check)
                out.append(batch)
                pending = rest
        return out


class Check:
    """One batch: written, scanned, and every record in it accounted for."""

    @staticmethod
    def write(root: Path, ecosystem: str, batch: list[tuple[str, str, str, str]]) -> None:
        from tests.conformancebuilders import Pkg, Writers

        if ecosystem == "vscode":
            pins = [f"{name}@{version}" for _e, name, version, _i in batch]
            (root / ".devcontainer").mkdir()
            (root / ".devcontainer/devcontainer.json").write_text(
                json.dumps({"customizations": {"vscode": {"extensions": pins}}}), encoding="utf-8"
            )
            return
        if ecosystem == "git":
            sections = "".join(
                f'[submodule "s{i}"]\n\tpath = third_party/s{i}\n\turl = https://{name}.git\n'
                for i, (_e, name, _v, _i) in enumerate(batch)
            )
            (root / ".gitmodules").write_text(sections, encoding="utf-8")
            return
        getattr(Writers, ecosystem)(root, [Pkg(name, version) for _e, name, version, _i in batch])

    @staticmethod
    def run(batch: list[tuple[str, str, str, str]]) -> tuple[str, int, list[dict[str, str]]]:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        ecosystem = batch[0][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                Check.write(root, ecosystem, batch)
                result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
            except Exception as exc:
                return (
                    ecosystem,
                    0,
                    [
                        {
                            "name": n,
                            "version": v,
                            "id": i,
                            "why": f"{type(exc).__name__}: {exc}"[:200],
                        }
                        for _e, n, v, i in batch
                    ],
                )
            flagged = {
                (d.name.lower(), (d.version or "").lower())
                for d in result.dependencies
                if d.to_dict()["record"]["malware_status"] == "malicious"
            }
            named = " ".join(
                f.message.lower() for f in result.findings if f.rule_id.startswith("MALWARE.")
            )
            misses: list[dict[str, str]] = []
            caught = 0
            for _e, name, version, identifier in batch:
                hit = (
                    name.lower() in named
                    if ecosystem in ("vscode", "git")
                    else (name.lower(), version.lower()) in flagged
                    or (name.lower(), version.lower().lstrip("v")) in flagged
                )
                if hit:
                    caught += 1
                else:
                    recorded = [d for d in result.dependencies if d.name.lower() == name.lower()]
                    why = (
                        "not in the inventory"
                        if not recorded
                        else f"recorded as {recorded[0].to_dict()['record']['malware_status']} at {recorded[0].version}"
                    )
                    misses.append({"name": name, "version": version, "id": identifier, "why": why})
            return ecosystem, caught, misses

    @staticmethod
    def main() -> None:
        placeholder_only: list[tuple[str, str, str]] = []
        checks = Records.load(placeholder_only)
        batches = Records.batches(checks)
        totals: Counter[str] = Counter(check[0] for check in checks)
        caught: Counter[str] = Counter()
        misses: list[dict[str, str]] = []
        with multiprocessing.get_context("fork").Pool() as pool:
            for done, (ecosystem, count, missed) in enumerate(
                pool.imap_unordered(Check.run, batches), start=1
            ):
                caught[ecosystem] += count
                misses.extend({"ecosystem": ecosystem, **m} for m in missed)
                if done % 20 == 0:
                    print(f"{done}/{len(batches)} batches", flush=True)
        records = RecordCount.unique()
        report = {
            "records": records,
            "checks": len(checks),
            "caught": sum(caught.values()),
            # Records whose every listed version is npm's empty takedown placeholder: nothing
            # malicious is left to depend on, and Cordon does not flag the placeholder.
            "placeholder_only_records": len(placeholder_only),
            "by_ecosystem": {e: {"checks": totals[e], "caught": caught[e]} for e in sorted(totals)},
            "misses": misses,
        }
        RESULT.parent.mkdir(parents=True, exist_ok=True)
        RESULT.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
        print(json.dumps({k: v for k, v in report.items() if k != "misses"}, indent=1))
        print("misses", len(misses), json.dumps(misses[:10], indent=1))


class RecordCount:
    """The malicious records themselves, as against the (record, version) checks made of them."""

    @staticmethod
    def unique() -> int:
        count = 0
        for path in sorted(DATA.glob("advisories-*.json.gz")):
            with gzip.open(path) as handle:
                count += sum(
                    1 for r in json.load(handle) if isinstance(r, dict) and r.get("malicious")
                )
        return count


if __name__ == "__main__":
    Check.main()
