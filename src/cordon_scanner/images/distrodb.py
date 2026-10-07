"""Distribution advisories on disk, so an image's operating-system packages match offline.

`cordon-scanner advisories sync --os debian alpine ...` downloads OSV's export for each
distribution family once, keeps only what matching needs -- per release and source package, the
affected ranges, the advisory id, its CVEs and its rating -- and writes it beside the language
advisories in the user's sync directory, sealed with this install's key. From then on an image scan
matches its packages here, with the network off, and names no package to anyone.

Not bundled with the release: Debian's export alone is larger than the rest of the wheel, Ubuntu's
and Chainguard's run to hundreds of megabytes, and the distributions revise them daily. A machine
that scans images syncs the families it needs; an air-gapped one syncs on a connected host and
copies the directory across.

Versions are compared by each distribution's own rules, implemented here: dpkg for Debian and
Ubuntu, apk for Alpine, Wolfi and Chainguard, rpm (shared with `images/alas.py`) for the rest.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from cordon_scanner.images.osv import Matches, Query

#: Family -> OSV's export name.
FAMILIES: Final[dict[str, str]] = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
    "wolfi": "Wolfi",
    "chainguard": "Chainguard",
    "rocky": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "redhat": "Red Hat",
    "suse": "SUSE",
    "opensuse": "openSUSE",
}
MAX_EXPORT_BYTES: Final = 2 << 30
MAX_RECORD_BYTES: Final = 4 << 20
SEAL_LABEL: Final = "os-advisory-manifest"
MANIFEST: Final = "os-digests.json"


class DistroVersions:
    """Each distribution's version ordering."""

    @staticmethod
    def _dpkg_order(character: str) -> int:
        if character == "~":
            return -1
        if character.isdigit():
            return 0
        if character.isalpha():
            return ord(character)
        return ord(character) + 256

    @staticmethod
    def _dpkg_part(a: str, b: str) -> int:
        """Debian Policy 5.6.12: alternate non-digit and digit runs; `~` sorts before anything."""
        i = j = 0
        while i < len(a) or j < len(b):
            first_diff = 0
            while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
                ac = DistroVersions._dpkg_order(a[i]) if i < len(a) and not a[i].isdigit() else 0
                bc = DistroVersions._dpkg_order(b[j]) if j < len(b) and not b[j].isdigit() else 0
                if ac != bc:
                    return -1 if ac < bc else 1
                i += 1
                j += 1
            while i < len(a) and a[i] == "0":
                i += 1
            while j < len(b) and b[j] == "0":
                j += 1
            while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
                if not first_diff:
                    first_diff = ord(a[i]) - ord(b[j])
                i += 1
                j += 1
            if i < len(a) and a[i].isdigit():
                return 1
            if j < len(b) and b[j].isdigit():
                return -1
            if first_diff:
                return -1 if first_diff < 0 else 1
        return 0

    @staticmethod
    def dpkg(a: str, b: str) -> int:
        def split(version: str) -> tuple[int, str, str]:
            epoch, _, rest = version.rpartition(":") if ":" in version else ("0", "", version)
            upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "0")
            return int(epoch or 0) if epoch.isdigit() else 0, upstream, revision

        ea, ua, ra = split(a)
        eb, ub, rb = split(b)
        if ea != eb:
            return -1 if ea < eb else 1
        return DistroVersions._dpkg_part(ua, ub) or DistroVersions._dpkg_part(ra, rb)

    _APK = re.compile(
        r"^(\d{1,12}(?:\.\d{1,12}){0,16})([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d{0,12}){0,8})(?:-r(\d{1,12}))?$"
    )
    _APK_SUFFIX: Final = {
        "alpha": 0,
        "beta": 1,
        "pre": 2,
        "rc": 3,
        "": 4,
        "cvs": 5,
        "svn": 6,
        "git": 7,
        "hg": 8,
        "p": 9,
    }

    @staticmethod
    def apk(a: str, b: str) -> int:
        def key(version: str) -> tuple[Any, ...]:
            match = DistroVersions._APK.match(version.strip())
            if not match:
                return ((), 0, ((4, 0),), 0, version)
            numbers = tuple(int(n) for n in match.group(1).split("."))
            letter = ord(match.group(2)) if match.group(2) else 0
            suffixes = tuple(
                (
                    DistroVersions._APK_SUFFIX.get(re.sub(r"\d+$", "", s), 4),
                    int(re.sub(r"^\D+", "", s) or 0),
                )
                for s in match.group(3).split("_")
                if s
            ) or ((4, 0),)
            return (numbers, letter, suffixes, int(match.group(4) or 0), "")

        ka, kb = key(a), key(b)
        return (ka > kb) - (ka < kb)

    @staticmethod
    def rpm(a: str, b: str) -> int:
        from cordon_scanner.images.alas import AmazonLinuxAdvisories

        def evr(version: str) -> tuple[str, str, str]:
            epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
            ver, _, rel = rest.rpartition("-") if "-" in rest else (rest, "", "")
            return epoch or "0", ver, rel

        return AmazonLinuxAdvisories.evr_compare(evr(a), evr(b))

    @staticmethod
    def for_ecosystem(ecosystem: str) -> Any:
        family = ecosystem.split(":", 1)[0]
        if family in ("Debian", "Ubuntu"):
            return DistroVersions.dpkg
        if family in ("Alpine", "Wolfi", "Chainguard"):
            return DistroVersions.apk
        return DistroVersions.rpm


@dataclass(frozen=True)
class Record:
    id: str
    intervals: tuple[tuple[str | None, str | None, str | None], ...]
    versions: tuple[str, ...]
    score: float | None
    rating: str
    cves: tuple[str, ...]
    summary: str

    def affects(self, version: str, compare: Any) -> bool:
        if version in self.versions:
            return True
        for introduced, fixed, last in self.intervals:
            if introduced not in (None, "0") and compare(version, introduced) < 0:
                continue
            if fixed is not None and compare(version, fixed) >= 0:
                continue
            if last is not None and compare(version, last) > 0:
                continue
            return True
        return False

    @property
    def fixed(self) -> str:
        return next((f for _, f, _ in self.intervals if f), "")


class DistroDatabase:
    """The synced distribution advisories."""

    @staticmethod
    def directory() -> Path:
        from cordon_scanner.intel.advisories import AdvisoryFiles

        return AdvisoryFiles.user_sync_dir() / "os"

    # -- sync ----------------------------------------------------------------------------------

    @staticmethod
    def _record(raw: dict[str, Any]) -> list[tuple[str, str, list[Any]]]:
        """`(ecosystem, package, compact record)` for each affected entry of one OSV record."""
        from cordon_scanner.images.osv import OsvClient

        identifier = str(raw.get("id") or "")
        if not identifier or raw.get("withdrawn"):
            return []
        scores = [
            OsvClient.cvss3_base(str(s.get("score", "")))
            for s in raw.get("severity") or ()
            if isinstance(s, dict)
        ]
        known = [s for s in scores if s is not None]
        rating = ""
        for s in raw.get("severity") or ():
            if isinstance(s, dict) and str(s.get("type", "")).lower() == "ubuntu":
                rating = str(s.get("score", "")).lower()
        specific = raw.get("database_specific")
        if not rating and isinstance(specific, dict) and isinstance(specific.get("severity"), str):
            rating = specific["severity"].lower()
        cves = sorted(
            {
                c
                for text in [identifier, *(raw.get("aliases") or []), *(raw.get("upstream") or [])]
                for c in re.findall(r"CVE-\d{4}-\d{4,7}", str(text))
            }
        )
        summary = str(raw.get("summary") or raw.get("details") or "")[:200]
        out: list[tuple[str, str, list[Any]]] = []
        for affected in raw.get("affected") or ():
            package = affected.get("package") if isinstance(affected, dict) else None
            if not isinstance(package, dict):
                continue
            ecosystem, name = str(package.get("ecosystem") or ""), str(package.get("name") or "")
            if not ecosystem or not name:
                continue
            intervals: list[list[str | None]] = []
            for rng in affected.get("ranges") or ():
                if rng.get("type") != "ECOSYSTEM":
                    continue
                introduced: str | None = None
                for event in rng.get("events") or ():
                    if "introduced" in event:
                        introduced = str(event["introduced"])
                    elif "fixed" in event:
                        intervals.append([introduced, str(event["fixed"]), None])
                        introduced = None
                    elif "last_affected" in event:
                        intervals.append([introduced, None, str(event["last_affected"])])
                        introduced = None
                if introduced is not None:
                    intervals.append([introduced, None, None])
            versions = [str(v) for v in affected.get("versions") or ()][:200]
            if not intervals and not versions:
                continue
            out.append(
                (
                    ecosystem,
                    name,
                    [
                        identifier,
                        intervals,
                        versions,
                        max(known) if known else None,
                        rating,
                        cves,
                        summary,
                    ],
                )
            )
        return out

    @staticmethod
    def sync(family: str, *, tmp_dir: Path) -> int:
        """Download one family's export and write its compact index. Returns the record count."""
        from cordon_scanner.intel import osv_import

        export = FAMILIES[family]
        archive = tmp_dir / f"os-{family}.zip"
        osv_import.OsvImport._download(
            f"https://{osv_import.OSV_HOST}/{export.replace(' ', '%20')}/all.zip",
            archive,
            limit=MAX_EXPORT_BYTES,
        )
        index: dict[str, dict[str, list[Any]]] = {}
        count = 0
        try:
            with zipfile.ZipFile(archive) as bundle:
                for info in bundle.infolist():
                    if not info.filename.endswith(".json") or info.file_size > MAX_RECORD_BYTES:
                        continue
                    try:
                        raw = json.loads(bundle.read(info))
                    except (ValueError, zipfile.BadZipFile, OSError):
                        continue
                    if not isinstance(raw, dict):
                        continue
                    for ecosystem, name, record in DistroDatabase._record(raw):
                        index.setdefault(ecosystem, {}).setdefault(name, []).append(record)
                        count += 1
        finally:
            archive.unlink(missing_ok=True)
        DistroDatabase._write(family, index)
        return count

    @staticmethod
    def _write(family: str, index: dict[str, dict[str, list[Any]]]) -> None:
        from cordon_scanner.core.local_seal import LocalSeal

        directory = DistroDatabase.directory()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = gzip.compress(json.dumps(index, separators=(",", ":")).encode(), mtime=0)
        path = directory / f"os-{family}.json.gz"
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(payload)
        temporary.chmod(0o600)
        temporary.replace(path)
        manifest_path = directory / MANIFEST
        digests: dict[str, Any] = {}
        if manifest_path.exists():
            try:
                loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
                if LocalSeal.valid(SEAL_LABEL, loaded):
                    digests = LocalSeal.unsealed(loaded)
            except (OSError, ValueError):
                digests = {}
        digests[path.name] = hashlib.sha256(payload).hexdigest()
        manifest_path.write_text(
            json.dumps(LocalSeal.sealed(SEAL_LABEL, digests), sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)

    # -- matching ------------------------------------------------------------------------------

    @staticmethod
    def family_of(ecosystem: str) -> str | None:
        prefix = ecosystem.split(":", 1)[0]
        return next((f for f, name in FAMILIES.items() if name == prefix), None)

    @staticmethod
    def covers(ecosystem: str | None) -> bool:
        """Whether this distribution's advisories were synced here (verified when loaded)."""
        family = DistroDatabase.family_of(ecosystem or "")
        return (
            family is not None and (DistroDatabase.directory() / f"os-{family}.json.gz").is_file()
        )

    @staticmethod
    def load(family: str) -> dict[str, dict[str, list[Any]]] | None:
        """One family's index, or None when it was never synced or does not verify."""
        from cordon_scanner.core.local_seal import LocalSeal

        directory = DistroDatabase.directory()
        path = directory / f"os-{family}.json.gz"
        try:
            manifest = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
            payload = path.read_bytes()
        except (OSError, ValueError):
            return None
        if not LocalSeal.valid(SEAL_LABEL, manifest):
            raise ValueError(f"{MANIFEST} is not sealed by this install")
        if LocalSeal.unsealed(manifest).get(path.name) != hashlib.sha256(payload).hexdigest():
            raise ValueError(f"{path.name} does not match its recorded digest")
        loaded = json.loads(gzip.decompress(payload))
        return loaded if isinstance(loaded, dict) else None

    @staticmethod
    def match(ecosystem: str, queries: list[Query]) -> Matches | None:
        """Offline matches, or None when this distribution was never synced here."""
        from cordon_scanner.images.osv import Matches, Vulnerability

        family = DistroDatabase.family_of(ecosystem)
        if family is None:
            return None
        index = DistroDatabase.load(family)
        if index is None:
            return None
        # Exact release first ("Debian:12"); Ubuntu's LTS suffix and Red Hat's product strings
        # name the same release more specifically, so a prefix match covers those.
        tables = [
            table
            for name, table in index.items()
            if name == ecosystem or name.startswith(ecosystem + ":")
        ]
        if not tables:
            found = Matches()
            found.problems.append(
                f"the synced {FAMILIES[family]} advisories have no {ecosystem} records"
            )
            return found
        compare = DistroVersions.for_ecosystem(ecosystem)
        found = Matches()
        for query in queries:
            vulnerabilities: dict[str, Vulnerability] = {}
            for table in tables:
                for raw in table.get(query.name, ()):
                    record = Record(
                        id=raw[0],
                        intervals=tuple(tuple(i) for i in raw[1]),
                        versions=tuple(raw[2]),
                        score=raw[3],
                        rating=raw[4],
                        cves=tuple(raw[5]),
                        summary=raw[6],
                    )
                    try:
                        hit = record.affects(query.version, compare)
                    except (ValueError, TypeError):
                        hit = False
                    if hit and record.id not in vulnerabilities:
                        vulnerabilities[record.id] = Vulnerability(
                            id=record.id,
                            summary=record.summary,
                            score=record.score,
                            cves=frozenset(record.cves),
                            fixed=record.fixed,
                            references=(f"https://osv.dev/vulnerability/{record.id}",),
                            rating=record.rating
                            if record.rating in ("critical", "high", "medium", "low")
                            else "",
                        )
            found.by_query[query] = list(vulnerabilities.values())
        return found


__all__ = ["FAMILIES", "DistroDatabase", "DistroVersions", "Record"]
