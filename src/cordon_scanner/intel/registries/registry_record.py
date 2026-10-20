"""What the registry showed about a release when it was published -- acquired online, read offline.

The second review's publisher reviewer (`reviews/review-98/12-SECOND-REVIEW.md`, P). A package
whose content says nothing -- a manifest and a README, a binary, a hook that runs a dependency --
still has a registry record: who published it, when the name was created, what came before it.
Dependency-confusion squats, name families from one account and the release that adds an install
hook to an established package all show there, and nowhere in the archive.

```
  cordon-scanner intel acquire <target>   (network: registries only)
        │  npm packument / PyPI JSON for the release's name
        ▼
  RegistryRecord.from_npm / from_pypi     the record AS OF this release: only versions published
        │                                 at or before it are read, so a record fetched months
        │                                 later says what the registry said at publish time
        ▼
  <cache>/registry-record/<ecosystem>/<name>@<version>.json            (local, plain JSON)
        │
        ▼
  cordon scan <target>                    (no network: reads the store, or nothing)
        RegistryRecord.facts() -> verdict features `reg_*`; the strong shapes as findings
```

Every fact is read from the registry's own timestamps and per-version metadata, never from the
archive. Facts an attacker types into the manifest (description, repository) are kept apart from
facts the registry records (times, the publishing account) and weighed after them.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar, Final

STORE_VERSION: Final = 1
ECOSYSTEMS: Final = frozenset({"npm", "pypi"})
#: npm's lifecycle scripts that run on the installing machine.
INSTALL_HOOKS: Final = frozenset({"preinstall", "install", "postinstall", "prepare"})
#: A version number chosen to outrank any internal release: the dependency-confusion shape.
_CONFUSION_VERSION: Final = re.compile(r"^(?:9{2,}|[1-9]\d{3,})\.|^0\.0\.0(?:$|-)")
_PRERELEASE_BUILD: Final = re.compile(r"-(?:dev|canary|nightly|next|alpha|beta|rc)", re.I)
#: npm writes this when a version was published without one.
_NO_README: Final = "ERROR: No README data found!"


@dataclass(frozen=True, slots=True)
class RegistryRecord:
    """A release's registry record, as of its own publish time."""

    ecosystem: str
    name: str
    version: str
    published: str = ""
    """When the registry says this release was published (ISO 8601, UTC)."""
    created: str = ""
    """When the name itself was first published."""
    prior_versions: int = 0
    """Releases of this name published before this one."""
    prior_24h: int = 0
    """Of those, how many in the 24 hours before this one -- a burst."""
    previous_version: str = ""
    publisher: str = ""
    """The account that published this release (npm `_npmUser`); "" where the registry does not say."""
    prior_publishers: tuple[str, ...] = ()
    """The accounts that published the earlier releases."""
    maintainers: int = 0
    hooks: tuple[str, ...] = ()
    """Install hooks this release declares."""
    hooks_added: tuple[str, ...] = ()
    """Install hooks this release declares and the previous release did not."""
    dependencies_added: tuple[str, ...] = ()
    """Runtime dependencies this release declares and the previous release did not."""
    has_repository: bool = False
    has_readme: bool = False
    description_length: int = 0
    has_author: bool = False
    manifest_known: bool = True
    """Whether the manifest facts describe THIS release. PyPI's JSON describes only the newest one;
    for an older release they are unknown, not absent."""
    owners: tuple[str, ...] = field(default_factory=tuple)
    """PyPI project roles (owners and maintainers) where the JSON API lists them."""

    ECOSYSTEMS_READ: ClassVar[frozenset[str]] = ECOSYSTEMS

    # -- reading a registry document (pure; no network) ----------------------------------

    @staticmethod
    def _when(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return moment.replace(tzinfo=None) if moment.tzinfo else moment

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        """A registry document's object, or an empty one when it is anything else."""
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _iso(moment: datetime | None) -> str:
        return moment.isoformat(timespec="seconds") if moment else ""

    @classmethod
    def _history(
        cls, times: dict[str, datetime], version: str
    ) -> tuple[datetime | None, list[tuple[datetime, str]]]:
        """This release's time and the releases published before it, oldest first."""
        released = times.get(version)
        if released is None:
            return None, []
        earlier = sorted((when, v) for v, when in times.items() if when < released and v != version)
        return released, earlier

    @classmethod
    def from_npm(cls, document: dict[str, Any], version: str) -> RegistryRecord | None:
        """The record from an npm packument, as of `version`'s publish time."""
        name = str(document.get("name") or "")
        versions = RegistryRecord._mapping(document.get("versions"))
        raw_times = RegistryRecord._mapping(document.get("time"))
        times = {
            str(v): when
            for v, value in raw_times.items()
            if v not in ("created", "modified") and (when := cls._when(value)) is not None
        }
        released, earlier = cls._history(times, version)
        if not name or released is None:
            return None
        this = RegistryRecord._mapping(versions.get(version))
        previous = earlier[-1][1] if earlier else ""
        before = RegistryRecord._mapping(versions.get(previous))

        def publisher(meta: Any) -> str:
            user = meta.get("_npmUser") if isinstance(meta, dict) else None
            return str(user.get("name") or "") if isinstance(user, dict) else ""

        def hooks(meta: Any) -> set[str]:
            scripts = meta.get("scripts") if isinstance(meta, dict) else None
            return set(scripts) & INSTALL_HOOKS if isinstance(scripts, dict) else set()

        def dependencies(meta: Any) -> set[str]:
            out: set[str] = set()
            for section in ("dependencies", "optionalDependencies"):
                value = meta.get(section) if isinstance(meta, dict) else None
                if isinstance(value, dict):
                    out.update(str(k) for k in value)
            return out

        created = cls._when(raw_times.get("created"))
        first = earlier[0][0] if earlier else released
        repository = this.get("repository")
        readme = (
            this.get("readme") if isinstance(this.get("readme"), str) else document.get("readme")
        )
        maintainers = this.get("maintainers") or document.get("maintainers") or []
        return cls(
            ecosystem="npm",
            name=name,
            version=version,
            published=cls._iso(released),
            created=cls._iso(min(created, first) if created else first),
            prior_versions=len(earlier),
            prior_24h=sum(1 for when, _ in earlier if released - when <= timedelta(hours=24)),
            previous_version=previous,
            publisher=publisher(this),
            prior_publishers=tuple(
                sorted({p for _, v in earlier if (p := publisher(versions.get(v)))})
            ),
            maintainers=len(maintainers) if isinstance(maintainers, list) else 0,
            hooks=tuple(sorted(hooks(this))),
            hooks_added=tuple(sorted(hooks(this) - hooks(before))) if previous else (),
            dependencies_added=(
                tuple(sorted(dependencies(this) - dependencies(before))) if previous else ()
            ),
            has_repository=bool(repository),
            has_readme=isinstance(readme, str) and bool(readme.strip()) and readme != _NO_README,
            description_length=len(str(this.get("description") or "")),
            has_author=bool(this.get("author")),
        )

    @classmethod
    def from_pypi(cls, document: dict[str, Any], version: str) -> RegistryRecord | None:
        """The record from PyPI's JSON API, as of `version`'s first upload."""
        info = RegistryRecord._mapping(document.get("info"))
        name = str(info.get("name") or "")
        releases = RegistryRecord._mapping(document.get("releases"))
        times: dict[str, datetime] = {}
        for release, files in releases.items():
            for upload in files if isinstance(files, list) else ():
                when = cls._when(
                    upload.get("upload_time_iso_8601") or upload.get("upload_time")
                    if isinstance(upload, dict)
                    else None
                )
                if when is not None:
                    times[str(release)] = min(times.get(str(release), when), when)
        if version not in times:
            for upload in document.get("urls") or ():
                when = cls._when(
                    upload.get("upload_time_iso_8601") or upload.get("upload_time")
                    if isinstance(upload, dict)
                    else None
                )
                if when is not None:
                    times[version] = min(times.get(version, when), when)
        released, earlier = cls._history(times, version)
        if not name or released is None:
            return None
        ownership = RegistryRecord._mapping(document.get("ownership"))
        raw_roles = ownership.get("roles")
        roles: list[Any] = raw_roles if isinstance(raw_roles, list) else []
        project_urls = info.get("project_urls")
        # The JSON document describes the newest release; what it says about this one is only
        # trustworthy when it IS this one.
        current = str(info.get("version") or "") == version
        return cls(
            ecosystem="pypi",
            name=name,
            version=version,
            published=cls._iso(released),
            created=cls._iso(earlier[0][0] if earlier else released),
            prior_versions=len(earlier),
            prior_24h=sum(1 for when, _ in earlier if released - when <= timedelta(hours=24)),
            previous_version=earlier[-1][1] if earlier else "",
            maintainers=len(roles),
            has_repository=current
            and bool(info.get("home_page") or (isinstance(project_urls, dict) and project_urls)),
            has_readme=current and len(str(info.get("description") or "").strip()) > 40,
            description_length=len(str(info.get("summary") or "")) if current else 0,
            has_author=current and bool(info.get("author") or info.get("author_email")),
            manifest_known=current,
            owners=tuple(
                sorted(str(r.get("user")) for r in roles if isinstance(r, dict) and r.get("user"))
            ),
        )

    # -- facts for the verdict (offline) -------------------------------------------------

    def facts(self) -> dict[str, float]:
        """Verdict features, `reg_` prefixed. Registry-recorded facts first; manifest-typed ones
        (`reg_manifest_*`) are the attacker's own words and are named so."""
        published = self._when(self.published)
        created = self._when(self.created)
        age_days = (published - created).total_seconds() / 86400 if published and created else 0.0
        new_publisher = bool(
            self.publisher and self.prior_publishers and self.publisher not in self.prior_publishers
        )
        return {
            "reg_known": 1.0,
            "reg_name_age_days": round(min(age_days, 3650.0), 2),
            "reg_first_release": float(self.prior_versions == 0),
            "reg_prior_versions": float(min(self.prior_versions, 500)),
            "reg_prior_24h": float(min(self.prior_24h, 100)),
            "reg_new_publisher": float(new_publisher),
            # PyPI's JSON began listing project roles in 2025: a record captured before then
            # has none, so the count dates the capture, not the project (review 98: 0.99 of
            # benign releases fetched now against 0.10 of malware captured earlier). npm only.
            **(
                {"reg_maintainers": float(min(self.maintainers, 50))}
                if self.ecosystem == "npm"
                else {}
            ),
            "reg_hooks": float(len(self.hooks)),
            "reg_hooks_added": float(len(self.hooks_added)),
            "reg_dependencies_added": float(min(len(self.dependencies_added), 50)),
            "reg_confusion_version": float(bool(_CONFUSION_VERSION.match(self.version))),
            "reg_prerelease_build": float(bool(_PRERELEASE_BUILD.search(self.version))),
            "reg_manifest_known": float(self.manifest_known),
            "reg_manifest_repository": float(self.has_repository),
            "reg_manifest_readme": float(self.has_readme),
            "reg_manifest_description": float(min(self.description_length, 500)),
            "reg_manifest_author": float(self.has_author),
        }

    # -- the store ----------------------------------------------------------------------

    @staticmethod
    def store_dir() -> Path:
        from cordon_scanner.engine.cache import ScanCache

        return ScanCache.default_cache_dir() / "registry-record"

    @staticmethod
    def _entry(root: Path, ecosystem: str, name: str, version: str) -> Path:
        quoted = urllib.parse.quote(f"{name}@{version}", safe="")
        return root / ecosystem / f"{quoted[:200]}.json"

    def to_dict(self) -> dict[str, Any]:
        return {"store_version": STORE_VERSION, **asdict(self)}

    @classmethod
    def load(
        cls, ecosystem: str, name: str, version: str, root: Path | None = None
    ) -> RegistryRecord | None:
        """The stored record, or None. Reads one file; never the network."""
        path = cls._entry(root or cls.store_dir(), ecosystem, name, version)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.pop("store_version", None) != STORE_VERSION:
            return None
        try:
            fields: dict[str, Any] = {
                key: tuple(value) if isinstance(value, list) else value
                for key, value in data.items()
                if key in cls.__dataclass_fields__
            }
            return cls(**fields)
        except TypeError:
            return None

    def save(self, root: Path | None = None) -> Path:
        path = self._entry(root or self.store_dir(), self.ecosystem, self.name, self.version)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.to_dict(), sort_keys=True), encoding="utf-8")
        temporary.replace(path)
        return path

    # -- acquiring (network; `intel acquire` only) --------------------------------------

    @classmethod
    def acquire(cls, ecosystem: str, name: str, version: str) -> RegistryRecord | None:
        """Fetch the name's registry document and keep the record as of `version`. Network."""
        from cordon_scanner.intel.registries.registry_client import REGISTRY_HOSTS, RegistryClient

        if ecosystem == "npm":
            document = RegistryClient._fetch(
                f"{REGISTRY_HOSTS['npm']}/{urllib.parse.quote(name, safe='@')}"
            )
            record = cls.from_npm(document, version) if isinstance(document, dict) else None
        elif ecosystem == "pypi":
            quoted = urllib.parse.quote(name, safe="")
            document = RegistryClient._fetch(f"{REGISTRY_HOSTS['pypi']}/pypi/{quoted}/json")
            record = cls.from_pypi(document, version) if isinstance(document, dict) else None
        else:
            return None
        if record is not None:
            record.save()
        return record


__all__ = ["ECOSYSTEMS", "INSTALL_HOOKS", "STORE_VERSION", "RegistryRecord"]
