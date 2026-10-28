"""What an earlier, established release of a package contained -- acquired online, read offline.

A finding in code the package has shipped unchanged for months is a different claim from the
same finding in code that appeared in this release. Compromised releases arrive as a diff: a new
lifecycle script, a new file, a changed one. The prebuilt-binary installer or the notifier that
has been in every release since the first is not a new attack, and on the long tail it is most of
what a reader of capabilities alone reports (review 98).

```
  cordon-scanner intel acquire <target>  (network: registries only)
        │  for each release: the newest earlier release published >= MIN_AGE_DAYS before it,
        │  downloaded through the registry clients' pinned, digest-checked paths, hashed per file
        ▼
  <cache>/release-history/<ecosystem>/<name>@<version>.json        (local, plain JSON)
        │
        ▼
  cordon scan <target>                   (no network: reads the store, or nothing)
        a suspicious finding in a file byte-identical to the established release is reported
        below the gate; a file that is new or changed keeps its grade
```

The baseline must be OLD, not merely earlier: an attacker who publishes twice controls both
releases. Age is measured by the registry's own publish times, never by anything in the package.

Nothing here runs during a scan. `load` reads a file; `acquire` is the only function that touches
the network, and the CLI refuses it under CORDON_OFFLINE.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.detect.base import FileUnit

if TYPE_CHECKING:  # from the source
    from collections.abc import Sequence

MIN_AGE_DAYS: Final = 90
"""How much older the baseline release must be than the one scanned.

Long enough that a release has been installed, read and reported on by the ecosystem if it was
malicious -- malicious packages are typically removed within days -- and short enough that an
actively maintained package has one."""

STORE_VERSION: Final = 3

YOUNG_DEPENDENCY_DAYS: Final = 30
"""A dependency a release introduces that was itself first published this recently before the
release is the shape of a dependency injection: the compromised release of an established package
pulls in a name created for the attack (review 98: `@mastra/*` 2026-06-17)."""


@dataclass(frozen=True, slots=True)
class Baseline:
    """The established release a scanned release is compared with."""

    ecosystem: str
    name: str
    version: str
    baseline_version: str | None
    baseline_published: str | None = None
    published: str | None = None
    files: dict[str, str] = field(default_factory=dict)
    """Per file, its path with the release's version replaced by `{version}`, and its sha256."""
    dependencies: tuple[str, ...] = ()
    """The runtime dependencies the established release declared."""
    introduced: dict[str, str] = field(default_factory=dict)
    """Each dependency this release declares and the established one did not, with when the
    registry says it was first published ("" when the registry has no record of it)."""
    obfuscated: tuple[str, ...] = ()
    """The established release's files (by `ReleaseHistory.key`) that already had an
    obfuscator's output shape. Obfuscated output differs on every build, so an unchanged hash is
    no test for it; that the file was obfuscated months ago is."""

    def unchanged(self, key: str, digest: str) -> bool:
        return bool(self.baseline_version) and self.files.get(key) == digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "store_version": STORE_VERSION,
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "baseline_version": self.baseline_version,
            "baseline_published": self.baseline_published,
            "published": self.published,
            "files": self.files,
            "dependencies": list(self.dependencies),
            "introduced": self.introduced,
            "obfuscated": list(self.obfuscated),
        }


class ReleaseHistory:
    """Acquire (online) and load (offline) the established release behind a scanned one."""

    #: Ecosystems whose release times and archives this reads. Every other ecosystem answers
    #: `None`, which changes nothing about a scan.
    ECOSYSTEMS: Final = frozenset(
        {
            "npm",
            "pypi",
            "cargo",
            "rubygems",
            "nuget",
            "gomod",
            "hex",
            "pub",
            "maven",
            "gradle",
            "openvsx",
        }
    )

    # -- the store (offline) ------------------------------------------------------------------

    @staticmethod
    def store_dir() -> Path:
        from cordon_scanner.foundation.paths import StatePaths

        return StatePaths.default_cache_dir() / "release-history"

    @staticmethod
    def _entry(root: Path, ecosystem: str, name: str, version: str) -> Path:
        quoted = urllib.parse.quote(f"{name}@{version}", safe="")
        return root / ecosystem / f"{quoted[:200]}.json"

    @classmethod
    def load(
        cls, ecosystem: str, name: str, version: str, root: Path | None = None
    ) -> Baseline | None:
        """The stored baseline, or None. Reads one file; never the network."""
        path = cls._entry(root or cls.store_dir(), ecosystem, name, version)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or data.get("store_version") != STORE_VERSION:
            return None
        files = data.get("files")
        introduced = data.get("introduced")
        return Baseline(
            ecosystem=ecosystem,
            name=name,
            version=version,
            baseline_version=data.get("baseline_version") or None,
            baseline_published=data.get("baseline_published"),
            published=data.get("published"),
            files={str(k): str(v) for k, v in files.items()} if isinstance(files, dict) else {},
            dependencies=tuple(str(d) for d in data.get("dependencies") or ()),
            introduced=(
                {str(k): str(v) for k, v in introduced.items()}
                if isinstance(introduced, dict)
                else {}
            ),
            obfuscated=tuple(str(k) for k in data.get("obfuscated") or ()),
        )

    @classmethod
    def save(cls, baseline: Baseline, root: Path | None = None) -> Path:
        path = cls._entry(
            root or cls.store_dir(), baseline.ecosystem, baseline.name, baseline.version
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(baseline.to_dict(), sort_keys=True), encoding="utf-8")
        temporary.replace(path)
        return path

    # -- comparing (offline) ------------------------------------------------------------------

    @staticmethod
    def key(member_path: str, version: str) -> str:
        """A file's path inside its release, comparable across releases.

        The archive's own name is dropped and the version is written as `{version}`: an sdist's
        root is `name-1.2.3/`, a Go module's `example.com/m@v1.2.3/`, and the same file in the
        next release lives under a different root."""
        member = member_path.split("!", 1)[1] if "!" in member_path else member_path
        if not version:
            return member
        return re.sub(rf"(?<![\w.])(v?){re.escape(version)}(?!\w)", r"\1{version}", member)

    @classmethod
    def fingerprint(cls, data: bytes, filename: str, version: str) -> dict[str, str]:
        """Every file of a published archive, keyed by `key`, hashed. Read in memory."""
        from cordon_scanner.sources.archive import ArchiveReader

        out: dict[str, str] = {}
        for member_path, member in ArchiveReader.walk_archive(data, path=filename):
            out[cls.key(member_path, version)] = hashlib.sha256(member).hexdigest()
        return out

    @classmethod
    def obfuscated(cls, data: bytes, filename: str, version: str) -> tuple[str, ...]:
        """The archive's files with an obfuscator's output shape, keyed by `key`. Matched, never
        decoded: the same signatures `SUSPECT.OBFUSCATION.PACKED.001` reports."""
        from cordon_scanner.analysis.shared.languages import LanguageRegistry
        from cordon_scanner.detect.code.obfuscation.detector import ObfuscationDetector
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.sources.archive import ArchiveReader

        detector = ObfuscationDetector()
        out: list[str] = []
        for member_path, member in ArchiveReader.walk_archive(data, path=filename):
            content = FileContent.from_bytes(member_path, member)
            if content.is_binary:
                continue
            language = LanguageRegistry.of_file(member_path, content)
            if any(True for _ in detector._packers(content, language)):
                out.append(cls.key(member_path, version))
        return tuple(sorted(out))

    @staticmethod
    def declared(data: bytes, filename: str, ecosystem: str) -> frozenset[str]:
        """The runtime dependencies a published archive declares, read the way the scan reads
        them (`declared_dependencies`)."""
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.sources.archive import ArchiveReader

        units = [
            FileUnit(content=FileContent.from_bytes(member, payload))
            for member, payload in ArchiveReader.walk_archive(data, path=filename)
        ]
        return ReleaseHistory.declared_dependencies(units, ecosystem)

    # -- acquiring (online) -------------------------------------------------------------------

    @staticmethod
    def _when(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (
            parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
        )

    @classmethod
    def timeline(cls, ecosystem: str, name: str, version: str) -> dict[str, datetime]:
        """When the registry says each release was published. Network."""

        quoted = urllib.parse.quote(name, safe="")
        out: dict[str, datetime] = {}

        if ecosystem == "npm":
            ReleaseHistory._npm_times(name, version, out)
        elif ecosystem == "pypi":
            ReleaseHistory._pypi_times(quoted, out)
        elif ecosystem == "openvsx":
            ReleaseHistory._openvsx_times(name, version, out)
        elif ecosystem == "cargo":
            ReleaseHistory._cargo_times(quoted, out)
        elif ecosystem == "rubygems":
            ReleaseHistory._rubygems_times(quoted, out)
        elif ecosystem == "nuget":
            ReleaseHistory._nuget_times(quoted, out)
        elif ecosystem == "gomod":
            ReleaseHistory._gomod_times(name, version, out)
        elif ecosystem == "hex":
            ReleaseHistory._hex_times(quoted, out)
        elif ecosystem == "pub":
            ReleaseHistory._pub_times(quoted, out)
        elif ecosystem in ("maven", "gradle"):
            ReleaseHistory._maven_times(name, out)
        return out

    @staticmethod
    def _put(out: dict[str, datetime], release: Any, when: Any) -> None:
        """Record when a release was published: its earliest time, if it has one."""
        moment = ReleaseHistory._when(when)
        if isinstance(release, str) and release and moment is not None:
            out[release] = min(out.get(release, moment), moment)

    @staticmethod
    def _npm_times(name: str, version: str, out: dict[str, datetime]) -> None:
        """When npm says each release was published."""
        from cordon_scanner.intel.registries.registry_client import REGISTRY_HOSTS, RegistryClient

        document = RegistryClient._fetch(
            f"{REGISTRY_HOSTS['npm']}/{urllib.parse.quote(name, safe='@')}"
        )
        listed = RegistryClient._mapping(document.get("versions"))
        for release, when in RegistryClient._mapping(document.get("time")).items():
            # The scanned release keeps its time after npm withdraws it (as it does a
            # malicious one); a baseline must still be served.
            if release in listed or release == version:
                ReleaseHistory._put(out, release, when)

    @staticmethod
    def _pypi_times(quoted: str, out: dict[str, datetime]) -> None:
        """When pypi says each release was published."""
        from cordon_scanner.intel.registries.registry_client import REGISTRY_HOSTS, RegistryClient

        document = RegistryClient._fetch(f"{REGISTRY_HOSTS['pypi']}/pypi/{quoted}/json")
        for release, files in RegistryClient._mapping(document.get("releases")).items():
            for upload in files if isinstance(files, list) else ():
                if isinstance(upload, dict) and not upload.get("yanked"):
                    ReleaseHistory._put(out, release, upload.get("upload_time_iso_8601"))

    @staticmethod
    def _openvsx_times(name: str, version: str, out: dict[str, datetime]) -> None:
        """When openvsx says each release was published."""
        from cordon_scanner.intel.registries.openvsx import OpenVsx

        out.update(OpenVsx.timeline(name, version))

    @staticmethod
    def _cargo_times(quoted: str, out: dict[str, datetime]) -> None:
        """When cargo says each release was published."""
        from cordon_scanner.intel.registries.registry_hosts import HOSTS
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        document = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['cargo']}/api/v1/crates/{quoted}")
        )
        for entry in RegistryHttp.entries(document.get("versions")):
            if not entry.get("yanked"):
                ReleaseHistory._put(out, entry.get("num"), entry.get("created_at"))

    @staticmethod
    def _rubygems_times(quoted: str, out: dict[str, datetime]) -> None:
        """When rubygems says each release was published."""
        from cordon_scanner.intel.registries.registry_hosts import HOSTS
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        listed = RegistryHttp.json(f"{HOSTS['rubygems']}/api/v1/versions/{quoted}.json")
        for entry in RegistryHttp.entries(listed):
            if entry.get("platform", "ruby") == "ruby":
                ReleaseHistory._put(out, entry.get("number"), entry.get("created_at"))

    @staticmethod
    def _nuget_times(quoted: str, out: dict[str, datetime]) -> None:
        """When nuget says each release was published."""
        from cordon_scanner.intel.registries.registry_hosts import HOSTS
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        index = RegistryHttp.mapping(
            RegistryHttp.json(
                f"{HOSTS['nuget']}/v3/registration5-gz-semver2/{quoted.lower()}/index.json"
            )
        )
        for page in RegistryHttp.entries(index.get("items")):
            items = page.get("items")
            if items is None and isinstance(page.get("@id"), str):
                items = RegistryHttp.mapping(RegistryHttp.json(page["@id"])).get("items")
            for item in RegistryHttp.entries(items):
                entry = RegistryHttp.mapping(item.get("catalogEntry"))
                if entry.get("listed", True):
                    ReleaseHistory._put(out, entry.get("version"), entry.get("published"))

    @staticmethod
    def _gomod_times(name: str, version: str, out: dict[str, datetime]) -> None:
        """When gomod says each release was published."""
        from cordon_scanner.intel.advisories.versions import Versions
        from cordon_scanner.intel.registries.more_registries import MoreRegistries
        from cordon_scanner.intel.registries.package_registries import PackageRegistries
        from cordon_scanner.intel.registries.registry_hosts import HOSTS
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        current = version.lstrip("v")
        earlier = sorted(
            (
                v
                for v in MoreRegistries.versions("gomod", name)
                if Versions.compare("gomod", v, current) < 0
            ),
            key=lambda v: Versions.sort_key("gomod", v),
            reverse=True,
        )
        module = PackageRegistries.go_escape(name)
        for release in [current, *earlier[:40]]:
            info = RegistryHttp.mapping(
                RegistryHttp.json(f"{HOSTS['gomod']}/{module}/@v/v{release}.info")
            )
            ReleaseHistory._put(out, release, info.get("Time"))
            moment = out.get(release)
            if (
                release != current
                and moment is not None
                and current in out
                and moment <= out[current] - timedelta(days=MIN_AGE_DAYS)
            ):
                break

    @staticmethod
    def _hex_times(quoted: str, out: dict[str, datetime]) -> None:
        """When hex says each release was published."""
        from cordon_scanner.intel.registries.registry_hosts import HOSTS
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        document = RegistryHttp.mapping(RegistryHttp.json(f"{HOSTS['hex']}/api/packages/{quoted}"))
        for entry in RegistryHttp.entries(document.get("releases")):
            ReleaseHistory._put(out, entry.get("version"), entry.get("inserted_at"))

    @staticmethod
    def _pub_times(quoted: str, out: dict[str, datetime]) -> None:
        """When pub says each release was published."""
        from cordon_scanner.intel.registries.registry_hosts import HOSTS
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        document = RegistryHttp.mapping(RegistryHttp.json(f"{HOSTS['pub']}/api/packages/{quoted}"))
        for entry in RegistryHttp.entries(document.get("versions")):
            if entry.get("retracted") is not True:
                ReleaseHistory._put(out, entry.get("version"), entry.get("published"))

    @staticmethod
    def _maven_times(name: str, out: dict[str, datetime]) -> None:
        """When maven says each release was published."""
        from cordon_scanner.intel.registries.registry_http import RegistryHttp

        group, _, artifact = name.partition(":")
        query = urllib.parse.quote(f'g:"{group}" AND a:"{artifact}"', safe="")
        document = RegistryHttp.mapping(
            RegistryHttp.json(
                f"https://search.maven.org/solrsearch/select?q={query}&core=gav&rows=200&wt=json"
            )
        )
        for entry in RegistryHttp.entries(
            RegistryHttp.mapping(document.get("response")).get("docs")
        ):
            stamp = entry.get("timestamp")
            if isinstance(stamp, int):
                ReleaseHistory._put(
                    out,
                    entry.get("v"),
                    datetime.fromtimestamp(stamp / 1000).astimezone().isoformat(),
                )

    @classmethod
    def established(
        cls, ecosystem: str, name: str, version: str
    ) -> tuple[str, datetime, datetime] | None:
        """The newest release published at least `MIN_AGE_DAYS` before `version`: (release, its
        time, the scanned release's time). Network."""
        times = cls.timeline(ecosystem, name, version)
        current = times.get(version.lstrip("v") if ecosystem == "gomod" else version)
        if current is None:
            return None
        cutoff = current - timedelta(days=MIN_AGE_DAYS)
        older = [(when, release) for release, when in times.items() if when <= cutoff]
        if not older:
            return None
        when, release = max(older)
        return release, when, current

    @classmethod
    def first_published(cls, ecosystem: str, name: str) -> str:
        """When the registry says a package was first published, ISO-8601, or "". Network."""
        from cordon_scanner.intel.registries.registry_client import RegistryError

        if ecosystem == "gomod":
            # The proxy dates versions, not modules; a module's first version is not asked here.
            return ""
        try:
            if ecosystem == "npm":
                from cordon_scanner.intel.registries.registry_client import (
                    REGISTRY_HOSTS,
                    RegistryClient,
                )

                document = RegistryClient._fetch(
                    f"{REGISTRY_HOSTS['npm']}/{urllib.parse.quote(name, safe='@')}"
                )
                created = cls._when(RegistryClient._mapping(document.get("time")).get("created"))
                return created.isoformat() if created else ""
            times = cls.timeline(ecosystem, name, "")
        except RegistryError:
            return ""
        return min(times.values()).isoformat() if times else ""

    @classmethod
    def acquire(
        cls,
        ecosystem: str,
        name: str,
        version: str,
        root: Path | None = None,
        current_dependencies: tuple[str, ...] = (),
    ) -> Baseline:
        """Fetch, hash and store the established release behind `name@version`. Network.

        A release with no established predecessor is stored too, as such: the scan then knows the
        question was asked and the answer is "nothing to compare with"."""
        from cordon_scanner.intel.registries.registry_client import RegistryClient

        eco = "maven" if ecosystem == "gradle" else ecosystem
        found = cls.established(eco, name, version)
        if found is None:
            baseline = Baseline(ecosystem, name, version, None)
        else:
            release, when, current = found
            if eco == "openvsx":
                from cordon_scanner.intel.registries.openvsx import OpenVsx

                archive = OpenVsx.archive(name, release)
            else:
                archive = RegistryClient.package_archive(eco, name, release)
            established = cls.declared(archive.data, archive.filename, ecosystem)
            introduced = {
                dependency: cls.first_published(eco, dependency)
                for dependency in sorted(set(current_dependencies) - set(established))[:40]
            }
            baseline = Baseline(
                ecosystem=ecosystem,
                name=name,
                version=version,
                baseline_version=archive.version,
                baseline_published=when.isoformat(),
                published=current.isoformat(),
                files=cls.fingerprint(archive.data, archive.filename, archive.version),
                dependencies=tuple(sorted(established)),
                introduced=introduced,
                obfuscated=cls.obfuscated(archive.data, archive.filename, archive.version),
            )
        cls.save(baseline, root)
        return baseline

    _REQUIRES_DIST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?m)^Requires-Dist:\s*([A-Za-z0-9][A-Za-z0-9._-]*)([^\n]*)$"
    )

    @staticmethod
    def declared_dependencies(units: Sequence[FileUnit], distribution: str) -> frozenset[str]:
        """A release's runtime dependencies: npm's (optional ones too), PyPI's `Requires-Dist`."""
        if distribution == "npm":
            manifest = next((u for u in units if u.path.endswith("!package/package.json")), None)
            try:
                document = json.loads(manifest.content.text) if manifest is not None else {}
            except ValueError:
                return frozenset()
            if not isinstance(document, dict):
                return frozenset()
            names: set[str] = set()
            for section in ("dependencies", "optionalDependencies"):
                value = document.get(section)
                if isinstance(value, dict):
                    names.update(str(k) for k in value)
            return frozenset(names)
        if distribution == "pypi":
            for unit in units:
                member = unit.path.rpartition("!")[2]
                if member.endswith(("/PKG-INFO", ".dist-info/METADATA")) and member.count("/") == 1:
                    return frozenset(
                        re.sub(r"[-_.]+", "-", found.group(1)).lower()
                        for found in ReleaseHistory._REQUIRES_DIST.finditer(
                            unit.content.text[:200_000]
                        )
                        if "extra ==" not in found.group(2)
                    )
        return frozenset()


__all__ = ["MIN_AGE_DAYS", "YOUNG_DEPENDENCY_DAYS", "Baseline", "ReleaseHistory"]
