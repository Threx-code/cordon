"""Facts the language package registries give: CRAN, opam, Julia, Hackage, conda, CocoaPods, crates.io,
RubyGems, NuGet, the Go module proxy (with retractions), Maven Central, Packagist, pub.dev and Hex.
"""

from __future__ import annotations

import json
import re
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

from cordon_scanner.intel.base import PackageFacts
from cordon_scanner.intel.registries.registry_hosts import (
    _DIGEST_LINE,
    _RELEASE_TAG,
    _VERSION_TAG,
    HOSTS,
    Redirected,
)
from cordon_scanner.intel.registries.registry_http import RegistryHttp
from cordon_scanner.intel.registries.registry_request import PackageNotFound, RegistryError


class PackageRegistries:
    """Facts from language package registries."""

    @staticmethod
    def cran(name: str, version: str | None) -> PackageFacts:
        """crandb, r-pkg.org's database of CRAN: every version with its DESCRIPTION, the
        publication timeline, and whether CRAN archived the package -- removed it for problems the
        maintainer did not fix, which is CRAN's withdrawal. CRAN publishes no archive hash a lock
        could be compared with, so none is returned."""
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9.]{0,127}", name):
            raise RegistryError(f"{name} is not a CRAN package name")
        document = RegistryHttp.mapping(RegistryHttp.json(f"{HOSTS['cran']}/{name}/all"))
        versions = RegistryHttp.mapping(document.get("versions"))
        timeline = RegistryHttp.mapping(document.get("timeline"))
        archived = document.get("archived") is True
        # R reads a version as integers separated by single `.` or `-` (`package_version`):
        # `1.2.16` and `1.2-16` are one version. A renv.lock pinning AER `1.2.16` -- CRAN's
        # `1.2-16` -- was reported withdrawn, as were 60 more of one real lock.
        wanted = PackageRegistries._r_version(version) if version else None
        known = bool(version) and (
            version in versions
            or (
                wanted is not None
                and any(PackageRegistries._r_version(v) == wanted for v in versions)
            )
        )
        latest = (
            RegistryHttp.mapping(document.get("latest"))
            if isinstance(document.get("latest"), dict)
            else {}
        )
        dates = [str(v) for v in timeline.values() if isinstance(v, str)]
        return PackageFacts(
            name=name,
            version=version,
            yanked=archived or (bool(version) and not known),
            yanked_reason="archived by CRAN"
            if archived
            else ("not a version CRAN published" if version and not known else None),
            latest=RegistryHttp.string(latest.get("Version"))
            or (
                max(versions, key=lambda v: PackageRegistries._r_version(v) or ())
                if versions
                else None
            ),
            first_published=min(dates) if dates else None,
            last_published=max(dates) if dates else None,
            releases=len(versions),
        )

    @staticmethod
    def _r_version(value: str) -> tuple[int, ...] | None:
        """An R package version as R compares it: its integers, separated by `.` or `-`. None
        for a string that is not one."""
        if not re.fullmatch(r"\d+(?:[.-]\d+)+", value):
            return None
        return tuple(int(part) for part in re.split(r"[.-]", value))

    @staticmethod
    def opam(name: str, version: str | None) -> PackageFacts:
        """opam-repository's definition of the version, `packages/<n>/<n>.<v>/opam`: the archive's
        checksums (what dune's lock records), dev-repo, and the `deprecated` / `avoid-version`
        flags its maintainers set. A version that is not there is checked against the package's
        page on opam.ocaml.org, so a removed version is told apart from an unknown package."""
        from cordon_scanner.ecosystems.packages.ocaml.opam_syntax import OpamDocument, OpamError
        from cordon_scanner.foundation.content import FileContent

        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+\-]{0,127}", name):
            raise RegistryError(f"{name} is not an opam package name")
        if version is not None and not re.fullmatch(r"[A-Za-z0-9_+.~\-]{1,64}", version):
            raise RegistryError(f"{version} is not an opam version")
        if version is None:
            RegistryHttp.text(f"{HOSTS['opam-site']}/packages/{name}/")
            return PackageFacts(name=name, version=None)
        try:
            text = RegistryHttp.text(f"{HOSTS['opam']}/packages/{name}/{name}.{version}/opam")
        except PackageNotFound:
            # The package page answers for the name; a 404 here is an unknown package.
            RegistryHttp.text(f"{HOSTS['opam-site']}/packages/{name}/")
            return PackageFacts(
                name=name,
                version=version,
                yanked=True,
                yanked_reason="not a version opam-repository holds",
            )
        try:
            document = OpamDocument.load(FileContent.from_bytes("opam", text.encode()))
        except OpamError as exc:
            raise RegistryError("unreadable package definition from opam-repository") from exc
        digests: list[str] = []
        for section in document.fields.get("section:url", []):
            for entry in section.items:
                if entry.text != "checksum":
                    continue
                for node in entry.items:
                    values = node.items if node.kind == "list" else [node]
                    for value in values:
                        algorithm, _, digest = value.text.partition("=")
                        if (
                            value.kind == "str"
                            and algorithm in ("sha256", "sha512", "md5")
                            and re.fullmatch(r"[0-9a-fA-F]+", digest)
                        ):
                            digests.append(f"{algorithm}:{digest.lower()}")
        flags: set[str] = set()
        for node in document.fields.get("flags", []):
            for item in node.items if node.kind == "list" else [node]:
                if item.kind == "ident":
                    flags.add(item.text)
        return PackageFacts(
            name=name,
            version=version,
            yanked="avoid-version" in flags,
            yanked_reason="flagged avoid-version: the solver avoids it"
            if "avoid-version" in flags
            else None,
            repository=document.string("dev-repo"),
            digests=tuple(digests),
            deprecated="deprecated in opam-repository" if "deprecated" in flags else None,
        )

    @staticmethod
    def julia(name: str, version: str | None) -> PackageFacts:
        """The General registry, a git repository of TOML: `<L>/<Name>/Package.toml` (the
        package's UUID and repository, and `[metadata.deprecated]` when its maintainers retired
        it) and `Versions.toml` (every version's git-tree-sha1 -- the tree a manifest pins -- and
        `yanked`). Read from the repository's raw files; a package registered elsewhere is not
        found here, which is not evidence of anything."""
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", name):
            raise RegistryError(f"{name} is not a Julia package name")
        base_url = f"{HOSTS['julia']}/{name[0].upper()}/{name}"
        try:
            package = tomllib.loads(RegistryHttp.text(f"{base_url}/Package.toml"))
            versions = tomllib.loads(RegistryHttp.text(f"{base_url}/Versions.toml"))
        except tomllib.TOMLDecodeError as exc:
            raise RegistryError("unreadable registry entry from the General registry") from exc
        if package.get("name") != name:
            raise RegistryError("the General registry entry names another package")
        entry = RegistryHttp.mapping(versions.get(version)) if version else {}
        known = not version or version in versions
        tree = RegistryHttp.string(entry.get("git-tree-sha1"))
        metadata = RegistryHttp.mapping(package.get("metadata"))
        retired = (
            RegistryHttp.mapping(metadata.get("deprecated")) if "deprecated" in metadata else None
        )
        notice = None
        if retired is not None:
            alternative = RegistryHttp.string(retired.get("alternative"))
            notice = "deprecated in the General registry" + (
                f" in favour of {alternative}" if alternative else ""
            )
        reason = None
        if version and not known:
            reason = "not a version the General registry holds"
        elif entry.get("yanked") is True:
            reason = "yanked from the General registry"

        def order(v: str) -> tuple[int, ...]:
            return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.+-]", v))

        listed = sorted(
            (v for v in versions if not RegistryHttp.mapping(versions[v]).get("yanked")),
            key=order,
        )
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=listed[-1] if listed else None,
            repository=RegistryHttp.string(package.get("repo")),
            digests=(f"git-tree-sha1:{tree.lower()}",)
            if tree and re.fullmatch(r"[0-9a-fA-F]{40}", tree)
            else (),
            deprecated=notice,
            releases=len(versions),
        )

    @staticmethod
    def hackage(name: str, version: str | None) -> PackageFacts:
        """Hackage's JSON API: `preferred` (every version, and those the maintainer deprecated --
        the ones the solver avoids, Hackage's withdrawal), `deprecated` (the package as a whole,
        and what replaces it), and the version's metadata `revisions` with each revision's
        SHA-256 -- the cabal-file hash a Stack lock pins."""
        if not re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", name) or len(name) > 128:
            raise RegistryError(f"{name} is not a Hackage package name")
        preferred = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['hackage']}/package/{name}/preferred")
        )
        normal = [str(v) for v in preferred.get("normal-version") or () if isinstance(v, str)]
        withdrawn = [
            str(v) for v in preferred.get("deprecated-version") or () if isinstance(v, str)
        ]
        package = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['hackage']}/package/{name}/deprecated")
        )
        replacements = [str(r) for r in package.get("in-favour-of") or () if isinstance(r, str)]
        notice = None
        if package.get("is-deprecated") is True:
            notice = "deprecated on Hackage" + (
                f" in favour of {', '.join(replacements)}" if replacements else ""
            )
        digests: tuple[str, ...] = ()
        published = None
        known = True
        if version:
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
                raise RegistryError(f"{version} is not a Hackage version")
            known = version in normal or version in withdrawn
            if known:
                revisions = RegistryHttp.entries(
                    RegistryHttp.json(f"{HOSTS['hackage']}/package/{name}-{version}/revisions/")
                )
                digests = tuple(
                    f"sha256:{str(r['sha256']).lower()}"
                    for r in revisions
                    if isinstance(r.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-fA-F]{64}", r["sha256"])
                )
                times = sorted(str(r["time"]) for r in revisions if isinstance(r.get("time"), str))
                published = times[0] if times else None
        reason = None
        if version and not known:
            reason = "not a version Hackage published"
        elif version and version in withdrawn:
            reason = "deprecated by its maintainer: the solver avoids it"
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=normal[0] if normal else None,
            digests=digests,
            last_published=published,
            deprecated=notice,
            releases=len(normal) + len(withdrawn),
        )

    @staticmethod
    def conda(name: str, version: str | None) -> PackageFacts:
        """conda-forge's files on anaconda.org: every build of every version, each with its md5
        and sha256 and its labels. A version whose every build is labelled `broken` was withdrawn
        by conda-forge. A package conda-forge does not have may be another channel's (bioconda),
        so its absence is not checked, not reported as a missing package."""
        if not re.fullmatch(r"[a-z0-9_.\-]{1,128}", name):
            raise RegistryError(f"{name} is not a conda package name")
        try:
            files = RegistryHttp.entries(
                RegistryHttp.json(f"{HOSTS['conda']}/package/conda-forge/{name}/files")
            )
        except PackageNotFound as exc:
            raise RegistryError(
                f"{name} is not on conda-forge; other channels are not asked"
            ) from exc
        versions = sorted({str(f.get("version")) for f in files if f.get("version")})
        builds = [f for f in files if version and str(f.get("version")) == version]
        digests: list[str] = []
        for build in builds:
            for algorithm in ("sha256", "md5"):
                value = build.get(algorithm)
                if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32,64}", value):
                    digests.append(f"{algorithm}:{value}")
        broken = bool(builds) and all("broken" in (b.get("labels") or []) for b in builds)
        return PackageFacts(
            name=name,
            version=version,
            yanked=broken,
            yanked_reason="labelled broken by conda-forge" if broken else None,
            latest=versions[-1] if versions else None,
            digests=tuple(dict.fromkeys(digests)),
            releases=len(versions),
        )

    @staticmethod
    def cocoapods_shard(name: str) -> tuple[str, str, str]:
        """Trunk shards specs by the first three hex digits of the pod name's MD5."""
        import hashlib

        digest = hashlib.md5(name.encode("utf-8"), usedforsecurity=False).hexdigest()
        return digest[0], digest[1], digest[2]

    #: Where trunk's CDN now sends every podspec: a 301 to jsDelivr's mirror of the Specs repository
    #: (October 2026; the body hashes to the lock's SPEC CHECKSUMS value, as before).
    COCOAPODS_SPECS_MIRROR: Final = "https://cdn.jsdelivr.net/cocoa/Specs/"

    @staticmethod
    def cocoapods_spec(url: str) -> bytes:
        """A podspec, following trunk's one redirect to the Specs mirror and no other. Every
        spec request had answered 301, which the redirect-free reader refused: no CocoaPods lock
        was compared with its registry (YandexMobileMetrica, Alamofire, Firebase checked)."""
        try:
            return RegistryHttp.get(url)
        except Redirected as moved:
            if not moved.location.startswith(PackageRegistries.COCOAPODS_SPECS_MIRROR):
                raise
            return RegistryHttp.get(moved.location)

    @staticmethod
    def cocoapods(name: str, version: str | None) -> PackageFacts:
        """CocoaPods trunk's CDN: the shard's `all_pods_versions_<a>_<b>_<c>.txt` lists every
        version, and each version's podspec JSON is what `SPEC CHECKSUMS` hashes -- so its SHA-1
        is the digest a lock's checksum is compared with."""
        import hashlib

        if not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,128}", name) or (
            version and not re.fullmatch(r"[\w.+\-]{1,64}", version)
        ):
            raise RegistryError(f"{name} is not a pod name")
        a, b, c = PackageRegistries.cocoapods_shard(name)
        listing = RegistryHttp.text(f"{HOSTS['cocoapods']}/all_pods_versions_{a}_{b}_{c}.txt")
        versions: list[str] = []
        for line in listing.splitlines():
            parts = line.strip().split("/")
            if parts and parts[0] == name:
                versions = parts[1:]
                break
        else:
            raise PackageNotFound(f"{name} is not on CocoaPods trunk")
        digests: tuple[str, ...] = ()
        deprecated = None
        if version and version in versions:
            body = PackageRegistries.cocoapods_spec(
                f"{HOSTS['cocoapods']}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json"
            )
            digests = (f"sha1:{hashlib.sha1(body, usedforsecurity=False).hexdigest()}",)
            try:
                spec = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                spec = {}
            if isinstance(spec, dict) and spec.get("deprecated"):
                replacement = spec.get("deprecated_in_favor_of")
                deprecated = (
                    f"deprecated in favour of {replacement}"
                    if isinstance(replacement, str)
                    else "deprecated"
                )
        return PackageFacts(
            name=name,
            version=version,
            # Trunk keeps every version it published: a version missing from the listing while the
            # pod exists was deleted by its owner.
            yanked=bool(version) and version not in versions,
            # The listing is in text order, 9.6.0 after 12.x: the newest by version, not the last.
            latest=RegistryHttp.latest(versions),
            digests=digests,
            deprecated=deprecated,
            releases=len(versions),
        )

    @staticmethod
    def cargo(name: str, version: str | None) -> PackageFacts:
        document = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['cargo']}/api/v1/crates/{urllib.parse.quote(name, safe='')}")
        )
        crate = RegistryHttp.mapping(document.get("crate"))
        versions = RegistryHttp.entries(document.get("versions"))
        entry = next((v for v in versions if v.get("num") == version), {}) if version else {}
        checksum = RegistryHttp.string(entry.get("checksum"))
        return PackageFacts(
            name=name,
            version=version,
            yanked=bool(entry.get("yanked")),
            yanked_reason=RegistryHttp.string(entry.get("yank_message")),
            latest=RegistryHttp.string(crate.get("max_stable_version"))
            or RegistryHttp.string(crate.get("newest_version")),
            repository=RegistryHttp.string(crate.get("repository")),
            digests=(checksum,) if checksum else (),
            first_published=RegistryHttp.string(crate.get("created_at")),
            releases=len(versions),
        )

    @staticmethod
    def rubygems(name: str, version: str | None) -> PackageFacts:
        quoted = urllib.parse.quote(name, safe="")
        gem = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['rubygems']}/api/v1/gems/{quoted}.json")
        )
        versions = RegistryHttp.entries(
            RegistryHttp.json(f"{HOSTS['rubygems']}/api/v1/versions/{quoted}.json")
        )

        def matches(v: dict[str, Any]) -> bool:
            number, platform = str(v.get("number", "")), str(v.get("platform", "ruby"))
            return version in (number, f"{number}-{platform}")

        builds = [v for v in versions if matches(v)] if version else []
        # RubyGems removes a yanked version from this list: a version the gem no longer lists, while
        # the gem itself exists, is one its owner withdrew.
        yanked = bool(version) and not builds
        created = [str(v["created_at"]) for v in versions if isinstance(v.get("created_at"), str)]
        return PackageFacts(
            name=name,
            version=version,
            yanked=yanked,
            yanked_reason="no longer listed on rubygems.org" if yanked else None,
            latest=RegistryHttp.string(gem.get("version")),
            repository=RegistryHttp.string(gem.get("source_code_uri"))
            or RegistryHttp.string(gem.get("homepage_uri")),
            digests=tuple(str(v["sha"]) for v in builds if isinstance(v.get("sha"), str)),
            first_published=min(created) if created else None,
            releases=len({v.get("number") for v in versions}),
        )

    @staticmethod
    def _nuget_allowed(url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname != "api.nuget.org":
            raise RegistryError("NuGet named a page outside api.nuget.org; it was not fetched")
        return url

    @staticmethod
    def nuget(name: str, version: str | None) -> PackageFacts:
        package_id = name.lower()
        index = RegistryHttp.mapping(
            RegistryHttp.json(
                f"{HOSTS['nuget']}/v3/registration5-gz-semver2/{urllib.parse.quote(package_id, safe='')}/index.json"
            )
        )
        leaves: list[dict[str, Any]] = []
        for page in RegistryHttp.entries(index.get("items"))[:50]:
            items = page.get("items")
            if not isinstance(items, list):
                url = RegistryHttp.string(page.get("@id"))
                if url is None:
                    continue
                items = RegistryHttp.mapping(
                    RegistryHttp.json(PackageRegistries._nuget_allowed(url))
                ).get("items")
            for item in RegistryHttp.entries(items):
                entry = RegistryHttp.mapping(item.get("catalogEntry"))
                if entry:
                    leaves.append(entry)

        def same(v: Any) -> bool:
            return isinstance(v, str) and version is not None and v.lower() == version.lower()

        entry = next((e for e in leaves if same(e.get("version"))), {})
        listed = entry.get("listed", True) is not False
        deprecation = RegistryHttp.mapping(entry.get("deprecation"))
        reasons = [str(r) for r in deprecation.get("reasons") or [] if isinstance(r, str)]
        digest: tuple[str, ...] = ()
        leaf_url = RegistryHttp.string(entry.get("@id"))
        if leaf_url:
            leaf = RegistryHttp.mapping(
                RegistryHttp.json(PackageRegistries._nuget_allowed(leaf_url))
            )
            algorithm = str(leaf.get("packageHashAlgorithm", "")).lower()
            package_hash = RegistryHttp.string(leaf.get("packageHash"))
            if package_hash and algorithm in ("sha512", "sha256"):
                digest = (f"{algorithm}-{package_hash}",)
        stable = [
            str(e["version"])
            for e in leaves
            if isinstance(e.get("version"), str)
            and e.get("listed", True) is not False
            and "-" not in str(e["version"])
        ]
        # An unlisted package reports `published` as 1900-01-01: not a date, so not counted.
        published = sorted(
            str(e["published"])
            for e in leaves
            if isinstance(e.get("published"), str) and not str(e["published"]).startswith("1900")
        )
        reason = None
        if not listed:
            reason = "unlisted on nuget.org" + (
                f"; deprecated: {', '.join(reasons)}" if reasons else ""
            )
        return PackageFacts(
            name=name,
            version=version,
            yanked=bool(version) and bool(entry) and not listed,
            yanked_reason=reason,
            latest=stable[-1] if stable else None,
            repository=RegistryHttp.string(entry.get("projectUrl")),
            digests=digest,
            first_published=published[0] if published else None,
            releases=len(leaves),
        )

    @staticmethod
    def go_escape(path: str) -> str:
        return "".join(f"!{c.lower()}" if "A" <= c <= "Z" else c for c in path)

    @staticmethod
    def retractions(go_mod: str) -> dict[str, str]:
        """`version -> rationale` for every version a go.mod retracts, single or in ranges.
        Ranges are expanded against nothing: they are returned as `lo..hi` keys for `retracted`."""
        out: dict[str, str] = {}
        text = re.sub(r"(?s)/\*.*?\*/", "", go_mod)
        blocks = re.findall(r"(?ms)^\s*retract\s*\((.*?)^\s*\)", text)
        singles = re.findall(r"(?m)^\s*retract\s+([^(\n][^\n]*)$", text)
        for line in [ln for block in blocks for ln in block.splitlines()] + singles:
            body, _, comment = line.partition("//")
            body = body.strip()
            rationale = comment.strip()
            if not body:
                continue
            ranged = re.match(r"^\[\s*(v[^\s,\]]+)\s*,\s*(v[^\s,\]]+)\s*\]$", body)
            if ranged:
                out[f"{ranged.group(1)}..{ranged.group(2)}"] = rationale
            elif re.match(r"^v\S+$", body):
                out[body] = rationale
        return out

    @staticmethod
    def retracted(version: str, retractions: dict[str, str]) -> str | None:
        """The rationale when `version` is retracted, single or within a range; else None."""
        if version in retractions:
            return retractions[version] or "retracted by its author"
        key = PackageRegistries._semver_key(version)
        if key is None:
            return None
        for span, rationale in retractions.items():
            if ".." not in span:
                continue
            low, high = (PackageRegistries._semver_key(v) for v in span.split("..", 1))
            if low is not None and high is not None and low <= key <= high:
                return rationale or "retracted by its author"
        return None

    @staticmethod
    def _semver_key(version: str) -> tuple[Any, ...] | None:
        match = re.match(
            r"^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", version
        )
        if not match:
            return None
        major, minor, patch, pre = match.groups()
        ids = (
            tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
            if pre
            else ()
        )
        return (int(major), int(minor), int(patch), 0 if pre else 1, ids)

    @staticmethod
    def gomod(name: str, version: str | None) -> PackageFacts:
        module = PackageRegistries.go_escape(name)
        # Cordon records Go versions as OSV does, without the `v` (`0.9.1`); the proxy and the
        # checksum database answer only for the canonical `v0.9.1`, and refused every lookup with
        # HTTP 400 -- so no Go module's go.sum hash was ever compared with the log.
        canonical = version if not version or version.startswith("v") else f"v{version}"
        listing = [
            v.strip()
            for v in RegistryHttp.text(f"{HOSTS['gomod']}/{module}/@v/list").splitlines()
            if v.strip()
        ]
        latest = RegistryHttp.string(
            RegistryHttp.mapping(RegistryHttp.json(f"{HOSTS['gomod']}/{module}/@latest")).get(
                "Version"
            )
        )
        rationale = None
        if latest and canonical:
            try:
                go_mod = RegistryHttp.text(
                    f"{HOSTS['gomod']}/{module}/@v/{PackageRegistries.go_escape(latest)}.mod"
                )
            except PackageNotFound:
                go_mod = ""
            rationale = PackageRegistries.retracted(
                canonical, PackageRegistries.retractions(go_mod)
            )
        digests: tuple[str, ...] = ()
        if canonical:
            try:
                lookup = RegistryHttp.text(
                    f"{HOSTS['gosum']}/lookup/{module}@{PackageRegistries.go_escape(canonical)}"
                )
            except PackageNotFound:
                lookup = ""
            digests = tuple(
                parts[2]
                for parts in (line.split() for line in lookup.splitlines())
                if len(parts) == 3 and parts[0] == name and parts[2].startswith("h1:")
            )
        repository = (
            f"https://{name}"
            if name.startswith(("github.com/", "gitlab.com/", "bitbucket.org/"))
            else None
        )
        return PackageFacts(
            name=name,
            version=version,
            yanked=rationale is not None,
            yanked_reason=rationale if rationale else None,
            latest=latest,
            repository=repository,
            digests=digests,
            releases=len(listing),
        )

    @staticmethod
    def maven(name: str, version: str | None) -> PackageFacts:
        group, _, artifact = name.partition(":")
        if not group or not artifact or "/" in name or ".." in name:
            raise RegistryError(f"{name} is not a Maven group:artifact")
        root = f"{HOSTS['maven']}/maven2/{group.replace('.', '/')}/{artifact}"
        metadata = RegistryHttp.get(f"{root}/maven-metadata.xml", accept="application/xml")
        versions = [v.decode() for v in _VERSION_TAG.findall(metadata)]
        tags = {kind.decode(): value.decode() for kind, value in _RELEASE_TAG.findall(metadata)}
        digests: tuple[str, ...] = ()
        attested = False
        repository: str | None = None
        if version and version in versions:
            stem = f"{root}/{version}/{artifact}-{version}.jar"
            # Every algorithm Central publishes, because a lockfile records one and a comparison
            # is only made within an algorithm: Gradle verification commonly records sha256 or
            # sha512, and older artefacts carry only sha1.
            found = []
            for algorithm in ("sha512", "sha256", "sha1"):
                try:
                    match = _DIGEST_LINE.match(RegistryHttp.text(f"{stem}.{algorithm}"))
                except RegistryError:
                    # Absent or unreachable: that algorithm is not compared, and the rest still are.
                    continue
                if match:
                    found.append(f"{algorithm}:{match.group(1).lower()}")
            digests = tuple(found)
            try:
                attested = isinstance(RegistryHttp.json(f"{stem}.sigstore.json"), dict)
            except RegistryError:
                attested = False
            repository = PackageRegistries.maven_scm(f"{root}/{version}/{artifact}-{version}.pom")
        return PackageFacts(
            name=name,
            version=version,
            # Maven Central never deletes a release, so nothing on it is ever withdrawn.
            yanked=False,
            latest=tags.get("release")
            or tags.get("latest")
            or (versions[-1] if versions else None),
            digests=digests,
            attested=attested,
            releases=len(versions),
            repository=repository,
        )

    @staticmethod
    def maven_scm(pom_url: str) -> str | None:
        """The source repository a published POM declares (`<scm><url>`, else `<url>`), the
        identity a Sigstore signature is tied to. Read structurally and never expanded
        (`core/safexml.py`); a POM that cannot be read declares nothing."""
        from cordon_scanner.foundation.formats.safexml import SafeXml, SafeXmlError

        try:
            root = SafeXml.parse(RegistryHttp.text(pom_url), source=pom_url)
        except (RegistryError, SafeXmlError):
            return None
        for path in (("scm", "url"), ("scm", "connection"), ("url",)):
            value = root.value(*path)
            if value:
                return value.removeprefix("scm:git:")
        return None

    @staticmethod
    def expand_minified(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Composer 2's minified metadata: each version lists only the keys that changed from the one
        before it, and `"__unset"` removes one. Expanded so every version is a whole record."""
        expanded: list[dict[str, Any]] = []
        current: dict[str, Any] = {}
        for entry in entries:
            current = dict(current)
            for key, value in entry.items():
                if value == "__unset":
                    current.pop(key, None)
                else:
                    current[key] = value
            expanded.append(current)
        return expanded

    @staticmethod
    def _stable(version: str) -> bool:
        lowered = version.lower()
        return not any(tag in lowered for tag in ("dev", "alpha", "beta", "rc", "-"))

    @staticmethod
    def composer(name: str, version: str | None) -> PackageFacts:
        vendor, _, package = name.lower().partition("/")
        if not vendor or not package or "/" in package or ".." in name:
            raise RegistryError(f"{name} is not a Composer vendor/package")
        document = RegistryHttp.mapping(
            RegistryHttp.json(
                f"{HOSTS['composer']}/p2/{urllib.parse.quote(vendor, safe='')}/{urllib.parse.quote(package, safe='')}.json"
            )
        )
        raw = RegistryHttp.mapping(document.get("packages")).get(name.lower())
        versions = PackageRegistries.expand_minified(RegistryHttp.entries(raw))
        development = version is None or version.startswith("dev-") or version.endswith("-dev")

        def same(entry: dict[str, Any]) -> bool:
            return version is not None and version in (
                entry.get("version"),
                entry.get("version_normalized"),
            )

        entry = next((e for e in versions if same(e)), {})
        # A Packagist version is a tag in the package's repository: one the list no longer carries,
        # while the package does, had its tag deleted after it was published. Development branches
        # are never in this list, so their absence means nothing.
        withdrawn = not development and bool(versions) and not entry
        dist = RegistryHttp.mapping(entry.get("dist"))
        shasum = RegistryHttp.string(dist.get("shasum"))
        stable = [
            str(e["version"])
            for e in versions
            if isinstance(e.get("version"), str) and PackageRegistries._stable(str(e["version"]))
        ]
        times = sorted(str(e["time"]) for e in versions if isinstance(e.get("time"), str))
        return PackageFacts(
            name=name,
            version=version,
            yanked=withdrawn,
            yanked_reason="no longer published on Packagist" if withdrawn else None,
            latest=stable[0] if stable else None,
            repository=RegistryHttp.string(
                RegistryHttp.mapping(
                    entry.get("source") or (versions[0].get("source") if versions else None)
                ).get("url")
            ),
            digests=(shasum,) if shasum else (),
            first_published=times[0] if times else None,
            releases=len(versions),
        )

    @staticmethod
    def pub(name: str, version: str | None) -> PackageFacts:
        document = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['pub']}/api/packages/{urllib.parse.quote(name, safe='')}")
        )
        versions = RegistryHttp.entries(document.get("versions"))
        latest = RegistryHttp.mapping(document.get("latest"))
        pubspec = RegistryHttp.mapping(latest.get("pubspec"))
        entry = next((v for v in versions if v.get("version") == version), {}) if version else {}
        digest = RegistryHttp.string(entry.get("archive_sha256"))
        published = sorted(
            str(v["published"]) for v in versions if isinstance(v.get("published"), str)
        )
        return PackageFacts(
            name=name,
            version=version,
            yanked=entry.get("retracted") is True,
            yanked_reason="retracted by its publisher" if entry.get("retracted") is True else None,
            latest=RegistryHttp.string(latest.get("version")),
            repository=RegistryHttp.string(pubspec.get("repository"))
            or RegistryHttp.string(pubspec.get("homepage")),
            digests=(f"sha256:{digest.lower()}",) if digest else (),
            first_published=published[0] if published else None,
            releases=len(versions),
        )

    @staticmethod
    def hex(name: str, version: str | None) -> PackageFacts:
        quoted = urllib.parse.quote(name, safe="")
        document = RegistryHttp.mapping(RegistryHttp.json(f"{HOSTS['hex']}/api/packages/{quoted}"))
        retirements = RegistryHttp.mapping(document.get("retirements"))
        retired = RegistryHttp.mapping(retirements.get(version)) if version else {}
        releases = RegistryHttp.entries(document.get("releases"))
        links = RegistryHttp.mapping(RegistryHttp.mapping(document.get("meta")).get("links"))
        repository = next(
            (
                str(links[k])
                for k in links
                if isinstance(links[k], str)
                and k.lower() in ("github", "gitlab", "source", "repository")
            ),
            None,
        )
        digests: tuple[str, ...] = ()
        if version and any(r.get("version") == version for r in releases):
            release = RegistryHttp.mapping(
                RegistryHttp.json(
                    f"{HOSTS['hex']}/api/packages/{quoted}/releases/{urllib.parse.quote(version, safe='')}"
                )
            )
            checksum = RegistryHttp.string(release.get("checksum"))
            digests = (f"sha256:{checksum.lower()}",) if checksum else ()
        reason = None
        if retired:
            reason = (
                " - ".join(
                    str(retired[k])
                    for k in ("reason", "message")
                    if isinstance(retired.get(k), str) and retired[k]
                )
                or "retired by its owner"
            )
        return PackageFacts(
            name=name,
            version=version,
            yanked=bool(retired),
            yanked_reason=reason,
            latest=RegistryHttp.string(document.get("latest_stable_version"))
            or RegistryHttp.string(document.get("latest_version")),
            repository=repository,
            digests=digests,
            first_published=RegistryHttp.string(document.get("inserted_at")),
            releases=len(releases),
        )


__all__ = ["PackageRegistries"]
