"""Facts the infrastructure registries give: Homebrew, the Bazel Central Registry, Helm repositories
and OCI charts, the Terraform registry and its provider checksums, Ansible Galaxy, GitHub Actions
tags, vcpkg and Conan Center.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from cordon_scanner.intel.registries.registry_client import (
    PackageFacts,
    PackageNotFound,
    RegistryError,
)
from cordon_scanner.intel.registries.registry_hosts import (
    HOSTS,
)
from cordon_scanner.intel.registries.registry_http import RegistryHttp


class InfraRegistries:
    """Facts from infrastructure registries."""

    @staticmethod
    def homebrew(name: str, version: str | None) -> PackageFacts:
        """formulae.brew.sh: a formula's current version, its source checksum and every bottle's
        (what Brewfile.lock.json records), and whether it is deprecated or disabled; a name that is
        not a formula is looked up as a cask. Homebrew keeps one version of each formula: an older
        one is not on the registry any more."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@+._\-]{0,127}", name):
            raise RegistryError(f"{name} is not a formula or cask name")
        try:
            data = RegistryHttp.mapping(
                RegistryHttp.json(f"{HOSTS['homebrew']}/api/formula/{name}.json")
            )
            current = str(RegistryHttp.mapping(data.get("versions")).get("stable") or "") or None
            stable = RegistryHttp.mapping(RegistryHttp.mapping(data.get("urls")).get("stable"))
            found = [stable["checksum"]] if isinstance(stable.get("checksum"), str) else []
            bottle = RegistryHttp.mapping(RegistryHttp.mapping(data.get("bottle")).get("stable"))
            for file in RegistryHttp.mapping(bottle.get("files")).values():
                digest = RegistryHttp.mapping(file).get("sha256")
                if isinstance(digest, str):
                    found.append(digest)
            homepage = data.get("homepage")
        except PackageNotFound:
            data = RegistryHttp.mapping(
                RegistryHttp.json(f"{HOSTS['homebrew']}/api/cask/{name}.json")
            )
            current = str(data.get("version") or "") or None
            found = (
                [data["sha256"]]
                if isinstance(data.get("sha256"), str) and data["sha256"] != "no_check"
                else []
            )
            homepage = data.get("homepage")
        revision = data.get("revision")
        installed = version.split("_", 1)[0] if version else None
        digests = (
            tuple(f"sha256:{d}" for d in found if re.fullmatch(r"[0-9a-f]{64}", d))
            if installed == current
            else ()
        )
        reason = None
        if data.get("disabled"):
            reason = f"disabled: {data.get('disable_reason') or 'no longer installable'}"
        elif data.get("deprecated"):
            reason = f"deprecated: {data.get('deprecation_reason') or 'no reason given'}"
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=f"{current}_{revision}"
            if current and isinstance(revision, int) and revision
            else current,
            repository=homepage if isinstance(homepage, str) else None,
            digests=digests,
            releases=1,
        )

    @staticmethod
    def bazel(name: str, version: str | None) -> PackageFacts:
        """The Bazel Central Registry: a module's metadata.json (its versions, the ones yanked and
        why, its repository) and the version's source.json -- whose SHA-256 is what a Bazel 7.2+
        lock records, and whose `integrity` is the archive's, which an older lock records."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9._\-]{0,127}", name):
            raise RegistryError(f"{name} is not a Bazel module name")
        if version is not None and not re.fullmatch(r"[A-Za-z0-9._+\-]{1,64}", version):
            raise RegistryError(f"{version} is not a module version")
        metadata = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['bazel']}/modules/{name}/metadata.json")
        )
        versions = [str(v) for v in metadata.get("versions") or [] if isinstance(v, str)]
        yanked = RegistryHttp.mapping(metadata.get("yanked_versions"))
        repository = next(
            (str(r) for r in metadata.get("repository") or [] if isinstance(r, str)), None
        )
        if repository and repository.startswith("github:"):
            repository = f"https://github.com/{repository.removeprefix('github:')}"
        digests: tuple[str, ...] = ()
        if version is not None and version in versions:
            import hashlib

            raw = RegistryHttp.get(f"{HOSTS['bazel']}/modules/{name}/{version}/source.json")
            found = [f"sha256:{hashlib.sha256(raw).hexdigest()}"]
            try:
                integrity = RegistryHttp.mapping(json.loads(raw)).get("integrity")
            except (json.JSONDecodeError, ValueError):
                integrity = None
            if isinstance(integrity, str):
                found.append(integrity)
            digests = tuple(found)
        reason = None
        if version is not None and version not in versions:
            reason = "not a version the registry holds"
        elif version is not None and version in yanked:
            reason = f"yanked: {yanked[version]}" if isinstance(yanked[version], str) else "yanked"
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=RegistryHttp.latest([v for v in versions if v not in yanked]),
            repository=repository,
            digests=digests,
            releases=len(versions),
        )

    @staticmethod
    def helm(name: str, version: str | None, source: str | None = None) -> PackageFacts:
        """A chart's own repository -- Helm has no central one. Over HTTPS, the repository's
        index.yaml: every version, its digest (the archive's SHA-256, which a downloaded chart in
        charts/ is hashed to), and `deprecated`. Over OCI, the registry's tags and the chart
        layer's digest, which is the same SHA-256. A chart from a repository named only (`@name`)
        or from the project itself has no repository to ask: nothing is claimed about it."""
        if not re.fullmatch(r"[A-Za-z0-9][\w.\-]{0,127}", name):
            raise RegistryError(f"{name} is not a chart name")
        if version is not None and not re.fullmatch(r"[A-Za-z0-9][\w.+\-]{0,63}", version):
            raise RegistryError(f"{version} is not a chart version")
        if source and source.startswith("oci://"):
            return InfraRegistries._helm_oci(name, version, source)
        if not source or not source.startswith("https://"):
            return PackageFacts(name=name, version=version)
        from cordon_scanner.foundation.formats.datayaml import DataYaml

        text = RegistryHttp.text(f"{source.rstrip('/')}/index.yaml")
        try:
            index = DataYaml.load(text, source="index.yaml")
        except ValueError as exc:
            raise RegistryError("an unreadable chart repository index") from exc
        entries = RegistryHttp.mapping(RegistryHttp.mapping(index).get("entries"))
        listed = RegistryHttp.entries(entries.get(name))
        if not listed:
            raise PackageNotFound(f"the repository lists no chart {name}")
        entry = next((e for e in listed if str(e.get("version")) == version), None)
        digest = RegistryHttp.string(entry.get("digest")) if entry else None
        return PackageFacts(
            name=name,
            version=version,
            yanked=version is not None and entry is None,
            yanked_reason="not a version the repository's index lists"
            if version is not None and entry is None
            else None,
            latest=RegistryHttp.latest([str(e.get("version")) for e in listed if e.get("version")]),
            digests=(f"sha256:{digest.lower()}",)
            if digest and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
            else (),
            deprecated="deprecated in its repository"
            if entry and entry.get("deprecated") is True
            else None,
            releases=len(listed),
        )

    @staticmethod
    def _helm_oci(name: str, version: str | None, source: str) -> PackageFacts:
        host, _, path = source.removeprefix("oci://").partition("/")
        if not re.fullmatch(r"[a-z0-9.\-]+(?::\d+)?", host) or ".." in path:
            raise RegistryError("not an OCI registry reference")
        repository = f"{path.strip('/')}/{name}" if path.strip("/") else name
        tags = RegistryHttp.mapping(
            RegistryHttp.oci(f"https://{host}/v2/{repository}/tags/list", "application/json")
        )
        # helm `pkg/registry/reference.go` pushes version `1.0.0+build` as tag `1.0.0_build`, and
        # reads a tag back with `_` as `+` (`client.go`, Tags).
        listed = [str(t).replace("_", "+") for t in tags.get("tags") or [] if isinstance(t, str)]
        if not listed:
            raise PackageNotFound(f"{host} has no chart {repository}")
        digests: tuple[str, ...] = ()
        if version is not None and version in listed:
            manifest = RegistryHttp.mapping(
                RegistryHttp.oci(
                    f"https://{host}/v2/{repository}/manifests/{version.replace('+', '_')}",
                    "application/vnd.oci.image.manifest.v1+json",
                )
            )
            layers = RegistryHttp.entries(manifest.get("layers"))
            chart = [
                str(layer["digest"])
                for layer in layers
                # The chart layer's media type, and the legacy one older charts were pushed with.
                if (
                    "helm.chart.content" in str(layer.get("mediaType"))
                    or layer.get("mediaType") == "application/tar+gzip"
                )
                and isinstance(layer.get("digest"), str)
            ]
            digests = tuple(d.lower() for d in chart if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", d))
        return PackageFacts(
            name=name,
            version=version,
            yanked=version is not None and version not in listed,
            yanked_reason="not a tag the registry holds"
            if version is not None and version not in listed
            else None,
            latest=RegistryHttp.latest(listed),
            digests=digests,
            releases=len(listed),
        )

    @staticmethod
    def terraform(name: str, version: str | None) -> PackageFacts:
        """The Terraform registry: a provider's versions and the SHA-256 of every platform's zip
        (what a lock's `zh:` hashes are), or a module's versions and its deprecation. Every
        platform's hash is gathered -- from the release's SHA256SUMS, or one platform at a time --
        because a lock records several, and comparing against one platform's alone would call
        every other one a mismatch."""
        parts = name.split("/")
        if not all(re.fullmatch(r"[A-Za-z0-9][\w\-]{0,63}", p) for p in parts) or len(
            parts
        ) not in (2, 3):
            raise RegistryError(f"{name} is not a registry provider or module address")
        if version is not None and not re.fullmatch(r"[0-9A-Za-z.+\-]{1,64}", version):
            raise RegistryError(f"{version} is not a version")
        if len(parts) == 3:
            document = RegistryHttp.mapping(
                RegistryHttp.json(f"{HOSTS['terraform']}/v1/modules/{name}/versions")
            )
            modules = RegistryHttp.entries(document.get("modules"))
            versions = RegistryHttp.entries(modules[0].get("versions")) if modules else []
            listed = [str(v.get("version")) for v in versions if v.get("version")]
            entry = next((v for v in versions if v.get("version") == version), None)
            notice = (
                RegistryHttp.mapping(entry.get("deprecation"))
                if entry and isinstance(entry.get("deprecation"), dict)
                else {}
            )
            return PackageFacts(
                name=name,
                version=version,
                yanked=version is not None and entry is None,
                yanked_reason="not a version the registry holds"
                if version is not None and entry is None
                else None,
                latest=RegistryHttp.latest(listed),
                deprecated=(
                    "deprecated on the registry"
                    + (f": {notice['reason']}" if isinstance(notice.get("reason"), str) else "")
                )
                if notice
                else None,
                releases=len(listed),
            )
        document = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['terraform']}/v1/providers/{name}/versions")
        )
        versions = RegistryHttp.entries(document.get("versions"))
        listed = [str(v.get("version")) for v in versions if v.get("version")]
        entry = next((v for v in versions if v.get("version") == version), None)
        digests: tuple[str, ...] = ()
        if entry is not None:
            digests = InfraRegistries._provider_digests(
                name, str(version), RegistryHttp.entries(entry.get("platforms"))
            )
        return PackageFacts(
            name=name,
            version=version,
            yanked=version is not None and entry is None,
            yanked_reason="not a version the registry holds"
            if version is not None and entry is None
            else None,
            latest=RegistryHttp.latest(listed),
            digests=digests,
            releases=len(listed),
        )

    @staticmethod
    def _provider_digests(
        name: str, version: str, platforms: list[dict[str, Any]]
    ) -> tuple[str, ...]:
        found: set[str] = set()
        for platform in platforms[: RegistryHttp.MAX_PLATFORMS]:
            os_name, arch = platform.get("os"), platform.get("arch")
            if not (
                isinstance(os_name, str)
                and isinstance(arch, str)
                and re.fullmatch(r"[a-z0-9_]+", os_name + arch)
            ):
                continue
            download = RegistryHttp.mapping(
                RegistryHttp.json(
                    f"{HOSTS['terraform']}/v1/providers/{name}/{version}/download/{os_name}/{arch}"
                )
            )
            if not found and isinstance(download.get("shasums_url"), str):
                try:
                    sums = RegistryHttp.text(download["shasums_url"])
                except RegistryError:
                    sums = ""
                listed = {
                    line.split()[0].lower()
                    for line in sums.splitlines()
                    if re.match(r"^[0-9a-fA-F]{64}\s", line)
                }
                if listed:
                    return tuple(sorted(f"sha256:{s}" for s in listed))
            shasum = download.get("shasum")
            if isinstance(shasum, str) and re.fullmatch(r"[0-9a-fA-F]{64}", shasum):
                found.add(shasum.lower())
        return tuple(sorted(f"sha256:{s}" for s in found))

    @staticmethod
    def ansible(name: str, version: str | None) -> PackageFacts:
        """Galaxy: a collection's index (its highest version, and whether it is deprecated) and
        the version's artefact SHA-256 from the v3 API; failing that, a role's versions from the
        v1 API. `namespace.name` names either, so the collection is asked first."""
        found = re.fullmatch(r"([A-Za-z0-9_]{1,64})\.([A-Za-z0-9_\-]{1,100})", name)
        if not found:
            raise RegistryError(f"{name} is not a Galaxy namespace.name")
        namespace, short = found.groups()
        if version is not None and not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,64}", version):
            raise RegistryError(f"{version} is not a Galaxy version")
        index_url = f"{HOSTS['ansible']}/api/v3/plugin/ansible/content/published/collections/index/{namespace}/{short}/"
        try:
            index = RegistryHttp.mapping(RegistryHttp.json(index_url))
        except PackageNotFound:
            return InfraRegistries._galaxy_role(namespace, short, name, version)
        highest = RegistryHttp.mapping(index.get("highest_version"))
        digests: tuple[str, ...] = ()
        missing = False
        if version is not None:
            try:
                detail = RegistryHttp.mapping(RegistryHttp.json(f"{index_url}versions/{version}/"))
            except PackageNotFound:
                missing = True
            else:
                artifact = RegistryHttp.mapping(detail.get("artifact"))
                digest = RegistryHttp.string(artifact.get("sha256"))
                digests = (
                    (f"sha256:{digest.lower()}",)
                    if digest and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
                    else ()
                )
        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="not a version Galaxy holds" if missing else None,
            latest=RegistryHttp.string(highest.get("version")),
            digests=digests,
            first_published=RegistryHttp.string(index.get("created_at")),
            last_published=RegistryHttp.string(index.get("updated_at")),
            deprecated="deprecated on Galaxy" if index.get("deprecated") is True else None,
        )

    @staticmethod
    def _galaxy_role(namespace: str, short: str, name: str, version: str | None) -> PackageFacts:
        listing = RegistryHttp.mapping(
            RegistryHttp.json(
                f"{HOSTS['ansible']}/api/v1/roles/?owner__username={namespace}&name={urllib.parse.quote(short)}"
            )
        )
        results = RegistryHttp.entries(listing.get("results"))
        if not results:
            raise PackageNotFound(f"Galaxy has no collection or role {name}")
        role = results[0]
        summary = RegistryHttp.mapping(role.get("summary_fields"))
        versions = [
            str(v.get("name")).lstrip("v")
            for v in RegistryHttp.entries(summary.get("versions"))
            if v.get("name")
        ]
        missing = version is not None and version.lstrip("v") not in versions
        user, repository = (
            RegistryHttp.string(role.get("github_user")),
            RegistryHttp.string(role.get("github_repo")),
        )

        def order(v: str) -> tuple[int, ...]:
            return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.+\-]", v))

        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="not a version Galaxy lists for the role" if missing else None,
            latest=max(versions, key=order) if versions else None,
            repository=f"https://github.com/{user}/{repository}" if user and repository else None,
            releases=len(versions),
        )

    @staticmethod
    def tags(advertisement: bytes) -> dict[str, str]:
        """`tag -> commit` from git's smart-HTTP ref advertisement (pkt-lines), annotated tags
        peeled to the commit they name."""
        out: dict[str, str] = {}
        index = 0
        while index + 4 <= len(advertisement):
            try:
                length = int(advertisement[index : index + 4], 16)
            except ValueError as exc:
                raise RegistryError("an unreadable ref advertisement") from exc
            if length == 0:
                index += 4
                continue
            if length < 4 or index + length > len(advertisement):
                raise RegistryError("an unreadable ref advertisement")
            line = (
                advertisement[index + 4 : index + length]
                .split(b"\0", 1)[0]
                .decode("ascii", "replace")
                .strip()
            )
            index += length
            sha, _, ref = line.partition(" ")
            if not ref.startswith("refs/tags/") or not re.fullmatch(r"[0-9a-f]{40}", sha):
                continue
            tag = ref.removeprefix("refs/tags/")
            if tag.endswith("^{}"):
                out[tag[:-3]] = sha  # the commit an annotated tag names
            else:
                out.setdefault(tag, sha)
        return out

    @staticmethod
    def actions(name: str, version: str | None) -> PackageFacts:
        """The action repository's tags, read the way git reads them (no API, no rate limit): the
        commit the release tag names is what a SHA pin must equal -- so a `# vX.Y.Z` comment that
        does not match its commit is caught."""
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\-]{0,38}/[A-Za-z0-9._\-]{1,100}", name)
            or ".." in name
        ):
            raise RegistryError(f"{name} is not an owner/repository")
        try:
            advertisement = RegistryHttp.get(
                f"{HOSTS['actions']}/{name}.git/info/refs?service=git-upload-pack", accept="*/*"
            )
        except RegistryError as exc:
            # GitHub asks for credentials, rather than answering 404, for a repository that does
            # not exist (or is private).
            if str(exc).startswith("HTTP 401"):
                raise PackageNotFound(f"github.com has no public repository {name}") from exc
            raise
        tags = InfraRegistries.tags(advertisement)

        def release(tag: str) -> tuple[int, ...] | None:
            found = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
            return tuple(int(p) for p in found.groups()) if found else None

        releases = {tag: key for tag in tags if (key := release(tag)) is not None}
        commit = None
        if version is not None:
            commit = tags.get(f"v{version}") or tags.get(version)
        missing = version is not None and commit is None
        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="no tag of the repository names this release" if missing else None,
            latest=max(releases, key=releases.__getitem__).lstrip("v") if releases else None,
            repository=f"https://github.com/{name}",
            digests=(commit,) if commit else (),
            releases=len(releases),
        )

    @staticmethod
    def vcpkg(name: str, version: str | None) -> PackageFacts:
        """The builtin registry's version database, `versions/<x>-/<port>.json`: every version and
        port-version of the port with the git-tree it builds from. Read at the registry's tip."""
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 128:
            raise RegistryError(f"{name} is not a vcpkg port name")
        document = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['vcpkg']}/versions/{name[0]}-/{name}.json")
        )
        versions = RegistryHttp.entries(document.get("versions"))

        def named(entry: dict[str, Any]) -> str | None:
            for key in ("version", "version-semver", "version-date", "version-string"):
                if isinstance(entry.get(key), str):
                    return str(entry[key])
            return None

        listed = [named(v) for v in versions]
        matching = [v for v in versions if version is not None and named(v) == version]
        digests = tuple(
            f"git-tree-sha1:{str(v['git-tree']).lower()}"
            for v in matching
            if isinstance(v.get("git-tree"), str)
            and re.fullmatch(r"[0-9a-fA-F]{40}", v["git-tree"])
        )
        missing = version is not None and not matching
        return PackageFacts(
            name=name,
            version=version,
            yanked=missing,
            yanked_reason="not a version the vcpkg registry holds" if missing else None,
            latest=next((v for v in listed if v), None),
            digests=digests,
            releases=len({v for v in listed if v}),
        )

    @staticmethod
    def conan(name: str, version: str | None) -> PackageFacts:
        """ConanCenter's v2 API: `search` for the versions it holds, and a version's recipe
        `revisions` -- each the MD5 of the recipe's manifest, which a lock pins. ConanCenter has
        no user/channel namespaces, so only plain references are asked about."""
        if not re.fullmatch(r"[a-z0-9_][a-z0-9_+.\-]{0,100}", name):
            raise RegistryError(f"{name} is not a ConanCenter recipe name")
        found = RegistryHttp.mapping(
            RegistryHttp.json(f"{HOSTS['conan']}/v2/conans/search?q={urllib.parse.quote(name)}")
        )
        versions = [
            str(r).split("@")[0].partition("/")[2]
            for r in found.get("results") or ()
            if isinstance(r, str) and str(r).split("@")[0].partition("/")[0] == name
        ]
        if not versions:
            raise PackageNotFound(f"ConanCenter has no recipe {name}")

        def order(v: str) -> tuple[Any, ...]:
            return tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.+\-]", v))

        digests: tuple[str, ...] = ()
        published = None
        reason = None
        if version is not None:
            if not re.fullmatch(r"[A-Za-z0-9_+.\-]{1,100}", version):
                raise RegistryError(f"{version} is not a Conan version")
            if version not in versions:
                reason = "not a version ConanCenter holds"
            else:
                document = RegistryHttp.mapping(
                    RegistryHttp.json(f"{HOSTS['conan']}/v2/conans/{name}/{version}/_/_/revisions")
                )
                revisions = RegistryHttp.entries(document.get("revisions"))
                digests = tuple(
                    f"md5:{str(r['revision']).lower()}"
                    for r in revisions
                    if isinstance(r.get("revision"), str)
                    and re.fullmatch(r"[0-9a-fA-F]{32}", r["revision"])
                )
                times = sorted(str(r["time"]) for r in revisions if isinstance(r.get("time"), str))
                published = times[0] if times else None
        return PackageFacts(
            name=name,
            version=version,
            yanked=reason is not None,
            yanked_reason=reason,
            latest=max(versions, key=order),
            digests=digests,
            last_published=published,
            releases=len(versions),
        )


__all__ = ["InfraRegistries"]
