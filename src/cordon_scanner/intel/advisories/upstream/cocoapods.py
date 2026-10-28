"""CocoaPods: the pods built beside each other, and the podspecs npm packages ship (React Native)."""

from __future__ import annotations

import collections
import http.client
import io
import json
import re
import tarfile
import urllib.parse
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.intel.advisories.upstream.base import (
    RepositoryArchive,
    Unnamed,
    Upstream,
)
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.inference import Inference
from cordon_scanner.intel.advisories.upstream.tags import TagInference

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from cordon_scanner.foundation.results import Dependency


class PodSiblings:
    """A binary pod published from the repository another pod of the same lockfile comes from.

    Firebase's FirebaseAnalytics and GoogleAppMeasurement are closed binaries on dl.google.com,
    but their podspecs live in github.com/firebase/firebase-ios-sdk beside FirebaseCore's, and are
    published from it at each release tag. So a pod whose trunk source is only a download is looked
    for in the repositories its lockfile's other pods resolved to, at tags that name its version
    (FirebaseCore 10.6.0 is at `CocoaPods-10.6.0`): `<repository>/<tag>/<Name>.podspec`. It is that
    release only if that podspec declares the locked version and names the very download trunk
    gives (`https://dl.google.com/firebase/ios/analytics/c549faaa5cd321b5/FirebaseAnalytics-10.6.0
    .tar.gz`) -- the same file, published from that commit."""

    MAX_CANDIDATES: ClassVar[int] = 6

    @staticmethod
    def http(text: str, version: str) -> str | None:
        """A podspec's `source = { :http => '...' }`, `#{s.version}` read as the version."""
        found = re.search(r"\.source\s*=\s*\{((?:[^{}]|#\{[^{}]*\})*)\}", text)
        if not found:
            return None
        for entry in NpmPodspec.FIELD.finditer(found.group(1)):
            if (entry.group(1) or entry.group(2)) == "http":
                value = entry.group(3) if entry.group(3) is not None else entry.group(4)
                if value is not None:
                    return re.sub(r"#\{\w+\.version(?:\.to_s)?\}", version, value)
        return None

    @staticmethod
    def resolve(
        dependencies: Sequence[Dependency], answers: Sequence[Upstream | Unnamed]
    ) -> list[Upstream | Unnamed]:
        tags: dict[str, set[str]] = collections.defaultdict(set)
        for dependency, answer in zip(dependencies, answers, strict=True):
            if not isinstance(answer, Upstream):
                continue
            package = answer.query.get("package")
            if (
                dependency.ecosystem == "cocoapods"
                and isinstance(package, dict)
                and package.get("ecosystem") == "GIT"
                and str(package.get("name") or "").startswith("https://github.com/")
            ):
                tags[str(package["name"])].add(str(answer.query.get("version") or ""))
        out = list(answers)
        if not tags:
            return out
        for i, (dependency, answer) in enumerate(zip(dependencies, answers, strict=True)):
            if (
                dependency.ecosystem == "cocoapods"
                and dependency.resolved_from is None
                and dependency.version
                and isinstance(answer, Unnamed)
                and answer.reason.startswith(
                    ("its source is downloaded from", "a prebuilt binary", "an umbrella of headers")
                )
            ):
                try:
                    found = PodSiblings.find(dependency, tags)
                except (OSError, ValueError, http.client.HTTPException):
                    found = None
                if found is not None:
                    out[i] = found
                    # A fact of the pod at its version, whichever lockfile asks next.
                    Fetch.resolved[
                        (
                            dependency.ecosystem,
                            dependency.name,
                            dependency.version,
                            dependency.integrity,
                        )
                    ] = found
        return out

    @staticmethod
    def find(dependency: Dependency, tags: Mapping[str, set[str]]) -> Upstream | None:
        from cordon_scanner.intel.registries.package_registries import PackageRegistries
        from cordon_scanner.intel.registries.registry_client import PackageNotFound
        from cordon_scanner.intel.registries.registry_hosts import HOSTS

        name, version = dependency.name.split("/", 1)[0], dependency.version or ""
        if not re.fullmatch(r"[\w.+-]+", name):
            return None
        naming = re.compile(rf"(?<![\w.]){re.escape(version)}$")
        candidates = sorted(
            (repository, tag)
            for repository, refs in tags.items()
            for tag in refs
            if naming.search(tag)
        )[: PodSiblings.MAX_CANDIDATES]
        if not candidates:
            return None
        a, b, c = PackageRegistries.cocoapods_shard(name)
        spec = json.loads(
            PackageRegistries.cocoapods_spec(
                f"{HOSTS['cocoapods']}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json"
            )
        )
        source = spec.get("source") if isinstance(spec, dict) else None
        given = source.get("http") if isinstance(source, dict) else None
        if not isinstance(given, str) or not given:
            return None
        matched: list[tuple[str, str]] = []
        for repository, tag in candidates:
            raw = repository.replace("https://github.com/", "https://raw.githubusercontent.com/")
            try:
                text = Fetch.get(f"{raw}/{urllib.parse.quote(tag, safe='')}/{name}.podspec").decode(
                    "utf-8", "replace"
                )
            except PackageNotFound:
                continue
            if NpmPodspec.declared(text, version, {}) == version and (
                PodSiblings.http(text, version) == given
            ):
                matched.append((repository, tag))
        if not matched or len({repository for repository, _ in matched}) > 1:
            return None
        repository, tag = matched[0]
        return RepositoryArchive.upstream(
            repository,
            tag,
            f"the {name} {version} podspec, published from {repository} at {tag} with the same "
            "download",
        )


#: Where a React Native release pins the Hermes it was built from: a tag of facebook/hermes whose
#: name ends in its commit (`hermes-2024-11-12-RNv0.76.2-5b4aa20c...`).
HERMES_PIN: Final = "sdks/.hermesversion"


#: The Hermes versions React Native 0.83 and later build or download (`HERMES_VERSION_NAME`, and
#: `HERMES_V1_VERSION_NAME` for Hermes V1), which hermes-engine.podspec reads as its version.
HERMES_PROPERTIES: Final = "sdks/hermes-engine/version.properties"


class NpmPodspec:
    """A podspec installed from inside an npm package (React Native's `third-party-podspecs/
    DoubleConversion.podspec`), read from that package as the npm registry serves it.

    The CocoaPods reader names the package, the podspec's path in it, and the versions the pods at
    the package's own root are at (React Native's `React-Core` is versioned as the package). For
    each, the registry's tarball is checked against the SHA-512 the registry gives, and the podspec
    in it is used only if it declares the very version the lockfile locks; its `source` is then read
    as any podspec's. Values a podspec takes from the package's own Ruby helpers -- React Native's
    `glog_git_url = get_glog_config()[:git]`, defined as `@@glog_config = { :git => ... }` in its
    `scripts/cocoapods/helpers.rb` -- are read from that same release. Every version tried must
    agree."""

    NOTE: ClassVar[re.Pattern[str]] = re.compile(
        r"the podspec (\S+) of the npm package (\S+), at ([^\s]+(?: or [^\s]+){0,16})$"
    )
    REGISTRY: ClassVar[str] = "https://registry.npmjs.org"
    MAX_TARBALL: ClassVar[int] = 96 << 20
    MAX_TEXT: ClassVar[int] = 1 << 20
    #: `@@<name>_config = { :key => 'value', key: "value", ... }`, simple string values only.
    CONSTANT: ClassVar[re.Pattern[str]] = re.compile(r"@@(\w+_config)\s*=\s*\{([^{}]*)\}")
    #: The same hash returned by a method (React Native 0.74's `def self.folly_config` in
    #: `Helpers::Constants`, which `get_folly_config()` returns).
    METHOD: ClassVar[re.Pattern[str]] = re.compile(
        r"def self\.(\w+_config)\s*(?:\(\s*\))?\s*return\s*\{([^{}]*)\}\s*end"
    )
    #: Podspecs that are the package's own code, whatever source they compute: React Native's
    #: React-Core-prebuilt is its core, built from source or downloaded as the Maven artefact
    #: `com.facebook.react:react-native-artifacts` of the same version (`scripts/cocoapods/rncore.rb`).
    OWN_CODE: ClassVar[frozenset[tuple[str, str]]] = frozenset(
        {("react-native", "React-Core-prebuilt.podspec")}
    )
    FIELD: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?::(\w+)\s*=>|\b(\w+):)\s*(?:'([^']*)'|"([^"]*)"|(\w+)\b)"""
    )
    _packages: ClassVar[dict[tuple[str, str], dict[str, str] | None]] = {}

    @staticmethod
    def download(url: str) -> bytes:
        """The tarball's bytes as served -- not inflated, which the shared fetch does to a gzip
        answer: the registry's SHA-512 is over the file itself."""
        import urllib.request

        if not url.startswith("https://"):
            raise ValueError("not an https tarball")
        request = urllib.request.Request(  # noqa: S310 - https, from the registry's own record
            url, headers={"User-Agent": "cordon-scanner", "Accept-Encoding": "identity"}
        )
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            body: bytes = response.read(NpmPodspec.MAX_TARBALL + 1)
        if len(body) > NpmPodspec.MAX_TARBALL:
            raise ValueError("tarball too large")
        return body

    @staticmethod
    def package(package: str, version: str) -> dict[str, str] | None:
        """`path -> text` of the package's podspecs and Ruby scripts, from the registry's tarball
        once its SHA-512 matches the registry's record; None when it does not or cannot be read."""
        key = (package, version)
        if key in NpmPodspec._packages:
            return NpmPodspec._packages[key]
        import base64
        import hashlib

        meta = json.loads(
            Fetch.get(
                f"{NpmPodspec.REGISTRY}/{urllib.parse.quote(package, safe='@')}/"
                f"{urllib.parse.quote(version, safe='')}"
            )
        )
        dist = (meta or {}).get("dist") or {}
        tarball, integrity = str(dist.get("tarball") or ""), str(dist.get("integrity") or "")
        files: dict[str, str] | None = None
        if tarball.startswith("https://") and integrity.startswith("sha512-"):
            body = NpmPodspec.download(tarball)
            if hashlib.sha512(body).digest() == base64.b64decode(integrity.removeprefix("sha512-")):
                files = {}
                with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as archive:
                    for member in archive:
                        path = member.name.split("/", 1)[-1]
                        if member.isfile() and (
                            path.endswith((".podspec", ".rb"))
                            or path in (HERMES_PIN, HERMES_PROPERTIES)
                        ):
                            handle = archive.extractfile(member)
                            if handle is not None:
                                files[path] = handle.read(NpmPodspec.MAX_TEXT).decode(
                                    "utf-8", "replace"
                                )
        NpmPodspec._packages[key] = files
        return files

    @staticmethod
    def constants(files: Mapping[str, str]) -> dict[str, dict[str, str]]:
        """The `@@<name>_config` hashes the package's Ruby defines, by name."""
        out: dict[str, dict[str, str]] = {}
        for path, text in files.items():
            if not path.endswith(".rb"):
                continue
            for found in [*NpmPodspec.CONSTANT.finditer(text), *NpmPodspec.METHOD.finditer(text)]:
                out[found.group(1)] = {
                    m.group(1) or m.group(2): m.group(3) if m.group(3) is not None else m.group(4)
                    for m in NpmPodspec.FIELD.finditer(found.group(2))
                    if m.group(3) is not None or m.group(4) is not None
                }
        return out

    @staticmethod
    def variables(
        text: str, constants: Mapping[str, Mapping[str, str]], version: str = ""
    ) -> dict[str, str]:
        """`name = get_<x>_config()` and `name = <config>[:key]` lines, resolved; and
        `name = package['version']`, the package's own version."""
        configs = {
            m.group(1): m.group(2) + "_config"
            for m in re.finditer(r"^\s*(\w+)\s*=\s*get_(\w+)_config\(\)\s*$", text, re.MULTILINE)
        }
        # Literals first (`folly_release_version = '2021.06.28.00'`), then config lookups.
        out: dict[str, str] = {
            m.group(1): m.group(2) if m.group(2) is not None else m.group(3)
            for m in re.finditer(
                r"""^(\w+)\s*=\s*(?:'([^'#]*)'|"([^"#]*)")\s*$""", text, re.MULTILINE
            )
        }
        for m in re.finditer(r"^\s*(\w+)\s*=\s*(\w+)\[:(\w+)\]\s*$", text, re.MULTILINE):
            value = constants.get(configs.get(m.group(2), ""), {}).get(m.group(3))
            if value is not None:
                out[m.group(1)] = value
        if version:
            for m in re.finditer(
                r"""^\s*(\w+)\s*=\s*package\[['"]version['"]\]\s*$""", text, re.MULTILINE
            ):
                out[m.group(1)] = version
        return out

    @staticmethod
    def declared(text: str, version: str, variables: Mapping[str, str]) -> str | None:
        """The version the podspec declares: a literal, `package['version']`, or a variable."""
        found = re.search(
            r"""^\s*\w+\.version\s*=\s*(?:'([^']*)'|"([^"]*)"|package\[['"]version['"]\]|(\w+))\s*$""",
            text,
            re.MULTILINE,
        )
        joined = re.search(
            r"""^\s*\w+\.version\s*=\s*(\w+)\s*\+\s*(?:'([^']*)'|"([^"]*)")\s*$""",
            text,
            re.MULTILINE,
        )
        if joined and joined.group(1) in variables:
            # `folly_release_version + '-v2'`
            return variables[joined.group(1)] + (joined.group(2) or joined.group(3) or "")
        if not found:
            return None
        if found.group(1) is not None or found.group(2) is not None:
            return found.group(1) if found.group(1) is not None else found.group(2)
        if found.group(3):
            return variables.get(found.group(3))
        return version

    @staticmethod
    def source(
        text: str, locked: str, variables: Mapping[str, str], how: str
    ) -> Upstream | Unnamed:
        """The podspec's `source = { :git => ..., :tag|:commit => ... }` or `{ :http => ... }`:
        `#{<spec>.version}` is the locked version and a bare name a resolved variable; anything
        else computed is unknown, never guessed."""
        # The hash may hold interpolations (`"v#{spec.version}"`), whose braces are not its own.
        found = re.search(r"\.source\s*=\s*\{((?:[^{}]|#\{[^{}]*\})*)\}", text)
        if not found:
            return Unnamed("its podspec's source is computed")
        fields: dict[str, str] = {}
        for m in NpmPodspec.FIELD.finditer(found.group(1)):
            key = m.group(1) or m.group(2)
            if m.group(5) is not None:
                if m.group(5) not in variables:
                    return Unnamed(f"its podspec's source names {m.group(5)}, computed elsewhere")
                value = variables[m.group(5)]
            else:
                value = m.group(3) if m.group(3) is not None else m.group(4)
            value = re.sub(r"#\{\w+\.version\}", locked, value)
            fields[key] = re.sub(
                r"#\{(\w+)\}", lambda m: variables.get(m.group(1), m.group(0)), value
            )
        if any("#{" in v for v in fields.values()):
            return Unnamed("its podspec's source names a value computed elsewhere")
        repository = RepositoryArchive.repository(fields.get("git", ""))
        ref = fields.get("commit") or fields.get("tag")
        if repository and ref:
            return RepositoryArchive.upstream(repository, ref, f"{how} ({repository})")
        page = re.search(r"""\.homepage\s*=\s*['"]([^'"]+)['"]""", text)
        homes = tuple(u for u in (fields.get("http"), page.group(1) if page else None) if u)
        if fields.get("http"):
            downloaded = Inference.from_urls([fields["http"]], how)
            if isinstance(downloaded, Upstream):
                return downloaded
            return Unnamed(downloaded.reason, homes=homes)
        return Unnamed("its podspec names no git tag or commit, or download", homes=homes)

    @staticmethod
    def _answers(
        package: str, inside: str, versions: list[str], locked: str, how: str
    ) -> list[Upstream | Unnamed]:
        from cordon_scanner.intel.registries.registry_client import PackageNotFound

        answers: list[Upstream | Unnamed] = []
        for version in versions:
            try:
                files = NpmPodspec.package(package, version)
            except PackageNotFound:
                continue
            if files is None:
                continue
            text = files.get(inside)
            pinned = re.fullmatch(r"\s*(\S*-([0-9a-f]{40}))\s*", files.get(HERMES_PIN, ""))
            if inside.endswith("hermes-engine.podspec") and locked == version and pinned:
                # hermes-engine at React Native's own version is the release build, which React
                # Native's release scripts make from the tag `sdks/.hermesversion` names.
                answers.append(
                    RepositoryArchive.upstream(
                        "https://github.com/facebook/hermes",
                        pinned.group(2),
                        f"{how}@{version}: its sdks/.hermesversion pins the tag {pinned.group(1)}",
                    )
                )
                continue
            properties = dict(
                re.findall(
                    r"^\s*(HERMES_\w*VERSION_NAME)\s*=\s*(\S+)\s*$",
                    files.get(HERMES_PROPERTIES, ""),
                    re.MULTILINE,
                )
            )
            if inside.endswith("hermes-engine.podspec") and locked in properties.values():
                # React Native 0.83 and later: the Hermes release its version.properties names,
                # downloaded from Maven (`com.facebook.hermes:hermes-ios`) or built from that tag.
                answers.append(
                    TagInference.infer(
                        "https://github.com/facebook/hermes",
                        locked,
                        ("hermes",),
                        f"{how}@{version}: its version.properties names Hermes {locked}",
                    )
                )
                continue
            if text is None:
                continue
            variables = NpmPodspec.variables(text, NpmPodspec.constants(files), version)
            if NpmPodspec.declared(text, version, variables) != locked:
                continue
            answer = NpmPodspec.source(text, locked, variables, f"{how}@{version}")
            if isinstance(answer, Unnamed) and (package, inside) in NpmPodspec.OWN_CODE:
                answer = Upstream(
                    {"package": {"name": package, "ecosystem": "npm"}, "version": version},
                    f"{how}@{version}: {package}'s own code, versioned as it",
                )
            answers.append(answer)
        return answers

    @staticmethod
    def read(
        package: str, inside: str, versions: list[str], locked: str, how: str
    ) -> Upstream | Unnamed:
        answers = NpmPodspec._answers(package, inside, versions, locked, how)
        if not answers and locked not in versions and re.fullmatch(r"\d+\.\d+\.\d+[\w.-]*", locked):
            # The pod at a release of its own: hermes-engine 0.72.5 in a lock whose React pods
            # are at 0.72.6 is React Native 0.72.5's, pinned by that release.
            answers = NpmPodspec._answers(package, inside, [locked], locked, how)
        if not answers:
            return Unnamed(
                f"no {package} release among {', '.join(versions)} holds {inside} at {locked}"
            )
        named = {json.dumps(a.query, sort_keys=True) for a in answers if isinstance(a, Upstream)}
        if len(named) == 1 and all(isinstance(a, Upstream) for a in answers):
            return next(a for a in answers if isinstance(a, Upstream))
        if len(named) > 1:
            return Unnamed(f"{package}'s releases name different sources for {inside}")
        return next(a for a in answers if isinstance(a, Unnamed))


__all__ = ["HERMES_PIN", "HERMES_PROPERTIES", "NpmPodspec", "PodSiblings"]
