"""Advisories for ecosystems no advisory source covers, matched through each package's upstream.

OSV publishes no Bazel, vcpkg, Conan, Homebrew, CocoaPods, Terraform or Nix ecosystem (its
`ecosystems.txt`, October 2026). Each of those packages is built from an upstream repository the
ecosystem's own data names exactly, and OSV does cover upstream repositories: its GIT ecosystem
keys advisories by repository and tag (`https://github.com/madler/zlib` at `v1.2.11` names
CVE-2018-25032), and its commit query by commit. Terraform providers are Go modules, which OSV's Go
ecosystem covers. So a package is matched through what its own ecosystem says it was built from:

    bazel      BCR's `modules/<name>/<version>/source.json`: the archive URL, or a git commit
    conan      Conan Center's recipe export for the locked revision: `conandata.yml`'s source URLs
    cocoapods  the podspec on trunk's CDN: `source.git` with its `tag` or `commit`
    homebrew   formulae.brew.sh: the stable URL, when the version installed is the stable one
    vcpkg      the port at the baseline commit, when it is the version installed: the REPO and REF
               of its `vcpkg_from_github`
    terraform  the registry's provider record: its source repository, as a Go module
    nix        a flake input's locked commit
    conda      the recipe inside the package itself (`info/recipe`): its source URL, or git URL and rev

Nothing is guessed. An archive URL is read only in GitHub's and GitLab's fixed forms; a ref that is
a branch, a version the source no longer serves, a download from a project's own site, a port
whose REF uses anything but its version -- each leaves the package unchecked, and says why.
Network use is the scan's `--online` only, over HTTPS, to the hosts above and api.osv.dev.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import re
import tarfile
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.intel.advisories.advisories import Advisory
from cordon_scanner.intel.advisories.upstream.base import (
    VCPKG_RAW,
    Archive,
    RegistryArchive,
    RepositoryArchive,
    Unnamed,
    Upstream,
)
from cordon_scanner.intel.advisories.upstream.cocoapods import NpmPodspec, PodSiblings
from cordon_scanner.intel.advisories.upstream.conan import ConanCenter
from cordon_scanner.intel.advisories.upstream.conda import CondaPackage, CondaSiblings
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.homebrew import HomebrewBottles, HomebrewHistory
from cordon_scanner.intel.advisories.upstream.inference import Inference
from cordon_scanner.intel.advisories.upstream.tags import TagInference
from cordon_scanner.intel.advisories.upstream.vcpkg import VcpkgPorts, VcpkgVersions

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.foundation.results import Dependency

OSV_QUERYBATCH: Final = "https://api.osv.dev/v1/querybatch"
OSV_VULN: Final = "https://api.osv.dev/v1/vulns/"
BCR: Final = "https://bcr.bazel.build/modules"
CONAN_CENTER: Final = "https://center2.conan.io/v2/conans"
TERRAFORM_REGISTRY: Final = "https://registry.terraform.io/v1/providers"
MAX_PACKAGES: Final = 20_000
#: Packages whose upstream is looked up at once: each is a few HTTP requests, and a proof one
#: download, so a conda lock of a thousand artifacts is not read one at a time.
WORKERS: Final = 8
"""Packages resolved per scan. Past it the rest are reported unchecked, never silently skipped."""
MAX_EXPORT_BYTES: Final = 1 << 20
SUPPORTED: Final = frozenset(
    {"bazel", "conan", "cocoapods", "homebrew", "vcpkg", "terraform", "nix", "conda", "ansible"}
)


@dataclass
class UpstreamResult:
    advisories: dict[str, tuple[Advisory, ...]] = field(default_factory=dict)
    """By purl: what OSV names for each package whose upstream was named."""
    checked: set[str] = field(default_factory=set)
    """The purls asked of OSV, whether or not anything matched."""
    unchecked: dict[str, str] = field(default_factory=dict)
    """By purl: why the package could not be matched."""
    homes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    """By purl: the homepage and download URLs read for a package left unchecked."""
    versions: dict[str, str] = field(default_factory=dict)
    """By purl: the release resolved for a package left unchecked whose lockfile names none."""


class Upstreams:
    """What each ecosystem says a package was built from."""

    @staticmethod
    def bazel(dependency: Dependency) -> Upstream | Unnamed:
        name, version = dependency.name, dependency.version or ""
        given = dependency.resolved_from or ""
        if given and (RepositoryArchive.parse(given) or RegistryArchive.parse(given)):
            # Bazel 7.0-7.1's lock records the module's archive itself.
            return Inference.from_urls(
                [given], f"the archive the lock records for {name} {version}"
            )
        # Any registry has BCR's layout, and the lock names the one it used: BCR, its git source
        # (`raw.githubusercontent.com/bazelbuild/bazel-central-registry/main/`), or another.
        registry = (
            given.rstrip("/") if given.startswith("https://") else BCR.removesuffix("/modules")
        )
        data = json.loads(
            Fetch.get(
                f"{registry}/modules/{urllib.parse.quote(name, safe='')}/"
                f"{urllib.parse.quote(version, safe='')}/source.json"
            )
        )
        how = f"{registry}'s source.json for {name} {version}"
        if data.get("type") == "git_repository":
            repository = RepositoryArchive.repository(str(data.get("remote") or ""))
            commit = str(data.get("commit") or "")
            if repository and re.fullmatch(r"[0-9a-f]{40}", commit):
                return RepositoryArchive.upstream(repository, commit, f"{how} ({repository})")
            return Unnamed("its source is a git repository BCR names without a commit")
        urls = [data["url"]] if isinstance(data.get("url"), str) else []
        urls += [u for u in data.get("mirror_urls") or [] if isinstance(u, str)]
        first = Inference.from_urls(urls, how)
        if isinstance(first, Upstream):
            return first
        # The module's metadata.json names its repository (`github:madler/zlib`); BCR versions a
        # module `<upstream>.bcr.<n>` when it patches one.
        try:
            meta = json.loads(
                Fetch.get(f"{registry}/modules/{urllib.parse.quote(name, safe='')}/metadata.json")
            )
        except (OSError, ValueError, http.client.HTTPException):
            return first
        homes = [*(meta.get("repository") or []), meta.get("homepage")]
        integrity = str(data.get("integrity") or "")
        return Inference.inferred(
            first,
            homes,
            re.sub(r"\.bcr\.\d+$", "", version),
            (name,),
            how,
            Archive(tuple(urls), integrity) if urls and integrity else None,
        )

    @staticmethod
    def conan(dependency: Dependency) -> Upstream | Unnamed:
        if dependency.resolved_from not in (None, "conancenter"):
            return Unnamed("it is not from Conan Center")
        name, version = dependency.name, dependency.version or ""
        base = f"{CONAN_CENTER}/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/_/_/revisions"
        from cordon_scanner.intel.registries.registry_client import RegistryError

        locked = (dependency.integrity or "").removeprefix("md5:")
        try:
            if not re.fullmatch(r"[0-9a-f]{32}", locked):
                revisions = json.loads(Fetch.get(base)).get("revisions") or []
                if not revisions:
                    return Unnamed("Conan Center holds no recipe for this version")
                locked = str(revisions[0].get("revision") or "")
            export = Fetch.get(f"{base}/{locked}/files/conan_export.tgz", MAX_EXPORT_BYTES)
        except (RegistryError, OSError, ValueError):
            # A version Conan Center has since dropped (ruby 3.2.2): the package's current recipe
            # still names its repository.
            return ConanCenter.removed(name, version)
        # `RegistryHttp.get` inflates a gzip answer itself, so this may already be a plain tar.
        with tarfile.open(fileobj=io.BytesIO(export), mode="r:*") as archive:
            member = archive.extractfile("conandata.yml")
            text = member.read(MAX_EXPORT_BYTES).decode("utf-8", "replace") if member else ""
            try:
                recipe = archive.extractfile("conanfile.py")
            except KeyError:
                recipe = None
            conanfile = recipe.read(MAX_EXPORT_BYTES).decode("utf-8", "replace") if recipe else ""
        if not conanfile:
            # Conan 2 serves the recipe beside the export, not in it (conan_export.tgz holds
            # conandata.yml alone): its homepage is what NVD ties the package by.
            with contextlib.suppress(RegistryError, OSError, ValueError, http.client.HTTPException):
                conanfile = Fetch.get(
                    f"{base}/{locked}/files/conanfile.py", MAX_EXPORT_BYTES
                ).decode("utf-8", "replace")
        from cordon_scanner.foundation.formats.datayaml import DataYaml

        data = DataYaml.load(text) if text else {}
        sources = (data.get("sources") or {}) if isinstance(data, dict) else {}
        source = sources.get(version) if isinstance(sources, dict) else None
        how = f"Conan Center's recipe {name}/{version}#{locked[:8]}"
        homepage = re.search(r'^\s*homepage\s*=\s*["\']([^"\']+)["\']', conanfile, re.MULTILINE)
        urls, pinned = ConanCenter.leaves(source)
        # Where this version's sources name no repository (zlib 1.2.11: only zlib.net), the
        # recipe's other versions may: one repository named across them is a candidate.
        exact = ConanCenter.committed(source, how) or ConanCenter.exact(urls, how)
        if isinstance(exact, Upstream):
            return exact
        current = ConanCenter.repositories(name) or set()
        return Inference.inferred(
            exact,
            [
                *([homepage.group(1)] if homepage else []),
                *(sorted(current) if len(current) == 1 else []),
            ],
            version,
            (name,),
            how,
            pinned,
        )

    @staticmethod
    def cocoapods(dependency: Dependency) -> Upstream | Unnamed:
        from cordon_scanner.foundation.models import Scope
        from cordon_scanner.intel.registries.package_registries import PackageRegistries
        from cordon_scanner.intel.registries.registry_hosts import HOSTS

        if dependency.scope == Scope.TOOL and dependency.name == "cocoapods":
            # Podfile.lock's COCOAPODS line: the version of CocoaPods itself, a RubyGem.
            return Upstream(
                {
                    "package": {"name": "cocoapods", "ecosystem": "RubyGems"},
                    "version": dependency.version or "",
                },
                f"CocoaPods {dependency.version}, the RubyGem",
            )
        given = dependency.resolved_from
        if given is not None:
            return Upstreams.cocoapods_checkout(dependency, given)
        name, version = dependency.name.split("/", 1)[0], dependency.version or ""
        a, b, c = PackageRegistries.cocoapods_shard(name)
        spec = json.loads(
            PackageRegistries.cocoapods_spec(
                f"{HOSTS['cocoapods']}/Specs/{a}/{b}/{c}/{name}/{version}/{name}.podspec.json"
            )
        )
        source = spec.get("source") if isinstance(spec, dict) else None
        how = f"the {name} {version} podspec"
        if isinstance(source, dict) and isinstance(source.get("git"), str):
            repository = RepositoryArchive.repository(source["git"])
            ref = source.get("commit") or source.get("tag")
            if repository and isinstance(ref, str) and ref:
                return RepositoryArchive.upstream(repository, ref, f"{how} ({repository})")
            first: Upstream | Unnamed = Unnamed(
                "its podspec names a git source off GitHub and GitLab, or no tag"
            )
        elif isinstance(source, dict) and isinstance(source.get("http"), str):
            first = Inference.from_urls([source["http"]], how)
        else:
            first = Unnamed("its podspec names no source")
        homes = [
            (source or {}).get("git") if isinstance(source, dict) else None,
            spec.get("homepage") if isinstance(spec, dict) else None,
        ]
        pinned = (
            Archive((source["http"],), f"sha256:{source['sha256']}")
            if isinstance(source, dict)
            and isinstance(source.get("http"), str)
            and isinstance(source.get("sha256"), str)
            else None
        )
        answer = Inference.inferred(first, homes, version, (name,), how, pinned)
        if (
            isinstance(answer, Unnamed)
            and isinstance(source, dict)
            and isinstance(source.get("http"), str)
            and Upstreams.prebuilt(spec)
        ):
            # A vendor's closed binary (Google's FirebaseAnalytics before firebase-ios-sdk held
            # its podspec, Agora's SDKs): no source exists to name, so said as what it is.
            return Unnamed(
                f"a prebuilt binary its vendor ships from {source['http']} (its podspec vends "
                "frameworks or libraries and builds no source), with no repository to name",
                homes=answer.homes,
            )
        if (
            isinstance(answer, Unnamed)
            and isinstance(source, dict)
            and isinstance(source.get("http"), str)
            and Upstreams.umbrella(spec)
        ):
            # Firebase 3 to 6: the pod is a header and a module map over its subspecs' pods, from
            # the vendor's binary distribution.
            return Unnamed(
                f"an umbrella of headers from {source['http']} (its podspec builds only headers "
                "and vends nothing; the code is in the pods it depends on), with no repository to "
                "name",
                homes=answer.homes,
            )
        return answer

    @staticmethod
    def cocoapods_checkout(dependency: Dependency, given: str) -> Upstream | Unnamed:
        """A pod installed from a checkout, not trunk: its commit or tag, or the npm podspec it came with."""
        # `pod 'X', :git => ..., :commit|:tag => ...`: Podfile.lock's CHECKOUT OPTIONS hold
        # what was checked out: a commit is exact; a ref only once the repository shows it is
        # a tag -- a branch moves, so it is no fixed point.
        git = re.fullmatch(r"git\+(\S+)#(\S+)", given)
        repository = RepositoryArchive.repository(git.group(1)) if git else None
        if git and repository:
            ref, how = git.group(2), f"the {dependency.name} checkout ({repository})"
            if re.fullmatch(r"[0-9a-f]{40}", ref) or ref in (TagInference.refs(repository) or {}):
                return RepositoryArchive.upstream(repository, ref, how)
            return Unnamed(f"its checkout names {ref}, which is not a tag of {repository}")
        within = NpmPodspec.NOTE.search(dependency.resolution_note or "")
        if within:
            return NpmPodspec.read(
                within.group(2),
                within.group(1),
                within.group(3).split(" or "),
                dependency.version or "",
                f"the {dependency.name} podspec in npm's {within.group(2)}",
            )
        return Unnamed("it is not from CocoaPods trunk")

    @staticmethod
    def patterns(value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []

    @staticmethod
    def header(pattern: str) -> bool:
        """A file pattern that matches headers only: `*.h`, `X.hpp`, `**/*.{h,hh}`."""
        found = re.search(r"\.(\w+|\{[\w,]+\})$", pattern.strip())
        if not found:
            return False
        extensions = found.group(1).strip("{}").split(",")
        return all(e in ("h", "hh", "hpp", "hxx", "inl", "modulemap") for e in extensions)

    @staticmethod
    def umbrella(spec: object) -> bool:
        """Whether a podspec, with its subspecs, vends nothing and builds headers alone."""
        vends, headers, builds = False, False, False
        stack: list[object] = [spec]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for platform in (node, *(node.get(p) for p in ("ios", "osx", "tvos", "watchos"))):
                if isinstance(platform, dict):
                    vends |= bool(
                        platform.get("vendored_frameworks") or platform.get("vendored_libraries")
                    )
                    for pattern in Upstreams.patterns(platform.get("source_files")):
                        headers |= Upstreams.header(pattern)
                        builds |= not Upstreams.header(pattern)
            stack += [s for s in node.get("subspecs") or [] if isinstance(s, dict)]
        return headers and not vends and not builds

    @staticmethod
    def prebuilt(spec: object) -> bool:
        """Whether a podspec, with its subspecs, vends frameworks or libraries and builds no
        source files: a binary distribution. Headers alone are not source built (Crashlytics
        3.x ships `Crashlytics.framework/Headers/*.h` beside its framework)."""
        vends, builds = False, False
        stack: list[object] = [spec]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for platform in (node, *(node.get(p) for p in ("ios", "osx", "tvos", "watchos"))):
                if isinstance(platform, dict):
                    vends |= bool(
                        platform.get("vendored_frameworks") or platform.get("vendored_libraries")
                    )
                    builds |= any(
                        not Upstreams.header(pattern)
                        for pattern in Upstreams.patterns(platform.get("source_files"))
                    )
            stack += [s for s in node.get("subspecs") or [] if isinstance(s, dict)]
        return vends and not builds

    @staticmethod
    def homebrew(dependency: Dependency) -> Upstream | Unnamed:
        name = dependency.name
        installed = dependency.version or ""
        if "cask" in dependency.platform:
            return HomebrewBottles.cask(name)
        if name.count("/") == 1 and re.fullmatch(r"[0-9a-f]{40}", installed):
            # A tap, locked to a commit of its repository (`<owner>/homebrew-<tap>`).
            owner, tap = name.split("/")
            repository = f"https://github.com/{owner}/homebrew-{tap.removeprefix('homebrew-')}"
            return RepositoryArchive.upstream(
                repository, installed, f"the tap {name} at its locked commit"
            )
        given = dependency.resolved_from or ""
        if given.startswith("registry:") and given.count("/") == 1:
            return HomebrewBottles.tap_formula(given.removeprefix("registry:"), name, installed)
        if "/" in name or dependency.resolved_from is not None:
            return Unnamed("it is from a tap, which formulae.brew.sh does not describe")
        found = HomebrewBottles.formula_data(name, installed)
        if isinstance(found, Unnamed):
            if found.reason.startswith("Homebrew no longer has this formula"):
                return HomebrewHistory.upstream(dependency, found)
            return found
        name, data = found
        if installed.startswith("HEAD-"):
            return HomebrewBottles.head(data, installed, name)
        stable = str((data.get("versions") or {}).get("stable") or "")
        if not installed or re.sub(r"_\d+$", "", installed) == stable:
            # The formula the API describes, at the commit it names, checked against the SHA-256
            # it gives: its mirrors are read too (curl's include GitHub's release asset).
            import hashlib

            head, path = (
                str(data.get("tap_git_head") or ""),
                str(data.get("ruby_source_path") or ""),
            )
            expected = str((data.get("ruby_source_checksum") or {}).get("sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{40}", head) or not re.fullmatch(
                r"Formula/[\w@+./-]+\.rb", path
            ):
                return Unnamed("formulae.brew.sh names no formula file for it")
            body = Fetch.get(
                f"https://raw.githubusercontent.com/Homebrew/homebrew-core/{head}/{path}"
            )
            if expected and hashlib.sha256(body).hexdigest() != expected:
                return Unnamed(
                    "the formula file does not hash to the SHA-256 formulae.brew.sh gives"
                )
            text, version = body.decode("utf-8", "replace"), stable
            how = f"the {name} {stable} formula"
        else:
            # An older version: the formula its bottle was built from, which the bottle carries.
            version = re.sub(r"_\d+$", "", installed)
            try:
                text = HomebrewBottles.formula(name, installed)
                how = f"the {name} {installed} formula its bottle carries"
            except (OSError, ValueError, tarfile.TarError, EOFError, http.client.HTTPException):
                # No bottle (one from before ghcr.io): the current formula still names the
                # repository, in which the installed version's tag is looked for. Nothing pins
                # the old release archive, so it cannot be proved: an inference, said as one.
                historical = HomebrewHistory.upstream(
                    dependency,
                    Unnamed(f"no bottle of {installed} remains to read its formula from"),
                )
                if isinstance(historical, Upstream):
                    return historical
                current = HomebrewBottles.current_formula(data)
                heads = re.findall(
                    r'^\s*(?:head\s+|url\s+)"([^"]+?)(?:\.git)?"', current, re.MULTILINE
                )
                return Inference.inferred(
                    historical,
                    [*heads, data.get("homepage")],
                    version,
                    (name.split("@", 1)[0],),
                    f"the {name} formula's repository",
                )
        # Where the stable source names no tag, the formula's `head` and homepage name the
        # repository to look for the version's tag in.
        heads = re.findall(r'^\s*(?:head\s+|url\s+)"([^"]+\.git)"', text, re.MULTILINE)
        return Inference.inferred(
            HomebrewBottles.source(text, how),
            [*heads, data.get("homepage")],
            version,
            (name.split("@", 1)[0],),
            how,
            HomebrewBottles.archive(text),
        )

    #: Cordon's own wording for a port read at a baseline (`ecosystems/vcpkg.py`).
    VCPKG_BASELINE: ClassVar[re.Pattern[str]] = re.compile(r"\bat baseline ([0-9a-f]{40})\b")

    @staticmethod
    def vcpkg(dependency: Dependency) -> Upstream | Unnamed:
        if dependency.resolved_from is not None:
            return Unnamed("it is not from vcpkg's built-in registry")
        found = Upstreams.VCPKG_BASELINE.search(dependency.resolution_note or "")
        if not found:
            return Unnamed("no baseline commit says which port it is")
        baseline, port = found.group(1), urllib.parse.quote(dependency.name, safe="")
        manifest = VcpkgPorts.manifest(baseline, port)
        scheme, at_baseline = next(
            (
                (k, str(manifest[k]))
                for k in ("version", "version-semver", "version-date", "version-string")
                if isinstance(manifest.get(k), str)
            ),
            ("version", ""),
        )
        wanted = dependency.version
        spec = dependency.declared_spec or ""
        if not wanted and spec and spec != "*" and not spec.startswith(">="):
            # An override names the version exactly, whatever the baseline and constraints say.
            wanted = spec
        if not wanted:
            # vcpkg installs the greater of the baseline's version and every `version>=`.
            minimum = spec.removeprefix(">=")
            if minimum and minimum != "*":
                ordered = VcpkgVersions.compare(scheme, at_baseline, minimum)
                if ordered is None:
                    return Unnamed(f"a version>= constraint on a {scheme}, which is not ordered")
                if ordered < 0:
                    wanted = minimum
        if wanted and wanted != at_baseline:
            files = VcpkgPorts.at_version(baseline, dependency.name, wanted)
            if isinstance(files, Unnamed):
                return files
            portfile, version = files

            def other(filename: str) -> str:
                return VcpkgPorts.file_at_version(baseline, dependency.name, wanted or "", filename)

        else:
            portfile = Fetch.get(f"{VCPKG_RAW}/{baseline}/ports/{port}/portfile.cmake").decode(
                "utf-8", "replace"
            )
            version = at_baseline

            def other(filename: str) -> str:
                return Fetch.get(f"{VCPKG_RAW}/{baseline}/ports/{port}/{filename}").decode(
                    "utf-8", "replace"
                )

        how = f"the {dependency.name} {version} port"
        if re.search(
            r"\bqt_(?:install_submodule|submodule_installation|download_submodule)\s*\(", portfile
        ):

            def qtbase(filename: str) -> str:
                return Fetch.get(f"{VCPKG_RAW}/{baseline}/ports/qtbase/{filename}").decode(
                    "utf-8", "replace"
                )

            return VcpkgPorts.qt(dependency.name, version.split("#", 1)[0], other, how, qtbase)
        first, archive = VcpkgPorts.read(portfile, version, dependency.name, how)
        if isinstance(first, Unnamed) and first.nothing:
            return first
        if isinstance(first, Unnamed) and not VcpkgPorts.DOWNLOADS.search(portfile):
            # A port that downloads nothing (vcpkg-cmake, a helper of CMake scripts; cuda, which
            # finds the system's): what it installs is the registry's own files, so its upstream
            # is the vcpkg repository at the baseline -- exactly.
            return RepositoryArchive.upstream(
                VcpkgPorts.REPOSITORY, baseline, f"{how}: its files are vcpkg's own"
            )
        return Inference.inferred(
            first,
            [manifest.get("homepage")],
            version.split("#", 1)[0],
            (dependency.name,),
            how,
            archive,
        )

    @staticmethod
    def terraform(dependency: Dependency) -> Upstream | Unnamed:
        parts = dependency.name.split("/")
        if len(parts) != 2 or dependency.resolved_from is not None:
            return Unnamed("it is not a provider from registry.terraform.io")
        data = json.loads(
            Fetch.get(
                f"{TERRAFORM_REGISTRY}/{urllib.parse.quote(parts[0], safe='')}/"
                f"{urllib.parse.quote(parts[1], safe='')}"
            )
        )
        repository = RepositoryArchive.repository(str(data.get("source") or ""))
        if not repository or not repository.startswith("https://github.com/"):
            return Unnamed("the registry names no GitHub source repository for it")
        module = repository.removeprefix("https://")
        return Upstream(
            {"package": {"name": module, "ecosystem": "Go"}, "version": dependency.version},
            f"its source repository's Go module, {module} {dependency.version}",
        )

    @staticmethod
    def conda(dependency: Dependency) -> Upstream | Unnamed:
        """The recipe a conda package carries (`info/recipe/meta.yaml`, rendered, or rattler-build's
        `rendered_recipe.yaml`): its source URLs, or its git URL and revision."""
        url = dependency.resolved_from or ""
        if not re.match(r"^https://(?:conda\.anaconda\.org|repo\.anaconda\.com)/", url):
            return Unnamed("it is not from a public conda channel")
        seen: dict[str, int] = {}
        recipe = CondaPackage.recipe(url, seen)
        if recipe is None:
            return Unnamed("its package carries no rendered recipe")
        from cordon_scanner.foundation.formats.datayaml import DataYaml

        data = DataYaml.load(recipe)
        finalized: list[object] = []
        if isinstance(data, dict) and isinstance(data.get("recipe"), dict):
            # rattler-build's rendered_recipe.yaml wraps the recipe, and records the sources the
            # build used, rendered: its own, and a multi-output recipe's shared stage's (glib-tools
            # names none of its own; the stage it was built from fetched glib's release).
            for key in ("finalized_sources", "finalized_cache_sources"):
                listed = data.get(key)
                finalized += listed if isinstance(listed, list) else []
            data = data["recipe"]
        CondaSiblings.record(url, data)
        source = data.get("source") if isinstance(data, dict) else None
        sources = [
            *(source if isinstance(source, list) else [source] if source else []),
            *finalized,
        ]
        urls: list[str] = []
        how = f"the recipe inside {url.rsplit('/', 1)[-1]}"
        for one in sources:
            if not isinstance(one, dict):
                continue
            git = one.get("git_url") or one.get("git")
            rev = one.get("git_rev") or one.get("rev") or one.get("tag")
            repository = RepositoryArchive.repository(str(git or ""))
            if repository and isinstance(rev, str) and rev:
                return RepositoryArchive.upstream(repository, rev, f"{how} ({repository})")
            given = one.get("url")
            urls += (
                [given]
                if isinstance(given, str)
                else [u for u in given or [] if isinstance(u, str)]
            )
        sourceless = not urls and not any(
            isinstance(s, dict) and (s.get("git_url") or s.get("git")) for s in sources
        )
        if sourceless and "paths" not in seen:
            # Its recipe came before paths.json: read on to it, which a small info/ allows.
            seen["want_paths"] = 1
            CondaPackage.recipe(url, seen)
        if sourceless and seen.get("paths") == 0:
            # A metapackage (python_abi, fonts-conda-ecosystem): no source, and its paths.json
            # lists no file it installs.
            return Unnamed("a metapackage: it names no source and installs no files", nothing=True)
        about = data.get("about") if isinstance(data, dict) else None
        homes = [about.get("dev_url"), about.get("home")] if isinstance(about, dict) else []
        sha256 = next(
            (
                str(one["sha256"])
                for one in sources
                if isinstance(one, dict) and isinstance(one.get("sha256"), str)
            ),
            "",
        )
        answer = Inference.inferred(
            Inference.from_urls(urls, how),
            homes,
            dependency.version or "",
            (dependency.name,),
            how,
            Archive(tuple(urls), f"sha256:{sha256}") if urls and sha256 else None,
        )
        licence = Upstreams.proprietary(about)
        if isinstance(answer, Unnamed) and not licence:
            if "paths" not in seen:
                seen["want_paths"] = 1
                CondaPackage.recipe(url, seen)
            if seen.get("fonts_only"):
                # DejaVu, Ubuntu: the package installs font files and nothing else.
                return Unnamed("it installs font files only: no code", nothing=True)
        if isinstance(answer, Unnamed) and licence:
            # NVIDIA's CUDA, Intel's MKL, Microsoft's runtimes: a vendor's binaries, under its
            # own licence, with no public source to name.
            return Unnamed(
                f"a vendor's proprietary distribution (licensed {licence}), with no public "
                "source to name",
                homes=answer.homes,
            )
        return answer

    #: A licence that is a vendor's own, not an open one (`LicenseRef-` alone is not: the Ubuntu
    #: Font Licence is one).
    PROPRIETARY: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)proprietary|end[-_ ]user[-_ ]licen[cs]e|\bEULA\b|LicenseRef-Microsoft"
    )

    @staticmethod
    def proprietary(about: object) -> str:
        """The recipe's licence where it, or its family, says proprietary; else empty."""
        if not isinstance(about, dict):
            return ""
        licence = str(about.get("license") or "")
        family = str(about.get("license_family") or "")
        if family.lower() == "proprietary" or Upstreams.PROPRIETARY.search(licence):
            return licence or family
        return ""

    @staticmethod
    def ansible(dependency: Dependency) -> Upstream | Unnamed:
        """A collection on galaxy.ansible.com: its version record names the git commit it was
        built from (`git_url`, `git_commit_sha`)."""
        namespace, _, collection = dependency.name.partition(".")
        if dependency.resolved_from is not None or not collection or "." in collection:
            return Unnamed("it is not a collection from galaxy.ansible.com")
        record = json.loads(
            Fetch.get(
                "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/"
                f"index/{urllib.parse.quote(namespace, safe='')}/"
                f"{urllib.parse.quote(collection, safe='')}/versions/"
                f"{urllib.parse.quote(dependency.version or '', safe='')}/"
            )
        )
        repository = RepositoryArchive.repository(str(record.get("git_url") or ""))
        commit = str(record.get("git_commit_sha") or "")
        if repository and re.fullmatch(r"[0-9a-f]{40}", commit):
            return RepositoryArchive.upstream(
                repository, commit, f"Galaxy's record of {dependency.name} {dependency.version}"
            )
        return Inference.inferred(
            Unnamed("Galaxy's record names no commit"),
            [
                (record.get("metadata") or {}).get("repository"),
                (record.get("metadata") or {}).get("homepage"),
            ],
            dependency.version or "",
            (dependency.name, collection),
            f"Galaxy's record of {dependency.name} {dependency.version}",
            # The collection artefact Galaxy serves, by the SHA-256 its record gives.
            Archive(
                (urllib.parse.urljoin("https://galaxy.ansible.com", str(record["download_url"])),),
                f"sha256:{(record.get('artifact') or {}).get('sha256')}",
            )
            if isinstance(record.get("download_url"), str)
            and isinstance((record.get("artifact") or {}).get("sha256"), str)
            else None,
        )

    @staticmethod
    def nix(dependency: Dependency) -> Upstream | Unnamed:
        commit = dependency.version or ""
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            return Unnamed("it is locked to no git commit")
        return Upstream({"commit": commit}, f"its locked commit {commit[:12]}")


class UpstreamAdvisories:
    """Name each package's upstream, ask OSV, and return what it names, as `Advisory` records."""

    _records: ClassVar[dict[str, dict[str, Any]]] = {}

    @staticmethod
    def name(dependency: Dependency) -> Upstream | Unnamed:
        key = (dependency.ecosystem, dependency.name, dependency.version, dependency.integrity)
        cached = Fetch.resolved.get(key)
        if cached is not None:
            return cached
        resolver = getattr(Upstreams, dependency.ecosystem, None)
        if resolver is None:
            return Unnamed("no upstream is read for this ecosystem")
        if dependency.ecosystem != "vcpkg" and not dependency.version:
            result: Upstream | Unnamed = Unnamed("no version is locked")
        else:
            from cordon_scanner.intel.provenance.gitfetch import GitFetchError
            from cordon_scanner.intel.registries.registry_client import RegistryError

            try:
                result = resolver(dependency)
            except RegistryError as exc:
                result = Unnamed(f"its ecosystem's source could not be read ({exc})")
            except (
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
                tarfile.TarError,
                # A response cut short mid-body (`IncompleteRead`): not an OSError.
                http.client.HTTPException,
                # The git client's own refusals (a tree it could not fetch).
                GitFetchError,
            ) as exc:
                result = Unnamed(f"its ecosystem's source could not be read ({type(exc).__name__})")
        Fetch.resolved[key] = result
        return result

    @staticmethod
    def _post(url: str, body: dict[str, Any]) -> dict[str, Any]:
        import urllib.request

        request = urllib.request.Request(  # noqa: S310 - a fixed https URL
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "cordon-scanner"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            data = json.loads(response.read(64 << 20))
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _record(identifier: str) -> dict[str, Any]:
        cached = UpstreamAdvisories._records.get(identifier)
        if cached is None:
            cached = json.loads(
                Fetch.get(OSV_VULN + urllib.parse.quote(identifier, safe=""), 16 << 20)
            )
            UpstreamAdvisories._records[identifier] = cached
        return cached

    @staticmethod
    def check(dependencies: Iterable[Dependency]) -> UpstreamResult:
        from concurrent.futures import ThreadPoolExecutor

        from cordon_scanner.intel.advisories.osv_import import OsvImport

        result = UpstreamResult()
        named: list[tuple[Dependency, Upstream]] = []
        listed = list(dependencies)
        for dependency in listed[MAX_PACKAGES:]:
            result.unchecked[dependency.purl] = (
                f"past the {MAX_PACKAGES}-package ceiling for one scan"
            )
        within = listed[:MAX_PACKAGES]
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            answers = list(pool.map(UpstreamAdvisories.name, within))
        # A binary pod published from the repository a sibling pod resolved to (Firebase's).
        answers = PodSiblings.resolve(within, answers)
        # A conda output naming no source, built in the same feedstock commit as one that does.
        answers = CondaSiblings.resolve(within, answers)
        for dependency, upstream in zip(within, answers, strict=True):
            if isinstance(upstream, Unnamed):
                if upstream.nothing:
                    result.checked.add(dependency.purl)
                    continue
                result.unchecked[dependency.purl] = upstream.reason
                if upstream.homes:
                    result.homes[dependency.purl] = upstream.homes
                if upstream.version and not dependency.version:
                    result.versions[dependency.purl] = upstream.version
            else:
                named.append((dependency, upstream))
        if not named:
            return result
        found: list[list[str]] = [[] for _ in named]
        try:
            for start in range(0, len(named), 1000):
                pending = {
                    i: named[i][1].query for i in range(start, min(start + 1000, len(named)))
                }
                while pending:
                    answer = UpstreamAdvisories._post(
                        OSV_QUERYBATCH, {"queries": list(pending.values())}
                    )
                    following: dict[int, dict[str, Any]] = {}
                    for i, entry in zip(pending, answer.get("results") or [], strict=False):
                        found[i] += [str(v["id"]) for v in entry.get("vulns") or [] if "id" in v]
                        if entry.get("next_page_token"):
                            following[i] = {
                                **named[i][1].query,
                                "page_token": entry["next_page_token"],
                            }
                    pending = following
        except (OSError, ValueError, http.client.HTTPException) as exc:
            for dependency, _ in named:
                result.unchecked[dependency.purl] = f"OSV could not be asked ({type(exc).__name__})"
            return result
        for (dependency, upstream), identifiers in zip(named, found, strict=True):
            result.checked.add(dependency.purl)
            advisories: list[Advisory] = []
            for identifier in dict.fromkeys(identifiers):
                try:
                    record = UpstreamAdvisories._record(identifier)
                except (OSError, ValueError, http.client.HTTPException) as exc:
                    result.checked.discard(dependency.purl)
                    result.unchecked[dependency.purl] = (
                        f"OSV's record {identifier} could not be read ({type(exc).__name__})"
                    )
                    break
                summary = str(record.get("summary") or record.get("details") or "").strip()
                summary = summary.splitlines()[0][:300] if summary else ""
                advisories.append(
                    Advisory(
                        ecosystem=dependency.ecosystem,
                        name=dependency.name,
                        versions=(dependency.version,) if dependency.version else (),
                        summary=f"{summary} Matched through {upstream.how}.".strip(),
                        reference=OsvImport._reference_of(record),
                        identifier=identifier,
                        severity=OsvImport._severity_of(record),
                        aliases=tuple(str(a) for a in record.get("aliases") or ()),
                        matched_through="inferred" if upstream.inferred else "upstream",
                    )
                )
            else:
                result.advisories[dependency.purl] = tuple(advisories)
        return result


__all__ = ["UpstreamAdvisories", "UpstreamResult", "Upstreams"]
