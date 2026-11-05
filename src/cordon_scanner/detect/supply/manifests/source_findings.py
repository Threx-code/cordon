"""The manifest findings about where dependencies come from.

A git commit, a remote tarball or another project's commit as a dependency; indexes merged so the
highest version anywhere wins; the public repository listed before a private one (CocoaPods, Conan,
Bundler, NuGet); a Composer constraint naming a branch; a source or chart repository over plain HTTP;
a build wrapper that downloads its tool without a pinned checksum; and the images a build or a
workload is made from -- a stage FROM an image named by tag alone, a container naming its image so,
a digest written so it pins nothing."""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.supply.manifests.findings import ManifestFinding
from cordon_scanner.detect.supply.manifests.rule_ids import (
    CLEARTEXT_SOURCE_RULE,
    FOREIGN_COMMIT_RULE,
    MALICIOUS_REMOTE_TARBALL_RULE,
    MUTABLE_REF_RULE,
    SOURCE_PRIORITY_RULE,
    WRAPPER_RULE,
)
from cordon_scanner.detect.supply.manifests.scripts import ManifestScripts
from cordon_scanner.detect.supply.manifests.sources import DeclaredSource
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Scope,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping

    from cordon_scanner.ecosystems.base import DeclaredDependency, Ecosystem, Manifest


class SourceFindings:
    """The manifest findings about dependency sources."""

    #: The checks that are one ecosystem's own, by the ecosystems each applies to: a new ecosystem
    #: with such a rule adds a declaration here, not a branch in the check.
    APPLIES_TO: ClassVar[Mapping[str, frozenset[str]]] = MappingProxyType(
        {
            "_composer_branch_findings": frozenset({"composer"}),
            "_cocoapods_source_findings": frozenset({"cocoapods"}),
            "_base_image_findings": frozenset({"image"}),
            "_helm_repository_findings": frozenset({"helm"}),
            "_conan_remote_findings": frozenset({"conan"}),
            "_bundler_source_findings": frozenset({"rubygems"}),
            "_nuget_source_findings": frozenset({"nuget"}),
            # A Dockerfile's `ADD` of a URL, which the Dockerfile rule for remote ADD reports.
            "_dockerfile_add": frozenset({"image"}),
            # A full commit hash of a repository not the package's, which npm installs from.
            "_foreign_commit": frozenset({"npm"}),
        }
    )

    @classmethod
    def wrapper_findings(cls, unit: FileUnit, ctx: ScanContext) -> Iterable[Finding]:
        """A build wrapper that downloads its tool without a pinned checksum.

        `./mvnw` and `./gradlew` fetch a Maven or Gradle distribution from `distributionUrl` and
        run it for every build, on every machine. With `distributionSha256Sum` set the wrapper
        refuses a download that does not match; without it, whatever that URL serves runs."""
        name = unit.path.rpartition("/")[2]
        if name not in ("maven-wrapper.properties", "gradle-wrapper.properties"):
            return
        values = {
            line.partition("=")[0].strip(): line.partition("=")[2].strip()
            for line in unit.content.text.splitlines()
            if "=" in line and not line.lstrip().startswith(("#", "!"))
        }
        if not values.get("distributionUrl") or values.get("distributionSha256Sum"):
            return
        tool = "Maven" if name.startswith("maven") else "Gradle"
        yield ManifestFinding.finding(
            rule_id=WRAPPER_RULE,
            category=Category.POLICY,
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            title=f"{tool} wrapper downloads the build tool without a checksum",
            message=(
                f"{unit.path} names a {tool} distribution to download and run for every build, and "
                f"pins no `distributionSha256Sum`: whatever the URL serves is what builds this project."
            ),
            remediation=f"Add `distributionSha256Sum` (the {tool} project publishes it beside each distribution).",
            unit=unit,
            ctx=ctx,
            detail="distributionUrl without distributionSha256Sum",
            capabilities=(),
            reasons=["build tool fetched unverified"],
        )

    @classmethod
    def _source_priority_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """Indexes merged so that the highest version anywhere wins.

        pip given an extra index does not prefer either one: it collects every candidate from every
        index and installs the highest version. With a private index beside PyPI, anyone can
        publish an internal package's name on PyPI at a higher version and it is installed --
        dependency confusion without a typo. Reported when PyPI and another index are merged.

        NuGet the same way: with several package sources and no package source mapping, restore
        takes a package from whichever source answers, so an internal name published on nuget.org
        can be restored in place of the internal package. Microsoft's remedy is source mapping,
        and its absence is what is reported."""
        yield from cls._nuget_source_findings(manifest, unit, ctx)
        yield from cls._bundler_source_findings(manifest, unit, ctx)
        yield from cls._cocoapods_source_findings(manifest, unit, ctx)
        yield from cls._conan_remote_findings(manifest, unit, ctx)
        yield from cls._helm_repository_findings(manifest, unit, ctx)
        yield from cls._base_image_findings(manifest, unit, ctx)
        yield from cls._malformed_integrity_findings(manifest, unit, ctx)
        indexes = [
            s.split(" ", 1)[1]
            for s in manifest.sources
            if s.startswith(("index-url ", "extra-index-url "))
        ]
        extra = any(s.startswith("extra-index-url ") for s in manifest.sources)
        public = [i for i in indexes if "pypi.org" in i or "pythonhosted.org" in i]
        private = [i for i in indexes if i not in public]
        if not (extra and public and private):
            return
        from cordon_scanner.foundation.dependencies import DependencySource

        hosts = ", ".join(
            sorted(
                {
                    (DependencySource.sanitise(i) or i).split("/")[2] if "://" in i else i
                    for i in private
                }
            )
        )
        yield ManifestFinding.finding(
            rule_id=SOURCE_PRIORITY_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="A private index merged with PyPI",
            message=(
                f"{unit.path} sends pip to PyPI and to {hosts} together. pip installs the highest "
                f"version any index offers, so a name that exists only on the private index can be "
                f"published on PyPI at a higher version and installed in its place."
            ),
            remediation=(
                "Resolve from one index that proxies PyPI, or pin each internal package to its index "
                "(pip's `--index-url` alone, or Poetry/uv/PDM source pinning), and reserve the internal "
                "names on PyPI."
            ),
            unit=unit,
            ctx=ctx,
            detail=hosts,
            capabilities=(),
            reasons=["extra index merged with PyPI"],
        )

    _COMPOSER_BRANCH: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:dev-[\w./\-]{1,128}|[\w.]{1,64}\.x-dev|[\w.\-]{1,64}-dev)$"
    )

    @classmethod
    def _composer_branch_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A Composer constraint that names a branch (`dev-master`, `2.x-dev`), with or without an
        inline alias: what installs is whatever the branch points at when the lock is next
        updated. The lock pins a commit until then; the constraint is what lets it move."""
        if manifest.ecosystem not in SourceFindings.APPLIES_TO["_composer_branch_findings"]:
            return
        for declared in manifest.dependencies:
            constraint = declared.spec.split(" as ", 1)[0].strip()
            branch, _, commit = constraint.partition("#")
            if declared.scope is Scope.PLATFORM or not cls._COMPOSER_BRANCH.match(branch):
                continue
            if re.fullmatch(r"[0-9a-fA-F]{40}", commit):
                continue  # `dev-main#<full sha>`: pinned to one commit, whatever the branch does
            yield ManifestFinding.finding(
                rule_id=MUTABLE_REF_RULE,
                category=Category.POLICY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="Dependency on a branch that can move",
                message=(
                    f"{declared.name!r} is required as {declared.spec!r}: a branch, which a push "
                    f"re-points. The lock holds one commit until the next `composer update`, which "
                    f"takes whatever the branch has become, unreviewed and outside any release."
                ),
                remediation="Require a tagged release, or pin the commit (`dev-master#<sha>`) until one exists.",
                unit=unit,
                ctx=ctx,
                detail=f"{declared.field_name}.{declared.name} = {declared.spec}",
                capabilities=(),
                reasons=[f"declared in {declared.field_name}", "branch constraint"],
            )

    @classmethod
    def _cocoapods_source_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """The public spec repo listed before a private one. CocoaPods searches `source` lines in
        order and takes the first that has the pod, so a private pod's name published on trunk is
        resolved from trunk. Private repos first, trunk last, is the safe order."""
        if manifest.ecosystem not in SourceFindings.APPLIES_TO["_cocoapods_source_findings"]:
            return
        listed = [s.partition(" ")[2] for s in manifest.sources if s.startswith("source ")]
        public = [
            i for i, s in enumerate(listed) if "cdn.cocoapods.org" in s or "CocoaPods/Specs" in s
        ]
        private = [i for i, s in enumerate(listed) if i not in public]
        if not public or not private or min(public) > min(private):
            return
        from cordon_scanner.foundation.dependencies import DependencySource

        named = ", ".join(DependencySource.sanitise(listed[i]) or listed[i] for i in private)
        yield ManifestFinding.finding(
            rule_id=SOURCE_PRIORITY_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="Public spec repo searched before a private one",
            message=(
                f"{unit.path} lists the public CocoaPods trunk before {named}. CocoaPods takes a pod "
                f"from the first source that has it, so a private pod's name published on trunk is "
                f"installed in its place."
            ),
            remediation="List the private spec repos first and the public trunk last.",
            unit=unit,
            ctx=ctx,
            detail=named,
            capabilities=(),
            reasons=["public source before private"],
        )

    @classmethod
    def _malformed_integrity_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A digest a manifest pins (an image's `@sha256:...`, an archive's checksum) that is not a
        digest of any algorithm: what a lockfile's malformed hash is, written in the manifest. The
        value is never repeated."""
        from cordon_scanner.detect.supply.lockfile import MALFORMED_RULE
        from cordon_scanner.ecosystems.base import Coordinate

        malformed = sorted(
            {
                f"{declared.name}@{declared.spec}" if declared.spec else declared.name
                for declared in manifest.dependencies
                if (Coordinate.integrity(declared.integrity) or "").startswith(Coordinate.MALFORMED)
            }
        )
        if not malformed:
            return
        yield ManifestFinding.finding(
            rule_id=MALFORMED_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Lockfile integrity value is not a hash",
            message=(
                f"{len(malformed)} dependenc{'y pins' if len(malformed) == 1 else 'ies pin'} a digest that is not a "
                f"digest of any algorithm: {', '.join(malformed[:10])}. The values are not repeated here."
            ),
            remediation="Pin the digest the registry serves (`docker buildx imagetools inspect`, the registry's own record), and find out what wrote these values.",
            unit=unit,
            ctx=ctx,
            detail=malformed[0].split("@", 1)[0],
            capabilities=(),
            reasons=["a pinned digest that is not one"],
        )

    @classmethod
    def _base_image_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A stage built FROM an image named by tag alone. Read from the Dockerfile's stages, so
        `FROM builder` (an earlier stage), `FROM scratch`, `FROM --platform=...` and an image
        built from a global `ARG` are each read for what they are."""
        if manifest.ecosystem not in SourceFindings.APPLIES_TO["_base_image_findings"]:
            return
        for declared in manifest.dependencies:
            if declared.integrity:
                continue
            if declared.field_name.endswith(".image") or declared.field_name.startswith(
                "Kustomization images["
            ):
                yield from cls._workload_image_finding(declared, unit, ctx)
                continue
            if not declared.field_name.startswith("FROM "):
                continue
            written = declared.alias or declared.name
            yield ManifestFinding.finding(
                rule_id="POLICY.CONTAINER.UNPINNED_BASE.001",
                category=Category.POLICY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                title="Base image referenced by tag rather than digest",
                message=(
                    f"{written}:{declared.spec} is pinned by tag. A tag is mutable, so two builds of "
                    f"the same Dockerfile can produce different images, and a rebuild can pull "
                    f"content nobody reviewed."
                ),
                remediation="Pin by digest: FROM image:tag@sha256:...",
                unit=unit,
                ctx=ctx,
                detail=written,
                capabilities=(),
                reasons=[f"declared in {declared.field_name}", "no digest"],
            )

    @classmethod
    def _workload_image_finding(
        cls, declared: DeclaredDependency, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A Kubernetes container (or a Kustomize override) naming its image by tag."""
        written = declared.alias or declared.name
        yield ManifestFinding.finding(
            rule_id="POLICY.CONTAINER.UNPINNED_WORKLOAD_IMAGE.001",
            category=Category.POLICY,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            title="Kubernetes workload runs an image by tag rather than digest",
            message=(
                f"{declared.field_name} runs {written}:{declared.spec}, pinned by tag. Each node pulls "
                f"the tag when it schedules the pod, so a re-pushed tag reaches production with no "
                f"change to this manifest."
            ),
            remediation="Pin by digest: image: registry/name:tag@sha256:...",
            unit=unit,
            ctx=ctx,
            detail=f"{declared.field_name}:{written}",
            capabilities=(),
            reasons=[f"declared in {declared.field_name}", "no digest"],
        )

    @classmethod
    def _helm_repository_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A chart dependency from a plain-HTTP repository, or with no version at all. Read from
        the chart's dependencies, so the order of `version` and `repository` in an entry does not
        matter -- Helm's own examples put the version first."""
        basename = unit.path.rpartition("/")[2]
        if manifest.ecosystem in SourceFindings.APPLIES_TO["_helm_repository_findings"] and (
            basename in ("Chart.yaml", "Chart.yml")
        ):
            dependencies = list(manifest.dependencies)
        elif basename == "requirements.yaml":
            # An apiVersion v1 chart's dependencies: Helm's `dependencies:` key, where Ansible's
            # file of the same name holds `roles:` and `collections:`.
            from cordon_scanner.ecosystems.infra.helm import ChartFile
            from cordon_scanner.foundation.formats.datayaml import DataYaml

            try:
                data = DataYaml.load(unit.content.text, source=unit.path)
            except ValueError:
                return
            listed = data.get("dependencies") if isinstance(data, dict) else None
            if not isinstance(listed, list):
                return
            dependencies = [
                d
                for d in (
                    ChartFile.dependency(e, "dependencies") for e in listed if isinstance(e, dict)
                )
                if d is not None
            ]
        else:
            return
        weak = [
            d.name
            for d in dependencies
            if d.scope is not Scope.PLATFORM
            and not d.spec.startswith("path:")
            and ((d.source or "").startswith("http://") or d.spec.strip() in ("", "*"))
        ]
        if not weak:
            return
        named = ", ".join(sorted(weak))
        yield ManifestFinding.finding(
            rule_id="SUSPECT.HELM.UNTRUSTED_REPOSITORY.001",
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title="Chart depends on a chart from an unpinned or plain-HTTP repository",
            message=(
                f"{unit.path} pulls {named} over plain HTTP, or with no version at all. Chart "
                f"dependencies are rendered into the manifests applied to the cluster, so whoever "
                f"controls that repository controls what runs."
            ),
            remediation="Use HTTPS, pin each dependency to a version, and prefer a repository the organisation controls or mirrors.",
            unit=unit,
            ctx=ctx,
            detail=named,
            capabilities=(),
            reasons=["unpinned or cleartext chart repository"],
        )

    @classmethod
    def _conan_remote_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """ConanCenter listed before a private remote. Conan takes a recipe from the first remote
        that has it, so an internal recipe's name published on ConanCenter is fetched from there."""
        if manifest.ecosystem not in SourceFindings.APPLIES_TO["_conan_remote_findings"]:
            return
        listed = [
            s.split(" ")[2] if len(s.split(" ")) > 2 else ""
            for s in manifest.sources
            if s.startswith("remote ")
        ]
        public = [
            i for i, s in enumerate(listed) if re.search(r"(?:^|//)center2?\.conan\.io(?:/|$)", s)
        ]
        private = [i for i, s in enumerate(listed) if i not in public and s]
        if not public or not private or min(public) > min(private):
            return
        from cordon_scanner.foundation.dependencies import DependencySource

        named = ", ".join(DependencySource.sanitise(listed[i]) or listed[i] for i in private)
        yield ManifestFinding.finding(
            rule_id=SOURCE_PRIORITY_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="Public remote searched before a private one",
            message=(
                f"{unit.path} lists ConanCenter before {named}. Conan takes a recipe from the first "
                f"remote that has it, so an internal recipe's name published on ConanCenter is "
                f"fetched in its place."
            ),
            remediation="List the private remotes first and ConanCenter last, or pin each internal recipe to its remote.",
            unit=unit,
            ctx=ctx,
            detail=named,
            capabilities=(),
            reasons=["public source before private"],
        )

    @classmethod
    def _bundler_source_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """Several global `source` lines in a Gemfile. Bundler resolves a gem not pinned to a
        source block from any of them, and before 2.2.18 took the highest version across all --
        the dependency confusion recorded as CVE-2020-36327. The remedy is one global source and
        a `source ... do` block for the internal gems."""
        if manifest.ecosystem not in SourceFindings.APPLIES_TO["_bundler_source_findings"]:
            return
        global_sources = [
            s.partition(" ")[2]
            for s in manifest.sources
            if s.startswith("source ") and not s.startswith("source block ")
        ]
        if len(set(global_sources)) < 2:
            return
        from cordon_scanner.foundation.dependencies import DependencySource

        named = ", ".join(sorted({DependencySource.sanitise(s) or s for s in global_sources}))
        yield ManifestFinding.finding(
            rule_id=SOURCE_PRIORITY_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="Several global gem sources",
            message=(
                f"{unit.path} declares {len(set(global_sources))} global sources ({named}). A gem not "
                f"scoped to one can be taken from any of them, so an internal gem's name published on "
                f"rubygems.org can be installed in its place."
            ),
            remediation='Keep one global `source`, and require internal gems inside `source "<internal>" do ... end`.',
            unit=unit,
            ctx=ctx,
            detail=named,
            capabilities=(),
            reasons=["several global sources"],
        )

    @classmethod
    def _nuget_source_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        if manifest.ecosystem not in SourceFindings.APPLIES_TO["_nuget_source_findings"]:
            return
        sources = [s.partition(": ")[2] for s in manifest.sources if s.startswith("source ")]
        mapped = any(s.startswith("mapping ") for s in manifest.sources)
        public = [s for s in sources if "nuget.org" in s.lower()]
        private = [s for s in sources if s not in public]
        if mapped or not (public and private):
            return
        from cordon_scanner.foundation.dependencies import DependencySource

        named = ", ".join(sorted({(DependencySource.sanitise(s) or s) for s in private}))
        yield ManifestFinding.finding(
            rule_id=SOURCE_PRIORITY_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            title="Package sources without source mapping",
            message=(
                f"{unit.path} restores from nuget.org and from {named} with no package source "
                f"mapping, so NuGet takes each package from whichever source answers: an internal "
                f"package's name published on nuget.org can be restored in its place."
            ),
            remediation=(
                "Add <packageSourceMapping> routing the internal package prefixes to the internal "
                "source, and reserve the prefix on nuget.org."
            ),
            unit=unit,
            ctx=ctx,
            detail=named,
            capabilities=(),
            reasons=["several sources, no package source mapping"],
        )

    _CLEARTEXT: ClassVar[re.Pattern[str]] = re.compile(r"\bhttp://([^/\s:@]{1,253})", re.IGNORECASE)

    _LOOPBACK: ClassVar[frozenset[str]] = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})

    @classmethod
    def _cleartext_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A package source reached over plain HTTP.

        Whoever is on the network path -- a café's Wi-Fi, a compromised proxy, a hostile CI
        network -- can answer for that repository, and the build installs what they serve: the
        index, the metadata and, where no hash is pinned, the artefact itself. Maven 3.8.1 and
        later refuse such repositories by default for exactly this reason; pip, Gradle, Composer
        and older Maven do not. A loopback address never leaves the machine and is not reported.
        """
        seen: set[str] = set()
        for source in manifest.sources:
            match = cls._CLEARTEXT.search(source)
            if match is None:
                continue
            host = match.group(1).lower()
            if host in cls._LOOPBACK or host in seen:
                continue
            seen.add(host)
            yield ManifestFinding.finding(
                rule_id=CLEARTEXT_SOURCE_RULE,
                category=Category.POLICY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="Package source over plain HTTP",
                message=(
                    f"{unit.path} fetches packages from {host} over plain HTTP. Anyone on the network "
                    f"path can answer for that host, and the build installs what they serve."
                ),
                remediation=f"Use https:// for {host}, or remove the source.",
                unit=unit,
                ctx=ctx,
                detail=host,
                capabilities=(),
                reasons=["package source without TLS"],
            )

    @classmethod
    def source_findings(
        cls, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        yield from cls._source_priority_findings(manifest, unit, ctx)
        yield from cls._cleartext_findings(manifest, unit, ctx)
        yield from cls._composer_branch_findings(manifest, unit, ctx)
        ecosystem = EcosystemRegistry.get(manifest.ecosystem)
        for declared in manifest.dependencies:
            yield from SourceFindings._declared_source_findings(
                ctx, declared, ecosystem, manifest, unit
            )

    @staticmethod
    def _declared_source_findings(
        ctx: ScanContext,
        declared: DeclaredDependency,
        ecosystem: Ecosystem | None,
        manifest: Manifest,
        unit: FileUnit,
    ) -> Iterator[Finding]:
        """The findings for one dependency a manifest declares from somewhere other than its registry: a path inside the project, a mutable git reference, a remote tarball, another project's commit, a git dependency the ecosystem does not distribute."""
        if not declared.is_non_registry:
            return
        kind = DeclaredSource.kind(declared.spec, unit.path)
        if kind == "inside":
            # `file:packages/util`, `workspace:*`, `../shared` within this repository: the
            # project's own code, reviewed here as source. Reporting it reported every
            # monorepo's members as packages from outside the registry.
            return
        if (
            manifest.ecosystem in SourceFindings.APPLIES_TO["_dockerfile_add"]
            and declared.field_name.startswith("ADD (line")
            and declared.spec.startswith(("http", "git+http"))
        ):
            # `ADD https://...` with no flags: the Dockerfile rule for remote ADD reports this
            # line, and two findings for one download say nothing a second time.
            return
        locked_inputs = str(getattr(ecosystem, "locked_inputs", None) or "")
        if kind == "mutable" and declared.field_name in getattr(ecosystem, "index_fields", ()):
            # A package index (a Homebrew tap) follows its branch by design: what matters is
            # whose index it is, which the source rule below reports.
            kind = "index"
        if kind == "mutable" and locked_inputs and declared.field_name.startswith(locked_inputs):
            # A flake input's ref is the channel `nix flake update` follows; flake.lock, which
            # Nix writes and every build of the flake reads, pins it to a commit and a hash.
            return
        if kind == "mutable":
            yield ManifestFinding.finding(
                rule_id=MUTABLE_REF_RULE,
                category=Category.POLICY,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                title="Git dependency on a reference that can move",
                message=(
                    f"{declared.name!r} is declared as {declared.spec!r}: a branch, a tag or "
                    f"no reference at all, any of which a push can re-point. What installs "
                    f"tomorrow need not be what was reviewed today, and no registry hash, "
                    f"advisory match or release-age delay applies to it."
                ),
                remediation="Pin it to a full commit SHA, or depend on a registry release.",
                unit=unit,
                ctx=ctx,
                detail=f"{declared.field_name}.{declared.name} = {declared.spec}",
                capabilities=(),
                reasons=[f"declared in {declared.field_name}", "mutable git reference"],
            )
            return
        # A commit pins a git source; a checksum the declaration records pins an archive the
        # same way -- what is fetched cannot change under the project.
        checksummed = (
            kind == "url"
            and bool(declared.integrity)
            and not (declared.integrity or "").startswith("malformed:")
        )
        pinned = kind == "pinned" or checksummed
        if getattr(ecosystem, "registryless", False):
            # No registry exists to depart from (Nix): every source is a repository or an
            # archive. Plain HTTP is the cleartext rule's to report.
            return
        remote = ManifestScripts._remote_tarball(declared.spec, unit.path, ctx, checksummed)
        if remote is not None:
            # A published package whose dependency is a URL (review 98, REC-3): 339 malicious
            # npm samples declare one, and in 58 it is the entire package.
            yield from SourceFindings._remote_tarball_finding(ctx, declared, remote, unit)
            return
        foreign = (
            ManifestScripts._foreign_commit(declared.name, declared.spec, unit.path, ctx)
            if manifest.ecosystem in SourceFindings.APPLIES_TO["_foreign_commit"]
            else None
        )
        if foreign is not None:
            yield from SourceFindings._foreign_commit_finding(ctx, declared, foreign, unit)
            return
        if pinned and getattr(ecosystem, "git_distribution", False):
            # Where git is how the ecosystem distributes every package (SwiftPM), a commit
            # pin is its most immutable form, not a departure from a registry.
            return
        yield from SourceFindings._git_dependency_finding(
            checksummed, ctx, declared, kind, manifest, pinned, unit
        )

    @staticmethod
    def _remote_tarball_finding(
        ctx: ScanContext,
        declared: DeclaredDependency,
        remote: tuple[str, str, Severity],
        unit: FileUnit,
    ) -> Iterator[Finding]:
        """The finding for a dependency fetched as an archive from an outside host, graded by whether it is checksummed and whether the host is known for malware."""
        rule_id, host, severity = remote
        malicious = rule_id == MALICIOUS_REMOTE_TARBALL_RULE
        yield ManifestFinding.finding(
            rule_id=rule_id,
            category=Category.MALICIOUS if malicious else Category.SUSPICIOUS,
            severity=severity,
            confidence=Confidence.HIGH if malicious else Confidence.MEDIUM,
            title=(
                "A published package installs a dependency from a drop-point host"
                if malicious
                else "A published package installs a dependency from an arbitrary URL"
            ),
            message=(
                f"{declared.name!r} is declared as {declared.spec!r}: every install of "
                f"this package fetches it from {host} and runs it, unpinned and unreviewed"
                + (
                    ", and that host is a raw address or a paste, webhook or tunnel "
                    "service, which no package is distributed from."
                    if malicious
                    else "."
                )
            ),
            remediation=(
                "Do not install it. Treat any machine that did as having run untrusted code."
                if malicious
                else "Do not install it until the URL's content has been examined."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"{declared.field_name}.{declared.name} = {declared.spec}",
            capabilities=(),
            reasons=[f"declared in {declared.field_name}", f"fetched from {host}"],
        )

    @staticmethod
    def _foreign_commit_finding(
        ctx: ScanContext, declared: DeclaredDependency, foreign: str, unit: FileUnit
    ) -> Iterator[Finding]:
        """The finding for a dependency installed from a commit of another project's repository: the hash reaches commits pushed to any fork, and npm runs the commit's install scripts."""
        yield ManifestFinding.finding(
            rule_id=FOREIGN_COMMIT_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="A published package installs a dependency from another project's commit",
            message=(
                f"{declared.name!r} is declared as {declared.spec!r}: one commit of "
                f"{foreign}, a repository that is not that package's. A full commit hash "
                f"reaches any commit in the repository's fork network, including one pushed "
                f"to a fork that no branch of it holds, and npm runs that commit's install "
                f"scripts on every machine that installs this package."
            ),
            remediation=(
                "Do not install it. Find the commit's origin; a dependency the publisher "
                "meant to ship has a registry release or a repository of its own name."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"{declared.field_name}.{declared.name} = {declared.spec}",
            capabilities=(),
            reasons=[f"declared in {declared.field_name}", f"commit of {foreign}"],
            # Only a published package's own manifest is judged here, and that is never a
            # test fixture -- a test helper's own release is still a release (review 98:
            # jest-date-mock 1.0.11, a mocking library, was capped as test material).
            fixture_ceiling=False,
        )

    @staticmethod
    def _git_dependency_finding(
        checksummed: bool,
        ctx: ScanContext,
        declared: DeclaredDependency,
        kind: str,
        manifest: Manifest,
        pinned: bool,
        unit: FileUnit,
    ) -> Iterator[Finding]:
        """The finding for a dependency installed from git that its ecosystem would otherwise distribute: graded by whether the reference is pinned."""
        yield ManifestFinding.finding(
            rule_id="POLICY.DEPENDENCY.SOURCE.001",
            category=Category.POLICY,
            severity=Severity.LOW if pinned else Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            title="Dependency resolved from outside the registry",
            message=(
                f"{declared.name!r} is declared as {declared.spec!r}, which does not "
                f"resolve from the {manifest.ecosystem} registry"
                + (
                    ", pinned by its checksum, so it cannot change under the project"
                    if checksummed
                    else ", pinned to a commit, so it cannot change under the project"
                    if pinned
                    else ""
                )
                + ". Lockfile integrity hashes, advisory matching and any release-age delay "
                "apply to registry packages and none of them apply here. The dependency may "
                "be entirely legitimate; the safety net is simply absent."
            ),
            remediation=(
                "Publish the package to a registry the organisation controls, or "
                "vendor it into the repository where it is reviewed like any other "
                "code."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"{declared.field_name}.{declared.name} = {declared.spec}",
            capabilities=(),
            reasons=[f"declared in {declared.field_name}", "commit-pinned" if pinned else kind],
        )


__all__ = ["SourceFindings"]
