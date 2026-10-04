"""Questions about dependencies that only a registry can answer.

Three facts have no local source, and each closes a gap the offline detectors
cannot reach:

**Withdrawal.** A version yanked from PyPI or unpublished from npm was
withdrawn by somebody -- often because it was malicious, often because it was
broken. A lockfile pins it happily either way, and nothing in the repository
records that the pin now points at something its own publisher retracted.

**Distance from what is published.** A pin far behind the current release is
ordinary in a conservative project and is also what a downgrade attack produces.
This reports the distance and says nothing about the cause, because the
difference between the two is a decision the reader makes with context this tool
does not have.

**Integrity.** A lockfile records a hash. The registry records a hash. If they
disagree, one of them is not describing the artefact that will be installed, and
that is worth interrupting a build over.

Every finding from here is marked as depending on a network answer, because it
does: rerun the same scan offline and it disappears, rerun it next week and it
may differ. That is a property of the question, not a defect, and a report that
did not say so would be claiming a reproducibility it does not have.

The detector requires `network`, so the engine skips it entirely unless the scan
was explicitly taken online. Failures are reported rather than swallowed -- an
unreachable registry means the questions went unanswered, which is not the same
as answering "no".

**The source a package claims.** A manifest names the repository the package is
built from, and that link is the thing most people actually check before
depending on something: they read the code on the forge and assume it is the
code in the artefact. Nothing enforces the connection. A package can point at a
well-regarded repository it has no relationship with, and the registry's own
record of that package is the only place the disagreement shows up.

So the comparison is between the repository this project's manifest declares and
the repository the registry records for the same package name. It runs on the
manifests in the scan target rather than on the dependency graph, because that
is where the local claim lives: a lockfile pins a name, a version and a hash,
and records nothing about where the code came from. Both sides are reduced to a
forge, an owner and a repository name before comparing, so a shorthand, an SSH
URL and a link into a monorepo subdirectory all compare equal to the plain HTTPS
form -- what differs after that is a real disagreement rather than a spelling.

A package the registry has never heard of produces nothing. Most manifests in
most repositories are for something unpublished, and treating "not found" as a
mismatch would report every private project in existence.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import TYPE_CHECKING

from cordon_scanner.core import references
from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import (
    BaseDetector,
    DetectorRequirements,
    FileUnit,
    GraphUnit,
    ScanContext,
)
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.ecosystems.registry import EcosystemRegistry

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.models import Dependency
    from cordon_scanner.detect.base import Unit
    from cordon_scanner.intel.registry_client import PackageFacts

MAX_QUERIES = 200
"""How many packages one scan will ask about.

A large graph would otherwise mean thousands of requests, which is slow enough
that people stop passing the flag, and impolite enough to the registry that it
deserves a ceiling. Direct dependencies are asked about first, because those are
the ones somebody chose."""

MAX_MANIFEST_QUERIES = 50
"""How many manifests one scan will ask the registry about.

A monorepo has hundreds, and asking about every one of them turns a scan into a
few hundred sequential requests -- slow enough that people stop passing
`--online`, and impolite enough to the registry that it deserves a ceiling.
The first fifty are the ones nearest the top of the walk, which in a monorepo
are the ones somebody publishes."""

REGISTRY_ECOSYSTEMS = frozenset(
    {
        "npm",
        "pypi",
        "cargo",
        "rubygems",
        "nuget",
        "gomod",
        "maven",
        "gradle",
        "composer",
        "pub",
        "hex",
    }
)
"""Ecosystems whose registry this can ask. Kept beside the client's own host
map so a manifest for an ecosystem with no configured registry is skipped
before a request is built rather than after it fails."""

CONFUSABLE_ECOSYSTEMS = frozenset({"npm", "pypi", "cargo", "rubygems", "nuget", "pub", "hex"})
"""Where a name missing from the public registry is a dependency-confusion risk.

Not Composer either: since Composer 2 a custom repository is canonical for every package it
holds, so Packagist is never consulted for a name a private repository serves.

Not Go and not Maven. A Go module path is a URL its owner controls and Maven Central verifies
group ownership by domain, so a private module or artefact absent from the public index cannot
be shadowed by a stranger registering the name - and both are absent for every private module
in existence, so reporting them would bury the finding where it means something."""

FORGE_SHORTHANDS = {
    "github": "github.com",
    "gitlab": "gitlab.com",
    "bitbucket": "bitbucket.org",
    "gist": "gist.github.com",
}
"""npm accepts `github:owner/repo` and friends in the `repository` field, and
plenty of packages use them. Expanded here so a shorthand and the HTTPS URL it
abbreviates compare as the same repository, which is what they are."""


class RegistryEvidence:
    """Repository identities and digests as registries report them."""

    @staticmethod
    def repository_identity(url: str | None) -> tuple[str, str, str] | None:
        """A repository URL reduced to the forge, owner and name it points at.

        The same repository is written half a dozen ways: `git@github.com:o/r.git`,
        `git+https://github.com/o/r.git`, `github:o/r`, a bare `o/r`, and a link
        into a subdirectory of a monorepo. All of those are one repository, and a
        comparison that treated them as different would report a mismatch on
        essentially every package that uses anything but the plain HTTPS form.

        So: the transport prefix goes, credentials go, the query and fragment go,
        the `.git` suffix goes, and only the first two path segments are kept --
        everything after `owner/repo` is a path *inside* the repository, not part of
        its identity.

        Returns `None` when the string does not resolve to all three parts.
        Comparing an unresolvable claim against anything would be guessing, and the
        caller is expected to stay quiet rather than guess.
        """
        if not url:
            return None

        text = url.strip()
        if not text:
            return None

        # `git+https://...`, `git+ssh://...`: the transport is a packaging detail.
        if text.startswith("git+"):
            text = text[4:]

        # An npm shorthand, or a bare `owner/repo` which npm reads as GitHub.
        scheme, separator, remainder = text.partition(":")
        if separator and scheme.lower() in FORGE_SHORTHANDS and not remainder.startswith("//"):
            text = f"https://{FORGE_SHORTHANDS[scheme.lower()]}/{remainder.lstrip('/')}"
        elif "://" not in text and "@" not in text:
            segments = [part for part in text.split("/") if part]
            if len(segments) == 2 and "." not in segments[0]:
                text = f"https://github.com/{segments[0]}/{segments[1]}"

        # `git@host:owner/repo`, the SCP-style form URL parsers do not accept.
        if "://" not in text and "@" in text:
            _, _, tail = text.partition("@")
            host, separator, path = tail.partition(":")
            if separator:
                text = f"https://{host}/{path.lstrip('/')}"

        parsed = urllib.parse.urlsplit(text if "://" in text else f"https://{text}")
        host = parsed.hostname or ""
        if not host:
            return None
        if host.startswith("www."):
            host = host[4:]

        segments = [part for part in parsed.path.split("/") if part]
        if len(segments) < 2:
            return None

        owner, name = segments[0], segments[1]
        if name.endswith(".git"):
            name = name[:-4]
        if not owner or not name:
            return None

        return (host.lower(), owner.lower(), name.lower())

    @staticmethod
    def _canonical_digest(value: str | None) -> tuple[str, str] | None:
        """A hash string as `(algorithm, lowercase hex)`, or `None` if it is not one.

        Registries and lockfiles write the same digest three ways: Subresource
        Integrity (`sha512-<base64>`, npm), a prefixed hex (`sha256:<hex>`, pip),
        and a bare hex whose length names the algorithm (PyPI\'s `digests.sha256`,
        npm\'s `dist.shasum`).

        Everything else returns `None`, and that is the point of the function.
        Yarn Berry\'s `checksum:` (`10c0/<hex>`) and Go\'s `h1:<base64>` occupy the
        same field as a registry digest and are not one, so a caller that compared
        them against what a registry publishes would find a contradiction in every
        correct lockfile.
        """
        if not value:
            return None
        text = value.strip()
        if not text:
            return None
        if text.startswith("h1:"):
            # Go's module hash, which sum.golang.org publishes and go.sum records: comparable
            # with itself and with nothing else, so it is its own algorithm here.
            return RegistryEvidence._h1(text[3:])

        prefix, separator, rest = text.partition("-")
        if not separator:
            prefix, separator, rest = text.partition(":")
        if separator:
            algorithm = prefix.strip().lower()
            expected = _DIGEST_HEX_LENGTHS.get(algorithm)
            if expected is None:
                return None
            return RegistryEvidence._as_hex(rest.strip(), expected, algorithm)

        for algorithm, expected in _DIGEST_HEX_LENGTHS.items():
            if len(text) == expected:
                return RegistryEvidence._as_hex(text, expected, algorithm)
        # A bare base64 digest, as NuGet's packages.lock.json writes `contentHash`: its decoded
        # length names the algorithm, and only a sha256 or sha512 length is accepted.
        for algorithm in ("sha512", "sha256"):
            parsed = RegistryEvidence._as_hex(text, _DIGEST_HEX_LENGTHS[algorithm], algorithm)
            if parsed is not None and len(text) in (44, 88):
                return parsed
        return None

    @staticmethod
    def _h1(body: str) -> tuple[str, str] | None:
        try:
            raw = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            return None
        return ("h1", raw.hex()) if len(raw) == 32 else None

    @staticmethod
    def _as_hex(body: str, expected_hex_length: int, algorithm: str) -> tuple[str, str] | None:
        """`body` as `(algorithm, hex)` when it decodes to a digest of that length."""
        lowered = body.lower()
        if len(lowered) == expected_hex_length:
            try:
                bytes.fromhex(lowered)
            except ValueError:
                return None
            return (algorithm, lowered)

        try:
            raw = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(raw) * 2 != expected_hex_length:
            return None
        return (algorithm, raw.hex())


#: Digest length in hex characters, by algorithm name. A value is a digest of
#: one of these only when its length says so, which is what separates a hash
#: from a string that merely sits in a hash-shaped field.
_DIGEST_HEX_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}


MIN_ATTESTED_SIBLINGS = 3
"""How many *earlier* attested releases make an unattested one worth reporting.

One is a project that tried provenance once. A handful is a project that
publishes with it, and a release that skipped it did not come from the pipeline
the others came from.

Earlier ones only, which the client counts. A package that adopted provenance
last month has an attested latest and an unattested everything-else, and
counting totals would put this finding on every pin that predates the practice
-- `requests==2.31.0` among them, which skipped nothing."""


NETWORK_CAVEAT = (
    "This finding came from a live registry query. It is not reproducible from "
    "the repository alone, and rerunning the scan offline will not produce it."
)


class RegistryNotices:
    """Publisher-written registry text, made safe to quote, and what it says."""

    MAX_NOTICE = 200
    _CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
    _SECURITY = re.compile(
        r"\b(?:secur\w*|vulnerab\w*|cve-\d{4}-\d+|malicious|malware|compromis\w*|backdoor\w*|exploit\w*)\b",
        re.IGNORECASE,
    )

    @classmethod
    def clean(cls, text: str) -> str:
        """Controls, bidi overrides and zero-width characters out; whitespace collapsed; bounded."""
        flat = " ".join(cls._CONTROL.sub(" ", text).split())
        return flat if len(flat) <= cls.MAX_NOTICE else flat[: cls.MAX_NOTICE - 1] + "\u2026"

    @classmethod
    def cites_security(cls, notice: str) -> bool:
        return bool(cls._SECURITY.search(notice))

    @staticmethod
    def older_than(timestamp: str | None, days: int) -> bool:
        import datetime as _dt

        if not timestamp:
            return False
        try:
            when = _dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=_dt.UTC)
        return (_dt.datetime.now(_dt.UTC) - when).days > days


class RegistryDetector(BaseDetector):
    """Enriches the dependency graph with what the registry says."""

    id = "registry"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True, dependencies=True, network=True)

    def __init__(self) -> None:
        self._manifests_asked = 0

    def applicable(self, ctx: ScanContext) -> bool:
        return bool(ctx.dependencies) and not ctx.offline

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.YANKED.001",
                title="Dependency pins a version its publisher withdrew",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "The publisher withdrew this version. A yank is the strongest signal a "
                    "registry offers short of deletion, and it usually means the release was "
                    "broken, mis-published or compromised."
                ),
                references=(references.PYPI_YANK,),
                remediation=(
                    "Move off the withdrawn version. A release is yanked because "
                    "its publisher decided nobody should be installing it."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.STARJACKING.001",
                title="A new package claims a popular project's repository",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "A package published in the last ninety days names, as its source, the repository of "
                    "a different and popular package. The registry shows that repository's stars and "
                    "history beside it, which is the trust a squat borrows (starjacking)."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation=(
                    "Check that the package is really published by that project; if it is not, remove it "
                    "and install the package the repository actually publishes."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.001",
                title="Dependency pins a version its publisher deprecated for a security reason",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "The publisher deprecated this version and the notice names a vulnerability, a "
                    "compromise or malicious code. Publishers deprecate rather than unpublish when "
                    "npm will not let them remove a release, so this is often the only warning."
                ),
                references=(references.INSECURE_DEFAULT,),
                remediation="Move to the version the notice names, and check whether the deprecated one ran anywhere.",
            ),
            DeclaredRule(
                id="POLICY.DEPENDENCY.DEPRECATED.001",
                title="Dependency pins a version its publisher deprecated",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.POLICY,
                detector=RegistryDetector.id,
                message=(
                    "The publisher marked this version deprecated, or the project declares itself "
                    "inactive. Nothing will be fixed in it, security fixes included."
                ),
                references=(references.INSECURE_DEFAULT,),
                remediation="Move to the replacement the notice names, or a maintained alternative.",
            ),
            DeclaredRule(
                id="POLICY.DEPENDENCY.UNMAINTAINED.001",
                title="Dependency has had no release in five years",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=RegistryDetector.id,
                message=(
                    "The package's last release is more than five years old. Finished is not the "
                    "same as abandoned, and an abandoned package is one whose next vulnerability "
                    "will not be fixed, and whose name is the one a takeover would target."
                ),
                references=(references.INSECURE_DEFAULT,),
                remediation="Confirm it is finished rather than abandoned, or plan a maintained replacement.",
            ),
            DeclaredRule(
                id="POLICY.DEPENDENCY.DOWNGRADE.001",
                references=(references.INSECURE_DEFAULT,),
                title="Dependency pins a version far behind the current release",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category=Category.POLICY,
                detector=RegistryDetector.id,
                message=(
                    "The pinned version trails the current release by a wide margin. Old is not "
                    "the same as vulnerable, and it does mean fixes published since have not "
                    "been taken."
                ),
                remediation=(
                    "Confirm the pin is deliberate. A distant pin is ordinary in a "
                    "conservative project and is also what a downgrade attack "
                    "produces."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.PROVENANCE.MISMATCH.001",
                title="Lockfile hash disagrees with the registry",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "The hash in the lockfile is not the hash the registry serves for that "
                    "version. One of the two changed after the other was recorded, and until it "
                    "is known which, the artefact that installs is not the one that was "
                    "reviewed."
                ),
                references=(
                    references.INSUFFICIENT_VERIFICATION,
                    references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
                ),
                remediation=(
                    "Do not install. One of the two records is not describing the "
                    "artefact that will arrive, and until that is resolved neither "
                    "can be trusted."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.REPOSITORY.001",
                title="Package claims a source repository the registry does not record",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "The package's stated source repository disagrees with what the registry "
                    "holds. Whoever reads the source to decide whether to trust the package may "
                    "not be reading the source the package was built from."
                ),
                references=(references.INSUFFICIENT_VERIFICATION,),
                remediation=(
                    "Establish which repository the published artefact was "
                    "actually built from. Reading the linked source proves "
                    "nothing about the package while the two disagree."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.PROVENANCE.001",
                title="Version published without the provenance its package normally carries",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "Earlier releases of this package carry build provenance and this one does "
                    "not. A publishing pipeline that stops attesting for one version is worth "
                    "understanding before that version is trusted."
                ),
                references=(references.SLSA_PROVENANCE,),
                remediation=(
                    "Establish where this release was built. Its siblings can "
                    "be traced to a commit and a workflow and this one cannot, "
                    "which is the difference a compromised publishing token "
                    "produces."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.UNVETTED.001",
                title="A dependency is new, sourceless and unknown: the shape of a slopsquatted package",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "The registry says this package is under three months old and records no source "
                    "repository, and it is either barely downloaded or named by adding a generic word "
                    "to an established package. AI coding assistants suggest names like these, and "
                    "attackers register them."
                ),
                references=(references.PACKAGE_HALLUCINATION,),
                remediation=(
                    "Confirm the package is the one you meant: check its publisher and code, or replace "
                    "it with the established package it was named after."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.DEPENDENCY.UNREGISTERED.001",
                title="A dependency does not exist on its public registry",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=RegistryDetector.id,
                message=(
                    "The public registry has no package by this name. Either it is private, and "
                    "anyone who registers the name publicly can have their package installed in its "
                    "place (dependency confusion), or the name was invented -- AI coding assistants "
                    "suggest plausible package names that do not exist, and attackers register them "
                    "(slopsquatting)."
                ),
                references=(references.DEPENDENCY_CONFUSION, references.PACKAGE_HALLUCINATION),
                remediation=(
                    "If the package is private, resolve it only from your private registry (a scoped "
                    "registry for npm, `--index-url` without `--extra-index-url` for pip) and register "
                    "the name publicly as a placeholder. If nobody can say where it came from, remove it."
                ),
            ),
            DeclaredRule(
                id="OPERATIONAL.REGISTRY.UNREACHABLE.001",
                title="Registry could not be asked about a dependency",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=RegistryDetector.id,
                message=(
                    "A registry lookup failed. The package is neither confirmed good nor "
                    "confirmed bad, and reporting that is the only honest outcome."
                ),
                remediation=(
                    "Rerun when the registry is reachable, or accept that these checks did not run."
                ),
            ),
            DeclaredRule(
                id="OPERATIONAL.REGISTRY.NO_SOURCE.001",
                title="No registry is configured for part of the dependency graph",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=RegistryDetector.id,
                message=(
                    "Some of the graph belongs to an ecosystem no registry was configured for, "
                    "so nothing could be asked about those packages at all."
                ),
                remediation=(
                    "None needed if the ecosystem is not one you gate on. The online "
                    "checks cover npm, PyPI, crates.io, RubyGems, NuGet, Go, Maven "
                    "Central, Packagist, pub.dev and Hex; for anything else the offline "
                    "rules are the whole answer."
                ),
            ),
            DeclaredRule(
                id="OPERATIONAL.REGISTRY.NOT_ASKED.001",
                title="Dependencies past the query ceiling or time budget were never asked about",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.OPERATIONAL,
                detector=RegistryDetector.id,
                message=(
                    "The scan stopped asking the registry before the graph ran out. Everything "
                    "past that point is unexamined rather than clean, and this finding is what "
                    "keeps the two distinguishable."
                ),
                remediation=(
                    "Raise --timeout, or narrow the scan so the budget covers the graph. "
                    "A package nobody asked about is not a package that came back clean."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.offline:
            return ()
        if isinstance(unit, FileUnit):
            return self._manifest_findings(unit, ctx)
        if not isinstance(unit, GraphUnit):
            return ()

        from cordon_scanner.intel.registry_client import (
            PackageNotFound,
            RegistryClient,
            RegistryError,
        )

        findings: list[Finding] = []
        unanswered: list[str] = []

        # Only the ecosystems this can actually ask. `facts()` raises for the
        # rest, which landed them in `unanswered` beside genuine network
        # failures -- so a Cargo lockfile scanned with --online reported that
        # its packages "could not be checked against their registry", which
        # reads as a transient outage rather than a capability this tool does
        # not have.
        # A container image's OS packages come from the distribution's own signed repositories,
        # not a language registry; they are matched against distribution advisories instead.
        unsupported = sorted(
            {
                d.ecosystem
                for d in unit.dependencies
                if d.ecosystem not in REGISTRY_ECOSYSTEMS
                and d.ecosystem not in ("deb", "apk", "rpm")
            }
        )
        askable = [
            d
            for d in self._order(unit.dependencies)
            if d.version and d.ecosystem in REGISTRY_ECOSYSTEMS
        ]
        asking = askable[:MAX_QUERIES]
        # Counted, not inferred from the finding below. A reader reconciling
        # "250 dependencies" against "200 could not be checked" concludes that
        # fifty were checked and came back clean, and the fifty past the ceiling
        # were never asked about at all.
        over_ceiling = len(askable) - len(asking)
        ran_out_of_time = 0

        for index, dependency in enumerate(asking):
            if ctx.out_of_time():
                ran_out_of_time = len(asking) - index
                break
            try:
                observed = RegistryClient.facts(
                    dependency.ecosystem, dependency.name, dependency.version
                )
            except PackageNotFound:
                if dependency.ecosystem in CONFUSABLE_ECOSYSTEMS and not self._resolved_privately(
                    dependency
                ):
                    findings.append(
                        self._finding(
                            "SUSPECT.DEPENDENCY.UNREGISTERED.001",
                            ctx,
                            dependency=dependency,
                            detail=(
                                f"{dependency.name} is not on the public {dependency.ecosystem} registry. "
                                f"Either it is private, and a public package registered under the name "
                                f"could be installed in its place, or the name was invented -- AI coding "
                                f"assistants suggest package names that do not exist, and attackers "
                                f"register them."
                            ),
                        )
                    )
                continue
            except RegistryError as exc:
                unanswered.append(f"{dependency.name}: {exc}")
                continue
            findings.extend(self._compare(dependency, observed, ctx))

        if unanswered:
            # One aggregated report rather than one per package: an offline
            # runner would otherwise produce a finding for every dependency in
            # the graph, and a report nobody reads is the same as no report.
            # It is still reported, because "we could not ask" and "the answer
            # was no" are different facts.
            findings.append(
                self._finding(
                    "OPERATIONAL.REGISTRY.UNREACHABLE.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"{len(unanswered)} of {len(askable)} package(s) could not be "
                        f"checked against their registry, so withdrawal, distance and "
                        f"hash verification did not run for them. First: {unanswered[0]}"
                    ),
                    degrades_coverage=True,
                )
            )

        if unsupported:
            counted = sum(1 for d in unit.dependencies if d.ecosystem in unsupported and d.version)
            findings.append(
                self._finding(
                    "OPERATIONAL.REGISTRY.NO_SOURCE.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"--online has no registry configured for "
                        f"{', '.join(unsupported)}, so withdrawal, distance, hash and "
                        f"provenance checks did not run for {counted} package(s). Only "
                        f"{' and '.join(sorted(REGISTRY_ECOSYSTEMS))} are asked. Those "
                        f"packages were not checked and found clean; they were not "
                        f"checked."
                    ),
                    degrades_coverage=True,
                )
            )

        if over_ceiling or ran_out_of_time:
            reasons = []
            if over_ceiling:
                reasons.append(f"{over_ceiling} past the {MAX_QUERIES}-query ceiling for one scan")
            if ran_out_of_time:
                reasons.append(f"{ran_out_of_time} when the scan's time budget ran out")
            findings.append(
                self._finding(
                    "OPERATIONAL.REGISTRY.NOT_ASKED.001",
                    ctx,
                    dependency=None,
                    detail=(
                        f"{over_ceiling + ran_out_of_time} of {len(askable)} package(s) "
                        f"were never asked about: {', and '.join(reasons)}. Nothing is "
                        f"known about those versions -- they were not checked and found "
                        f"clean."
                    ),
                    degrades_coverage=True,
                )
            )
        return findings

    def _manifest_findings(self, unit: FileUnit, ctx: ScanContext) -> list[Finding]:
        """Whether this project's manifest and the registry agree on the source.

        Silent unless every part of the question has an answer: the file is a
        manifest, it names a package, the package declares a repository, the
        registry knows the name, the registry records a repository of its own,
        and both reduce to a forge, an owner and a name. Any gap means the
        comparison was not made, and a finding claiming otherwise would be
        asserting a disagreement between two things one of which was never
        read.
        """
        from cordon_scanner.intel.registry_client import RegistryClient, RegistryError

        ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
        if ecosystem_id is None or ecosystem_id not in REGISTRY_ECOSYSTEMS:
            return []

        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return []

        manifest = ecosystem.parse_manifest(unit.content)
        if manifest.parse_error or manifest.private or not manifest.name:
            return []

        declared = RegistryEvidence.repository_identity(manifest.repository)
        if declared is None:
            return []

        # Counted after every cheap reason to stay quiet, so the budget is
        # spent on manifests a question could actually be asked about.
        if self._manifests_asked >= MAX_MANIFEST_QUERIES:
            return []
        self._manifests_asked += 1

        try:
            observed = RegistryClient.facts(ecosystem_id, manifest.name, manifest.version)
        except RegistryError:
            # A name the registry cannot answer about is the ordinary case for
            # an unpublished project, and is already reported in aggregate by
            # the graph pass. Reporting it again per manifest would drown the
            # thing this method exists to say.
            return []

        published = RegistryEvidence.repository_identity(observed.repository)
        if published is None or published == declared:
            return []

        detail = (
            f"{unit.path} says {manifest.name} is built from "
            f"{'/'.join(declared)}, and the {ecosystem_id} registry records "
            f"{'/'.join(published)} for that package. Reviewers who follow the "
            f"link in the manifest are reading a different repository from the "
            f"one the published package names."
        )
        return [
            self._finding(
                "SUSPECT.PACKAGE.REPOSITORY.001",
                ctx,
                dependency=None,
                detail=detail,
                path=unit.path,
            )
        ]

    @staticmethod
    def _order(dependencies: tuple[Dependency, ...]) -> list[Dependency]:
        """Every dependency, in the order requests should be spent on them.

        Direct first, then by depth. A ceiling applied to this order spends the
        budget where an answer is most likely to matter, and the caller reports
        how much of the list it did not reach.
        """
        return sorted(dependencies, key=lambda d: (not d.direct, d.depth, d.purl))

    def _compare(
        self, dependency: Dependency, observed: object, ctx: ScanContext
    ) -> Iterable[Finding]:
        from cordon_scanner.intel.registry_client import PackageFacts

        if not isinstance(observed, PackageFacts):  # pragma: no cover - defensive
            return

        unvetted = self._unvetted(dependency, observed)
        if unvetted:
            yield self._finding(
                "SUSPECT.DEPENDENCY.UNVETTED.001", ctx, dependency=dependency, detail=unvetted
            )

        if observed.yanked and self._withdrawal_applies(dependency):
            reason = f" ({observed.yanked_reason})" if observed.yanked_reason else ""
            yield self._finding(
                "SUSPECT.DEPENDENCY.YANKED.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}@{dependency.version} was withdrawn by its "
                    f"publisher{reason}, and this lockfile still pins it"
                ),
            )

        borrowed = self._starjacked(dependency, observed)
        if borrowed:
            yield self._finding(
                "SUSPECT.PACKAGE.STARJACKING.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name}, first published {str(observed.first_published)[:10]}, names "
                    f"{borrowed} as its repository: the repository of the popular package of that name, "
                    f"not of {dependency.name}"
                ),
            )

        if observed.deprecated:
            notice = RegistryNotices.clean(observed.deprecated)
            security = RegistryNotices.cites_security(notice)
            yield self._finding(
                "SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.001"
                if security
                else "POLICY.DEPENDENCY.DEPRECATED.001",
                ctx,
                dependency=dependency,
                detail=f"{dependency.name}@{dependency.version} is deprecated by its publisher: \u201c{notice}\u201d",
            )
        elif RegistryNotices.older_than(observed.last_published, UNMAINTAINED_DAYS):
            yield self._finding(
                "POLICY.DEPENDENCY.UNMAINTAINED.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{dependency.name} last published a release on "
                    f"{str(observed.last_published)[:10]}, more than five years ago"
                ),
            )

        if self._digest_conflict(dependency, observed.digests):
            yield self._finding(
                "SUSPECT.PROVENANCE.MISMATCH.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"the hash recorded for {dependency.name}@{dependency.version} "
                    f"is not among the hashes the registry publishes for that version"
                ),
            )

        if observed.attested_versions >= MIN_ATTESTED_SIBLINGS and not observed.attested:
            yield self._finding(
                "SUSPECT.PACKAGE.PROVENANCE.001",
                ctx,
                dependency=dependency,
                detail=(
                    f"{observed.attested_versions} earlier release(s) of "
                    f"{dependency.name} were published with build provenance and "
                    f"{dependency.version} was not. The package was already "
                    f"attesting when this one shipped, so this is not a pin that "
                    f"predates the practice -- it is a release that can be traced "
                    f"to no commit and no workflow while its siblings can"
                ),
            )

        if observed.latest and dependency.version and observed.latest != dependency.version:
            behind = self._major_distance(dependency.version, observed.latest)
            if behind >= ctx.config.policy.max_major_drift:
                yield self._finding(
                    "POLICY.DEPENDENCY.DOWNGRADE.001",
                    ctx,
                    dependency=dependency,
                    detail=(
                        f"{dependency.name} is pinned to {dependency.version} while "
                        f"{observed.latest} is current, {behind} major versions ahead"
                    ),
                )

    @staticmethod
    def _starjacked(dependency: Dependency, observed: PackageFacts) -> str:
        """The borrowed repository (`forge/owner/name`), or "" when the claim is the package's own.

        Fires only for a young package whose repository's name is a DIFFERENT popular package in the
        same ecosystem, and never when the repository is the package's own name, a prefix of it, or
        its npm scope: `@babel/plugin-x` pointing at `babel/babel` is a monorepo, not a squat.
        """
        from cordon_scanner.intel.popular import PackageIntel

        identity = RegistryEvidence.repository_identity(observed.repository)
        first = observed.first_published
        if identity is None or not first or RegistryNotices.older_than(first, STARJACK_YOUNG_DAYS):
            return ""
        forge, owner, repo = identity
        repo, owner = repo.lower().removesuffix(".git"), owner.lower()
        name = dependency.name.lower()
        scope, _, base = name.rpartition("/")
        scope = scope.lstrip("@")
        if repo in (base, scope) or owner == scope or base.startswith(repo):
            return ""
        if repo not in PackageIntel.POPULAR_PACKAGES.get(dependency.ecosystem, frozenset()):
            return ""
        return f"{forge}/{owner}/{repo}"

    @staticmethod
    def _digest_conflict(dependency: Dependency, published: tuple[str, ...]) -> bool:
        """Whether the recorded hash contradicts every published one.

        Absence is not a conflict. A lockfile with no hash is already reported
        by the offline integrity rule, and a registry that publishes none
        cannot contradict anything -- treating either as a mismatch would make
        this rule fire on the ordinary case and mean nothing on the real one.

        Neither is a value that is not a registry digest at all. Yarn Berry\'s
        `checksum:` is a hash of its own cache entry, prefixed with the cache
        key (`10c0/...`), and it can never equal the tarball hash npm serves --
        so comparing the two reported every dependency of every Berry lockfile
        as a CRITICAL mismatch. Only a value that resolves to a known algorithm
        and a digest of that algorithm\'s length is a claim about the artefact.

        Comparison is per algorithm. npm publishes a sha512 `integrity` beside a
        sha1 `shasum`, and a lockfile recording one of the two contradicts
        neither: a sha1 that does not appear among the sha512s is the ordinary
        case, not evidence.
        """
        recorded = RegistryEvidence._canonical_digest(dependency.integrity)
        if recorded is None or not published:
            return False

        algorithm, digest = recorded
        comparable: set[str] = set()
        for entry in published:
            parsed = RegistryEvidence._canonical_digest(entry)
            if parsed is not None and parsed[0] == algorithm:
                comparable.add(parsed[1])
        if not comparable:
            return False
        return digest not in comparable

    @staticmethod
    def _major_distance(pinned: str, latest: str) -> int:
        """How many major versions separate two version strings.

        Deliberately crude. Version schemes differ enough that a precise
        comparison needs each ecosystem's own rules, and the question here is
        only "is this pin far behind", which the leading number answers well
        enough to prompt a look. Anything unparseable returns zero rather than
        guessing.
        """

        def leading(value: str) -> int | None:
            head = value.lstrip("v=^~ ").split(".", 1)[0]
            digits = "".join(c for c in head if c.isdigit())
            return int(digits) if digits else None

        first, second = leading(pinned), leading(latest)
        if first is None or second is None:
            return 0
        return max(0, second - first)

    LOW_DOWNLOADS = 100
    _AFFIXES = frozenset(
        {"cli", "utils", "util", "tools", "tool", "helper", "helpers", "sdk", "api", "client", "lib", "core",
         "py", "python", "js", "node", "plugin", "wrapper", "fix", "patch", "pro", "plus", "lite", "official", "dev"}
    )  # fmt: skip

    @classmethod
    def _unvetted(cls, dependency: Dependency, observed: object) -> str | None:
        """The shape a slopsquatted package has: new, no source repository, and either barely
        downloaded or named by adding a generic affix to an established package."""
        from cordon_scanner.intel.real import RealPackages
        from cordon_scanner.intel.registry_client import (
            NEW_PACKAGE_DAYS,
            PackageFacts,
            RegistryClient,
        )

        if not isinstance(observed, PackageFacts) or observed.repository:
            return None
        if not RegistryClient._younger_than(observed.first_published, NEW_PACKAGE_DAYS):
            return None
        established = RealPackages.real_packages(dependency.ecosystem)
        name = dependency.name.lower()
        if name in established:
            return None
        tokens = [t for t in re.split(r"[-_.]", name.split("/")[-1]) if t]
        borrowed = next((t for t in tokens if t in established and len(t) >= 4), None)
        affixed = borrowed is not None and any(t in cls._AFFIXES for t in tokens if t != borrowed)
        quiet = (
            observed.weekly_downloads is not None and observed.weekly_downloads < cls.LOW_DOWNLOADS
        )
        if not (affixed or quiet):
            return None
        signals = [
            f"first published {(observed.first_published or '')[:10]}",
            "no source repository on record",
        ]
        if quiet:
            signals.append(f"{observed.weekly_downloads} downloads last week")
        if affixed:
            signals.append(
                f"named by adding a generic word to the established package {borrowed!r}"
            )
        return (
            f"{dependency.name} has the shape of a package registered to catch a name an AI assistant "
            f"invented: {'; '.join(signals)}."
        )

    #: Registries that mark a withdrawal only by dropping the version from their public list.
    ABSENCE_IS_WITHDRAWAL = frozenset({"rubygems", "composer"})
    #: Where Packagist sends Composer for a public package: the forge's own archive service.
    FORGE_ARCHIVE_HOSTS = frozenset(
        {"api.github.com", "codeload.github.com", "gitlab.com", "bitbucket.org"}
    )

    @classmethod
    def _withdrawal_applies(cls, dependency: Dependency) -> bool:
        """Whether the registry's withdrawal answer is about this dependency.

        RubyGems and Packagist say a version was withdrawn only by no longer listing it, and a
        version from a private source is never on the public list in the first place. Reporting
        that as a withdrawal would put a finding on every private gem or package pinned under
        --online, so for those two the answer counts only when the lockfile says the version came
        from the public registry or its forge archive, or records no source at all.
        """
        if dependency.ecosystem not in cls.ABSENCE_IS_WITHDRAWAL:
            return True
        import urllib.parse

        from cordon_scanner.intel.more_registries import PUBLIC_HOSTS

        resolved = dependency.resolved_from or ""
        if not resolved.startswith(("http://", "https://")):
            return True
        host = urllib.parse.urlsplit(resolved).hostname or ""
        return host in PUBLIC_HOSTS or host in cls.FORGE_ARCHIVE_HOSTS

    @staticmethod
    def _resolved_privately(dependency: Dependency) -> bool:
        """The lockfile says this came from somewhere other than the public registry."""
        import urllib.parse

        resolved = dependency.resolved_from or ""
        if not resolved.startswith(("http://", "https://")):
            return False
        host = urllib.parse.urlsplit(resolved).hostname or ""
        from cordon_scanner.intel.more_registries import PUBLIC_HOSTS

        return host not in {
            "registry.npmjs.org",
            "registry.yarnpkg.com",
            "pypi.org",
            "files.pythonhosted.org",
            *PUBLIC_HOSTS,
        }

    def _finding(
        self,
        rule_id: str,
        ctx: ScanContext,
        *,
        dependency: Dependency | None,
        detail: str,
        path: str | None = None,
        degrades_coverage: bool = False,
    ) -> Finding:
        declared = next(r for r in self.declared_rules() if r.id == rule_id)
        if path is None:
            path = (dependency.declared_in or dependency.project or "") if dependency else ""

        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=declared.severity,
            confidence=declared.confidence,
            message=detail,
            location=Location(path=path, line=1),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(detail.encode("utf-8")),
                redaction=RedactionMode.HASH_ONLY,
                metadata=(("source", "registry"),),
            ),
            remediation=declared.remediation,
            explanation=Explanation(
                summary=detail,
                matched_rule=rule_id,
                escalations=(NETWORK_CAVEAT,),
            ),
            risk=ctx.scorer.score(
                declared.severity,
                declared.confidence,
                ScoringContext(in_install_hook=False, capabilities=frozenset()),
            ),
            detector=self.id,
            always_report=declared.category is Category.OPERATIONAL,
            degrades_coverage=degrades_coverage,
        )


STARJACK_YOUNG_DAYS = 90
"""A package younger than this that names a popular project's repository is reported."""

UNMAINTAINED_DAYS = 5 * 365 + 1
"""Five years without a release: Socket's threshold, and long enough that a stable, finished
package is rarely caught by it."""


__all__ = [
    "MAX_MANIFEST_QUERIES",
    "MAX_QUERIES",
    "MIN_ATTESTED_SIBLINGS",
    "REGISTRY_ECOSYSTEMS",
    "UNMAINTAINED_DAYS",
    "RegistryDetector",
    "RegistryEvidence",
    "RegistryNotices",
]
