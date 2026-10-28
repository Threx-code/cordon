"""Manifest inspection: lifecycle scripts and dependency sources.

This detector covers the single most common supply-chain attack: a lifecycle
script added to a package so that arbitrary code runs during installation, as
the developer, before any other control applies.

Two decisions define it.

**The lifecycle check is an allowlist, not a blocklist.** The attack is *adding
a script*, so enumerating known-bad commands is permanently one step behind
whoever writes the next one. Instead, the set of permitted lifecycle entries is
declared and anything else is a finding, including a changed value for a
permitted key.

**The dependency-source check is about mechanism, not intent.** A dependency
resolved from a git URL, an archive URL or a filesystem path may be entirely
legitimate. The point is that none of the ecosystem's own protections apply to
it: no lockfile integrity hash, no advisory matching, no release-age cooldown.
The finding says the safety net is absent, not that something is wrong.
"""

from __future__ import annotations

import posixpath
import re
from typing import TYPE_CHECKING

from cordon_scanner.analysis.shared.inline_programs import InlinePrograms
from cordon_scanner.analysis.shared.source_paths import SourcePaths
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation import references
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import (
    AUTHOR_TIME_HOOKS,
    INSTALL_TIME_HOOKS,
    Category,
    Confidence,
    Finding,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.ecosystems.base import Manifest
from cordon_scanner.detect.supply.manifests.findings import ManifestFinding
from cordon_scanner.detect.supply.manifests.rule_ids import (
    CLEARTEXT_SOURCE_RULE,
    CONFUSION_RULE,
    FOREIGN_COMMIT_RULE,
    MALICIOUS_REMOTE_TARBALL_RULE,
    MUTABLE_REF_RULE,
    REMOTE_TARBALL_RULE,
    SOURCE_PRIORITY_RULE,
    WRAPPER_RULE,
)
from cordon_scanner.detect.supply.manifests.scripts import ManifestScripts
from cordon_scanner.detect.supply.manifests.source_findings import SourceFindings

# Commands that in a lifecycle script are, on their own, sufficient evidence.
# Every entry either fetches and runs remote content, reads credentials, or
# opens a shell. None has a legitimate purpose in code that executes silently
# during `install`.
HOSTILE_IN_LIFECYCLE = (
    ("curl", Capability.EGRESS),
    ("wget", Capability.EGRESS),
    ("nc ", Capability.EGRESS),
    ("Invoke-WebRequest", Capability.EGRESS),
    ("base64", Capability.DECODE),
    ("eval", Capability.EXECUTE),
    ("node -e", Capability.EXECUTE),
    ("python -c", Capability.EXECUTE),
    ("bash -c", Capability.SPAWN),
    ("sh -c", Capability.SPAWN),
    ("/dev/tcp", Capability.EGRESS),
    ("chmod +x", Capability.PERSIST),
)

INLINE_INTERPRETER_NEEDLES = frozenset({"node -e", "python -c"})
"""The `HOSTILE_IN_LIFECYCLE` entries that stand for an inline program, which a lifted program's
own unit answers for."""

PIPE_TO_SHELL = ("| sh", "|sh", "| bash", "|bash", "| python", "|python")

_REQUIRE_ONLY = re.compile(
    r"""^node\s{1,4}-e\s{1,4}["']\s{0,4}(?:try\s{0,4}\{\s{0,4})?require\(\s{0,4}['"](?P<path>\.{1,2}/[^'"\s]{1,200})['"]\s{0,4}\)\s{0,4};?"""
    r"""\s{0,4}(?:\}\s{0,4}catch\s{0,4}(?:\(\s{0,4}\w{0,20}\s{0,4}\))?\s{0,4}\{\s{0,4}\}\s{0,4})?["']$"""
)
"""`node -e "try{require('./postinstall')}catch(e){}"`: an inline command that only loads a file."""

READABLE_HOOK_TARGETS = frozenset(
    {"js", "cjs", "mjs", "ts", "py", "sh", "bash", "rb", "pl", "php", "ps1"}
)
"""Hook targets the content detectors read as source. A binary or extensionless executable is not."""


class ManifestDetector(BaseDetector):
    """Inspects dependency manifests."""

    id = ManifestFinding.DETECTOR
    version = "0.5.0"
    categories = frozenset(
        {Category.MALICIOUS, Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id=FOREIGN_COMMIT_RULE,
                title="A published package installs a dependency from another project's commit",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector="manifest",
                message=(
                    "A dependency is installed from a full commit of a git repository whose name "
                    "is not the dependency's. The hash reaches commits pushed to any fork, and npm "
                    "runs the commit's install scripts."
                ),
                remediation="Do not install it; find where the commit came from.",
                references=(
                    references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
                    references.EMBEDDED_MALICIOUS_CODE,
                    references.NPM_LIFECYCLE,
                ),
            ),
            DeclaredRule(
                id=CLEARTEXT_SOURCE_RULE,
                title="Package source over plain HTTP",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=Category.POLICY,
                detector="manifest",
                message=(
                    "A repository or index is reached over http://, so anyone on the network path "
                    "can serve the packages the build installs."
                ),
                references=(
                    references.CLEARTEXT_TRANSMISSION,
                    references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
                ),
                remediation="Use an https:// URL for the source.",
            ),
            DeclaredRule(
                id="POLICY.CONTAINER.UNPINNED_BASE.001",
                title="Base image referenced by tag rather than digest",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category=Category.POLICY,
                detector="manifest",
                message=(
                    "The base image is pinned by tag. A tag is mutable, so two builds of the "
                    "same Dockerfile can produce different images, and a rebuild can pull "
                    "content nobody reviewed."
                ),
                references=(
                    references.DOCKER_BUILD_BEST_PRACTICE,
                    references.OPENSSF_SCORECARD_PINNED,
                ),
                remediation="Pin by digest: FROM image:tag@sha256:...",
            ),
            DeclaredRule(
                id="POLICY.CONTAINER.UNPINNED_WORKLOAD_IMAGE.001",
                title="Kubernetes workload runs an image by tag rather than digest",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category=Category.POLICY,
                detector="manifest",
                message=(
                    "A container in this manifest names its image by tag. Each node pulls the tag "
                    "when it schedules the pod, so replicas of one Deployment can run different "
                    "images, and a re-pushed tag reaches production with no change to the manifest."
                ),
                references=(references.OPENSSF_SCORECARD_PINNED,),
                remediation="Pin by digest: image: registry/name:tag@sha256:..., or set the digest through Kustomize's images: field.",
            ),
            DeclaredRule(
                id=WRAPPER_RULE,
                title="Build wrapper downloads its tool without a checksum",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                category=Category.POLICY,
                detector="manifest",
                message=(
                    "A Maven or Gradle wrapper fetches the build tool from a URL and runs it, with "
                    "no checksum pinned to refuse a different download."
                ),
                references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
                remediation="Pin `distributionSha256Sum` in the wrapper properties.",
            ),
            DeclaredRule(
                id="SUSPECT.HELM.UNTRUSTED_REPOSITORY.001",
                title="Chart depends on a chart from an unpinned or plain-HTTP repository",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector="manifest",
                message=(
                    "This chart pulls a dependency over plain HTTP, or with no version at all. Chart "
                    "dependencies are rendered into the manifests applied to the cluster, so whoever "
                    "controls that repository controls what runs."
                ),
                references=(
                    references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,
                    references.CLEARTEXT_TRANSMISSION,
                ),
                remediation="Use HTTPS, pin each dependency to a version, and prefer a repository the organisation controls or mirrors.",
            ),
            DeclaredRule(
                id=SOURCE_PRIORITY_RULE,
                title="A private package index merged with a public one",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector="manifest",
                message=(
                    "The project resolves from a private index and a public one together, and the "
                    "resolver takes the highest version either offers: an internal name published "
                    "publicly at a higher version is installed instead."
                ),
                references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
                remediation="Resolve through one index, or pin internal packages to their index.",
            ),
            DeclaredRule(
                id=REMOTE_TARBALL_RULE,
                title="A published package installs a dependency from an arbitrary URL",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector="manifest",
                message=(
                    "A dependency of this published package is an http(s) URL on a host that is "
                    "not a registry. Every install fetches whatever that host serves at that "
                    "moment and runs its install scripts: no hash, no advisory and no review "
                    "applies, and the package itself can be empty -- the PhantomRaven shape."
                ),
                references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
                remediation="Do not install it until the URL's content has been examined.",
            ),
            DeclaredRule(
                id=MALICIOUS_REMOTE_TARBALL_RULE,
                title="A published package installs a dependency from a drop-point host",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.MALICIOUS,
                detector="manifest",
                message=(
                    "A dependency of this published package is fetched from a raw IP address or "
                    "from a paste, webhook, tunnel or interaction host. No package is distributed "
                    "that way; it is how a payload is kept off the registry so that scanning the "
                    "package finds nothing."
                ),
                references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
                remediation=(
                    "Do not install it. Treat any machine that did as having run untrusted code."
                ),
            ),
            DeclaredRule(
                id=MUTABLE_REF_RULE,
                title="Git dependency on a reference that can move",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                category=Category.POLICY,
                detector="manifest",
                message=(
                    "A dependency is declared from git at a branch, a tag or no reference: a push "
                    "re-points it, so what installs can differ from what was reviewed."
                ),
                references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK,),
                remediation="Pin it to a full commit SHA, or depend on a registry release.",
            ),
            DeclaredRule(
                id="SUSPECT.VERDICT.MODEL.001",
                title="The package's findings together look malicious",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "No single finding in this package blocks, but the combination -- which rules, "
                    "how strong, in what kind of package -- scores above the learned blocking "
                    "threshold of the package verdict."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read each finding listed. Do not install until explained.",
            ),
            DeclaredRule(
                id="SUSPECT.INTENT.UNEXPLAINED_EFFECT.001",
                title="The package's effects are not explained by what it says it is",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector="intent",
                message=(
                    "What the package's code does on the machine -- when it runs, what it reaches, "
                    "what it hides -- is unexplained by its stated purpose and by its user asking "
                    "for it: measured facts, each listed with its weight, score above the line "
                    "set on benign packages of its ecosystem (`core/intent.py`)."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation=(
                    "Read each listed effect and check it against what the package says it is "
                    "for. Do not install until each one is explained."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.MCP.BORROWED_NAME.001",
                title="MCP server published under a service's name its code never mentions",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "This MCP server's package is named after a well-known service -- GitHub, "
                    "Slack, Postgres -- that nothing in its code refers to. Chosen by that name, it "
                    "receives the requests and credentials meant for the service."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Install the service's own server instead.",
            ),
            DeclaredRule(
                id="SUSPECT.INSTALL.UNEXAMINED.001",
                title="Install-time code too large or slow to examine",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "A file that runs at install was truncated or ran out of its time budget, so "
                    "part of it was never examined. Install scripts are kilobytes; one padded past "
                    "the limits keeps its payload out of reach."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read the file in full before installing; raise the scan limits to examine it.",
            ),
            DeclaredRule(
                id="SUSPECT.RELEASE.NEW_INSTALL_HOOK.001",
                title="This release runs code at install that the previous release did not",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="This release runs code at install that the previous release did not, compared with the release before it (`--compare-with`, or `--online` for a published artefact).",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read what changed between the two releases before installing this one.",
            ),
            DeclaredRule(
                id="SUSPECT.RELEASE.NEW_CAPABILITY.001",
                title="This release's flagged code gains network, process or execution capability",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="This release's flagged code gains network, process or execution capability, compared with the release before it (`--compare-with`, or `--online` for a published artefact).",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read what changed between the two releases before installing this one.",
            ),
            DeclaredRule(
                id="SUSPECT.RELEASE.NEW_OBFUSCATION.001",
                title="This release ships obfuscated code where the previous shipped none",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="This release ships obfuscated code where the previous shipped none, compared with the release before it (`--compare-with`, or `--online` for a published artefact).",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read what changed between the two releases before installing this one.",
            ),
            DeclaredRule(
                id="SUSPECT.RELEASE.NEW_BINARY.001",
                title="This release adds compiled files",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="This release adds compiled files, compared with the release before it (`--compare-with`, or `--online` for a published artefact).",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read what changed between the two releases before installing this one.",
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.MANIFEST_CONFUSION.001",
                title="The manifest npm serves is not the package.json in the tarball",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "The registry's copy of the manifest disagrees with the tarball's own package.json "
                    "on install scripts, dependencies, commands, name or version (`--online`, for a "
                    "published npm tarball). npm installs from the tarball, so the registry's view hides "
                    "what runs; critical when the difference is an install script."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install this version; read the tarball's package.json and report the package.",
            ),
            DeclaredRule(
                id="MALWARE.DEPENDENCY.PAYLOAD.001",
                title="A declared dependency is malicious by its own content",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.MALICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="A dependency this npm package declares, resolved and scanned on its own bytes (`--dependency-store`, or `--online`), is malicious by its content: installing this package installs it.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install this package; read the named dependency's finding first.",
            ),
            DeclaredRule(
                id="SUSPECT.RELEASE.NEW_PUBLISHER.001",
                title="This release was published by a different account than the previous one",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="This release was published by a different account than the previous one, compared with the release before it (`--compare-with`, or `--online` for a published artefact).",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read what changed between the two releases before installing this one.",
            ),
            DeclaredRule(
                id="SUSPECT.RELEASE.NEW_YOUNG_DEPENDENCY.001",
                title="This release adds a dependency that was itself published days ago",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector="release-history",
                message=(
                    "Compared with its established release (`cordon-scanner intel acquire`), this release "
                    "declares a dependency the earlier one did not, first published within 30 days "
                    "before this release, outside the package's own scope: the shape of a "
                    "compromised release pulling in a package created for the attack."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read the new dependency before installing; pin the previous release meanwhile.",
            ),
            DeclaredRule(
                id="SUSPECT.REGISTRY.REVIEW.001",
                title="What the registry recorded about this release looks like a malicious release",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector="registry-review",
                message=(
                    "The second review: the registry's record of this release, acquired beforehand "
                    "(`cordon-scanner intel acquire`) -- who published it, how old the name was, what "
                    "came before it and what it added -- scores over the line its model was measured "
                    "at. It finds what the package's content cannot show; it never lifts a block."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Check who published this release and why; pin an earlier release until explained.",
            ),
            DeclaredRule(
                id="MALWARE.PACKAGE.KNOWN.001",
                title="The scanned package is a recorded malicious release",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category=Category.MALICIOUS,
                detector="advisory",
                message="The package's own manifest names a release the malicious-package records list.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install it; treat any machine that did as compromised.",
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.001",
                title="A published release ships no code under a throwaway description",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector="advisory",
                message=(
                    "A published gem carries no code and describes itself with a throwaway word "
                    "(`x`, `a`, `test`): a name taken to be used, not a library."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not depend on it; find out who published it and what depends on the name.",
            ),
            DeclaredRule(
                id="SUSPECT.ARCHIVE.PATH_ESCAPE.001",
                title="Archive member named to write outside the archive",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="An archive member's name is absolute or climbs out with `..`.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not unpack or install it.",
            ),
            DeclaredRule(
                id="SUSPECT.ARCHIVE.LINK_TO_SECRET.001",
                title="Archive member is a link to a secret on the user's machine",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "A member of this archive is a symbolic link to a system or credential file -- "
                    "/etc/hosts, ~/.ssh/id_rsa, ~/.aws. Anything that reads or uploads the "
                    "package's file reads or uploads that one instead."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install or use it.",
            ),
            DeclaredRule(
                id="SUSPECT.ARCHIVE.POLYGLOT.001",
                title="Archive that is a tarball and a zip at once",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="The file begins as a tar or compressed stream and ends as a zip, so different tools read different contents.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install it.",
            ),
            DeclaredRule(
                id="SUSPECT.ARCHIVE.PADDED.001",
                title="Archive padded past the scan's budget",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="The archive expands far past its compression ceiling and the byte budget ran out inside it, so what follows the padding was not read.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install it until it is examined whole.",
            ),
            DeclaredRule(
                id="SUSPECT.ARCHIVE.NESTING.001",
                title="Archives nested past the depth the scan opens",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message="The innermost archive was never examined; depth past two levels keeps a payload out of reach.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Raise limits.max_archive_depth and examine the inner archives before installing.",
            ),
            DeclaredRule(
                id="SUSPECT.BINARY.NATIVE_IN_PURE_WHEEL.001",
                title="A pure-Python wheel loads a native library it carries",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector="binary",
                message=(
                    "The wheel is tagged none-any, declaring no compiled code, and loads a native "
                    "library shipped inside it into the interpreter with ctypes."
                ),
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install it; genuine native code ships as platform wheels.",
            ),
            DeclaredRule(
                id="SUSPECT.TYPOSQUAT.PACKAGE_NAME.001",
                title="Package is named like a popular package",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "The scanned package's own name is one slip from a widely used package and "
                    "is not itself established: the shape of a typosquat waiting for the typo. "
                    "HIGH for a published artefact, MEDIUM for a working tree."
                ),
                references=(references.DEPENDENCY_CONFUSION,),
                remediation="Install the package that was meant, and report this one.",
            ),
            DeclaredRule(
                id="SUSPECT.PACKAGE.NAME_RISK.001",
                title="Published package is a name with nothing behind it",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "A published package whose name looks chosen to be installed by mistake -- a "
                    "slip of a popular name, an organisation's name outside its scope, a "
                    "dependency-confusion version, a self-declared probe -- with no code in it "
                    "and no source named. HIGH when the name evidence is strong and there is "
                    "nothing to run; LOW, at low confidence, otherwise."
                ),
                references=(references.DEPENDENCY_CONFUSION,),
                remediation="Install the package that was meant, and report this one.",
            ),
            DeclaredRule(
                id="MALWARE.INSTALL.FETCH_EXEC.001",
                title="Install script fetches and executes remote content",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=Category.MALICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "An install-time script downloads something and runs it. Install hooks run "
                    "unprompted, as the developer, with the developer's full environment, "
                    "before any test, review, container boundary or network policy applies -- "
                    "and what runs is decided at install time by whoever serves the URL."
                ),
                references=(references.DOWNLOAD_WITHOUT_INTEGRITY_CHECK, references.NPM_LIFECYCLE),
                remediation="Treat the host as compromised. Do not install this package.",
            ),
            DeclaredRule(
                id="SUSPECT.INSTALL.SCRIPT.001",
                title="Package declares an install-time lifecycle script",
                # HIGH, which is the most this rule reports. It declared LOW, and the
                # code has always reported HIGH for a DEPENDENCY's install script --
                # `_lifecycle_findings` grades by whose manifest it is -- so the one
                # severity a reader could check in `rules list` was not the one that
                # decided whether their build failed.
                #
                # Raised rather than capped, because the grading is right: a lifecycle
                # script in code this project did not write runs on the developer's
                # machine, unprompted, before any review. What was wrong was the
                # declaration. `POLICY.LOCKFILE.INTEGRITY.001` had the same divergence
                # and was resolved the other way, because there the declared severity
                # was the defensible one.
                #
                # A declaration is a promise about the maximum. Reporting LOWER than
                # declared is what every ceiling in this tool does and is fine;
                # reporting higher is misinformation.
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "This package runs a script during installation. That is ordinary for "
                    "packages that compile something and it is also the single most used "
                    "foothold in published malware, because the code runs before anything "
                    "inspects the package."
                ),
                references=(references.NPM_LIFECYCLE,),
                remediation="Read the script. Install hooks run before any review or test.",
            ),
            DeclaredRule(
                id=CONFUSION_RULE,
                title="A version made to win resolution runs code on install",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestFinding.DETECTOR,
                message=(
                    "This package's version is engineered to win a version resolution -- 99 or "
                    "above, or all nines -- it runs a script of its own on install, and it has "
                    "next to no other code. That is the shape of dependency confusion: a public "
                    "package named like a private one, published so an installer prefers it, "
                    "whose only purpose is the code its install hook runs."
                ),
                references=(references.NPM_LIFECYCLE,),
                remediation=(
                    "Do not install it. If the name is your organisation's, scope your registry "
                    "so the private package can never be resolved from the public one."
                ),
            ),
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        # Read before the manifest lookup: a wheel's METADATA and an sdist's PKG-INFO are a
        # release's own metadata without being dependency manifests.
        name_risk = list(self._name_risk_findings(unit, ctx))
        ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
        if ecosystem_id is None:
            return name_risk

        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return ()

        manifest = ecosystem.parse_manifest(unit.content)
        hooks_from_tree = getattr(ecosystem, "hooks_from_tree", None)
        if hooks_from_tree is not None:
            # Install-time code that is a file beside the manifest rather than a field in it (an R
            # package's `configure`, a Dart package's `hook/build.dart`), seen from the tree's paths.
            manifest = hooks_from_tree(manifest, ctx.tree_paths)

        if manifest.parse_error:
            # A manifest that could not be read is a manifest whose contents
            # were not checked. Reporting it keeps that from resembling a pass.
            return [
                ManifestFinding.operational(
                    unit.path,
                    f"Could not parse this {ecosystem_id} manifest, so its "
                    f"lifecycle scripts and dependency sources were not "
                    f"checked: {manifest.parse_error}",
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._lifecycle_findings(manifest, unit, ctx))
        findings.extend(self._confusion_findings(manifest, unit, ctx))
        findings.extend(SourceFindings.source_findings(manifest, unit, ctx))
        findings.extend(self._own_name_findings(manifest, unit, ctx, ecosystem_id))
        findings.extend(name_risk)
        findings.extend(SourceFindings.wrapper_findings(unit, ctx))
        return findings

    def _name_risk_findings(self, unit: FileUnit, ctx: ScanContext) -> Iterable[Finding]:
        """A published package with nothing in it but a name worth suspecting (`detect.name_risk`).

        Blocks only when the name evidence is strong and there is nothing in the package to run
        and no source to read; otherwise a warning. The package's code, if it has any, is read by
        the content rules on its own merits, so this never has to stand in for them.
        """
        from cordon_scanner.detect.supply.name_risk import RULE, NameRisk, PackageIdentities

        identity = PackageIdentities.read(unit, ctx)
        if identity is None:
            return
        assessment = NameRisk.assess(identity)
        if assessment is None:
            return
        reasons = [signal.reason for signal in assessment.signals]
        yield ManifestFinding.finding(
            rule_id=RULE,
            category=Category.SUSPICIOUS,
            # Below a block it is recorded, not raised: measured on 162,499 long-tail units the
            # warning fell on 5,164 benign releases against 674 of 1,567 no-payload samples, a
            # warning on 3.2% of ordinary packages for signals each common alone (review 98, REC-4).
            severity=Severity.HIGH if assessment.blocks else Severity.LOW,
            confidence=Confidence.MEDIUM if assessment.blocks else Confidence.LOW,
            title="Published package is a name with nothing behind it",
            message=(
                f"{identity.name} {identity.version} "
                + "; ".join(reasons)
                + ". "
                + (
                    "That is the shape of a dependency-confusion probe or a name-squat: the "
                    "name is the whole of the package."
                    if assessment.blocks
                    else "Each of these is common alone; together they are worth a look "
                    "before installing."
                )
            ),
            remediation=(
                "Confirm this is the package you meant, from the publisher you meant. If it was "
                "pulled in by name from a private registry, pin that registry for the scope."
            ),
            unit=unit,
            ctx=ctx,
            detail=f"name: {identity.name} {identity.version} (score {assessment.score})",
            capabilities=[],
            reasons=reasons,
            # The file is the release's own metadata, so the directory it sits in is named for
            # the release: `example-utils-1.0/PKG-INFO` and `test-helpers-2.0/PKG-INFO` are not
            # test fixtures, they are packages whose names contain those words.
            fixture_ceiling=False,
        )

    def _own_name_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext, ecosystem_id: str
    ) -> Iterable[Finding]:
        """A package whose own name is a slip of a popular one.

        The dependency check asks this of what a project installs; a scanned package is asked
        of itself. `aiiohttp`, `cryptograohy` and `botocote` are published with nothing in
        them but the name, waiting for the typo -- there is no code to find, and the name is the
        whole of the evidence.
        """
        from cordon_scanner.detect.supply.dependency import DependencyDetector
        from cordon_scanner.intel.registries.popular import PackageIntel

        if not manifest.name or "node_modules/" in f"/{unit.path}" or "site-packages/" in unit.path:
            return
        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return
        name = ecosystem.normalize_name(manifest.name)
        if PackageIntel.is_known_package(ecosystem_id, name):
            return
        target = DependencyDetector._typosquat_target(ecosystem_id, name)
        if target is None:
            return
        # A published artefact: the archive scanned as one, an npm tarball's `package/`, or an
        # extracted sdist, whose root is `<name>-<version>/` by the format's own convention.
        directory = posixpath.basename(unit.path.rpartition("!")[2].rpartition("/")[0])
        sdist_root = re.fullmatch(
            rf"{re.escape(name).replace('-', '[-_.]')}-\d[\w.+!-]{{0,40}}",
            directory.lower().replace("_", "-"),
        )
        # Only the formats this was measured on. Raised for every published format, it blocked
        # plyr, tsibble, pyaml, pytest, istio and the homebrew-core and vcpkg Go snapshots (17 of
        # 34,500 real packages, review 98): there the matched manifest is often not the package's.
        published = (
            ctx.distribution in ("pypi", "npm")
            or sdist_root is not None
            or unit.path.rpartition("!")[2] == "package/package.json"
        )
        yield ManifestFinding.finding(
            rule_id="SUSPECT.TYPOSQUAT.PACKAGE_NAME.001",
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH if published else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            title="Package is named like a popular package",
            message=(
                f"This package calls itself {manifest.name!r}, one slip from the widely used "
                f"{target!r}, and is not itself an established package. A published package "
                f"under a name like this collects the installs meant for the other."
            ),
            remediation=f"Install {target!r} if that is what was meant, and report this one.",
            unit=unit,
            ctx=ctx,
            detail=f"{manifest.name} ~ {target}",
            capabilities=[],
            reasons=[f"one edit from {target}"],
        )

    # -- Dependency confusion --------------------------------------------

    #: A version that wins semver resolution over any real release: major 99 or above, or every
    #: component all nines (`9.9.9`, `99.99.99`). What winning resolution is for is the attack.
    _WINNING_VERSION = re.compile(r"^(?:(?:\d{3,}|99)\.|9+(?:\.9+){1,3}(?:[-+].*)?$)")
    _CODE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts")

    def _confusion_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """An npm package whose version is engineered to win resolution, whose install hook runs a
        script that is not a build step, and which has at most one other code file.

        The three together are the dependency-confusion foothold, and none of them alone is: big
        versions, install hooks and tiny packages are each ordinary. Measured on the npm study half
        (review 98): the shape is 246 of 1,923 malicious units, 3 of them caught by nothing else, and
        0 of 11,255 benign npm units across the random, popular and ecosystem corpora."""
        version = (manifest.version or "").strip()
        if manifest.ecosystem != "npm" or not self._WINNING_VERSION.match(version):
            return
        if SourcePaths.is_editor_extension(unit.path):
            return
        scripts, declared = ManifestScripts.npm_scripts(unit)
        running = [
            hook
            for hook in manifest.hooks
            if hook.command
            and hook.name.lower() in ("preinstall", "install", "postinstall")
            and not ManifestScripts._prints_only(hook.command)
            and not ManifestScripts._is_safe_lifecycle(hook.command, scripts, declared)
        ]
        if not running:
            return
        root = unit.path.rpartition("/")[0]
        prefix = f"{root}/" if root else ""
        others = [
            path
            for path in ctx.tree_paths
            if path.startswith(prefix)
            and "/node_modules/" not in path[len(prefix) - 1 :]
            and path.endswith(self._CODE_SUFFIXES)
            and not path.endswith(".d.ts")
            and path not in ctx.install_hook_paths
        ]
        if len(others) > 1:
            return
        hook = running[0]
        yield ManifestFinding.finding(
            rule_id=CONFUSION_RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="A version made to win resolution runs code on install",
            message=(
                f"{manifest.name or 'This package'} is version {version}, a version made to win "
                f"resolution, and its {hook.name} script runs {hook.command[:120]!r} with "
                f"{len(others)} other code file(s) in the package: the dependency-confusion shape."
            ),
            remediation=(
                "Do not install it. If the name is your organisation's, scope your registry so the "
                "private package can never be resolved from the public one."
            ),
            unit=unit,
            ctx=ctx,
            detail=hook.name,
            capabilities=[],
            reasons=[f"version {version}", f"{hook.name} runs a non-build script", "no other code"],
        )

    # -- Lifecycle scripts -----------------------------------------------

    def _lifecycle_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        if manifest.ecosystem == "image":
            # A Dockerfile's RUN steps are the project's own build, judged by the Dockerfile rules
            # that read them in context (a fetched script piped to a shell, sudo, a remote ADD).
            # Listed as build hooks; graded as a dependency's install script, each was reported twice.
            return
        if manifest.ecosystem == "npm" and SourcePaths.is_editor_extension(unit.path):
            # A packaged or installed editor extension: the editor unpacks it and runs its `main`,
            # never npm, so no lifecycle script in it -- its own `postinstall`, or one in a bundled
            # node_modules manifest, which ran when the extension was built -- runs on this
            # machine. 471 of 1,943 popular extensions were blocked for scripts that cannot run.
            # What the extension's code does is read by the code detectors, with its severity.
            return
        scripts, declared = (
            ManifestScripts.npm_scripts(unit) if manifest.ecosystem == "npm" else ({}, {})
        )
        for hook in manifest.hooks:
            command = hook.command
            if not command or hook.action_step:
                continue
            loader = _REQUIRE_ONLY.match(command.strip())
            if loader:
                # A one-liner whose only act is to load a file beside the manifest is that file,
                # run: graded by what the file is, as `node <file>` would be.
                command = f"node {loader.group('path')}"
            # A program the hook carries inline was lifted into a unit of its own and read by
            # every content detector as install-time code (`core.inline_programs`). Its
            # interpreter flag is then no more a finding than `node install.js` is, and the
            # hook is graded like one that runs a file this scan read.
            programs = [] if loader else InlinePrograms.found(unit.path, hook.name, command)
            lifted = (
                bool(programs)
                and all(p.path in ctx.tree_paths for p in programs)
                # And only a program that can do nothing: no network, no process, no evaluation,
                # no decoding, no credential or system read, no persistence. Whatever one of
                # those does in a hook, a word list judged it before and still does.
                and not any(ManifestScripts._capable(p.path, p.source, ctx) for p in programs)
            )
            tree_command = InlinePrograms.as_file_command(command, programs) if lifted else command

            capabilities: list[Capability] = []
            reasons: list[str] = []

            for needle, capability in HOSTILE_IN_LIFECYCLE:
                if lifted and needle in INLINE_INTERPRETER_NEEDLES:
                    continue
                if needle in command:
                    capabilities.append(capability)
                    reasons.append(f"invokes {needle.strip()!r}")

            if capabilities and ManifestScripts._prints_only(command):
                # A one-liner whose whole effect is a message or an exit. See
                # `INERT_CALL`. The capability it named is real -- `node -e` does
                # evaluate a string -- and what it evaluates is a line of text.
                capabilities = []
                reasons = []

            piped = any(marker in command for marker in PIPE_TO_SHELL)
            if piped:
                capabilities.append(Capability.SPAWN)
                reasons.append("pipes fetched content directly into an interpreter")

            # Case-insensitively, because npm spells one of them `prepublishOnly`.
            install_time = hook.name.lower() in INSTALL_TIME_HOOKS
            if not capabilities:
                # A step whose one-liner only prints is safe to run, and still a hook that runs:
                # recorded below the gate rather than dropped.
                talks = ManifestScripts._prints_only(command)
                if not install_time or (
                    not talks and ManifestScripts._is_safe_lifecycle(command, scripts, declared)
                ):
                    continue
                talks = talks and ManifestScripts._is_safe_lifecycle(command, scripts, declared)
                # An install-time script that is not a recognised build step.
                # Reported for existing, rather than for containing a word from
                # a list: `node ./scripts/setup.js` matched no hostile substring
                # and produced nothing, while being the shape most npm
                # compromises actually take. What the referenced file does is a
                # separate question the file detectors answer -- and cannot
                # answer at all if nothing points at it.
                first_party = ManifestScripts._is_first_party(unit.path, ctx) or (
                    manifest.ecosystem == "npm"
                    and not ManifestScripts._is_vendored(unit.path)
                    and ManifestScripts.unpublishable(unit)
                )
                vendored = not first_party
                in_tree = (
                    (unit.path,)
                    if hook.kind == "consumerinstall" and unit.path in ctx.install_hook_paths
                    else ManifestScripts._targets_in_tree(
                        tree_command, ctx.install_hook_paths, unit.path
                    )
                )
                # A published package's hook that runs only source files inside the package:
                # those files were scanned in this run with install-time escalation, so a
                # payload in them is already reported as what it is. What runs something
                # opaque -- a binary, an inline `-e` string, a file that is not there -- keeps
                # the dependency grading, because then this finding is all there is.
                # Or a file the command hands to a shell, which is shell text whatever its name:
                # `sh configure` and `sh cleanup` are how R installs a source package, and
                # 11 of 300 CRAN packages were blocked on them (review 98). `sh` cannot run a
                # binary, so what it runs is a script this scan read.
                readable = bool(in_tree) and all(
                    path.rsplit(".", 1)[-1].lower() in READABLE_HOOK_TARGETS
                    # A file `node` is handed is JavaScript, whatever it is called:
                    # `node bin/preinstall` runs `bin/preinstall` as source.
                    or re.search(
                        rf"(?:^|[\s;&|(])(?:node|nodejs|tsx|ts-node|bun)\s+(?:\S*/)?"
                        rf"{re.escape(path.rpartition('/')[2])}(?:\s|$)",
                        tree_command,
                    )
                    or re.search(
                        rf"(?:^|[\s;&|(])(?:ba|da|z)?sh\s+{re.escape(path)}(?:\s|$)",
                        tree_command,
                    )
                    for path in in_tree
                )
                yield ManifestFinding.finding(
                    rule_id="SUSPECT.INSTALL.SCRIPT.001",
                    category=Category.SUSPICIOUS,
                    # Graded by whose manifest it is and what the command reaches.
                    # A dependency's install script is the attack; the project's
                    # own, pointing at a file in the same repository that this scan
                    # has already read, is a fact worth stating once.
                    # And lowered again for an author-time hook, which cannot reach a
                    # consumer installing from a registry tarball. See
                    # `AUTHOR_TIME_HOOKS`.
                    # A hook that runs only the package's own source is recorded, not raised: that
                    # source was read here as install-time code and graded on what it does, so the
                    # manifest adds only that a hook exists. Raised at MEDIUM it was the only code
                    # warning on 9,352 of 234,509 benign units (review 98) and changed no verdict.
                    # An author-time hook is recorded too: npm never fires it for a registry
                    # install, and the git-dependency case is `SUSPECT.DEPENDENCY.SOURCE.001`'s.
                    # At MEDIUM, `prepare: tsdx build` and `prepublish: npm run build` were most of
                    # what remained of this warning in the long tail (review 98).
                    severity=min(
                        (Severity.LOW if readable else Severity.HIGH)
                        if vendored
                        else Severity.LOW
                        if in_tree
                        else Severity.MEDIUM,
                        Severity.LOW
                        if talks or hook.name.lower() in AUTHOR_TIME_HOOKS
                        else Severity.CRITICAL,
                    ),
                    confidence=Confidence.MEDIUM,
                    title=(
                        "Install script in code this project did not write"
                        if vendored
                        else "Install script runs an unrecognised command"
                    ),
                    message=(
                        (
                            f"The {hook.name!r} script runs automatically during install, "
                            f"before any test, review or container boundary applies, and "
                            f"runs {command!r}. This manifest is not the scanned "
                            f"project's own - it is a dependency's, or this is a "
                            f"published package rather than a working tree - so nobody "
                            f"here wrote it and no review here covered it."
                            + (
                                f" It runs {', '.join(in_tree)}, which this scan read as "
                                f"install-time code; anything it does is reported there."
                                if readable
                                else ""
                            )
                        )
                        if vendored
                        else (
                            f"The {hook.name!r} script runs automatically during install "
                            f"and runs {command!r}, which reaches "
                            f"{', '.join(in_tree)} in this repository. That file is "
                            f"tracked, was reviewed when it landed, and has been scanned "
                            f"by every other detector in this run, so this is reported to "
                            f"be recorded rather than because anything is wrong with it. "
                            f"What remains true is that it runs before any test does."
                        )
                        if in_tree
                        else (
                            f"The {hook.name!r} script runs automatically during install, "
                            f"before any test, review or container boundary applies, and "
                            f"runs {command!r} -- which is not a recognised build step "
                            f"and does not resolve to a file in this repository, so "
                            f"nothing here can say what it does."
                        )
                    ),
                    remediation=(
                        "Read the script. If it is a build step, move it behind an "
                        "explicit command a developer chooses to run; if it must run at "
                        "install time, suppress this finding with a justification."
                    ),
                    unit=unit,
                    ctx=ctx,
                    detail=f"{hook.name}: {command}",
                    capabilities=[],
                    reasons=["runs at install time and is not a recognised build step"],
                )
                continue

            fetch_and_run = Capability.EGRESS in capabilities and (
                piped or Capability.SPAWN in capabilities or Capability.EXECUTE in capabilities
            )

            if fetch_and_run:
                yield ManifestFinding.finding(
                    rule_id="MALWARE.INSTALL.FETCH_EXEC.001",
                    category=Category.MALICIOUS,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="Install script fetches and executes remote content",
                    message=(
                        f"The {hook.name!r} script downloads content and runs it. This "
                        f"executes automatically on every install, as the user, before "
                        f"any test, review or container boundary applies. What runs is "
                        f"whatever the remote host serves at that moment, so it is not "
                        f"pinned by the lockfile and not captured by review."
                    ),
                    remediation=(
                        "Treat the host as compromised. Do not install this package. "
                        "Rotate credentials reachable from the affected machine, "
                        "starting with registry publish tokens."
                    ),
                    unit=unit,
                    ctx=ctx,
                    detail=f"{hook.name}: {command}",
                    capabilities=capabilities,
                    reasons=reasons,
                )
            else:
                author_time = hook.name.lower() in AUTHOR_TIME_HOOKS
                yield ManifestFinding.finding(
                    rule_id="SUSPECT.INSTALL.SCRIPT.001",
                    category=Category.SUSPICIOUS,
                    # An author-time hook cannot reach a consumer installing from a
                    # registry tarball. See `AUTHOR_TIME_HOOKS`: `unionlabs/union`
                    # declares `prepare: svelte-kit sync` and
                    # `prepack: svelte-kit sync && svelte-package && publint`, and the
                    # `&&` chain is what brought them to this branch rather than the one
                    # above -- so the grading had to be applied in both places.
                    severity=Severity.MEDIUM if author_time else Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    title="Install script performs unexpected operations",
                    message=(
                        f"The {hook.name!r} script runs automatically during "
                        + ("packing or publishing" if author_time else "install")
                        + " and performs operations a build step does not need. "
                        "Install-time code runs as the user with their full environment."
                        + (
                            " This hook runs on the author's machine rather than on a "
                            "consumer's: npm does not fire it for a package installed "
                            "from a registry tarball, which is how every transitive "
                            "dependency arrives. It does fire for a dependency installed "
                            "from a git URL."
                            if author_time
                            else ""
                        )
                    ),
                    remediation=(
                        "Move the work into an explicit build command that a developer "
                        "chooses to run, and review what the script does."
                    ),
                    unit=unit,
                    ctx=ctx,
                    detail=f"{hook.name}: {command}",
                    capabilities=capabilities,
                    reasons=reasons,
                )

    # -- Dependency sources ----------------------------------------------

    # -- Construction ----------------------------------------------------


__all__ = [
    "HOSTILE_IN_LIFECYCLE",
    "INLINE_INTERPRETER_NEEDLES",
    "PIPE_TO_SHELL",
    "READABLE_HOOK_TARGETS",
    "ManifestDetector",
]
