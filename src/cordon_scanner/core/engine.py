"""Scan orchestration.

The engine is the application core. It knows the *shape* of a scan -- which
phases run, in what order, with what feeding what -- and nothing about how any
individual step is implemented. It holds references to protocols, never to
concrete detectors, ecosystems or reporters.

That separation is what makes the rest of the architecture work. A new detector
is registered, not wired in. A new output format never touches this file. And
because detectors are pure functions over immutable units, moving execution from
a loop to a process pool to a distributed queue is a deployment decision rather
than a rewrite.

Phases:

    Source -> Inventory -> Plan -> Execute -> Correlate -> Judge

Each has one input type and one output type, so a phase can be replaced,
parallelised or cached without disturbing its neighbours.
"""

from __future__ import annotations

import io
import json
import posixpath
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.archive.safe import ArchiveReader, Rejection
from cordon_scanner.core.cache import CacheKey, ScanCache
from cordon_scanner.core.composer_plugins import ComposerPluginHooks
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent, Skipped
from cordon_scanner.core.errors import ArchiveError, SourceError
from cordon_scanner.core.models import (
    AUTHOR_TIME_HOOKS,
    Category,
    Confidence,
    Dependency,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Hook,
    LanguageStat,
    Location,
    Project,
    RedactionMode,
    Repository,
    RiskScore,
    ScanResult,
    ScanStats,
    Scope,
    Severity,
)
from cordon_scanner.core.parallel import MAX_CARRIED_BYTES, ParallelScanner, WorkItem
from cordon_scanner.core.paths import ContainerPaths
from cordon_scanner.core.policy import PolicyGate, SuppressionMatcher
from cordon_scanner.core.progress import NullProgress, Progress
from cordon_scanner.core.scoring import RiskScorer
from cordon_scanner.core.walker import (
    INSTALLED_CODE_PRUNE_DIRS,
    WalkEntry,
    Walker,
    WalkStats,
)
from cordon_scanner.detect.base import (
    FileUnit,
    GraphUnit,
    RepositoryUnit,
    ScanContext,
    Unit,
)
from cordon_scanner.ecosystems.base import WORKSPACE_INHERITED, Coordinate, LockEntry, LockGraph
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.langs.registry import LanguageRegistry
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from cordon_scanner.sources.base import FileSource, WorkingTreeSource
from cordon_scanner.version import SCHEMA_VERSION, __version__

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence

    from cordon_scanner.detect.base import Detector
    from cordon_scanner.ecosystems.base import DeclaredDependency

NO_RISK = RiskScore(value=0, base=0, confidence_multiplier=1.0)


@dataclass
class _Accumulator:
    """Mutable state for one scan.

    Deliberately local to a single run. The engine itself holds no per-scan
    state, which is what makes one Scanner instance reusable and safe to share.
    """

    findings: list[Finding] = field(default_factory=list)
    complete: bool = True
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    rules_evaluated: int = 0

    finding_cap: int = 0
    """Ceiling on retained findings, from `limits.max_findings`.

    Zero disables it. The limit was declared and documented -- "a hostile
    repository can otherwise turn a scan into an out-of-memory failure by
    arranging for every line to match. Reaching this cap is itself reported" --
    and never checked anywhere.
    """

    capped: bool = False

    def append(self, finding: Finding) -> bool:
        """Retain one finding if the cap allows it.

        Enforced here rather than at render time, which is where
        `ReportOptions.max_findings` applies -- by then everything is already in
        memory and the limit has prevented nothing.
        """
        if finding.rule_id in INCOMPLETE_WHEN_REPORTED:
            self.complete = False
        if self.finding_cap and len(self.findings) >= self.finding_cap:
            self.capped = True
            self.complete = False
            return False
        self.findings.append(finding)
        return True

    def add(self, produced: Iterable[Finding]) -> None:
        """Retain a batch, stopping at the cap."""
        for finding in produced:
            if not self.append(finding):
                return


ALWAYS_RUN = frozenset({"capability", "obfuscation", "secrets", "binary"})
"""Detectors the per-file budget never skips: the ones that find malware, hidden code, secrets and
committed executables. See `Engine._inspect_file`."""

BLINDING_SETTINGS = frozenset(
    {
        "scan.allow_plugins",
        "scan.expand_archives",
        "scan.intel_feed",
        "scan.max_intel_age",
        "scan.minified",
    }
)
"""Repository settings that would switch detection off or load code into the scanner. Refused
from a scan target and reported at HIGH, where the default gate fails, like a weakened gate."""

INCOMPLETE_WHEN_REPORTED = frozenset(
    {
        "OPERATIONAL.FORMAT.UNREADABLE",
        "OPERATIONAL.IMAGE.UNMATCHED",
        "OPERATIONAL.CLAMAV.UNAVAILABLE",
    }
)
"""Detector findings that say a file's content went unexamined, so the scan is not complete."""

DEPENDENCY_BUILD_FILENAMES = frozenset(
    {
        # Python
        "setup.py",
        "conanfile.py",
        # Rust and node-gyp
        "build.rs",
        "binding.gyp",
        # Ruby and Perl compile steps, which a gem or CPAN install runs for you.
        "extconf.rb",
        "Makefile.PL",
        "Build.PL",
        # vcpkg runs a port's portfile.cmake to fetch and build it.
        "portfile.cmake",
        # SwiftPM evaluates every dependency's manifest; Zig runs every dependency's build
        # script; Cabal runs a package's custom Setup when it is built as a dependency.
        "Package.swift",
        "build.zig",
        "Setup.hs",
        "Setup.lhs",
    }
)
DEPENDENCY_BUILD_SUFFIXES = (".nimble",)
"""Nimble evaluates a package's `.nimble` file -- NimScript, top-level code and hooks -- when
the package is installed as a dependency."""
"""Build files that run when somebody installs the package as a DEPENDENCY.

This is the install-hook condition, and the word install is doing the work. `pip
install` compiles an sdist by executing its `setup.py`; `cargo build` compiles a
crate by executing its `build.rs`; `npm install` of a native module runs
`binding.gyp`. Nobody asked for any of it, and it happens on the machine of
whoever pulled the dependency in.
"""

PROJECT_BUILD_FILENAMES = frozenset(
    {
        # Make. A recipe line is a shell command, and it runs when a developer
        # types `make`.
        "Makefile",
        "makefile",
        "GNUmakefile",
        # JVM. Gradle build files are Groovy or Kotlin programs, not
        # declarations: `exec { commandLine ... }` runs during configuration.
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "pom.xml",
        # CMake and MSBuild both have first-class "run this command" steps.
        "CMakeLists.txt",
        "Rakefile",
    }
)
"""Build files somebody INVOKES.

The same file list used to be one set with the one above, on the reasoning that a
repository's build is the thing a developer runs without reading. Half of that is
true and it is the wrong half: a `Makefile` does run commands, and it runs them
when a developer typed `make`, on their own project, having chosen to. A `setup.py`
runs on a stranger's machine because they typed `pip install something-else`.

Treating them alike put every Makefile that downloads a tool into
`MALWARE.DROPPER.001`, whose first branch is the install-hook context on its own.
Measured across the corpus that was 20 repositories at CRITICAL -- Prometheus,
zstd's fuzz harness, MLX's `tests/CMakeLists.txt`, OpenCV, Ollama,
semantic-kernel, Proton's docker build, and a Makefile *vendored* inside
lazygit's `vendor/` tree. Every one of them fetches something and shells out,
because that is what a build does.

Still a build hook, still reported, and a dropper in one still reaches `high`
through `SUSPECT.DROPPER.001`. What it no longer does is claim the code runs
without anybody asking.
"""

BUILD_HOOK_FILENAMES = DEPENDENCY_BUILD_FILENAMES | PROJECT_BUILD_FILENAMES
"""Either kind, for callers that only ask whether a file executes during a build."""

KEY_CORPUS_CEILING = Severity.MEDIUM
KEY_CORPUS_CONFIDENCE = Confidence.MEDIUM
"""What a directory of keys may be reported at.

The same two ceilings the detectors apply to test material, stated here rather than
imported: `core` does not depend on `detect`, and an engine that reached into a
detector for a constant would be the first crack in that."""

KEY_TABLE_SIZE = 3
"""How many keys in ONE FILE make it a table.

Lower than `PRIVATE_KEY_CORPUS`, and the asymmetry is the point: a directory is a
place a leak can land in, and a file is not. A leak is one key in a file. See
`Engine._collapse_key_table`."""

PRIVATE_KEY_RULE = "SECRET.PRIVATE_KEY.001"
PRIVATE_KEY_CORPUS = 5
"""How many key files in one directory make it a corpus rather than a disclosure.

One or two is what a leak looks like. Five is a hierarchy somebody generated, and
every repository that implements TLS has at least one such directory. See
`Engine._collapse_key_corpus`."""

CREDENTIAL_NAME_CEILING = Severity.MEDIUM
"""What a collapsed credential-name group reports at. The step down a key corpus takes."""

CREDENTIAL_NAME_FILES = 10
"""How many files must assign the same credential-shaped NAME before it is one decision.

The same number `MIN_IDIOM_FILES` uses and the same argument, applied to the key the
secrets evidence actually carries. `_collapse_idiom` groups on a forty-byte snippet, and
a secret's evidence is hash-only by policy, so it has a snippet of nothing and never
groups -- which is why `rclone` reported sixteen.

`rclone` declares `rcloneEncryptedClientSecret` once per cloud backend, sixteen of them,
each revealed at runtime by `obscure.MustReveal`. They are OAuth client secrets for a
native application: RFC 8252 says such an app cannot keep one confidential, which is why
the value ships in the binary at all. Sixteen findings is not how to tell a reader that
the project hardcodes a client secret per backend.

Collapsed with the count and the paths in the message, like every other collapse here,
so nothing is hidden."""

POLYGLOT_RULE = "SUSPECT.POLYGLOT.MISMATCH.001"
POLYGLOT_CORPUS = 5
"""How many format-mismatched files in one directory make it a collection.

The same argument `PRIVATE_KEY_CORPUS` makes, about the same kind of place. One or two
files whose contents contradict their names is what a disguise looks like; five in one
directory is somebody's collection of them.

`swisskyrepo/PayloadsAllTheThings` keeps sixteen under
`Upload Insecure Files/Picture ImageMagick/` -- `ghostscript_rce_curl.jpg`,
`imagetragik2_ubuntu_shell.jpg`, `imagetragik1_payload_url_portscan.png` -- and every one
is a genuine polyglot, which is the point of the repository. Sixteen findings is not how
to tell a reader that. Any fuzzing or upload-test corpus has the same shape.

Ceilinged rather than dropped, with the count in the message, for the reason the key
corpus is: a directory of real polyglots is still in the report and still says how many.
See `Engine._collapse_polyglot_corpus`."""

POLYGLOT_CORPUS_CEILING = Severity.MEDIUM
"""What a collapsed polyglot corpus reports at. The same step down a key corpus takes."""

MIN_IDIOM_FILES = 10
MIN_IDIOM_SNIPPET = 40
"""When the same construct in many files becomes one finding.

Ten files, and a snippet specific enough that ten copies cannot be coincidence. See
`Engine._collapse_idiom`, which explains why both numbers are needed."""

MAX_REPEAT_PATHS_LISTED = 5
"""How many of the repeated paths a collapsed finding names.

Enough to recognise the shape of the duplication -- two backup directories, a
per-lesson copy -- without turning one message into a file listing."""

UNEXAMINED_INSTALL_RULE = "SUSPECT.INSTALL.UNEXAMINED.001"

NATIVE_IN_PURE_WHEEL_RULE = "SUSPECT.BINARY.NATIVE_IN_PURE_WHEEL.001"
KNOWN_MALICIOUS_RELEASE_RULE = "MALWARE.PACKAGE.KNOWN.001"
ARCHIVE_SLICE = 4000
"""Archive members handed to the worker pool at a time, between deadline checks."""
ARCHIVE_ESCAPE_RULE = "SUSPECT.ARCHIVE.PATH_ESCAPE.001"
ARCHIVE_NESTING_RULE = "SUSPECT.ARCHIVE.NESTING.001"
ARCHIVE_POLYGLOT_RULE = "SUSPECT.ARCHIVE.POLYGLOT.001"
PURE_WHEEL = re.compile(r"(?mi)^Root-Is-Purelib:\s*true\s*$|^Tag:\s*\S+-none-any\s*$")
NATIVE_MAGIC = frozenset({b"\x7fELF", b"MZ\x90\x00", b"MZP\x00"})
MACHO_MAGIC = frozenset(
    {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"}
)
NATIVE_LOAD = re.compile(r"\b(?:CDLL|PyDLL|WinDLL|OleDLL|LoadLibrary|cdll|windll)\b")

AUTHOR_TIME_PREFIXES = (".github/", ".gitlab/", ".circleci/", ".buildkite/", ".azure-pipelines/")
AUTHOR_TIME_FILENAMES = frozenset(
    {
        "Makefile",
        "GNUmakefile",
        "makefile",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        ".travis.yml",
        "appveyor.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yaml",
    }
)
"""Files a published package may carry that only its maintainers' tooling runs."""

SHIPPED_DOCUMENTS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt")
"""Documents in a published package: pypdf ships sample forms for its own tests. Installing the
package opens none of them; a document's active content runs when a person opens it."""

COMPILED_SOURCE = (".rs", ".go", ".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".kt", ".cs", ".swift")
"""Source an install compiles but does not run. maturin's `upload.rs` reads `.pypirc` to publish,
which is maturin's job, and nothing in `pip install maturin` calls it. `build.rs` is the
exception: Cargo runs it during the build, so it is never in this set's reach."""

JS_LOCAL_REFERENCE = re.compile(
    r"""(?:\brequire\s{0,4}\(\s{0,4}|\bimport\s{0,4}\(\s{0,4}|\bfrom\s{1,4})['"`](?P<rel>\.{1,2}/[^'"`\s]{1,200})['"`]"""
    r"""|__dirname\s{0,4},\s{0,4}['"`](?P<sib>[\w.-]{1,100}\.(?:js|cjs|mjs))['"`]"""
)
"""A relative module a script loads, or a sibling file it names beside `__dirname`."""

JS_CLOSURE_LIMIT = 500
"""Files followed from install-hook scripts, like the Python closure's bound."""

INLINE_REQUIRE = re.compile(r"""require\(\s{0,4}['"](\.{1,2}/[^'"\s]{1,200})['"]\s{0,4}\)""")
"""A relative `require` inside an inline `node -e` lifecycle command."""

PRINTING_COMMANDS = frozenset({"echo", "printf"})
"""Commands whose arguments are text for a person, not code to run.

A lifecycle script that prints instructions is the commonest `postinstall` there
is, and the instructions it prints name commands. See `Engine._runs`."""


PACKAGED_BUILD_FILENAMES = frozenset({"setup.py", "conanfile.py"})
"""Build filenames that are ordinary module names as well.

`setup.py` is the one that matters and `conanfile.py` has the same property:
both are plain Python names, both are common words, and neither can be a build
file from inside a package directory -- a packaging script sits at a
distribution root, not next to an `__init__.py`. See `Engine._hook_executes`.
"""

CI_HOOK_PREFIXES = (
    ".github/workflows/",
    ".circleci/",
    ".buildkite/",
)
"""Directories whose contents are pipeline definitions."""

CI_HOOK_FILENAMES = frozenset(
    {
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        ".travis.yml",
        "bitbucket-pipelines.yml",
        "cloudbuild.yaml",
        "cloudbuild.yml",
    }
)
"""Pipeline definitions that live at a fixed filename rather than in a
directory. Recognising only `.github/workflows/` meant every other CI system's
secret handling was scored as if it were ordinary configuration."""


class Engine:
    """Runs the phases. Holds no per-scan state."""

    @staticmethod
    def _unexamined_install_code(findings: Sequence[Finding], ctx: ScanContext) -> list[Finding]:
        """Install-time code the scan could not read to the end.

        A truncation or a timeout is a coverage note anywhere else. In a file that runs at
        install it is the evasion: aioconsol's `setup.py` is 22 MB on one line -- an executable
        written out as a bytes literal -- past the size limit and the per-file budget, so the
        payload and the call that runs it were never read. Install scripts are kilobytes.
        """
        out: list[Finding] = []
        seen: set[str] = set()
        for finding in findings:
            path = finding.location.path
            if (
                finding.rule_id not in ("OPERATIONAL.FILE.TRUNCATED", "OPERATIONAL.FILE.TIMEOUT")
                or path in seen
                or path not in ctx.install_hook_paths
            ):
                continue
            seen.add(path)
            out.append(
                replace(
                    Engine._operational(
                        path=path,
                        rule_id=UNEXAMINED_INSTALL_RULE,
                        message=(
                            "This file runs at install time and is larger, or slower to read, "
                            "than the scan's limits allow, so part of it was never examined. "
                            "Install scripts are kilobytes; one padded past the limits keeps its "
                            "payload out of reach of every check."
                        ),
                        remediation=(
                            "Do not install this package until the file has been read in full. "
                            "Raise limits.max_file_bytes and limits.per_file_timeout to examine it."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.HIGH,
                    risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                    detector="manifest",
                )
            )
        return out

    @staticmethod
    def _known_malicious_release(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """The scanned package is itself a recorded malicious release.

        Dependencies have always been checked against the malicious-package records; the
        package being vetted was not. A tarball whose own `package.json` names a release OSV
        records as malicious is answered by that record, whatever its code does or no longer
        contains -- the commonest shape in the public datasets is a dependency-confusion
        placeholder whose payload was pulled, which no reading of the code can convict.

        Only a package's own manifest counts, recognised by where its format puts it: an npm
        tarball's `package/package.json`, an sdist's `<name>-<version>/PKG-INFO`, a wheel's
        `*.dist-info/METADATA`. A repository's root `package.json` is not a release, so a project
        that shares a name with a malicious package is never matched by name alone.
        """
        from cordon_scanner.intel.advisories import AdvisoryDatabase

        identities: list[tuple[str, str, str, str]] = []
        for unit in units:
            member = unit.path.rpartition("!")[2]
            parts = member.split("/")
            # A root-level `.nuspec` is the one release manifest kept at the package's top; it
            # counts only inside an archive (a repository's own .nuspec is not a release).
            if len(parts) < 2 and not ("!" in unit.path and member.endswith(".nuspec")):
                continue
            parent, name = (parts[-2] if len(parts) >= 2 else ""), parts[-1]
            try:
                if name == "package.json" and parent == "package":
                    document = json.loads(unit.content.text)
                    if (
                        isinstance(document, dict)
                        and document.get("name")
                        and document.get("version")
                    ):
                        identities.append(
                            ("npm", str(document["name"]), str(document["version"]), unit.path)
                        )
                elif name == "package.json" and parent == "extension":
                    # A VS Code / Open VSX extension package (.vsix): the Marketplace names it
                    # `publisher.name`, and that is the key OSV's VSCode records use.
                    document = json.loads(unit.content.text)
                    if (
                        isinstance(document, dict)
                        and document.get("publisher")
                        and document.get("name")
                        and document.get("version")
                    ):
                        identities.append(
                            (
                                "vscode",
                                f"{document['publisher']}.{document['name']}",
                                str(document["version"]),
                                unit.path,
                            )
                        )
                elif name == "Cargo.toml" and re.search(r"-\d", parent):
                    # A published crate (.crate): `<name>-<version>/Cargo.toml`, normalised by
                    # cargo at publish time, so `[package]` holds the release's own name.
                    text = unit.content.text[:20000]
                    package = re.search(r"(?ms)^\[package\](.*?)(?:^\[|\Z)", text)
                    if package:
                        found_name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', package.group(1))
                        found_version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', package.group(1))
                        if found_name and found_version:
                            identities.append(
                                ("cargo", found_name.group(1), found_version.group(1), unit.path)
                            )
                elif name.endswith(".nuspec") and len(parts) == 1:
                    # A NuGet package (.nupkg): its `<id>.nuspec` sits at the package root.
                    text = unit.content.text[:20000]
                    found_name = re.search(r"<id>\s*([^<\s]+)\s*</id>", text)
                    found_version = re.search(r"<version>\s*([^<\s]+)\s*</version>", text)
                    if found_name and found_version:
                        identities.append(
                            ("nuget", found_name.group(1), found_version.group(1), unit.path)
                        )
                elif (name == "PKG-INFO" and re.search(r"-\d", parent)) or (
                    name == "METADATA" and parent.endswith(".dist-info")
                ):
                    text = unit.content.text[:20000]
                    found_name = re.search(r"(?m)^Name:\s*(\S+)", text)
                    found_version = re.search(r"(?m)^Version:\s*(\S+)", text)
                    if found_name and found_version:
                        identities.append(
                            ("pypi", found_name.group(1), found_version.group(1), unit.path)
                        )
            except (ValueError, TypeError):
                continue
        if not identities:
            return []
        database = AdvisoryDatabase.bundled()
        out: list[Finding] = []
        for ecosystem, name, version, path in identities[:20]:
            records = [a for a in database.matching(ecosystem, name, version) if a.malicious]
            if not records:
                continue
            record = records[0]
            out.append(
                replace(
                    Engine._operational(
                        path=path,
                        rule_id=KNOWN_MALICIOUS_RELEASE_RULE,
                        message=(
                            f"{name} {version} is itself a recorded malicious release "
                            f"({record.identifier}). {record.summary} This is an exact match "
                            "against a published incident, not a judgement of the code."
                        ),
                        remediation=(
                            "Do not install it. If it was installed anywhere, treat that machine "
                            "as compromised and rotate the credentials reachable from it."
                        ),
                        category=Category.MALICIOUS,
                        severity=Severity.CRITICAL,
                    ),
                    confidence=Confidence.CONFIRMED,
                    risk=ctx.scorer.score(Severity.CRITICAL, Confidence.CONFIRMED),
                    detector="advisory",
                    references=(record.reference,) if record.reference else (),
                )
            )
        return out

    @staticmethod
    def _native_code_in_a_pure_wheel(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """A pure-Python wheel that loads a native library it carries into the interpreter.

        A wheel tagged `py3-none-any` declares that it holds no compiled code; that is what lets
        one file serve every platform. colorinal, a colorama clone, shipped as one with
        `terminate.so` beside its modules and `ctypes.CDLL(os.path.dirname(__file__) +
        "/terminate.so")` at module level: importing the colour library ran a native payload.
        A package with real native code ships platform wheels. Running a bundled binary as a
        program (selenium's driver manager) is not this; loading it into the process is.
        """
        wheel = next(
            (u for u in units if u.path.rsplit("/", 1)[-1] == "WHEEL" and ".dist-info/" in u.path),
            None,
        )
        if wheel is None or not PURE_WHEEL.search(wheel.content.text):
            return []
        natives = {
            u.path.rsplit("/", 1)[-1]
            for u in units
            if u.content.raw[:4] in NATIVE_MAGIC or u.content.raw[:4] in MACHO_MAGIC
        }
        if not natives:
            return []
        out: list[Finding] = []
        for unit in units:
            if not unit.path.endswith(".py"):
                continue
            for number, line in enumerate(unit.content.text.splitlines(), 1):
                if NATIVE_LOAD.search(line) and any(name in line for name in natives):
                    out.append(
                        replace(
                            Engine._operational(
                                path=unit.path,
                                rule_id=NATIVE_IN_PURE_WHEEL_RULE,
                                message=(
                                    "This wheel declares itself pure Python (`none-any`), yet "
                                    "this line loads a native library shipped inside it into the "
                                    "interpreter. Compiled code no reviewer can read runs in-process "
                                    "on import, in a package that said it had none."
                                ),
                                remediation=(
                                    "Do not install it. A package with genuine native code ships "
                                    "platform wheels built from published source."
                                ),
                                category=Category.SUSPICIOUS,
                                severity=Severity.HIGH,
                            ),
                            location=replace(
                                Engine._operational(
                                    path=unit.path,
                                    rule_id=NATIVE_IN_PURE_WHEEL_RULE,
                                    message="",
                                    remediation="",
                                    category=Category.SUSPICIOUS,
                                    severity=Severity.HIGH,
                                ).location,
                                line=number,
                            ),
                            confidence=Confidence.HIGH,
                            risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                            detector="binary",
                        )
                    )
                    break
        return out

    @staticmethod
    def _rejected_member(path: str, reason: str, detail: str, *, image: bool = False) -> Finding:
        """A refused archive member, graded by why it was refused.

        Most refusals are limits -- size, ratio, a link -- and say only that a member was not
        read. Two are the attack. A member named `../../setup.py` or `/etc/cron.d/x` exists to
        write outside wherever the archive is unpacked, and no build tool produces one. And an
        archive nested past the depth limit puts its contents beyond every check: a payload
        twenty archives down passed the gate as "not examined". Both block.
        """
        # A container image is archives of archives by construction -- layers inside the image
        # tar -- so its depth limit is reached in ordinary use and stays a coverage note.
        from cordon_scanner.detect.secrets import SourcePaths

        # A zip-slip test fixture is an escaping archive on purpose: Django, Jenkins, Go's
        # archive/tar and every extractor with a security test ship one. Reported, below the gate.
        fixture = SourcePaths.is_test_material(path) or SourcePaths.is_vendored(path)
        if reason == Rejection.POLYGLOT and not fixture:
            return replace(
                Engine._operational(
                    path=path,
                    rule_id=ARCHIVE_POLYGLOT_RULE,
                    message=(
                        "This archive begins as a tarball and ends as a zip. A package manager "
                        "reads the tarball; a tool that looks for a zip directory reads the zip. "
                        "Both were examined here, but no packaging tool produces such a file: it is "
                        "built so that what is inspected and what is installed differ."
                    ),
                    remediation="Do not install it. Find out who built it and why.",
                    category=Category.SUSPICIOUS,
                    severity=Severity.HIGH,
                ),
                confidence=Confidence.HIGH,
            )
        if reason == Rejection.HIDDEN and not fixture:
            return replace(
                Engine._operational(
                    path=path,
                    rule_id=ARCHIVE_POLYGLOT_RULE,
                    message=(
                        "This zip member is present in the archive's local "
                        "headers and absent from its central directory. A streaming extractor "
                        "installs it; a tool that reads the directory never sees it. No packaging "
                        "tool produces such a file: it is built so that what is inspected and what "
                        "is installed differ. Its content was also scanned, under zip-local/."
                    ),
                    remediation="Do not install it. Find out who built it and why.",
                    category=Category.SUSPICIOUS,
                    severity=Severity.HIGH,
                ),
                confidence=Confidence.HIGH,
            )
        if not fixture and (
            reason in (Rejection.TRAVERSAL, Rejection.ABSOLUTE)
            or (reason == Rejection.DEPTH and not image)
        ):
            escape = reason != Rejection.DEPTH
            return replace(
                Engine._operational(
                    path=path,
                    rule_id=ARCHIVE_ESCAPE_RULE if escape else ARCHIVE_NESTING_RULE,
                    message=(
                        "An archive member's name points outside the archive "
                        f"({detail or reason}). Unpacked by an ordinary tool it writes wherever "
                        "the name says; no packaging tool produces such a name."
                        if escape
                        else "Archives are nested past the depth this scan opens, so what is "
                        "inside the innermost one was never examined. Ordinary packages nest "
                        "two levels at most; depth past that keeps a payload out of reach."
                    ),
                    remediation=(
                        "Do not unpack or install it."
                        if escape
                        else "Do not install it until the inner archives have been examined; "
                        "raise limits.max_archive_depth to read them."
                    ),
                    category=Category.SUSPICIOUS,
                    severity=Severity.HIGH,
                ),
                confidence=Confidence.HIGH,
            )
        return Engine._operational(
            path=path,
            rule_id="OPERATIONAL.ARCHIVE.MEMBER_REJECTED",
            message=(
                f"An archive member was refused ({reason}) and therefore not "
                f"examined{': ' + detail if detail else ''}."
            ),
            remediation=(
                "A refused member is not a clean member. Inspect it directly if "
                "the archive is from an untrusted source."
            ),
        )

    @staticmethod
    def release_change(*, path: str, rule_id: str, message: str, severity: Severity) -> Finding:
        """A finding about what this release added relative to the previous one."""
        return replace(
            Engine._operational(
                path=path,
                rule_id=rule_id,
                message=message,
                remediation=(
                    "Read what changed between the two releases before installing this one. "
                    "If the change is not in the project's own release notes, treat the "
                    "release as compromised."
                ),
                category=Category.SUSPICIOUS,
                severity=severity,
            ),
            confidence=Confidence.MEDIUM,
            always_report=False,
        )

    @staticmethod
    def package_check(
        *, path: str, rule_id: str, message: str, severity: Severity, remediation: str
    ) -> Finding:
        """A finding about the published package as its registry describes it, not about a file."""
        return replace(
            Engine._operational(
                path=path,
                rule_id=rule_id,
                message=message,
                remediation=remediation,
                category=Category.SUSPICIOUS,
                severity=severity,
            ),
            confidence=Confidence.HIGH,
            always_report=False,
        )

    @staticmethod
    def _operational(
        *,
        path: str,
        rule_id: str,
        message: str,
        remediation: str,
        category: Category = Category.OPERATIONAL,
        severity: Severity = Severity.INFO,
    ) -> Finding:
        """Build a finding about the scan itself.

        Every degradation produces one of these. A file that was not examined is
        indistinguishable in the output from one that was examined and found clean,
        so coverage loss must always be stated rather than inferred.
        """
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{rule_id}:{path}".encode()),
                redaction=RedactionMode.NONE,
            ),
            remediation=remediation,
            # No reporting threshold may hide a finding that says coverage was
            # lost. See PolicyGate.filter_for_reporting.
            always_report=True,
            explanation=Explanation(
                summary="Reported so that reduced coverage is never silent.",
                matched_rule=rule_id,
            ),
            risk=NO_RISK,
            detector="engine",
        )

    def __init__(
        self,
        config: Config,
        *,
        rules: RuleSet | None = None,
        detectors: Sequence[Detector] | None = None,
        source: FileSource | None = None,
        progress: Progress | None = None,
        shadowed: Sequence[tuple[str, str, str]] = (),
    ) -> None:
        self.config = config
        # Entry points that tried to take a built-in's name. Reported rather
        # than refused: refusing turned one entry-point line into a denial of
        # service against every scan.
        self.shadowed = tuple(shadowed)
        self.rules = rules if rules is not None else RuleSet(RuleLoader.load_builtin())
        self.detectors = tuple(detectors) if detectors is not None else self._default_detectors()
        self.scorer = RiskScorer()
        self.cache = ScanCache(config.cache_dir, enabled=config.use_cache)
        # Where files and their bytes come from. The default is the working
        # tree; a git source narrows the set or, in staged mode, changes the
        # bytes themselves.
        self.source: FileSource = source if source is not None else WorkingTreeSource()
        # Reports what the scan is doing. `NullProgress` rather than `None`, so
        # every call site is unconditional and there is no branch that can be
        # wrong in only one of the two modes.
        self.progress: Progress = progress if progress is not None else NullProgress()
        # Archives opened during a directory scan, by content hash, and the
        # counters reported in `ScanStats`: opened, members, milliseconds.
        self._expansions: dict[str, list[tuple[str, bytes]] | None] = {}
        self._archive_stats = [0, 0, 0]
        # What an ingested SBOM itself lists as vulnerable: `(document, vulnerability, purl,
        # name, version, tool)`, reported once the scan's own matching has run.
        self._sbom_listed: list[tuple[str, Any, str, str, str | None, str]] = []
        # True while the scan TARGET is an archive, where its members' lockfiles are
        # the package's own graph rather than a vendored artefact's.
        self._scanning_archive = False

    @staticmethod
    def _default_detectors() -> tuple[Detector, ...]:
        from cordon_scanner.core.registry import Registry

        return Registry.default_detectors()

    # -- Entry point -----------------------------------------------------

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a target and return a complete, sorted result."""
        try:
            return self._scan(target)
        finally:
            # In a `finally` because the progress line is a partial line with no
            # newline on it. Leaving it there puts a traceback or an error
            # message on the same row as a half-drawn progress bar.
            self.progress.finish()

    def scan_host(self, root: str | Path, home: str | Path | None = None) -> ScanResult:
        """What an installed system holds (advanced gap M7): its distribution's packages and the
        language packages installed outside any project, read from the metadata their installers
        left (`images/host.py`), then matched as an image's are -- language packages against the
        advisory database, OS packages through OSV with `--online`. Files are not content-scanned:
        that is what `scan` of a directory is for."""
        try:
            return self._scan_host(Path(root), Path(home) if home is not None else None)
        finally:
            self.progress.finish()

    def _scan_host(self, root: Path, home: Path | None) -> ScanResult:
        from cordon_scanner.images.host import HostFilesystem

        started = time.monotonic()
        acc = _Accumulator(finding_cap=self.config.limits.max_findings)
        intel = self._intel_status(acc)
        if not root.is_dir():
            raise SourceError(f"--host needs a directory to read as a filesystem root: {root}")
        self.progress.phase("inventory")
        inventory = HostFilesystem(root, home).inventory()
        for problem in inventory.problems:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.HOST.PARTIAL",
                    message=f"Part of the host was not read: {problem}.",
                    remediation="Run as a user that can read the package databases, or say so beside the result.",
                    severity=Severity.LOW,
                )
            )
        dependencies = self._image_dependencies(inventory)
        ctx = replace(self._context(Repository(root=str(root))), image=inventory)
        if dependencies:
            ctx = replace(ctx, dependencies=Engine._packages(dependencies))
            graph_unit = GraphUnit(dependencies=Engine._packages(dependencies))
            self.progress.phase("dependencies")
            for detector in self.detectors:
                if detector.requires.dependencies and self._detector_enabled(detector, ctx):
                    acc.add(self._run(detector, graph_unit, ctx, acc))
        dependencies = self._annotated(dependencies, acc.findings, ctx, [])
        result = ScanResult(
            findings=tuple(acc.findings),
            dependencies=dependencies,
            repository=Repository(root=str(root), file_count=0),
            target_kind="host",
            stats=ScanStats(
                files_scanned=0,
                bytes_scanned=0,
                dependencies=len(dependencies),
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )
        return replace(PolicyGate.filter_for_reporting(result, self.config).sorted(), intel=intel)

    def _scan(self, target: str | Path) -> ScanResult:
        started = time.monotonic()
        acc = _Accumulator(finding_cap=self.config.limits.max_findings)

        # Recorded before resolving, because resolving is what loses it. The
        # walker never follows a link found during traversal; a link *named as
        # the target* is the one path where a link's destination is read, and it
        # is operator-directed rather than an attack. Reported so the absolute
        # guarantee stated elsewhere has its one exception visible.
        named = Path(target)
        root = named.resolve()
        if named.is_symlink():
            acc.append(
                Engine._operational(
                    path=str(named),
                    rule_id="OPERATIONAL.FILE.SYMLINK_TARGET",
                    message=(
                        f"The scan target is a symbolic link and its destination "
                        f"({root}) was read. Links found during traversal are never "
                        f"followed; this one was named on the command line."
                    ),
                    remediation="Scan the destination directly if that was not intended.",
                    severity=Severity.INFO,
                )
            )
        intel = self._intel_status(acc)
        if root.is_file() and ArchiveReader.is_archive(root.name):
            return replace(self._scan_archive(root, acc, started), intel=intel)
        self.progress.phase("identifying")
        # One traversal for both phases where the source permits it. A git
        # source narrows the scan set, so there the inventory still describes
        # the whole repository and the two traversals are genuinely different.
        walker = self._walker()
        walked = list(walker.walk(root)) if self.source.yields_the_whole_walk else None
        # `total_timeout: 0` is "no budget", as every other check on it reads it -- not a budget
        # already spent, which stopped a scan before its first file.
        deadline = (
            started + self.config.limits.total_timeout
            if self.config.limits.total_timeout > 0
            else float("inf")
        )
        inventory = self.inventory(root, acc, walked=walked, walker=walker)
        ctx = self._context(
            inventory, deadline=deadline if self.config.limits.total_timeout > 0 else None
        )

        # Manifest hooks are discovered while scanning, and they change the
        # context every later finding is scored against: the same capability
        # pair means something different inside a lifecycle script. So files are
        # collected first, hooks are folded into the context, and detectors run
        # against the completed picture.
        self.progress.phase("reading")
        units = []
        for unit in self._units(root, inventory, acc, deadline, walked=walked, walker=walker):
            units.append(unit)
            self.progress.advance(unit.path)

        self.progress.phase("dependencies")
        dependencies = self._build_graph(units, acc)
        # A bill of materials named as the target is its inventory; in a tree it is a claim to
        # compare with what the tree resolves (`detect/sbom.py`), never counted twice.
        ingested = self._sbom_dependencies(units, acc) if root.is_file() else ()
        # Repositories checked out as git submodules, at the commits their gitlinks pin.
        from cordon_scanner.core.submodules import Submodules

        submodules, unreadable = Submodules.dependencies(
            units, root if root.is_dir() else root.parent
        )
        for path, problem in unreadable:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=path,
                    rule_id="OPERATIONAL.MANIFEST.UNPARSED",
                    message=f"This .gitmodules could not be read: {problem}. Its submodules are not in the inventory.",
                    remediation="Fix the file so `git submodule` reads it.",
                    severity=Severity.MEDIUM,
                )
            )
        dependencies = (*dependencies, *ingested, *submodules)
        manifest_hooks, consumer_hooks = self._manifest_hook_paths(units, acc)
        hook_paths = (
            set(ctx.install_hook_paths)
            | manifest_hooks
            | self._nuget_hooks(units)
            | ComposerPluginHooks.paths(units)
        )
        # What runs at install time is the hook and everything it imports. The
        # context stopped at the hook file, so moving the payload into a helper
        # module -- no obfuscation, just ordinary package structure -- avoided
        # the escalation entirely.
        entries = frozenset(hook_paths)
        hook_paths |= self._hook_import_closure(units, hook_paths)
        hook_paths |= self._hook_js_closure(units, hook_paths)
        # And which of those files' bodies the hooks actually reach. A file is
        # in the closure because something imports it, which runs its top level
        # and defines its functions -- it does not call them.
        deferred = self._hook_deferred_lines(units, hook_paths, entries)
        ctx = replace(
            ctx,
            dependencies=Engine._packages(dependencies),
            install_hook_paths=frozenset(hook_paths),
            install_entry_paths=entries,
            consumer_install_paths=frozenset(consumer_hooks),
            install_deferred_lines=deferred,
        )

        file_detectors = [
            d
            for d in self.detectors
            if self._detector_enabled(d, ctx)
            and not (d.requires.dependencies and d.requires.content is False)
        ]
        signature = ScanCache.detector_signature(file_detectors)

        # A source whose bytes are not what is on disk cannot have its files
        # re-read by a worker: a staged scan would examine the working tree
        # instead of the index. Such a source is parallelised by sending the
        # bytes the parent already read, so the worker reads nothing at all.
        #
        # Bounded by `MAX_CARRIED_BYTES`: above that the scan stays serial
        # rather than pickling an unbounded amount of a repository into a pool.
        carry_content = not self.source.parallel_safe
        carried_bytes = sum(len(u.content.raw) for u in units) if carry_content else 0
        parallelisable = not carry_content or carried_bytes <= MAX_CARRIED_BYTES
        workers = (
            ParallelScanner.worker_count(
                self.config.limits.max_workers,
                len(units),
                carried_bytes if carry_content else sum(u.content.size for u in units),
            )
            if parallelisable
            else 1
        )
        self.progress.phase("scanning", total=len(units))
        if workers > 1:
            acc.add(
                self._scan_parallel(
                    units, root, ctx, acc, file_detectors, signature, carry_content=carry_content
                )
            )
        else:
            for unit in units:
                acc.add(self._inspect_file(unit, ctx, acc, file_detectors, signature))
                self.progress.advance(unit.path)
        acc.add(self._unexamined_install_code(acc.findings, ctx))
        acc.add(self._native_code_in_a_pure_wheel(units, ctx))
        acc.add(self._known_malicious_release(units, ctx))

        if dependencies:
            self.progress.phase("graph")
            graph_unit = GraphUnit(dependencies=Engine._packages(dependencies))
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.add(self._run(detector, graph_unit, ctx, acc))
        acc.add(self._sbom_listed_findings(acc.findings, ctx))

        # Reachability annotates the vulnerability findings just produced, using
        # the imports of the files just scanned -- so it runs here, after the
        # graph pass and while `units` is still in hand. Opt-in, because it reads
        # every source file. It only ever lowers or tags a finding, never removes
        # one, so it is safe to run over the accumulator in place.
        if self.config.reachability and dependencies:
            from cordon_scanner.detect import reachability

            acc.findings[:] = reachability.ImportReachability.annotate(
                acc.findings, units, dependencies
            )

        # Repository-scoped detectors. `RepositoryUnit` existed and nothing
        # produced one, so a detector asking about the repository rather than
        # about a file had no way to run at all -- the port was declared and
        # never wired.
        repository_unit = RepositoryUnit(repository=inventory)
        for detector in self.detectors:
            if not detector.requires.repository:
                continue
            if not self._detector_enabled(detector, ctx):
                continue
            acc.add(self._run(detector, repository_unit, ctx, acc))

        if acc.capped:
            # Appended directly: the cap is full by definition, and the one
            # finding that explains why must not be the one it drops.
            acc.findings.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.SCAN.FINDING_LIMIT",
                    message=(
                        f"The scan reached its limit of {acc.finding_cap} findings and "
                        f"stopped recording more. Results are partial."
                    ),
                    remediation=(
                        "Raise limits.max_findings, or narrow the scan. A repository "
                        "that produces this many findings usually has one systemic "
                        "cause worth fixing first."
                    ),
                )
            )

        # A suppression that expired is reported, not merely inactive: the
        # finding it was hiding reappears at the same moment somebody is told
        # why, rather than as an unexplained new failure weeks later.
        matcher = SuppressionMatcher(self.config)
        acc.add(matcher.expiry_findings())
        findings = Engine._collapse_key_table(
            Engine._collapse_credential_name(
                Engine._collapse_polyglot_corpus(
                    Engine._collapse_key_corpus(
                        Engine._collapse_idiom(
                            Engine._collapse_repeats(
                                Engine._collapse_graded_pair(matcher.apply(acc.findings))
                            )
                        )
                    )
                )
            )
        )

        dependencies = self._annotated(dependencies, findings, ctx, units)
        result = ScanResult(
            findings=findings,
            repository=inventory,
            dependencies=dependencies,
            sources=Engine._configured_sources(units),
            target_kind="sbom" if ingested else "source",
            stats=ScanStats(
                cache_hits=self.cache.hits,
                cache_misses=self.cache.misses,
                archives_expanded=self._archive_stats[0],
                archive_members=self._archive_stats[1],
                archive_ms=self._archive_stats[2],
                dependencies=len(dependencies),
                files_scanned=acc.files_scanned,
                files_skipped=acc.files_skipped,
                bytes_scanned=acc.bytes_scanned,
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
            intel=intel,
        )

        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    def _intel_status(self, acc: _Accumulator) -> dict[str, Any]:
        """Refresh from the signed feed when allowed, and say how current the intel is.

        Stale intel is not a clean scan: a package that turned malicious since the intel was
        built matches nothing. So past `max_intel_age` the scan says so and is incomplete.
        """
        from cordon_scanner.intel import feed

        use_feed = self.config.intel_feed and not feed.FeedClient.offline_requested()
        if use_feed:
            self.progress.phase("intel")
        status = feed.FeedClient.status(use_feed=use_feed, max_age=self.config.max_intel_age)
        if status.stale:
            acc.complete = False
            age = (
                f"{status.age_seconds // 3600} hours old"
                if status.age_seconds is not None
                else "of unknown age"
            )
            reason = f" The feed could not be used: {status.error}." if status.error else ""
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.INTEL.STALE",
                    message=(
                        f"The threat intel behind this scan is {age}, past the "
                        f"{status.max_age_seconds} second limit, so recently published "
                        f"malware and advisories may not be matched.{reason}"
                    ),
                    remediation=(
                        "Allow the scan to reach the feed, run `cordon-scanner intel update`, "
                        "or install a current signed bundle with `cordon-scanner bundle install`."
                    ),
                    severity=Severity.MEDIUM,
                )
            )
        return status.to_dict()

    # -- Archives ---------------------------------------------------------

    def _scan_archive(self, path: Path, acc: _Accumulator, started: float) -> ScanResult:
        """Scan an archive without writing any of it to disk.

        Members are held in memory and never materialised. Nothing that was
        never written can be executed, followed, or left behind by a crash,
        which removes a class of problem rather than mitigating it.

        A rejected member becomes an OPERATIONAL finding. An archive that was
        refused and one that was clean must never look alike, which is the same
        rule the rest of the engine follows for skipped files.
        """
        self._scanning_archive = True
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SourceError(f"cannot read {path}: {exc}") from exc

        ctx = self._context(Repository(root=str(path)))
        # Deliberately uncached. The archive has to be read and expanded in full
        # either way, so caching would skip only the matching, and a stale entry
        # keyed on an archive whose contents changed under the same name is a
        # risk with almost no payoff.
        units: list[FileUnit] = []

        # Members the extractor refused. Collected rather than discarded: a
        # package shipping a payload member that was oversize, a symlink, a
        # traversal name or past the entry cap was scanned, reported nothing
        # about that member, and returned complete.
        rejected: list[tuple[str, str, str]] = []

        # The directory path computes a deadline and a retained-byte budget;
        # this one returned before reaching either, so `cordon-scanner scan
        # package.tgz` had no wall-clock bound at all and a 2 GiB memory bound
        # that was never compared against the configured one. That is the
        # amplifier behind the tar-bomb finding: the limits existed and this
        # path did not consult them.
        # `total_timeout: 0` is "no budget", as every other check on it reads it -- not a budget
        # already spent, which stopped a scan before its first file.
        deadline = (
            started + self.config.limits.total_timeout
            if self.config.limits.total_timeout > 0
            else float("inf")
        )
        retained = 0

        # A container image is read the way a runtime assembles it -- layers squashed, whiteouts
        # applied -- rather than as nested tarballs, whose layer members are far past any per-member
        # limit and whose files would be scanned once per layer that touched them.
        image = self._image_inventory(data, acc)
        members: Iterable[tuple[str, bytes]]
        if image is not None:
            from cordon_scanner.images import oci

            members = (
                (f"{path.name}!{member}", payload)
                for member, payload in oci.ImageLayers.added_files(
                    data,
                    image,
                    max_file_bytes=self.config.limits.max_file_bytes,
                    max_total_bytes=self.config.limits.max_memory_bytes or (1 << 30),
                )
            )
        else:
            members = ArchiveReader.walk_archive(
                data,
                path=path.name,
                limits=self.config.limits,
                rejected=rejected,
                deadline=deadline if self.config.limits.total_timeout > 0 else None,
            )

        try:
            for member_path, member_data in members:
                if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                    acc.complete = False
                    acc.append(
                        Engine._operational(
                            path=path.name,
                            rule_id="OPERATIONAL.SCAN.TIMEOUT",
                            message=(
                                f"Expanding this archive exceeded the "
                                f"{self.config.limits.total_timeout:.0f}s budget, so the "
                                f"remaining members were not examined."
                            ),
                            remediation=(
                                "Raise --timeout, or treat an archive this large as "
                                "something to unpack and scan as a directory."
                            ),
                            severity=Severity.MEDIUM,
                        )
                    )
                    break

                retained += len(member_data)
                if (
                    self.config.limits.max_memory_bytes > 0
                    and retained > self.config.limits.max_memory_bytes
                ):
                    acc.complete = False
                    acc.append(
                        Engine._operational(
                            path=path.name,
                            rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                            message=(
                                f"Expanded members reached the "
                                f"{self.config.limits.max_memory_bytes} byte ceiling, so "
                                f"the remaining members were not examined."
                            ),
                            remediation="Raise limits.max_memory_bytes, or scan unpacked.",
                            severity=Severity.MEDIUM,
                        )
                    )
                    break

                member_content = FileContent.from_bytes(
                    member_path, member_data, self.config.limits
                )
                units.append(
                    FileUnit(
                        content=member_content,
                        language=LanguageRegistry.of_file(member_path, member_content),
                    )
                )
                acc.files_scanned += 1
                acc.bytes_scanned += len(member_data)
        except ArchiveError as exc:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=path.name,
                    rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                    message=f"The archive was refused and not scanned: {exc.message}",
                    remediation=(
                        "Treat a refused archive as unexamined. If the limits are wrong "
                        "for this input, raise them deliberately rather than assuming "
                        "the archive is clean."
                    ),
                    severity=Severity.MEDIUM,
                )
            )

        for member_path, reason, detail in rejected:
            acc.complete = False
            acc.append(
                Engine._rejected_member(member_path, reason, detail, image=image is not None)
            )

        # Manifests inside a package determine whether its code runs at install
        # time, which is the whole reason a package archive is worth scanning.
        hook_paths, consumer_hooks = self._manifest_hook_paths(units, acc)
        # The same install-time picture a directory scan builds: filename hooks (`setup.py`, a
        # `.pth`), and everything the hooks import or run. A downloaded sdist or tarball is the
        # commonest thing to vet, and it was the one target that skipped all three.
        hook_paths |= {
            unit.path
            for unit in units
            if not self._under_fixture_directory(unit.path)
            and any(
                hook.kind not in ("ci", "projectbuild")
                for hook in self._hooks_for(unit.path.rpartition("!")[2])
            )
        }
        hook_paths |= self._nuget_hooks(units)
        hook_paths |= ComposerPluginHooks.paths(units)
        entries = frozenset(hook_paths)
        hook_paths |= self._hook_import_closure(units, hook_paths)
        hook_paths |= self._hook_js_closure(units, hook_paths)
        ctx = replace(
            ctx,
            install_hook_paths=frozenset(hook_paths),
            install_entry_paths=entries,
            consumer_install_paths=frozenset(consumer_hooks),
            install_deferred_lines=self._hook_deferred_lines(units, hook_paths, entries),
            # Known before any file is examined, so a detector can tell an image's files from a
            # source tree's: an image's executables are what it ships.
            image=image if image is not None else ctx.image,
        )

        detectors = [d for d in self.detectors if self._detector_enabled(d, ctx)]
        self.progress.phase("scanning", total=len(units))
        # An image or a large archive is thousands of members (a Grafana image adds eleven
        # thousand files): across the worker pool, as a directory is, with each member's bytes
        # carried since it has no path on disk. In slices, so the scan's deadline is still checked.
        content_detectors = [
            d for d in detectors if not (d.requires.dependencies and d.requires.content is False)
        ]
        workers = ParallelScanner.worker_count(
            self.config.limits.max_workers, len(units), sum(len(u.content.raw) for u in units)
        )
        if workers > 1:
            from cordon_scanner.core.cache import ScanCache

            signature = ScanCache.detector_signature(content_detectors)
            for start in range(0, len(units), ARCHIVE_SLICE):
                if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                    acc.complete = False
                    acc.append(
                        Engine._operational(
                            path=path.name,
                            rule_id="OPERATIONAL.SCAN.TIMEOUT",
                            message=f"The {self.config.limits.total_timeout:.0f}s budget was reached with members still unexamined.",
                            remediation="Raise --timeout, or unpack and scan as a directory.",
                            severity=Severity.MEDIUM,
                        )
                    )
                    break
                acc.add(
                    self._scan_parallel(
                        units[start : start + ARCHIVE_SLICE],
                        path.parent,
                        ctx,
                        acc,
                        content_detectors,
                        signature,
                        carry_content=True,
                    )
                )
            units_left: list[FileUnit] = []
        else:
            units_left = units
        for unit in units_left:
            # The same budget the directory path applies between units. Most of
            # the cost of a hostile archive is here rather than in extraction --
            # a fifty-thousand-member archive expands in a second and then takes
            # eight to match against -- so a deadline that only covered
            # expansion bounded the wrong half.
            if self.config.limits.total_timeout > 0 and time.monotonic() > deadline:
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=path.name,
                        rule_id="OPERATIONAL.SCAN.TIMEOUT",
                        message=(
                            f"The {self.config.limits.total_timeout:.0f}s budget was reached "
                            f"with members still unexamined."
                        ),
                        remediation="Raise --timeout, or unpack and scan as a directory.",
                        severity=Severity.MEDIUM,
                    )
                )
                break
            for detector in detectors:
                if detector.requires.dependencies and detector.requires.content is False:
                    continue
                acc.add(self._run(detector, unit, ctx, acc))
            self.progress.advance(unit.path)
        acc.add(self._unexamined_install_code(acc.findings, ctx))
        acc.add(self._native_code_in_a_pure_wheel(units, ctx))
        acc.add(self._known_malicious_release(units, ctx))

        # A published archive carries its own manifests and lockfiles, and
        # "is this tarball a known-malicious release?" is the question most
        # people open one to ask. Building the graph from the members is what
        # lets the advisory, licence and dependency detectors answer it --
        # without it they had no `GraphUnit` to inspect, so scanning a package
        # archive silently skipped every check about its dependencies.
        self.progress.phase("dependencies")
        dependencies = self._build_graph(units, acc)
        if image is not None:
            self._report_image_contents(image, acc)
        package = self._is_package_distribution(units)
        target_kind = "image" if image is not None else "package" if package else "archive"
        if package:
            # A consumer's installer resolves from the package's declared metadata, never from a
            # lockfile shipped inside it: those pins are the maintainers' own environment.
            ctx = replace(ctx, package_distribution=True)
            acc.findings[:] = self._author_time_ceiling(acc.findings, units)
            dependencies = tuple(
                replace(d, scope=Scope.DEV) if d.scope in (Scope.RUNTIME, Scope.UNKNOWN) else d
                for d in dependencies
            )
        if image is not None:
            ctx = replace(ctx, image=image)
            dependencies = (*dependencies, *self._image_dependencies(image))
        if dependencies:
            ctx = replace(ctx, dependencies=Engine._packages(dependencies))
            graph_unit = GraphUnit(dependencies=Engine._packages(dependencies))
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.add(self._run(detector, graph_unit, ctx, acc))

        dependencies = self._annotated(dependencies, acc.findings, ctx, units)
        result = ScanResult(
            findings=tuple(acc.findings),
            dependencies=dependencies,
            repository=Repository(root=str(path), file_count=acc.files_scanned),
            target_kind=target_kind,
            image=image.identity.to_dict() if image is not None else None,
            stats=ScanStats(
                files_scanned=acc.files_scanned,
                bytes_scanned=acc.bytes_scanned,
                dependencies=len(dependencies),
                rules_evaluated=len(self.rules),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            complete=acc.complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
        )
        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    # -- Phase 0: inventory ----------------------------------------------

    def inventory(
        self,
        root: Path,
        acc: _Accumulator | None = None,
        *,
        walked: Sequence[WalkEntry] | None = None,
        walker: Walker | None = None,
    ) -> Repository:
        """Determine what the target is.

        Consumed by every detector's applicability check, which is what makes
        detector selection automatic rather than configured. A user should not
        have to declare that their repository contains Terraform; the tool should
        observe it.
        """
        # Shared with `_units` when the caller has one, so the traversal
        # counters both phases read are the same counters. Creating a second
        # walker here left `_coverage_findings` reading a set of stats nobody
        # had walked with: a source that selected nothing then produced no
        # NOTHING_SCANNED finding, because as far as those stats were concerned
        # the tree was empty rather than unexamined.
        walker = walker if walker is not None else self._walker()
        # Materialised once by `_scan` and handed to both phases when the source
        # yields the walker's own output, which is the default and the case a
        # large monorepo actually hits. Walking twice cost a fifth of a warm
        # scan of fifty thousand files in `stat` calls that answered the same
        # question twice.
        traversal: Iterable[WalkEntry] = walked if walked is not None else walker.walk(root)
        languages: dict[str, tuple[int, int]] = {}
        evidence: dict[str, set[str]] = {}
        hooks: list[Hook] = []
        # Directories that are importable Python packages. Collected during the
        # walk because `_hooks_for` sees one path at a time and the question
        # `PACKAGED_BUILD_FILENAMES` asks is about a file's neighbours. This set
        # rather than every path walked, which on a large monorepo is tens of
        # megabytes held to answer a question about a handful of files.
        package_directories: set[str] = set()
        manifests: dict[str, list[str]] = {}
        lockfiles: dict[str, list[str]] = {}
        total_bytes = 0
        file_count = 0

        for entry in traversal:
            if entry.is_symlink:
                continue
            file_count += 1
            total_bytes += entry.size

            language = LanguageRegistry.identify_language(entry.rel_path)
            if language:
                files, size = languages.get(language, (0, 0))
                languages[language] = (files + 1, size + entry.size)
                evidence.setdefault(language, set()).add(
                    f"*{Path(entry.rel_path).suffix}"
                    if Path(entry.rel_path).suffix
                    else entry.rel_path
                )

            if ContainerPaths.basename(entry.rel_path) == "__init__.py":
                package_directories.add(entry.rel_path.rpartition("/")[0])

            hooks.extend(self._hooks_for(entry.rel_path))

            eco = EcosystemRegistry.manifest_ecosystem(entry.rel_path)
            if eco:
                manifests.setdefault(eco, []).append(entry.rel_path)
                hooks.extend(self._manifest_hooks(entry.real_path, entry.rel_path, eco))
            lock = EcosystemRegistry.lockfile_ecosystem(entry.rel_path)
            if lock:
                lockfiles.setdefault(lock, []).append(entry.rel_path)

        stats = tuple(
            LanguageStat(
                language=language,
                files=files,
                bytes=size,
                share=(size / total_bytes) if total_bytes else 0.0,
                evidence=tuple(sorted(evidence.get(language, ()))),
            )
            # Sorted by size then name: byte-weighted ranking reflects what the
            # repository actually is better than file count, which over-weights
            # many small config files. The name breaks ties so the order is
            # deterministic.
            for language, (files, size) in sorted(
                languages.items(), key=lambda kv: (-kv[1][1], kv[0])
            )
        )

        hooks = [hook for hook in hooks if Engine._hook_executes(hook, package_directories)]

        if acc is not None and walker.stats.limit_hit:
            acc.complete = False

        # A project is a subtree with its own manifest. Modelling a monorepo as
        # N projects is what keeps detector selection correct: without it, a
        # polyglot tree gets the union of every rule applied to every file.
        projects: list[Project] = []
        for eco_id, paths in sorted(manifests.items()):
            for manifest_path in sorted(paths):
                directory = manifest_path.rpartition("/")[0]
                projects.append(
                    Project(
                        path=directory,
                        ecosystem=eco_id,
                        manifests=(manifest_path,),
                        lockfiles=tuple(
                            p
                            for p in lockfiles.get(eco_id, ())
                            if p.rpartition("/")[0] == directory
                        ),
                    )
                )

        is_git, revision, remote, at_repository_root = self._provenance(root)
        return Repository(
            root=str(root),
            is_git=is_git,
            scanned_repository_root=at_repository_root,
            languages=stats,
            projects=tuple(projects),
            ecosystems=tuple(sorted(set(manifests) | set(lockfiles))),
            hooks=tuple(hooks),
            file_count=file_count,
            total_bytes=total_bytes,
            revision=revision,
            remote=remote,
        )

    @staticmethod
    def _collapse_repeats(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """One finding per distinct issue, however many copies of the file exist.

        A repository that keeps an old copy of a tree reports everything in it twice.
        `stacksimplify/terraform-on-aws-ec2` keeps `BACKUP-BEFORE-DEC2023-UPDATES/` and
        `V1-UPDATES-DEC2023/` beside the current material, and 124 of its 180 findings
        were in those two directories -- the same security group, the same key, reported
        again. `terraform-on-aws-eks` commits one RSA private key into 179 directories,
        one per lesson, and `community-scripts/ProxmoxVE` has 618 scripts that source
        the same bootstrap function from the same mutable branch.

        In each of those a reader needs one finding and a count, not N findings. So
        findings that share a rule AND the hash of the VALUE they matched collapse to
        the first by path, carrying the number of files and the first few names.

        The grouping key is the rule and the hash of the FILE, which is the only
        definition of "a copy" that holds up. Two earlier keys were tried and both were
        wrong:

        * The hash of the matched VALUE. For a private key that match is the PEM header
          plus twelve characters of body, and every 2048-bit RSA key in the world begins
          `MIIEogIBAAKC` -- so Spring Boot's nineteen distinct client keys would have
          collapsed into one finding claiming they were the same value. A test written
          to assert the opposite caught it.
        * The hash of a matched SNIPPET. `cidr_blocks = ["0.0.0.0/0"]` hashes the same
          in a hundred unrelated modules and `eval(` the same in fifty unrelated files,
          and saying "this is one thing to fix" about fifty independent problems is
          false. This project's own suite caught that one: two tests write the same
          payload to two paths to prove a point about path selection.

        Identical files are immune to both. A duplicated lesson directory, a `BACKUP-`
        copy of a tree, one key committed into 179 places: same bytes, same finding,
        one report.

        Only across DIFFERENT paths, and never operational notes -- those are already
        aggregated where it helps and are about the scan rather than the code.

        The trade is SARIF: a consumer that renders one alert per location now gets one
        alert for the group. That is the right answer for the text report and the wrong
        answer for a code-scanning annotation, and the count in the message and the
        `copies` metadata are what a reader has instead.
        """
        groups: dict[tuple[str, str], list[Finding]] = {}
        order: list[Finding] = []
        for finding in findings:
            file_hash = dict(finding.evidence.metadata).get(Finding.FILE_HASH_KEY)
            if not file_hash or finding.category is Category.OPERATIONAL:
                order.append(finding)
                continue
            groups.setdefault((finding.rule_id, file_hash), []).append(finding)

        for group in groups.values():
            paths = sorted({f.location.path for f in group})
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            if len(paths) < 2:
                order.extend(group)
                continue
            listed = ", ".join(paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            order.append(
                replace(
                    first,
                    message=(
                        f"{first.message} This file is byte-for-byte identical in "
                        f"{len(paths)} places ({listed}{more}), so the finding is "
                        f"reported once: it is one thing to fix, not {len(paths)}."
                    ),
                    evidence=replace(
                        first.evidence,
                        metadata=(*first.evidence.metadata, ("copies", str(len(paths)))),
                    ),
                )
            )

        return tuple(sorted(order, key=lambda f: (f.location.path, f.location.line or 0)))

    @staticmethod
    def _collapse_idiom(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """One decision made in many files is one finding.

        `community-scripts/ProxmoxVE` ships about six hundred container install scripts
        and every one of them opens the same way: source a bootstrap function from the
        `main` branch of a GitHub repository. 601 of its 618 dropper findings carry a
        byte-identical snippet, and 97 of its 98 persistence findings carry another.

        That is one design decision applied six hundred times. It is a real finding --
        what runs is whatever that branch holds at install time -- and it is ONE thing
        for the project to change, in the generator that writes those scripts.

        Two conditions, and both exist to keep this away from independent findings:

        * Ten or more distinct files. Three modules with the same one-line mistake are
          three things to fix, and a test asserts they stay three.
        * A snippet long enough to be specific -- forty bytes. `cidr_blocks =
          ["0.0.0.0/0"]` is twenty-seven and hashes the same in a hundred unrelated
          modules; the ProxmoxVE line is eighty and could not arrive by coincidence.

        The count and the first few paths are in the message, so nothing is hidden: a
        reader who wants the full list has the rule id and can ask for it without the
        collapsing.
        """
        groups: dict[tuple[str, str], list[Finding]] = {}
        for finding in findings:
            evidence = finding.evidence
            snippet = evidence.snippet or ""
            if finding.category is Category.OPERATIONAL:
                continue
            # A composite carries its own key, because the hit its evidence
            # points at and the construct its files SHARE are different hits.
            # `_anchor` moved the evidence onto the specific half -- the
            # `curl | bash` rather than the banner above it -- and keying this
            # on the evidence therefore switched the collapse off: ProxmoxVE's
            # persistence findings went from one to twenty-seven in a pass. See
            # `CapabilityDetector._with_idiom_key`, which is where the shared
            # half is hashed, and which applies this same length test to it.
            idiom = dict(evidence.metadata).get("idiom_hash")
            if idiom is None and (not evidence.match_hash or len(snippet) < MIN_IDIOM_SNIPPET):
                continue
            groups.setdefault((finding.rule_id, idiom or evidence.match_hash), []).append(finding)

        replaced: dict[int, Finding | None] = {}
        for group in groups.values():
            paths = sorted({f.location.path for f in group})
            if len(paths) < MIN_IDIOM_FILES:
                continue
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            kept = replace(
                first,
                message=(
                    f"{first.message} The identical construct appears in {len(paths)} "
                    f"files ({listed}{more}), so it is reported once: that is one "
                    f"decision applied {len(paths)} times, and one place to change it."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("occurrences", str(len(paths)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        if not replaced:
            return tuple(findings)

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def _collapse_key_corpus(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """A directory full of private keys is a corpus, not a disclosure.

        OpenSSL ships eleven in `apps/` -- `ca-key.pem`, `pca-key.pem`, `privkey.pem`,
        `s512-key.pem`, `rsa8192.pem` and the rest -- and has since the 1990s. They are
        in every release tarball and vendored into Node, Python and most of the
        internet. Metasploit ships thirty under `data/exploits/CVE-2023-34039/`, one per
        affected appliance version, because the vulnerability IS that the vendor shipped
        those keys. MongoDB keeps twenty-eight under `x509/static/`; rustls keeps eight
        per algorithm under `test-ca/`.

        None of those is a key somebody leaked, and eleven CRITICAL findings is not how
        to tell a reader so. One finding naming the directory and the count is, and it
        is also what they would act on: baseline the directory, or explain it.

        The threshold is what makes this safe to do at all. One or two keys in a
        directory is what a leak looks like -- a stray `id_rsa`, a `server.key` beside a
        `deploy.sh` -- and those are untouched. Five distinct key FILES in one directory
        is a hierarchy somebody generated: a CA, an intermediate, a client, a server, a
        revoked one.

        Ceilinged rather than dropped, and the count is in the message, so a directory
        of live keys is still in the report and still says how many. What changes is
        that it stops failing a build eleven times over.
        """
        keys: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.rule_id == PRIVATE_KEY_RULE:
                keys.setdefault(finding.location.path.rpartition("/")[0], []).append(finding)

        corpora = {
            directory: group
            for directory, group in keys.items()
            if len({f.location.path for f in group}) >= PRIVATE_KEY_CORPUS
        }
        if not corpora:
            return tuple(findings)

        replaced: dict[int, Finding | None] = {}
        for directory, group in corpora.items():
            paths = sorted({f.location.path for f in group})
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(path.rpartition("/")[2] for path in paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            where = directory or "the repository root"
            kept = replace(
                first,
                severity=min(first.severity, KEY_CORPUS_CEILING),
                confidence=min(first.confidence, KEY_CORPUS_CONFIDENCE),
                message=(
                    f"{where} holds {len(paths)} private keys ({listed}{more}). A "
                    f"directory of keys is a generated hierarchy -- a CA, an "
                    f"intermediate, a client, a server -- far more often than it is a "
                    f"disclosure, so this is reported once and below its usual "
                    f"severity. If any of these protects something live, every one of "
                    f"them is public: they are in git history and in every clone."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("keys_in_directory", str(len(paths)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def _collapse_credential_name(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """The same credential-shaped name assigned in many files is one decision.

        `_collapse_idiom` makes this argument already and cannot reach a secret: it groups
        on a forty-byte snippet, and a secret's evidence is hash-only by policy, so there
        is no snippet to group on. What a secret finding does carry is the name the value
        was assigned to, and that is the key here.

        `rclone` declares `rcloneEncryptedClientSecret` in sixteen backend modules. Each
        value differs -- one OAuth app per cloud provider -- and the decision is one: ship
        a client secret in the binary, which a native application has to do, because RFC
        8252 says it cannot keep one confidential and `obscure.MustReveal` un-obscures it
        at runtime anyway.

        The threshold is `_collapse_idiom`'s ten, for the reason that docstring gives:
        three modules with the same mistake are three things to fix.
        """
        groups: dict[tuple[str, str], list[Finding]] = {}
        for finding in findings:
            if not finding.rule_id.startswith("SECRET."):
                continue
            kind = dict(finding.evidence.metadata).get("kind")
            if not kind:
                continue
            groups.setdefault((finding.rule_id, kind), []).append(finding)

        replaced: dict[int, Finding | None] = {}
        for (_, kind), group in groups.items():
            paths = sorted({f.location.path for f in group})
            if len(paths) < CREDENTIAL_NAME_FILES:
                continue
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            kept = replace(
                first,
                severity=min(first.severity, CREDENTIAL_NAME_CEILING),
                message=(
                    f"The same {kind} appears in {len(paths)} files ({listed}{more}). The "
                    f"same name in that many files is one decision rather than that many "
                    f"leaks -- a "
                    f"credential per backend, per provider or per tenant -- so it is "
                    f"reported once and below its usual severity. Every value is still "
                    f"committed: if any of them protects something live, all of them are "
                    f"in git history and in every clone."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("files_with_this_name", str(len(paths)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def _collapse_polyglot_corpus(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """A directory full of format mismatches is a collection of them.

        Built from `_collapse_key_corpus` above, which makes the same argument about the
        same kind of place, and the thresholds match for the same reason: one or two files
        whose contents contradict their names is what a disguise looks like, and five in
        one directory is somebody's collection.

        `swisskyrepo/PayloadsAllTheThings` keeps sixteen under
        `Upload Insecure Files/Picture ImageMagick/`. Every one is a genuine polyglot and
        the repository exists to collect them; what the reader needs is one finding saying
        the directory holds sixteen, which is also the thing they would act on.
        """
        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.rule_id == POLYGLOT_RULE:
                groups.setdefault(finding.location.path.rpartition("/")[0], []).append(finding)

        corpora = {
            directory: group
            for directory, group in groups.items()
            if len({f.location.path for f in group}) >= POLYGLOT_CORPUS
        }
        if not corpora:
            return tuple(findings)

        replaced: dict[int, Finding | None] = {}
        for directory, group in corpora.items():
            paths = sorted({f.location.path for f in group})
            first = min(group, key=lambda f: (f.location.path, f.location.line or 0))
            listed = ", ".join(path.rpartition("/")[2] for path in paths[:MAX_REPEAT_PATHS_LISTED])
            more = (
                f" and {len(paths) - MAX_REPEAT_PATHS_LISTED} more"
                if len(paths) > MAX_REPEAT_PATHS_LISTED
                else ""
            )
            where = directory or "the repository root"
            kept = replace(
                first,
                severity=min(first.severity, POLYGLOT_CORPUS_CEILING),
                message=(
                    f"{where} holds {len(paths)} files whose contents contradict their "
                    f"names ({listed}{more}). A directory of them is a collection -- an "
                    f"upload-test corpus, a fuzzing corpus, a payload reference -- far "
                    f"more often than it is a disguise, so this is reported once and "
                    f"below its usual severity. Each file is still a polyglot: if any of "
                    f"them is served to a browser or passed to an image library, the "
                    f"contents are what runs."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(
                        *first.evidence.metadata,
                        ("polyglots_in_directory", str(len(paths))),
                    ),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def _collapse_key_table(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """Several private keys in ONE file are a table of keys.

        The directory form above needs five, because a directory is a place a leak can
        land in: a stray `id_rsa`, a `server.key` beside a `deploy.sh`. A FILE is not.
        A leak is one key in a file -- it got there by being copied in -- and three in
        one file is a fixture table somebody generated on purpose.

        `bitwarden/server` keeps four in `util/RustSdk/rust/src/rsa_keys.rs`, which is
        test key material for its SDK bindings held as Rust constants, and mbedtls's
        `certs.c` and its vendored copies hold a dozen apiece. Four CRITICAL findings
        pointing at four lines of one file is not how to tell a reader that.

        Same ceiling and same shape as the directory form, for the same reason: the
        count is in the message, so a file of live keys is still in the report and still
        says how many.
        """
        keys: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.rule_id == PRIVATE_KEY_RULE:
                keys.setdefault(finding.location.path, []).append(finding)

        tables = {path: group for path, group in keys.items() if len(group) >= KEY_TABLE_SIZE}
        if not tables:
            return tuple(findings)

        replaced: dict[int, Finding | None] = {}
        for path, group in tables.items():
            first = min(group, key=lambda f: f.location.line or 0)
            kept = replace(
                first,
                severity=min(first.severity, KEY_CORPUS_CEILING),
                confidence=min(first.confidence, KEY_CORPUS_CONFIDENCE),
                message=(
                    f"{path} holds {len(group)} private keys. Several keys in one file "
                    f"is a table somebody generated -- test material for a TLS handshake, "
                    f"a fixture per algorithm -- far more often than it is a disclosure, "
                    f"so this is reported once and below its usual severity. If any of "
                    f"them protects something live, every one of them is public: they are "
                    f"in git history and in every clone."
                ),
                evidence=replace(
                    first.evidence,
                    metadata=(*first.evidence.metadata, ("keys_in_file", str(len(group)))),
                ),
            )
            for finding in group:
                replaced[id(finding)] = kept if finding is first else None

        out: list[Finding] = []
        for finding in findings:
            if id(finding) not in replaced:
                out.append(finding)
                continue
            substitute = replaced[id(finding)]
            if substitute is not None:
                out.append(substitute)
        return tuple(out)

    @staticmethod
    def _collapse_graded_pair(findings: Sequence[Finding]) -> tuple[Finding, ...]:
        """`MALWARE.X` and `SUSPECT.X` on one span are one observation.

        The composites come in graded pairs on purpose: `SUSPECT.EXFIL.001` is
        credential access with egress, and `MALWARE.EXFIL.001` is the same pair
        in an install hook. Where the install hook is what the file is, both
        match the same capabilities at the same place, and the report carried
        each of them -- so `saltstack/salt`'s `setup.py:459` and
        `tinyhumansai/openhuman`'s `install.js:9` appeared twice, and a reader
        counting findings counted one thing as two.

        The stronger rule already says everything the weaker one says: its match
        clause is the weaker clause plus the context. So the weaker finding is
        dropped rather than ceilinged -- there is no residual claim left in it.

        Only within a family and only on an identical span. `SUSPECT.DROPPER.001`
        elsewhere in the same file is a second place that fetches and executes,
        and it stays.

        Measured: seven findings across five repositories of 1,427. Small, and
        the reason to fix it anyway is that severity counts are what a gate
        reads -- two criticals for one line makes the number mean less than it
        appears to.
        """
        Span = tuple[str, int | None, int | None, int | None]
        by_span: dict[Span, set[str]] = {}
        for finding in findings:
            location = finding.location
            span = (location.path, location.line, location.byte_start, location.byte_end)
            by_span.setdefault(span, set()).add(finding.rule_id)

        superseded: set[tuple[Span, str]] = set()
        for span, rule_ids in by_span.items():
            for rule_id in rule_ids:
                if not rule_id.startswith("MALWARE."):
                    continue
                weaker = f"SUSPECT.{rule_id[len('MALWARE.') :]}"
                if weaker in rule_ids:
                    superseded.add((span, weaker))
        if not superseded:
            return tuple(findings)

        out: list[Finding] = []
        for finding in findings:
            location = finding.location
            span = (location.path, location.line, location.byte_start, location.byte_end)
            if (span, finding.rule_id) in superseded:
                continue
            out.append(finding)
        return tuple(out)

    @staticmethod
    def _hook_executes(hook: Hook, package_directories: set[str]) -> bool:
        """Whether a file identified as a hook by its NAME really is one.

        Two filename tests are not specific enough on their own, and both were
        wrong in the direction that matters: they invent an install-time execution
        context, which is the largest multiplier in the risk model and the
        condition every `MALWARE.*` composite hinges on.

        **A `setup.py` inside a package.** `NousResearch/hermes-agent` carries
        `hermes_cli/setup.py` (an interactive setup wizard),
        `hermes_cli/subcommands/setup.py` (the `hermes setup` argument parser) and
        `plugins/memory/hindsight/setup.py`. None is a packaging script, and a
        packaging script cannot be one of these: a file inside a package directory
        is imported as `package.setup`, and `python setup.py` from the
        distribution root would not find it.

        The cost of getting this wrong was not one finding. `_hook_import_closure`
        follows imports out of every hook, and from those three modules it reached
        582 files -- the whole agent. Every credential read beside an HTTPS call in
        any of them became `MALWARE.EXFIL.001` at CRITICAL, in the MALICIOUS
        category, with remediation telling the reader to treat their host as
        compromised and rotate every credential on it. Seventeen of those, plus
        fifteen `MALWARE.DYNAMIC_DISPATCH.001` on ordinary `getattr` calls, on a
        repository whose worst actual finding is a lockfile without hashes.

        **A git sample hook.** `.git/hooks/pre-commit.sample` is shipped by `git
        init` and never runs: git executes `.git/hooks/pre-commit`, and the suffix
        is how it tells the two apart. Fourteen of them were counted as hooks in
        every repository ever scanned.
        """
        name = ContainerPaths.basename(hook.path)
        directory = hook.path.rpartition("/")[0]
        if name in PACKAGED_BUILD_FILENAMES:
            if directory in package_directories:
                return False
            # And a build file the project's own tests build. See
            # `FIXTURE_DIRECTORIES`: this one costs more than the others,
            # because a hook seeds an import closure and a fixture that imports
            # the library puts the whole library in install-time context.
            return not Engine._under_fixture_directory(hook.path)
        return not name.endswith(".sample")

    @staticmethod
    def _under_fixture_directory(path: str) -> bool:
        """Whether any directory on this path is a test or example directory.

        Any segment, not just the first: pytorch's is `test/cpp_extensions/`,
        mongodb vendors one at `src/third_party/wiredtiger/test/3rdparty/`, and
        servo's is `tests/wpt/tests/tools/third_party/`. A rule that only looked
        at the top level would have caught one of the three.
        """
        return ContainerPaths.under_fixture_directory(path)

    @staticmethod
    def _provenance(root: Path) -> tuple[bool, str | None, str | None, bool]:
        """The commit and remote this scan describes.

        `Repository` declared both fields, `to_dict` serialised both, and
        nothing ever set either -- so every report and every SARIF upload
        recorded `null` for the two values that say *which* code was examined.
        A result nobody can tie to a commit is a result nobody can act on later:
        it says a repository was clean without saying which version of it.

        `GitRepository.discover` already computed both, including stripping any
        credential from the remote, and its answer was simply never asked for.

        `is_git` had the identical defect and is returned here for the same
        reason. It gated whether any repository-scoped detector runs at all, so
        leaving it false meant the history checks were shipped and never
        executed -- a detector that cannot run is indistinguishable from one
        that found nothing.

        Failure is silent on purpose. A directory that is not a repository is
        the ordinary case, not a degraded scan, and it is already visible in the
        report as an absent revision.
        """
        from cordon_scanner.sources.git import GitRepository

        try:
            info = GitRepository.discover(root)
        except (SourceError, OSError):  # pragma: no cover - defensive
            return (False, None, None, False)
        if info is None:
            return (False, None, None, False)
        # Whether the target is the repository root, which is a different question
        # from whether a repository is above it. Resolved on both sides, so a
        # symlinked or relative target does not read as a subdirectory of itself.
        try:
            at_root = Path(info.root).resolve() == Path(root).resolve()
        except OSError:  # pragma: no cover - defensive
            at_root = False
        return (True, info.revision, info.remote, at_root)

    def _manifest_hooks(self, real_path: Path, rel_path: str, ecosystem_id: str) -> list[Hook]:
        """Lifecycle hooks declared inside a manifest.

        Parsed during inventory rather than inferred from the filename, because
        a `postinstall` entry is the single most useful thing this phase can
        surface: it names code that runs before any other control, and it is
        invisible from the path alone.
        """
        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:
            return []
        loaded = FileContent.load(real_path, rel_path, self.config.limits)
        if isinstance(loaded, Skipped):
            return []
        try:
            return list(ecosystem.parse_manifest(loaded).hooks)
        except Exception:
            return []

    @staticmethod
    def _languages_from_hooks(inventory: Repository) -> dict[str, str]:
        """Languages implied by what a lifecycle script runs.

        `"postinstall": "node ./payload.png"` names both the interpreter and the
        file. An interpreter handed an explicit path does not consult the
        extension, so the file is JavaScript however it is spelled -- and
        `payload.png` otherwise gets `language=None` and only the
        language-agnostic rules, which is the rename half of the NUL-byte
        evasion.

        Only lifecycle commands are read, and only the token immediately after a
        recognised interpreter. That keeps this from becoming a general
        shell parser: the aim is to stop a rename hiding executed code, not to
        model every command line.
        """
        implied: dict[str, str] = {}
        for hook in inventory.hooks:
            if not hook.command:
                continue

            base = hook.path.rpartition("/")[0]
            tokens = [token for token in re.split(r"[\s;&|()]+", hook.command) if token]
            for index, token in enumerate(tokens):
                language = LanguageRegistry.language_from_interpreter(token)
                if language is None:
                    continue
                for candidate in tokens[index + 1 :]:
                    if candidate.startswith("-"):
                        continue
                    target = candidate.lstrip("./")
                    if not target:
                        break
                    resolved = f"{base}/{target}" if base else target
                    implied.setdefault(resolved, language)
                    break
        return implied

    @staticmethod
    def _nuget_hooks(units: Sequence[FileUnit]) -> set[str]:
        """What a NuGet package runs on the consumer's machine, when there is a `.nuspec` beside it.

        `tools/init.ps1` and `tools/install.ps1` run inside Visual Studio when the package is
        added; `build/` and `buildTransitive/` `.targets` and `.props` are imported into every
        build of every project that references the package, so their `<Exec>` tasks run there.
        Only beside a `.nuspec`: a repository's own `tools/install.ps1` is a script a person runs.
        """
        roots = {
            unit.path.rpartition("!")[2].rpartition("/")[0]
            for unit in units
            if unit.path.lower().endswith(".nuspec")
        }
        if not roots:
            return set()
        hooks: set[str] = set()
        for unit in units:
            member = unit.path.rpartition("!")[2]
            for root in roots:
                prefix = f"{root}/" if root else ""
                if not member.startswith(prefix):
                    continue
                inner = member[len(prefix) :].lower()
                if inner in ("tools/init.ps1", "tools/install.ps1", "tools/uninstall.ps1") or (
                    inner.startswith(("build/", "buildtransitive/"))
                    and inner.endswith((".targets", ".props"))
                ):
                    hooks.add(unit.path)
        return hooks

    @staticmethod
    def _hooks_for(rel_path: str) -> Iterator[Hook]:
        """Identify paths that execute during install, build or version control.

        First-class because execution context is the largest single multiplier in
        the risk model. Detecting these before scanning is what lets the same
        capability pair be quiet in application code and decisive here.

        This is the filename-level pass. Manifest lifecycle scripts are found by
        the manifest detector, which can parse them properly.
        """
        name = ContainerPaths.basename(rel_path)
        if (
            name in DEPENDENCY_BUILD_FILENAMES
            or name.endswith(DEPENDENCY_BUILD_SUFFIXES)
            or f"/{rel_path}".endswith("/deps/build.jl")
        ):
            # Julia's Pkg runs a package's deps/build.jl when the package is added or built.
            yield Hook(kind="build", path=rel_path, name=name)
        elif name.endswith(".pth"):
            # Installed into site-packages, its `import` lines run in every Python process the
            # machine starts -- earlier and more often than any install hook.
            yield Hook(kind="startup", path=rel_path, name=name)
        elif name in PROJECT_BUILD_FILENAMES:
            yield Hook(kind="projectbuild", path=rel_path, name=name)
        elif rel_path.startswith(".githooks/") or "/.git/hooks/" in f"/{rel_path}":
            yield Hook(kind="githook", path=rel_path, name=name)
        elif rel_path.startswith(CI_HOOK_PREFIXES) or name in CI_HOOK_FILENAMES:
            yield Hook(kind="ci", path=rel_path, name=name)

    # -- Phase 1: planning and unit production ---------------------------

    def _walker(self) -> Walker:
        return Walker(
            exclude=self.config.exclude,
            include=self.config.include,
            limits=self.config.limits,
        )

    def _context(self, inventory: Repository, deadline: float | None = None) -> ScanContext:
        return ScanContext(
            config=self.config,
            rules=self.rules,
            repository=inventory,
            deadline=deadline,
            # `projectbuild` is in neither. A Makefile is not an install hook -- see
            # `PROJECT_BUILD_FILENAMES` -- and it is not a pipeline either, so it gets
            # no context multiplier and is scored on what it actually contains.
            install_hook_paths=frozenset(
                h.path for h in inventory.hooks if h.kind not in ("ci", "projectbuild")
            ),
            ci_hook_paths=frozenset(h.path for h in inventory.hooks if h.kind == "ci"),
            scorer=self.scorer,
            offline=self.config.offline,
        )

    def _units(
        self,
        root: Path,
        inventory: Repository,
        acc: _Accumulator,
        deadline: float,
        *,
        walked: Sequence[WalkEntry] | None = None,
        walker: Walker | None = None,
    ) -> Iterator[FileUnit]:
        """Produce one unit per scannable file.

        A generator, but `scan` collects it into a list, because manifest hooks
        are discovered during this pass and change the context every later
        finding is scored against -- so detection cannot begin until the pass is
        complete. The generator therefore does not bound memory on its own, and
        the docstring here used to claim it did.

        What bounds it is `limits.max_memory_bytes`, enforced below as a running
        budget over retained content. The input is attacker-controlled and its
        size is not known in advance, so the ceiling has to be real rather than
        implied by the shape of the code.
        """
        walker = walker if walker is not None else self._walker()

        # A file an install hook executes is that interpreter's language,
        # whatever the file is called.
        implied_languages = self._languages_from_hooks(inventory)

        # Counted here rather than read from walker.stats, because the source
        # sits between the walker and this loop. A git mode narrows the walker's
        # output, and that narrowing is invisible to the walker's own counters:
        # `--tracked` in a repository where nothing is tracked once yielded zero
        # files while the stats reported a full traversal, so the scan examined
        # nothing and reported clean.
        selected = 0
        # Bytes of file content this scan is holding. `max_memory_bytes` was
        # declared, documented and checked nowhere.
        retained = 0
        # Files classified as binary artefacts. Counted so the scan can say how
        # many files it did not examine as source: a file that was skipped and a
        # file that was examined and found clean must not look the same.
        binary: list[str] = []
        lfs_pointers: list[str] = []
        # Archives left closed because expansion is off. See `expand_archives`.
        unopened: list[str] = []

        selection: Iterable[WalkEntry] = (
            walked if walked is not None else self.source.entries(root, walker)
        )
        for entry in selection:
            selected += 1

            # `>=`, not `>`. A budget of zero means no time is allowed, and on
            # platforms with a coarse monotonic clock the first reading can equal
            # the start time exactly, so a strict comparison silently never
            # trips. That made --timeout 0 a no-op on Windows.
            if time.monotonic() >= deadline:
                # A partial result a human can act on beats a stack trace, and
                # marking it partial is what stops it being read as a pass.
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="OPERATIONAL.SCAN.TIMEOUT",
                        message=(
                            f"The scan exceeded its {self.config.limits.total_timeout:.0f}s "
                            f"budget and stopped early. Results are partial."
                        ),
                        remediation=(
                            "Raise limits.total_timeout, narrow the scan with --include, "
                            "or scan projects individually."
                        ),
                    )
                )
                return

            if entry.is_symlink:
                acc.files_skipped += 1
                acc.append(
                    Engine._operational(
                        path=entry.rel_path,
                        rule_id="OPERATIONAL.FILE.SYMLINK",
                        message="Symbolic link was recorded but not followed.",
                        remediation="No action needed. Links are never dereferenced.",
                        severity=Severity.INFO,
                    )
                )
                continue

            loaded = self.source.load(entry, self.config.limits)
            if isinstance(loaded, Skipped):
                acc.files_skipped += 1
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=entry.rel_path,
                        rule_id="OPERATIONAL.FILE.UNREADABLE",
                        message=f"File could not be read ({loaded.reason}); it was not scanned.",
                        remediation="Check permissions, or exclude the path deliberately.",
                    )
                )
                continue

            expanded: list[FileUnit] | None = None
            if ArchiveReader.is_archive(entry.rel_path):
                if self.config.expand_archives:
                    expanded = self._expand_member_units(entry.rel_path, loaded, acc, deadline)
                else:
                    unopened.append(entry.rel_path)

            if loaded.is_binary and expanded is None:
                binary.append(entry.rel_path)

            if loaded.is_lfs_pointer:
                lfs_pointers.append(entry.rel_path)

            if loaded.truncated:
                # A file examined in part is not a file examined. Truncation was
                # reported at INFO and left `complete` true, so
                # `fail_on_incomplete` -- the one organisation control that
                # catches the timeout variant of this -- did not catch the
                # sharpest one: `max_file_bytes: 65536` in a repository's own
                # config, which reads as ordinary tuning and pads a payload out
                # of reach.
                acc.complete = False

            retained += len(loaded.raw)
            if 0 < self.config.limits.max_memory_bytes <= retained:
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                        message=(
                            f"Retained content reached the "
                            f"{self.config.limits.max_memory_bytes} byte budget after "
                            f"{acc.files_scanned} files, so the remaining files were "
                            f"not examined. Results are partial."
                        ),
                        remediation=(
                            "Raise limits.max_memory_bytes, exclude generated or "
                            "vendored directories, or scan the repository in parts."
                        ),
                    )
                )
                return

            acc.files_scanned += 1
            acc.bytes_scanned += len(loaded.raw)

            language = LanguageRegistry.identify_language(entry.rel_path)
            if language is None:
                language = implied_languages.get(entry.rel_path)
            if language is None:
                # An extensionless script -- `install`, `preinstall`,
                # `configure` -- got `language=None` and therefore only the
                # language-agnostic rules, although its shebang says exactly
                # what it is. Extensionless install scripts are a normal
                # shipping form and a normal place for a payload.
                language = LanguageRegistry.language_from_interpreter(loaded.shebang or "")
            if language is None and not loaded.is_binary:
                # And, last, what the content looks like. A file with neither a
                # known extension nor a shebang got no language at all, so a
                # payload in `postinstall` or `payload.dat` was examined by none
                # of the language rules while the identical bytes in
                # `postinstall.sh` were CRITICAL. See
                # `LanguageRegistry.identify_from_content` for why this is the
                # last step and never overrides a filename.
                language = LanguageRegistry.identify_from_content(loaded.text)

            yield FileUnit(content=loaded, language=language)

            # Members after the archive itself, each budgeted like a file: an
            # archive is the cheapest way to put a lot of content in front of a
            # scanner, so its members count against the same memory ceiling.
            for member in expanded or ():
                retained += len(member.content.raw)
                if 0 < self.config.limits.max_memory_bytes <= retained:
                    acc.complete = False
                    acc.append(
                        Engine._operational(
                            path=entry.rel_path,
                            rule_id="OPERATIONAL.SCAN.MEMORY_LIMIT",
                            message=(
                                f"Retained content reached the "
                                f"{self.config.limits.max_memory_bytes} byte budget while "
                                f"expanding this archive, so the remaining files were not "
                                f"examined. Results are partial."
                            ),
                            remediation=(
                                "Raise limits.max_memory_bytes, or exclude vendored "
                                "artefacts deliberately."
                            ),
                        )
                    )
                    return
                acc.files_scanned += 1
                acc.bytes_scanned += len(member.content.raw)
                yield member

        if unopened:
            # An archive that was not opened is content that was not examined. Said
            # once, with the paths, and it makes the scan incomplete: `--no-expand`
            # buys speed, not a clean result.
            acc.complete = False
            sample = ", ".join(sorted(unopened)[:5])
            more = f" and {len(unopened) - 5} more" if len(unopened) > 5 else ""
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.ARCHIVE.NOT_EXPANDED",
                    message=(
                        f"{len(unopened)} archive(s) were not opened because archive "
                        f"expansion is off, so their contents were not examined: "
                        f"{sample}{more}."
                    ),
                    remediation="Scan without --no-expand, or set scan.expand_archives: true.",
                )
            )

        if walker.stats.limit_hit:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.SCAN.LIMIT",
                    message=f"Traversal stopped early: {walker.stats.limit_hit}",
                    remediation="Raise the relevant limit or narrow the scan.",
                )
            )

        # -- Configuration that reduced coverage ---------------------------
        #
        # The scan target is untrusted input, and its configuration file is part
        # of it. Without an organisation policy there is no ceiling, so a
        # repository can legitimately exclude paths and disable detectors -- and
        # a hostile one can do the same to blind the scan entirely.
        #
        # That cannot be prevented without a policy, so it is made loud instead.
        # Every one of these findings exists because a scan that examined
        # nothing and a scan that found nothing must never look alike.
        acc.add(
            self._coverage_findings(
                walker.stats,
                root,
                selected,
                complete=acc.complete,
                binary=binary,
                lfs_pointers=lfs_pointers,
                examined=acc.files_scanned,
            )
        )

        # L5 - traversal limits that dropped paths without a word.
        # `max_path_depth` incremented `dirs_pruned` and `max_path_bytes` pushed
        # the path into `stats.errors`; neither reached a finding, so both were
        # silent skips against the limits module's own invariant that reaching a
        # limit is never one.
        #
        # Only the second half landed. `dirs_pruned` is shared with
        # `node_modules` and every configured exclusion, so a depth cut stayed
        # invisible: a payload under seventy directories gave `files_scanned:
        # 1`, `complete: true`, no findings and exit 0. The walker now records
        # those paths separately, and this is where they are said out loud.
        if walker.stats.too_deep:
            sample = ", ".join(walker.stats.too_deep[:5])
            more = (
                f" and {len(walker.stats.too_deep) - 5} more"
                if len(walker.stats.too_deep) > 5
                else ""
            )
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.WALK.TOO_DEEP",
                    message=(
                        f"{len(walker.stats.too_deep)} directory tree(s) went deeper than "
                        f"the configured limit of {self.config.limits.max_path_depth} and "
                        f"everything below them was not examined: {sample}{more}."
                    ),
                    remediation=(
                        "Raise scan.limits.max_path_depth, or scan the deep tree "
                        "directly. Nothing under the cut was read, so nothing under "
                        "it was found clean -- and making a tree deep is the "
                        "cheapest way to put a file out of a scanner's reach."
                    ),
                )
            )
            acc.complete = False

        if walker.stats.errors:
            sample = ", ".join(path for path, _ in walker.stats.errors[:5])
            more = (
                f" and {len(walker.stats.errors) - 5} more" if len(walker.stats.errors) > 5 else ""
            )
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.WALK.ERROR",
                    message=(
                        f"{len(walker.stats.errors)} path(s) could not be traversed and were "
                        f"not examined: {sample}{more}."
                    ),
                    remediation=(
                        "Check permissions and path lengths. A path the walker could "
                        "not reach is not a path that was found clean."
                    ),
                    severity=Severity.MEDIUM,
                )
            )
            acc.complete = False

        for group, name, provider in self.shadowed:
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.PLUGIN.SHADOWED",
                    category=Category.POLICY,
                    severity=Severity.HIGH,
                    message=(
                        f"The package {provider!r} registers {name!r} in {group}, which "
                        f"is the name of a built-in. It was not loaded; the built-in "
                        f"ran. A package that can replace a detector can disable it."
                    ),
                    remediation=(
                        "Uninstall the package, or report it if you did not install it "
                        "deliberately."
                    ),
                )
            )

        # Directories the built-in prune list skipped. Reported, because they
        # were not: a file never walked was indistinguishable in the output from
        # one scanned and found clean, which is the failure this whole file
        # exists to prevent, applied to the tool's own defaults.
        #
        # `node_modules` is why this matters rather than being tidy. It is where
        # an installed malicious dependency's code and lifecycle scripts live,
        # so a scan run after `npm install` could not see the dependency code it
        # was there to examine and said nothing about that.
        if walker.stats.pruned_dirs:
            names = sorted(walker.stats.pruned_dirs)
            sample = ", ".join(names[:6])
            more = f" and {len(names) - 6} more" if len(names) > 6 else ""
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.COVERAGE.PRUNED",
                    category=Category.POLICY,
                    severity=Severity.LOW,
                    message=(
                        f"{len(names)} director(ies) were skipped by the built-in prune "
                        f"list and not examined: {sample}{more}. These normally hold "
                        f"build output or an installed dependency tree, which is "
                        f"reproducible from the manifests that were scanned -- but "
                        f"installed dependency code is also where a malicious package's "
                        f"payload actually runs from."
                    ),
                    remediation=(
                        "Pass --include with a pattern covering the directory to scan "
                        "it, for example --include 'node_modules/**'."
                    ),
                )
            )
            # An installed dependency tree or an editor execution vector was
            # skipped, so code that runs was not read. A default scan still only
            # carries the low note above, but the result is marked incomplete so
            # `--fail-on-incomplete` fails on it -- the same stance the walker
            # takes toward an archive pruned past its depth limit, applied to
            # the directory where an installed malicious package's payload runs.
            skipped_code = set(walker.stats.pruned_dirs) & set(INSTALLED_CODE_PRUNE_DIRS)
            # A narrowed scan (`--staged`, `--tracked`, `--git-diff`) still walks the working
            # tree once, for the repository inventory, and that walk prunes `node_modules/` on
            # every developer machine. Marking the scan incomplete for it failed a pre-commit
            # hook under any policy with `fail_on_incomplete` - on every commit, for a directory
            # holding nothing the commit contained. What decides it for a narrowed scan is
            # whether a path it was ASKED to read lies under a pruned directory.
            narrowed_to: frozenset[str] | None = getattr(self.source, "selected_paths", None)
            if narrowed_to is not None:
                skipped_code = {
                    name
                    for name in skipped_code
                    if any(name in path.split("/")[:-1] for path in narrowed_to)
                }
            if skipped_code:
                acc.complete = False

        # An exclusion matching nothing is either a mistake or a hole held open
        # for a file that does not exist yet. Both are worth surfacing: commit a
        # file at that path and it would be skipped by the very check meant to
        # examine it.
        for pattern in walker.stats.unmatched_patterns:
            acc.append(
                Engine._operational(
                    path=pattern,
                    rule_id="POLICY.EXCLUDE.UNMATCHED",
                    category=Category.POLICY,
                    severity=Severity.LOW,
                    message=(
                        f"Exclusion pattern {pattern!r} matched nothing. An exclusion "
                        f"for a path that does not exist silently skips any file later "
                        f"committed there."
                    ),
                    remediation="Remove the pattern, or correct it to match its intended path.",
                )
            )

    def _inspect_file(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        acc: _Accumulator,
        detectors: list[Detector],
        signature: str,
    ) -> list[Finding]:
        """Run every file detector over one unit, via the cache.

        The cache is keyed on content plus everything that could change a
        finding, so a hit is provably identical to a cold run. A test asserts
        that equivalence rather than assuming it, because a stale cached "clean"
        is a false negative and false negatives are the failure that matters.
        """
        key = self._cache_key(unit, ctx, signature)

        cached = self.cache.get(key)
        if cached is not None:
            return list(cached)

        produced: list[Finding] = []
        budget = self.config.limits.per_file_timeout
        # `perf_counter`, not `monotonic`. Windows' monotonic clock ticks about
        # every 15 milliseconds, so a per-file budget smaller than one tick
        # measured zero elapsed time and never tripped -- the same coarse-clock
        # failure that made `--timeout 0` a no-op there. perf_counter is the
        # high-resolution timer and is what a sub-second budget needs.
        started = time.perf_counter()
        skipped: list[str] = []

        for detector in detectors:
            # Checked between detectors rather than inside one. Python's `re`
            # cannot be interrupted mid-match -- a single call holds the
            # interpreter until it returns -- so nothing in this process can
            # bound one pathological regex. What this does bound is
            # accumulation: fifty detectors and several hundred rules over a
            # very large file. The single-regex case is prevented at load time
            # instead, by PatternCompiler rejecting the shapes that backtrack.
            #
            # Stating the division plainly because the previous docstring did
            # not: it named this timeout as the backstop for catastrophic
            # regexes, the timeout was never implemented, and had it been it
            # could not have stopped the case it was named for.
            #
            # The budget never cuts the detectors that find malware and secrets. It did, and that
            # was a way to hide a payload: pad a file with near-miss credentials so an earlier
            # detector spends the budget, and `capability` never ran on it -- an INFO note and a
            # passing scan. Those detectors' patterns are validated linear at load and the file is
            # capped in size, so their cost is bounded without the budget; the total timeout still
            # ends the scan. What the budget cuts now is everything else, and it says which.
            if (
                budget > 0
                and time.perf_counter() - started >= budget
                and detector.id not in ALWAYS_RUN
            ):
                skipped.append(detector.id)
                continue

            produced.extend(self._run(detector, unit, ctx, acc))

        if skipped:
            acc.complete = False
            produced.append(
                Engine._operational(
                    path=unit.path,
                    rule_id="OPERATIONAL.FILE.TIMEOUT",
                    message=(
                        f"This file exceeded its {budget:.0f}s budget, so these detectors did not "
                        f"run on it: {', '.join(skipped)}. The malware, obfuscation, secret and "
                        f"binary detectors ran in full."
                    ),
                    remediation=(
                        "Raise limits.per_file_timeout, or exclude the file if it "
                        "is generated output rather than source."
                    ),
                )
            )
            # Not cached below, because acc.complete is now False.
            return produced

        # Every finding carries the hash of the file it came from, recorded once here
        # rather than in each of eleven detectors. `_collapse_repeats` is the only
        # reader: it is what lets "the same credential in 179 directories" be told from
        # "179 files that happen to start with the same RSA header".
        produced = [
            f.with_file_hash(unit.content.sha256) if f.location.path == unit.path else f
            for f in produced
        ]

        # Only a complete result is cached. Caching the output of a run that hit
        # a limit would make the degradation permanent and invisible.
        if acc.complete:
            self.cache.put(key, produced)

        return produced

    def _scan_parallel(
        self,
        units: list[FileUnit],
        root: Path,
        ctx: ScanContext,
        acc: _Accumulator,
        detectors: list[Detector],
        signature: str,
        *,
        carry_content: bool = False,
    ) -> list[Finding]:
        """Inspect files across a worker pool.

        The cache is consulted in this process first, so only genuine misses are
        distributed. A warm scan therefore does almost no cross-process work,
        which is the case a commit-time hook actually hits.

        A pool that cannot start falls back to serial execution. On a platform
        where processes cannot be spawned, a slower scan is the correct outcome;
        a failed one is not.
        """
        by_path = {unit.path: unit for unit in units}
        pending: list[WorkItem] = []
        results: list[Finding] = []

        for index, unit in enumerate(units):
            key = self._cache_key(unit, ctx, signature)
            cached = self.cache.get(key)
            if cached is not None:
                results.extend(cached)
                # A cache hit is a file accounted for. Counting only the misses
                # made a warm scan appear to stall at zero and then finish.
                self.progress.advance(unit.path)
            else:
                # The parent's content hash travels with the work item, so the
                # worker can tell whether it read the same bytes -- and, for a
                # source the worker must not re-read, the bytes themselves.
                pending.append(
                    (
                        index,
                        unit.path,
                        len(unit.content.raw),
                        unit.content.sha256,
                        # An archive member has no path on disk to re-read.
                        unit.content.raw if carry_content or "!" in unit.path else None,
                    )
                )

        if not pending:
            return results

        def report(indices: Sequence[int]) -> None:
            # Called as each batch's results arrive, so the count moves while
            # the pool is still working. Advancing after `run` returned meant a
            # parallel scan sat at 0 for its whole duration and then jumped to
            # complete, which reads exactly like the hang it exists to rule out.
            for index in indices:
                self.progress.advance(units[index].path)

        produced = ParallelScanner.run(
            config=self.config,
            root=str(root),
            files=pending,
            workers=ParallelScanner.worker_count(
                self.config.limits.max_workers, len(pending), sum(item[2] for item in pending)
            ),
            # The set the parent already filtered. Without it the worker ran
            # every detector it could find, and a scan's findings depended on
            # the machine's core count.
            detector_ids=[getattr(d, "id", "") for d in detectors],
            # The parent already walked the tree. Sending the result costs one
            # pickle; recomputing it costs a full traversal per worker.
            inventory=ctx.repository,
            # And the parts of the context the inventory cannot produce: which
            # FILES an install hook runs, and the import closure around them. A
            # worker rebuilding the context from the inventory alone knows that
            # `package.json` declares a `postinstall` and not that it runs
            # `scripts/setup.js`, so every composite gated on
            # `ctx.in_install_hook` was silently off in parallel.
            install_hook_paths=ctx.install_hook_paths,
            ci_hook_paths=ctx.ci_hook_paths,
            # And which bodies inside that closure the hooks never reach, for
            # the same reason: a worker cannot derive it, and one that had the
            # paths without it would apply install-time context more widely than
            # the parent does.
            install_deferred_lines=ctx.install_deferred_lines,
            # An image's members are judged as an image's: a binary there is what it ships.
            image=ctx.image,
            install_entry_paths=ctx.install_entry_paths,
            consumer_install_paths=ctx.consumer_install_paths,
            on_batch=report,
        )

        if produced is None:
            # The pool did not run. Fall back rather than lose coverage. `None`
            # rather than an empty list, so a pool that ran and legitimately
            # found nothing is not re-scanned from scratch.
            for _index, path, _size, _digest, _carried in pending:
                unit = by_path[path]
                results.extend(self._inspect_file(unit, ctx, acc, detectors, signature))
                self.progress.advance(unit.path)
            return results

        for index, findings, trusted in produced:
            unit = units[index]
            results.extend(findings)
            if not trusted:
                # The worker could not read the file, or read different bytes
                # than the parent hashed. Reported exactly as the serial path
                # reports an unreadable file, and never cached: storing it would
                # file a result under a key describing content the result was
                # not produced from.
                acc.complete = False
                results.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.FILE.UNREADABLE",
                        message=(
                            "A worker could not read this file, or read different "
                            "content than the scan had already hashed, so its checks "
                            "did not run on the content being reported."
                        ),
                        remediation=(
                            "Re-run the scan on a tree nothing else is writing to, or pass -j 1."
                        ),
                    )
                )
                continue
            if acc.complete:
                self.cache.put(self._cache_key(unit, ctx, signature), findings)

        return results

    def _cache_key(self, unit: FileUnit, ctx: ScanContext, signature: str) -> CacheKey:
        return CacheKey(
            content_hash=unit.content.sha256,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
            detector_signature=signature,
            path=unit.path,
            in_install_hook=ctx.in_install_hook(unit.path),
            language=unit.language or "",
        )

    # -- Dependency graph ------------------------------------------------

    @staticmethod
    def _author_time_ceiling(findings: list[Finding], units: list[FileUnit]) -> list[Finding]:
        """Findings in files a published package carries but nothing installing it runs.

        An sdist ships its maintainers' CI workflows, Makefile and Dockerfile, and a Python
        package with a JavaScript front end ships that front end's `package.json`; pip runs
        none of them. psutil's Makefile pipes a download into Python, jupyterlab's
        `package.json` declares npm lifecycle scripts, mcp's `.github/workflows/claude.yml`
        hands an issue to an agent -- each true of the repository, and none of it reaching a
        machine that runs `pip install`. Reported, below the gate. A MALICIOUS finding is never
        lowered.
        """
        npm_distribution = any(
            unit.path.rpartition("!")[2] == "package/package.json" for unit in units
        )
        out: list[Finding] = []
        for finding in findings:
            member = finding.location.path.rpartition("!")[2]
            name = ContainerPaths.basename(member)
            other_ecosystem = (name == "package.json" and not npm_distribution) or (
                name in ("setup.py", "pyproject.toml") and npm_distribution
            )
            author_time = (
                other_ecosystem
                or name.lower().endswith(SHIPPED_DOCUMENTS)
                or (name.lower().endswith(COMPILED_SOURCE) and name != "build.rs")
                or member.startswith(AUTHOR_TIME_PREFIXES)
                or f"/{member}".find("/.github/") >= 0
                or name in AUTHOR_TIME_FILENAMES
                or name.startswith(("Dockerfile", "Containerfile"))
                or name.endswith((".mk", ".dockerfile"))
            )
            if (
                author_time
                and finding.category is not Category.MALICIOUS
                and finding.severity > Severity.MEDIUM
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " This file ships in the published package but is not run by installing it,"
                    " so it is reported below the gate.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _is_package_distribution(units: list[FileUnit]) -> bool:
        """An sdist (`<name>-<version>/PKG-INFO`), a wheel (`*.dist-info/METADATA`) or an npm
        tarball (`package/package.json`), recognised by the metadata file its format requires."""
        for unit in units:
            parts = unit.path.rpartition("!")[2].split("/")
            if len(parts) == 2 and parts[1] == "PKG-INFO":
                return True
            if len(parts) == 2 and parts[0].endswith(".dist-info") and parts[1] == "METADATA":
                return True
            if parts == ["package", "package.json"]:
                return True
        return False

    def _image_inventory(self, data: bytes, acc: _Accumulator) -> Any:
        """The OS packages of a container image tarball, or None when the archive is not one.

        What could not be read is stated and marks the scan incomplete: an image whose package
        database was skipped must not read as an image with no vulnerable packages.
        """
        import tarfile

        from cordon_scanner.images import oci

        # Is it an image at all? Asked of the archive in whatever compression it uses. This was
        # asked with `mode="r:"` (uncompressed only), so every gzip tarball - every npm package,
        # every sdist - failed the OPEN, and the failure was reported as "an image whose layers could
        # not be read", marking the scan incomplete. An archive that is not a tar, or is a tar with no
        # image manifest, is simply not an image.
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                if not oci.ImageLayers.is_image(archive):
                    return None
        except (tarfile.TarError, OSError, ValueError, EOFError):
            if oci.ImageLayers.cut_short(data):
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="OPERATIONAL.IMAGE.UNREADABLE",
                        message="The target is a container image archive that ends early: its layers begin and the archive stops before its manifest, so nothing in it was inventoried.",
                        remediation="Export the image again with `docker save` or `skopeo copy ... oci-archive:` and rescan.",
                    )
                )
            return None
        try:
            inventory = oci.ImageLayers.read_image(data)
        except (tarfile.TarError, OSError, ValueError, KeyError, EOFError) as exc:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.UNREADABLE",
                    message=f"The target looks like a container image and its layers could not be read ({type(exc).__name__}), so its operating-system packages were not inventoried.",
                    remediation="Export the image again with `docker save` or `skopeo copy ... oci-archive:` and rescan.",
                )
            )
            return None
        release = inventory.release
        if inventory.packages and (release is None or release.advisory_source is None):
            inventory.problems.append(
                f"the distribution ({release.pretty_name or release.id if release else 'no os-release'}) "
                f"has no advisory source Cordon reads (OSV, or Amazon's ALAS), so its packages cannot be matched"
            )
        for problem in inventory.problems:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.PARTIAL",
                    message=f"Part of the image's operating-system inventory is missing: {problem}.",
                    remediation="Rescan an image exported without zstd compression, or check the distribution is supported.",
                )
            )
        from cordon_scanner.images.distrodb import DistroDatabase

        synced = inventory.release is not None and DistroDatabase.covers(
            inventory.release.osv_ecosystem
        )
        if inventory.packages and self.config.offline and not synced:
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.NOT_MATCHED",
                    message=(
                        f"{len(inventory.packages)} operating-system packages were inventoried and not "
                        f"matched against distribution advisories: none are synced on this machine for "
                        f"this distribution, and matching through OSV's API needs --online (it sends the "
                        f"package names and versions to OSV)."
                    ),
                    remediation=(
                        "Run `cordon-scanner advisories sync --os <family>` once (debian, ubuntu, "
                        "alpine, wolfi, chainguard, rocky, almalinux, redhat, suse, opensuse) to match "
                        "offline, or scan with --online."
                    ),
                )
            )
        return inventory

    @staticmethod
    def _report_image_contents(inventory: Any, acc: _Accumulator) -> None:
        """Say what of the image was content-scanned and what was not, and why."""
        from cordon_scanner.images.oci import OVERSIZE, OVERSIZE_STRINGS

        skipped = ", ".join(
            f"{count} ({reason})" for reason, count in sorted(inventory.skipped.items())
        )
        acc.append(
            Engine._operational(
                path=REPOSITORY_SCOPE,
                rule_id="OPERATIONAL.IMAGE.CONTENTS",
                message=(
                    f"{inventory.added_files} files the image adds beyond its distribution's packages were "
                    f"scanned"
                    + (
                        f" (and {inventory.binaries_as_strings} past the per-file limit as their "
                        f"printable strings and build metadata)"
                        if inventory.binaries_as_strings
                        else ""
                    )
                    + (
                        f", {inventory.removed_files} file(s) a later layer removed were scanned in "
                        f"the layer that holds them"
                        if inventory.removed_files
                        else ""
                    )
                    + f", and {len(inventory.language_packages)} installed language packages were "
                    f"inventoried. Not content-scanned: {skipped or 'nothing'}."
                ),
                remediation="None needed; the counts say what this scan covered.",
            )
        )
        oversize = inventory.skipped.get(OVERSIZE, 0) + inventory.skipped.get(OVERSIZE_STRINGS, 0)
        if oversize:
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.IMAGE.PARTIAL",
                    message=(
                        "Part of the image was not fully examined: "
                        + "; ".join(
                            f"{inventory.skipped[reason]} file(s) {reason}"
                            for reason in (OVERSIZE, OVERSIZE_STRINGS)
                            if inventory.skipped.get(reason)
                        )
                        + "."
                    ),
                    remediation="Raise limits.max_file_bytes to read them.",
                )
            )

    def _sbom_dependencies(
        self, units: list[FileUnit], acc: _Accumulator
    ) -> tuple[Dependency, ...]:
        """The components of a CycloneDX or SPDX document, validated and attributed to it."""
        from cordon_scanner.core.sbom_ingest import SbomDocument, SbomInventory

        out: list[Dependency] = []
        self._sbom_listed = []
        for unit in units:
            data, unreadable = SbomDocument.recognise(unit.content.text, unit.path)
            if unreadable:
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.SBOM.INVALID",
                        message=f"This file is named or shaped as a bill of materials and was not read: {unreadable}. Nothing from it is in the inventory.",
                        remediation="Regenerate the document with its tool, or validate it against the CycloneDX or SPDX schema.",
                        severity=Severity.MEDIUM,
                    )
                )
                continue
            if data is None:
                continue
            reading = SbomDocument.read(data)
            for problem in reading.problems[:20]:
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.SBOM.INVALID",
                        message=f"Part of this bill of materials could not be believed: {problem}. What it says there was not read into the inventory.",
                        remediation="Regenerate the document with its tool, or validate it against the CycloneDX or SPDX schema.",
                        severity=Severity.MEDIUM,
                    )
                )
            if len(reading.problems) > 20:
                acc.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.SBOM.INVALID",
                        message=f"{len(reading.problems) - 20} further problems in this bill of materials were not listed.",
                        remediation="Regenerate the document with its tool.",
                        severity=Severity.MEDIUM,
                    )
                )
            records = SbomInventory.dependencies(unit.path, reading)
            out.extend(records)
            by_key = {
                component.key: record
                for component, record in zip(reading.components, records, strict=True)
            }
            for listed in reading.vulnerabilities:
                for key in listed.affects:
                    record = by_key.get(key)
                    if record is not None:
                        self._sbom_listed.append(
                            (
                                unit.path,
                                listed,
                                record.purl,
                                record.name,
                                record.version,
                                reading.tool,
                            )
                        )
        return tuple(out)

    def _sbom_listed_findings(self, findings: Sequence[Finding], ctx: ScanContext) -> list[Finding]:
        """What an ingested SBOM itself lists as affecting its components, where the scan's own
        advisory matching did not already say so. A listed vulnerability the document rules out
        is not applied: a scan target cannot vouch for its own vulnerabilities (`--vex` can)."""
        from cordon_scanner.core.vex import RULED_OUT, VexDocuments

        if not self._sbom_listed:
            return []
        known: dict[str, set[str]] = {}
        for finding in findings:
            if finding.category is Category.VULNERABLE and finding.location.package:
                known.setdefault(finding.location.package.split("?", 1)[0].lower(), set()).update(
                    VexDocuments.identifiers_of(finding)
                )
        out: list[Finding] = []
        ruled_out: dict[str, int] = {}
        seen: set[tuple[str, str]] = set()
        for path, listed, purl, name, version, tool in self._sbom_listed:
            if listed.state in RULED_OUT:
                ruled_out[path] = ruled_out.get(path, 0) + 1
                continue
            names = {listed.identifier, *listed.aliases}
            if (
                names & known.get(purl.split("?", 1)[0].lower(), set())
                or (purl, listed.identifier) in seen
            ):
                continue
            seen.add((purl, listed.identifier))
            severity = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }.get(listed.severity or "", Severity.MEDIUM)
            finding = Engine._operational(
                path=path,
                rule_id="VULNERABLE.SBOM.LISTED.001",
                message=(
                    f"{name} {version or ''} is listed in {path} as affected by {listed.identifier}"
                    + (f" ({listed.state})" if listed.state else "")
                    + f", by {tool}. The advisory data this scan matched against does not name it for this "
                    f"version, so it rests on the document's word."
                ),
                remediation="Look the advisory up and upgrade past it, or record why it does not apply as a VEX statement.",
                category=Category.VULNERABLE,
                severity=severity,
            )
            out.append(
                replace(
                    finding,
                    location=replace(finding.location, package=purl),
                    confidence=Confidence.MEDIUM,
                    risk=ctx.scorer.score(severity, Confidence.MEDIUM),
                    detector="sbom",
                    references=(listed.reference,) if listed.reference else (),
                )
            )
        for path, count in sorted(ruled_out.items()):
            out.append(
                Engine._operational(
                    path=path,
                    rule_id="OPERATIONAL.SBOM.VEX_NOT_APPLIED",
                    message=(
                        f"{path} rules out {count} vulnerabilit{'y' if count == 1 else 'ies'} for its own components. A scan "
                        f"target cannot vouch for its own vulnerabilities, so none was applied; the scan's own matching stands."
                    ),
                    remediation="Pass the document with --vex to apply its statements, if its author is trusted to make them.",
                )
            )
        return out

    @staticmethod
    def _image_dependencies(inventory: Any) -> tuple[Dependency, ...]:
        from cordon_scanner.core.inventory import NAMED_BY_FILE
        from cordon_scanner.images.packages import OsPackage

        where = OsPackage.DATABASE
        languages = tuple(
            Dependency(
                purl=package.purl,
                ecosystem=package.ecosystem,
                name=package.name,
                version=package.version,
                direct=True,
                declared_in=package.path,
                # The checksum the build recorded where it recorded one (Go). Otherwise these are
                # bytes already installed in the image, not something still to be fetched whose
                # hash could be missing -- and never `local`, which would hide their advisories.
                integrity=package.integrity or "installed-in-image",
                # A binary's architecture and whether it is signed, where it came from one.
                platform=package.platform,
                resolved_from=NAMED_BY_FILE if package.named_by_file else None,
            )
            for package in inventory.language_packages
        )
        from cordon_scanner.images.packages import PackageGraph

        # The installed graph: what each package requires, from the asked-for ones down. Each
        # manager's packages are their own graph -- an image holds one, but nothing assumes it.
        operating_system: list[Dependency] = []
        for manager in OsPackage.MANAGERS:
            packages = [p for p in inventory.packages if p.manager == manager]
            if not packages:
                continue
            edges = PackageGraph.edges(packages)
            direct = PackageGraph.direct(packages, edges)
            depth = {index: 0 for index, asked in enumerate(direct) if asked}
            parents: dict[int, set[str]] = {index: set() for index in range(len(packages))}
            frontier = list(depth)
            while frontier:
                following: list[int] = []
                for index in frontier:
                    for child in edges[index]:
                        parents[child].add(packages[index].name)
                        if child not in depth:
                            depth[child] = depth[index] + 1
                            following.append(child)
                frontier = following
            for index, package in enumerate(packages):
                operating_system.append(
                    Dependency(
                        purl=package.purl(inventory.release),
                        ecosystem=OsPackage.PURL_TYPE[manager],
                        name=package.name,
                        version=package.version,
                        direct=direct[index],
                        # Installed automatically and required by nothing now (what `apt
                        # autoremove` would take): a dependency of nothing in the graph.
                        depth=depth.get(index, 1),
                        parents=tuple(sorted(parents[index])),
                        declared_in=where[manager],
                    )
                )
        identity = inventory.identity
        base: tuple[Dependency, ...] = ()
        if identity.base_name:
            from cordon_scanner.ecosystems.image import ImageReference

            reference = ImageReference.parse(identity.base_name)
            if reference is not None:
                version = reference.tag
                digest = identity.base_digest or reference.digest
                base = (
                    Dependency(
                        purl=f"pkg:docker/{reference.familiar}"
                        + (f"@{version}" if version else ""),
                        ecosystem="image",
                        name=reference.familiar,
                        version=version,
                        direct=True,
                        integrity=digest,
                        resolved_from=f"registry:{reference.registry}"
                        if reference.registry
                        else None,
                        declared_in="image-config/labels",
                        declared_spec=version or "",
                    ),
                )
        return base + languages + tuple(operating_system)

    def _build_graph(self, units: list[FileUnit], acc: _Accumulator) -> tuple[Dependency, ...]:
        """Build the resolved graph from lockfiles.

        Never by invoking the package manager and never over the network (C2,
        C4). Running the ecosystem's own resolver would execute untrusted
        tooling against attacker-controlled metadata inside the tool whose whole
        purpose is avoiding that, and it would make results non-reproducible
        because a resolver consults a live registry.
        """
        Engine._unread_dependency_files(units, acc)
        collected: list[Dependency] = []
        companions: list[tuple[str | None, str, Any, LockGraph]] = []
        completing: set[tuple[str | None, str, str]] = set()
        fragments: dict[tuple[str, str], tuple[Any, list[tuple[LockEntry, str]]]] = {}
        # `(member directory, ecosystem) -> the lockfile's directory`: a workspace member's
        # manifest is resolved by the root lockfile, so it is joined to that graph, not graphed
        # again on its own (which put a second, unresolved copy of each of its dependencies in).
        workspace_members: dict[tuple[str, str], str | None] = {}
        for unit in units:
            if "!" in unit.path and not self._scanning_archive:
                # A lockfile inside a vendored archive describes that artefact's own
                # build, not what this project installs. Its members are scanned for
                # content; they do not become this project's dependency graph.
                continue
            ecosystem_id = EcosystemRegistry.lockfile_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            # Contained. `Engine._run` exists so that "a detector that raises
            # must not abort the scan", and this call site and the manifest one
            # below bypassed it and called an ecosystem parser straight from
            # `scan()`. `inventory` wraps the identical call, so the
            # inconsistency sat within one file: a parser raising on a crafted
            # lockfile terminated the whole scan with exit 2, which reads as
            # "the scanner broke" and gets a pipeline to skip the step.
            try:
                graph = ecosystem.parse_lockfile(unit.content)
            except Exception as exc:
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.PARSER.FAILED",
                        message=(
                            f"The {ecosystem_id} lockfile parser failed on this file, so "
                            f"its dependencies are not in the graph: {type(exc).__name__}"
                        ),
                        remediation="Report this with the file that triggered it.",
                        severity=Severity.MEDIUM,
                    )
                )
                continue
            if graph.parse_error or not graph.entries:
                continue
            project = unit.path.rpartition("/")[0]
            # `.mvn/checksums/`, `gradle/verification-metadata.xml`, `gradle/dependency-locks/`:
            # files that belong to the project directories above them.
            for _ in range(max(0, min(graph.owner_levels, 8))):
                project = project.rpartition("/")[0]
            if graph.fragment:
                pieces = fragments.setdefault((project, ecosystem_id), (ecosystem, []))[1]
                pieces.extend((entry, unit.path) for entry in graph.entries)
                continue
            if graph.completed_by_companion:
                completing.add((project or None, ecosystem_id, unit.path))
            if graph.companion:
                # `go.sum`, `vendor/modules.txt`: facts about the resolution beside them, applied
                # once every resolving file has been read. `vendor/` belongs to its parent module.
                owner = (
                    project.rpartition("/")[0]
                    if project.endswith("vendor") and not graph.owner_levels
                    else project
                )
                companions.append((owner or None, ecosystem_id, ecosystem, graph))
                continue
            for member in graph.workspaces:
                if not isinstance(member, str) or not member:
                    continue  # a parser's mistake must not end the scan
                joined = posixpath.normpath(posixpath.join(project, member) if project else member)
                if joined not in (".", "") and not joined.startswith(".."):
                    workspace_members[(joined, ecosystem_id)] = project or None
            collected.extend(
                replace(dependency, declared_in=unit.path)
                for dependency in ecosystem.to_dependencies(graph, project=project or None)
            )

            if len(collected) > self.config.limits.max_dependencies:
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.GRAPH.LIMIT",
                        message=(
                            f"The dependency graph exceeded "
                            f"{self.config.limits.max_dependencies} entries and was "
                            f"truncated. Dependency analysis is partial."
                        ),
                        remediation="Raise limits.max_dependencies, or scan projects separately.",
                    )
                )
                break

        for (project, ecosystem_id), (ecosystem, pieces) in sorted(
            fragments.items(), key=lambda item: item[0]
        ):
            # The pieces of one installed tree, joined: an edge in one keg's receipt reaches the
            # keg it names. Each record keeps the file that holds it as its location.
            from cordon_scanner.core.inventory import DependencyRecords

            where = {(entry.name, entry.version): path for entry, path in pieces}
            merged_graph = LockGraph(
                path=pieces[0][1],
                ecosystem=ecosystem_id,
                entries=tuple(entry for entry, _ in pieces),
            )
            merged = tuple(ecosystem.to_dependencies(merged_graph, project=project or None))
            chains = DependencyRecords._paths(merged)
            collected.extend(
                replace(
                    dependency,
                    declared_in=where.get(
                        (dependency.name, dependency.version or ""), pieces[0][1]
                    ),
                    dependency_path=chains.get(id(dependency), (dependency.name,)),
                )
                for dependency in merged
            )

        # Per project AND ecosystem. A lockfile resolves its own ecosystem's
        # manifests and says nothing about anyone else's, so a `requirements.txt`
        # cannot stand in for the `conanfile.txt` beside it. Keyed per path
        # alone, it did, and those dependencies left the graph entirely.
        collected = Engine._apply_companions(collected, companions)
        collected.extend(Engine._companion_completions(collected, companions, completing))
        # A resolved entry naming a package this repository defines, with no registry hash of
        # its own -- `app` depending on `core` in one Maven reactor -- is built from that module's
        # source here, not downloaded. An entry the registry hashed is left alone: that is a
        # published package, whatever a local directory happens to be called.
        defined = Engine._workspace_members(units)
        if defined:
            collected = [
                replace(d, local=True)
                if not d.local and not d.integrity and Engine._defined_member(d, defined)
                else d
                for d in collected
            ]
        workspace_members.update(Engine._members_by_name(units, collected, workspace_members))
        workspace_members.update(
            Engine._members_by_lock_reference(units, collected, workspace_members)
        )
        covered = {(d.project, d.ecosystem) for d in collected} | set(workspace_members)
        collected = Engine._join_manifests(units, collected, covered, workspace_members)
        collected = Engine._propagate_scopes(collected)
        # Exact pins in a build with no lockfile are completed by its companions too: Gradle's
        # verification metadata holds the hash of `guava:33.3.1-jre` whether or not the build
        # also locks.
        collected.extend(
            Engine._apply_companions(self._declared_graph(units, acc, covered=covered), companions)
        )

        # Deduplicated by project and package URL, and sorted, so the graph is deterministic
        # regardless of the order lockfiles were encountered in. Per project: two services in
        # one repository that each require the same module each depend on it, and each needs
        # its own fix -- one record for both left the second service's use out of the inventory.
        # Within a project, one record however many times the lockfile lists it.
        from cordon_scanner.ecosystems.npm import LockScopes

        unique: dict[tuple[str | None, str], Dependency] = {}
        for dependency in collected:
            key = (dependency.project, dependency.purl)
            existing = unique.get(key)
            # Keep the shallowest occurrence: depth drives the risk score, and
            # the closest path to the root is the honest one. At equal depth, the scope that
            # reaches furthest: a module on both the compile and the runtime classpath ships.
            if (
                existing is None
                or dependency.depth < existing.depth
                or (
                    dependency.depth == existing.depth
                    and LockScopes.rank(dependency.scope) < LockScopes.rank(existing.scope)
                )
            ):
                unique[key] = dependency
        resolved = list(unique.values())
        if not self.config.offline:
            resolved = Engine._resolve_maven_ranges(resolved)
        return tuple(sorted(resolved, key=lambda d: (d.purl, d.project or "")))

    #: Dependency files in a format no parser here reads, and what to supply instead. Reported,
    #: never skipped silently: a project whose only lockfile is one of these was not resolved.
    UNREAD_DEPENDENCY_FILES: ClassVar[dict[str, tuple[str, str]]] = {
        "bun.lockb": (
            "bun.lock",
            "Bun's legacy binary lockfile: an undocumented format Bun itself replaced with the "
            "text `bun.lock` in 1.2. Regenerate it with `bun install --save-text-lockfile`.",
        ),
    }

    @staticmethod
    def _unread_dependency_files(units: list[FileUnit], acc: _Accumulator) -> None:
        present = {u.path for u in units}
        for unit in units:
            name = unit.path.rpartition("/")[2]
            known = Engine.UNREAD_DEPENDENCY_FILES.get(name)
            if known is None:
                continue
            directory = unit.path.rpartition("/")[0]
            replacement, why = known
            if (f"{directory}/{replacement}" if directory else replacement) in present:
                continue  # the readable lockfile is beside it and is what was read
            acc.complete = False
            acc.append(
                Engine._operational(
                    path=unit.path,
                    rule_id="OPERATIONAL.LOCKFILE.UNSUPPORTED",
                    message=(
                        f"{name} was not read: {why} The dependencies it resolves are not in "
                        f"the graph from this file."
                    ),
                    remediation=f"Commit `{replacement}` beside it.",
                    severity=Severity.MEDIUM,
                )
            )

    @staticmethod
    def _companion_completions(
        collected: list[Dependency],
        companions: list[tuple[str | None, str, Any, LockGraph]],
        completing: set[tuple[str | None, str, str]],
    ) -> list[Dependency]:
        """The indirect modules a pre-1.17 `go.mod` leaves out, from the `go.sum` beside it: each
        module hashed and not already in the graph, at the highest version hashed (what minimal
        version selection settles on), marked indirect and declared in `go.sum`."""
        from cordon_scanner.intel.versions import Versions

        present = {(d.project, d.ecosystem, d.name) for d in collected}
        resolved = {(d.project, d.ecosystem) for d in collected}
        added: list[Dependency] = []
        for owner, ecosystem_id, ecosystem, graph in companions:
            # Go only: other ecosystems' companions (Maven checksums, Gradle verification
            # metadata) record hashes of what something else resolved, never a build of their own.
            if ecosystem_id != "gomod" or graph.path.endswith("modules.txt"):
                continue
            # Completed where the resolving file leaves indirect modules out (a pre-1.17 go.mod),
            # and where there is no resolving file at all: a go.sum on its own is then the only
            # record of the build there is.
            if (
                not any(p == owner and e == ecosystem_id for p, e, _ in completing)
                and (owner, ecosystem_id) in resolved
            ):
                continue
            highest: dict[str, LockEntry] = {}
            for entry in graph.entries:
                if (owner, ecosystem_id, entry.name) in present or not entry.version:
                    continue
                best = highest.get(entry.name)
                if (
                    best is None
                    or Versions.compare(
                        ecosystem_id, entry.version.lstrip("v"), best.version.lstrip("v")
                    )
                    > 0
                ):
                    highest[entry.name] = entry
            if not highest:
                continue
            completion = LockGraph(
                path=graph.path,
                ecosystem=ecosystem_id,
                entries=tuple(replace(e, direct=False) for _, e in sorted(highest.items())),
            )
            added.extend(
                replace(d, direct=False, depth=max(d.depth, 2))
                for d in ecosystem.to_dependencies(completion, project=owner)
            )
        return added

    @staticmethod
    def _apply_companions(
        collected: list[Dependency], companions: list[tuple[str | None, str, Any, LockGraph]]
    ) -> list[Dependency]:
        """Complete each resolved entry with what its companion files record about it: the hash
        `go.sum` holds for that exact module version, the vendored copy `vendor/modules.txt`
        lists. An entry a companion has and the resolution does not (a version `go.sum` still
        hashes but the build no longer selects) adds nothing: it is not in the build."""
        if not companions:
            return collected
        facts: dict[tuple[str | None, str, str, str], LockEntry] = {}
        projects = {d.project for d in collected}
        for owner, ecosystem_id, ecosystem, graph in companions:
            # A tree companion is applied to every project at or below its owner.
            covered = (
                [
                    p
                    for p in projects
                    if owner is None or p == owner or (p or "").startswith(f"{owner}/")
                ]
                if graph.companion_tree
                else [owner]
            )
            for project in covered:
                Engine._companion_facts(facts, project, ecosystem_id, ecosystem, graph)
        out: list[Dependency] = []
        for dependency in collected:
            ecosystem = EcosystemRegistry.get(dependency.ecosystem)
            name = ecosystem.normalize_name(dependency.name) if ecosystem else dependency.name
            fact = facts.get(
                (dependency.project, dependency.ecosystem, name, dependency.version or "")
            )
            if fact is None:
                out.append(dependency)
                continue
            out.append(
                replace(
                    dependency,
                    integrity=dependency.integrity or fact.integrity,
                    resolved_from=dependency.resolved_from
                    if dependency.resolved_from
                    and not (fact.resolved_from or "").startswith("vendored:")
                    else fact.resolved_from or dependency.resolved_from,
                )
            )
        return out

    @staticmethod
    def _companion_facts(
        facts: dict[tuple[str | None, str, str, str], LockEntry],
        project: str | None,
        ecosystem_id: str,
        ecosystem: Any,
        graph: LockGraph,
    ) -> None:
        for entry in graph.entries:
            key = (project, ecosystem_id, ecosystem.normalize_name(entry.name), entry.version)
            previous = facts.get(key)
            if previous is None:
                facts[key] = entry
            else:
                facts[key] = LockEntry(
                    name=entry.name,
                    version=entry.version,
                    integrity=previous.integrity or entry.integrity,
                    resolved_from=previous.resolved_from or entry.resolved_from,
                )

    @staticmethod
    def _members_by_lock_reference(
        units: list[FileUnit],
        collected: list[Dependency],
        known: dict[tuple[str, str], str | None],
    ) -> dict[tuple[str, str], str | None]:
        """Manifests that name the lockfile resolving them (`lockfile: "../../mix.lock"` in an
        umbrella app): members of the project that lockfile belongs to, when it was read."""
        locked = {(d.project or "", d.ecosystem) for d in collected}
        contents = {u.path: u.content for u in units}
        out: dict[tuple[str, str], str | None] = {}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
            if ecosystem is None or ecosystem_id is None:
                continue
            project = unit.path.rpartition("/")[0]
            if not project or (project, ecosystem_id) in known:
                continue
            try:
                manifest = Engine._manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: S112 - reported where the manifest is parsed for hooks
                continue
            owner = manifest.locked_by
            if owner is not None and (owner, ecosystem_id) in locked:
                out[(project, ecosystem_id)] = owner or None
        return out

    @staticmethod
    def _members_by_name(
        units: list[FileUnit],
        collected: list[Dependency],
        known: dict[tuple[str, str], str | None],
    ) -> dict[tuple[str, str], str | None]:
        """Workspace members a lockfile does not list by directory (Yarn Classic, Cargo).

        A manifest below a lockfile's directory whose own package name is one of that lockfile's
        local entries is a member it resolves."""
        local: dict[tuple[str | None, str], set[str]] = {}
        for dependency in collected:
            if dependency.local:
                local.setdefault((dependency.project, dependency.ecosystem), set()).add(
                    dependency.name.lower()
                )
        if not local:
            return {}
        found: dict[tuple[str, str], str | None] = {}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            project = unit.path.rpartition("/")[0]
            if ecosystem_id is None or not project or (project, ecosystem_id) in known:
                continue
            for (lock_project, lock_ecosystem), names in local.items():
                if lock_ecosystem != ecosystem_id or lock_project == project:
                    continue
                if lock_project and not project.startswith(lock_project + "/"):
                    continue
                ecosystem = EcosystemRegistry.get(ecosystem_id)
                try:
                    manifest = ecosystem.parse_manifest(unit.content) if ecosystem else None
                except Exception:  # noqa: S112 - reported where the manifest is parsed for hooks
                    continue
                if manifest is not None and manifest.name and manifest.name.lower() in names:
                    found[(project, ecosystem_id)] = lock_project
                    break
        return found

    @staticmethod
    def _configured_sources(units: list[FileUnit]) -> tuple[tuple[str, str, str], ...]:
        """Every package source the scanned manifests configure, credentials removed."""
        from cordon_scanner.core.inventory import DependencySource

        found: list[tuple[str, str, str]] = []
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
            if ecosystem is None or ecosystem_id is None:
                continue
            try:
                manifest = ecosystem.parse_manifest(unit.content)
            except Exception:  # noqa: S112 - reported where the manifest is parsed for hooks
                continue
            for source in manifest.sources:
                # A URL inside the description loses its userinfo and query: a token in an
                # index URL is a credential, and the report is not where it goes.
                cleaned = re.sub(
                    r"\S+://\S+", lambda m: DependencySource.sanitise(m.group(0)) or "", source
                )
                found.append((unit.path, ecosystem_id, cleaned))
        return tuple(sorted(set(found)))

    @staticmethod
    def _declared_inside(spec: str, manifest_path: str) -> bool:
        """Whether a declaration names a path inside the scanned repository (`path:../lib`,
        `file:packages/util`): the project's own code, not a package from anywhere."""
        if not spec.startswith(("path:", "file:", "link:", "./", "../", "workspace:")):
            return False
        from cordon_scanner.detect.manifest import DeclaredSource

        return DeclaredSource.kind(spec, manifest_path) == "inside"

    @staticmethod
    def _manifest_of(ecosystem: Any, unit: FileUnit, files: Mapping[str, Any]) -> Any:
        """A manifest parsed with the rest of its build in view, where the ecosystem needs it:
        a Maven module inherits from a parent POM elsewhere in the tree, a .NET project from
        `Directory.Packages.props` above it. Other ecosystems read one file on its own."""
        in_tree = getattr(ecosystem, "parse_in_tree", None)
        if in_tree is not None:
            return in_tree(unit.content, files)
        return ecosystem.parse_manifest(unit.content)

    MAX_INCLUDE_DEPTH: ClassVar[int] = 8

    @staticmethod
    def _included(
        manifest: Any, path: str, by_path: dict[str, FileUnit], ecosystem: Any
    ) -> list[tuple[str, str, Any]]:
        """`(kind, path, manifest)` for each file a manifest includes, followed through nested
        includes, each file once, to `MAX_INCLUDE_DEPTH`. A path that leaves the scanned tree or
        is not in it is skipped (and was never going to be readable here)."""
        out: list[tuple[str, str, Any]] = []
        seen = {path}
        pending = [(kind, target, path, 0) for kind, target in getattr(manifest, "includes", ())]
        while pending:
            kind, target, origin, depth = pending.pop(0)
            directory = origin.rpartition("/")[0]
            resolved = posixpath.normpath(
                posixpath.join(directory, target) if directory else target
            )
            if resolved.startswith("..") or resolved in seen or resolved not in by_path:
                continue
            seen.add(resolved)
            parse = getattr(ecosystem, "parse_included", None)
            try:
                included = (
                    parse(by_path[resolved].content)
                    if parse
                    else ecosystem.parse_manifest(by_path[resolved].content)
                )
            except Exception:  # noqa: S112 - an unreadable include is reported where it is parsed
                continue
            out.append((kind, resolved, included))
            if depth + 1 < Engine.MAX_INCLUDE_DEPTH:
                # A constraints file's own `-r` lines are constraints too.
                pending.extend(
                    (kind if kind == "constraints" else nested_kind, nested, resolved, depth + 1)
                    for nested_kind, nested in getattr(included, "includes", ())
                )
        return out

    @staticmethod
    def _packages(dependencies: tuple[Dependency, ...]) -> tuple[Dependency, ...]:
        """The dependencies a registry could serve: not the platform requirements.

        `requires-python = ">=3.10"`, Composer's `php` and `ext-json`, Cargo's `rust-version`, a
        Dart SDK constraint: each is in the inventory, and none is a package. `python` on PyPI
        and `php` on Packagist are unrelated distributions, and a typosquat, advisory or registry
        check against them would be a claim about the wrong thing."""
        return tuple(d for d in dependencies if d.scope is not Scope.PLATFORM)

    @staticmethod
    def _override_target(selector: str) -> tuple[str | None, str | None]:
        """`(package, version selector)` an override key applies to.

        `ms`, `ms@2.0.0` (npm, pnpm), `**/ms`, `debug/ms` (Yarn resolutions: the last segment),
        `debug>ms` (pnpm's parent selector) and `@scope/pkg@^1`."""
        text = selector.strip()
        for separator in (">",):
            text = text.rpartition(separator)[2] if separator in text else text
        if "/" in text and not text.startswith("@"):
            text = text.rpartition("/")[2]
        elif text.startswith("@") and text.count("/") > 1:
            text = "/".join(text.split("/")[-2:])
        at = text.find("@", 1 if text.startswith("@") else 0)
        if at > 0:
            return text[:at] or None, text[at + 1 :] or None
        return text or None, None

    @staticmethod
    def _propagate_scopes(collected: list[Dependency]) -> list[Dependency]:
        """Carry each direct dependency's scope down to what only it brings in.

        Yarn, Bun and several other lockfiles record no scope: a package needed only by a test
        runner read as runtime. With the direct dependencies' scopes known from the manifest,
        a transitive one reached only through dev dependencies is dev, only through optional
        ones optional -- npm's own rule for its `dev` and `optional` flags."""
        from cordon_scanner.ecosystems.npm import LockScopes

        groups: dict[tuple[str | None, str], list[Dependency]] = {}
        for dependency in collected:
            groups.setdefault((dependency.declared_in, dependency.ecosystem), []).append(dependency)
        out: list[Dependency] = []
        for members in groups.values():
            # The workspace's own packages are the project, not its dependencies: a Cargo member
            # lists its dev and build dependencies as edges too, and as a runtime root it made
            # every test-only crate runtime.
            roots: dict[str, set[Scope]] = {}
            for d in members:
                if d.direct and not d.local:
                    roots.setdefault(d.name, set()).add(d.scope)
            if not roots or all(d.direct for d in members):
                out.extend(members)
                continue
            edges: dict[str, set[str]] = {}
            for dependency in members:
                for parent in dependency.parents:
                    edges.setdefault(parent, set()).add(dependency.name)
            scopes = LockScopes.propagate(roots, edges)
            for dependency in members:
                found = scopes.get(dependency.name)
                if (
                    not dependency.direct
                    and dependency.scope is Scope.RUNTIME
                    and found is not None
                    and found is not Scope.RUNTIME
                ):
                    out.append(replace(dependency, scope=found))
                else:
                    out.append(dependency)
        return out

    MAX_RANGE_LOOKUPS: ClassVar[int] = 200

    @staticmethod
    def _resolve_maven_ranges(dependencies: list[Dependency]) -> list[Dependency]:
        """A Maven or Gradle range (`[1.2,2.0)`) a pom declares with no lockfile to pin it,
        resolved online to the highest release Maven Central lists inside it -- what Maven itself
        picks -- so its advisories can be matched. Offline it stays unresolved, and says why."""
        from cordon_scanner.intel.more_registries import MoreRegistries
        from cordon_scanner.intel.ranges import VersionRanges
        from cordon_scanner.intel.registry_client import RegistryError
        from cordon_scanner.intel.versions import Versions

        listed: dict[str, list[str]] = {}
        out: list[Dependency] = []
        for dependency in dependencies:
            spec = (dependency.declared_spec or "").strip()
            if (
                dependency.ecosystem not in ("maven", "gradle")
                or dependency.version
                or spec[:1] not in ("[", "(")
                or ":" not in dependency.name
            ):
                out.append(dependency)
                continue
            if dependency.name not in listed and len(listed) < Engine.MAX_RANGE_LOOKUPS:
                try:
                    listed[dependency.name] = MoreRegistries.versions("maven", dependency.name)
                except (RegistryError, OSError, ValueError):
                    listed[dependency.name] = []
            admitted = [
                v for v in listed.get(dependency.name, []) if VersionRanges.admits("maven", spec, v)
            ]
            if not admitted:
                out.append(dependency)
                continue
            best = admitted[0]
            for candidate in admitted[1:]:
                if Versions.compare("maven", candidate, best) > 0:
                    best = candidate
            base, sep, query = dependency.purl.partition("?")
            out.append(
                replace(
                    dependency,
                    version=best,
                    purl=f"{base}@{best}" + (f"?{query}" if sep else ""),
                    resolution_note=f"the range {spec} resolved online to {best}, the highest release Maven Central lists inside it",
                )
            )
        return out

    @staticmethod
    def _join_manifests(
        units: list[FileUnit],
        collected: list[Dependency],
        covered: set[tuple[str | None, str]],
        members: dict[tuple[str, str], str | None] | None = None,
    ) -> list[Dependency]:
        """Give each locked direct dependency the manifest entry that declared it.

        A lockfile says what resolved; the manifest beside it says what was asked for -- the
        constraint, the platform conditions, the line a reviewer edits. The record carries both
        (`version_constraint` beside `resolved_version`, `manifest_location` beside
        `lockfile_location`), so a pin that has drifted from its declared range is visible.
        """
        declared: dict[tuple[str | None, str, str], tuple[str, DeclaredDependency]] = {}
        declared_from_lock: dict[tuple[str | None, str, str], bool] = {}
        shared: dict[tuple[str | None, str, str], str] = {}
        forced: dict[tuple[str | None, str, str], tuple[str, str, str | None]] = {}
        routed: dict[tuple[str | None, str], dict[str, str]] = {}
        contents = {u.path: u.content for u in units}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            project = unit.path.rpartition("/")[0] or None
            if (project, ecosystem_id) not in covered:
                continue
            if members and project is not None and (project, ecosystem_id) in members:
                project = members[(project, ecosystem_id)]
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                manifest = Engine._manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: S112 - reported where the manifest is parsed for hooks
                continue
            for shared_name, shared_spec in manifest.shared_specs.items():
                shared.setdefault(
                    (project, ecosystem_id, ecosystem.normalize_name(shared_name)), shared_spec
                )
            if manifest.source_patterns:
                routed.setdefault((project, ecosystem_id), {}).update(manifest.source_patterns)
            # A file that is also a lockfile (a pinned `requirements.txt`) is the manifest of last
            # resort: where `requirements.in` names the same package, that is what was asked for.
            is_lock = EcosystemRegistry.lockfile_ecosystem(unit.path) is not None
            for entry in manifest.dependencies:
                key = (
                    project,
                    entry.ecosystem or ecosystem_id,
                    ecosystem.normalize_name(entry.name),
                )
                if key not in declared or (not is_lock and declared_from_lock.get(key, False)):
                    declared[key] = (unit.path, entry)
                    declared_from_lock[key] = is_lock
            for selector, spec in manifest.overrides.items():
                target, selected = Engine._override_target(str(selector))
                if target:
                    forced.setdefault(
                        (project, ecosystem_id, ecosystem.normalize_name(target)),
                        (
                            f"{selector!s} = {spec!s} in {manifest.override_origin or unit.path}",
                            str(spec),
                            selected,
                        ),
                    )
        if not declared and not forced:
            return collected
        joined: list[Dependency] = []
        matched: set[tuple[str | None, str, str]] = set()
        present: set[tuple[str | None, str, str]] = set()
        # Lockfiles that say which entries are direct; for the rest (`Pipfile.lock`, `go.sum`),
        # the manifest beside them is the only record of what the project asked for.
        marked = {d.declared_in for d in collected if d.direct}
        manifested = {(k[0], k[1]) for k in declared}
        for dependency in collected:
            ecosystem = EcosystemRegistry.get(dependency.ecosystem)
            name = (
                ecosystem.normalize_name(dependency.name) if ecosystem else dependency.name.lower()
            )
            key = (dependency.project, dependency.ecosystem, name)
            present.add(key)
            override = forced.get(key)
            if override is not None and dependency.version and not dependency.forced_by:
                description, spec, selected = override
                # Forced when the override names this exact version, or applies to every
                # version and resolved to this one -- or is a range (mix's `override: true` on
                # `"~> 2.0"`), which governs whatever version the tree resolved under it.
                exact = Engine._exact_pin(spec)
                if spec.lstrip("=v") == dependency.version or (
                    selected is None
                    and (
                        exact == dependency.version
                        or (exact is None and not spec.startswith(("path:", "git")))
                    )
                ):
                    dependency = replace(dependency, forced_by=description)
            found = declared.get(key)
            if found is not None and not dependency.direct and dependency.depth > 0:
                # A second copy deeper in the tree (`debug`'s own `ms`) is not the one the
                # manifest declared; only the direct one is joined to the declaration.
                found = None
            if found is not None:
                matched.add(key)
            if found is None or dependency.manifest_path:
                if (
                    found is None
                    and dependency.declared_in not in marked
                    and (dependency.project, dependency.ecosystem) in manifested
                ):
                    # Not declared, in a lockfile that marks nothing: transitive.
                    dependency = replace(dependency, direct=False)
                joined.append(dependency)
                continue
            path, entry = found
            spec = entry.spec
            if spec == WORKSPACE_INHERITED:
                # `{ workspace = true }`: the constraint is the workspace root's.
                spec = shared.get(key, spec)
            joined.append(
                replace(
                    dependency,
                    manifest_path=path,
                    declared_spec=dependency.declared_spec or spec or None,
                    # Both are conditions on the same package: the manifest's marker (`win32`
                    # only) and the lockfile's own (`python >=3.7`).
                    platform=tuple(dict.fromkeys((*entry.platform, *dependency.platform))),
                    direct=True,
                    # What the project asked for decides a direct dependency's scope: a PDM
                    # lockfile cannot tell an optional extra from a dev group, the manifest can.
                    scope=entry.scope,
                    alias=dependency.alias or entry.alias,
                    extras=dependency.extras or entry.extras,
                    editable=dependency.editable or entry.editable,
                    exclusions=dependency.exclusions or entry.exclusions,
                    # Where the lockfile does not say where it came from (NuGet's does not), the
                    # source the project configures for it (package source mapping) does.
                    resolved_from=dependency.resolved_from or entry.source,
                )
            )
        # Declared beside a lockfile that does not resolve it: the two have drifted, and what
        # installs is whatever the range resolves to on the day. Kept in the inventory, unresolved,
        # with the reason -- dropping it hid a dependency the project really asks for.
        defined: frozenset[tuple[str, str]] | None = None
        for key, (path, entry) in sorted(
            declared.items(), key=lambda item: (str(item[0]), item[1][0])
        ):
            # Resolved anywhere in the lockfile's graph is resolved: a pip-compile output is both
            # the lockfile and, by its name, a manifest, and every pin in it is "declared".
            if key in matched or key in present:
                continue
            project, ecosystem_id, name = key
            pinned = Engine._exact_pin(entry.spec)
            implementation = EcosystemRegistry.get(ecosystem_id)
            if defined is None:
                defined = Engine._workspace_members(units)
            purl_type = implementation.purl_type if implementation else ecosystem_id
            if Engine._declared_inside(entry.spec, path) or (ecosystem_id, name) in defined:
                # Another project of this build (Gradle's `project(":lib")`), or a module this
                # repository builds (an included build substituting `shared-util`): built from
                # its source here, which no lockfile lists because nothing is fetched for it.
                joined.append(
                    Dependency(
                        purl=f"pkg:{purl_type}/{name}",
                        ecosystem=ecosystem_id,
                        name=entry.name,
                        direct=True,
                        local=True,
                        scope=entry.scope,
                        declared_spec=entry.spec,
                        project=project,
                        declared_in=path,
                        manifest_path=path,
                        platform=entry.platform,
                    )
                )
                continue
            joined.append(
                Dependency(
                    purl=f"pkg:{purl_type}/{name}"
                    + (f"@{pinned}" if pinned else "")
                    + (implementation.qualifiers(entry.platform) if implementation else ""),
                    ecosystem=ecosystem_id,
                    name=entry.name,
                    version=pinned,
                    direct=True,
                    scope=entry.scope,
                    declared_spec=entry.spec,
                    project=project,
                    declared_in=path,
                    manifest_path=path,
                    resolved_from=entry.source,
                    platform=entry.platform,
                    alias=entry.alias,
                    extras=entry.extras,
                    editable=entry.editable,
                    exclusions=entry.exclusions,
                    # A value that is no digest is never echoed: recorded as `malformed:<hash>`.
                    integrity=Coordinate.integrity(entry.integrity),
                    resolution_note=entry.note
                    or "declared in the manifest but absent from the lockfile beside it",
                )
            )
        # A local entry that no manifest declares and nothing in its lockfile depends on is a
        # root of the workspace -- the project itself (a Cargo workspace's own crate, an
        # independent monorepo member) -- not one of its dependencies. A member another member
        # depends on, or that a manifest names, is a path dependency and stays.
        if routed:
            joined = [
                replace(
                    d, resolved_from=Engine._routed_source(d.name, routed[(d.project, d.ecosystem)])
                )
                if not d.resolved_from
                and not d.local
                and (d.project, d.ecosystem) in routed
                and Engine._routed_source(d.name, routed[(d.project, d.ecosystem)])
                else d
                for d in joined
            ]
        return [d for d in joined if not (d.local and not d.parents and d.manifest_path is None)]

    @staticmethod
    def _routed_source(name: str, patterns: Mapping[str, str]) -> str | None:
        """The source a pattern routes `name` to: the longest matching pattern, `Prefix.*` or an
        exact name, as NuGet's package source mapping matches."""
        lowered = name.lower()
        best: tuple[int, str] | None = None
        for pattern, source in patterns.items():
            text = pattern.lower()
            matched = lowered == text or (text.endswith("*") and lowered.startswith(text[:-1]))
            if matched and (best is None or len(text) > best[0]):
                best = (len(text), source)
        return best[1] if best else None

    def _annotated(
        self,
        dependencies: tuple[Dependency, ...],
        findings: Iterable[Finding],
        ctx: ScanContext,
        units: list[FileUnit],
    ) -> tuple[Dependency, ...]:
        """Each dependency's shared record: its check statuses, path and locations."""
        if not dependencies:
            return dependencies
        from cordon_scanner.core.inventory import DependencyRecords, InventoryContext

        findings = tuple(findings)
        advisory = next((d for d in self.detectors if d.id == "advisory"), None)
        database = (
            getattr(advisory, "_database", None)
            if advisory is not None and self._detector_enabled(advisory, ctx)
            else None
        )
        failed = any(
            f.rule_id == "OPERATIONAL.DETECTOR.FAILED" and "'advisory'" in f.message
            for f in findings
        )
        wanted = {d.declared_in for d in dependencies} | {d.manifest_path for d in dependencies}
        texts = {u.path: u.content.text for u in units if u.path in wanted}
        return DependencyRecords.annotate(
            dependencies,
            findings,
            InventoryContext(
                advisory_database=database,
                advisory_failed=failed,
                offline=ctx.offline,
                checks=ctx.checks,
                texts=texts,
            ),
        )

    _EXACT_PIN = re.compile(r"^(?:==|=)?\s*v?(\d[A-Za-z0-9.+\-_]*)$")
    """A specification that names one version and no other.

    `==3.2`, `=1.19.0`, `4.17.15`. Not `^4.17.0`, `~=3.2`, `>=1,<2`, `1.2.*` or
    anything carrying a comparator, a comma or a wildcard -- each of those is a
    range, and which release it resolves to is the resolver's decision rather
    than the manifest's.
    """

    @staticmethod
    def _exact_pin(spec: str) -> str | None:
        """The version a specification pins to, or None if it is a range."""
        text = spec.strip().strip("'\"")
        bracketed = re.fullmatch(r"\[\s*([^,\[\]\s]{1,64})\s*\]", text)
        if bracketed:
            # `[1.2.3]`: NuGet's and Maven's notation for exactly one version.
            text = bracketed.group(1)
        if not text or any(character in text for character in "*,<>~^!| #"):
            return None
        if text.startswith("dev-") or ".x-dev" in text:
            # Composer's branch constraints (`dev-main`, `2.x-dev`): a branch, never a version.
            return None
        found = Engine._EXACT_PIN.match(text)
        return found.group(1) if found else None

    @staticmethod
    def _defined_member(dependency: Dependency, defined: frozenset[tuple[str, str]]) -> bool:
        """Whether a dependency names a module this checkout defines, by its ecosystem's own
        name normalisation."""
        ecosystem = EcosystemRegistry.get(dependency.ecosystem)
        name = ecosystem.normalize_name(dependency.name) if ecosystem else dependency.name
        return (dependency.ecosystem, name) in defined

    @staticmethod
    def _workspace_members(units: list[FileUnit]) -> frozenset[tuple[str, str]]:
        """The packages this repository itself defines, as `(ecosystem, normalized name)`.

        A manifest's own `name` outside any installed-dependency tree. A dependency on one of
        these names is resolved to the member by the workspace, not fetched from the registry.
        """
        members: set[tuple[str, str]] = set()
        contents = {u.path: u.content for u in units}
        for unit in units:
            if "node_modules/" in f"/{unit.path}" or "site-packages/" in unit.path:
                continue
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
            if (
                ecosystem is None
                or ecosystem_id is None
                or not getattr(ecosystem, "defines_members", True)
            ):
                continue
            try:
                # With the build in view: a Gradle project's name is in its settings script, a
                # Maven module's group in its parent POM.
                manifest = Engine._manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: S112 - reported where the manifest is parsed for hooks
                continue
            if manifest.name:
                members.add((ecosystem_id, ecosystem.normalize_name(manifest.name)))
        return frozenset(members)

    def _declared_graph(
        self,
        units: list[FileUnit],
        acc: _Accumulator,
        *,
        covered: set[tuple[str | None, str]],
    ) -> list[Dependency]:
        """Manifest-declared dependencies, for projects no lockfile resolved.

        A repository without a lockfile is not a repository without
        dependencies. It is the common case for a library, and it was a hole:
        the graph was built from lockfiles alone, so `lodahs` in a
        `package.json` with no `package-lock.json` produced no finding at all,
        while the identical typo beside a lockfile was reported at high. The
        check that matters most for an unpinned project was the one that did
        not run.

        These are declared, not resolved: the version is a range, nothing
        records where they would come from, and no integrity hash exists. So
        they carry `version=None` and no source, and the rules that need a
        resolved version -- advisory matching, integrity, release age -- skip
        them of their own accord rather than guessing. What does apply is
        everything about the *name*, which is what typosquatting, combosquatting
        and dependency confusion are attacks on.

        Only for a project and ecosystem a lockfile did not already cover, so a
        repository with both does not get each dependency twice in different
        states -- while a second ecosystem in the same directory, which that
        lockfile says nothing about, is still read.
        """
        collected: list[Dependency] = []
        members = Engine._workspace_members(units)
        by_path = {u.path: u for u in units}
        contents = {u.path: u.content for u in units}

        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue

            project = unit.path.rpartition("/")[0] or None
            if (project, ecosystem_id) in covered:
                continue

            try:
                manifest = Engine._manifest_of(ecosystem, unit, contents)
            except Exception:  # noqa: S112
                # Deliberately silent here, and not a swallowed failure.
                # `_manifest_hook_paths` parses the same file, under the same
                # predicate, in the same scan, and reports
                # OPERATIONAL.PARSER.FAILED for it. A second finding would say
                # nothing the first did not.
                continue

            if manifest.parse_error:
                continue

            # What the file includes: pip's `-r` adds another file's requirements to this one,
            # and `-c` pins whatever they resolve to. An included file the walk would not graph
            # on its own (`-r common.txt`) is read here; one it would is left to its own pass.
            declarations = [(unit.path, d) for d in manifest.dependencies]
            pins: dict[str, tuple[str, str]] = {}
            for kind, path, included in Engine._included(manifest, unit.path, by_path, ecosystem):
                if kind == "requirements" and EcosystemRegistry.manifest_ecosystem(path) is None:
                    declarations.extend((path, d) for d in included.dependencies)
                elif kind == "constraints":
                    for constraint in included.dependencies:
                        pin = Engine._exact_pin(constraint.spec)
                        if pin:
                            pins.setdefault(ecosystem.normalize_name(constraint.name), (pin, path))

            for source_path, declared in declarations:
                # A manifest may carry another ecosystem's packages -- conda's
                # nested `pip:` list is PyPI -- and they are graphed as what they
                # are, so the advisory and typosquat layers can reach them.
                declared_id = declared.ecosystem or ecosystem_id
                implementation = (
                    ecosystem
                    if declared_id == ecosystem_id
                    else EcosystemRegistry.get(declared_id) or ecosystem
                )
                name = implementation.normalize_name(declared.name)
                # An exact pin is a resolved version, whatever file it is
                # written in. `django==3.2` in an `environment.yml` installs
                # 3.2 and nothing else, and treating it as unresolved meant the
                # advisory layer skipped it -- in a file whose own ecosystem has
                # no advisory feed, so nothing else was going to match it
                # either. A range stays unresolved, because a range is a
                # decision the resolver has not made yet -- unless a constraints
                # file pins it, which is the resolver's own input.
                # An ecosystem whose versions are not version numbers (an image's tag) says what pins.
                pinned = getattr(implementation, "exact_pin", Engine._exact_pin)(declared.spec)
                constrained = None if pinned or declared.editable else pins.get(name)
                if constrained is not None:
                    pinned = constrained[0]
                if pinned:
                    # Bounded like every version a lockfile gives: a spec is bounded at the
                    # length of a constraint, which is longer than any real version.
                    pinned = Coordinate.token(pinned, Coordinate.MAX_VERSION) or None
                # Where the project's configuration routes the name (a vcpkg registry serving
                # `acme-*`, NuGet package source mapping), when the declaration names no source.
                routed = declared.source or (
                    Engine._routed_source(declared.name, manifest.source_patterns)
                    if manifest.source_patterns
                    else None
                )
                collected.append(
                    Dependency(
                        # The Package URL type, not the ecosystem id: a Gradle dependency is
                        # `pkg:maven/...`, a Go module `pkg:golang/...`, a gem `pkg:gem/...`.
                        purl=f"pkg:{implementation.purl_type}/{name}"
                        + (f"@{pinned}" if pinned else "")
                        + implementation.qualifiers(declared.platform),
                        ecosystem=declared_id,
                        name=declared.name,
                        version=pinned,
                        direct=True,
                        depth=0,
                        scope=declared.scope,
                        declared_spec=declared.spec,
                        project=project,
                        declared_in=source_path,
                        manifest_path=source_path,
                        resolved_from=routed,
                        integrity=Coordinate.integrity(declared.integrity),
                        resolved_by=f"the constraints file {constrained[1]}"
                        if constrained
                        else None,
                        resolution_note=declared.note,
                        exclusions=declared.exclusions,
                        platform=declared.platform,
                        alias=declared.alias,
                        extras=declared.extras,
                        editable=declared.editable,
                        # Strapi's `packages/cli/cloud` declares `"vitest-config": "5.56.0"`, and
                        # `packages/utils/vitest-config` is that package: the workspace resolves
                        # it locally. Squatters register exactly these names on the registry.
                        local=(declared_id, name) in members
                        or Engine._declared_inside(declared.spec, source_path)
                        or bool(routed and Engine._declared_inside(routed, source_path)),
                    )
                )

            if len(collected) > self.config.limits.max_dependencies:
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.GRAPH.LIMIT",
                        message=(
                            f"The dependency graph exceeded "
                            f"{self.config.limits.max_dependencies} entries and was "
                            f"truncated. Dependency analysis is partial."
                        ),
                        remediation="Raise limits.max_dependencies, or scan projects separately.",
                    )
                )
                break

        return collected

    @staticmethod
    def _hook_import_closure(units: list[FileUnit], hooks: set[str]) -> set[str]:
        """First-party Python files reachable by import from an install hook.

        Read, never executed. Only files present in this scan are followed: a
        payload inside an installed third-party package is not this repository's
        file to judge, and following imports out of the tree would make the
        closure unbounded and mostly irrelevant.
        """
        from cordon_scanner.core.closure import ImportClosure

        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if not sources:
            return set()
        return ImportClosure.resolve(hooks, sources)

    @staticmethod
    def _hook_js_closure(units: list[FileUnit], hooks: set[str]) -> set[str]:
        """First-party JavaScript files an install-hook script loads or runs.

        `require("./lib/x")`, `import ... from "./x.js"`, `import("./x")`, and a sibling named as
        `path.join(__dirname, "bun_environment.js")` -- the last is how the Shai-Hulud 2.0
        `setup_bun.js` hands its obfuscated payload to Bun. Followed transitively within the
        files of this scan, never out of it, and bounded.
        """
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith((".js", ".cjs", ".mjs")) and not unit.content.is_binary
        }
        pending = [path for path in hooks if path in sources]
        found: set[str] = set()
        while pending and len(found) < JS_CLOSURE_LIMIT:
            current = pending.pop()
            directory = current.rpartition("/")[0]
            for match in JS_LOCAL_REFERENCE.finditer(sources[current]):
                relative = match.group("rel") or match.group("sib")
                stem = posixpath.normpath(f"{directory}/{relative}" if directory else relative)
                for candidate in (
                    stem,
                    f"{stem}.js",
                    f"{stem}.cjs",
                    f"{stem}.mjs",
                    f"{stem}/index.js",
                ):
                    if candidate in sources and candidate not in found and candidate not in hooks:
                        found.add(candidate)
                        pending.append(candidate)
                        break
        return found

    @staticmethod
    def _hook_deferred_lines(
        units: list[FileUnit], hooks: set[str], entries: frozenset[str] | None = None
    ) -> frozenset[tuple[str, int, int]]:
        """Bodies inside the closure that the hooks never actually call.

        The closure answers which files run at install time. Importing a module
        runs its top level and defines its functions; it does not call them, and
        a library reached because `setup.py` reads its `__version__` is almost
        entirely functions nothing on that path calls. See
        `core.reachability.CallReachability` for what is and is not treated as
        reachable, and why every approximation there keeps the finding.
        """
        from cordon_scanner.core.reachability import CallReachability

        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if not sources:
            return frozenset()
        return CallReachability.deferred_lines(hooks, sources, entries)

    def _expand_member_units(
        self, rel_path: str, loaded: FileContent, acc: _Accumulator, deadline: float
    ) -> list[FileUnit] | None:
        """The members of an archive found during a directory scan, as units.

        A vendored `.whl`, `.jar`, `.tgz` or `.nupkg` is part of what a repository
        ships, and one reported as "not examined" let a malicious artefact pass the
        default gate. Members are expanded in memory by the same bounded reader a
        scanned archive uses, named `archive!member` exactly as they are when the
        archive is the target, and never written to disk.

        Expanded once per distinct content per scan: the same wheel vendored in ten
        places is read ten times from disk but opened once. Returns None when the
        archive was refused, so the caller reports it as unexamined rather than as
        opened.
        """
        started = time.monotonic()
        digest = loaded.sha256
        cache = self._expansions
        if digest in cache:
            members = cache[digest]
        else:
            if loaded.truncated:
                members = None
                acc.complete = False
                acc.append(
                    Engine._operational(
                        path=rel_path,
                        rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                        message=(
                            "The archive is larger than limits.max_file_bytes, so it was "
                            "read in part and could not be opened. Its contents were not "
                            "examined."
                        ),
                        remediation="Raise limits.max_file_bytes, or scan the archive directly.",
                        severity=Severity.MEDIUM,
                    )
                )
            else:
                rejected: list[tuple[str, str, str]] = []
                collected: list[tuple[str, bytes]] = []
                prefix = rel_path.rsplit("/", 1)[-1]
                try:
                    for member_path, member_data in ArchiveReader.walk_archive(
                        loaded.raw,
                        path=prefix,
                        limits=self.config.limits,
                        rejected=rejected,
                        deadline=deadline if self.config.limits.total_timeout > 0 else None,
                    ):
                        collected.append((member_path[len(prefix) :], member_data))
                    members = collected
                except ArchiveError as exc:
                    members = None
                    acc.complete = False
                    acc.append(
                        Engine._operational(
                            path=rel_path,
                            rule_id="OPERATIONAL.ARCHIVE.REJECTED",
                            message=f"The archive was refused and not scanned: {exc.message}",
                            remediation=(
                                "Treat a refused archive as unexamined. If the limits are "
                                "wrong for this input, raise them deliberately."
                            ),
                            severity=Severity.MEDIUM,
                        )
                    )
                directory = rel_path[: -len(prefix)]
                for member_path, reason, detail in rejected:
                    acc.complete = False
                    acc.append(Engine._rejected_member(directory + member_path, reason, detail))
            cache[digest] = members
            if members is not None:
                self._archive_stats[0] += 1
        self._archive_stats[2] += int((time.monotonic() - started) * 1000)
        if members is None:
            return None
        units: list[FileUnit] = []
        for suffix, data in members:
            member_path = rel_path + suffix
            content = FileContent.from_bytes(member_path, data, self.config.limits)
            units.append(
                FileUnit(content=content, language=LanguageRegistry.of_file(member_path, content))
            )
        self._archive_stats[1] += len(units)
        return units

    @staticmethod
    def _manifest_hook_paths(
        units: list[FileUnit], acc: _Accumulator | None = None
    ) -> tuple[set[str], set[str]]:
        """Paths that execute at install time, according to their manifests.

        The same packaging test the inventory applies, for the same reason and
        against the same repository: this is the SECOND place a `setup.py`
        becomes an install hook, and fixing only the first left
        `hermes_cli/subcommands/setup.py` -- an argument parser -- seeding an
        import closure of 510 files. See `Engine._hook_executes`.
        """
        paths: set[str] = set()
        consumer: set[str] = set()
        """Paths that run for whoever INSTALLS the package, which is a subset.

        See `ScanContext.consumer_install_paths`. A `setup.py` is an install hook
        because arbitrary Python runs during a build; it reaches a consumer only
        when it overrides a consumer-time command.
        """
        known = frozenset(unit.path for unit in units)
        package_directories = {
            unit.path.rpartition("/")[0]
            for unit in units
            if ContainerPaths.basename(unit.path) == "__init__.py"
        }
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None:
                continue
            if ContainerPaths.basename(unit.path) in PACKAGED_BUILD_FILENAMES and (
                unit.path.rpartition("/")[0] in package_directories
                # And the second half of the same test. Applying only the
                # package-directory half here is the mistake this function's
                # docstring already warns about, one member of the family later:
                # `test/cpp_extensions/setup.py` is a fixture pytorch's own test
                # suite compiles, and it seeded a 507-file closure over `torch`.
                # See `FIXTURE_DIRECTORIES`.
                or Engine._under_fixture_directory(unit.path)
            ):
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                manifest = ecosystem.parse_manifest(unit.content)
            except Exception as exc:
                # Same containment as the lockfile path, and reported for the
                # same reason. Catching it and moving on quietly would trade one
                # failure mode (the scan dies) for the worse one (the manifest
                # was never read and nothing says so), which is the trade this
                # whole audit is about.
                if acc is not None:
                    acc.complete = False
                    acc.append(
                        Engine._operational(
                            path=unit.path,
                            rule_id="OPERATIONAL.PARSER.FAILED",
                            message=(
                                f"The {ecosystem_id} manifest parser failed on this file, "
                                f"so its install hooks were not identified: "
                                f"{type(exc).__name__}"
                            ),
                            remediation="Report this with the file that triggered it.",
                            severity=Severity.MEDIUM,
                        )
                    )
                continue
            # Consumer-time hooks only. A `prepare` or a `prepack` runs on the author's
            # machine, not on the machine of anybody who installs the package from a
            # registry -- and marking the script it names as install-time code is what
            # put `MALWARE.ANTI_ANALYSIS.001` at critical on `n8n`'s three-line
            # `scripts/prepare.mjs`, which is the file the anti-analysis composite's own
            # comment cites as the false positive it was corrected for. See
            # `core.models.AUTHOR_TIME_HOOKS`, including what this gives up.
            #
            # The MANIFEST still counts whenever it declares any of them, because
            # `SUSPECT.INSTALL.SCRIPT.001` is about the declaration and grades itself by
            # which kind it is.
            if manifest.hooks:
                paths.add(unit.path)
                reaching = [
                    hook for hook in manifest.hooks if hook.name.lower() not in AUTHOR_TIME_HOOKS
                ]
                if reaching:
                    paths |= Engine._hook_script_paths(unit.path, reaching, known)
                consuming = [hook for hook in manifest.hooks if hook.kind == "consumerinstall"]
                if consuming:
                    consumer.add(unit.path)
                    consumer |= Engine._hook_script_paths(unit.path, consuming, known)
        return paths, consumer

    @staticmethod
    def _hook_script_paths(
        manifest_path: str, hooks: Sequence[Hook], known: frozenset[str]
    ) -> set[str]:
        r"""Files a lifecycle command runs.

        A manifest declaring `"postinstall": "node install.js"` means
        `install.js` executes at install time, but marking only the manifest
        leaves that file scored as ordinary application code. The same
        credential read and outbound request that is critical in a hook then
        reports as merely suspicious, purely because the code lives one file
        away from the declaration.

        Only paths already present in the scan are added. A command naming a
        file that is not there tells us nothing, and resolving outside the scan
        root would follow attacker-controlled text out of the tree.

        **Resolved with `posixpath`, not `os.path`.** Scan paths are POSIX
        everywhere, and `os.path.normpath` on Windows rewrites `/` as `\`: a
        `postinstall` naming `scripts/setup.js` resolved to `scripts\setup.js`,
        matched nothing in `known`, and the file was never marked as running at
        install time. Every `MALWARE.*` composite that requires install-hook
        context then downgraded to its `SUSPECT.*` counterpart -- so Windows
        got weaker findings for one of the commonest layouts there is, and
        silently, because the finding was still produced.

        Only hooks in a subdirectory were affected, which is why it survived: a
        top-level `postinstall.js` has no separator for `normpath` to rewrite,
        and that is the shape every corpus sample used.
        """
        base = PurePosixPath(manifest_path).parent
        found: set[str] = set()

        for hook in hooks:
            # `node -e "try{require('./postinstall')}catch(e){}"` runs `postinstall.js` exactly as
            # `node postinstall.js` does; core-js declares it that way.
            for required in INLINE_REQUIRE.findall(hook.command):
                stem = posixpath.normpath(str(base / required))
                for candidate in (
                    stem,
                    f"{stem}.js",
                    f"{stem}.cjs",
                    f"{stem}.mjs",
                    f"{stem}/index.js",
                ):
                    if candidate in known and not candidate.startswith(".."):
                        found.add(candidate)
                        break
            for token in re.split(r"[\s;&|]+", Engine._runs(hook.command)):
                candidate = token.strip("\"'")
                if not candidate or candidate.startswith("-"):
                    continue
                if "." not in PurePosixPath(candidate).name:
                    # No extension: a program name such as `node` or `make`,
                    # not a file in the repository.
                    continue
                resolved = posixpath.normpath(str(base / candidate))
                if resolved.startswith(".."):
                    continue
                if resolved in known:
                    found.add(resolved)

        return found

    @staticmethod
    def _runs(command: str) -> str:
        """A lifecycle command with the parts that only print stripped out.

        `NousResearch/hermes-agent` declares this `postinstall`:

            echo 'Node dependencies installed. Run: python run_agent.py --help'

        Every token of that is inside the quotes of an `echo`, and the resolver
        read `python run_agent.py` out of it and marked `run_agent.py` as a file
        that executes at install time. From there the import closure reached 510
        modules and every credential read beside an HTTPS call in the agent became
        `MALWARE.EXFIL.001` at CRITICAL -- from a help message.

        Split on the shell's own separators and drop the segments whose command is
        a printer. `sh -c "python x.py"` keeps its payload, because `sh` is not a
        printer and that shape is a real one: the distinction is the same one
        `CapabilityDetector._is_printed_text` draws inside file contents.
        """
        segments = re.split(r"(?:&&|\|\||[;&|\n])", command)
        kept = []
        for segment in segments:
            first = segment.strip().lstrip("@-").split(" ", 1)[0]
            if ContainerPaths.basename(first) in PRINTING_COMMANDS:
                continue
            kept.append(segment)
        return " ".join(kept)

    def _coverage_findings(
        self,
        stats: WalkStats,
        root: Path,
        selected: int,
        *,
        complete: bool,
        binary: Sequence[str] = (),
        lfs_pointers: Sequence[str] = (),
        examined: int = 0,
    ) -> list[Finding]:
        """Report configuration that reduced what was examined.

        None of this is prevented, because a repository has legitimate reasons
        to exclude generated directories and to turn off a detector that does
        not apply. What is guaranteed is that the reduction appears in the
        output, so a reviewer can see that a clean result was produced by not
        looking.
        """
        findings: list[Finding] = []

        # Files that exist but hold no source to examine. One aggregated finding
        # rather than one per file: a repository with four hundred icons would
        # otherwise drown the report, and a report nobody reads is the same
        # outcome as not reporting.
        #
        # Reported at INFO and not treated as incompleteness. A PNG is not a
        # degraded scan, it is a file with nothing for a source rule to match.
        # Marking every repository with an image as incomplete would make
        # `fail_on_incomplete` unusable, and an unusable control is worse than
        # an absent one.
        # Git LFS pointers, aggregated for the same reason binaries are. A repository
        # that tracks its assets through LFS has hundreds, and a checkout without LFS -
        # which is what `actions/checkout` does by default - turns every one of them
        # into a 130-byte text file naming content that is still on a server.
        #
        # Reported rather than passed over, because a file that was not examined must
        # not look like a file that was examined and found clean. Not treated as
        # incompleteness: a repository's images being absent is not a degraded scan of
        # its source, and marking it so would make `fail_on_incomplete` unusable for
        # every project that uses LFS.
        #
        # `unionlabs/union` tracks `*.png`, `*.pdf` and `*.psd`, and a shallow clone of
        # it produced 907 format-mismatch findings before this: every tracked asset
        # reported as a file contradicting its own extension.
        if lfs_pointers:
            sample = ", ".join(sorted(lfs_pointers)[:5])
            more = f" and {len(lfs_pointers) - 5} more" if len(lfs_pointers) > 5 else ""
            findings.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.FILE.LFS_POINTER",
                    severity=Severity.INFO,
                    message=(
                        f"{len(lfs_pointers)} file(s) are Git LFS pointers, so the bytes "
                        f"they name were not fetched and nothing about their content was "
                        f"examined: {sample}{more}."
                    ),
                    remediation=(
                        "Clone with LFS content if these files matter to the scan. "
                        "`actions/checkout` needs `lfs: true`, which is off by default."
                    ),
                )
            )

        if binary:
            sample = ", ".join(sorted(binary)[:5])
            more = f" and {len(binary) - 5} more" if len(binary) > 5 else ""
            findings.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="OPERATIONAL.FILE.BINARY",
                    severity=Severity.INFO,
                    message=(
                        f"{len(binary)} file(s) were not examined as source because "
                        f"they are binary artefacts: {sample}{more}."
                    ),
                    remediation=(
                        "No action needed for genuine binaries. The classification "
                        "is made from the file's extension and leading bytes, never "
                        "from its contents, so a source file cannot be excluded from "
                        "scanning by what it contains."
                    ),
                )
            )

        # Anything the *scan target's own* configuration removed, at any share.
        #
        # BROAD_EXCLUSION below only fires past 80 percent of a tree of at least
        # 25 files, which is right for "this repository excludes most of
        # itself" and useless against the actual attack: one line excluding the
        # one file that carries the finding. That produced output byte-for-byte
        # identical to a clean scan.
        #
        # HIGH, not MEDIUM, because the default gate fails at HIGH. A repository
        # removing a file from its own scan is not a note.
        if self.config.untrusted_exclusions:
            removed = {
                pattern: count
                for pattern, count in stats.excluded_by_pattern.items()
                if pattern in set(self.config.untrusted_exclusions) and count
            }
            dropped = stats.files_dropped_by_config
            if removed or dropped:
                listed = ", ".join(
                    f"{pattern!r} ({count})" for pattern, count in sorted(removed.items())
                ) or ", ".join(repr(p) for p in sorted(self.config.untrusted_exclusions))
                findings.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.TARGET_EXCLUSION",
                        category=Category.POLICY,
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration removed {dropped} "
                            f"file(s) from this scan: {listed}. A file the scan target "
                            f"excluded is a file it chose not to have examined, which "
                            f"is reported whatever the count -- one file is enough when "
                            f"it is the right one."
                        ),
                        remediation=(
                            "Confirm each pattern is intended. Exclusions an operator "
                            "needs belong on the command line or in a config passed "
                            "with --config, where they are not supplied by the thing "
                            "being scanned."
                        ),
                    )
                )

        # Nothing at all was examined, but the tree is not empty.
        #
        # The count that matters is what reached a detector and was read, not
        # what the walker selected. Those diverge whenever selected files fail
        # to load, and that gap was the whole bug: make every file in a
        # repository unreadable and each one produced an INFO note, `selected`
        # stayed at its full value, this check never fired, and the scan exited
        # 0. A repository nothing could be read from reported exactly like a
        # repository with nothing in it -- which is the one outcome this tool
        # is built to prevent.
        if examined == 0 and stats.files_seen > 0:
            # Always reported, never silent. An empty *selection* may be
            # ordinary -- an empty staged set is a normal commit -- but files
            # that were selected and then could not be read is never ordinary,
            # whatever the source, so the source's opinion only applies when it
            # selected nothing in the first place.
            unreadable = selected > 0
            normal = self.source.empty_selection_is_normal and not unreadable
            cause = (
                f"{selected} file(s) were selected and none could be read"
                if unreadable
                else (
                    f"everything was removed by configuration or by the selected "
                    f"source ({self.source.describe()})"
                )
            )
            findings.append(
                Engine._operational(
                    path=REPOSITORY_SCOPE,
                    rule_id="POLICY.COVERAGE.NOTHING_SCANNED",
                    category=Category.POLICY,
                    severity=Severity.INFO if normal else Severity.HIGH,
                    message=(
                        f"No files were examined, although {stats.files_seen} were "
                        f"present: {cause}. This result reports that nothing was "
                        f"looked at rather than that nothing was found."
                    ),
                    remediation=(
                        "Review the exclude patterns and any --staged, --tracked or "
                        "--git-diff selection, and check the permissions on the tree. "
                        "A clean scan that examined no files is not a clean scan."
                    ),
                )
            )
        elif stats.files_seen >= _BROAD_EXCLUSION_MIN_FILES:
            dropped = stats.files_dropped_by_config
            share = dropped / stats.files_seen
            # A repository excluding most of itself may be correct -- a large
            # vendored tree, a generated directory -- but it is worth stating,
            # because it is also exactly what blinding the scanner looks like.
            # The floor on tree size is there so a five-file repository with one
            # generated directory does not produce this every run; a check that
            # fires constantly on correct configuration gets excluded itself.
            if share >= _BROAD_EXCLUSION_SHARE:
                findings.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.BROAD_EXCLUSION",
                        category=Category.POLICY,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Configuration removed {dropped} of {stats.files_seen} "
                            f"files ({share:.0%}) before any check ran. That may be "
                            f"correct for a repository with a large generated or "
                            f"vendored tree, and it is also what blinding a scanner "
                            f"looks like, so it is reported either way."
                        ),
                        remediation=(
                            "Confirm the exclusions are intended. Narrow any that "
                            "cover more than the generated output they were written "
                            "for."
                        ),
                    )
                )

        # A detector turned off in a config that came from the scan target.
        if self.config.from_untrusted_source:
            disabled = sorted(name for name, on in self.config.detectors.items() if on is False)
            if disabled:
                findings.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.DETECTOR_DISABLED",
                        category=Category.POLICY,
                        # HIGH, because the default gate fails at HIGH and this
                        # was reported at MEDIUM: `detectors: {manifest: false}`
                        # in the scan target's own config made a CRITICAL
                        # finding disappear and the build pass.
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration disabled "
                            f"{len(disabled)} detector(s): {', '.join(disabled)}. "
                            f"Those checks did not run."
                        ),
                        remediation=(
                            "Confirm each is genuinely inapplicable. An organisation "
                            "policy can require detectors that a repository may not "
                            "disable."
                        ),
                    )
                )

            if self.config.disabled_rules:
                names = ", ".join(sorted(self.config.disabled_rules))
                findings.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.COVERAGE.RULE_DISABLED",
                        category=Category.POLICY,
                        severity=Severity.HIGH,
                        message=(
                            f"The repository's own configuration disabled "
                            f"{len(self.config.disabled_rules)} rule(s): {names}. "
                            f"Those checks produced nothing here whatever the code "
                            f"contains."
                        ),
                        remediation=(
                            "Confirm each is genuinely inapplicable. An organisation "
                            "policy can require rules that a repository may not "
                            "disable."
                        ),
                    )
                )

            for setting in self.config.reduced_limits:
                # An incomplete scan does not fail the build by default, and
                # that default is right: making it fatal would break pipelines
                # on the first genuinely large repository and teach people to
                # append `|| true`, which is worse than the failure it prevents.
                #
                # It is not right here. This scan is incomplete *because the
                # scan target asked for it to be*, which is not the same thing
                # as a repository that outgrew a default, so it fails.
                truncated = not complete
                findings.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id="POLICY.CONFIG.LIMIT_REDUCED",
                        category=Category.POLICY,
                        severity=Severity.HIGH if truncated else Severity.MEDIUM,
                        message=(
                            f"{setting} was lowered below the built-in default by the "
                            f"repository's own configuration, which narrows what the "
                            f"scan reaches. A lowered limit is an exclusion written in "
                            f"a form that produces no exclusion patterns to report, so "
                            f"it is reported here instead."
                            + (
                                " The scan did not finish, so this limit is what stopped it."
                                if truncated
                                else ""
                            )
                        ),
                        remediation=(
                            "Confirm the reduction is intended. If the scan is slow, "
                            "narrow it with exclusions, which are visible, rather than "
                            "with a limit, which is not."
                        ),
                    )
                )

            for setting in self.config.clamped_settings:
                # Weakening the failure gate is reported at HIGH, where the
                # default gate fails, rather than at LOW with the resource
                # limits. Raising a limit is a repository being greedy with the
                # scanning machine; emptying `fail_on` is a repository turning
                # the verdict off for every finding including MALICIOUS at
                # CRITICAL. Those are not the same act and must not read the
                # same in a report.
                gate = setting.startswith("policy.")
                blinding = setting in BLINDING_SETTINGS
                findings.append(
                    Engine._operational(
                        path=REPOSITORY_SCOPE,
                        rule_id=(
                            "POLICY.CONFIG.GATE_WEAKENED"
                            if gate or blinding
                            else "POLICY.CONFIG.CLAMPED"
                        ),
                        category=Category.POLICY,
                        severity=Severity.HIGH if gate or blinding else Severity.LOW,
                        message=(
                            (
                                f"The repository's own configuration tried to weaken the "
                                f"failure gate ({setting}) and was refused. A scan target "
                                f"cannot decide which of its own findings are allowed to "
                                f"fail the build; the built-in gate was used instead."
                            )
                            if gate
                            else (
                                f"The repository's own configuration set {setting}, which "
                                f"switches detection off or loads code into the scanner, and "
                                f"was refused. A scan target cannot choose how closely it is "
                                f"examined; the built-in behaviour was used instead."
                            )
                            if blinding
                            else (
                                f"{setting} was set by the repository's own configuration "
                                f"and reduced to the built-in default. A configuration "
                                f"file inside the scan target cannot raise a resource "
                                f"limit or add a rule pack, because both can be used "
                                f"against the machine running the scan."
                            )
                        ),
                        remediation=(
                            "Pass the value on the command line, which is operator "
                            "input, or set it in an organisation policy."
                        ),
                    )
                )

        return findings

    # -- Phase 2: execution ----------------------------------------------

    def _detector_enabled(self, detector: Detector, ctx: ScanContext) -> bool:
        if not self.config.detector_enabled(detector.id):
            return False
        if detector.requires.network and ctx.offline:
            return False
        return detector.applicable(ctx)

    def _drop_disabled(self, produced: list[Finding]) -> list[Finding]:
        """Remove findings whose rule the configuration turned off.

        Applied to every detector's output rather than inside each detector, so
        a rule declared in Python is as disableable as one declared in YAML.
        Operational findings are never dropped: they describe the scan, and a
        configuration that could silence them could hide the fact that it had
        silenced everything else.
        """
        disabled = self.config.disabled_rules
        if not disabled:
            return produced
        return [
            f
            for f in produced
            if f.category is Category.OPERATIONAL or f.always_report or f.rule_id not in disabled
        ]

    def _run(
        self, detector: Detector, unit: Unit, ctx: ScanContext, acc: _Accumulator
    ) -> list[Finding]:
        """Run one detector over one unit, containing its failures.

        A detector that raises must not abort the scan, because one broken
        detector silently reducing coverage across every file is far worse than
        one loud finding saying it broke. The scan continues and reports itself
        as incomplete.
        """
        try:
            produced = list(detector.inspect(unit, ctx))
        except Exception as exc:
            acc.complete = False
            return [
                Engine._operational(
                    path=getattr(unit, "path", "<graph>"),
                    rule_id="OPERATIONAL.DETECTOR.FAILED",
                    message=(
                        f"Detector {detector.id!r} failed on this file, so its checks "
                        f"did not run: {type(exc).__name__}: {exc}"
                    ),
                    remediation="Report this with the file that triggered it.",
                    severity=Severity.MEDIUM,
                )
            ]

        # The engine asserts that a file detector reports only about the file it
        # was given. A detector that reports about somewhere else is a bug, and
        # accepting it silently would make findings untraceable to their source.
        #
        # Graph and repository units have no single path, so the check applies
        # only where it is meaningful. Asserting `unit.path` unconditionally is
        # what made every graph detector crash the scan.
        if isinstance(unit, FileUnit):
            kept: list[Finding] = []
            stray: list[Finding] = []
            for finding in produced:
                if (
                    finding.category is not Category.OPERATIONAL
                    and finding.location.path != unit.path
                ):
                    stray.append(finding)
                else:
                    kept.append(finding)

            if stray:
                # Reported and dropped, not raised. This check sat outside the
                # `try` above, so `DetectorError` propagated out of `scan()` and
                # terminated the run -- meaning a detector that mislabelled one
                # finding killed the entire scan on the first file it touched,
                # inside the very method whose docstring says a broken detector
                # must not abort anything.
                acc.complete = False
                kept.append(
                    Engine._operational(
                        path=unit.path,
                        rule_id="OPERATIONAL.DETECTOR.STRAY_FINDING",
                        message=(
                            f"Detector {detector.id!r} reported {len(stray)} finding(s) "
                            f"about other paths while inspecting this file "
                            f"({stray[0].location.path!r}). They were discarded."
                        ),
                        remediation=(
                            "Report this. A file detector must report only about the "
                            "file it was given, or findings cannot be traced to their "
                            "source."
                        ),
                        severity=Severity.MEDIUM,
                    )
                )
            produced = kept

        # A detector that hit a ceiling of its own knows something the engine
        # cannot observe from outside: that it answered fewer questions than it
        # was asked. Reading it here keeps `complete` meaning the same thing
        # whether the coverage was lost in the walk or inside a detector.
        if any(f.degrades_coverage for f in produced):
            acc.complete = False

        return self._drop_disabled(produced)


REPOSITORY_SCOPE = "."
"""Location for a finding about the scan rather than about one file.

`Location.path` is documented as "Repository-relative, forward-slashed,
normalised. Never absolute, so that results are comparable across machines and
safe to publish", and every operational and coverage finding used the absolute
resolved root. In CI that put runner directory layouts, internal project names
and sometimes usernames into artefacts that are routinely uploaded to third
parties and attached to pull requests."""


# A scan that skipped most of the tree is worth reporting; a small repository
# with one generated directory is not. The floor keeps the check from firing on
# correct configuration, which is how a check gets turned off.
_BROAD_EXCLUSION_SHARE = 0.8
_BROAD_EXCLUSION_MIN_FILES = 25


__all__ = ["Engine"]
