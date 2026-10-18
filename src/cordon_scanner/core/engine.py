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

import base64
import binascii
import contextlib
import hashlib
import io
import json
import posixpath
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.archive.safe import ArchiveReader, Rejection
from cordon_scanner.core.cache import CacheKey, ScanCache
from cordon_scanner.core.composer_plugins import ComposerPluginHooks
from cordon_scanner.core.config import Config, Policy
from cordon_scanner.core.content import FileContent, Skipped
from cordon_scanner.core.errors import ArchiveError, SourceError
from cordon_scanner.core.inline_programs import InlinePrograms
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
from cordon_scanner.core.windows import WindowPass
from cordon_scanner.detect.agent_judge import JudgeGate
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

    from cordon_scanner.core.taxonomy import ThreatDomain
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
    """Every file's content was read: nothing refused, truncated, pruned or timed out."""
    advisory_complete: bool = True
    """Every dependency was checked against an advisory or registry source, and the threat intel
    was current. A missing feed is reported and never blocks a package for malware purposes
    (review 98, REC-5): the two halves are kept apart so the gate can tell them apart."""
    rejected_archives: set[str] = field(default_factory=set)
    """Archives already reported as read in part (`OPERATIONAL.ARCHIVE.REJECTED`), which the
    truncation notice would only repeat."""
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

ADVISORY_DETECTORS = frozenset({"advisory", "registry", "provenance", "ospackages"})
"""Detectors whose lost coverage is about what is KNOWN of a dependency (an advisory feed, a registry,
an attestation), not about content left unread."""

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
SWEPT_NOTE = "Read to its end in windows."
"""How the note for an oversized file whose windows reached its end begins (`Engine._truncated_note`)."""

NATIVE_IN_PURE_WHEEL_RULE = "SUSPECT.BINARY.NATIVE_IN_PURE_WHEEL.001"
KNOWN_MALICIOUS_RELEASE_RULE = "MALWARE.PACKAGE.KNOWN.001"
YOUNG_DEPENDENCY_RULE = "SUSPECT.RELEASE.NEW_YOUNG_DEPENDENCY.001"
REGISTRY_REVIEW_RULE = "SUSPECT.REGISTRY.REVIEW.001"
CERTIFICATE_BLOCK: Final = re.compile(
    rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]{40,20000}?)-----END CERTIFICATE-----"
)
DER_STRING: Final = re.compile(rb"[\x0c\x13\x16]([\x02-\x7f])([ -~]{2,127})")
"""A DER PrintableString, UTF8String or IA5String: tag, short length, then the text."""
TEST_IDENTITY: Final = re.compile(
    rb"(?i)testing purposes|\btest(?:ing)?\b|\bexample\b|localhost|127\.0\.0\.1|some-state|"
    rb"internet widgits|snakeoil|\bdummy\b|\bfake\b"
)
"""What a certificate made for tests calls itself; `Some-State` and `Internet Widgits Pty Ltd`
are OpenSSL's defaults for a subject nobody filled in."""
NPM_PLACEHOLDER_VERSION: Final = re.compile(r"0\.0\.\d{1,4}-security(?:\.\d{1,4})?")
"""The version npm publishes in place of a malicious package it removed."""
ARCHIVE_SLICE = 4000
"""Archive members handed to the worker pool at a time, between deadline checks."""
ARCHIVE_ESCAPE_RULE = "SUSPECT.ARCHIVE.PATH_ESCAPE.001"
ARCHIVE_NESTING_RULE = "SUSPECT.ARCHIVE.NESTING.001"
ARCHIVE_POLYGLOT_RULE = "SUSPECT.ARCHIVE.POLYGLOT.001"
ARCHIVE_LINK_TO_SECRET_RULE = "SUSPECT.ARCHIVE.LINK_TO_SECRET.001"  # noqa: S105 -- a rule id
#: A link target that is the user's or the system's secret, not the package's own file.
_SECRET_LINK_TARGET: Final = re.compile(
    r"^(?:/etc/|/proc/|/root/|/var/run/secrets/|~|\$HOME)"
    r"|/\.(?:ssh|aws|gnupg|kube|docker|azure|config/gcloud)(?:/|$)"
    r"|/\.(?:npmrc|pypirc|netrc|git-credentials|env|bash_history|zsh_history)$"
    r"|\bid_(?:rsa|ed25519|ecdsa|dsa)\b"
)
ARCHIVE_PADDED_RULE = "SUSPECT.ARCHIVE.PADDED.001"
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
        # zc.buildout's bootstrap, which a developer runs by hand to set up a checkout: it fetches
        # and runs the installer, and pip never runs it (review 98: 10 sdists blocked on it).
        # `ez_setup.py` is not here -- an old `setup.py` imports it, and then it runs at install.
        "bootstrap.py",
        "bootstrap-buildout.py",
    }
)
"""Files a published package may carry that only its maintainers' tooling runs."""

MAKEFILES = frozenset({"Makefile", "GNUmakefile", "makefile"})
MAKE_AT_INSTALL = frozenset({"cran", "hex", "rubygems", "hackage"})
"""Formats whose install can run make: R builds `src/Makefile`, Hex packages compile through
`elixir_make`, a gem's `ext/` is built by the Makefile its `extconf.rb` writes, and a cabal
package may declare `build-type: Make`. A Makefile there is install-time code, not the
maintainers'."""

HONOURED_PINS: dict[str, re.Pattern[str]] = {
    # npm installs a published package's own `npm-shrinkwrap.json` exactly as written.
    "npm": re.compile(r"(?:^|!)package/npm-shrinkwrap\.json$"),
    # Maven resolves the jar's pom, and its `<version>` is the version it fetches.
    "maven": re.compile(r"(?:^|!)META-INF/maven/[^!]+/pom\.xml$"),
    # NuGet picks the LOWEST version a dependency range allows: the `.nuspec` pin is the install.
    "nuget": re.compile(r"(?:^|!)[^/!]+\.nuspec$"),
    # Go's minimal version selection starts from the module's own `go.mod` requirements.
    "gomod": re.compile(r"(?:^|!)[^!]*@v[^/!]+/go\.mod$"),
}
"""Files inside a published package that its consumer's installer reads and obeys: what they pin
is what installing the package brings in, so they keep their rating."""

DROP_POINT_SECRETS = frozenset(
    {
        "SECRET.TELEGRAM.BOT_TOKEN.001",
        "SECRET.DISCORD.WEBHOOK.001",
        "SECRET.SLACK.WEBHOOK.001",
        "SECRET.SLACK.TOKEN.001",
        "SECRET.MICROSOFT.TEAMS_WEBHOOK.001",
    }
)
"""Tokens that are somewhere to SEND to: a bot or webhook a package posts through. In a published
package that is how stolen data leaves (`@0xme5war/apicli` 2.0.0 is blocked by its Telegram bot
token alone), not a key its publisher leaked, so it keeps its grade. 13 of 139,000 real npm and
PyPI packages are blocked by one of these alone (review 98)."""

GO_MODULE_ROOT = re.compile(r"[^@!]{1,1024}@v\d[^/@!]{0,128}/")
"""A module proxy zip's first level: every file sits under `<module path>@<version>/`."""

SHIPPED_DOCUMENTS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt")
"""Documents in a published package: pypdf ships sample forms for its own tests. Installing the
package opens none of them; a document's active content runs when a person opens it."""

STANDALONE_SCRIPTS = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".psm1", ".bat", ".cmd")
"""Scripts that run only when something starts them (`Engine._author_time_ceiling`)."""

CONDA_LINK_SCRIPT = re.compile(r"-(?:pre|post)-(?:link|unlink)\.(?:sh|bat)$")
"""conda runs a package's `bin/.<name>-post-link.sh` (and its kin) when it installs it."""

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
#: Programs whose argument is a JavaScript or TypeScript module, resolved as Node resolves one.
JS_RUNNERS = frozenset({"node", "nodejs", "tsx", "ts-node", "bun"})
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
        from cordon_scanner.detect.secrets import SourcePaths

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
            if (
                SourcePaths.is_editor_extension(path) or path in ctx.agent_run_paths
            ) and finding.message.startswith(SWEPT_NOTE):
                # An extension ships its code as one bundle, and ten or twenty megabytes is what a
                # language extension's bundle weighs; this one was read whole by the high-signal
                # sweep. An install script is kilobytes, so for one the size is still the finding.
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

    #: Names an agent host's users expect to find: the reference servers and the services the
    #: most-installed MCP servers front. A server published under one is chosen by that name.
    EXPECTED_SERVER_NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "github",
            "gitlab",
            "slack",
            "notion",
            "gmail",
            "google-drive",
            "gdrive",
            "filesystem",
            "postgres",
            "sqlite",
            "brave-search",
            "puppeteer",
            "playwright",
            "fetch",
            "memory",
            "git",
            "sentry",
            "linear",
            "jira",
            "confluence",
            "figma",
            "stripe",
            "discord",
            "telegram",
            "whatsapp",
            "outlook",
            "teams",
            "dropbox",
            "kubernetes",
            "docker",
            "openai",
            "anthropic",
            "everything",
            "sequential-thinking",
            "google-maps",
            "youtube",
            "twitter",
            "reddit",
            "spotify",
            "shopify",
            "salesforce",
            "hubspot",
            "zapier",
            "airtable",
            "mongodb",
            "mysql",
            "redis",
            "supabase",
            "firebase",
            "vercel",
            "cloudflare",
        }
    )

    @staticmethod
    def _borrowed_server_name(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """An MCP server published under a well-known service's name that its code never names.

        A chess server whose `pyproject.toml` says `name = "github"`, a Messages bridge called
        `slack`: an agent host offering "github" installs whatever answers to the name, and the
        requests meant for GitHub -- with the tokens they carry -- arrive here (review 98:
        mcp-variants' Tool Squatting servers; none of its 786 reference servers). A real GitHub
        server mentions GitHub in its code.
        """
        sources = Engine._mcp_server_sources(units)
        if not sources:
            return []
        code = [
            u.content.text
            for u in units
            if u.path.endswith((".py", ".ts", ".js", ".mjs", ".cjs"))
            and "/node_modules/" not in u.path
        ]
        out: list[Finding] = []
        for unit in units:
            name_of = unit.path.rpartition("!")[2].rpartition("/")[2]
            if name_of not in ("pyproject.toml", "package.json") or "/node_modules/" in unit.path:
                continue
            found = re.search(
                r'(?m)^name\s*=\s*["\']([^"\']+)|"name"\s*:\s*"([^"]+)"', unit.content.text
            )
            if found is None:
                continue
            bare = (found.group(1) or found.group(2)).lower().rpartition("/")[2]
            for prefix in ("mcp-server-", "server-", "mcp-"):
                bare = bare.removeprefix(prefix)
            for suffix in ("-mcp-server", "-mcp", "-server"):
                bare = bare.removesuffix(suffix)
            if bare not in Engine.EXPECTED_SERVER_NAMES:
                continue
            brand = re.compile("(?i)" + re.escape(bare).replace("\\-", "[-_ ]?"))
            if any(brand.search(text) for text in code):
                continue
            out.append(
                replace(
                    Engine._operational(
                        path=unit.path,
                        rule_id="SUSPECT.MCP.BORROWED_NAME.001",
                        message=(
                            f"This MCP server is published as {bare!r}, the name of a service its "
                            "code never mentions. An agent host offering that service installs "
                            "whatever answers to the name, and the requests meant for it -- with "
                            "the credentials they carry -- arrive here."
                        ),
                        remediation=(
                            "Install the service's own server. Check what this one does with "
                            "requests meant for the service it is named after."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.MEDIUM,
                    risk=ctx.scorer.score(Severity.HIGH, Confidence.MEDIUM),
                    detector="manifest",
                    always_report=False,
                )
            )
        return out

    @staticmethod
    def _release_identities(
        units: Sequence[FileUnit],
    ) -> tuple[list[tuple[str, str, str, str]], set[str]]:
        """(ecosystem, name, version, manifest path) for each release manifest the archive holds,
        recognised only where its format puts it (see `_known_malicious_release`); and the npm
        security-holding placeholders among them."""
        identities: list[tuple[str, str, str, str]] = []
        placeholders: set[str] = set()
        for unit in units:
            member = unit.path.rpartition("!")[2]
            parts = member.split("/")
            own = Engine._archive_release_identity(unit)
            if own is not None:
                identities.append((*own, unit.path))
                continue
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
                        if NPM_PLACEHOLDER_VERSION.fullmatch(str(document["version"])) and (
                            str(document.get("description", "")).strip().lower()
                            == "security holding package"
                        ):
                            placeholders.add(unit.path)
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
        return identities, placeholders

    _CRATE_MANIFEST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|!)(?P<name>[A-Za-z0-9_-]{1,64})-(?P<version>\d[\w.+-]{0,40})/Cargo\.toml$"
    )
    _GO_MODULE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|!)(?P<module>[^!@]{1,300})@(?P<version>v[^/!]{1,80})/go\.mod$"
    )

    @staticmethod
    def _archive_release_identity(unit: FileUnit) -> tuple[str, str, str] | None:
        """(ecosystem, name, version) when the unit is the release manifest of a published gem,
        crate or Go module zip -- recognised only where each format puts it inside its archive.

        npm, PyPI, NuGet and VS Code releases were matched against the malicious-package records
        by their own manifests; these three were not, so a `.gem` OSV records as malicious was
        judged by its code alone (review 98: 485 of 587 recovered malicious gems carry no code).
        """
        archive, bang, member = unit.path.rpartition("!")
        if not bang:
            return None
        if member == "metadata.gz" and archive.lower().endswith(".gem"):
            import gzip
            import zlib

            try:
                with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                    text = stream.read(50_000).decode("utf-8", "replace")
            except (OSError, EOFError, zlib.error):
                return None
            name = re.search(r"(?m)^name:[ \t]{0,8}(\S{1,120})", text)
            version = re.search(r"(?m)^[ \t]{1,8}version:[ \t]{0,8}['\"]?([\w.+-]{1,60})", text)
            if name and version:
                return "rubygems", name.group(1), version.group(1)
            return None
        crate = Engine._CRATE_MANIFEST.search(unit.path)
        if crate is not None and archive.lower().endswith(".crate"):
            return "cargo", crate.group("name"), crate.group("version")
        module = Engine._GO_MODULE.search(unit.path)
        if module is not None and archive.lower().endswith(".zip"):
            return "gomod", module.group("module").rpartition("!")[2], module.group("version")
        return None

    _THROWAWAY_SUMMARY: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)\S{1,3}|test|tmp|temp|foo|bar|x gem|a gem|gem"
    )
    _GEM_CODE: ClassVar[tuple[str, ...]] = (".rb", ".sh", ".py", ".js", ".c", ".so", ".bundle")

    @staticmethod
    def _placeholder_release(units: Sequence[FileUnit], ctx: ScanContext) -> list[Finding]:
        """A published gem with no code whose summary is a throwaway word.

        RubyGems' malicious records are mostly releases that ship nothing -- an empty `lib/a.rb`,
        a file `x` -- under the summary `x`, `a` or `x gem`: 478 of 485 code-free malicious gems
        recovered from a mirror, and none of 6,999 benign gems (194 of which are also code-free,
        as shims and renamed packages are, but say what they are). Measured, review 98.
        """
        import gzip
        import zlib

        out: list[Finding] = []
        for unit in units:
            gem, _, member = unit.path.rpartition("!")
            if member != "metadata.gz" or not gem.lower().endswith(".gem"):
                continue
            code = sum(
                u.content.size
                for u in units
                if u.path.startswith(f"{gem}!data.tar.gz!")
                and u.path.lower().endswith(Engine._GEM_CODE)
            )
            if code >= 40:
                continue
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                    text = stream.read(50_000).decode("utf-8", "replace")
            except (OSError, EOFError, zlib.error):
                continue
            summary = re.search(r"(?m)^summary:[ \t]{0,8}(.{0,120})$", text)
            said = summary.group(1).strip().strip("'\"") if summary else ""
            if not said or not Engine._THROWAWAY_SUMMARY.fullmatch(said):
                continue
            out.append(
                replace(
                    Engine._operational(
                        path=unit.path,
                        rule_id="SUSPECT.PACKAGE.PLACEHOLDER_RELEASE.001",
                        message=(
                            f"This gem carries no code and its summary is `{said}`: a name taken "
                            "to be used, not a library. Most releases RubyGems records as "
                            "malicious have exactly this shape."
                        ),
                        remediation=(
                            "Do not depend on it; find out who published it and what depends on "
                            "the name."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.HIGH,
                    risk=ctx.scorer.score(Severity.HIGH, Confidence.HIGH),
                    detector="advisory",
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

        identities, placeholders = Engine._release_identities(units)
        if not identities:
            return []
        database = AdvisoryDatabase.bundled()
        out: list[Finding] = []
        for ecosystem, name, version, path in identities[:20]:
            records = [a for a in database.matching(ecosystem, name, version) if a.malicious]
            if not records:
                continue
            record = records[0]
            if path in placeholders:
                # npm's own stand-in for a release it removed: `0.0.1-security`, "security holding
                # package", nothing that runs. The name is the finding, not the tarball: 16 of
                # 300 random npm packages in the corpus were these, blocked as malware.
                out.append(
                    replace(
                        Engine._operational(
                            path=path,
                            rule_id=KNOWN_MALICIOUS_RELEASE_RULE,
                            message=(
                                f"{name} {version} is npm's security placeholder for a package "
                                f"removed as malicious ({record.identifier}). It contains no code; "
                                "what it says is that something depended on a name that carried "
                                "malware."
                            ),
                            remediation=(
                                "Remove the dependency, and find out where it came from: a "
                                "lockfile or manifest that names it once resolved the malicious "
                                "release."
                            ),
                            category=Category.SUSPICIOUS,
                            severity=Severity.MEDIUM,
                        ),
                        confidence=Confidence.CONFIRMED,
                        risk=ctx.scorer.score(Severity.MEDIUM, Confidence.CONFIRMED),
                        detector="advisory",
                        references=(record.reference,) if record.reference else (),
                    )
                )
                continue
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
    def _changed_while_read(path: str) -> Finding:
        """A file whose windows could not be read from the file that was first read."""
        return Engine._operational(
            path=path,
            rule_id="OPERATIONAL.FILE.UNREADABLE",
            message=(
                "This file changed, or was replaced, between being read and having the rest of it "
                "read in windows, so only what was read before the change was examined."
            ),
            remediation="Re-run the scan on a tree nothing else is writing to.",
        )

    @staticmethod
    def _read_to_end(content: FileContent) -> bool:
        """Whether a file over `max_file_bytes` was still read to its last byte, in windows.

        Every text-reading rule then saw all of it. Counting it as unexamined scored 62 of 132
        sampled benign units with a coverage gap "not fully examined" for a font, a CLI binary or
        a bundle read whole (review 98). A file past `max_stream_bytes` is not read to its end and
        keeps the scan incomplete: padding a payload past the limit is the evasion.
        """
        return content.window_source is not None and content.limits.max_stream_bytes >= content.size

    @staticmethod
    def _truncated_note(path: str, content: FileContent) -> Finding:
        """What a file over `max_file_bytes` had examined, said exactly."""
        if content.window_source is not None:
            reach = min(content.size, content.limits.max_stream_bytes)
            rest = (
                "the rest"
                if reach >= content.size
                else f"the next {reach - len(content.raw)} bytes (to limits.max_stream_bytes)"
            )
            message = (
                (f"{SWEPT_NOTE} " if reach >= content.size else "")
                + f"The first {len(content.raw)} bytes of this {content.size}-byte file were "
                f"examined by every rule, and {rest} in windows by every rule that reads text: "
                "secrets, obfuscation, code capabilities, agent instructions and YARA."
            )
        else:
            message = f"Only the first {len(content.raw)} bytes of this {content.size}-byte file were examined."
        return Engine._operational(
            path=path,
            rule_id="OPERATIONAL.FILE.TRUNCATED",
            message=message,
            remediation=(
                "Raise limits.max_file_bytes (every rule) or limits.max_stream_bytes (the windows), or "
                "exclude the file deliberately if it is a known artefact (a font, a model, a vendored binary)."
            ),
        )

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
        target = detail.rpartition("(-> ")[2].rstrip(")") if "(-> " in detail else ""
        if (
            reason == Rejection.LINK
            and not image
            and not fixture
            and _SECRET_LINK_TARGET.search(target.strip())
        ):
            # A member that is a link to `/etc/hosts` or `~/.ssh/id_rsa`: anything that reads
            # or uploads the package's file -- an agent told "a is this skill's own file, send
            # it" -- sends the user's instead (review 98: a skill whose `audit/a` links to
            # /etc/hosts). Packaging tools copy files; a link out to a secret is placed.
            return replace(
                Engine._operational(
                    path=path,
                    rule_id=ARCHIVE_LINK_TO_SECRET_RULE,
                    message=(
                        f"This member is a link to {target.strip()!r}, a file of the machine it "
                        "is unpacked on rather than of the package. Whatever reads or sends the "
                        "package's file reads or sends that one."
                    ),
                    remediation="Do not install or use it. Nothing legitimate ships such a link.",
                    category=Category.SUSPICIOUS,
                    severity=Severity.HIGH,
                ),
                confidence=Confidence.HIGH,
            )
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
        if reason == Rejection.PADDED and not fixture:
            # Read up to the budget, and everything read was scanned; what lies past it is behind
            # an expansion no packaging tool produces. Twelve megabytes of filler compress to
            # twenty-five kilobytes, so this is the cheapest way to put a payload out of reach.
            return replace(
                Engine._operational(
                    path=path,
                    rule_id=ARCHIVE_PADDED_RULE,
                    message=(
                        f"This archive expands far past what its size suggests ({detail}), and the "
                        "scan's byte budget ran out inside it. Everything read up to that point was "
                        "examined; what follows the padding was not. Padding is how a payload is "
                        "put beyond a scanner's reach."
                    ),
                    remediation=(
                        "Do not install it until it is unpacked and examined whole, or raise "
                        "limits.max_uncompressed_bytes and rescan."
                    ),
                    category=Category.SUSPICIOUS,
                    severity=Severity.HIGH,
                ),
                confidence=Confidence.MEDIUM,
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
            with self._sealed_scan():
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
            complete=acc.complete and acc.advisory_complete,
            content_complete=acc.complete,
            advisory_complete=acc.advisory_complete,
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
            with self._sealed_scan():
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
        units.extend(self._inline_hook_units(units))
        units.extend(self._deobfuscated_units(units))

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
        manifest_hooks, consumer_hooks, ci_scripts = self._manifest_hook_paths(units, acc)
        hook_paths = (
            set(ctx.install_hook_paths)
            | manifest_hooks
            | self._nuget_hooks(units)
            | self._gem_extension_hooks(units)
            | ComposerPluginHooks.paths(units)
        )
        # A skill's scripts run when the agent uses the skill, on the user's machine and unasked:
        # the trust boundary an install hook has (review 98: a skill script reading files and
        # posting them out was graded as a library's, at MEDIUM).
        skill_scripts = Engine._skill_scripts(units)
        agent_run = skill_scripts | Engine._mcp_server_sources(units)
        agent_tools = self._agent_tool_paths(units, agent_run, hook_paths)
        # Only a skill's scripts take the install grade. An MCP server runs when the agent calls
        # a tool the user asked it to use: downloading a browser, starting a detached emulator or
        # writing its config is the tool's work, and graded as install code it blocked 40 of 863
        # real MCP packages (review 98). What a server's handlers do with the agent's input is
        # read by `detect/mcp_code.py` instead -- a shell behind a secret prefix, a hidden copy of
        # every argument, a gate that turns the tool later, secrets gathered by name.
        hook_paths |= skill_scripts
        # What runs at install time is the hook and everything it imports. The
        # context stopped at the hook file, so moving the payload into a helper
        # module -- no obfuscation, just ordinary package structure -- avoided
        # the escalation entirely.
        entries = frozenset(hook_paths)
        hook_paths |= self._hook_import_closure(units, hook_paths)
        hook_paths |= self._hook_js_closure(units, hook_paths)
        hook_paths, entries, consumer_hooks = Engine._outside_extensions(
            units, hook_paths, entries, consumer_hooks
        )
        # And which of those files' bodies the hooks actually reach. A file is
        # in the closure because something imports it, which runs its top level
        # and defines its functions -- it does not call them.
        # Every function of agent-run code is an entry point: the agent calls them by name.
        deferred = Engine._entry_points_reached(
            self._hook_deferred_lines(units, hook_paths, entries), agent_run
        )
        ctx = replace(
            ctx,
            dependencies=Engine._packages(dependencies),
            install_hook_paths=frozenset(hook_paths),
            tree_paths=frozenset(unit.path for unit in units),
            install_entry_paths=entries,
            agent_run_paths=agent_tools,
            consumer_install_paths=frozenset(consumer_hooks),
            install_deferred_lines=deferred,
            ci_hook_paths=ctx.ci_hook_paths | frozenset(ci_scripts),
        )
        ctx = Engine._lifted_inherit(ctx)

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
        with self._sealed_scan():
            if workers > 1:
                acc.add(
                    self._scan_parallel(
                        units,
                        root,
                        ctx,
                        acc,
                        file_detectors,
                        signature,
                        carry_content=carry_content,
                    )
                )
            else:
                for unit in units:
                    acc.add(self._inspect_file(unit, ctx, acc, file_detectors, signature))
                    self.progress.advance(unit.path)
            acc.add(self._unexamined_install_code(acc.findings, ctx))
            acc.add(self._native_code_in_a_pure_wheel(units, ctx))
            acc.add(self._known_malicious_release(units, ctx))
            acc.add(self._placeholder_release(units, ctx))
            acc.add(self._borrowed_server_name(units, ctx))

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

        acc.findings[:] = self._person_run_ceiling(acc.findings, units, ctx)
        acc.findings[:] = Engine._graded_by_what_it_does(acc.findings, ctx)

        # Repository-scoped detectors. `RepositoryUnit` existed and nothing
        # produced one, so a detector asking about the repository rather than
        # about a file had no way to run at all -- the port was declared and
        # never wired.
        repository_unit = RepositoryUnit(repository=inventory)
        with self._sealed_scan():
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

        graded, verdict = Engine._package_verdict(
            Engine._hardening_tier(
                Engine._onto_manifest(Engine._test_identity_keys(list(findings), units), units),
                self.config.policy,
            ),
            units,
            {**self._capability_profile(units, ctx), **Engine._registry_facts(units)},
        )
        findings = tuple(graded)
        dependencies = self._annotated(dependencies, findings, ctx, units)
        result = ScanResult(
            findings=findings,
            verdict=verdict,
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
            complete=acc.complete and acc.advisory_complete,
            content_complete=acc.complete,
            advisory_complete=acc.advisory_complete,
            schema_version=SCHEMA_VERSION,
            engine_version=__version__,
            rulepack_version=self.rules.version,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
            intel=intel,
        )

        return PolicyGate.filter_for_reporting(result, self.config).sorted()

    @contextlib.contextmanager
    def _sealed_scan(self) -> Iterator[None]:
        """Seal the network for the detector phase of a scan that may not use it (gap G1).

        Intel is pulled before this (`_intel_status`), so the scan phase itself has no reason to
        reach the network. When the config forbids network (a plain offline scan), the seal makes
        that an enforced invariant rather than a promise: any `getaddrinfo` a detector, parser or
        third-party library attempts inside here is refused by `NetworkGuard`. Entered in the
        parent before the worker pool forks, so workers inherit the seal. When network is allowed
        (`--online`, `--model`), detectors legitimately resolve input-named hosts, so the seal is
        not applied and `NetworkGuard`'s public-only filter governs instead.
        """
        if self.config.constraints.allow_network:
            yield
            return
        from cordon_scanner.core.netguard import NetworkGuard

        with NetworkGuard.sealed():
            yield

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
            acc.advisory_complete = False
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
                        "Let the scan reach OSV (osv-vulnerabilities.storage.googleapis.com), "
                        "which it asks for what changed unless --offline, CORDON_OFFLINE or "
                        "CORDON_NO_ADVISORY_REFRESH is set; or run `cordon-scanner advisories "
                        "sync`, `cordon-scanner intel update`, or install a current signed "
                        "bundle with `cordon-scanner bundle install`."
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
                if member_content.truncated:
                    acc.complete = acc.complete and Engine._read_to_end(member_content)
                    acc.append(Engine._truncated_note(member_path, member_content))
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
            # A link has no content of its own: refusing it leaves nothing unread.
            acc.complete = acc.complete and reason == Rejection.LINK
            acc.append(
                Engine._rejected_member(member_path, reason, detail, image=image is not None)
            )

        # Manifests inside a package determine whether its code runs at install
        # time, which is the whole reason a package archive is worth scanning.
        units.extend(self._inline_hook_units(units))
        units.extend(self._deobfuscated_units(units))
        hook_paths, consumer_hooks, ci_scripts = self._manifest_hook_paths(units, acc)
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
        hook_paths |= self._gem_extension_hooks(units)
        hook_paths |= ComposerPluginHooks.paths(units)
        skill_scripts = Engine._skill_scripts(units)
        agent_run = skill_scripts | Engine._mcp_server_sources(units)
        agent_tools = self._agent_tool_paths(units, agent_run, hook_paths)
        # Only a skill's scripts take the install grade. An MCP server runs when the agent calls
        # a tool the user asked it to use: downloading a browser, starting a detached emulator or
        # writing its config is the tool's work, and graded as install code it blocked 40 of 863
        # real MCP packages (review 98). What a server's handlers do with the agent's input is
        # read by `detect/mcp_code.py` instead -- a shell behind a secret prefix, a hidden copy of
        # every argument, a gate that turns the tool later, secrets gathered by name.
        hook_paths |= skill_scripts
        entries = frozenset(hook_paths)
        hook_paths |= self._hook_import_closure(units, hook_paths)
        hook_paths |= self._hook_js_closure(units, hook_paths)
        hook_paths, entries, consumer_hooks = Engine._outside_extensions(
            units, hook_paths, entries, consumer_hooks
        )
        ctx = replace(
            ctx,
            install_hook_paths=frozenset(hook_paths),
            tree_paths=frozenset(unit.path for unit in units),
            install_entry_paths=entries,
            agent_run_paths=agent_tools,
            consumer_install_paths=frozenset(consumer_hooks),
            ci_hook_paths=ctx.ci_hook_paths | frozenset(ci_scripts),
            install_deferred_lines=Engine._entry_points_reached(
                self._hook_deferred_lines(units, hook_paths, entries), agent_run
            ),
            # Known before any file is examined, so a detector can tell an image's files from a
            # source tree's: an image's executables are what it ships.
            image=image if image is not None else ctx.image,
            # And so can a published package's: its `build/` and `bin/` are what runs, and the
            # typosquat grading asks which format it is.
            package_distribution=bool(early_format := self._distribution_format(units)),
            distribution=early_format,
            import_entry_paths=Engine._import_entries(units, early_format),
            package_repository=Engine._package_repository(units, early_format),
        )
        ctx = Engine._lifted_inherit(ctx)

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
            member_detectors = [
                d
                for d in detectors
                if not (d.requires.dependencies and d.requires.content is False)
            ]
            produced: list[Finding] = []
            for detector in member_detectors:
                produced.extend(self._run(detector, unit, ctx, acc))
            # The rest of an oversized member, a window at a time, as `_inspect_file` reads one.
            windowed, intact = WindowPass.run(
                unit,
                member_detectors,
                lambda detector, part: self._run(detector, part, ctx, acc),
                produced,
            )
            produced.extend(windowed)
            if not intact:
                acc.complete = False
                produced.append(Engine._changed_while_read(unit.path))
            acc.add(produced)
            self.progress.advance(unit.path)
        acc.add(self._unexamined_install_code(acc.findings, ctx))
        acc.add(self._native_code_in_a_pure_wheel(units, ctx))
        acc.add(self._known_malicious_release(units, ctx))
        acc.add(self._placeholder_release(units, ctx))
        acc.add(self._borrowed_server_name(units, ctx))

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
        package = self._distribution_format(units)
        target_kind = "image" if image is not None else "package" if package else "archive"
        if package:
            # A consumer's installer resolves from the package's declared metadata, never from a
            # lockfile shipped inside it: those pins are the maintainers' own environment. The
            # exception is a file that installer reads and obeys (`HONOURED_PINS`): what it pins
            # is what installing the package brings in.
            ctx = replace(ctx, package_distribution=True, distribution=package)
            acc.add(self._young_dependency_introduced(units, package, ctx))
            acc.findings[:] = self._impersonator_runs_downloads(
                self._publisher_hygiene(
                    self._publisher_secrets(
                        self._established_release_ceiling(
                            self._author_time_ceiling(
                                acc.findings, units, package, ctx.install_hook_paths
                            ),
                            units,
                            package,
                            hook_paths=ctx.install_hook_paths,
                        )
                    ),
                    self.config.policy.advisory_domains,
                )
            )
            honoured = HONOURED_PINS.get(package)
            dependencies = tuple(
                replace(d, scope=Scope.DEV)
                if d.scope in (Scope.RUNTIME, Scope.UNKNOWN)
                and not (honoured and honoured.search(d.declared_in or ""))
                else d
                for d in dependencies
            )
        elif image is None:
            # A source tree read from an archive: graded as a repository (`_person_run_ceiling`).
            acc.findings[:] = self._person_run_ceiling(acc.findings, units, ctx)
            if Engine._history_distribution(units) == "openvsx":
                # An editor extension against its own established release (`intel/openvsx.py`).
                acc.findings[:] = self._established_release_ceiling(
                    acc.findings, units, "openvsx", hook_paths=ctx.install_hook_paths
                )
        acc.findings[:] = Engine._graded_by_what_it_does(acc.findings, ctx)
        if image is not None:
            acc.findings[:] = Engine._image_start_ceiling(acc.findings, units)
            ctx = replace(ctx, image=image)
            installed = self._image_dependencies(image)
            present = {(d.ecosystem, d.name.lower(), d.version) for d in installed}
            # An image's inventory is what is installed in it. A lockfile or manifest inside it
            # names what the application was built from, development packages and ranges
            # included; an entry counts only where the same package is installed.
            dependencies = (
                *(d for d in dependencies if (d.ecosystem, d.name.lower(), d.version) in present),
                *installed,
            )
        if dependencies:
            ctx = replace(ctx, dependencies=Engine._packages(dependencies))
            graph_unit = GraphUnit(dependencies=Engine._packages(dependencies))
            for detector in self.detectors:
                if not detector.requires.dependencies:
                    continue
                if not self._detector_enabled(detector, ctx):
                    continue
                acc.add(self._run(detector, graph_unit, ctx, acc))

        acc.findings[:], verdict = Engine._package_verdict(
            Engine._hardening_tier(
                Engine._onto_manifest(Engine._test_identity_keys(acc.findings, units), units),
                self.config.policy,
            ),
            units,
            {**self._capability_profile(units, ctx), **Engine._registry_facts(units)},
        )
        dependencies = self._annotated(dependencies, acc.findings, ctx, units)
        result = ScanResult(
            findings=tuple(acc.findings),
            verdict=verdict,
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
            complete=acc.complete and acc.advisory_complete,
            content_complete=acc.complete,
            advisory_complete=acc.advisory_complete,
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
        seen_paths: set[str] = set()
        deferred: list[tuple[Path, str, str]] = []

        for entry in traversal:
            if entry.is_symlink:
                continue
            file_count += 1
            total_bytes += entry.size
            seen_paths.add(entry.rel_path)

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
                if hasattr(EcosystemRegistry.get(eco), "hooks_from_tree"):
                    # Its install-time code is a file beside the manifest: read once the whole
                    # tree has been walked, as the manifest detector reads it.
                    deferred.append((entry.real_path, entry.rel_path, eco))
                else:
                    hooks.extend(self._manifest_hooks(entry.real_path, entry.rel_path, eco))
            lock = EcosystemRegistry.lockfile_ecosystem(entry.rel_path)
            if lock:
                lockfiles.setdefault(lock, []).append(entry.rel_path)

        frozen = frozenset(seen_paths)
        for real_path, rel_path, eco in deferred:
            hooks.extend(self._manifest_hooks(real_path, rel_path, eco, frozen))

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
    def _outside_extensions(
        units: Sequence[FileUnit],
        hook_paths: set[str],
        entries: frozenset[str],
        consumer_hooks: set[str],
    ) -> tuple[set[str], frozenset[str], set[str]]:
        """The install-time picture of an editor extension: its activation entry, nothing else.

        The editor unpacks an extension and starts the `main` (or `browser`) its manifest names --
        on every start, unasked -- so that file runs as an install hook's does. No package manager
        runs in it, so no lifecycle script a bundled manifest names runs at all: kept, they made
        `node_modules/d3/dist/d3.min.js` inside a data-preview extension "runs during install" and
        its `new Function` beside a `fetch` a critical dropper. The entry alone, not what it
        imports: a bundled library is loaded, and what it does is read with its own context.
        """
        from cordon_scanner.detect.secrets import SourcePaths

        def keep(path: str) -> bool:
            return not SourcePaths.is_editor_extension(path)

        activation = Engine._extension_entries(units)
        return (
            {p for p in hook_paths if keep(p)} | activation,
            frozenset(p for p in entries if keep(p)) | activation,
            {p for p in consumer_hooks if keep(p)},
        )

    @staticmethod
    def _extension_entries(units: Sequence[FileUnit]) -> set[str]:
        """The files an editor starts in each extension present: its manifest's `main` and
        `browser`, with `.js` added when the manifest leaves it off, as Node resolves them."""
        from cordon_scanner.detect.secrets import SourcePaths

        paths = {unit.path for unit in units}
        found: set[str] = set()
        for unit in units:
            path = unit.path
            if not path.endswith("package.json") or not SourcePaths.is_editor_extension(path):
                continue
            root = path[: -len("package.json")]
            if not (root.endswith(".vsix!extension/") or re.search(r"/extensions/[^/]+/$", root)):
                continue
            try:
                manifest = json.loads(unit.content.raw)
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(manifest, dict) or not isinstance(manifest.get("engines"), dict):
                continue
            if "vscode" not in manifest["engines"]:
                continue
            for key in ("main", "browser"):
                value = manifest.get(key)
                if not isinstance(value, str) or not value.strip():
                    continue
                target = posixpath.normpath(root + value.strip().removeprefix("./"))
                for candidate in (target, f"{target}.js", f"{target}/index.js"):
                    if candidate in paths:
                        found.add(candidate)
                        break
        return found

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

    def _manifest_hooks(
        self,
        real_path: Path,
        rel_path: str,
        ecosystem_id: str,
        tree: frozenset[str] | None = None,
    ) -> list[Hook]:
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
            manifest = ecosystem.parse_manifest(loaded)
            hooks_from_tree = getattr(ecosystem, "hooks_from_tree", None)
            if tree is not None and hooks_from_tree is not None:
                manifest = hooks_from_tree(manifest, tree)
            return list(manifest.hooks)
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

    _GEM_EXTENSIONS: ClassVar[re.Pattern[str]] = re.compile(r"(?m)^extensions:[ \t]{0,8}$")
    _GEM_LISTED: ClassVar[re.Pattern[str]] = re.compile(r"[ \t]{0,8}-[ \t]{1,8}([^\n]{1,300})")

    @staticmethod
    def _gem_extension_hooks(units: Sequence[FileUnit]) -> set[str]:
        """The native-extension scripts a published `.gem` runs when it is installed.

        `gem install` runs every `extconf.rb` (or extension Rakefile) its `metadata.gz` lists under
        `extensions:`, on the installing machine, before any code is required. A gemspec in a
        repository declares the same through `spec.extensions`; a built gem only through its
        metadata, so the scripts read as ordinary library code (review 98: active-record_lite and
        aliyun-live renamed a bundled image to `a.exe` and ran it from extconf.rb, unflagged).
        """
        import gzip
        import zlib

        hooks: set[str] = set()
        by_path = {unit.path: unit for unit in units}
        for unit in units:
            gem, _, member = unit.path.rpartition("!")
            if member != "metadata.gz" or not gem.lower().endswith(".gem"):
                continue
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                    text = stream.read(200_000).decode("utf-8", "replace")
            except (OSError, EOFError, zlib.error):
                continue
            header = Engine._GEM_EXTENSIONS.search(text)
            if header is None:
                continue
            for line in text[header.end() + 1 :].splitlines()[:64]:
                item = Engine._GEM_LISTED.fullmatch(line)
                if item is None:
                    break
                extension = item.group(1).strip().strip("'\"")
                candidate = f"{gem}!data.tar.gz!{extension}"
                if extension and not extension.startswith(("/", "..")) and candidate in by_path:
                    hooks.add(candidate)
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
                # of reach. Unless the windows read it to its end: then every text rule saw
                # every byte, and only the whole-file parsers stopped at the limit.
                acc.complete = acc.complete and Engine._read_to_end(loaded)
                # Said here, for every such file. It was said by the capability detector, which
                # returns before it for a binary file and for one no rule applies to -- so a
                # repository with a 12 MB font was incomplete, failed the Action's default gate,
                # and gave no reason.
                if entry.rel_path not in acc.rejected_archives:
                    acc.append(Engine._truncated_note(entry.rel_path, loaded))

            retained += len(loaded.streamed or loaded.raw)
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
        skipped_judge = False

        for detector in JudgeGate.last(detectors):
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

            # The judge reads the grey band only, after every other detector (review 98, AG-5).
            if detector.id == JudgeGate.ID and not JudgeGate.wants(produced):
                skipped_judge = True
                continue
            produced.extend(self._run(detector, unit, ctx, acc))

        # The rest of an oversized file, a window at a time (`core/windows.py`). The workers make
        # the same call (`ParallelScanner._inspect_batch`), so a parallel scan reads as far.
        windowed, intact = WindowPass.run(
            unit,
            [
                d
                for d in detectors
                if d.id not in skipped and not (d.id == JudgeGate.ID and skipped_judge)
            ],
            lambda detector, part: self._run(detector, part, ctx, acc),
            produced,
        )
        produced.extend(windowed)
        if not intact:
            acc.complete = False
            produced.append(Engine._changed_while_read(unit.path))

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
                        # An archive member has no path on disk to re-read. The whole of an
                        # oversized one travels, so the worker can sweep it as well. Nor does
                        # a hook's inline program (`core.inline_programs`).
                        (unit.content.streamed or unit.content.raw)
                        if carry_content or "!" in unit.path or "#" in unit.path
                        else None,
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
            package_facts={
                "package_distribution": ctx.package_distribution,
                "distribution": ctx.distribution,
                "tree_paths": ctx.tree_paths,
                "import_entry_paths": ctx.import_entry_paths,
                "package_repository": ctx.package_repository,
            },
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
    def _publisher_hygiene(findings: list[Finding], advisory: frozenset[Any]) -> list[Finding]:
        """How a published package's own repository was kept, as against what it installs.

        A `.github/workflows/*.yml`, a `Dockerfile` or a release setting that ended up inside a
        tarball describes its publisher's repository and runs for nobody who installs it. These
        domains never fail a build (`Policy.advisory_domains`), and in a package scan they were
        most of what a clean package still warned about: unpinned actions, lockfile integrity,
        an unpinned base image (review 98, FP-8). Reported at INFO -- in JSON and SARIF for anyone
        auditing the publisher, out of the default report. A MALICIOUS finding is untouched.
        """
        from cordon_scanner.core.taxonomy import Taxonomy

        out: list[Finding] = []
        for finding in findings:
            if (
                finding.category is not Category.MALICIOUS
                and finding.severity > Severity.INFO
                and (
                    Taxonomy.domain_of(finding.rule_id) in advisory
                    or finding.rule_id.startswith(("POLICY.RELEASE.", "POLICY.LOCKFILE."))
                )
            ):
                finding = replace(finding, severity=Severity.INFO)
            out.append(finding)
        return out

    @staticmethod
    def _certificate_names(raw: bytes) -> bytes:
        """The printable names in the certificates a file holds: subject and issuer fields."""
        names: list[bytes] = []
        for block in CERTIFICATE_BLOCK.findall(raw[:200_000])[:8]:
            try:
                der = base64.b64decode(b"".join(block.split()), validate=False)
            except (ValueError, binascii.Error):
                continue
            names.extend(m.group(2)[: m.group(1)[0]] for m in DER_STRING.finditer(der))
        return b" ".join(names)

    @staticmethod
    def _test_identity_keys(findings: list[Finding], units: Sequence[FileUnit]) -> list[Finding]:
        """A private key whose certificate says it is for testing is a test key (review 98, FP-6).

        OpenSSL's `apps/` ships `client.pem` and `server2.pem` issued by "OpenSSL Test
        Intermediate CA ... FOR TESTING PURPOSES ONLY", and `ca-key.pem` beside "Server test
        cert"; every Bazel module that vendors OpenSSL carried 6 such blocks. Judged from the
        certificate in the key's own file or its directory, never from a path: a real key in
        `certs/` beside a real certificate keeps its grade. Reported at LOW, not withdrawn."""
        keys = [
            f
            for f in findings
            if f.rule_id == "SECRET.PRIVATE_KEY.001" and f.severity >= Severity.HIGH
        ]
        if not keys:
            return findings
        directories = {f.location.path.rpartition("/")[0] for f in keys}
        testing: dict[str, bool] = {}
        for unit in units:
            directory = unit.path.rpartition("/")[0]
            if directory not in directories or testing.get(directory):
                continue
            raw = unit.content.raw
            if b"BEGIN CERTIFICATE" in raw[:200_000]:
                names = Engine._certificate_names(raw)
                testing[directory] = bool(names and TEST_IDENTITY.search(names))
        out: list[Finding] = []
        for finding in findings:
            if finding in keys and testing.get(finding.location.path.rpartition("/")[0]):
                finding = replace(
                    finding,
                    severity=Severity.LOW,
                    message=finding.message
                    + " The certificate beside it names a test identity, so this is read as a "
                    "test key: confirm it is not used anywhere real.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _publisher_secrets(findings: list[Finding]) -> list[Finding]:
        """A credential committed inside a published package, graded for whoever installs it.

        The key is its publisher's: they leaked it and they are the ones who can rotate it.
        Nothing about it acts on the machine that installs the package, so for that consumer it
        is reported, in full, at MEDIUM, and does not stop the build. In 40 such blocks read
        from 441 real npm and PyPI packages (review 98) every one was the publisher's own token
        -- a `.coveralls.yml` repo token, a `.env`, a demo's API key. A repository's own
        secrets are untouched: this runs only for a recognised published package. Code that
        USES a credential (harvesting, exfiltration) is a different rule and keeps its grade, and
        so does a token that is a place to post to (`DROP_POINT_SECRETS`).
        """
        out: list[Finding] = []
        for finding in findings:
            if (
                finding.rule_id.startswith("SECRET.")
                and finding.rule_id not in DROP_POINT_SECRETS
                and finding.category is not Category.MALICIOUS
                and finding.severity > Severity.MEDIUM
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " It ships inside a published package, so the exposure is its publisher's"
                    " to rotate; it does not act on whoever installs the package, and is reported"
                    " below the gate.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _entry_points_reached(
        deferred: frozenset[tuple[str, int, int]], agent_run: set[str]
    ) -> frozenset[tuple[str, int, int]]:
        """Deferred bodies, less those in code an agent runs: a skill script's functions and an MCP
        server's handlers are called by the agent by name, so none of them is unreached. Counted as
        deferred, a skill script appending to `/etc/passwd` and `/etc/crontab` from its functions
        had no install-time finding at all (review 98)."""
        return frozenset(t for t in deferred if t[0] not in agent_run)

    def _agent_tool_paths(
        self, units: Sequence[FileUnit], agent_run: set[str], hooks: set[str]
    ) -> frozenset[str]:
        """Agent-run code and the modules it imports, less anything a real install hook reaches.

        An MCP server's file importing the SDK hands its API calls to `client.py` and `core.py`;
        those run on the agent's tool calls exactly as the server does (review 98: serper's
        `core.py` sending SERPER_API_KEY to google.serper.dev was blocked while the same call in
        the server file was not). What `setup.py` or a lifecycle script also reaches keeps the
        install grade."""
        if not agent_run:
            return frozenset()
        tools = agent_run | self._hook_import_closure(units, agent_run)
        tools |= self._hook_js_closure(units, tools)
        if hooks:
            real = hooks | self._hook_import_closure(units, hooks)
            real |= self._hook_js_closure(units, real)
            tools -= real - agent_run
        return frozenset(tools)

    @staticmethod
    def _mcp_server_sources(units: Sequence[FileUnit]) -> set[str]:
        """An MCP server's own source: started by the agent host and run on the agent's tool calls,
        never on a run the user chose -- the boundary an install hook has. Graded as application
        code, a server reading the environment's secrets and posting them out was a warning
        (review 98, mcp-variants: 12 of 177 malicious servers blocked by their code)."""
        from cordon_scanner.detect.agents import _SERVER_SOURCE_SUFFIXES

        return {
            u.path
            for u in units
            if u.path.endswith(_SERVER_SOURCE_SUFFIXES)
            and "/node_modules/" not in u.path
            and "site-packages/" not in u.path
            and not Engine._NOT_A_SERVER_PATH.search(u.path.rpartition("!")[2])
            and Engine._MCP_SDK_IMPORT.search(u.content.text[:200_000]) is not None
        }

    #: An import statement of an MCP server SDK at the start of a line -- not the same words in a
    #: string, which is how a test file holds a server's source as a fixture.
    _MCP_SDK_IMPORT: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:from[ \t]{1,8}(?:mcp|fastmcp)(?:\.\w{1,40}){0,4}[ \t]{1,8}import\b|import[ \t]{1,8}(?:mcp|fastmcp)\b"
        r"|[ \t]{0,8}import\b[^\n]{0,200}[\"']@modelcontextprotocol/sdk"
        r"|[^\n]{0,80}require\(\s{0,4}[\"']@modelcontextprotocol/sdk)",
        re.MULTILINE,
    )
    #: Tests, fixtures, examples and documentation are read, not started by an agent host.
    _NOT_A_SERVER_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|bench(?:marks?)?)/"
        r"|(?:^|/)test_[^/]*$|\.(?:test|spec)\.[^/]+$"
    )

    @staticmethod
    def _skill_scripts(units: Sequence[FileUnit]) -> set[str]:
        """Scripts an agent skill ships (`CapabilityDetector._skill_script`)."""
        from types import SimpleNamespace

        from cordon_scanner.detect.capability import CapabilityDetector

        tree = SimpleNamespace(tree_paths=frozenset(u.path for u in units))
        return {
            u.path
            for u in units
            if CapabilityDetector._skill_script(u.path, tree)  # type: ignore[arg-type]
        }

    #: Manifests the verdict reads for package context, by file name.
    _VERDICT_MANIFESTS: ClassVar[tuple[str, ...]] = (
        "package.json",
        "setup.py",
        "pyproject.toml",
        "requirements.txt",
        # A skill's claim about itself: its front matter's name and description.
        "SKILL.md",
    )

    #: A hook's whole command lifted out of its manifest: `package.json#preinstall.sh`.
    _LIFTED_HOOK: ClassVar[re.Pattern[str]] = re.compile(r"^(?P<hook>[\w:.-]+?)\.sh$")

    @staticmethod
    def _onto_manifest(findings: list[Finding], units: Sequence[FileUnit]) -> list[Finding]:
        """Findings on a hook's command read as shell, placed on the hook in its manifest.

        The lifted command is not a file anyone can open; the manifest line declaring the hook
        is. (An inline `node -e` program keeps its own path: `core.inline_programs`.)
        The finding keeps what it says and its evidence hash, and points at that line.
        """
        manifests = {u.path: u.content.raw for u in units if "#" not in u.path}
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path or ""
            owner, _, lifted = path.rpartition("#")
            hook = Engine._LIFTED_HOOK.match(lifted) if owner else None
            raw = manifests.get(owner) if hook else None
            if raw is None or hook is None:
                out.append(finding)
                continue
            found = raw.find(f'"{hook.group("hook")}"'.encode())
            start = max(found, 0)
            end = raw.find(b"\n", start)
            end = len(raw) if end < 0 else end
            line_text = raw[start:end].decode("utf-8", "replace")
            snippet = finding.evidence.snippet
            out.append(
                replace(
                    finding,
                    location=replace(
                        finding.location,
                        path=owner,
                        line=raw[:start].count(b"\n") + 1,
                        column=None,
                        end_line=None,
                        end_column=None,
                        byte_start=start,
                        byte_end=end,
                    ),
                    evidence=replace(
                        finding.evidence,
                        span=(start, end),
                        snippet=line_text if snippet and "[redacted]" not in snippet else snippet,
                    ),
                )
            )
        return out

    #: How many files of one kind the capability profile labels: the files that run at install or
    #: on import are a handful in any real package; past this the rest are not read again.
    _PROFILE_FILES: ClassVar[int] = 50

    def _capability_profile(self, units: Sequence[FileUnit], ctx: ScanContext) -> dict[str, float]:
        """What the code that runs on its own can do: the capabilities of the files an install
        runs, of the files importing the package runs first, and of the scripts an agent runs.

        A rule reports a combination it was written for; most malware that no rule names still
        does, at install or on import, things a library's entry point does not -- start a
        process, reach the network, decode and evaluate (review 98: a `setup.py` that clones a
        repository and runs a script from it raised nothing). The verdict weighs the profile with
        everything else; on its own it blocks nothing.
        """
        from cordon_scanner.detect.capability import CapabilityDetector
        from cordon_scanner.detect.download_flow import DownloadFlow

        detector = next((d for d in self.detectors if isinstance(d, CapabilityDetector)), None)
        if detector is None:
            return {}
        out: dict[str, float] = {}
        places = {
            "install": ctx.install_hook_paths | ctx.install_entry_paths,
            "import": ctx.import_entry_paths,
            "agent": ctx.agent_run_paths,
        }
        for place, paths in places.items():
            held: set[str] = set()
            read = 0
            for unit in units:
                if unit.path not in paths or unit.content.size > 1_000_000:
                    continue
                if read >= Engine._PROFILE_FILES:
                    break
                read += 1
                try:
                    labelled = detector.labelled(unit, ctx)
                except Exception:  # noqa: S112 -- a profile is evidence, never a scan failure
                    continue
                if labelled is not None:
                    held |= {hit.capability.value for hit in labelled[0]}
                if "runs_download" not in held and DownloadFlow.runs_download(
                    unit.content.text, unit.language
                ):
                    held.add("runs_download")
            out[f"{place}_files"] = float(read)
            out[f"{place}_capabilities"] = float(len(held))
            out.update({f"{place}_can_{name}": 1.0 for name in held})
        return out

    @staticmethod
    def _registry_facts(units: Sequence[FileUnit], root: Path | None = None) -> dict[str, float]:
        """What the registry recorded about this release, as verdict facts (`reg_*`).

        Read from the store `cordon-scanner intel acquire` wrote (`intel/registry_record.py`);
        nothing acquired, nothing added -- and `reg_known` absent tells the verdict so. These are
        second-review facts: the trainer keeps them out of the content-only measure.
        """
        from cordon_scanner.intel.registry_record import ECOSYSTEMS, RegistryRecord

        files = [u for u in units if isinstance(u, FileUnit)]
        distribution = Engine._history_distribution(files)
        if distribution not in ECOSYSTEMS:
            return {}
        identity = Engine._history_identity(files, distribution)
        if identity is None:
            return {}
        record = RegistryRecord.load(*identity, root=root)
        return record.facts() if record is not None else {}

    @staticmethod
    def _package_verdict(
        findings: list[Finding], units: Sequence[FileUnit], profile: dict[str, float] | None = None
    ) -> tuple[list[Finding], dict[str, Any]]:
        """The package verdict over everything this scan found (`core/verdict.py`)."""
        from cordon_scanner.core.verdict import Verdict

        paths_sizes = [(u.path, u.content.size) for u in units]
        manifests = {
            u.path: u.content.raw[:1_000_000]
            for u in units
            if u.path.rsplit("!", 1)[-1].rsplit("/", 1)[-1] in Engine._VERDICT_MANIFESTS
        }
        sources = [
            (u.path, u.content.raw)
            for u in units
            if u.path.rsplit("!", 1)[-1].lower().endswith((".js", ".mjs", ".cjs", ".ts", ".py"))
        ]
        graded, verdict = Verdict.decide(
            list(findings), paths_sizes, manifests, sources, profile or {}
        )
        second, line = verdict.get("registry_score"), verdict.get("registry_block")
        if second is not None and line is not None and second >= line:
            # The second review: what the registry recorded about this release -- who published
            # it, when the name was made, what it added over the release before -- scores over its
            # line (`intel/registry_record.py`). Content-free malware is found here or not at all.
            graded.append(
                replace(
                    Engine._operational(
                        path=".",
                        rule_id=REGISTRY_REVIEW_RULE,
                        message=(
                            f"What the registry recorded about this release scores {second:.2f} "
                            f"against the second review's line of {line:.2f} for "
                            f"{verdict.get('area', 'packages')}: its publisher, its age, its "
                            "release history and what it added are what malicious releases in the "
                            "training half looked like."
                        ),
                        remediation=(
                            "Check who published this release and why; pin a release from before "
                            "it until that is explained."
                        ),
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.MEDIUM,
                    always_report=False,
                    detector="registry-review",
                )
            )
        score, block = verdict.get("score"), verdict.get("block")
        if score is not None and block is not None and score >= block:
            # The package over its line blocks as a package, whether or not one finding would
            # alone: the combination is the evidence. MalSkillBench's malicious skills were
            # flagged 98.3% of the time and blocked 80.1%, because no one of their findings was
            # strong alone (review 98).
            rules = sorted(verdict.get("rules", {}), key=lambda r: -verdict["rules"][r])
            graded.append(
                replace(
                    Engine._operational(
                        path=".",
                        rule_id=Verdict.RULE,
                        message=(
                            f"Taken together, this package's findings ({', '.join(rules[:5])}"
                            f"{', ...' if len(rules) > 5 else ''}) and what kind of package it "
                            f"is score {score:.2f} against the blocking line of {block:.2f} for "
                            f"{verdict.get('area', 'packages')}: the combination is what malicious "
                            "packages in the training half looked like."
                        ),
                        remediation="Read each finding listed. Do not install until explained.",
                        category=Category.SUSPICIOUS,
                        severity=Severity.HIGH,
                    ),
                    confidence=Confidence.MEDIUM,
                    always_report=False,
                    detector="manifest",
                )
            )
        return graded, verdict

    @staticmethod
    def _hardening_tier(findings: list[Finding], policy: Policy) -> list[Finding]:
        """Record pipeline, container and infrastructure hardening findings at LOW.

        See `Policy.hardening`: those domains (`Policy.advisory_domains`) describe how a project
        configured itself, and by default they are reported in full and below the warning level.
        A MALICIOUS finding in them is never lowered; nor is anything when `--hardening` is on.
        """
        if policy.hardening:
            return findings
        from cordon_scanner.core.taxonomy import Taxonomy

        out: list[Finding] = []
        for finding in findings:
            domain = Taxonomy.domain_of(finding.rule_id)
            if finding.category is Category.SUSPICIOUS:
                # A generic code finding inside a container build file or a pipeline definition
                # is about how the project builds and ships, whatever rule read it: the RUN line
                # that downloads, unpacks and runs a toolchain is `SUSPECT.CONTAINER.*`'s
                # finding, and reading the same text as shell does not make it an attack on
                # whoever scans the repository (review 98: 45 benign units blocked by a dropper in
                # a Dockerfile, against no malware sample).
                domain = Engine._build_definition_domain(finding.location.path) or domain
            if (
                finding.category is not Category.MALICIOUS
                and finding.severity > Severity.LOW
                and domain in policy.advisory_domains
            ):
                finding = replace(
                    finding,
                    severity=Severity.LOW,
                    message=finding.message
                    + " Hardening finding: recorded at LOW by default; `--hardening` reports it "
                    "at its own severity.",
                )
            out.append(finding)
        return out

    _PIPELINE_FILES: ClassVar[frozenset[str]] = frozenset(
        {
            ".gitlab-ci.yml",
            ".gitlab-ci.yaml",
            "azure-pipelines.yml",
            "azure-pipelines.yaml",
            "bitbucket-pipelines.yml",
            "cloudbuild.yml",
            "cloudbuild.yaml",
            ".drone.yml",
            ".woodpecker.yml",
        }
    )

    @staticmethod
    def _build_definition_domain(path: str) -> ThreatDomain | None:
        """CONTAINER for a container build file, CICD for a pipeline definition, else None."""
        from cordon_scanner.core.taxonomy import ThreatDomain

        member = "/" + path.rpartition("!")[2]
        name = member.rpartition("/")[2]
        lower = name.lower()
        if lower.startswith(("dockerfile", "containerfile")) or lower.endswith(
            (".dockerfile", ".containerfile")
        ):
            return ThreatDomain.CONTAINER
        if (
            lower in Engine._PIPELINE_FILES
            or name.startswith("Jenkinsfile")
            or (lower.endswith((".yml", ".yaml")) and "/.github/workflows/" in member)
            or any(f"/{d}/" in member for d in (".circleci", ".buildkite", ".azure-pipelines"))
        ):
            return ThreatDomain.CICD
        return None

    #: Directories whose files a tool runs when the project is opened or committed to: editor
    #: tasks, dev containers, agent settings and hooks, git hooks.
    _OPENED_DIRECTORIES: ClassVar[tuple[str, ...]] = (
        "/.vscode/",
        "/.devcontainer/",
        "/.claude/",
        "/.cursor/",
        "/.windsurf/",
        "/.idea/",
        "/.husky/",
        "/.githooks/",
        "/.git/hooks/",
        "/.gemini/",
        "/.codex/",
        "/.continue/",
    )
    _OPENED_FILES: ClassVar[frozenset[str]] = frozenset(
        {".envrc", ".mcp.json", "mcp.json", "devcontainer.json", ".pre-commit-config.yaml"}
    )

    @staticmethod
    def _runs_on_its_own(path: str, ctx: ScanContext) -> bool:
        """Whether a repository file runs without a person naming it: installing the project
        (lifecycle hooks and what they import), building it (build definitions), opening it
        (editor tasks, direnv, dev containers, git and agent hooks), or an agent using it (MCP
        servers, skill scripts)."""
        if (
            path in ctx.install_hook_paths
            or path in ctx.agent_run_paths
            or path in ctx.install_entry_paths
            or path in ctx.consumer_install_paths
        ):
            return True
        member = path.rpartition("!")[2]
        if any(
            hook.kind in ("build", "startup", "projectbuild", "githook")
            for hook in Engine._hooks_for(member)
        ):
            return True
        slashed = "/" + member
        name = ContainerPaths.basename(member)
        return (
            name in Engine._OPENED_FILES
            or any(d in slashed for d in Engine._OPENED_DIRECTORIES)
            or name in PROJECT_BUILD_FILENAMES
            or name in DEPENDENCY_BUILD_FILENAMES
            or name.endswith((".bzl", ".gradle", ".gradle.kts", ".mk"))
            or name in ("BUILD", "BUILD.bazel", "WORKSPACE", "MODULE.bazel", "CMakeLists.txt")
            or name in ("flake.nix", "default.nix", "shell.nix", "configure", "package.json")
        )

    _MCP_SDK_DECLARED: ClassVar[re.Pattern[str]] = re.compile(
        r"@modelcontextprotocol/sdk|^\s*(?:fastmcp|mcp)\s*[<>=~\[\"',]|^\s*rmcp\s*=|\"(?:fastmcp|mcp)[<>=~\[]",
        re.MULTILINE,
    )

    @staticmethod
    def _agent_or_editor_tree(units: Sequence[FileUnit], ctx: ScanContext) -> bool:
        """A tree an agent host or an editor starts: a skill (`SKILL.md`), an MCP server (its code
        runs on the agent's tool calls, `agent_run_paths`, or its manifest declares an MCP SDK),
        or an editor extension."""
        from cordon_scanner.detect.secrets import SourcePaths

        if ctx.agent_run_paths:
            return True
        for unit in units:
            member = unit.path.rpartition("!")[2]
            name = ContainerPaths.basename(member)
            if name == "SKILL.md" or SourcePaths.is_editor_extension(unit.path):
                return True
            if name in ("package.json", "pyproject.toml", "requirements.txt", "Cargo.toml") and (
                Engine._MCP_SDK_DECLARED.search(unit.content.text[:100_000])
            ):
                return True
        return False

    _SHELL_DOTFILES: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:\.|dot_)?(?:bashrc|bash_profile|bash_aliases|bash_logout|profile|zshrc|zshenv|"
        r"zprofile|zlogin|aliases|functions|exports|inputrc)$|\.(?:bashrc|zshrc|fish)$|^config\.fish$"
    )

    @staticmethod
    def _a_tool_a_person_runs(path: str, unit: FileUnit | None) -> bool:
        """Whether a repository file is a tool someone starts by name, rather than the project's
        source: a shell, PowerShell or batch script, an extensionless executable script (a
        shebang), a container build file, or a shell startup file a dotfiles repository keeps."""
        member = path.rpartition("!")[2]
        name = ContainerPaths.basename(member)
        lower = name.lower()
        if lower.endswith(STANDALONE_SCRIPTS) or Engine._SHELL_DOTFILES.search(lower):
            return True
        if lower.startswith(("dockerfile", "containerfile")) or lower.endswith(
            (".dockerfile", ".containerfile")
        ):
            return True
        return (
            "." not in name
            and unit is not None
            and not unit.content.is_binary
            and unit.content.raw[:2] == b"#!"
        )

    @staticmethod
    def _person_run_ceiling(
        findings: list[Finding], units: list[FileUnit], ctx: ScanContext
    ) -> list[Finding]:
        """Suspicious findings in a repository file nothing runs on its own, reported below the
        gate (review 98, option A, 2026-10-17).

        A repository is scanned before someone builds or opens it. What runs then, unasked, is
        the attack surface: the install hooks and what they import, the build definitions, the
        editor tasks, dev container, git and agent hooks that fire on open, and the servers and
        skills an agent starts. A release script, a dotfile, a provisioning script or a tool under
        `bin/` runs when a person runs it by name, and the finding is still reported -- as a
        warning. A file one of the auto-run files names (`sh ./scripts/x.sh` in a Makefile) is
        auto-run too. A MALICIOUS finding is never lowered, wherever it is.
        """
        if Engine._agent_or_editor_tree(units, ctx):
            # An agent skill, an MCP server or an editor extension: the agent host or the editor
            # starts it, so none of it waits for a person to run it by name.
            return findings
        from cordon_scanner.core.taxonomy import Taxonomy, ThreatDomain

        auto = [u for u in units if Engine._runs_on_its_own(u.path, ctx)]
        named: dict[str, bool] = {}

        def named_by_auto_run(path: str) -> bool:
            name = ContainerPaths.basename(path.rpartition("!")[2])
            if len(name) < 4:
                return False
            if name not in named:
                named[name] = any(
                    u.path != path and not u.content.is_binary and name in u.content.text
                    for u in auto
                )
            return named[name]

        by_path = {u.path: u for u in units}
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            if (
                finding.category is Category.SUSPICIOUS
                and finding.severity > Severity.MEDIUM
                and path
                and path != REPOSITORY_SCOPE
                # A leaked key is leaked whoever runs the file it sits in.
                and not finding.rule_id.startswith("SECRET.")
                # Wiping a home directory harms whoever runs the script, a person included.
                and not finding.rule_id.startswith("SUSPECT.DESTROY.")
                # An agent reads its instruction and configuration files on open, unasked.
                and Taxonomy.domain_of(finding.rule_id) is not ThreatDomain.AGENT
                and Engine._a_tool_a_person_runs(path, by_path.get(path))
                and not Engine._runs_on_its_own(path, ctx)
                and not named_by_auto_run(path)
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " Nothing in this repository runs this file on its own -- it is not an "
                    "install or build step, not run when the project is opened, and not named by "
                    "one -- so it runs when a person runs it, and is reported below the gate.",
                )
            out.append(finding)
        return out

    #: Fetch-and-run findings a package-level verdict can raise.
    _RUNS_DOWNLOADS: ClassVar[frozenset[str]] = frozenset({"SUSPECT.DROPPER.001"})

    @staticmethod
    def _impersonator_runs_downloads(findings: list[Finding]) -> list[Finding]:
        """A published package named one slip from a popular one that downloads and runs code.

        Each half is graded below the gate on its own: a typo-shaped name is common in the long
        tail (`SUSPECT.PACKAGE.NAME_RISK.001` records it), and a library function that fetches
        and starts a program is held at MEDIUM because it runs only when called. Together they
        are the typosquat dropper -- `fequests`, `rwquests` and `tequests` wrap every `requests`
        call in a download that is then run (review 98). The dropper finding is raised to HIGH;
        a dropper in a test, a document or generated output keeps its ceiling.
        """
        from cordon_scanner.detect.secrets import SourcePaths

        squat = any(
            f.rule_id == "SUSPECT.PACKAGE.NAME_RISK.001"
            and "one slip from the popular" in f.message
            for f in findings
        )
        if not squat:
            return findings
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            if (
                finding.rule_id in Engine._RUNS_DOWNLOADS
                and finding.severity < Severity.HIGH
                and not SourcePaths.is_test_material(path)
                and not SourcePaths.is_documentation(path)
                and not SourcePaths.is_generated_artefact(path)
            ):
                finding = replace(
                    finding,
                    severity=Severity.HIGH,
                    message=finding.message
                    + " The package is named one slip from a popular one, and a package that "
                    "imitates another's name while downloading and running code is a typosquat "
                    "dropper.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _author_time_ceiling(
        findings: list[Finding],
        units: list[FileUnit],
        distribution: str,
        runs: frozenset[str] = frozenset(),
    ) -> list[Finding]:
        """Findings in files a published package carries but nothing installing it runs.

        An sdist ships its maintainers' CI workflows, Makefile and Dockerfile, and a Python
        package with a JavaScript front end ships that front end's `package.json`; pip runs
        none of them. psutil's Makefile pipes a download into Python, jupyterlab's
        `package.json` declares npm lifecycle scripts, mcp's `.github/workflows/claude.yml`
        hands an issue to an agent -- each true of the repository, and none of it reaching a
        machine that runs `pip install`. Reported, below the gate. A MALICIOUS finding is never
        lowered.

        What counts depends on the format's installer. Compiled source is lowered only in
        Python and npm packages, whose install compiles an extension but does not run it: in a
        crate, a Go module or a jar that source IS the program the consumer runs. A Makefile
        stays a finding where installing runs make (`MAKE_AT_INSTALL`).

        A shell, PowerShell or batch script runs only when something starts it. No installer
        starts one on its own: a hook that does is in `runs` (the install-hook paths), and code
        or a manifest that does names it. A script that is neither -- a `curl | sh` release
        installer, a CI helper -- is the maintainers' (review 98: 103 of 293 benign units
        blocked by a dropper alone, against 0 of 44 malware samples). A conda link script runs at
        install and keeps its grade.
        """
        from cordon_scanner.detect.secrets import SourcePaths

        compiled_is_inert = distribution in ("pypi", "npm")
        make_is_inert = distribution not in MAKE_AT_INSTALL

        def author_time(member: str) -> bool:
            name = ContainerPaths.basename(member)
            lower = name.lower()
            other_ecosystem = (name == "package.json" and distribution != "npm") or (
                name in ("setup.py", "pyproject.toml") and distribution != "pypi"
            )
            makefile = name in MAKEFILES or name.endswith(".mk")
            return (
                other_ecosystem
                or lower.endswith(SHIPPED_DOCUMENTS)
                or (compiled_is_inert and lower.endswith(COMPILED_SOURCE) and name != "build.rs")
                or member.startswith(AUTHOR_TIME_PREFIXES)
                or f"/{member}".find("/.github/") >= 0
                or (name in AUTHOR_TIME_FILENAMES and not makefile)
                or (makefile and make_is_inert)
                or container(name)
            )

        def container(name: str) -> bool:
            lower = name.lower()
            return lower.startswith(("dockerfile", "containerfile")) or lower.endswith(
                (".dockerfile", ".containerfile")
            )

        named: dict[str, bool] = {}

        def started_by_the_package(path: str, name: str) -> bool:
            """Whether code or a manifest the consumer's side runs names this script."""
            if name not in named:
                named[name] = any(
                    unit.path != path
                    and not unit.content.is_binary
                    and not SourcePaths.is_documentation(unit.path)
                    and not author_time(unit.path.rpartition("!")[2])
                    and name in unit.content.text
                    for unit in units
                )
            return named[name]

        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            member = path.rpartition("!")[2]
            name = ContainerPaths.basename(member)
            lowered = author_time(member) or (
                name.lower().endswith(STANDALONE_SCRIPTS)
                and not CONDA_LINK_SCRIPT.search(name)
                and path not in runs
                and not started_by_the_package(path, name)
            )
            if (
                lowered
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

    _HISTORY_MANIFESTS: ClassVar[dict[str, re.Pattern[str]]] = {
        # `<group>/<artifact>/pom.properties` inside a jar: the coordinates Maven resolved.
        "maven": re.compile(r"(?:^|!)META-INF/maven/[^/!]+/[^/!]+/pom\.properties$"),
        "gradle": re.compile(r"(?:^|!)META-INF/maven/[^/!]+/[^/!]+/pom\.properties$"),
        # A Go module zip's own go.mod, at `<module>@<version>/go.mod`.
        "gomod": re.compile(r"(?:^|!)([^!]+)@(v[^/!]+)/go\.mod$"),
        "hex": re.compile(r"(?:^|!)metadata\.config$"),
        "pub": re.compile(r"(?:^|!)[^/!]*/?pubspec\.yaml$"),
        "rubygems": re.compile(r"(?:^|!)metadata(?:\.gz)?$"),
    }

    @staticmethod
    def _history_identity(
        units: Sequence[FileUnit], distribution: str
    ) -> tuple[str, str, str] | None:
        """(ecosystem, name, version) of the release a published archive is, for
        `ReleaseHistory`: the manifest its format names, read the way that format writes it."""
        if distribution in ("npm", "pypi", "cargo", "nuget"):
            identities, _ = Engine._release_identities(units)
            for ecosystem, name, version, _ in identities:
                if ecosystem == distribution:
                    return ecosystem, name, version
            return None
        if distribution == "openvsx":
            manifest = next((u for u in units if u.path.endswith("!extension/package.json")), None)
            try:
                document = json.loads(manifest.content.text) if manifest is not None else None
            except ValueError:
                return None
            if not isinstance(document, dict):
                return None
            publisher, name, version = (
                document.get("publisher"),
                document.get("name"),
                document.get("version"),
            )
            if all(isinstance(v, str) and v for v in (publisher, name, version)):
                # As published: the API redirects any other spelling to this one.
                return "openvsx", f"{publisher}.{name}", str(version)
            return None
        pattern = Engine._HISTORY_MANIFESTS.get(distribution)
        if pattern is None:
            return None
        for unit in units:
            found = pattern.search(unit.path)
            if not found:
                continue
            text = unit.content.text[:20000]
            if unit.path.endswith(".gz"):
                # A gem's `metadata.gz`: the gemspec as YAML, gzipped, read bounded.
                import gzip
                import zlib

                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(unit.content.raw)) as stream:
                        text = stream.read(20000).decode("utf-8", "replace")
                except (OSError, EOFError, zlib.error):
                    continue
            if distribution == "gomod":
                return "gomod", found.group(1).rpartition("!")[2], found.group(2).lstrip("v")
            if distribution in ("maven", "gradle"):
                group = re.search(r"(?m)^groupId=(\S+)", text)
                artifact = re.search(r"(?m)^artifactId=(\S+)", text)
                version = re.search(r"(?m)^version=(\S+)", text)
                if group and artifact and version:
                    # A shaded jar carries the poms of what it bundles, and may not carry its
                    # own: only a pom whose artifact the jar was published as names it.
                    archive = unit.path.split("!", 1)[0]
                    if f"{artifact.group(1)}-{version.group(1)}" in archive:
                        return (
                            distribution,
                            f"{group.group(1)}:{artifact.group(1)}",
                            version.group(1),
                        )
            elif distribution == "hex":
                name = re.search(r'\{<<"name">>,\s*<<"([^"]+)">>\}', text)
                version = re.search(r'\{<<"version">>,\s*<<"([^"]+)">>\}', text)
                if name and version:
                    return "hex", name.group(1), version.group(1)
            elif distribution == "pub":
                name = re.search(r"(?m)^name:\s*['\"]?([\w-]+)", text)
                version = re.search(r"(?m)^version:\s*['\"]?([\w.+-]+)", text)
                if name and version:
                    return "pub", name.group(1), version.group(1)
            elif distribution == "rubygems":
                name = re.search(r"(?m)^name:\s*(\S+)", text)
                version = re.search(r"(?m)^\s+version:\s*['\"]?([\w.+-]+)", text)
                if name and version:
                    return "rubygems", name.group(1), version.group(1)
        return None

    _REQUIRES_DIST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?m)^Requires-Dist:\s*([A-Za-z0-9][A-Za-z0-9._-]*)([^\n]*)$"
    )

    @staticmethod
    def _declared_dependencies(units: Sequence[FileUnit], distribution: str) -> frozenset[str]:
        """The runtime dependencies a published release declares: npm's `dependencies` and
        `optionalDependencies`, a Python distribution's `Requires-Dist` outside any extra."""
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
                        for found in Engine._REQUIRES_DIST.finditer(unit.content.text[:200_000])
                        if "extra ==" not in found.group(2)
                    )
        return frozenset()

    @staticmethod
    def _young_dependency_introduced(
        units: list[FileUnit],
        distribution: str,
        ctx: ScanContext,
        root: Path | None = None,
    ) -> list[Finding]:
        """A dependency this release adds over its established release that was itself first
        published only days before this release.

        Read from the store `cordon-scanner intel acquire` wrote; nothing acquired, nothing reported. An
        established package's compromised release pulls in a name created for the attack -- the
        `@mastra/*` releases of 2026-06-17 added `easy-day-js` -- while a dependency the
        package's own scope publishes (a monorepo's new sibling) is the maintainers' and is not
        counted.
        """
        from datetime import datetime, timedelta

        from cordon_scanner.intel.release_history import YOUNG_DEPENDENCY_DAYS, ReleaseHistory

        identity = Engine._history_identity(units, distribution)
        if identity is None:
            return []
        baseline = ReleaseHistory.load(*identity, root=root)
        if baseline is None or not baseline.baseline_version or not baseline.published:
            return []
        try:
            released = datetime.fromisoformat(baseline.published)
        except ValueError:
            return []
        scope = identity[1].split("/", 1)[0] + "/" if identity[1].startswith("@") else None
        manifest = next(
            (
                u.path
                for u in units
                if u.path.endswith(("!package/package.json", "/PKG-INFO", ".dist-info/METADATA"))
            ),
            units[0].path if units else "",
        )
        out: list[Finding] = []
        family = re.sub(r"^@[^/]+/", "", identity[1]).lower()
        for dependency, first in sorted(baseline.introduced.items()):
            if not first or (scope and dependency.startswith(scope)):
                continue
            bare = re.sub(r"^@[^/]+/", "", dependency).lower()
            stem = min(family, bare, key=len)
            if len(stem) >= 4 and (
                bare.startswith(family) or family.startswith(bare.split("-")[0])
            ):
                # A package split into siblings: `astn` adds `astn-runtime` the day it is created.
                continue
            try:
                appeared = datetime.fromisoformat(first)
            except ValueError:
                continue
            if not timedelta(0) <= released - appeared <= timedelta(days=YOUNG_DEPENDENCY_DAYS):
                continue
            days = (released - appeared).days
            out.append(
                replace(
                    Engine._operational(
                        path=manifest,
                        rule_id=YOUNG_DEPENDENCY_RULE,
                        message=(
                            f"{identity[1]} {identity[2]} adds the dependency {dependency}, which "
                            f"its established release {baseline.baseline_version} did not have and "
                            f"which was first published {days} day(s) before this release. A "
                            "compromised release of an established package pulls in a name "
                            "created for the attack."
                        ),
                        remediation=(
                            f"Read {dependency} before installing this release; pin the previous "
                            "release until its maintainers confirm the change."
                        ),
                        # A warning: maintainers add new packages of their own too (review 98:
                        # 6 of 2,481 random npm and PyPI releases), so the name alone does not
                        # block; what the new dependency's own code does is the decision.
                        category=Category.SUSPICIOUS,
                        severity=Severity.MEDIUM,
                    ),
                    confidence=Confidence.MEDIUM,
                    risk=ctx.scorer.score(Severity.MEDIUM, Confidence.MEDIUM),
                    detector="release-history",
                )
            )
        return out

    @staticmethod
    def _established_release_ceiling(
        findings: list[Finding],
        units: list[FileUnit],
        distribution: str,
        root: Path | None = None,
        hook_paths: frozenset[str] = frozenset(),
    ) -> list[Finding]:
        """Suspicious findings in files this package has shipped unchanged since an established
        release, reported below the gate.

        `intel/release_history.py` holds, for a release acquired beforehand (`cordon intel
        acquire`), the per-file hashes of the newest release published at least
        `release_history.MIN_AGE_DAYS` earlier. A finding in a file byte-identical to that
        release describes code the ecosystem has carried for months; one in a file that is new
        or changed in this release keeps its grade, and that is where a compromised release puts
        its payload. Nothing acquired, nothing changed: this reads a file, never the network. A
        MALICIOUS finding is never lowered.
        """
        from cordon_scanner.intel.release_history import ReleaseHistory

        identity = Engine._history_identity(units, distribution)
        if identity is None:
            return findings
        baseline = ReleaseHistory.load(*identity, root=root)
        if baseline is None or not baseline.baseline_version:
            return findings
        digests = {unit.path: hashlib.sha256(unit.content.raw).hexdigest() for unit in units}
        out: list[Finding] = []
        for finding in findings:
            path = finding.location.path
            if (
                finding.rule_id == "SUSPECT.OBFUSCATION.PACKED.001"
                and finding.severity > Severity.MEDIUM
                and path in digests
                and path not in hook_paths
                and ReleaseHistory.key(path, identity[2]) in baseline.obfuscated
            ):
                # Obfuscated output changes on every build, so it is never byte-identical; what
                # the established release shows is that this file was already obfuscated months
                # ago. A new package, or a readable file turned obfuscated in this release --
                # the shape of a compromised release -- keeps its grade, as does anything an
                # install hook runs.
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + f" The same file was already obfuscated in {baseline.baseline_version}, "
                    f"published {(baseline.baseline_published or '')[:10]}, at least 90 days "
                    "before this release, so it is reported below the gate.",
                )
            elif (
                finding.category is Category.SUSPICIOUS
                and finding.severity > Severity.MEDIUM
                and path in digests
                and baseline.unchanged(ReleaseHistory.key(path, identity[2]), digests[path])
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + f" This file is byte-identical in {baseline.baseline_version}, published "
                    f"{(baseline.baseline_published or '')[:10]}, at least "
                    "90 days before this release, so it is reported below the gate.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _package_repository(units: list[FileUnit], distribution: str) -> str:
        """The published npm package's own `repository` URL, or "": a string, or an object's
        `url`, as `package.json` declares it (review 98, FP-2)."""
        if distribution != "npm":
            return ""
        manifest = next((u for u in units if u.path.endswith("!package/package.json")), None)
        try:
            document = json.loads(manifest.content.text) if manifest is not None else {}
        except ValueError:
            return ""
        repository = document.get("repository") if isinstance(document, dict) else None
        if isinstance(repository, dict):
            repository = repository.get("url")
        return repository.strip() if isinstance(repository, str) else ""

    @staticmethod
    def _import_entries(units: list[FileUnit], distribution: str) -> frozenset[str]:
        """The files of a published package that run when it is used rather than installed: npm's
        `main` (or `index.js`), `bin` and `exports` targets; a wheel's or sdist's top-level
        `__init__.py`. Their module top level runs on `require()`, `import` or the command, on
        every consumer, with no hook in the manifest (review 98, REC-2)."""
        members: dict[str, str] = {}
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep and "!" not in member:
                members[member] = unit.path
        found: set[str] = set()
        if distribution == "npm":
            manifest = next((u for u in units if u.path.endswith("!package/package.json")), None)
            try:
                document = json.loads(manifest.content.text) if manifest is not None else {}
            except ValueError:
                document = {}
            if not isinstance(document, dict):
                document = {}
            targets: list[str] = [document.get("main") or "index.js"]

            def strings(value: object) -> None:
                if isinstance(value, str):
                    targets.append(value)
                elif isinstance(value, dict):
                    for nested in value.values():
                        strings(nested)
                elif isinstance(value, list):
                    for nested in value:
                        strings(nested)

            strings(document.get("bin"))
            strings(document.get("exports"))
            for target in targets:
                if not isinstance(target, str) or "*" in target:
                    continue
                base = "package/" + target.strip().removeprefix("./").rstrip("/")
                for candidate in (base, f"{base}.js", f"{base}/index.js"):
                    if candidate in members:
                        found.add(members[candidate])
                        break
        elif distribution == "pypi":
            for member, path in members.items():
                parts = member.split("/")
                if parts[-1] != "__init__.py" or any(
                    part in ("tests", "test", "docs", "examples") for part in parts
                ):
                    continue
                # A wheel's `pkg/__init__.py`, an sdist's `name-1.0/pkg/__init__.py` or
                # `name-1.0/src/pkg/__init__.py`: the package itself, not a subpackage.
                if (
                    len(parts) == 2
                    or (len(parts) == 3 and "-" in parts[0])
                    or (len(parts) == 4 and parts[1] == "src")
                ):
                    found.add(path)
        return frozenset(found)

    @staticmethod
    def _history_distribution(units: list[FileUnit]) -> str:
        """The format release history knows this archive as: a published package's, or Open VSX
        for an editor extension (`.vsix`), which is not otherwise graded as a package."""
        package = Engine._distribution_format(units)
        if package:
            return package
        tops = {u.path.partition("!")[2] for u in units if u.path.count("!") == 1}
        if "extension.vsixmanifest" in tops and "extension/package.json" in tops:
            return "openvsx"
        return ""

    @staticmethod
    def _distribution_format(units: list[FileUnit]) -> str:
        """Which published-package format the archive is, or "" when it is not one.

        Recognised by the metadata file each format's own packaging tool writes, at the
        archive's first level only. That level matters: a repository snapshot that vendors a
        package tarball is still a repository, and its own lockfiles are still the project's.
        Formats whose archives have the same shape as a repository snapshot (pub, Packagist,
        Helm, Terraform modules) are not recognised, because nothing tells them apart.
        """
        top: set[str] = set()
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep and "!" not in member:
                top.add(member)
        roots: dict[str, set[str]] = {}
        for member in top:
            directory, sep, leaf = member.partition("/")
            if sep and "/" not in leaf:
                roots.setdefault(directory, set()).add(leaf)
        for directory, leaves in roots.items():
            if "PKG-INFO" in leaves or (directory.endswith(".dist-info") and "METADATA" in leaves):
                return "pypi"
            if directory == "package" and "package.json" in leaves:
                return "npm"
            if "Cargo.toml.orig" in leaves:
                return "cargo"
            if "DESCRIPTION" in leaves and "MD5" in leaves:
                return "cran"
            if any(
                leaf.endswith(".cabal")
                and re.fullmatch(rf"{re.escape(leaf[:-6])}-\d[\d.]*", directory)
                for leaf in leaves
            ):
                return "hackage"
        if "metadata.gz" in top:
            return "rubygems"
        if "[Content_Types].xml" in top and any(
            m.endswith(".nuspec") and "/" not in m for m in top
        ):
            return "nuget"
        if "metadata.config" in top and "CHECKSUM" in top:
            return "hex"
        if "META-INF/MANIFEST.MF" in top:
            return "maven"
        if "info/index.json" in top:
            return "conda"
        # A `.conda` package: a zip of `metadata.json` and two zstd tarballs, its `info/` inside
        # `info-*.tar.zst` -- the same package as the `.tar.bz2`, one level further down.
        if "metadata.json" in top and any(
            re.search(r"![^!/]*info-[^!/]*\.tar\.zst!info/index\.json$", unit.path)
            for unit in units
        ):
            return "conda"
        if "MANIFEST.json" in top and "FILES.json" in top:
            return "galaxy"
        if any(GO_MODULE_ROOT.match(m) for m in top):
            return "gomod"
        return ""

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
        platforms = oci.ImageLayers.platforms(data)
        if len(platforms) > 1:
            # Every platform's operating-system packages, each read from its own manifest; the
            # files are content-scanned on the first platform only, and the contents note says so.
            inventory.platform = platforms[0][1]
            for index, label in platforms[1:]:
                try:
                    other = oci.ImageLayers.read_image(data, index)
                except (tarfile.TarError, OSError, ValueError, KeyError, EOFError) as exc:
                    inventory.problems.append(
                        f"the {label} image could not be read ({type(exc).__name__})"
                    )
                    continue
                other.platform = label
                inventory.other_platforms.append(other)
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
                    + (
                        f" A multi-platform image: the operating-system packages of all "
                        f"{1 + len(inventory.other_platforms)} platforms were inventoried, and the "
                        f"files content-scanned on {inventory.platform}."
                        if getattr(inventory, "other_platforms", None)
                        else ""
                    )
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
        """An image's installed dependencies; for a multi-platform image, every platform's.

        An operating-system package installed on every platform is listed once, unlabelled; one
        installed on some is labelled with exactly those. Language packages come from the files,
        content-scanned on the first platform, and are not labelled: they would read as present on
        that platform alone."""
        primary = Engine._image_dependencies_of(inventory)
        others = getattr(inventory, "other_platforms", None) or []
        if not others:
            return primary
        from cordon_scanner.images.packages import OsPackage

        system = set(OsPackage.PURL_TYPE.values())
        merged: dict[tuple[str, str, str | None], Dependency] = {}
        seen_on: dict[tuple[str, str, str | None], list[str]] = {}
        for platform_inventory, dependencies in (
            (inventory, primary),
            *((other, Engine._image_dependencies_of(other)) for other in others),
        ):
            for dependency in dependencies:
                key = (dependency.ecosystem, dependency.name, dependency.version)
                merged.setdefault(key, dependency)
                seen_on.setdefault(key, []).append(platform_inventory.platform)
        everywhere = 1 + len(others)
        return tuple(
            replace(
                dependency,
                platform=(
                    *dependency.platform,
                    *(f"platform {label}" for label in seen_on[key] if label),
                ),
            )
            if dependency.ecosystem in system and len(seen_on[key]) < everywhere
            else dependency
            for key, dependency in merged.items()
        )

    @staticmethod
    def _image_dependencies_of(inventory: Any) -> tuple[Dependency, ...]:
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
        tree: dict[str, Any] | None = None
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
                # A lockfile read with the files beside it, where the ecosystem keeps part of the
                # record apart (an Ansible collection's signatures, in its `.info/GALAXY.yml`).
                in_tree = getattr(ecosystem, "parse_lockfile_in_tree", None)
                if in_tree is not None:
                    if tree is None:
                        tree = {u.path: u.content for u in units}
                    graph = in_tree(unit.content, tree)
                else:
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
                exact = Engine._exact_pin(spec, dependency.ecosystem)
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
                    signature_sources=dependency.signature_sources or entry.signature_sources,
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
            pinned = Engine._exact_pin(entry.spec, ecosystem_id)
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
                    signature_sources=entry.signature_sources,
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
        return [
            d
            for d in joined
            if not (
                d.local
                and not d.parents
                and d.manifest_path is None
                and d.ecosystem not in Engine.LOCKS_WITHOUT_ROOTS
            )
        ]

    #: Lockfiles that never list the project itself, so a local entry in one is always a
    #: dependency: Podfile.lock lists the pods installed, never the app. Flutter's Podfile adds
    #: `FlutterMacOS` through a helper (`flutter_install_all_macos_pods`) rather than a `pod` line,
    #: and the rule above took the pod for the project and dropped it.
    LOCKS_WITHOUT_ROOTS: ClassVar[frozenset[str]] = frozenset({"cocoapods"})

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

    #: Ecosystems where a bare version is a range resolved to its newest match, exact only with
    #: `=`: Cargo reads `1.2.3` as `^1.2.3`, Julia's `[compat]` reads `"1"` as `^1`.
    #: StaticArrays.jl's compat `PrecompileTools = "1"` was taken for version 1, which the General
    #: registry has never held, and reported withdrawn. (NuGet's `1.0` is `1.0` or higher too, but
    #: NuGet installs the lowest match: the version written.)
    BARE_VERSION_IS_A_RANGE: ClassVar[frozenset[str]] = frozenset({"cargo", "julia"})

    _EXACT_PIN = re.compile(r"^(?:==|=)?\s*v?(\d[A-Za-z0-9.+\-_]*)$")
    """A specification that names one version and no other.

    `==3.2`, `=1.19.0`, `4.17.15`. Not `^4.17.0`, `~=3.2`, `>=1,<2`, `1.2.*` or
    anything carrying a comparator, a comma or a wildcard -- each of those is a
    range, and which release it resolves to is the resolver's decision rather
    than the manifest's.
    """

    @staticmethod
    def _exact_pin(spec: str, ecosystem: str | None = None) -> str | None:
        """The version a specification pins to, or None if it is a range."""
        text = spec.strip().strip("'\"")
        if ecosystem in Engine.BARE_VERSION_IS_A_RANGE and not text.startswith("="):
            return None
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
            if ecosystem is None or ecosystem_id is None:
                continue
            # Whether a manifest in the tree names one of the project's own packages: for most
            # ecosystems always; never for Homebrew; for Conan only a workspace's members.
            defines = getattr(ecosystem, "defines_members", True)
            if callable(defines):
                defines = defines(unit.path, contents)
            if not defines:
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
                own = getattr(implementation, "exact_pin", None)
                pinned = (
                    own(declared.spec)
                    if own is not None
                    else Engine._exact_pin(declared.spec, declared_id)
                )
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
                        signature_sources=declared.signature_sources,
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
        from cordon_scanner.ecosystems.homebrew import NotRunAtInstall
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        # A formula or cask is a hook as a whole; its `service`, `test` and `caveats` blocks are
        # not run by `brew install` (`NotRunAtInstall`).
        brew = frozenset(
            (unit.path, first, last)
            for unit in units
            if unit.path in hooks
            and unit.path.endswith(".rb")
            and EcosystemRegistry.manifest_ecosystem(unit.path) == "homebrew"
            for first, last in NotRunAtInstall.spans(unit.content.text)
        )
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if not sources:
            return brew
        return brew | CallReachability.deferred_lines(hooks, sources, entries)

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
                acc.rejected_archives.add(rel_path)
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
                    acc.complete = acc.complete and reason == Rejection.LINK
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
            if content.truncated:
                acc.complete = acc.complete and Engine._read_to_end(content)
                acc.append(Engine._truncated_note(member_path, content))
            units.append(
                FileUnit(content=content, language=LanguageRegistry.of_file(member_path, content))
            )
        self._archive_stats[1] += len(units)
        return units

    _DEOBFUSCATION_MARKERS: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"while\s*\(\s*!!\[\]\s*\)|\batob\s*\(|\bBuffer\s*\.\s*from\s*\(\s*['\"`][A-Za-z0-9+/=_\-]{16}"
        rb"|fromCharCode\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*,|\xf3\xa0[\x80-\x87]|\xef\xb8[\x80-\x8f]"
    )
    """Bytes without which no reversal in `core.deobfuscation` applies: most files pay one search."""

    DEOBFUSCATED: ClassVar[str] = "#deobfuscated.js"
    """Suffix of the unit an obfuscated file's recovered text is read as (`core.deobfuscation`)."""

    def _deobfuscated_units(self, units: list[FileUnit]) -> list[FileUnit]:
        """Each obfuscated JavaScript file reversed statically, as a unit of its own.

        Read by every detector with the context of the file it came from (`_lifted_inherit`), so
        what the code does is graded rather than that it was hidden. A file that cannot be
        reversed, or only in part, is not lifted, and its obfuscation finding keeps its grade.
        """
        from cordon_scanner.core.deobfuscation import Deobfuscator

        lifted: list[FileUnit] = []
        for unit in units:
            if (
                unit.content.is_binary
                or unit.language not in ("javascript", "typescript")
                or "#" in unit.path
                or not Engine._DEOBFUSCATION_MARKERS.search(unit.content.raw)
            ):
                continue
            recovery = Deobfuscator.recover(unit.content.text, unit.language)
            if recovery is None or recovery.resolved == 0:
                continue
            if recovery.remaining > max(3, recovery.resolved // 20):
                continue
            path = unit.path + Engine.DEOBFUSCATED
            content = FileContent.from_bytes(
                path, recovery.text.encode("utf-8"), self.config.limits
            )
            lifted.append(FileUnit(content=content, language="javascript"))
        return lifted

    @staticmethod
    def _lifted_inherit(ctx: ScanContext) -> ScanContext:
        """A recovered unit runs when the file it came from runs: install hook, entry point,
        consumer install, agent tool, or a published package's import entry."""
        tree = ctx.tree_paths

        def grown(paths: frozenset[str]) -> frozenset[str]:
            more = {p + Engine.DEOBFUSCATED for p in paths if p + Engine.DEOBFUSCATED in tree}
            return paths | more if more else paths

        return replace(
            ctx,
            install_hook_paths=grown(ctx.install_hook_paths),
            install_entry_paths=grown(ctx.install_entry_paths),
            consumer_install_paths=grown(ctx.consumer_install_paths),
            agent_run_paths=grown(ctx.agent_run_paths),
            import_entry_paths=grown(ctx.import_entry_paths),
        )

    #: Form findings the recovered text repeats, because it keeps the obfuscator's variable names.
    RECOVERED_FORM: ClassVar[frozenset[str]] = frozenset(
        {"SUSPECT.OBFUSCATION.PACKED.001", "SUSPECT.OBFUSCATION.LONGLINE.001"}
    )

    #: Where an image's init systems, schedulers and shells keep what they start on their own.
    _IMAGE_STARTED: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:etc/services\.d/[^/]{1,200}/(?:run|finish)|etc/cont-(?:init|finish)\.d/[^/]{1,200}"
        r"|etc/s6-overlay/(?:s6-rc\.d/[^/]{1,200}/(?:run|up|finish)|scripts/[^/]{1,200})"
        r"|etc/supervisor(?:d\.conf|/[^\n]{1,300}\.conf)|etc/supervisord\.d/[^\n]{1,300}"
        r"|docker-entrypoint(?:-initdb)?\.d/[^/]{1,200}|etc/s(?:ervice|v)/[^/]{1,200}/run"
        r"|etc/crontabs/[^/]{1,200}|etc/cron\.(?:d|hourly|daily|weekly|monthly)/[^/]{1,200}"
        r"|var/spool/cron/[^\n]{1,300}|etc/periodic/[^\n]{1,300}|etc/profile|etc/profile\.d/[^/]{1,200}"
        r"|etc/bash\.bashrc|etc/rc\.local|etc/init\.d/[^/]{1,200}"
        r"|(?:usr/lib|etc)/systemd/system/[^\n]{1,300}"
        r"|(?:usr/local/)?bin/docker-entrypoint[^/]{0,100}|(?:docker-)?entrypoint[^/]{0,100})$"
    )
    _INTERPRETED: ClassVar[frozenset[str]] = frozenset(
        {"py", "js", "mjs", "cjs", "ts", "rb", "php", "pl", "sh", "bash", "lua", "r"}
    )
    _IMAGE_PATH_DIRS: ClassVar[tuple[str, ...]] = (
        "usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin", "sbin", "bin",
    )  # fmt: skip

    @staticmethod
    def _image_start_ceiling(findings: list[Finding], units: list[FileUnit]) -> list[Finding]:
        """Suspicious findings in an image's files that nothing in the image starts, reported
        below the gate (review 98: option A, for images).

        A container runs what its configuration starts -- the entrypoint and command, the
        healthcheck -- and what its init system, scheduler and login shell start on their own,
        and everything those name. The application the command runs lives under the working
        directory. The rest of the image -- a vendored library's Makefile, a package manager's
        cache, a script nobody calls -- runs when someone execs it. Malicious findings, secrets
        (readable by anyone who pulls the image) and agent findings keep their grade, and an
        image whose configuration cannot be read keeps every grade.
        """
        from cordon_scanner.core.taxonomy import Taxonomy, ThreatDomain

        def member(path: str) -> str:
            return path.split("!", 1)[1] if "!" in path else path

        history = next((u for u in units if member(u.path) == "image-config/history.txt"), None)
        if history is None:
            return findings
        start: list[str] = []
        workdir = ""
        for line in history.content.text.splitlines():
            head, _, rest = line.partition(" ")
            if head in ("ENTRYPOINT", "CMD", "HEALTHCHECK"):
                start.append(rest)
            elif head == "WORKDIR":
                workdir = rest.strip().strip("/")
        if not start:
            return findings
        members = {
            member(u.path): u for u in units if not member(u.path).startswith("image-config/")
        }
        by_name: dict[str, list[str]] = {}
        for path in members:
            by_name.setdefault(path.rpartition("/")[2], []).append(path)

        def resolve(token: str, base: str) -> set[str]:
            token = token.strip("'\"`;&|(){}")
            if not token or token.startswith("-") or "=" in token:
                return set()
            out: set[str] = set()
            if token.startswith("/"):
                if token[1:] in members:
                    out.add(token[1:])
            else:
                for root in (base, workdir):
                    candidate = posixpath.normpath(f"{root}/{token}") if root else token
                    if candidate in members:
                        out.add(candidate)
                if "/" not in token:
                    out.update(
                        f"{d}/{token}" for d in Engine._IMAGE_PATH_DIRS if f"{d}/{token}" in members
                    )
            return out

        auto: set[str] = {p for p in members if Engine._IMAGE_STARTED.match(p)}
        if workdir:
            # The application under the working directory, in the languages a runtime loads from
            # source. A Makefile runs at build time, and Go or Java sources never run: their
            # binary does, and is reached from the command.
            auto |= {
                p
                for p in members
                if p.startswith(workdir + "/")
                and p.rpartition(".")[2].lower() in Engine._INTERPRETED
                and "/vendor/" not in f"/{p}"
            }
        for command in start:
            for token in re.split(r"[\s;&|]+", command):
                auto |= resolve(token, workdir)
        # And what the started files name: a script they run or source, by path or by name.
        frontier = set(auto)
        for _ in range(6):
            found: set[str] = set()
            for path in frontier:
                unit = members.get(path)
                if unit is None or unit.content.is_binary or unit.content.size > 2_000_000:
                    continue
                text = unit.content.text
                base = path.rpartition("/")[0]
                for token in set(re.findall(r"[\w./${}-]{2,200}", text)):
                    token = token.replace("${", "").replace("}", "")
                    found |= resolve(token, base)
                    name = token.rpartition("/")[2]
                    if len(name) >= 6:
                        found.update(by_name.get(name, ()))
            frontier = found - auto
            if not frontier:
                break
            auto |= frontier
        out: list[Finding] = []
        for finding in findings:
            path = member(finding.location.path or "")
            if (
                finding.category is Category.SUSPICIOUS
                and finding.severity > Severity.MEDIUM
                and path in members
                and path not in auto
                and not finding.rule_id.startswith(("SECRET.", "SUSPECT.DESTROY."))
                and Taxonomy.domain_of(finding.rule_id) is not ThreatDomain.AGENT
            ):
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + " Nothing in this image starts this file -- not its entrypoint, command or "
                    "healthcheck, not its init system or scheduler, not under its working "
                    "directory, and not named by any of those -- so it runs only if someone runs "
                    "it, and is reported below the gate.",
                )
            out.append(finding)
        return out

    @staticmethod
    def _graded_by_what_it_does(findings: list[Finding], ctx: ScanContext) -> list[Finding]:
        """Findings on recovered text (`<file>#deobfuscated.js`) that add nothing: the form rules
        the recovered text repeats because it keeps the obfuscator's names, and anything the
        original file already says under the same rule.

        The obfuscation finding itself keeps its grade. Measured on the review-98 malware set,
        lowering it when the recovered code carried nothing at the gate lost compromised
        releases whose only visible symptom was the obfuscation -- `@draftlab/auth` 0.24.2 and
        `@dirigible-ai/sdk` 0.6.3 recover to code that does nothing graded, their payload being
        elsewhere. Reversal adds what the recovered code does; it does not excuse the hiding.
        """
        del ctx
        on_original = {
            (f.location.path, f.rule_id)
            for f in findings
            if f.location.path and not f.location.path.endswith(Engine.DEOBFUSCATED)
        }
        return [
            f
            for f in findings
            if not (
                (f.location.path or "").endswith(Engine.DEOBFUSCATED)
                and (
                    f.rule_id in Engine.RECOVERED_FORM
                    or ((f.location.path or "")[: -len(Engine.DEOBFUSCATED)], f.rule_id)
                    in on_original
                )
            )
        ]

    def _inline_hook_units(self, units: list[FileUnit]) -> list[FileUnit]:
        """The programs install hooks carry inline, each as a unit of its own.

        `node -e "<program>"` in a `postinstall` is install-time code like the file
        `node install.js` runs, and is read the same way: by every content detector, with the
        hook's escalation. See `core.inline_programs`. Author-time hooks are left alone, as
        their files are.
        """
        lifted: list[FileUnit] = []
        known = {unit.path for unit in units}
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            if ecosystem_id is None or ecosystem_id == "image" or unit.content.is_binary:
                continue
            ecosystem = EcosystemRegistry.get(ecosystem_id)
            if ecosystem is None:
                continue
            try:
                hooks = ecosystem.parse_manifest(unit.content).hooks
            except Exception:  # noqa: S112 -- `_manifest_hook_paths` reports the failure
                continue
            for hook in hooks:
                if not hook.command or hook.name.lower() in AUTHOR_TIME_HOOKS:
                    continue
                for program in InlinePrograms.lifted(unit.path, hook.name, hook.command):
                    if program.path in known:
                        continue
                    known.add(program.path)
                    content = FileContent.from_bytes(
                        program.path, program.source.encode("utf-8"), self.config.limits
                    )
                    lifted.append(
                        FileUnit(
                            content=content,
                            language=LanguageRegistry.of_file(program.path, content),
                        )
                    )
        return lifted

    @staticmethod
    def _manifest_hook_paths(
        units: list[FileUnit], acc: _Accumulator | None = None
    ) -> tuple[set[str], set[str], set[str]]:
        """Paths that execute at install time, according to their manifests -- and, third, the
        scripts a published GitHub action's composite steps run, which are CI code.

        The same packaging test the inventory applies, for the same reason and
        against the same repository: this is the SECOND place a `setup.py`
        becomes an install hook, and fixing only the first left
        `hermes_cli/subcommands/setup.py` -- an argument parser -- seeding an
        import closure of 510 files. See `Engine._hook_executes`.
        """
        paths: set[str] = set()
        consumer: set[str] = set()
        ci_scripts: set[str] = set()
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
                # And the hooks only the tree shows: a CRAN source package's `configure` and
                # `cleanup` beside its DESCRIPTION. The manifest detector and the inventory
                # already ask; without it here those scripts were never install-time code.
                hooks_from_tree = getattr(ecosystem, "hooks_from_tree", None)
                if hooks_from_tree is not None:
                    manifest = hooks_from_tree(manifest, known)
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
            if any(not hook.action_step for hook in manifest.hooks):
                paths.add(unit.path)
            if manifest.hooks:
                # A published action's composite steps run on its consumers' runners as CI code:
                # what they name is read in CI context, not install context (review 98: as
                # install code, 305 of 2,978 benign actions blocked).
                steps = [hook for hook in manifest.hooks if hook.action_step]
                if steps:
                    ci_scripts |= Engine._hook_script_paths(unit.path, steps, known)
                reaching = [
                    hook
                    for hook in manifest.hooks
                    if hook.name.lower() not in AUTHOR_TIME_HOOKS and hook not in steps
                ]
                if reaching:
                    paths |= Engine._hook_script_paths(unit.path, reaching, known)
                    paths |= {
                        program.path
                        for hook in reaching
                        for program in InlinePrograms.lifted(
                            unit.path, hook.name, hook.command or ""
                        )
                        if program.path in known
                    }
                consuming = [hook for hook in manifest.hooks if hook.kind == "consumerinstall"]
                if consuming:
                    consumer.add(unit.path)
                    consumer |= Engine._hook_script_paths(unit.path, consuming, known)
                    consumer |= {
                        program.path
                        for hook in consuming
                        for program in InlinePrograms.lifted(
                            unit.path, hook.name, hook.command or ""
                        )
                        if program.path in known
                    }
        return paths, consumer, ci_scripts

    _ACTION_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"""["']?(?:\$\{\{\s*github\.action_path\s*\}\}|\$\{?GITHUB_ACTION_PATH\}?)["']?/"""
    )

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
            previous = ""
            # A GitHub action names its own files through the action's checkout directory.
            command = Engine._ACTION_PATH.sub("./", Engine._runs(hook.command))
            for token in re.split(r"[\s;&|]+", command):
                candidate = token.strip("\"'")
                runner, previous = previous, PurePosixPath(candidate).name
                if not candidate or candidate.startswith("-"):
                    continue
                if runner in JS_RUNNERS and "." not in PurePosixPath(candidate).name.strip("."):
                    # What a JavaScript runner is handed is a module, resolved the way Node
                    # resolves one: `node setup` is `setup.js`, `node scripts/postinstall` is
                    # `scripts/postinstall.js`, `node .` is the package's `index.js`, and
                    # `node bin/preinstall` is that file, extension or not. Skipped as program
                    # names, 40 published packages' own hooks read as opaque, and a payload in
                    # `setup.js` reached this way was never install-time code (review 98).
                    stem = posixpath.normpath(str(base / candidate))
                    if stem.startswith(".."):
                        continue
                    for resolved in (
                        stem,
                        *(f"{stem}{suffix}" for suffix in (".js", ".cjs", ".mjs", ".ts")),
                        *(f"{stem}/index{suffix}" for suffix in (".js", ".cjs", ".mjs")),
                    ):
                        if resolved in known:
                            found.add(resolved)
                            break
                    continue
                if candidate in known:
                    # A command that names a member by its scan path, as a CRAN DESCRIPTION's
                    # `sh <archive>!<pkg>/configure` does: that file runs at install, whatever
                    # its extension. Exact membership only.
                    found.add(candidate)
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
        degrading = [f for f in produced if f.degrades_coverage]
        if any(f.detector in ADVISORY_DETECTORS for f in degrading):
            acc.advisory_complete = False
        if any(f.detector not in ADVISORY_DETECTORS for f in degrading):
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
