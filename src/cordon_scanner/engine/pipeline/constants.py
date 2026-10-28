"""The fixed facts a scan works with: rule ids the engine reports itself, file names that mean a
build or an install hook, the thresholds that fold repeated findings, and the shapes the archive
and release checks look for.

Held apart from the engine's phases so each phase imports what it needs, and none of them imports
the engine.
"""

from __future__ import annotations

import re
from typing import Final

from cordon_scanner.foundation.models import (
    Confidence,
    RiskScore,
    Severity,
)

NO_RISK = RiskScore(value=0, base=0, confidence_multiplier=1.0)

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
`ResultFolding.key_table`."""

PRIVATE_KEY_RULE = "SECRET.PRIVATE_KEY.001"
PRIVATE_KEY_CORPUS = 5
"""How many key files in one directory make it a corpus rather than a disclosure.

One or two is what a leak looks like. Five is a hierarchy somebody generated, and
every repository that implements TLS has at least one such directory. See
`ResultFolding.key_corpus`."""

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
See `ResultFolding.polyglot_corpus`."""

POLYGLOT_CORPUS_CEILING = Severity.MEDIUM
"""What a collapsed polyglot corpus reports at. The same step down a key corpus takes."""

MIN_IDIOM_FILES = 10
MIN_IDIOM_SNIPPET = 40
"""When the same construct in many files becomes one finding.

Ten files, and a snippet specific enough that ten copies cannot be coincidence. See
`ResultFolding.idiom`, which explains why both numbers are needed."""

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
SECRET_LINK_TARGET: Final = re.compile(
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

JS_PATH_SEGMENTS = r"""((?:\s{0,4}['"`][\w@./-]{1,120}['"`]\s{0,4},?){1,8})"""
JS_DIRECTORY_VARIABLE = re.compile(
    r"""\b(?:const|let|var)\s{1,4}(?P<name>[\w$]{1,60})\s{0,4}=\s{0,4}path\s{0,4}\.\s{0,4}(?:join|resolve)"""
    r"""\s{0,4}\(\s{0,4}__dirname\s{0,4},""" + JS_PATH_SEGMENTS + r"""\)"""
)
"""`const vendorDir = path.resolve(__dirname, "../../vendor/scrypt-js")`: a directory a script names."""

JS_JOINED_PATH = re.compile(
    r"""path\s{0,4}\.\s{0,4}(?:join|resolve)\s{0,4}\(\s{0,4}(?P<base>[\w$]{1,60})\s{0,4},"""
    + JS_PATH_SEGMENTS
    + r"""\)"""
)
"""`path.join(vendorDir, "version.js")`: a file under it (`bcryptance` 6.5.2, review 98)."""

JS_CLOSURE_LIMIT = 500
"""Files followed from install-hook scripts, like the Python closure's bound."""

INLINE_REQUIRE = re.compile(r"""require\(\s{0,4}['"](\.{1,2}/[^'"\s]{1,200})['"]\s{0,4}\)""")
#: Programs whose argument is a JavaScript or TypeScript module, resolved as Node resolves one.
JS_RUNNERS = frozenset({"node", "nodejs", "tsx", "ts-node", "bun"})
"""A relative `require` inside an inline `node -e` lifecycle command."""

PRINTING_COMMANDS = frozenset({"echo", "printf"})
"""Commands whose arguments are text for a person, not code to run.

A lifecycle script that prints instructions is the commonest `postinstall` there
is, and the instructions it prints name commands. See `Hooks.runs`."""


PACKAGED_BUILD_FILENAMES = frozenset({"setup.py", "conanfile.py"})
"""Build filenames that are ordinary module names as well.

`setup.py` is the one that matters and `conanfile.py` has the same property:
both are plain Python names, both are common words, and neither can be a build
file from inside a package directory -- a packaging script sits at a
distribution root, not next to an `__init__.py`. See `Hooks.hook_executes`.
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
BROAD_EXCLUSION_SHARE = 0.8
BROAD_EXCLUSION_MIN_FILES = 25


__all__ = [
    "ADVISORY_DETECTORS",
    "ALWAYS_RUN",
    "ARCHIVE_ESCAPE_RULE",
    "ARCHIVE_LINK_TO_SECRET_RULE",
    "ARCHIVE_NESTING_RULE",
    "ARCHIVE_PADDED_RULE",
    "ARCHIVE_POLYGLOT_RULE",
    "ARCHIVE_SLICE",
    "AUTHOR_TIME_FILENAMES",
    "AUTHOR_TIME_PREFIXES",
    "BLINDING_SETTINGS",
    "BROAD_EXCLUSION_MIN_FILES",
    "BROAD_EXCLUSION_SHARE",
    "BUILD_HOOK_FILENAMES",
    "CERTIFICATE_BLOCK",
    "CI_HOOK_FILENAMES",
    "CI_HOOK_PREFIXES",
    "COMPILED_SOURCE",
    "CONDA_LINK_SCRIPT",
    "CREDENTIAL_NAME_CEILING",
    "CREDENTIAL_NAME_FILES",
    "DEPENDENCY_BUILD_FILENAMES",
    "DEPENDENCY_BUILD_SUFFIXES",
    "DER_STRING",
    "DROP_POINT_SECRETS",
    "HONOURED_PINS",
    "INCOMPLETE_WHEN_REPORTED",
    "INLINE_REQUIRE",
    "JS_CLOSURE_LIMIT",
    "JS_DIRECTORY_VARIABLE",
    "JS_JOINED_PATH",
    "JS_LOCAL_REFERENCE",
    "JS_PATH_SEGMENTS",
    "JS_RUNNERS",
    "KEY_CORPUS_CEILING",
    "KEY_CORPUS_CONFIDENCE",
    "KEY_TABLE_SIZE",
    "KNOWN_MALICIOUS_RELEASE_RULE",
    "MACHO_MAGIC",
    "MAKEFILES",
    "MAKE_AT_INSTALL",
    "MAX_REPEAT_PATHS_LISTED",
    "MIN_IDIOM_FILES",
    "MIN_IDIOM_SNIPPET",
    "NATIVE_IN_PURE_WHEEL_RULE",
    "NATIVE_LOAD",
    "NATIVE_MAGIC",
    "NO_RISK",
    "NPM_PLACEHOLDER_VERSION",
    "PACKAGED_BUILD_FILENAMES",
    "POLYGLOT_CORPUS",
    "POLYGLOT_CORPUS_CEILING",
    "POLYGLOT_RULE",
    "PRINTING_COMMANDS",
    "PRIVATE_KEY_CORPUS",
    "PRIVATE_KEY_RULE",
    "PROJECT_BUILD_FILENAMES",
    "PURE_WHEEL",
    "REGISTRY_REVIEW_RULE",
    "REPOSITORY_SCOPE",
    "SECRET_LINK_TARGET",
    "SHIPPED_DOCUMENTS",
    "STANDALONE_SCRIPTS",
    "SWEPT_NOTE",
    "TEST_IDENTITY",
    "UNEXAMINED_INSTALL_RULE",
    "YOUNG_DEPENDENCY_RULE",
]
