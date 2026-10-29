"""Compiled artefacts, and files that are not what their name says.

Every other detector in this project reads source. A binary has none, so the
content rules open with `if content.is_binary: return ()` and a committed
executable was reported only as a note saying it was not examined -- which is
honest, and is also the whole opportunity: a payload that would be obvious as a
script is invisible as an `.so`, and nobody diffs it.

Three questions are answerable without decompiling anything, and they are the
ones that matter most often.

**Is this an executable, and should it be here?** A source repository holds
source. A committed ELF, PE or Mach-O binary is unusual on its own and
significant where it will run: under a package's `scripts/` directory, beside an
install hook, in a git hook directory. The context is doing the work here, not
the file format.

**Does the content agree with the name?** A `.png` whose bytes are a ZIP, or a
`.jpg` that starts with `#!/bin/sh`, is a polyglot -- a file crafted so that the
thing inspecting it and the thing running it disagree about what it is. That
disagreement is the finding; there is no benign reason to arrange one.

**What strings does it carry?** A URL, a shell command or a credential path
inside a committed binary says what it reaches for, and costs one bounded pass
over the bytes. This is not static analysis of the machine code and does not
pretend to be. Deep analysis belongs in a disassembler; presence, context and
strings are available now and catch the common case.

The honest boundary: none of this decides what a binary *does*. A packed
executable is reported as packed, not as malware, and a clean report here means
the questions above had unremarkable answers -- not that the binary was
understood.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.binary.magic import FORMATS, Format, MachO
from cordon_scanner.detect.binary.rule_declarations import DECLARED_RULES, DETECTOR
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets.secrets import RULE_MATERIAL_CEILING
from cordon_scanner.foundation.models import (
    Category,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.foundation.paths import ContainerPaths
from cordon_scanner.foundation.scoring import ScoringContext
from cordon_scanner.foundation.text.prose import Prose

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import Unit
    from cordon_scanner.foundation.content import FileContent

INTERCHANGEABLE_KINDS = frozenset({"image", "archive"})
"""Kinds whose members differ only in how they encode the same thing.

Within one of these, two formats confused is a naming error rather than a
disguise. A PNG saved as `.jpg` renders as a picture either way, executes
nothing either way, and conceals nothing from anybody: `geekxh/hello-algorithm`
held 458 of them -- every screenshot exported as PNG and written under a `.jpg`
name -- and image extensions accounted for 1,866 of the 1,980 format-mismatch
findings across the 1,487-repository corpus. A `.tar.gz` renamed `.zip` is the
same shape one kind over.

Executables are deliberately NOT here. A shell script named `.so`, or a Java
class named `.dylib`, is exactly the substitution the rule exists to notice, and
both would be silenced by comparing kinds alone. Nor is `data`, which is a
default rather than a claim that two formats mean the same thing."""

NATIVE_FORMATS = frozenset({"ELF executable", "PE executable", "Mach-O executable"})
"""Compiled machine code for one platform or another. Swapped for each other they are a build's
naming convention; a script or a Java class in their place is still a disguise -- reported, and for
a shell script, which every shell rule reads by its shebang, recorded at low."""

PACKERS: tuple[tuple[tuple[bytes, ...], str], ...] = (
    ((b"UPX!", b"UPX0", b"UPX1"), "UPX"),
    ((b"$Info: This file is packed with the UPX",), "UPX"),
    ((b"MEI\x0c\x0b\x0a\x0b\x0e",), "PyInstaller"),
    ((b".MPRESS1",), "MPRESS"),
    ((b".MPRESS2",), "MPRESS"),
    ((b".themida",), "Themida"),
)
"""Packer signatures: what each packer writes into its output, every part required.

The section names a packer adds (`UPX0`/`UPX1` beside the `UPX!` stamp, `.MPRESS1`, `.themida`)
and PyInstaller's archive cookie -- not the packer's name as a word. `MPRESS` alone is the middle
of `COMPRESSED`, and matched in Java classes, Android DEX files and debug symbols: 569 of the long
tail's benign units carried this finding, nearly all of them for that (review 98). Fourteen of
4,269 malware samples had it and none was blocked by it alone.

A packed binary is reported as packed and nothing more. Packing has legitimate
uses -- installers and single-file distributions are packed -- so the finding
says what was observed rather than what it means, and leaves the conclusion to
somebody who knows whether this project ships a packed artefact."""

#: A wheel's data directory holding scripts (`buf_bin-1.73.0.data/`), at the end of a path.
_WHEEL_SCRIPTS: Final = re.compile(r"(?:^|/)[A-Za-z0-9_.]+-[^/]+\.data/$")

EXECUTING_DIRECTORIES = (
    "scripts/",
    ".githooks/",
    "hooks/",
    "postinstall/",
)
"""Path fragments where a committed binary is not merely present but reachable.

The format is the same; the context is what changes the severity. A vendored
`.so` under `vendor/` is a build artefact somebody checked in. The same file
under `scripts/` is something a lifecycle step runs.

`bin/` was here and is not a lifecycle location: it is where a program puts its OWN
executables, which is the documented place for them rather than a surprising one.
Elasticsearch ships `distribution/src/bin/elasticsearch-service-x64.exe` and
`elasticsearch-service-mgr.exe` as the Windows service it installs, and both were
reported at HIGH as sitting "where a lifecycle step will run it". They sit where a
user runs them.

Nothing stops being reported: the other branch emits
`POLICY.BINARY.COMMITTED.001`, which is the accurate statement - a binary was
committed, and a binary is unreviewable wherever it lives."""

SOURCE_TREES = (
    "/src/",
    "/lib/",
    "/app/",
    "/internal/",
    "/pkg/",
    "/source/",
)
"""Directories whose contents are source, where a `scripts/` below is part of it.

`microsoft/vscode` ships PowerShell's PSReadLine module at
`src/vs/workbench/contrib/terminal/common/scripts/psreadline/
Microsoft.PowerShell.PSReadLine.dll` -- a library the integrated terminal loads at
runtime, seven directories inside the source tree. A `scripts/` that deep is a module
of the program; the lifecycle directory this rule is about is the one near the root,
which is where a package manager and a git hook look.

Named as a closed list rather than bounded by depth, because a monorepo's
`packages/server/scripts/postinstall.sh` is at the same depth and IS a lifecycle
location."""

NOT_LIFECYCLE_RUNNABLE = frozenset({"WebAssembly", "Java class"})
"""Executable formats that no lifecycle step can invoke.

A `.wasm` module has no entry point an operating system or a shell can start: it is
instantiated by a host runtime that has to be written to load it. `excalidraw` keeps
`scripts/wasm/hb-subset.wasm`, the HarfBuzz subsetter its font pipeline calls from
JavaScript, and the finding said it "sits where a lifecycle step will run it", which
is not something that can happen.

A Java class is the same: only a JVM given a classpath starts it, and in a JAR its directory is
its Java package (`Typechecker.jar!ksp/hooks/...class`), not a hooks directory: 57 legitimate
PyPI blocks, no malware in any archived set.

It still reports as a committed binary through the other branch, which is the true
statement about it."""

MAX_STRINGS_BYTES = 1 << 20
"""How much of a binary to read strings from. The interesting content in a
dropper is near the start, and an unbounded pass over a 400MB artefact is a
scan nobody waits for."""

MIN_STRING_LENGTH = 8

_URL = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,200}")

_COMMAND = re.compile(
    # No leading `\b`. A word boundary needs a word character on one side, and
    # in a binary these strings sit between NUL bytes -- `\x00/bin/sh\x00` has
    # non-word characters on both sides, so the assertion fails exactly where
    # this pattern is meant to run. It is the only place the pattern is used.
    rb"(?:/bin/(?:sh|bash)|cmd\.exe|powershell(?:\.exe)?|curl\s+-|wget\s+"
    rb"|chmod\s\+x|crontab\s+-|schtasks\s+/create)"
)

_FONT_SIGNATURES: tuple[tuple[tuple[str, ...], bytes, int], ...] = (
    ((".ttf",), b"\x00\x01\x00\x00", 0),
    ((".ttf", ".otf"), b"OTTO", 0),
    ((".ttc",), b"ttcf", 0),
    ((".woff",), b"wOFF", 0),
    ((".woff2",), b"wOF2", 0),
    # Embedded OpenType keeps its magic after a header of lengths and versions.
    ((".eot",), b"LP", 34),
)
"""Font files: the extensions each is stored under, its magic, and where the magic sits."""

_CREDENTIAL_PATH = re.compile(
    rb"(?:\.ssh/id_[a-z0-9_]{1,20}|\.aws/credentials|\.npmrc|\.pypirc|\.docker/config\.json"
    rb"|Login\s?Data|wallet\.dat)"
)

SOURCE_TEXT_EXTENSIONS = frozenset(
    {
        ".py",
        ".pyw",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".rb",
        ".php",
        ".pl",
        ".lua",
        ".sh",
        ".bash",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".vbs",
        ".txt",
        ".md",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".cfg",
        ".ini",
        ".xml",
        ".html",
        ".css",
        ".csv",
    }
)
"""Extensions that promise text. A native executable under one of these names is a disguise."""

NUL_FREE_SOURCE_EXTENSIONS = frozenset(
    {".py", ".pyw", ".js", ".mjs", ".cjs", ".rb", ".php", ".pl", ".lua", ".sh", ".bash"}
)
"""Source languages in which a NUL byte never appears. See `BinaryDetector.binary_source`.

Not `.ts`: the extension is as often an MPEG transport stream (video) or a Java truststore
(ActiveMQ's `conf/broker.ts`) as TypeScript, and a binary one is those. A PHP file is judged only
when it does not open as PHP: PHP strings are binary-safe, and protobuf's generated
`GPBMetadata/*.php` carries its descriptor as raw bytes inside one."""


class BinaryDetector(BaseDetector):
    """Examines committed binaries and files whose bytes contradict their name."""

    id = DETECTOR
    # 0.2.0: a mismatch between two formats of one interchangeable kind is a naming
    # error rather than a disguise, and the format table knows five more image formats.
    # See the note on `SecretDetector.version` for why this number matters.
    version = "0.7.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return DECLARED_RULES

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        raw = content.raw
        if not raw:
            return ()

        found = self.identify(raw)
        findings: list[Finding] = []

        # An LFS pointer does not contradict its name; the content it names is on a
        # server and was never fetched. Reporting it as a forgery says the repository
        # is lying about a file when the truth is that the checkout is partial.
        #
        # Reported as OPERATIONAL instead, because a file that was not examined must
        # not look like a file that was examined and found clean - which is the
        # invariant this whole detector set is built around.
        # A file in an image past the per-file limit is scanned as its printable strings, under
        # its own name. Its format is judged from its real first bytes, which the image reader
        # keeps: judged from the strings, every large `.so`, `.dll` and `.jar` in 36 of 650 real
        # images read as disguised (review 98), and skipping the check instead would let a
        # disguised executable hide by being padded past the limit.
        head = BinaryDetector.real_head(content.path, ctx)
        judged = raw if head is None else head
        named = found if head is None else self.identify(head)
        own_format = self.named_by_its_own_format(content.path, judged)
        mismatch = (
            None
            if content.is_lfs_pointer or own_format or self.damaged_in_transit(content.path, judged)
            else self.mismatch(content.path, named)
        )
        if mismatch is None and named is None and not content.is_lfs_pointer and not own_format:
            mismatch = self.binary_source(content.path, judged)
        self._mismatch_finding(content, ctx, findings, judged, mismatch, named, unit)

        if found is not None and found.executable and found.name != "shell script":
            findings.extend(self._executable_findings(unit, ctx, content, found))
            return findings

        # A recognised, non-executable format is what it says it is. A PNG
        # containing the string "https://" is a screenshot of a browser, and
        # reporting it as a binary carrying a URL is noise -- it happened on
        # Flask's own documentation images. The strings pass exists for things
        # that might run, not for everything that is not text.
        #
        # A shell script with a shebang is source, and every content rule
        # already reads it; reporting it here would double every script in
        # every repository.
        if found is not None:
            return findings

        # Not a recognised format, but not text either. This is the case that
        # matters most, because it is what an attacker produces on purpose:
        # `is_binary` is anchored at offset zero by design, so prepending
        # `/* NUL */` to an ELF stops it being an executable *and* stops it
        # being identified. The file is still not text, still contains whatever
        # it contained, and must not become silent -- so the content checks run
        # on what the bytes actually hold rather than on what the header claims.
        if self._looks_binary(raw) and not self._is_font(content.path, raw):
            findings.extend(self._content_findings(unit, ctx, content))

        return findings

    def _mismatch_finding(
        self,
        content: FileContent,
        ctx: ScanContext,
        findings: list[Finding],
        judged: bytes,
        mismatch: str | None,
        named: Format | None,
        unit: FileUnit,
    ) -> None:
        """The finding for a file whose bytes say one format and whose name says another, graded down where the pair is a known benign one."""
        if mismatch is not None:
            finding = self._finding("SUSPECT.POLYGLOT.MISMATCH.001", unit, ctx, mismatch)
            if (
                named is None
                and self._promises_a_binary_format(content.path)
                and not self._reads_as_code(judged)
            ):
                # The name promises an image, an archive or a document, and the bytes are no
                # format at all and no code either: a damaged or truncated file, a placeholder,
                # an encrypted secret named for what it decrypts to. Nothing opens it as the
                # name says and nothing runs it, so it is recorded. In the long tail these were
                # test screenshots, `secrets/*.conf.png` and broken fixtures (review 98). A
                # recognised executable or script under such a name is a disguise and keeps
                # the declared grade; so does text that reads as code.
                finding = replace(
                    finding,
                    severity=min(finding.severity, Severity.LOW),
                    message=finding.message
                    + " Its bytes are no recognised format and do not read as code, so it is "
                    "recorded rather than raised.",
                )
            elif (
                named is not None
                and named.name == "shell script"
                and self._names_a_native_program(content.path)
            ):
                # A launcher script under a compiled program's name: a `bin/cli.exe` that is
                # `#!/bin/sh` (review 98: 3 of the npm work set's 10 legitimate blocks by this rule
                # alone). The name still misleads a person, so it is recorded. It hides nothing
                # from this scan, which reads the file by its shebang with every shell rule: what
                # the script does is judged on its own.
                finding = replace(
                    finding,
                    severity=min(finding.severity, Severity.LOW),
                    message=finding.message
                    + " Every shell rule reads it by its shebang, so it is recorded rather than "
                    "raised.",
                )
            findings.append(finding)

    #: What code looks like when nothing announces its format: a script's opening, a call that
    #: runs or loads something, a language's markers. Read in the first few kilobytes.
    # Each run here is taken once (possessive; review 98, 27-PERFORMANCE): runs that can take the
    # same characters, with only optional items between them, split one stretch every way.
    _CODE_MARKERS: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?i)<\?php|<script\b|@echo\s+off|\bpowershell\b|cmd(?:\.exe)?\s+/c\b|\beval\s*\("
        rb"|\bexec\s*\(|\brequire\s*\(|\bimport\s+[\w.]+|\bfunction\s*+[\w$]*+\s*+\("
        rb"|\b(?:var|const|let)\s+[\w$]+\s*=|\bdef\s+\w+\s*\(|\bInvoke-\w+|\bSet-\w+"
        rb"|\bWScript\.|\bCreateObject\s*\(|/bin/(?:ba)?sh\b|\bcurl\s+-|\bwget\s+"
        # What an image or document processor executes: ImageMagick's MVG (ImageTragick), HTML,
        # an XML entity declaration, PostScript, and what SVG runs or fetches. A plain SVG saved
        # under `.png` draws shapes; one with a handler, a script URL, a fetched or piped
        # `href` or a `url()` is not plain.
        rb"|push\s+graphic-context|<html\b|<!doctype\b|<iframe\b|<!ENTITY\b|%!PS"
        rb"|<foreignObject\b|\bon[a-z]{3,20}\s*=|javascript:"
        rb"|(?:href\s*=\s*[\"']|url\(\s*[\"']?)(?:\||(?:https?|file|msl|text|ephemeral):)"
    )

    @staticmethod
    def _reads_as_code(raw: bytes) -> bool:
        return BinaryDetector._CODE_MARKERS.search(raw[:8192]) is not None

    @staticmethod
    def _promises_a_binary_format(path: str) -> bool:
        """The name is an extension one of the non-executable formats is stored under."""
        name = ContainerPaths.basename(path).lower()
        _, dot, extension = name.rpartition(".")
        if not dot:
            return False
        promised = next((f for f in FORMATS if f".{extension}" in f.extensions), None)
        return promised is not None and not promised.executable

    @staticmethod
    def _names_a_native_program(path: str) -> bool:
        """The name is an extension compiled machine code is stored under (`.exe`, `.so`, ...)."""
        _, dot, extension = ContainerPaths.basename(path).lower().rpartition(".")
        return bool(dot) and any(
            f.name in NATIVE_FORMATS and f".{extension}" in f.extensions for f in FORMATS
        )

    @staticmethod
    def _is_font(path: str, raw: bytes) -> bool:
        """A font, by its name and its own magic both: data a text renderer reads, never run.

        An icon font is a table of glyph names -- `terminal`, `console`, `bash` -- beside the
        foundry's URL, so the strings check read Material Design Icons and VS Code's codicons
        as a binary holding a URL and a shell command. Both tests, because four bytes of
        TrueType magic alone would let any blob opt out of the content checks.
        """
        name = path.rsplit("!", 1)[-1].lower()
        for extensions, magic, offset in _FONT_SIGNATURES:
            if name.endswith(extensions) and raw[offset : offset + len(magic)] == magic:
                return True
        return False

    @staticmethod
    def _opens_as_php(head: bytes) -> bool:
        """`<?php` before any NUL: the bytes after it sit inside PHP, which reads binary strings."""
        stripped = head.lstrip(b"\xef\xbb\xbf \t\r\n")
        return stripped[:5].lower() == b"<?php" and b"\x00" not in stripped[:5]

    @staticmethod
    def real_head(path: str, ctx: ScanContext) -> bytes | None:
        """The real first bytes of an image member scanned as its strings, else None."""
        if ctx.image is None:
            return None
        member = path.partition("!")[2]
        if "!strings-" in member:
            return b""  # a later part of the strings: nothing about the format to judge
        strings: bytes | None = ctx.image.as_strings.get(member)
        return strings

    @staticmethod
    def _looks_binary(raw: bytes) -> bool:
        """Whether the bytes are unlike text, regardless of any header.

        Deliberately not `FileContent.is_binary`, which asks a different and
        narrower question -- what format is this -- and answers it from offset
        zero so that a prepended comment cannot rename a payload into being
        skipped. Here the question is whether there is anything to read strings
        out of.
        """
        return b"\x00" in raw[:8192]

    # -- Identification --------------------------------------------------

    @staticmethod
    def identify(raw: bytes) -> Format | None:
        """The format these bytes begin with, if it is one we recognise."""
        head = raw[:16]
        if head.startswith(b"\xca\xfe\xba\xbe") and not MachO._is_fat_macho(head):
            # Shared magic, decided by what follows it. Reached before the
            # loop because Mach-O is listed first and would otherwise claim
            # every Java class file.
            return next(f for f in FORMATS if f.name == "Java class")
        for fmt in FORMATS:
            if any(head.startswith(magic, fmt.offset) for magic in fmt.magic):
                return fmt
        return None

    @staticmethod
    def damaged_in_transit(path: str, raw: bytes) -> bool:
        """Whether the bytes are the format the name promises, with its line endings rewritten.

        PNG's signature carries `\r\n` and `\n` so that a transfer which rewrites line endings
        breaks it detectably, and that is what git's text conversion does to a binary committed
        without `-text`: `\x89PNG\r\n\x1a\n` arrives as `\x89PNG\n\x1a\n`. The file is a
        damaged image, not a disguise -- a repository kept 128 of them in `static=broken/`
        (review 98). Nothing runs a damaged PNG, and a script under the name still has no such
        signature in front of it.
        """
        extension = "." + ContainerPaths.basename(path).lower().rpartition(".")[2]
        promised = next((f for f in FORMATS if extension in f.extensions), None)
        if promised is None:
            return False
        for magic in promised.magic:
            if b"\n" not in magic:
                continue
            for rewritten in (magic.replace(b"\r\n", b"\n"), magic.replace(b"\n", b"\r\n")):
                if rewritten != magic and raw.startswith(rewritten, promised.offset):
                    return True
        return False

    @staticmethod
    def binary_source(path: str, raw: bytes) -> str | None:
        """Binary data under the name of a language whose interpreter never reads it.

        CPython refuses source containing a NUL byte, and no JavaScript, Ruby, PHP, Perl or Lua
        file has one either -- so a `.py` with NULs is not source with odd bytes, it is something
        else wearing a source name: an executable with a few bytes in front, an archive, a blob
        the package opens by path. Text formats that are commonly UTF-16 (PowerShell, batch,
        XML, plain text) carry NULs legitimately and are not judged here.
        """
        extension = "." + ContainerPaths.basename(path).lower().rpartition(".")[2]
        if extension not in NUL_FREE_SOURCE_EXTENSIONS:
            return None
        head = raw[:1024]
        if b"\x00" not in head or head.startswith((b"\xff\xfe", b"\xfe\xff")):
            return None
        if extension == ".php" and BinaryDetector._opens_as_php(head):
            return None
        return (
            f"named {extension} but its contents are binary data, which no interpreter for it reads"
        )

    LD_DIRECTIVE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"(?:INPUT|GROUP|OUTPUT_FORMAT|OUTPUT_ARCH|AS_NEEDED|SEARCH_DIR|TARGET)\s*\(|\)"
    )

    @staticmethod
    def _ld_script(raw: bytes) -> bool:
        """A small text file of nothing but linker directives and comments."""
        if len(raw) > 4096 or not raw.isascii() or b"\x00" in raw:
            return False
        body = re.sub(rb"/\*.*?\*/", b"", raw, flags=re.S)
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        return bool(lines) and all(BinaryDetector.LD_DIRECTIVE.match(line) for line in lines)

    @staticmethod
    def named_by_its_own_format(path: str, raw: bytes) -> bool:
        """Files whose name and content disagree by the design of the tool that wrote them.

        Judged by their own signatures, never by the name alone, so a payload cannot borrow the
        exemption by being called `._x.png`:
        - AppleDouble: macOS's archiver stores each file's resource fork beside it as `._name`,
          with the original name and the signature `00 05 16 07` -- every zip made on a Mac
          carries them under `__MACOSX/`;
        - an OS/2 bitmap-array icon (`BA` and a 40-byte header), the format `.ico` began as;
        - a compiled terminfo entry under `terminfo/`, named for its terminal (`xterm.js`);
        - a GNU ld linker script named as the library it stands for: `libgcc_s.so` and
          `libncurses.so` in conda and biocontainers images are `GROUP ( ... )` text that tells
          the linker which real libraries to use (review 98). Every line has to be a linker
          directive, so what passes can only name libraries.
        """
        if raw.startswith(b"\x00\x05\x16\x07"):
            return True
        if ".so" in ContainerPaths.basename(path).lower() and BinaryDetector._ld_script(raw):
            return True
        name = ContainerPaths.basename(path).lower()
        if name.endswith(".ico") and raw.startswith(b"BA(\x00\x00\x00"):
            return True
        return "/terminfo/" in f"/{path}" and raw[:2] in (b"\x1a\x01", b"\x1e\x02")

    @staticmethod
    def mismatch(path: str, found: Format | None) -> str | None:
        """A description of how the content contradicts the name, if it does.

        Only extensions with a settled meaning are checked, and only against
        formats that declare one. Being wrong here means calling an ordinary
        file a forgery, so the question asked is narrow: does this name promise
        a specific format, and do the bytes say something else?
        """
        name = ContainerPaths.basename(path).lower()
        _, dot, extension = name.rpartition(".")
        if not dot:
            return None
        extension = f".{extension}"

        promised = next((f for f in FORMATS if extension in f.extensions), None)
        if (
            found is not None
            and found.executable
            and found.name != "shell script"
            and extension in SOURCE_TEXT_EXTENSIONS
        ):
            # Source has no required first bytes, but it does have forbidden ones: no interpreter
            # parses `MZ` or `\x7fELF`. A compiled program named `_build.py` is something the
            # package loads by path while every reader of its source skips it as text.
            return f"named {extension} but its contents are {Prose.article(found.kind)} {found.name} {found.kind}"
        if promised is None:
            # The name promises nothing checkable. Source extensions land here,
            # which is correct: a `.py` file has no required first bytes.
            return None

        if found is None:
            # The name promises a binary format and the bytes are not one. A
            # `.png` holding a script is the case this exists for.
            return f"named {extension} but its contents are not {promised.name.lower()}"

        if found is promised:
            return None
        if extension in found.extensions:
            # Shared extensions: `.o` is both ELF and Mach-O, `.jar` is a ZIP.
            return None
        if found.name in NATIVE_FORMATS and promised.name in NATIVE_FORMATS | {"WebAssembly"}:
            # One platform's binary under another's extension: dune names every Linux ELF
            # `main.exe`, and cross-built npm packages ship `tool-linux-x64.exe` (review 98: 40
            # of 201 benign units). It is a compiled program either way, judged as one by the
            # executable rules; what the name hides from is a reader of text, which neither is.
            return None
        if found.name == "WebAssembly" and promised.name in NATIVE_FORMATS:
            # Emscripten names a side module `.so`; it runs only inside a WebAssembly runtime.
            return None
        if found.kind == promised.kind and found.kind in INTERCHANGEABLE_KINDS:
            # A naming error rather than a disguise: a PNG saved as `.jpg` runs
            # no differently and hides nothing. See `INTERCHANGEABLE_KINDS`,
            # which is narrow for a reason.
            return None
        if found.kind == promised.kind:
            # Naming the kinds twice says nothing. A shell script and an ELF are both
            # `executable`, so the sentence read "an executable rather than an executable"
            # -- which is how the `.dll` and `.o` mismatches were found, because the
            # message was the thing that showed the comparison had nothing to say.
            return (
                f"named {extension} but its contents are {found.name.lower()} "
                f"rather than {promised.name.lower()}"
            )
        return (
            f"named {extension} but its contents are {found.name.lower()}, "
            f"{Prose.article(found.kind)} {found.kind} rather than "
            f"{Prose.article(promised.kind)} {promised.kind}"
        )

    # -- Executables -----------------------------------------------------

    def _executable_findings(
        self, unit: FileUnit, ctx: ScanContext, content: FileContent, found: Format
    ) -> Iterable[Finding]:
        path = content.path
        lowered = f"/{path.lower()}"

        in_lifecycle_directory = any(
            fragment in lowered
            for fragment in EXECUTING_DIRECTORIES
            # And not a `scripts/` that is part of a source tree. See `SOURCE_TREES`.
            if not any(tree in lowered.split(fragment, 1)[0] + "/" for tree in SOURCE_TREES)
        ) and not self._virtualenv_launcher(path, ctx)
        if found.name not in NOT_LIFECYCLE_RUNNABLE and (
            in_lifecycle_directory or ctx.in_install_hook(path)
        ):
            yield self._finding(
                "SUSPECT.BINARY.EXECUTABLE_PATH.001",
                unit,
                ctx,
                f"{Prose.article(found.name)} {found.name} sits where a lifecycle step will run it",
            )
        elif ctx.image is None:
            # In a container image a binary is the point, not a policy question; what it carries
            # is still examined below.
            yield self._finding(
                "POLICY.BINARY.COMMITTED.001",
                unit,
                ctx,
                f"{Prose.article(found.name)} {found.name} is committed to a source tree",
            )

        yield from self._import_findings(unit, ctx, content, found)
        yield from self._content_findings(unit, ctx, content, executable=True)

    @staticmethod
    def _virtualenv_launcher(path: str, ctx: ScanContext) -> bool:
        """A `scripts/` no lifecycle step runs: a wheel's installed commands, or a Windows virtual
        environment's own `Scripts/` (`pip.exe`, a console script's launcher), the directory above
        holding the environment's `pyvenv.cfg`. No lifecycle step runs it; an
        sdist that ships one has packaged its build environment by mistake (review 98 G6). What an
        install hook names is still reported, and the binary is still read."""
        cut = path.lower().rfind("scripts/")
        if cut < 0 or (cut > 0 and path[cut - 1] != "/"):
            return False
        # A wheel's `<name>-<version>.data/scripts/`: the wheel format installs these as the
        # package's commands, and no install step runs them (`buf-bin`, `litestream-bin` ship their
        # tool so). 34 legitimate PyPI blocks; none of 5,459 PyPI malware releases had one.
        if _WHEEL_SCRIPTS.search(path[:cut]):
            return True
        return f"{path[:cut]}pyvenv.cfg" in ctx.tree_paths

    def _import_findings(
        self, unit: FileUnit, ctx: ScanContext, content: FileContent, found: Format
    ) -> Iterable[Finding]:
        """What the binary can do, from the calls its own import table names (G12)."""
        from cordon_scanner.detect.binary.imports import ImportCapabilities, ImportReader

        table = ImportReader.read(content.raw)
        if table is None:
            return
        binding = ImportCapabilities.is_binding(table)
        # Cygwin's and MSYS2's POSIX layer builds `fork()` from another process's memory and
        # threads, so it imports what an injector does (review 98, CDI: two PyPI packages ship it).
        # Its name alone is free to take; its own `cygwin_internal` export is what makes it one.
        runtime = (
            content.path.rsplit("/", 1)[-1].lower() in {"cygwin1.dll", "msys-2.0.dll"}
            and b"cygwin_internal" in content.raw
        )
        profile = ImportCapabilities.profile(table)
        for rule_id, detail in ImportCapabilities.verdicts(profile, content.raw):
            finding = self._finding(
                rule_id, unit, ctx, f"{Prose.article(found.name)} {found.name} that {detail}"
            )
            if (binding or runtime) and rule_id == "SUSPECT.BINARY.PROCESS_INJECTION.001":
                # A language binding imports the API it wraps (FP-10): reported, not blocking.
                because = (
                    " It is a Python or Node binding, which imports the calls it exposes."
                    if binding
                    else " It is the Cygwin POSIX runtime, whose fork() is built from these calls."
                )
                finding = replace(
                    finding,
                    severity=min(finding.severity, Severity.MEDIUM),
                    message=finding.message + because,
                )
            yield finding

    def _content_findings(
        self, unit: FileUnit, ctx: ScanContext, content: FileContent, *, executable: bool = False
    ) -> Iterable[Finding]:
        """What the bytes carry, independent of what the header claims.

        Separate from the executable path so both callers share it. The header
        is the one part of a file an attacker edits for free, and these checks
        are about content -- so tying them to a recognised header would mean a
        prepended comment silences them.
        """
        window = content.raw[:MAX_STRINGS_BYTES]

        packer = next(
            (label for parts, label in PACKERS if all(part in window for part in parts)), None
        )
        if packer is not None:
            yield self._finding("SUSPECT.BINARY.PACKED.001", unit, ctx, f"packed with {packer}")

        observed = self._interesting_strings(window)
        # One kind is not evidence. Almost every data blob carries a URL --
        # a compiled translation catalogue records the project's homepage, a
        # font records its foundry, a test fixture records where it came from
        # -- and reporting on that produced one thousand two hundred findings
        # across twenty-one real repositories, more than half of all the noise
        # they generated. What is worth saying is that a file carries a URL
        # *and* a shell command, or a credential path: a combination a data
        # format has no reason to hold.
        #
        # A program does have reason to hold a URL and a shell command: its help text links
        # its homepage and it runs `/bin/sh`. ripgrep, cargo-clippy, PowerShell's own
        # assemblies and every ad SDK framework do, and in a recognised executable that pair
        # was the only code warning on 268 of the long tail's benign units (review 98) and
        # blocked none of 4,269 malware samples. What a program has no reason to name is
        # someone's credential store, so in an executable that is what it takes.
        if len(observed) >= 2 and (not executable or "a credential path" in observed):
            yield self._finding(
                "SUSPECT.BINARY.STRINGS.001",
                unit,
                ctx,
                ", ".join(observed),
            )

    @staticmethod
    def _interesting_strings(window: bytes) -> list[str]:
        """What kinds of interesting string the binary carries.

        The kinds, never the values. A URL inside a committed binary can be a
        licence link and can be a command-and-control address, and this finding
        travels into CI logs and pull-request comments -- so it says a URL is
        present and leaves reading it to somebody who has the file, which is
        the same discipline the secret detector applies.
        """
        kinds: list[str] = []
        if _URL.search(window):
            kinds.append("a URL")
        if _COMMAND.search(window):
            kinds.append("a shell command")
        if _CREDENTIAL_PATH.search(window):
            kinds.append("a credential path")
        return kinds

    # -- Construction ----------------------------------------------------

    def _finding(self, rule_id: str, unit: FileUnit, ctx: ScanContext, detail: str) -> Finding:
        declared = next(r for r in self.declared_rules() if r.id == rule_id)
        content = unit.content

        # The same ceiling the secrets detector, the composites and the obfuscation
        # rules apply. This detector had none, and a format-mismatch rule needs one
        # more than most: a test suite for an image or archive library is MADE of
        # files whose contents do not match their extension.
        #
        # Measured across 535 repositories, `SUSPECT.POLYGLOT.MISMATCH.001` produced
        # 1,022 findings in 100 of them. FFmpeg's `tests/ref/lavf/apng.png` and its
        # siblings are reference outputs for format tests. Ladybird ships
        # `Tests/LibWeb/.../images/broken.png`, which is broken on purpose and says so
        # in its name. Django's `tests/files/brokenimg.png` contains four bytes.
        #
        # MALICIOUS is never ceilinged, so a real polyglot -- an archive wearing a
        # `.png` extension -- is unaffected wherever it sits, and the detection itself
        # does not change. What changes is whether a library's own corpus of
        # deliberately malformed files fails its build.
        severity = declared.severity
        if declared.category is not Category.MALICIOUS:
            if content.is_rule_material:
                severity = min(severity, RULE_MATERIAL_CEILING)
            elif (
                SourcePaths.is_test_material_here(content.path, ctx)
                or SourcePaths.is_documentation(content.path)
                or SourcePaths.is_generated_artefact(content.path)
                or SourcePaths.is_vendored(content.path)
            ):
                severity = min(severity, FIXTURE_CEILING)

        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=severity,
            confidence=declared.confidence,
            message=f"{content.path}: {detail}.",
            location=Location(path=content.path, line=1, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(content.raw[:4096]),
                # Hash-only, like the secret detector and for the same reason:
                # the content is bytes nobody should paste into a log, and the
                # hash is enough to say "this is the same artefact as before".
                redaction=RedactionMode.HASH_ONLY,
                metadata=(("detail", detail),),
            ),
            remediation=declared.remediation,
            explanation=Explanation(summary=detail, matched_rule=rule_id),
            risk=ctx.scorer.score(
                declared.severity,
                declared.confidence,
                ScoringContext(
                    in_install_hook=ctx.in_install_hook(content.path),
                    capabilities=frozenset(),
                ),
            ),
            detector=self.id,
        )


__all__ = [
    "EXECUTING_DIRECTORIES",
    "INTERCHANGEABLE_KINDS",
    "MAX_STRINGS_BYTES",
    "MIN_STRING_LENGTH",
    "NATIVE_FORMATS",
    "NOT_LIFECYCLE_RUNNABLE",
    "NUL_FREE_SOURCE_EXTENSIONS",
    "PACKERS",
    "SOURCE_TEXT_EXTENSIONS",
    "SOURCE_TREES",
    "BinaryDetector",
]
