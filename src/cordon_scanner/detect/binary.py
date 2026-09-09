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
from dataclasses import dataclass
from typing import TYPE_CHECKING

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
from cordon_scanner.core.paths import basename
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit, ScanContext
from cordon_scanner.detect.catalogue import DeclaredRule

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.core.content import FileContent
    from cordon_scanner.detect.base import Unit


@dataclass(frozen=True, slots=True)
class Format:
    """A file format, recognised by the bytes it starts with."""

    name: str
    magic: tuple[bytes, ...]
    executable: bool = False
    extensions: tuple[str, ...] = ()
    """Extensions this format is normally stored under. Used only to notice
    disagreement; an empty tuple means the format is not tied to a name."""


FORMATS: tuple[Format, ...] = (
    Format("ELF executable", (b"\x7fELF",), executable=True, extensions=(".so", ".o", ".elf")),
    Format("PE executable", (b"MZ",), executable=True, extensions=(".exe", ".dll", ".sys")),
    Format(
        "Mach-O executable",
        (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"),
        executable=True,
        extensions=(".dylib", ".bundle", ".o"),
    ),
    Format("Java class", (b"\xca\xfe\xba\xbe",), executable=True, extensions=(".class",)),
    Format("WebAssembly", (b"\x00asm",), executable=True, extensions=(".wasm",)),
    # No extensions, deliberately. A shebang identifies a script when it is
    # present, but no source extension *promises* one: most Python files have
    # no shebang, and listing `.py` here made every one of them disagree with
    # its own name. Only formats whose files must begin with their magic take
    # part in the mismatch check.
    Format("shell script", (b"#!",), executable=True),
    Format("ZIP archive", (b"PK\x03\x04",), extensions=(".zip", ".jar", ".whl", ".egg", ".apk")),
    Format("gzip archive", (b"\x1f\x8b",), extensions=(".gz", ".tgz")),
    Format("PNG image", (b"\x89PNG\r\n\x1a\n",), extensions=(".png",)),
    Format("JPEG image", (b"\xff\xd8\xff",), extensions=(".jpg", ".jpeg")),
    Format("GIF image", (b"GIF8",), extensions=(".gif",)),
    Format("PDF document", (b"%PDF-",), extensions=(".pdf",)),
)

PACKERS: tuple[tuple[bytes, str], ...] = (
    (b"UPX!", "UPX"),
    (b"$Info: This file is packed with the UPX", "UPX"),
    (b"PyInstaller", "PyInstaller"),
    (b"MPRESS", "MPRESS"),
    (b"Themida", "Themida"),
)
"""Packer signatures.

A packed binary is reported as packed and nothing more. Packing has legitimate
uses -- installers and single-file distributions are packed -- so the finding
says what was observed rather than what it means, and leaves the conclusion to
somebody who knows whether this project ships a packed artefact."""

EXECUTING_DIRECTORIES = (
    "scripts/",
    "bin/",
    ".githooks/",
    "hooks/",
    "postinstall/",
)
"""Path fragments where a committed binary is not merely present but reachable.

The format is the same; the context is what changes the severity. A vendored
`.so` under `vendor/` is a build artefact somebody checked in. The same file
under `scripts/` is something a lifecycle step runs."""

MAX_STRINGS_BYTES = 1 << 20
"""How much of a binary to read strings from. The interesting content in a
dropper is near the start, and an unbounded pass over a 400MB artefact is a
scan nobody waits for."""

MIN_STRING_LENGTH = 8

_URL = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,200}")
_COMMAND = re.compile(
    rb"\b(?:/bin/(?:sh|bash)|cmd\.exe|powershell(?:\.exe)?|curl\s+-|wget\s+"
    rb"|chmod\s\+x|crontab\s+-|schtasks\s+/create)"
)
_CREDENTIAL_PATH = re.compile(
    rb"(?:\.ssh/id_[a-z0-9_]{1,20}|\.aws/credentials|\.npmrc|\.pypirc|\.docker/config\.json"
    rb"|Login\s?Data|wallet\.dat)"
)


class BinaryDetector(BaseDetector):
    """Examines committed binaries and files whose bytes contradict their name."""

    id = "binary"
    version = "0.1.0"
    categories = frozenset({Category.SUSPICIOUS, Category.POLICY})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return (
            DeclaredRule(
                id="POLICY.BINARY.COMMITTED.001",
                title="Executable committed to a source repository",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                # Policy, not suspicion, and deliberately quiet. Vendored native
                # libraries, prebuilt test fixtures and checked-in tools are
                # ordinary in a great many repositories, and calling each of
                # them suspicious is how a reader learns to skip this detector's
                # output entirely. What is worth saying is that the artefact is
                # here and its contents are not derivable from anything in the
                # tree -- which is a visibility statement, not an accusation.
                category=Category.POLICY,
                detector=BinaryDetector.id,
                remediation=(
                    "Build the artefact rather than committing it, so what it "
                    "contains is derivable from source that can be reviewed."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.BINARY.EXECUTABLE_PATH.001",
                title="Executable committed where a lifecycle step will run it",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=BinaryDetector.id,
                remediation=(
                    "Remove it. A binary in a scripts or hook directory runs "
                    "without ever being read."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.BINARY.PACKED.001",
                title="Committed binary is packed",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=BinaryDetector.id,
                remediation=(
                    "Confirm this project ships a packed artefact. Packing is "
                    "ordinary for installers and is also how a payload avoids "
                    "having readable strings."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.BINARY.STRINGS.001",
                title="Committed binary contains a URL, command or credential path",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category=Category.SUSPICIOUS,
                detector=BinaryDetector.id,
                remediation=(
                    "Read what the binary reaches for. A committed artefact that "
                    "names a host and a shell is doing something at runtime that "
                    "no source in this repository describes."
                ),
            ),
            DeclaredRule(
                id="SUSPECT.POLYGLOT.MISMATCH.001",
                title="File contents do not match its extension",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=Category.SUSPICIOUS,
                detector=BinaryDetector.id,
                remediation=(
                    "Rename the file to match what it is, or remove it. A file "
                    "whose name and content disagree is arranged so that the thing "
                    "inspecting it and the thing opening it reach different "
                    "conclusions."
                ),
            ),
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()

        content = unit.content
        raw = content.raw
        if not raw:
            return ()

        found = self.identify(raw)
        findings: list[Finding] = []

        mismatch = self.mismatch(content.path, found)
        if mismatch is not None:
            findings.append(self._finding("SUSPECT.POLYGLOT.MISMATCH.001", unit, ctx, mismatch))

        if found is not None and found.executable and found.name != "shell script":
            findings.extend(self._executable_findings(unit, ctx, content, found))
            return findings

        # A shell script with a shebang is source, and every content rule
        # already reads it; reporting it here would double every script in
        # every repository.
        if found is not None and found.name == "shell script":
            return findings

        # Not a recognised format, but not text either. This is the case that
        # matters most, because it is what an attacker produces on purpose:
        # `is_binary` is anchored at offset zero by design, so prepending
        # `/* NUL */` to an ELF stops it being an executable *and* stops it
        # being identified. The file is still not text, still contains whatever
        # it contained, and must not become silent -- so the content checks run
        # on what the bytes actually hold rather than on what the header claims.
        if self._looks_binary(raw):
            findings.extend(self._content_findings(unit, ctx, content))

        return findings

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
        for fmt in FORMATS:
            if any(head.startswith(magic) for magic in fmt.magic):
                return fmt
        return None

    @staticmethod
    def mismatch(path: str, found: Format | None) -> str | None:
        """A description of how the content contradicts the name, if it does.

        Only extensions with a settled meaning are checked, and only against
        formats that declare one. Being wrong here means calling an ordinary
        file a forgery, so the question asked is narrow: does this name promise
        a specific format, and do the bytes say something else?
        """
        name = basename(path).lower()
        _, dot, extension = name.rpartition(".")
        if not dot:
            return None
        extension = f".{extension}"

        promised = next((f for f in FORMATS if extension in f.extensions), None)
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
        return f"named {extension} but its contents are {found.name.lower()}"

    # -- Executables -----------------------------------------------------

    def _executable_findings(
        self, unit: FileUnit, ctx: ScanContext, content: FileContent, found: Format
    ) -> Iterable[Finding]:
        path = content.path
        lowered = f"/{path.lower()}"

        if any(fragment in lowered for fragment in EXECUTING_DIRECTORIES) or ctx.in_install_hook(
            path
        ):
            yield self._finding(
                "SUSPECT.BINARY.EXECUTABLE_PATH.001",
                unit,
                ctx,
                f"a {found.name} sits where a lifecycle step will run it",
            )
        else:
            yield self._finding(
                "POLICY.BINARY.COMMITTED.001",
                unit,
                ctx,
                f"a {found.name} is committed to a source tree",
            )

        yield from self._content_findings(unit, ctx, content)

    def _content_findings(
        self, unit: FileUnit, ctx: ScanContext, content: FileContent
    ) -> Iterable[Finding]:
        """What the bytes carry, independent of what the header claims.

        Separate from the executable path so both callers share it. The header
        is the one part of a file an attacker edits for free, and these checks
        are about content -- so tying them to a recognised header would mean a
        prepended comment silences them.
        """
        window = content.raw[:MAX_STRINGS_BYTES]

        packer = next((label for signature, label in PACKERS if signature in window), None)
        if packer is not None:
            yield self._finding("SUSPECT.BINARY.PACKED.001", unit, ctx, f"packed with {packer}")

        observed = self._interesting_strings(window)
        if observed:
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

        return Finding(
            rule_id=rule_id,
            category=declared.category,
            severity=declared.severity,
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


__all__ = ["FORMATS", "PACKERS", "BinaryDetector", "Format"]
