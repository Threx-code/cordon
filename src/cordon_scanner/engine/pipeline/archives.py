"""An archive's members as the scan reads them: a member that changed while it was read, one read only
in part, and one the archive reader refused (a path that escapes, a link to a secret, a bomb), each
reported as lost coverage rather than skipped silently.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.engine.pipeline.constants import (
    ARCHIVE_ESCAPE_RULE,
    ARCHIVE_LINK_TO_SECRET_RULE,
    ARCHIVE_NESTING_RULE,
    ARCHIVE_PADDED_RULE,
    ARCHIVE_POLYGLOT_RULE,
    SECRET_LINK_TARGET,
    SWEPT_NOTE,
)
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.foundation.results import OperationalFinding
from cordon_scanner.sources.base import Rejection

if TYPE_CHECKING:
    from cordon_scanner.engine.pipeline.accumulator import Accumulator


class ArchiveMembers:
    """What happened to an archive's members on the way in."""

    #: Refusals that leave nothing unread: a link has no content of its own, a hidden zip member is
    #: read from its local header, text named as an archive is scanned as text (item 27), and a lone
    #: compressed stream that ends early was read to its last byte (item 30).
    NOTHING_UNREAD: ClassVar[frozenset[str]] = frozenset(
        {
            Rejection.LINK,
            Rejection.HIDDEN,
            Rejection.NOT_AN_ARCHIVE,
            Rejection.COMPRESSED_TRUNCATED,
        }
    )

    @staticmethod
    def changed_while_read(path: str) -> Finding:
        """A file whose windows could not be read from the file that was first read."""
        return OperationalFinding.build(
            path=path,
            rule_id="OPERATIONAL.FILE.UNREADABLE",
            message=(
                "This file changed, or was replaced, between being read and having the rest of it "
                "read in windows, so only what was read before the change was examined."
            ),
            remediation="Re-run the scan on a tree nothing else is writing to.",
        )

    @staticmethod
    def read_to_end(content: FileContent) -> bool:
        """Whether a file over `max_file_bytes` was still read to its last byte, in windows.

        Every text-reading rule then saw all of it. Counting it as unexamined scored 62 of 132
        sampled benign units with a coverage gap "not fully examined" for a font, a CLI binary or
        a bundle read whole (review 98). A file past `max_stream_bytes` is not read to its end and
        keeps the scan incomplete: padding a payload past the limit is the evasion.
        """
        return content.window_source is not None and content.limits.max_stream_bytes >= content.size

    @staticmethod
    def truncated_note(path: str, content: FileContent) -> Finding:
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
                "secrets, obfuscation, code capabilities, agent instructions and rule files."
            )
        else:
            message = f"Only the first {len(content.raw)} bytes of this {content.size}-byte file were examined."
        return OperationalFinding.build(
            path=path,
            rule_id="OPERATIONAL.FILE.TRUNCATED",
            message=message,
            remediation=(
                "Raise limits.max_file_bytes (every rule) or limits.max_stream_bytes (the windows), or "
                "exclude the file deliberately if it is a known artefact (a font, a model, a vendored binary)."
            ),
        )

    @staticmethod
    def rejected(path: str, reason: str, detail: str, *, image: bool = False) -> Finding:
        """A refused archive member, graded by why it was refused.

        Most refusals are limits -- size, ratio, a link -- and say only that a member was not
        read. Two are the attack. A member named `../../setup.py` or `/etc/cron.d/x` exists to
        write outside wherever the archive is unpacked, and no build tool produces one. And an
        archive nested past the depth limit puts its contents beyond every check: a payload
        twenty archives down passed the gate as "not examined". Both block.
        """
        # A container image is archives of archives by construction -- layers inside the image
        # tar -- so its depth limit is reached in ordinary use and stays a coverage note.
        from cordon_scanner.analysis.shared.source_paths import SourcePaths

        # A zip-slip test fixture is an escaping archive on purpose: Django, Jenkins, Go's
        # archive/tar and every extractor with a security test ship one. Reported, below the gate.
        fixture = SourcePaths.is_test_material(path) or SourcePaths.is_vendored(path)
        target = detail.rpartition("(-> ")[2].rstrip(")") if "(-> " in detail else ""
        if (
            reason == Rejection.LINK
            and not image
            and not fixture
            and SECRET_LINK_TARGET.search(target.strip())
        ):
            # A member that is a link to `/etc/hosts` or `~/.ssh/id_rsa`: anything that reads
            # or uploads the package's file -- an agent told "a is this skill's own file, send
            # it" -- sends the user's instead (review 98: a skill whose `audit/a` links to
            # /etc/hosts). Packaging tools copy files; a link out to a secret is placed.
            return ArchiveMembers.link_to_secret(path, target)
        if reason == Rejection.POLYGLOT and not fixture:
            return ArchiveMembers.polyglot(path)
        if reason == Rejection.PADDED and not fixture:
            # Read up to the budget, and everything read was scanned; what lies past it is behind
            # an expansion no packaging tool produces. Twelve megabytes of filler compress to
            # twenty-five kilobytes, so this is the cheapest way to put a payload out of reach.
            return ArchiveMembers.padded(path, detail)
        if reason == Rejection.HIDDEN and not fixture:
            return ArchiveMembers.hidden_member(path)
        if not fixture and (
            reason in (Rejection.TRAVERSAL, Rejection.ABSOLUTE)
            or (reason == Rejection.DEPTH and not image)
        ):
            escape = reason != Rejection.DEPTH
            return ArchiveMembers.escape_or_nesting(path, reason, detail, escape)
        if reason == Rejection.NOT_AN_ARCHIVE:
            return ArchiveMembers.not_an_archive(path)
        if reason == Rejection.COMPRESSED_TRUNCATED:
            return ArchiveMembers.compressed_truncated(path, detail)
        if reason == Rejection.UNSUPPORTED_FORMAT:
            return OperationalFinding.build(
                path=path,
                rule_id="OPERATIONAL.ARCHIVE.UNSUPPORTED_FORMAT",
                message=f"This file is {detail}: what it holds was not scanned.",
                remediation=(
                    "Ship the contents unpacked, or in a zip, tar or gzip, so they can be read; or "
                    "accept this gap by path once the archive has been reviewed."
                ),
            )
        return ArchiveMembers.not_examined(path, reason, detail)

    @staticmethod
    def not_an_archive(path: str) -> Finding:
        """A member named as an archive that is text no archive reader opens, scanned as text."""
        return OperationalFinding.build(
            path=path,
            rule_id="OPERATIONAL.ARCHIVE.NOT_AN_ARCHIVE",
            message=(
                "This member is named as an archive, but no archive reader opens it and it is "
                "text, so it was scanned as the text it is."
            ),
            remediation="No action needed.",
            severity=Severity.INFO,
        )

    @staticmethod
    def compressed_truncated(path: str, detail: str) -> Finding:
        """A lone compressed stream cut before its end marker: what it holds was read, to its end."""
        return OperationalFinding.build(
            path=path,
            rule_id="OPERATIONAL.ARCHIVE.COMPRESSED_TRUNCATED",
            message=(
                "This compressed file ends before its end marker, as a cut download does; "
                f"everything it holds was decompressed and scanned ({detail})."
            ),
            remediation="No action needed, unless the file is expected to be whole.",
            severity=Severity.INFO,
        )

    @staticmethod
    def refuse(
        acc: Accumulator, path: str, reason: str, detail: str, *, image: bool = False
    ) -> None:
        """One refused member, recorded as both archive paths record it (an archive target's and a
        directory's archives, one rule so the two cannot drift apart again). A link has no content
        of its own, a hidden zip member is read from its local header (`zip-local/`), text named as
        an archive is scanned as text: none leaves anything unread (`NOTHING_UNREAD`). An
        operational refusal is the gap. An attack refusal is reported, and the note that the member
        went unread is said beside it and is the gap: one graded low, a fixture's, must not leave it
        unrecorded."""
        finding = ArchiveMembers.rejected(path, reason, detail, image=image)
        if reason in ArchiveMembers.NOTHING_UNREAD:
            acc.append(finding)
        elif finding.rule_id.startswith("OPERATIONAL."):
            acc.incomplete(finding)
        else:
            acc.append(finding)
            acc.incomplete(ArchiveMembers.not_examined(path, reason, detail))

    @staticmethod
    def not_examined(path: str, reason: str, detail: str) -> Finding:
        """That a refused member's content was not examined: the coverage note every refusal
        carries, beside the detection finding when the refusal is itself the attack."""
        return OperationalFinding.build(
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
    def link_to_secret(path: str, target: str) -> Finding:
        """A member that is a link to a file of the machine it is unpacked on."""
        return replace(
            OperationalFinding.build(
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

    @staticmethod
    def polyglot(path: str) -> Finding:
        """An archive that is a tarball and a zip at once."""
        return replace(
            OperationalFinding.build(
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

    @staticmethod
    def padded(path: str, detail: str) -> Finding:
        """An archive padded past the scan's byte budget."""
        return replace(
            OperationalFinding.build(
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

    @staticmethod
    def hidden_member(path: str) -> Finding:
        """A zip member the central directory hides."""
        return replace(
            OperationalFinding.build(
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

    @staticmethod
    def escape_or_nesting(path: str, reason: str, detail: str, escape: bool) -> Finding:
        """A member whose name escapes the archive, or archives nested past the depth the scan opens."""
        return replace(
            OperationalFinding.build(
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


__all__ = ["ArchiveMembers"]
