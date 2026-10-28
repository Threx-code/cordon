"""An archive's members as the scan reads them: a member that changed while it was read, one read only
in part, and one the archive reader refused (a path that escapes, a link to a secret, a bomb), each
reported as lost coverage rather than skipped silently.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.engine.pipeline.constants import (
    ARCHIVE_ESCAPE_RULE,
    ARCHIVE_LINK_TO_SECRET_RULE,
    ARCHIVE_NESTING_RULE,
    ARCHIVE_PADDED_RULE,
    ARCHIVE_POLYGLOT_RULE,
    SECRET_LINK_TARGET,
    SWEPT_NOTE,
)
from cordon_scanner.engine.pipeline.operational import OperationalFinding
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from cordon_scanner.sources.base import Rejection

if TYPE_CHECKING:
    pass


class ArchiveMembers:
    """What happened to an archive's members on the way in."""

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
        if reason == Rejection.POLYGLOT and not fixture:
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
        if reason == Rejection.PADDED and not fixture:
            # Read up to the budget, and everything read was scanned; what lies past it is behind
            # an expansion no packaging tool produces. Twelve megabytes of filler compress to
            # twenty-five kilobytes, so this is the cheapest way to put a payload out of reach.
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
        if reason == Rejection.HIDDEN and not fixture:
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
        if not fixture and (
            reason in (Rejection.TRAVERSAL, Rejection.ABSOLUTE)
            or (reason == Rejection.DEPTH and not image)
        ):
            escape = reason != Rejection.DEPTH
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


__all__ = ["ArchiveMembers"]
