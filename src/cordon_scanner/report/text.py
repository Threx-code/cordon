"""Human-readable terminal output.

Written for somebody who did not author the rule, reading it under time
pressure, deciding whether to act. That reader needs four things in order: how
bad is it, where is it, why does the tool believe this, and what do I do.

Anything that does not serve one of those questions is noise, and noise is not
neutral here. A report that is tiring to read is a report that gets skimmed, and
a tool whose output gets skimmed stops being a control.

The ``why`` block renders the risk score's own derivation. That is the
explainability requirement made concrete: a reader can check the arithmetic. A
score nobody can reconstruct is a score nobody trusts, and a score nobody trusts
gets configured away.
"""

from __future__ import annotations

import re
import shutil
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Category, Severity
from cordon_scanner.report.base import BaseReporter, ReportOptions
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import Finding, ScanResult

ANSI = re.compile(r"\033\[[0-9;]*m")

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
"""Foreground colours, for the places severity appears inside prose."""

SEVERITY_BADGE = {
    Severity.CRITICAL: "\033[1;97;41m",  # white on red
    Severity.HIGH: "\033[1;30;101m",  # black on bright red
    Severity.MEDIUM: "\033[1;30;43m",  # black on yellow
    Severity.LOW: "\033[1;30;46m",  # black on cyan
    Severity.INFO: "\033[1;30;47m",  # black on grey
}
"""Background colours, for the severity column.

A block of colour is read before any word in it, which is the point: the eye
finds the critical rows without reading a single line. Foreground colour alone
does not do that at a glance down a list of fifty, and it is the first thing
lost to a terminal whose theme fights it.

Every badge is `BADGE_WIDTH` visible characters whether or not colour is on, so
the columns line up in a pipe, a log and a terminal alike."""

BADGE_WIDTH = 10

PATH_COLOR = "\033[1;36m"
"""File headings. The path is what a reader navigates by, so it is the one
thing that should be findable while scrolling."""

WIDTH = 76
"""Width for the wrapped prose blocks, which read better narrow than wide."""

MIN_MESSAGE_ROOM = 28
"""Below this, a message beside the columns is clipped to uselessness and goes
on its own line instead."""


def TERMINAL_WIDTH() -> int:
    """How wide the table may be.

    Measured rather than assumed. The columns used to be laid out against a
    fixed 76, which left no room for a message beside a thirty-four character
    rule id on a window that was usually twice that wide. Capped because a
    maximised terminal is not an argument for a two-hundred-column line, and
    floored so a narrow one degrades rather than collapses.
    """
    return max(72, min(shutil.get_terminal_size((110, 24)).columns, 140))


class TextReporter(BaseReporter):
    @staticmethod
    def _wrap(text: str, width: int, indent: str) -> list[str]:
        """Wrap prose to a width, preserving the indent."""
        words = text.split()
        if not words:
            return []
        lines: list[str] = []
        current = indent
        for word in words:
            if len(current) + len(word) + 1 > width and current.strip():
                lines.append(current)
                current = indent + word
            else:
                current = f"{current} {word}" if current.strip() else indent + word
        if current.strip():
            lines.append(current)
        return lines

    id = "text"
    media_type = "text/plain"
    file_extension = ".txt"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        color = opts.color

        yield self._line(
            f"{DIM}cordon {__version__} · rulepack {result.rulepack_version} "
            f"({result.rulepack_hash}){RESET}",
            color,
        )
        yield b"\n"

        shown = [f for f in result.findings if opts.show_suppressed or not f.is_suppressed]
        reportable = [f for f in shown if f.category is not Category.OPERATIONAL]
        operational = [f for f in shown if f.category is Category.OPERATIONAL]

        if opts.max_findings and len(reportable) > opts.max_findings:
            hidden = len(reportable) - opts.max_findings
            reportable = reportable[: opts.max_findings]
        else:
            hidden = 0

        if opts.verbose:
            for finding in reportable:
                yield from self._finding(finding, color, verbose=True)
        else:
            yield from self._grouped(reportable, color)

        # Operational findings are grouped at the end rather than interleaved.
        # They describe the scan rather than the code, and mixing the two makes
        # a reader work to tell "your code is fine" from "I could not look".
        if operational:
            yield from self._operational_block(operational, color)

        yield from self._summary(result, color, hidden, compact=not opts.verbose)

    # -- Findings --------------------------------------------------------

    def _grouped(self, findings: list[Finding], color: bool) -> Iterator[bytes]:
        """The default view: one line per finding, grouped under its file.

        The full block -- message, evidence, score derivation, escalations, fix
        and references -- runs to about twenty-eight lines. That is the right
        amount to read about *one* finding and the wrong amount to print fifty
        times: a scan of this project's own corpus produced fourteen hundred
        lines, which nobody reads, and a report nobody reads is the same as no
        report. The derivation moves behind `-v`, where somebody who has
        decided to act on a specific finding goes looking for it.

        Two things about the order. The message comes before the rule id
        because that is the order somebody reads in -- what is wrong, then what
        to call it -- and because a padded identifier column ahead of a short
        message opens a gulf of whitespace between the two halves of the same
        sentence. And a position is printed once per location rather than once
        per finding: three composites firing on one line is three findings
        about one place, and repeating `22:1` down the margin says otherwise.
        """
        if not findings:
            # The common case, and the one the column measurement below cannot
            # survive: `max()` over nothing raises, so a clean scan crashed and
            # returned the scanner-error exit code instead of zero.
            return

        by_path: dict[str, list[Finding]] = {}
        for finding in findings:
            by_path.setdefault(finding.location.path, []).append(finding)

        width = TERMINAL_WIDTH()
        where = {f.fingerprint: self._where(f) for f in findings}
        position = max(len(w) for w in where.values())
        rule = max(len(f.rule_id) for f in findings)
        room = width - (position + BADGE_WIDTH + rule + 8)

        for path, group in by_path.items():
            yield b"\n"
            count = f"{len(group)} finding" + ("s" if len(group) != 1 else "")
            yield self._line(
                f"{PATH_COLOR}{path or 'dependencies'}{RESET}  {DIM}{count}{RESET}", color
            )

            seen = ""
            for finding in group:
                here = where[finding.fingerprint]
                shown = "" if here == seen else here
                seen = here
                yield from self._compact(finding, color, shown, position, room, path)

    def _compact(
        self,
        f: Finding,
        color: bool,
        where: str,
        position: int,
        room: int,
        path: str,
    ) -> Iterator[bytes]:
        headline = self._headline(f.message)
        # Some rules name the file in their message, which is right in a
        # standalone block and repeats the heading it is printed under here.
        if path and headline.startswith(path):
            # Only the first character. `str.capitalize()` lower-cases the rest,
            # which turned "a ELF executable" into "a elf executable", "packed
            # with UPX" into "upx", and "a URL, a shell command" into "a url" --
            # every acronym in the report, and acronyms are most of what a
            # security finding names.
            rest = headline[len(path) :].lstrip(": ")
            headline = (rest[:1].upper() + rest[1:]) if rest else headline

        head = f" {DIM}{where:<{position}}{RESET} {self._badge(f.severity)}"

        if room >= MIN_MESSAGE_ROOM:
            yield self._line(
                f"{head}  {self._clip(headline, room):<{room}}  {DIM}{f.rule_id}{RESET}", color
            )
            return

        # A narrow window. Better a second line than a message clipped to
        # nothing, which would leave a rule id and no sense of what it found.
        yield self._line(f"{head}  {DIM}{f.rule_id}{RESET}", color)
        for line in TextReporter._wrap(headline, TERMINAL_WIDTH() - 6, "    "):
            yield self._line(f"{DIM}{line}{RESET}", color)

    @staticmethod
    def _badge(severity: Severity) -> str:
        """A fixed-width block of colour naming the severity."""
        return f"{SEVERITY_BADGE.get(severity, '')}{str(severity).upper():^8}{RESET}"

    @staticmethod
    def _where(f: Finding) -> str:
        """Where the finding is, in the shortest form that still locates it.

        A file-scoped finding is placed by line and column under its heading. A
        dependency finding has no line -- its subject is a package rather than
        a position -- so it carries the package identity instead.
        """
        if f.location.path and f.location.line:
            return f"{f.location.line}:{f.location.column or 1}"
        if f.location.path:
            return "-"
        return str(f.location)

    @staticmethod
    def _headline(message: str) -> str:
        """The first sentence, which every rule message is written to make
        stand alone: what was observed, before why it matters."""
        head, separator, _ = message.partition(". ")
        return f"{head}." if separator else message

    @staticmethod
    def _clip(text: str, room: int) -> str:
        if len(text) <= room:
            return text
        # Cut at a word, so the clipped end is still a phrase.
        return f"{text[: room - 4].rsplit(' ', 1)[0]} ..."

    def _finding(self, f: Finding, color: bool, verbose: bool) -> Iterator[bytes]:
        tint = SEVERITY_COLOR.get(f.severity, "")
        header = f"{tint}{str(f.severity).upper():<9}{RESET}{BOLD}{f.rule_id}{RESET}"
        suffix = f"{DIM}risk {f.risk.value}/100{RESET}"
        yield self._line(f"{header}  {suffix}", color)

        yield self._line(f"  {f.location}", color)
        meta = f"  {DIM}{f.category} · confidence {f.confidence} · detector {f.detector}{RESET}"
        yield self._line(meta, color)

        if f.is_suppressed and f.suppressed:
            yield self._line(
                f"  {DIM}suppressed until {f.suppressed.expires}"
                f"{' by ' + f.suppressed.approved_by if f.suppressed.approved_by else ''}"
                f"{RESET}",
                color,
            )

        yield b"\n"
        for line in TextReporter._wrap(f.message, WIDTH, "  "):
            yield self._line(line, color)

        if f.evidence.snippet:
            yield b"\n"
            yield self._line(f"  {DIM}evidence{RESET}  {f.evidence.snippet}", color)
        elif f.evidence.match_hash:
            yield b"\n"
            yield self._line(
                f"  {DIM}evidence{RESET}  {DIM}withheld; match "
                f"{f.evidence.match_hash[:23]}...{RESET}",
                color,
            )

        # The score, rendered as its own derivation. The reader can check it.
        yield b"\n"
        first = True
        for line in f.risk.explain():
            label = "why     " if first else "        "
            yield self._line(f"  {DIM}{label}{RESET}  {line}", color)
            first = False

        # Escalations get their own labelled block. Printed under the `why`
        # indent they read as further arithmetic, which is misleading: they are
        # the reason the severity changed, not a term in the sum.
        if f.explanation.escalations:
            yield b"\n"
            for index, escalation in enumerate(f.explanation.escalations):
                label = "context " if index == 0 else "        "
                for line_index, line in enumerate(TextReporter._wrap(escalation, WIDTH - 12, "")):
                    prefix = label if line_index == 0 else "        "
                    yield self._line(f"  {DIM}{prefix}{RESET}  {line.strip()}", color)

        if verbose and f.explanation.contributing:
            contributors = ", ".join(f.explanation.contributing)
            yield self._line(f"  {DIM}        {RESET}  from: {contributors}", color)

        if f.remediation:
            yield b"\n"
            wrapped = TextReporter._wrap(f.remediation, WIDTH - 12, "")
            for index, line in enumerate(wrapped):
                label = "fix     " if index == 0 else "        "
                yield self._line(f"  {DIM}{label}{RESET}  {line.strip()}", color)

        if f.references:
            yield b"\n"
            for index, ref in enumerate(f.references):
                label = "refs    " if index == 0 else "        "
                yield self._line(f"  {DIM}{label}{RESET}  {ref}", color)

        yield b"\n"

    def _operational_block(self, findings: list[Finding], color: bool) -> Iterator[bytes]:
        yield self._line(f"{DIM}{'-' * WIDTH}{RESET}", color)
        yield self._line(
            f"{DIM}scan coverage{RESET}  {len(findings)} note(s) about the scan itself",
            color,
        )
        for f in findings[:10]:
            yield self._line(f"  {DIM}{f.location.path}{RESET}  {f.message}", color)
        if len(findings) > 10:
            yield self._line(f"  {DIM}... and {len(findings) - 10} more{RESET}", color)
        yield b"\n"

    # -- Summary ---------------------------------------------------------

    def _summary(
        self, result: ScanResult, color: bool, hidden: int, *, compact: bool = False
    ) -> Iterator[bytes]:
        counts = result.by_severity()
        yield self._line(f"{DIM}{'-' * WIDTH}{RESET}", color)

        parts = []
        for severity in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ):
            count = counts.get(severity, 0)
            if count:
                # A badge only where there is something to see. Colouring a
                # zero draws the eye to the severities that found nothing,
                # which is the opposite of what a summary is for.
                parts.append(f"{SEVERITY_BADGE[severity]} {count} {severity} {RESET}")
            else:
                parts.append(f"{DIM}{count} {severity}{RESET}")

        suppressed = len(result.suppressed)
        if suppressed:
            parts.append(f"{DIM}{suppressed} suppressed{RESET}")

        yield self._line(" · ".join(parts), color)

        stats = result.stats
        detail = (
            f"{DIM}{stats.files_scanned} files · {stats.duration_ms}ms"
            f"{f' · {stats.files_skipped} skipped' if stats.files_skipped else ''}"
            f"{RESET}"
        )
        yield self._line(detail, color)

        # Completeness is stated on every scan, not only when it fails. A reader
        # should never have to infer whether the tool actually looked.
        if result.complete:
            yield self._line(f"{DIM}scan complete{RESET}", color)
        else:
            yield self._line(
                f"{SEVERITY_COLOR[Severity.MEDIUM]}scan INCOMPLETE{RESET} "
                f"{DIM}- results are partial; see the coverage notes above{RESET}",
                color,
            )

        if hidden:
            yield self._line(f"{DIM}{hidden} further finding(s) not shown{RESET}", color)

        if compact and any(f.category is not Category.OPERATIONAL for f in result.findings):
            # Said once, at the end, where somebody who has just read the list
            # is deciding what to do about it. The reasoning, the evidence, the
            # score derivation and the fix are all still there; they are simply
            # not printed fifty times unasked.
            yield b"\n"
            yield self._line(
                f"{DIM}Run again with -v for the evidence, the score derivation "
                f"and the fix for each finding.{RESET}",
                color,
            )

    # -- Helpers ---------------------------------------------------------

    @staticmethod
    def _line(text: str, color: bool) -> bytes:
        if not color:
            # Every escape, not a list of the ones in use. The list was
            # enumerated by hand and went stale the moment a colour was added:
            # a code missing from it survives into a redirected file, a CI log
            # and a `--format text -o report.txt`, which is where colour does
            # the most damage.
            text = ANSI.sub("", text)
        return (text + "\n").encode("utf-8")


__all__ = ["TextReporter"]
