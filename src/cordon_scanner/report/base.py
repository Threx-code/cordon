"""The reporter contract.

Reporters are pure functions from a :class:`ScanResult` to bytes. They never see
the engine, and the engine never imports one. Two consequences follow, and both
matter more than the tidiness does.

Two reporters over one result cannot disagree. The SARIF and the terminal output
describe the same findings because they are transformations of the same value,
not two code paths that each decide what to show.

A saved result can be re-rendered later. ``cordon report convert`` turns a JSON
result from six months ago into SARIF without re-scanning, which matters when
the code that produced it no longer exists in that form.

``render`` returns an iterator of byte chunks rather than a string, so a result
with fifty thousand findings streams to disk instead of being assembled in
memory. On a hostile repository the finding count is attacker-influenced, which
makes streaming a resource-safety property rather than an optimisation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.core.models import ScanResult


@dataclass(frozen=True, slots=True)
class ReportOptions:
    """Presentation choices that never affect which findings exist.

    Kept separate from :class:`~cordon.core.config.Config` deliberately: nothing
    here can change a verdict, so a reporting change can never weaken a gate.
    """

    color: bool = True
    verbose: bool = False
    show_suppressed: bool = True
    """Suppressed findings appear by default, marked as suppressed. An auditor's
    first question is what the tool was told to ignore."""

    max_findings: int = 0
    """0 means no limit. A truncated report always says it was truncated."""

    repository_uri: str = ""
    revision: str = ""


@runtime_checkable
class Reporter(Protocol):
    """Renders a scan result in one format."""

    id: str
    media_type: str
    file_extension: str

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        """Yield the encoded report, in chunks."""
        ...


class BaseReporter:
    """Convenience base. Implementing the protocol directly is equally valid."""

    id: str = "base"
    media_type: str = "text/plain"
    file_extension: str = ".txt"

    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]:
        raise NotImplementedError

    def render_to_string(self, result: ScanResult, opts: ReportOptions | None = None) -> str:
        """Materialise the whole report. For tests and small results only."""
        return b"".join(self.render(result, opts or ReportOptions())).decode("utf-8")


__all__ = ["BaseReporter", "Escape", "ReportOptions", "Reporter"]


class Escape:
    """The one place a reporter renders attacker-controlled text.

    Four fields in every finding come from the scanned repository and reach a
    report unchanged: the path, the rule id, the message and the remediation. A
    path is the sharpest of them, because a directory name is chosen freely and
    appears in output that other people read and act on.

    Redaction already has a single choke point and this did not: each reporter
    solved escaping independently, JSON and SARIF got it for free from
    `json.dumps`, JUnit escaped XML, the GitHub reporter escaped workflow
    metacharacters, and markdown escaped nothing. A directory named

        x`|<img src=x onerror=1>

    broke the table row and put raw HTML into a pull-request comment -- enough
    to close the real finding's `<details>` block early and append a convincing
    "No findings." section under the scanner's name.
    """

    _MARKDOWN_SPECIAL = "\\`*_{}[]()#+!|~"

    @classmethod
    def code(cls, text: str) -> str:
        """Escape a value that will sit inside a code span or `<code>`.

        Only four characters matter there. Markdown metacharacters are already
        literal inside a span, so escaping them makes an ordinary rule id read
        as `MALWARE\\.INSTALL\\.FETCH\\_EXEC\\.001` -- unreadable, in the
        field a reviewer scans first. What still breaks out is a backtick, a
        pipe in a table cell, a newline, and the angle brackets that let inline
        HTML through.
        """
        out = []
        for char in text:
            if char in "\n\r":
                out.append(" ")
            elif char == "`":
                out.append("&#96;")
            elif char == "|":
                out.append("&#124;")
            elif char == "&":
                out.append("&amp;")
            elif char == "<":
                out.append("&lt;")
            elif char == ">":
                out.append("&gt;")
            else:
                out.append(char)
        return "".join(out)

    @classmethod
    def markdown(cls, text: str) -> str:
        """Escape for prose that may be rendered as HTML.

        Backslash-escapes the markdown metacharacters that create structure, and
        encodes `<`, `>` and `&` as entities, because GitHub renders inline HTML
        in comments and job summaries. `.` and `-` are deliberately left alone:
        they cannot start a construct mid-line and escaping them makes every
        sentence unreadable. Newlines become spaces -- a field spanning lines
        breaks the structure it sits in, which is the whole trick.
        """
        out = []
        for char in text:
            if char in "\n\r":
                out.append(" ")
            elif char == "&":
                out.append("&amp;")
            elif char == "<":
                out.append("&lt;")
            elif char == ">":
                out.append("&gt;")
            elif char in cls._MARKDOWN_SPECIAL:
                out.append("\\" + char)
            else:
                out.append(char)
        return "".join(out)

    _TERMINAL_UNSAFE = frozenset(
        # Bidirectional overrides, embeddings and isolates -- exactly what
        # SUSPECT.OBFUSCATION.BIDI.001 detects inside a file. A filename may
        # contain them too, and nothing strips them on the way to a terminal.
        #
        # Written as code points rather than as a run of `\u` escapes because
        # Cordon scans its own repository, and a long escape run is a true
        # positive for its own obfuscation rule. The tool should not need an
        # exception for itself; the same convention is used for the credential
        # shapes in the redaction tests.
        map(
            chr,
            (
                0x061C,  # Arabic letter mark
                0x200E,  # left-to-right mark
                0x200F,  # right-to-left mark
                0x202A,  # left-to-right embedding
                0x202B,  # right-to-left embedding
                0x202C,  # pop directional formatting
                0x202D,  # left-to-right override
                0x202E,  # right-to-left override
                0x2066,  # left-to-right isolate
                0x2067,  # right-to-left isolate
                0x2068,  # first strong isolate
                0x2069,  # pop directional isolate
            ),
        )
    )

    @classmethod
    def terminal(cls, text: str) -> str:
        """Escape a value written to a live terminal.

        Stricter than `control_characters`, which was written for XML and lets
        anything at or above `\x20` through. A terminal reads more than that:
        `\x1b` starts a control sequence that can move the cursor, recolour the
        screen or clear it, and the bidirectional overrides reorder what a
        reader sees without changing the bytes.

        Both are legal in a POSIX filename, and a path is chosen by the
        repository being scanned. Writing one to a terminal unescaped lets the
        scan target rewrite the scanner's own output -- including, with enough
        care, the line that says what was found. Cordon reports the trojan
        source technique as a finding; it should not be susceptible to the
        filename version of it.
        """
        return "".join(
            f"\\u{ord(char):04x}"
            if char in cls._TERMINAL_UNSAFE
            else f"\\x{ord(char):02x}"
            if ord(char) < 0x20 or ord(char) == 0x7F
            else char
            for char in text
        )

    @staticmethod
    def control_characters(text: str) -> str:
        """Remove C0 control characters other than tab.

        A filename may legally contain them on POSIX, and XML 1.0 may not: a
        path holding `\\x01` produced a JUnit document every conforming parser
        rejects, so the CI test tab showed nothing at all rather than the
        finding.
        """
        return "".join(
            char if char == "\t" or ord(char) >= 0x20 else f"\\x{ord(char):02x}" for char in text
        )
