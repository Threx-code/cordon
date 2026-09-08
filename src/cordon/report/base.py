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

    from cordon.core.models import ScanResult


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


__all__ = ["BaseReporter", "ReportOptions", "Reporter"]
