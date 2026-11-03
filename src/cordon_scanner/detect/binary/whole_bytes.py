"""The whole of a binary, for the readers that parse one (notes/74-binary-readers-read-the-whole-file.md).

Past `limits.max_file_bytes` a file's content is its first 10 MiB, and the text rules read the rest
in windows. The binary readers -- the import table, the rule engine and its decoded layers, ClamAV --
read only that prefix, so a PE, ELF or Mach-O padded past 10 MiB, its telling part after the padding,
passed every binary rule. They now read an owned copy of the whole member, at most
`limits.max_stream_bytes`:

```
  not truncated ─────────────────────► content.raw (as before)
  content.streamed (already in memory) ► that, to max_stream_bytes
  content.spill (Cordon's own file) ───► read whole, to max_stream_bytes
  content.window_source (a file on disk) ► one bounded read through the windows' reader, which
                                           reopens it and refuses another file; never mapped, so
                                           a file that changes mid-scan is a gap, not a SIGBUS
  content.spill / unit.opens ──────────► one bounded read, its length checked
```

A copy is made per member and held only by the reader's own call: nothing caches it, and evidence keeps
the `raw` prefix it always hashed. Before it is made, the worker's headroom is checked (its address-space
limit, and the container's memory limit where it can be read): a copy that would not fit is not taken.
Whatever stops the whole read -- past `max_stream_bytes`, no headroom, a file that changed or cannot be
read -- the readers read the prefix and the file carries a gap (`gap`), never a quiet pass.
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.binary.copy_budget import CopyBudget
from cordon_scanner.foundation.files.windows import WindowSourceChanged
from cordon_scanner.foundation.models import Category, Severity
from cordon_scanner.foundation.results import OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cordon_scanner.detect.base import FileUnit
    from cordon_scanner.foundation.models import Finding


@dataclass(frozen=True, slots=True)
class Whole:
    """A member's bytes for the binary readers, and why they are not the whole file ("" when they are)."""

    data: bytes
    gap: str


class WholeBytes:
    """An owned copy of a binary member, bounded and checked against the worker's memory."""

    MARGIN: ClassVar[int] = 64 << 20
    """Headroom kept beyond the copy itself, for what the readers build from it."""
    GAP_RULE: ClassVar[str] = "OPERATIONAL.FILE.TRUNCATED"

    @staticmethod
    def of(unit: FileUnit) -> Whole:
        content = unit.content
        if not content.truncated:
            return Whole(content.raw, "")
        bound = content.limits.max_stream_bytes
        want = min(content.size, bound)
        past = (
            f"it is {content.size} bytes, past limits.max_stream_bytes ({bound})"
            if content.size > bound
            else ""
        )
        if content.streamed is not None:
            return Whole(content.streamed[:want], past)
        room = WholeBytes.headroom()
        if room is not None and want + WholeBytes.MARGIN > room:
            return Whole(
                content.raw,
                f"reading its {want} bytes would pass the worker's memory headroom ({room} bytes)",
            )
        try:
            data = WholeBytes._read(unit, want)
        except (OSError, MemoryError, WindowSourceChanged):
            return Whole(content.raw, "it changed while it was read, or could not be read")
        if data is None:
            return Whole(content.raw, "the rest of it could not be reached on disk")
        if len(data) != want or not data.startswith(content.raw[: min(len(content.raw), want)]):
            return Whole(content.raw, "it changed while it was read")
        return Whole(data, past)

    @staticmethod
    @contextlib.contextmanager
    def held(
        unit: FileUnit, budget: str | None = None, deadline: float | None = None
    ) -> Iterator[Whole]:
        """`of`, within the scan's copy budget (`copy_budget.py`): the copy is made only once its slots
        are held, and they stay held while the readers use it. A wait past `deadline` gives the prefix,
        with the reason as its gap."""
        content = unit.content
        if not content.truncated:
            yield Whole(content.raw, "")
            return
        want = min(content.size, content.limits.max_stream_bytes)
        with CopyBudget(budget).hold(want, deadline) as slot:
            if not slot:
                yield Whole(content.raw, slot.reason)
                return
            yield WholeBytes.of(unit)

    @staticmethod
    def _read(unit: FileUnit, want: int) -> bytes | None:
        """One bounded read of the first `want` bytes, from where the windows read the file (a file
        on disk is reopened and refused if it is not the file first read), else Cordon's own spill,
        else the path the file opens by. None when there is nowhere to read it from."""
        content = unit.content
        if content.window_source is not None:
            with content.window_source.reader() as read:
                return read(0, want)
        source = content.spill.path if content.spill is not None else unit.opens
        if source is None:
            return None
        with Path(source).open("rb") as handle:
            return handle.read(want)

    @staticmethod
    def headroom() -> int | None:
        """Bytes this worker may still allocate, by its address-space limit and its container's
        memory limit, whichever is known and smaller; None when neither is known."""
        known: list[int] = []
        with contextlib.suppress(ImportError, OSError, ValueError):
            import resource

            soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
            if soft != resource.RLIM_INFINITY:
                used = WholeBytes._address_space()
                if used is not None:
                    known.append(soft - used)
        with contextlib.suppress(OSError, ValueError):
            limit = Path("/sys/fs/cgroup/memory.max").read_text(encoding="ascii").strip()
            if limit != "max":
                current = int(Path("/sys/fs/cgroup/memory.current").read_text(encoding="ascii"))
                known.append(int(limit) - current)
        return min(known) if known else None

    @staticmethod
    def _address_space() -> int | None:
        """This process's address space in bytes (Linux); None where it cannot be read."""
        try:
            pages = int(Path("/proc/self/statm").read_text(encoding="ascii").split()[0])
        except (OSError, ValueError, IndexError):
            return None
        return pages * os.sysconf("SC_PAGE_SIZE")

    @staticmethod
    def gap_finding(unit: FileUnit, reader: str, gap: str) -> Finding:
        """What the binary readers could not read of this file, said exactly: a gap, never a pass."""
        content = unit.content
        return OperationalFinding.build(
            path=content.path,
            rule_id=WholeBytes.GAP_RULE,
            message=(
                f"The {reader} read only the first {len(content.raw)} bytes of this {content.size}-byte "
                f"binary: {gap}."
            ),
            remediation=(
                "Scan it with more memory, or raise limits.max_stream_bytes, or exclude it "
                "deliberately if it is a known artefact."
            ),
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
        )


__all__ = ["Whole", "WholeBytes"]
