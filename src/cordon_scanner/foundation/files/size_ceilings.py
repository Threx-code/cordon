"""How large a file of each kind may be before its size is itself the finding.

The engine reads a file up to `Limits.max_file_bytes` whole and the rest in windows up to `Limits.max_stream_bytes` (4 GiB). A text file
of a gigabyte is not a source file, a manifest or a data table anyone ships: padding is the only reason for it, so the windows reading
all of it are time spent on the evasion. A kind has a ceiling, set in code (configuration cannot raise it, as with the stream hard
maxima in `limits.py`), from the largest legitimate file of the kind measured over the benign npm, HARVEST, L1_L2 and skills sets, at
least twice that and a power of two (reviews/mcp-98/52-DETECTOR-SIZE-CAPS.md, section 6, the source of the table):

    text (JavaScript, TypeScript, Python, JSON and other data, markup)    128 MiB   largest legitimate 55.9 MB
    Go, shell                                                              16 MiB   largest legitimate 1.5 MB
    archives                                                                1 GiB   decompression-ratio and member-count limits unchanged
    binary (compiled libraries, model weights, other binary data)          the stream limit (CUDA, PyTorch and weight files reach 1 to 2 GB)

A file over its ceiling is read up to the ceiling and then reported as a size anomaly: the scan is incomplete, never a pass
(`OPERATIONAL.FILE.TRUNCATED`, `degrades_coverage`). Size stays a signal for later work, never a rule of its own.
"""

from __future__ import annotations

from typing import ClassVar, Final

from cordon_scanner.foundation.limits import HARD_MAX_STREAM_BYTES

MIB: Final = 1024 * 1024


class SizeCeilings:
    """`of(path, binary)`: the most a file of this kind is expected to be, in bytes."""

    TEXT: ClassVar[int] = 128 * MIB
    GO_AND_SHELL: ClassVar[int] = 16 * MIB
    ARCHIVE: ClassVar[int] = 1024 * MIB
    #: Binary kinds are bounded by the stream limit alone, which an organisation may raise to the hard maximum.
    BINARY: ClassVar[int] = HARD_MAX_STREAM_BYTES

    GO_AND_SHELL_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".go",
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
    )
    ARCHIVE_SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".zip",
        ".tgz",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".zst",
        ".7z",
        ".rar",
        ".jar",
        ".war",
        ".whl",
        ".egg",
        ".nupkg",
        ".crate",
        ".vsix",
    )

    @staticmethod
    def name_of(path: str) -> str:
        """The file's own name: an archive member's path is `outer!inner/name`."""
        return path.rsplit("!", 1)[-1].rsplit("/", 1)[-1].lower()

    @classmethod
    def kind(cls, path: str, binary: bool) -> str:
        name = cls.name_of(path)
        if name.endswith(cls.ARCHIVE_SUFFIXES):
            return "archive"
        if name.endswith(cls.GO_AND_SHELL_SUFFIXES):
            return "go-or-shell"
        return "binary" if binary else "text"

    @classmethod
    def of(cls, path: str, binary: bool) -> int:
        """The ceiling for a file with this name whose bytes are binary (`FileContent.is_binary`) or text."""
        return {
            "archive": cls.ARCHIVE,
            "go-or-shell": cls.GO_AND_SHELL,
            "binary": cls.BINARY,
            "text": cls.TEXT,
        }[cls.kind(path, binary)]


__all__ = ["MIB", "SizeCeilings"]
