"""The OLE compound-file reader for cordon-rule: the `olecf` module's values as a condition sees them.

A compound file (MS-CFB: `.doc`, `.xls`, `.ppt`, `.msi`, `vbaProject.bin`) is read by the package's own
`analysis.formats.ole` reader, whose sector chains are bounded by the file's own sector count and refuse
a loop. The module lists the file's directory: every storage, stream and root record in the order the
directory sectors hold them, by its own name with one leading control character removed (`\\x05SummaryInformation`
is `SummaryInformation`), its kind and its size. Two records of one name keep the stream, or the later of
two non-streams, under the first one's position. The names are YARA-X's (`is_olecf`, `streams[].{name,type,size}`,
`StreamType.{UNKNOWN,STORAGE,STREAM,ROOT}`); the reading is ours.

Named differences from YARA-X's reading, each an accident of its parser rather than the format: a
record whose name is not valid UTF-16 is listed with the bad units replaced (YARA-X skips it); a file whose
mini-sector shift is not 6, or that has no root record, is not a compound file here (YARA-X reads on).
"""

from __future__ import annotations

from typing import Any, ClassVar

from cordon_scanner.analysis.formats import FormatError
from cordon_scanner.analysis.formats.ole import CompoundFile, Entry
from cordon_scanner.detect.binary.modules.values import Record, Scalar, Seq

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class Olecf:
    """The `olecf` module reader, and the compound-file listing `msi` and `vba` share."""

    TYPES: ClassVar[dict[str, int]] = {"UNKNOWN": 0, "STORAGE": 1, "STREAM": 2, "ROOT": 5}
    LISTED: ClassVar[frozenset[int]] = frozenset({1, 2, 5})
    SCHEMA: ClassVar[Record] = Record({
        "StreamType": Record(dict.fromkeys(TYPES, INT)),
        "is_olecf": BOOL,
        "streams": Seq(Record({"name": TEXT, "type": INT, "size": INT})),
    })  # fmt: skip

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {"StreamType": dict(Olecf.TYPES), "is_olecf": False, "streams": {}}
        compound = Olecf.compound(file)
        if compound is None:
            return out
        out["is_olecf"] = True
        out["streams"] = {
            i: {
                "name": name.encode("utf-8", "surrogatepass"),
                "type": entry.kind,
                "size": entry.size,
            }
            for i, (name, entry) in enumerate(Olecf.listing(compound))
        }
        return out

    @staticmethod
    def compound(file: bytes) -> CompoundFile | None:
        """The file as a compound file, or None when it is not one the reader accepts."""
        try:
            return CompoundFile(file)
        except (FormatError, ValueError, IndexError):
            return None

    @staticmethod
    def listing(compound: CompoundFile) -> list[tuple[str, Entry]]:
        """The directory's storages, streams and root by name, in directory order: a later record of
        a name already listed replaces it in place when it is a stream or the listed one is not."""
        by_name: dict[str, Entry] = {}
        for entry in compound.directory:
            if entry.kind not in Olecf.LISTED:
                continue
            name = entry.path
            if name[:1] and name[0] < "\x20":
                name = name[1:]
            if not name:
                continue
            listed = by_name.get(name)
            if listed is None or entry.kind == 2 or listed.kind != 2:
                by_name[name] = entry
        return list(by_name.items())

    @staticmethod
    def stream(compound: CompoundFile, entry: Entry) -> bytes | None:
        """A stream's bytes, or None for a storage or a stream the reader refuses."""
        if entry.kind != 2:
            return None
        try:
            return compound.open(entry)
        except (FormatError, ValueError, IndexError):
            return None


__all__ = ["Olecf"]
