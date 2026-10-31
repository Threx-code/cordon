"""The VBA reader for cordon-rule: the `vba` module's values as a condition sees them.

Macros live in a compound file (`.doc`, `.xls`, `vbaProject.bin`) or in one inside an Office zip
(`word/vbaProject.bin`, `xl/`, `ppt/`): the `dir` stream, MS-OVBA compressed, names the project, its
version and references, and each module with the stream and offset its compressed source sits at. The
package's own OLE reader (`analysis.formats.ole`) opens the file, walks the `dir` records and decompresses
the source; this module gives them YARA-X's names: `has_macros`, `modules[].{name,type,code}`,
`project_info.{name,version,references,module_count}`, `MODULE_TYPE_STANDARD/CLASS/UNKNOWN`.

The reading is ours, and differs from YARA-X's where that is an accident of its parser: the project
records are read in any order and a project whose locale is not US English, or whose help-file names
differ, still has macros (YARA-X refuses the whole project then); a module's source is found at its
offset, or by the first compressed container in its stream; text is decoded with the project's code page
through Python's codecs, unknown bytes replaced.
"""

from __future__ import annotations

import codecs
import io
import zipfile
from typing import Any, ClassVar

from cordon_scanner.analysis.formats import FormatError
from cordon_scanner.analysis.formats.ole import (
    MAX_STREAM_BYTES,
    CompoundFile,
    Entry,
    VbaDirectory,
    VbaModuleRecord,
    VbaSource,
)
from cordon_scanner.detect.binary.modules.formats.olecf import Olecf
from cordon_scanner.detect.binary.modules.values import Record, Scalar, Seq

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class Vba:
    """The `vba` module reader."""

    TYPES: ClassVar[dict[str, int]] = {
        "MODULE_TYPE_STANDARD": 1, "MODULE_TYPE_CLASS": 2, "MODULE_TYPE_UNKNOWN": 3
    }  # fmt: skip
    SCHEMA: ClassVar[Record] = Record({
        **dict.fromkeys(TYPES, INT),
        "has_macros": BOOL,
        "modules": Seq(Record({"name": TEXT, "type": INT, "code": TEXT})),
        "project_info": Record(
            {"name": TEXT, "version": TEXT, "references": Seq(TEXT), "module_count": INT}
        ),
    })  # fmt: skip
    PROJECT_MEMBERS: ClassVar[tuple[str, ...]] = (
        "word/vbaProject.bin", "xl/vbaProject.bin", "ppt/vbaProject.bin", "vbaProject.bin"
    )  # fmt: skip
    FOLDED: ClassVar[dict[str, str]] = {
        **dict.fromkeys("çćč", "c"), **dict.fromkeys("şśšþ", "s"), **dict.fromkeys("ıíìîïý", "i"),
        "ğ": "g", **dict.fromkeys("öóòôõ", "o"), **dict.fromkeys("üúùû", "u"),
        **dict.fromkeys("äáàâã", "a"), "ñ": "n",
    }  # fmt: skip
    """Accented letters folded when a module's stream is looked up by name, as Office does."""

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {
            **Vba.TYPES, "has_macros": False, "modules": {}, "project_info": {}
        }  # fmt: skip
        compound = Vba.compound(file)
        if compound is None:
            return out
        streams = Vba.streams(compound)
        directory = next((e for n, e in streams.items() if n.strip() == "dir"), None)
        data = Olecf.stream(compound, directory) if directory is not None else None
        if not data:
            return out
        try:
            project = VbaDirectory.project(VbaSource.decompress(data))
        except FormatError:
            return out
        out["has_macros"] = True
        modules: dict[int, Any] = {}
        for record in project.modules:
            code = Vba.code(compound, streams, record, project.codepage)
            if code is None:
                continue
            name = (
                record.unicode_name
                if record.unicode_name is not None
                else Vba.text(record.name, project.codepage)
            )
            modules[len(modules)] = {
                "name": name.encode("utf-8", "surrogatepass"),
                "type": record.kind,
                "code": code,
            }
        out["modules"] = modules
        info: dict[str, Any] = {
            "references": {
                i: Vba.text(r, project.codepage).encode("utf-8", "surrogatepass")
                for i, r in enumerate(project.references)
            },
            "module_count": len(project.modules),
        }
        if project.name is not None:
            info["name"] = Vba.text(project.name, project.codepage).encode("utf-8", "surrogatepass")
        if project.version is not None:
            info["version"] = f"{project.version[0]}.{project.version[1]}".encode()
        out["project_info"] = info
        return out

    @staticmethod
    def compound(file: bytes) -> CompoundFile | None:
        """The compound file itself, or the first VBA project inside an Office zip."""
        if file[:4] != b"PK\x03\x04":
            return Olecf.compound(file)
        try:
            with zipfile.ZipFile(io.BytesIO(file)) as archive:
                names = set(archive.namelist())
                for member in Vba.PROJECT_MEMBERS:
                    if member in names:
                        with archive.open(member) as handle:
                            return Olecf.compound(handle.read(MAX_STREAM_BYTES))
        except (zipfile.BadZipFile, OSError, EOFError, ValueError, RuntimeError):
            return None
        return None

    @staticmethod
    def streams(compound: CompoundFile) -> dict[str, Entry]:
        """The file's streams by folded name, the way a module's stream is looked up."""
        return {Vba.fold(name): entry for name, entry in Olecf.listing(compound) if entry.kind == 2}

    @staticmethod
    def fold(name: str) -> str:
        return "".join(Vba.FOLDED.get(c, c) for c in name.lower())

    @staticmethod
    def text(value: bytes, codepage: int) -> str:
        """Bytes in the project's code page as text, unknown bytes replaced."""
        try:
            codec = codecs.lookup(f"cp{codepage}").name
        except LookupError:
            codec = "utf-8"
        return value.decode(codec, "replace")

    @staticmethod
    def code(
        compound: CompoundFile, streams: dict[str, Entry], record: VbaModuleRecord, codepage: int
    ) -> bytes | None:
        """A module's source: its stream (by its stream name, else its own name), decompressed from
        its offset, else from the first container in the stream; None when there is none."""
        stream_name = record.unicode_stream
        if stream_name is None and record.stream is not None:
            stream_name = Vba.text(record.stream, codepage)
        entry = streams.get(Vba.fold(stream_name)) if stream_name is not None else None
        if entry is None:
            module_name = record.unicode_name or Vba.text(record.name, codepage)
            entry = streams.get(Vba.fold(module_name))
        if entry is None:
            return None
        data = Olecf.stream(compound, entry)
        if not data:
            return None
        source = b""
        if record.offset < len(data) and data[record.offset] == 0x01:
            try:
                source = VbaSource.decompress(data, record.offset)
            except FormatError:
                source = b""
        if not source:
            source = VbaSource.search_source(data)
        if not source:
            return None
        return Vba.text(source.rstrip(b"\x00"), codepage).encode("utf-8", "surrogatepass")


__all__ = ["Vba"]
