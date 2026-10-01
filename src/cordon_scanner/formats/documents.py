"""Active content in office documents and PDFs, read without opening them in anything.

What is looked for is the part of a document that runs or fetches when it is opened:

* OOXML (`.docx`, `.xlsm`, `.pptx`, ...): a VBA project, Excel 4.0 macro sheets, relationships
  that load a remote template or OLE object on open (template injection, CVE-2022-30190's
  `mhtml:`/`!` form), and DDE fields.
* OLE (`.doc`, `.xls`, `.ppt`): the VBA project, decompressed.
* PDF: `/JavaScript`, `/Launch`, auto-run actions (`/OpenAction`, `/AA`) and embedded files,
  including inside compressed object streams and with `#xx`-escaped names.
* RTF: embedded OLE objects that update themselves on open, and the Equation Editor class.

Nothing here renders, evaluates or executes the document.
"""

from __future__ import annotations

import io
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Final

from cordon_scanner.formats import FormatError, bounded
from cordon_scanner.formats.ole import MAGIC as OLE_MAGIC
from cordon_scanner.formats.ole import CompoundFile, VbaModule, vba_modules

MAX_MEMBER_BYTES: Final = 16 << 20
MAX_MEMBERS: Final = 4096
MAX_PDF_STREAMS: Final = 2048
MAX_INFLATED_BYTES: Final = 64 << 20
"""Across all of a PDF's streams, so a thousand small bombs cost what one large one would."""

OFFICE_SUFFIXES: Final = (
    ".doc", ".dot", ".docx", ".docm", ".dotm", ".dotx",
    ".xls", ".xlt", ".xlsx", ".xlsm", ".xlsb", ".xltm", ".xla", ".xlam",
    ".ppt", ".pps", ".pptx", ".pptm", ".potm", ".ppsm", ".ppam",
)  # fmt: skip
PDF_SUFFIXES: Final = (".pdf",)
RTF_SUFFIXES: Final = (".rtf", ".doc")

AUTO_EXEC: Final = re.compile(
    r"\b(?:Auto_?Open|AutoExec|AutoClose|Auto_Close|AutoNew|Document_Open|Document_Close|"
    r"Document_New|DocumentOpen|Workbook_Open|Workbook_Activate|Workbook_BeforeClose|"
    r"Presentation_?Open|App_Presentation\w*)\b",
    re.IGNORECASE,
)
"""Procedures Office runs by themselves, by name, when a document opens, closes or is created."""

EXEC_OR_FETCH: Final = re.compile(
    r"\b(?:Shell|ShellExecute|WScript\.Shell|CreateObject|GetObject|URLDownloadToFile|"
    r"MSXML2\.XMLHTTP|WinHttp|XMLHTTP|Powershell|cmd\.exe|mshta|regsvr32|rundll32|certutil|"
    r"Environ|CallByName|Declare\s+(?:PtrSafe\s+)?Function|VirtualAlloc|RtlMoveMemory|"
    r"CreateThread|ExecuteExcel4Macro|MacScript|AppleScriptTask|Kill|Open\s+\S+\s+For\s+(?:Output|Binary))\b",
    re.IGNORECASE,
)
"""Calls that run a program, fetch from the network, reach native code or write files."""

_EXTERNAL_REL: Final = re.compile(
    rb"<Relationship\b[^>]{0,2048}?>",
    re.IGNORECASE,
)
_ACTIVE_REL_TYPES: Final = (b"/attachedTemplate", b"/oleObject", b"/frame", b"/subDocument")
_DDE: Final = re.compile(
    rb"(?:<w:instrText[^>]{0,256}>|\bw:instr=\")\s*(?:DDEAUTO|DDE)\b", re.IGNORECASE
)


@dataclass(frozen=True)
class Signal:
    kind: str
    """macro, auto_exec, macro_sheet, remote_object, dde, pdf_javascript, pdf_launch,
    pdf_auto_action, pdf_embedded_executable, rtf_object."""
    detail: str
    where: str = ""


@dataclass
class DocumentReport:
    signals: list[Signal] = field(default_factory=list)
    modules: list[VbaModule] = field(default_factory=list)
    partial: bool = False

    def add(self, kind: str, detail: str, where: str = "") -> None:
        if not any(s.kind == kind and s.where == where for s in self.signals):
            self.signals.append(Signal(kind, detail, where))


def kind_of(raw: bytes, path: str) -> str | None:
    """`ooxml`, `ole`, `pdf` or `rtf` for a document this module reads, else None."""
    lowered = path.lower()
    if raw[:8] == OLE_MAGIC:
        return "ole"
    # By suffix: NuGet and VSIX packages are OPC zips with `[Content_Types].xml` too.
    if raw[:4] == b"PK\x03\x04" and lowered.endswith(OFFICE_SUFFIXES):
        return "ooxml"
    if b"%PDF-" in raw[:1024]:
        return "pdf"
    if raw[:5] == b"{\\rtf" or raw[:4] == b"{\\rt":
        return "rtf"
    return None


@bounded
def read(raw: bytes, path: str, *, truncated: bool = False) -> DocumentReport:
    kind = kind_of(raw, path)
    report = DocumentReport(partial=truncated)
    if kind == "ole":
        _read_ole(raw, report, "")
    elif kind == "ooxml":
        _read_ooxml(raw, report)
    elif kind == "pdf":
        _read_pdf(raw, report)
    elif kind == "rtf":
        _read_rtf(raw, report)
    else:
        raise FormatError("not a document this reader handles")
    return report


def _read_ole(raw: bytes, report: DocumentReport, where: str) -> None:
    compound = CompoundFile(raw)
    modules = vba_modules(compound)
    if not modules and not any(
        e.path.lower().endswith(("/vba", "_vba_project_cur")) for e in compound.entries
    ):
        return
    report.add("macro", "a VBA project", where)
    report.modules.extend(modules)
    _judge_modules(modules, report, where)


def _judge_modules(modules: list[VbaModule], report: DocumentReport, where: str) -> None:
    for module in modules:
        # `Attribute` lines are metadata; only the code decides what runs.
        code = "\n".join(
            line for line in module.source.splitlines() if not line.startswith("Attribute ")
        )
        auto = AUTO_EXEC.search(code)
        action = EXEC_OR_FETCH.search(code)
        if auto and action:
            report.add(
                "auto_exec",
                f"module {module.name} defines {auto.group(0)}, which Office runs on its own, "
                f"and calls {action.group(0)}",
                where,
            )


def _read_ooxml(raw: bytes, report: DocumentReport) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        if report.partial:
            return
        raise FormatError("not a readable OOXML package") from exc
    with archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise FormatError(f"the package holds more than {MAX_MEMBERS} parts")
        for info in members:
            name = info.filename
            lowered = name.lower()
            if info.file_size > MAX_MEMBER_BYTES:
                report.partial = True
                continue
            if lowered.endswith("vbaproject.bin"):
                data = archive.read(info)
                try:
                    _read_ole(data, report, name)
                except FormatError:
                    report.add("macro", "a VBA project that could not be read", name)
                    report.partial = True
                report.add("macro", "a VBA project", name)
            elif "/macrosheets/" in lowered or lowered.startswith("xl/macrosheets/"):
                report.add("macro_sheet", "an Excel 4.0 macro sheet", name)
            elif lowered.endswith(".rels"):
                _judge_relationships(archive.read(info), report, name)
            elif lowered.endswith(".xml") and (
                lowered.startswith("word/") or "externallink" in lowered
            ):
                data = archive.read(info)
                if _DDE.search(data) or b"ddeService" in data:
                    report.add(
                        "dde",
                        "a DDE field, which runs a command when the document updates its links",
                        name,
                    )


def _judge_relationships(data: bytes, report: DocumentReport, where: str) -> None:
    for match in _EXTERNAL_REL.finditer(data):
        element = match.group(0)
        if b'TargetMode="External"' not in element:
            continue
        if not any(t in element for t in _ACTIVE_REL_TYPES):
            continue
        target = re.search(rb'Target="([^"]{0,512})"', element)
        value = target.group(1).decode("utf-8", "replace") if target else ""
        lowered = value.lower()
        if lowered.startswith(
            ("http:", "https:", "ftp:", "\\\\", "file:", "mhtml:", "ms-")
        ) or value.endswith("!"):
            kind = next(t for t in _ACTIVE_REL_TYPES if t in element).decode()[1:]
            report.add(
                "remote_object",
                f"a {kind} relationship loads {_host_of(value)} when the document opens",
                where,
            )


def _host_of(target: str) -> str:
    match = re.match(r"(?i)(?:mhtml:)?([a-z][a-z0-9+.-]*):/*([^/\\!?#]*)", target)
    if match:
        return f"{match.group(1)}://{match.group(2)}"
    if target.startswith("\\\\"):
        return "\\\\" + target[2:].split("\\", 1)[0]
    return "an external target"


# -- PDF ---------------------------------------------------------------------------------------

_PDF_NAME: Final = re.compile(rb"/([A-Za-z0-9#]{1,64})")
_PDF_STREAM: Final = re.compile(rb"<<(.{0,4096}?)>>\s*stream\r?\n", re.DOTALL)
_RISKY_URI: Final = re.compile(
    rb"/URI\s*\(\s*((?:javascript|vbscript|file|data|smb|ms-[\w-]+|search-ms):[^)]{0,300}"
    rb"|\\\\[^)]{0,300}"
    rb"|[a-z]+://[^)]{0,300}?\.(?:exe|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|msi|jar|iso|img|dmg|apk)(?:[?#][^)]{0,100})?)\s*\)",
    re.IGNORECASE,
)
"""A link action a viewer follows on a click: script schemes, local files, UNC paths, Windows
protocol handlers, or a download of something that runs. An ordinary https link is not reported."""
_EXECUTABLE_NAME: Final = re.compile(
    rb"\(([^)]{0,256}\.(?:exe|scr|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|msi|dll|jar|sh|app|dmg|iso))\)",
    re.IGNORECASE,
)


def _names(data: bytes) -> set[str]:
    found: set[str] = set()
    for match in _PDF_NAME.finditer(data):
        name = match.group(1)
        if b"#" in name:
            name = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), name)
        found.add(name.decode("latin-1"))
    return found


def _pdf_segments(raw: bytes, report: DocumentReport) -> list[bytes]:
    """The file itself, plus every Flate stream inflated -- object streams hide dictionaries."""
    segments = [raw]
    budget = MAX_INFLATED_BYTES
    for count, match in enumerate(_PDF_STREAM.finditer(raw)):
        if count >= MAX_PDF_STREAMS:
            report.partial = True
            break
        if b"FlateDecode" not in match.group(1) and b"Fl " not in match.group(1):
            continue
        end = raw.find(b"endstream", match.end())
        body = raw[match.end() : end if end >= 0 else len(raw)]
        inflater = zlib.decompressobj()
        try:
            inflated = inflater.decompress(body, budget)
        except zlib.error:
            continue
        budget -= len(inflated)
        if inflater.unconsumed_tail:
            report.partial = True
        segments.append(inflated)
        if budget <= 0:
            report.partial = True
            break
    return segments


def _read_pdf(raw: bytes, report: DocumentReport) -> None:
    names: set[str] = set()
    embedded: list[str] = []
    risky_uri: str | None = None
    for segment in _pdf_segments(raw, report):
        names |= _names(segment)
        if "EmbeddedFile" in names or b"EmbeddedFile" in segment:
            embedded.extend(
                m.group(1).decode("latin-1", "replace") for m in _EXECUTABLE_NAME.finditer(segment)
            )
        if risky_uri is None and b"URI" in segment:
            match = _RISKY_URI.search(segment)
            if match:
                risky_uri = match.group(1).decode("latin-1", "replace")[:120]
    script = names & {"JavaScript", "JS"}
    auto = names & {"OpenAction", "AA"}
    if "Launch" in names:
        report.add("pdf_launch", "a /Launch action, which asks the viewer to run a program")
    if script and auto:
        report.add("pdf_auto_action", f"/{sorted(auto)[0]} runs JavaScript when the document opens")
    elif script:
        report.add("pdf_javascript", "embedded JavaScript")
    if embedded:
        report.add("pdf_embedded_executable", f"an embedded file named {embedded[0]!r}")
    if risky_uri:
        report.add("pdf_risky_uri", f"a /URI action to {risky_uri!r}")


# -- RTF ---------------------------------------------------------------------------------------

_RTF_OBJECT: Final = re.compile(rb"\\object\b")
_RTF_AUTO: Final = re.compile(rb"\\objupdate\b|\\objautlink\b")
_RTF_CLASS: Final = re.compile(rb"\\objclass\s+([^}\\]{1,64})")
_RTF_OBJDATA: Final = re.compile(rb"\\objdata\b([^}]{0,262144})")
_RISKY_CLASSES: Final = (b"equation.3", b"package", b"htmlfile", b"ole2link", b"word.document")


def _read_rtf(raw: bytes, report: DocumentReport) -> None:
    if not _RTF_OBJECT.search(raw) and b"\\objdata" not in raw:
        return
    classes = [m.group(1).strip().lower() for m in _RTF_CLASS.finditer(raw)]
    # The OLE class name is also inside `\objdata`, hex-encoded, where `\objclass` can be omitted.
    risky = [c for c in classes if c.startswith(_RISKY_CLASSES)]
    for match in _RTF_OBJDATA.finditer(raw):
        digits = re.sub(rb"[^0-9A-Fa-f]", b"", match.group(1))[: 2 * 65536]
        decoded = bytes.fromhex(digits[: len(digits) // 2 * 2].decode("ascii")).lower()
        risky.extend(c for c in _RISKY_CLASSES if c in decoded)
    if _RTF_AUTO.search(raw) or risky:
        what = risky[0].decode("latin-1") if risky else "an object"
        report.add("rtf_object", f"an embedded OLE object ({what}) that the reader loads on open")


__all__ = ["AUTO_EXEC", "EXEC_OR_FETCH", "DocumentReport", "Signal", "kind_of", "read"]
