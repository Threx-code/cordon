"""Model files, office documents, PDFs and images: the parts of them that run.

Source scanners read text, and these arrive as binaries: a model checkpoint in a repository, a
`.docm` in a docs folder, a PNG logo in a package. Each carries a way to execute on open -- a
pickle names callables for `pickle.load` to call, a document names a macro or a remote template,
an image hides a payload after its end marker -- that no text rule sees. The readers in
`cordon_scanner.formats` parse each format by structure without loading, rendering or running it.

A file whose header says it is one of these formats and whose body cannot be read is reported as
not examined (`OPERATIONAL.FORMAT.UNREADABLE`, which marks the scan incomplete), never as clean.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from cordon_scanner.core import references as ref
from cordon_scanner.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.core.scoring import ScoringContext
from cordon_scanner.detect.base import BaseDetector, DetectorRequirements, FileUnit
from cordon_scanner.detect.catalogue import DeclaredRule
from cordon_scanner.detect.secrets import SourcePaths
from cordon_scanner.formats import FormatError, documents, media, pickles

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext, Unit

MAX_IMPORTS_LISTED: Final = 8


@dataclass(frozen=True)
class FormatRule:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    references: tuple[str, ...] = ()


class FormatRules:
    """Building the format detector's rules."""

    @staticmethod
    def _rule(*args: Any, **kwargs: Any) -> FormatRule:
        return FormatRule(*args, **kwargs)


RULES: Final = {
    rule.rule_id: rule
    for rule in (
        FormatRules._rule(
            "MALWARE.MODEL.PICKLE_EXEC.001",
            "A pickle that runs a command, reaches the network or evaluates code when loaded",
            Category.MALICIOUS,
            Severity.CRITICAL,
            Confidence.HIGH,
            "This pickle imports a callable that runs commands, opens connections, writes files "
            "or evaluates code. Unpickling calls what the stream imports, so `pickle.load`, "
            "`torch.load` or `joblib.load` on this file runs it.",
            "Do not load the file. Obtain the model as safetensors, or load it with "
            "`torch.load(weights_only=True)` after confirming its source.",
            (ref.UNTRUSTED_DESERIALIZATION, ref.PICKLE_SECURITY),
        ),
        FormatRules._rule(
            "SUSPECT.MODEL.PICKLE_IMPORT.001",
            "A pickle imports something ordinary model files do not",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.LOW,
            "This pickle imports callables outside the libraries model files are normally built "
            "from, or builds an import from values this reader could not resolve. Loading it "
            "calls them.",
            "Check what the listed callables do before loading the file, or load it with "
            "`torch.load(weights_only=True)`.",
            (ref.UNTRUSTED_DESERIALIZATION, ref.PICKLE_SECURITY),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.MACRO.001",
            "An office document carries macros",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "This document carries a VBA project or an Excel 4.0 macro sheet: code that runs in "
            "Office with the rights of whoever opens it.",
            "Remove the macros (save as .docx/.xlsx/.pptx) unless the document needs them, and "
            "review the source if it does.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.AUTO_EXEC.001",
            "A macro runs by itself on open and starts a program or fetches from the network",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This document's VBA defines a procedure Office runs by itself when the document "
            "opens or closes, and the same module starts a program, fetches from the network or "
            "calls native code.",
            "Do not enable content in this document. Remove the macro, or replace the document "
            "with one from a trusted source.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.REMOTE_OBJECT.001",
            "A document loads a template or object from elsewhere when opened",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This document declares an external template, frame or OLE object relationship. "
            "Office fetches it when the document opens, with no macro and no prompt -- the "
            "mechanism of remote template injection and of CVE-2022-30190.",
            "Remove the external relationship from the package, or replace the document.",
            (ref.ATTACK_TEMPLATE_INJECTION, ref.CVE_2022_30190),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.DDE.001",
            "A document contains a DDE field",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This document contains a DDE or DDEAUTO field, or a DDE external link. Updating the "
            "document's links runs the command the field names, without macros.",
            "Remove the field. Documents rarely need DDE; its common use now is to run a command.",
            (ref.ATTACK_DDE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.PDF_AUTO_ACTION.001",
            "A PDF runs JavaScript when it is opened",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This PDF declares an action that runs on open (/OpenAction or /AA) and carries "
            "JavaScript. A viewer with scripting enabled runs it without a click.",
            "Remove the script and the open action, or regenerate the PDF from its source.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.PDF_LAUNCH.001",
            "A PDF asks the viewer to launch a program",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.HIGH,
            "This PDF contains a /Launch action, which asks the viewer to start a program or open "
            "a file with its default handler.",
            "Remove the action or regenerate the PDF from its source.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.PDF_JAVASCRIPT.001",
            "A PDF carries JavaScript",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.LOW,
            "This PDF carries JavaScript. Forms use it legitimately; it is also the usual way a "
            "PDF exploits its viewer.",
            "Confirm the document needs scripting, or regenerate it without.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.PDF_EMBEDDED_EXECUTABLE.001",
            "A PDF embeds a file with an executable name",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This PDF embeds a file whose name ends in an executable or script extension. Viewers "
            "offer to open embedded files, which runs them.",
            "Remove the attachment, or deliver the file separately where it can be scanned.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.PDF_RISKY_URI.001",
            "A PDF link opens a script, a local file or a download that runs",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "This PDF has a /URI link whose target is a script scheme, a local or network file path, "
            "a Windows protocol handler, or a download of an executable. One click from the reader "
            "runs or fetches it.",
            "Remove the link, or point it at an ordinary web page.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
        FormatRules._rule(
            "SUSPECT.DOCUMENT.RTF_OBJECT.001",
            "An RTF document embeds an object that loads itself",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This RTF document embeds an OLE object that updates on open, or one of the classes "
            "RTF exploits have loaded (Equation Editor, Package, OLE2Link).",
            "Remove the object, or convert the document to a format without embedded objects.",
            (ref.ATTACK_MALICIOUS_FILE, ref.CVE_2017_11882),
        ),
        FormatRules._rule(
            "SUSPECT.MEDIA.APPENDED_PAYLOAD.001",
            "An image has an archive, executable or script appended after its end",
            Category.SUSPICIOUS,
            Severity.HIGH,
            Confidence.MEDIUM,
            "This image has data after its end marker, and the data starts as an archive, an "
            "executable or a script. Viewers stop at the end marker, so the payload is invisible "
            "to anyone who looks at the picture.",
            "Re-export the image from its source. If it came with a package, examine what reads "
            "the file past its end.",
            (ref.ATTACK_STEGANOGRAPHY,),
        ),
        FormatRules._rule(
            "SUSPECT.MEDIA.OPAQUE_TRAILER.001",
            "A file carries a large, near-random block after its end",
            Category.SUSPICIOUS,
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "This image or archive has kilobytes of near-random data after its end marker. Editors "
            "leave metadata there, which is far from random; an encrypted or compressed second stage "
            "is not, and a loader elsewhere reads it past the point any viewer stops.",
            "Re-export the file from its source, and look for the code that reads past its end.",
            (ref.ATTACK_STEGANOGRAPHY,),
        ),
        FormatRules._rule(
            "SUSPECT.MEDIA.TRAILING_DATA.001",
            "An image has data after its end",
            Category.SUSPICIOUS,
            Severity.LOW,
            Confidence.LOW,
            "This image has data after its end marker. Some editors leave metadata there; it is "
            "also where a payload is hidden inside a picture.",
            "Re-export the image from its source to drop the trailing data.",
            (ref.ATTACK_STEGANOGRAPHY,),
        ),
        FormatRules._rule(
            "OPERATIONAL.FORMAT.UNREADABLE",
            "A model, document or image could not be read",
            Category.OPERATIONAL,
            Severity.INFO,
            Confidence.HIGH,
            "This file's header identifies a format Cordon reads for active content, and its body "
            "could not be read within the reader's limits, so its content was not examined.",
            "Examine the file by other means; a malformed file of this kind is itself unusual.",
            (ref.ATTACK_MALICIOUS_FILE,),
        ),
    )
}

_DOCUMENT_RULES: Final = {
    "macro": "SUSPECT.DOCUMENT.MACRO.001",
    "macro_sheet": "SUSPECT.DOCUMENT.MACRO.001",
    "auto_exec": "SUSPECT.DOCUMENT.AUTO_EXEC.001",
    "remote_object": "SUSPECT.DOCUMENT.REMOTE_OBJECT.001",
    "dde": "SUSPECT.DOCUMENT.DDE.001",
    "pdf_auto_action": "SUSPECT.DOCUMENT.PDF_AUTO_ACTION.001",
    "pdf_launch": "SUSPECT.DOCUMENT.PDF_LAUNCH.001",
    "pdf_javascript": "SUSPECT.DOCUMENT.PDF_JAVASCRIPT.001",
    "pdf_embedded_executable": "SUSPECT.DOCUMENT.PDF_EMBEDDED_EXECUTABLE.001",
    "rtf_object": "SUSPECT.DOCUMENT.RTF_OBJECT.001",
    "pdf_risky_uri": "SUSPECT.DOCUMENT.PDF_RISKY_URI.001",
}


class FormatDetector(BaseDetector):
    """Pickles, office documents, PDFs and images, read by structure for what runs on open."""

    id = "formats"
    version = "0.1.0"
    categories = frozenset({Category.MALICIOUS, Category.SUSPICIOUS, Category.OPERATIONAL})
    requires = DetectorRequirements(content=True)

    def applicable(self, ctx: ScanContext) -> bool:
        return True

    @staticmethod
    def declared_rules() -> tuple[DeclaredRule, ...]:
        return tuple(
            DeclaredRule(
                id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                detector=FormatDetector.id,
                message=rule.message,
                remediation=rule.remediation,
                references=rule.references,
            )
            for rule in RULES.values()
        )

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        if not isinstance(unit, FileUnit):
            return ()
        content = unit.content
        raw = content.raw
        if len(raw) < 8:
            return ()
        path = content.path.rpartition("!")[2].lower()
        try:
            if path.endswith(pickles.ALWAYS_PICKLE) or (
                path.endswith(pickles.PICKLE_SUFFIXES)
                and pickles.PickleReader.looks_like_pickle(raw)
            ):
                return self._pickle(unit, ctx)
            if documents.DocumentReader.kind_of(raw, path) is not None:
                return self._document(unit, ctx)
            if media.ImageTrailers.image_format(raw) is not None and not content.truncated:
                # A broken image is common (placeholders, partial downloads) and nothing reads
                # past an end it does not have, so it is skipped rather than made incomplete.
                with contextlib.suppress(FormatError):
                    return self._image(unit, ctx)
                return ()
        except FormatError as exc:
            return [self._finding("OPERATIONAL.FORMAT.UNREADABLE", unit, ctx, detail=str(exc))]
        return ()

    def _pickle(self, unit: FileUnit, ctx: ScanContext) -> list[Finding]:
        report = pickles.PickleReader.read(unit.content.raw, truncated=unit.content.truncated)
        dangerous = sorted({i.dotted for i in report.imports if i.dangerous})
        if dangerous:
            listed = ", ".join(dangerous[:MAX_IMPORTS_LISTED])
            return [
                self._finding(
                    "MALWARE.MODEL.PICKLE_EXEC.001", unit, ctx, detail=f"It imports {listed}."
                )
            ]
        unknown = sorted({i.dotted for i in report.imports if not i.recognised})
        if unknown:
            listed = ", ".join(unknown[:MAX_IMPORTS_LISTED])
            return [
                self._finding(
                    "SUSPECT.MODEL.PICKLE_IMPORT.001", unit, ctx, detail=f"It imports {listed}."
                )
            ]
        return []

    def _document(self, unit: FileUnit, ctx: ScanContext) -> list[Finding]:
        report = documents.DocumentReader.read(
            unit.content.raw, unit.content.path, truncated=unit.content.truncated
        )
        kinds = {s.kind for s in report.signals}
        findings: list[Finding] = []
        seen: set[str] = set()
        for signal in report.signals:
            # An auto-running macro subsumes the plain "has macros" finding for the same file.
            if signal.kind in ("macro", "macro_sheet") and "auto_exec" in kinds:
                continue
            rule_id = _DOCUMENT_RULES[signal.kind]
            if rule_id in seen:
                continue
            seen.add(rule_id)
            where = f" (in {signal.where})" if signal.where else ""
            findings.append(
                self._finding(rule_id, unit, ctx, detail=f"Found {signal.detail}{where}.")
            )
        return findings

    def _image(self, unit: FileUnit, ctx: ScanContext) -> list[Finding]:
        found = media.ImageTrailers.trailer(unit.content.raw)
        if found is None:
            return []
        detail = f"{found.size} bytes follow the {found.format} end marker at offset {found.offset}"
        if found.looks_like:
            return [
                self._finding(
                    "SUSPECT.MEDIA.APPENDED_PAYLOAD.001",
                    unit,
                    ctx,
                    detail=f"{detail}, starting as {found.looks_like}.",
                )
            ]
        if found.opaque:
            return [
                self._finding(
                    "SUSPECT.MEDIA.OPAQUE_TRAILER.001",
                    unit,
                    ctx,
                    detail=f"{detail}, at {found.entropy:.2f} bits per byte.",
                )
            ]
        return [self._finding("SUSPECT.MEDIA.TRAILING_DATA.001", unit, ctx, detail=f"{detail}.")]

    def _finding(
        self, rule_id: str, unit: FileUnit, ctx: ScanContext, *, detail: str = ""
    ) -> Finding:
        rule = RULES[rule_id]
        content = unit.content
        severity = rule.severity
        message = f"{rule.message} {detail}".strip()
        if rule.category not in (
            Category.MALICIOUS,
            Category.OPERATIONAL,
        ) and SourcePaths.is_test_material(content.path):
            severity = min(severity, Severity.LOW)
            message += " It sits under a path that holds test material, so it is reported below its usual severity."
        elif rule.category not in (Category.MALICIOUS, Category.OPERATIONAL) and (
            SourcePaths.is_documentation(content.path) or SourcePaths.is_vendored(content.path)
        ):
            # A PDF in a bundled library's `docs/` is that project's paper, read by nobody's
            # installer: rapidfuzz carries taskflow's under `extern/taskflow/docs/`.
            severity = min(severity, Severity.MEDIUM)
            message += " It sits in documentation or bundled third-party material, so it is reported below the gate."
        return Finding(
            rule_id=rule.rule_id,
            category=rule.category,
            severity=severity,
            confidence=rule.confidence,
            message=message,
            location=Location(path=content.path, project=unit.project),
            evidence=Evidence(
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(content.raw[:65536] + rule.rule_id.encode()),
                redaction=RedactionMode.HASH_ONLY,
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=rule.rule_id),
            risk=ctx.scorer.score(severity, rule.confidence, ScoringContext()),
            detector=self.id,
            references=rule.references,
        )


__all__ = ["RULES", "FormatDetector"]
