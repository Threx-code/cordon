"""An obfuscation finding, built the one way every obfuscation check builds it.

The rule's severity and message at the hit, lowered where the file is documentation, test material
or generated output and raised where it runs at install time, with a masked snippet as evidence."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.shared.source_paths import FIXTURE_CEILING, SourcePaths
from cordon_scanner.decide.scoring import ScoringContext
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.secrets.secrets import RULE_MATERIAL_CEILING
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.models import (
    Category,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)
from cordon_scanner.foundation.text.redact import Redactor

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent
from cordon_scanner.detect.code.obfuscation.text import Hit, ObfuscationText

TAG_SMUGGLING_RULE = "SUSPECT.OBFUSCATION.TAG_SMUGGLING.001"
"""Not ceilinged in documentation: a README is what an agent is told to read."""

SOURCE_MAP_TRAILER = re.compile(
    rb"(?://|/\*)# sourceMappingURL=[^\s]{1,300}\s{0,8}(?:\*/)?\s{0,8}$"
)
"""The comment a bundler appends to point a debugger at the original source."""


class ObfuscationFinding:
    """Building an obfuscation finding from a rule and a hit."""

    DESCRIPTION_VALUE: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?:\b(?:long_)?description\s{0,4}=|["'](?:long_)?description["']\s{0,4}:)"""
    )

    #: What turns a long line in an install hook into a payload: it is run, or decoded to be run.
    RUNS_LONG_LINE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:exec|eval|compile|b64decode|a85decode|b32decode|decompress|loads|unhexlify|fromhex|"
        r"Function)\s*\("
    )

    @staticmethod
    def _long_line_runs(content: FileContent, offset: int) -> bool:
        """Whether a long line in an install hook is install-time payload, as against a README
        inlined as `long_description` -- what a poetry-generated `setup.py` holds (review 98,
        FP-5: pfzy, grpc-interceptor, InquirerPy).

        Judged by excluding that one shape, not by requiring an `exec`: `mariabd`'s `setup.py`
        writes a 2,263-character obfuscated browser extension to `%APPDATA%` with `.write()` and
        points every browser shortcut at it, and a rule that escalated only executed or decoded
        lines let it and seven other malregistry and DataDog payloads through (measured on the
        v10 malware run). A description is prose for an index page; anything else that long in
        code an installer runs is the payload until shown otherwise."""
        text = content.text
        start = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        line = text[start : len(text) if end == -1 else end]
        if ObfuscationFinding.RUNS_LONG_LINE.search(line):
            return True
        return ObfuscationFinding.DESCRIPTION_VALUE.search(line) is None

    @staticmethod
    def _long_line_executed(content: FileContent, offset: int) -> bool:
        text = content.text
        start = text.rfind("\n", 0, offset) + 1
        end = text.find("\n", offset)
        line = text[start : len(text) if end == -1 else end]
        return ObfuscationFinding.RUNS_LONG_LINE.search(line) is not None

    #: The id every obfuscation finding carries, wherever in the package it is built.
    DETECTOR: ClassVar[str] = "obfuscation"

    @classmethod
    def finding(cls, hit: Hit, unit: FileUnit, ctx: ScanContext) -> Finding:
        content = unit.content
        # The same ceiling the secrets detector and the composites apply, and these
        # rules need it for a reason of their own: a file that DETECTS an obfuscation
        # technique has to contain the technique.
        #
        # Bandit's `plugins/trojansource.py` and `examples/trojansource.py` were both
        # reported at HIGH for bidirectional characters in source. The first is the
        # plugin that finds Trojan Source attacks; the second is the example it was
        # written against. Every scanner in this category hits this on its own corpus
        # and on every repository that vendors security rules, and telling those users
        # their rule set is an attack is how a tool teaches people to ignore it.
        #
        # A ceiling rather than a path exemption: the characters really are there, and
        # a real override smuggled into a fixture directory is still worth finding.
        # What changes is whether it fails a build.
        severity = hit.severity
        severity = ObfuscationFinding._ceiling(content, ctx, hit, severity)
        severity = ObfuscationFinding._escalated(content, ctx, hit, severity, unit)
        return cls._scored(content, ctx, hit, severity, unit)

    @staticmethod
    def _ceiling(content: FileContent, ctx: ScanContext, hit: Hit, severity: Severity) -> Severity:
        """The ceiling a hit's place puts on it: rule material, test material, documentation or generated output."""
        if content.is_rule_material:
            # Bandit's pair is the canonical case and is in this detector's own history:
            # `plugins/trojansource.py` finds Trojan Source attacks and
            # `examples/trojansource.py` is the example it matches. Any repository that
            # vendors a rule set has the shape. See `core.samples`.
            severity = min(severity, RULE_MATERIAL_CEILING)
        elif (
            SourcePaths.is_test_material_here(content.path, ctx)
            or (SourcePaths.is_documentation(content.path) and hit.rule_id != TAG_SMUGGLING_RULE)
            or (
                SourcePaths.is_generated_artefact(content.path)
                and not ObfuscationText._obfuscator_io(hit)
            )
            # Or somebody else wrote it. What prompted this is the packer rule,
            # whose entire remaining volume is a third party's minified
            # JavaScript: `octobercms/october` carries SyntaxHighlighter 3.0.83
            # under `modules/system/assets/vendor/`, still wearing Alex
            # Gorbatchev's copyright header, and `Qloapps/QloApps` has four jQuery
            # plugins under `js/jquery/plugins/` with Andreas Eberhard's. The
            # rule's claim stays true -- a packed file cannot be reviewed -- but
            # its remediation, "obtain the original source and review that", is
            # upstream's work. The capability detector has ceilinged vendored code
            # for this reason since the twenty-third round; this detector was not
            # asking.
            #
            # **This block is shared by every rule in this detector**, so the
            # ceiling reaches the bidirectional and escape-run rules too, and that
            # is deliberate rather than incidental: the three tests beside it
            # already do the same, and a bidi override in a test fixture has been
            # ceilinged since they were added. What it gives up, stated: a
            # directional override smuggled into a checked-in dependency drops
            # below the failure gate. Two things bound that. `node_modules` --
            # where an installed compromise actually lands -- never reaches here,
            # because the walker prunes it and reports the prune. And a `vendor/`
            # tree is committed code, so the override arrives in a diff somebody
            # can see, which is the condition Trojan Source needs to defeat and
            # the reason it is a ceiling rather than an exemption.
            or SourcePaths.is_vendored(content.path)
            # A bidirectional mark in a bundle that names its source map: webpack and Vite
            # output, where the mark sits in a library's Unicode tables (KaTeX's tokenizer
            # ranges over U+202A) and the reviewable source is elsewhere. For this rule only --
            # a trailer is one line anybody can append, and the packer rules must not trust it.
            or (
                hit.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"
                and SOURCE_MAP_TRAILER.search(content.raw[-400:]) is not None
            )
        ):
            severity = min(severity, FIXTURE_CEILING)
        return severity

    @staticmethod
    def _escalated(
        content: FileContent, ctx: ScanContext, hit: Hit, severity: Severity, unit: FileUnit
    ) -> Severity:
        """The grade a hit's context raises it to: a long line or encoded run that runs at install time."""
        # Obfuscated code an install hook runs is never a build artefact somebody forgot to
        # exclude: it executes on every install, unread. `sensitive-paths-focus` named its
        # obfuscator.io payload `CHANGELOG.js` and ran it from `postinstall`.
        if (
            hit.rule_id
            in (
                "SUSPECT.OBFUSCATION.PACKED.001",
                "SUSPECT.OBFUSCATION.ENCODED.001",
                # A line of high-entropy text that is not minified output -- the rule excludes
                # minification -- is a payload kept off the screen; in a `setup.py` it was 60 KB
                # of base64 written out and run.
                "SUSPECT.OBFUSCATION.LONGLINE.001",
            )
            and ctx.in_install_hook(content.path)
            and severity < Severity.HIGH
            and (
                hit.rule_id != "SUSPECT.OBFUSCATION.LONGLINE.001"
                or ObfuscationFinding._long_line_runs(content, hit.start)
            )
        ):
            severity = Severity.HIGH
        elif (
            hit.rule_id == "SUSPECT.OBFUSCATION.LONGLINE.001"
            and (content.path in ctx.import_entry_paths or ctx.in_install_hook(content.path))
            and severity < Severity.HIGH
            and (
                hit.offscreen
                # A long executed line counts only in a Python entry point: a JavaScript `main` is
                # very often a minified bundle whose long lines hold `Function(` and `eval(` by
                # construction -- 48 benign npm packages' `index.js` were blocked by it (review 98).
                or (
                    unit.language == "python"
                    and ObfuscationFinding._long_line_executed(content, hit.start)
                )
            )
        ):
            # A published package's entry point -- the `__init__.py` every `import` runs --
            # holding a long high-entropy line that is itself executed or decoded: the payload
            # runs for every consumer without any hook. Stricter than the install-hook case:
            # entry points carry tables and data, so the line has to be what runs. The Roblox
            # cookie stealers in malregistry hide behind exactly this (review 98).
            severity = Severity.HIGH
        return severity

    @classmethod
    def _scored(
        cls, content: FileContent, ctx: ScanContext, hit: Hit, severity: Severity, unit: FileUnit
    ) -> Finding:
        """The obfuscation finding, scored, with its masked evidence."""
        return Finding(
            rule_id=hit.rule_id,
            category=Category.SUSPICIOUS,
            severity=severity,
            confidence=hit.confidence,
            message=hit.message,
            location=Location(
                path=content.path,
                line=content.line_of(hit.start),
                column=content.column_of(hit.start),
                byte_start=hit.start,
                byte_end=hit.end,
                project=unit.project,
            ),
            evidence=Redactor.build_evidence(content, hit.start, hit.end, RedactionMode.MASKED)
            if hit.rule_id != "SUSPECT.OBFUSCATION.BIDI.001"
            else Evidence(
                # A bidi snippet would render in the report exactly as it renders
                # in the editor, which is the problem being reported. Only the
                # position and the hash are emitted.
                kind=EvidenceKind.HASH,
                match_hash=Evidence.hash_bytes(content.slice(hit.start, hit.end)),
                redaction=RedactionMode.HASH_ONLY,
                span=(hit.start, hit.end),
            ),
            remediation=hit.remediation,
            explanation=Explanation(summary=hit.title, matched_rule=hit.rule_id),
            risk=ctx.scorer.score(
                hit.severity,
                hit.confidence,
                ScoringContext(
                    in_install_hook=ctx.in_install_hook(content.path),
                    is_obfuscated=True,
                    capabilities=frozenset({Capability.DECODE}),
                ),
            ),
            detector=cls.DETECTOR,
            capabilities=(Capability.DECODE,),
        )


__all__ = ["SOURCE_MAP_TRAILER", "TAG_SMUGGLING_RULE", "ObfuscationFinding"]
