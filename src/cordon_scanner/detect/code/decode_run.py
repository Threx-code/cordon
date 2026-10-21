"""Whether a run the decode-run composites pair with could be of the decoded value.

`SUSPECT.DECODE_EXEC.001` and `MALWARE.INSTALL.DECODED_LAUNCH.001` pair a decode with something that
runs. The decoded value cannot be inside a run whose command and arguments carry nothing decoded or
otherwise tracked: `execFileSync(PYTHON, ['-c', '...'])` beside an unrelated `Buffer.from(png,
'base64')`. js_flow proves that on a hand-written JavaScript file -- its `decoded` source makes a
real `decode -> exec` keep the pairing -- and the Python AST's `fixed` marks a wholly literal argv.
A `decode -> writeFile(p) -> exec(p)` keeps the pairing: the written path then carries the decoded
label (js_flow), or the literal path names a file the unit writes. Unresolved, dynamic, minified or
bundled code keeps today's proximity pairing (fail-closed).

`excused_lines` is taken by LINE, as `_evaluate_over`'s fixed-argv discount is, so both the pattern
and AST hits for one call are dropped: `fixed` sits only on the AST hit, and the pattern hit on the
same line would otherwise satisfy the term anyway.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.foundation.models import Capability

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import FileUnit
    from cordon_scanner.detect.code.capability import CapabilityHit
    from cordon_scanner.foundation.content import FileContent


class DecodeRun:
    """The decode-run composites and the spawns that cannot be running their decoded value."""

    COMPOSITES: ClassVar[frozenset[str]] = frozenset(
        {"SUSPECT.DECODE_EXEC.001", "MALWARE.INSTALL.DECODED_LAUNCH.001"}
    )

    _WRITTEN_LITERAL_PATH: ClassVar[re.Pattern[str]] = re.compile(
        r"""(?:writeFile(?:Sync)?|appendFile(?:Sync)?|outputFile(?:Sync)?|write_bytes|write_text)"""
        r"""\s*\(\s*["'`]([^"'`\n]{1,200})["'`]"""
        r"""|open\s*\(\s*["'`]([^"'`\n]{1,200})["'`]\s*,\s*["'`][wax+b]{1,3}["'`]""",
        re.I,
    )

    _JS: Final = frozenset({"javascript", "typescript"})

    #: A decode in the argv means the run is OF decoded content, so a `fixed` spawn is not excused
    #: even when its argv folds to a constant: `exec(b64decode('...'))` is the dropper itself. (The
    #: JavaScript path does not need this -- js_flow's `decoded` source already keeps such a call.)
    _DECODE_CALL: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:b64decode|b32decode|b85decode|a85decode|decodebytes|unhexlify|decompress"
        r"|gunzip|inflate|brotli|atob|fromhex|frombase64)\b"
        r"|Buffer\.from\([^)\n]{0,200}?(?:base64|hex)",
        re.I,
    )

    @classmethod
    def _written_literal_paths(cls, content: FileContent) -> frozenset[str]:
        """Literal file paths this unit writes to (`writeFileSync("x.js", ...)`, `open("x", "w")`),
        so a `fixed` spawn naming one is kept: it may run a decoded payload written there."""
        out: set[str] = set()
        for m in cls._WRITTEN_LITERAL_PATH.finditer(content.text):
            if m.group(1) or m.group(2):
                out.add(m.group(1) or m.group(2))
        return frozenset(out)

    @classmethod
    def excused_lines(
        cls, unit: FileUnit, hits: list[CapabilityHit], bundled: bool, rule_ids: Iterable[str]
    ) -> frozenset[int]:
        """Lines whose run cannot be of decoded content, so a spawn or execute there does not pair
        with a decode. Empty, computing nothing, unless a decode-run composite is among `rule_ids`.
        See the module docstring."""
        if not any(r in cls.COMPOSITES for r in rule_ids):
            return frozenset()
        content = unit.content
        safe_spawn: frozenset[int] = frozenset()
        if not bundled and unit.language in cls._JS:
            from cordon_scanner.analysis.javascript.js_flow import JsFlow

            safe_spawn = JsFlow.safe_spawn_lines(content.text)
        elif not bundled and unit.language == "python":
            # The Python analogue: a spawn whose command folds from literals and interpreter
            # constants only (`os.system(f"{sys.executable} -m pip install …")`) cannot be running
            # the file's decoded bytes, which go to `write_bytes`/a data URI (review 98 media skills).
            from cordon_scanner.analysis.python.pyast import PythonAnalyzer

            safe_spawn = PythonAnalyzer.safe_spawn_lines(content.text)
        written = cls._written_literal_paths(content) if hits else frozenset()
        fixed: set[int] = set()
        for h in hits:
            if h.capability is Capability.SPAWN and h.fixed:
                text = content.raw[h.byte_start : max(h.byte_end, h.byte_start + 1)].decode(
                    "utf-8", "replace"
                )
                if not any(p in text for p in written) and not cls._DECODE_CALL.search(text):
                    fixed.add(h.line)
        return safe_spawn | fixed

    @classmethod
    def hits_for(
        cls, rule_id: str, hits: list[CapabilityHit], excused: frozenset[int]
    ) -> list[CapabilityHit]:
        """The hits a composite is evaluated over: for a decode-run composite, `hits` with the
        spawn and execute hits on excused lines removed; otherwise `hits` unchanged."""
        if rule_id not in cls.COMPOSITES:
            return hits
        return [
            h
            for h in hits
            if not (h.capability in (Capability.SPAWN, Capability.EXECUTE) and h.line in excused)
        ]
