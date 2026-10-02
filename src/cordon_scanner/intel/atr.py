"""The Agent Threat Rules catalogue, evaluated over text a repository hands an agent.

ATR (https://github.com/Agent-Threat-Rule/agent-threat-rules, MIT licensed) catalogues AI agent
threats -- prompt injection, tool poisoning, context exfiltration, agent manipulation, privilege
escalation, skill compromise -- as regular expressions over named text fields, each rule tested
against its own attack and benign examples. `scripts/import_atr.py` converts it to
`data/atr-rules.json.gz`: Python's regex dialect, every pattern timed against backtracking inputs,
every rule re-checked against its own test cases and measured against ATR's benign corpus.

ATR is written for traffic: a prompt, a tool's response, a tool call's arguments. A repository
carries the same text in files -- an instruction file, a skill, the tool descriptions in its own MCP
server, a hook's command. Evaluation follows ATR's reference engine: every pattern is
case-insensitive; text is normalised (NFKC, invisible characters removed, Cyrillic and Greek
lookalikes folded to Latin) and the raw text is tried as well; base64 blocks are decoded once and
read too; and a rule that asks for it ignores matches inside fenced code blocks.

Each rule is graded by how often it matched ATR's benign corpus -- published skills,
conversations, package descriptions -- which is the text an instruction file most resembles, so a
rule that flags any text addressing an agent is measured doing so and demoted for it.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import gzip
import json
import re
import unicodedata
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import cache
from typing import Final

from cordon_scanner.intel.advisories import DATA_DIR, AdvisoryFiles

FILE_NAME: Final = "atr-rules.json.gz"

KINDS: Final = {
    "content": "text",
    "user_input": "text",
    "tool_description": "tool",
    "tool_response": "tool",
    "tool_name": "tool_name",
    "tool_args": "command",
    "tool_input": "command",
}
"""ATR field -> the family of repository text its rules are evaluated over."""

TEXT_KINDS: Final = ("text", "tool", "command")
"""Every family but tool names, for any text an agent is handed.

ATR's own test cases cross fields freely -- a tool-argument rule's attack written as prose, a
content rule's as a command -- so each piece of repository text is checked against all of them.
What keeps that precise is the measurement: `import_atr.py` ran every rule over every benign
sample whatever its field, so a rule that misfires on text addressed to an agent (a published
skill, say) is measured doing so and graded down for it."""

CHUNK: Final = 4096
"""The longest text one pattern is run over: the length `import_atr.py` timed every pattern at."""
_OVERLAP: Final = 512

RULE_URL: Final = "https://agentthreatrule.org/en/rules/{}"

PRODUCTION_AT_MOST: Final = 0.005
DEMOTED_ABOVE: Final = 0.02
"""ATR's published lines (docs/QUALITY-STANDARD.md): a rule is production-grade at a benign
false-positive rate of 0.5% or less, and demoted out of the blocking tier above 2%."""


@dataclass(frozen=True)
class Condition:
    kind: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class AtrRule:
    rule_id: str
    title: str
    category: str
    severity: str
    status: str
    every: bool
    conditions: tuple[Condition, ...]
    benign_rate: float
    """The share of ATR's benign corpus this rule matched when it was imported, 0.0 to 1.0."""
    outside_code: bool = False
    """The rule ignores matches inside fenced code blocks (ATR's `suppress_in_code_blocks`)."""
    instruction_rate: float | None = None
    """The share of real repository instruction files it matched, when that was measured."""
    instruction_hits: int | None = None
    """How many of those real instruction files it matched."""

    @property
    def grade(self) -> str:
        """ATR's quality standard: production at or below 0.5% benign matches, demoted above 2%."""
        return AtrRule._grade(self.benign_rate)

    @property
    def instruction_grade(self) -> str:
        """The same standard, over real instruction files as well: the stricter of the two.

        An instruction file is written to the agent and full of commands, which ATR's benign
        corpus has little of; a rule clean there can still flag ordinary CLAUDE.md files.
        """
        if self.instruction_rate is None:
            return self.grade
        order = ("production", "warn", "observe")
        return max(self.grade, AtrRule._grade(self.instruction_rate), key=order.index)

    @staticmethod
    def _grade(rate: float) -> str:
        if rate > DEMOTED_ABOVE:
            return "observe"
        if rate > PRODUCTION_AT_MOST:
            return "warn"
        return "production"


@dataclass(frozen=True)
class AtrMatch:
    rule: AtrRule
    start: int
    end: int


@dataclass(frozen=True)
class Catalogue:
    rules: tuple[AtrRule, ...]
    commit: str
    refused: bool
    """The bundled file failed its recorded digest and was not read."""


class AtrText:
    "Text made ready for the rules the way ATR's engine prepares it: normalised, chunked, decoded."

    @staticmethod
    def flags_of(letters: str) -> int:
        """Python flags for an ATR pattern. ATR's reference engine compiles every pattern
        case-insensitive whatever its inline flags say, and a rule's test cases are written to that."""
        value = re.IGNORECASE
        for letter in letters:
            value |= {"m": re.MULTILINE, "s": re.DOTALL}.get(letter, 0)
        return value

    @staticmethod
    def normalise(text: str) -> str:
        """NFKC, with zero-width and direction-override characters removed and lookalikes folded."""
        return _INVISIBLE.sub("", unicodedata.normalize("NFKC", text)).translate(_CONFUSABLES)

    @staticmethod
    def decoded_blocks(text: str) -> list[tuple[int, int, str]]:
        """Text hidden as base64: up to five blocks, decoded once, kept when they read as text.

        Each is `(start, end, decoded)`, the span being where the block sits in `text`.
        """
        found: list[tuple[int, int, str]] = []
        for match in _BASE64_BLOCK.finditer(text):
            if len(found) >= _MAX_DECODED_BLOCKS:
                break
            block = match.group(0)
            try:
                raw = base64.b64decode(block + "=" * (-len(block) % 4))
            except (ValueError, binascii.Error):
                continue
            decoded = raw.decode("utf-8", "replace")
            printable = sum(1 for c in decoded if 32 <= ord(c) < 127)
            if len(decoded) >= 10 and printable / len(decoded) > 0.7:
                found.append((match.start(), match.end(), decoded[:100_000]))
        return found

    @staticmethod
    def code_block_ranges(text: str) -> list[tuple[int, int]]:
        """The spans of fenced code blocks, fences paired line by line as ATR's engine pairs them."""
        ranges: list[tuple[int, int]] = []
        opened: int | None = None
        position = 0
        for line in text.split("\n"):
            if line.lstrip().startswith("```"):
                if opened is None:
                    opened = position
                else:
                    ranges.append((opened, position + len(line) + 1))
                    opened = None
            position += len(line) + 1
        return ranges

    @staticmethod
    def chunks(text: str) -> Iterator[tuple[int, str]]:
        """`text` in pieces of at most `CHUNK` characters, at paragraph breaks where it can.

        A paragraph longer than a chunk is cut with an overlap, so a phrase spanning the cut is still
        whole in one of the two pieces.
        """
        start = 0
        length = len(text)
        while start < length:
            end = min(length, start + CHUNK)
            if end < length:
                cut = text.rfind("\n\n", start + CHUNK // 2, end)
                if cut > start:
                    end = cut
            yield start, text[start:end]
            if end >= length:
                return
            start = end if text.startswith("\n\n", end) else max(start + 1, end - _OVERLAP)

    @staticmethod
    def _views(text: str) -> list[_View]:
        views = []
        for offset, piece in AtrText.chunks(text):
            normal = AtrText.normalise(piece)
            views.append(
                _View(
                    offset,
                    piece,
                    normal,
                    tuple(AtrText.code_block_ranges(piece)),
                    tuple(AtrText.code_block_ranges(normal)),
                )
            )
        return views

    @staticmethod
    def prepare(text: str) -> Prepared:
        return Prepared(
            tuple(AtrText._views(text)),
            tuple(
                (start, end, tuple(AtrText._views(decoded)))
                for start, end, decoded in AtrText.decoded_blocks(text)
            ),
        )


_INVISIBLE_CODES: Final = (
    *(0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x180E, 0x200E, 0x200F),
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
)
"""Zero-width characters and direction overrides: removed before matching, as ATR's engine does."""
_INVISIBLE: Final = re.compile("[" + "".join(chr(code) for code in _INVISIBLE_CODES) + "]")
_CONFUSABLE_PAIRS: Final = (
    # Cyrillic lowercase
    ("\\u0430", "a"), ("\\u0435", "e"), ("\\u043e", "o"), ("\\u0440", "p"), ("\\u0441", "c"),
    ("\\u0445", "x"), ("\\u0443", "y"), ("\\u0456", "i"), ("\\u0455", "s"), ("\\u0458", "j"),
    ("\\u04bb", "h"), ("\\u0501", "d"), ("\\u051b", "q"), ("\\u0261", "g"), ("\\u043d", "h"),
    ("\\u043a", "k"), ("\\u043c", "m"), ("\\u0442", "t"), ("\\u0432", "b"),
    # Cyrillic uppercase
    ("\\u0410", "A"), ("\\u0412", "B"), ("\\u0415", "E"), ("\\u041a", "K"), ("\\u041c", "M"),
    ("\\u041d", "H"), ("\\u041e", "O"), ("\\u0420", "P"), ("\\u0421", "C"), ("\\u0422", "T"),
    ("\\u0425", "X"), ("\\u0423", "Y"), ("\\u0406", "I"), ("\\u0408", "J"), ("\\u0405", "S"),
    # Greek
    ("\\u03bf", "o"), ("\\u03c1", "p"), ("\\u03b1", "a"), ("\\u03b5", "e"), ("\\u03bd", "v"),
    ("\\u03ba", "k"), ("\\u0391", "A"), ("\\u0392", "B"), ("\\u0395", "E"), ("\\u0396", "Z"),
    ("\\u0397", "H"), ("\\u0399", "I"), ("\\u039a", "K"), ("\\u039c", "M"), ("\\u039d", "N"),
    ("\\u039f", "O"), ("\\u03a1", "P"), ("\\u03a4", "T"), ("\\u03a7", "X"), ("\\u03a5", "Y"),
    # Other lookalikes
    ("\\u0131", "i"), ("\\u01c0", "l"), ("\\u0578", "n"),
)  # fmt: skip
_CONFUSABLES: Final = str.maketrans(
    {code.encode("ascii").decode("unicode_escape"): latin for code, latin in _CONFUSABLE_PAIRS}
)
"""Cyrillic, Greek and other letters drawn identically to a Latin one, folded to it: the table
ATR's engine uses, so "ignore previous instructions" spelled with a Cyrillic `o` matches the
English rule it was spelled to slip past. Genuine Cyrillic or Greek text folds to Latin gibberish
that cannot spell an English trigger, and the raw text is tested as well."""


_BASE64_BLOCK: Final = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
_MAX_DECODED_BLOCKS: Final = 5


class AtrEngine:
    "The bundled catalogue, and matching its rules against prepared text."

    @staticmethod
    @cache
    def catalogue() -> Catalogue:
        """The bundled rules, or none when the file is missing, malformed or fails its digest."""
        path = DATA_DIR / FILE_NAME
        recorded = AdvisoryFiles._digest_manifest(DATA_DIR)
        try:
            if (
                recorded
                and FILE_NAME in recorded
                and AdvisoryFiles.digest_of(path) != recorded[FILE_NAME]
            ):
                return Catalogue((), "", refused=True)
            document = json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))
        except (OSError, ValueError, EOFError):
            return Catalogue((), "", refused=False)
        rules: list[AtrRule] = []
        samples = max(1, int(document.get("benign_samples") or 0))
        instruction_samples = int(document.get("instruction_samples") or 0)
        for raw in document.get("rules") or ():
            conditions = []
            for condition in raw.get("conditions") or ():
                kind = KINDS.get(str(condition.get("field")))
                if kind is None:
                    continue
                with contextlib.suppress(re.error):
                    conditions.append(
                        Condition(
                            kind,
                            re.compile(
                                str(condition["pattern"]), AtrText.flags_of(condition["flags"])
                            ),
                        )
                    )
            if conditions:
                rules.append(
                    AtrRule(
                        rule_id=str(raw["id"]),
                        title=str(raw.get("title") or ""),
                        category=str(raw.get("category") or "prompt-injection"),
                        severity=str(raw.get("severity") or "medium"),
                        status=str(raw.get("status") or "experimental"),
                        every=raw.get("condition") == "all",
                        conditions=tuple(conditions),
                        # Unmeasured is treated as demoted, the way ATR's own gate treats it.
                        benign_rate=(
                            int(raw["benign_hits"]) / samples if "benign_hits" in raw else 1.0
                        ),
                        outside_code=bool(raw.get("outside_code")),
                        instruction_hits=(
                            int(raw.get("instruction_hits") or 0) if instruction_samples else None
                        ),
                        instruction_rate=(
                            int(raw.get("instruction_hits") or 0) / instruction_samples
                            if instruction_samples
                            else None
                        ),
                    )
                )
        return Catalogue(tuple(rules), str(document.get("commit") or ""), refused=False)

    @staticmethod
    def _search(
        pattern: re.Pattern[str], view: _View, outside_code: bool
    ) -> tuple[int, int] | None:
        """Where `pattern` matches the chunk, normalised first and raw second, as offsets into the raw
        text; a match on the normalised form, whose offsets do not map back, spans the whole chunk."""
        for text, code, mapped in (
            (view.normal, view.normal_code, False),
            (view.raw, view.raw_code, True),
        ):
            if not mapped and view.normal == view.raw:
                continue
            for match in pattern.finditer(text):
                if outside_code and any(a <= match.start() < b for a, b in code):
                    continue
                if mapped:
                    return view.offset + match.start(), view.offset + match.end()
                return view.offset, view.offset + len(view.raw)
        return None

    @staticmethod
    def _match_rule(
        rule: AtrRule, usable: list[Condition], views: list[_View]
    ) -> tuple[int, int] | None:
        for view in views:
            if rule.every:
                spans = [AtrEngine._search(c.pattern, view, rule.outside_code) for c in usable]
                if all(span is not None for span in spans):
                    return min((s for s in spans if s is not None), key=lambda s: s[0])
                continue
            for condition in usable:
                span = AtrEngine._search(condition.pattern, view, rule.outside_code)
                if span is not None:
                    return span
        return None

    @staticmethod
    def rule_span(
        rule: AtrRule, prepared: Prepared, kinds: Iterable[str]
    ) -> tuple[int, int] | None:
        """Where one rule first matches a prepared text, or None.

        The one path both the scan and `import_atr.py` take: the importer checks every rule against
        its own test cases and measures it against the benign corpus through this, so a grade
        describes the engine that will use it. A rule whose conditions must all hold matches only when
        each can be evaluated for these kinds of text and each does. A match inside a base64 block
        points at the block.
        """
        wanted = frozenset(kinds)
        usable = [c for c in rule.conditions if c.kind in wanted]
        if not usable or (rule.every and len(usable) < len(rule.conditions)):
            return None
        span = AtrEngine._match_rule(rule, usable, list(prepared.views))
        if span is not None:
            return span
        for start, end, views in prepared.hidden:
            if AtrEngine._match_rule(rule, usable, list(views)) is not None:
                return start, end
        return None

    @staticmethod
    def rule_matches(rule: AtrRule, text: str, kinds: Iterable[str]) -> bool:
        return bool(text) and AtrEngine.rule_span(rule, AtrText.prepare(text), kinds) is not None

    @staticmethod
    def evaluate(text: str, kinds: Iterable[str]) -> list[AtrMatch]:
        """Every ATR rule that matches `text` read as these kinds, with where each first did."""
        if not text:
            return []
        prepared = AtrText.prepare(text)
        found = []
        for rule in AtrEngine.catalogue().rules:
            span = AtrEngine.rule_span(rule, prepared, kinds)
            if span is not None:
                found.append(AtrMatch(rule, span[0], span[1]))
        return sorted(found, key=lambda m: (m.start, m.rule.rule_id))

    @staticmethod
    def reset_cache() -> None:
        AtrEngine.catalogue.cache_clear()


@dataclass(frozen=True)
class _View:
    """One chunk of the text as the patterns see it: normalised, and raw when that differs."""

    offset: int
    raw: str
    normal: str
    raw_code: tuple[tuple[int, int], ...]
    normal_code: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Prepared:
    """A text made ready for the rules once: its chunks, normalised, and its decoded base64."""

    views: tuple[_View, ...]
    hidden: tuple[tuple[int, int, tuple[_View, ...]], ...]


INSTRUCTION_TOLERANCE: Final = 1
"""Real instruction files a rule may have matched and still count in instruction files.

Chosen on the calibration half of the real-world corpus (`bench/fetch_agent_configs.py`): at
one file, ATR's attacks planted in instruction files were caught 90.9% of the time and 2.8% of the
real calibration files were flagged; at two, 92.6% and 5.0%; at none, 85.5% and 0%. Wording on
prose written to an agent has that ceiling; Cordon's own signals close the rest."""

__all__ = [
    "CHUNK",
    "DEMOTED_ABOVE",
    "INSTRUCTION_TOLERANCE",
    "KINDS",
    "PRODUCTION_AT_MOST",
    "RULE_URL",
    "TEXT_KINDS",
    "AtrEngine",
    "AtrMatch",
    "AtrRule",
    "AtrText",
    "Catalogue",
    "Prepared",
]
