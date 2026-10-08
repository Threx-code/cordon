"""Every count a document states is the count the code has.

The package's strongest asset is that its documents do not overclaim, and the commonest way they
drift into overclaiming is not a false sentence but a true one that aged: "8 exfiltration rules"
was right when written and wrong four rules later, and "47% of everything Cordon ships" stayed in
a tutorial long after the policy table made it five. The coverage matrix and the ecosystem table
are generated, so they cannot drift; the prose around them was not, and did.

Each claim below is a phrase documents use, mapped to the value the shipped code computes. A
document stating any of these phrases with any other number fails here, and the fix is to change
the sentence -- or, if the code is what is wrong, the code.
"""

from __future__ import annotations

import functools
import gzip
import json
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
    "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
}  # fmt: skip
NUMBER = r"(?P<n>\d[\d,]*|" + "|".join(WORDS) + r")"


class DocumentTruth:
    """The values the documents' counts must equal, computed from what ships."""

    @staticmethod
    @functools.cache
    def reported_rules() -> tuple[str, ...]:
        from cordon_scanner.core.registry import Registry
        from cordon_scanner.detect.catalogue import RuleCatalogue
        from cordon_scanner.rules.loader import RuleLoader

        ids = [c.rule.id for p in RuleLoader.load_builtin() for c in p]
        ids += [d.id for d in RuleCatalogue.from_detectors(Registry().detectors())]
        # Capability labels are composite inputs, never reported, and the matrix excludes them.
        return tuple(r for r in ids if not r.startswith(("CAP.", "AST.")))

    @classmethod
    def domain(cls, name: str) -> int:
        from cordon_scanner.core.taxonomy import Taxonomy

        return Counter(Taxonomy.domain_of(r).name for r in cls.reported_rules())[name]

    @staticmethod
    def iac(kind: str) -> int:
        from cordon_scanner.detect import iac_policies

        generated = len(iac_policies.GeneratedPolicies.generated_policies())
        total = len(iac_policies.GeneratedPolicies.all_policies())
        return {"total": total, "generated": generated, "curated": total - generated}[kind]

    @staticmethod
    def advisories() -> int:
        meta = ROOT / "src/cordon_scanner/intel/data/advisories-meta.json"
        return int(json.loads(meta.read_text(encoding="utf-8"))["record_count"])

    @staticmethod
    def atr(kind: str) -> int:
        with gzip.open(ROOT / "src/cordon_scanner/intel/data/atr-rules.json.gz") as handle:
            data = json.load(handle)
        # ATR's own rules only: Cordon's supplementary rules (source "cordon") are not ATR's.
        carried = sum(1 for r in data["rules"] if r.get("source") != "cordon")
        supplement = len(data["rules"]) - carried
        dropped = sum(len(v) for v in data["dropped"].values())
        return {"carried": carried, "upstream": carried + dropped, "supplement": supplement}[kind]


#: (phrase, the value it must state). The number is the named group `n`.
CLAIMS: tuple[tuple[str, re.Pattern[str], Callable[[], int]], ...] = (
    (
        "rule badge",
        re.compile(r"badge/rules-(?P<n>\d[\d%2C,]*)-"),
        lambda: len(DocumentTruth.reported_rules()),
    ),
    (
        "secret rules",
        re.compile(rf"\b{NUMBER} secret rules\b", re.I),
        lambda: DocumentTruth.domain("CREDENTIAL"),
    ),
    (
        "exfiltration rules",
        re.compile(rf"\b{NUMBER} exfiltration rules\b", re.I),
        lambda: DocumentTruth.domain("EXFILTRATION"),
    ),
    (
        "container rules",
        re.compile(rf"\b{NUMBER} container rules\b", re.I),
        lambda: DocumentTruth.domain("CONTAINER"),
    ),
    (
        "policy controls",
        re.compile(rf"\b{NUMBER} controls\b", re.I),
        lambda: DocumentTruth.iac("total"),
    ),
    (
        "hand-written policies",
        re.compile(rf"\b{NUMBER} of them are written by hand\b", re.I),
        lambda: DocumentTruth.iac("curated"),
    ),
    (
        "generated policies",
        re.compile(rf"\b{NUMBER} (?:are generated|generated policies)\b", re.I),
        lambda: DocumentTruth.iac("generated"),
    ),
    (
        "bundled advisories",
        re.compile(rf"\b{NUMBER} bundled advisories\b", re.I),
        DocumentTruth.advisories,
    ),
    (
        "ATR carried",
        re.compile(rf"\bcarries {NUMBER} of its \d[\d,]* rules\b"),
        lambda: DocumentTruth.atr("carried"),
    ),
    (
        "ATR upstream",
        re.compile(r"\bcarries \d[\d,]* of its (?P<n>\d[\d,]*) rules\b"),
        lambda: DocumentTruth.atr("upstream"),
    ),
    (
        "Cordon rules in ATR's format",
        re.compile(rf"\b{NUMBER} of Cordon's own\b"),
        lambda: DocumentTruth.atr("supplement"),
    ),
)


class DocumentClaims:
    @staticmethod
    def documents() -> list[Path]:
        paths = [
            ROOT / "README.md",
            ROOT / "SECURITY.md",
            ROOT / "schemas/README.md",
            ROOT / "bench/README.md",
        ]
        paths += sorted((ROOT / "docs").glob("*.md")) + sorted((ROOT / "tutorials").glob("*.md"))
        return [p for p in paths if p.is_file()]

    @staticmethod
    def number(text: str) -> int:
        lowered = text.lower()
        if lowered in WORDS:
            return WORDS[lowered]
        return int(lowered.replace("%2c", "").replace(",", ""))

    @classmethod
    def stated(cls, pattern: re.Pattern[str]) -> list[tuple[str, int, int]]:
        found = []
        for path in cls.documents():
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for match in pattern.finditer(line):
                    found.append(
                        (
                            path.relative_to(ROOT).as_posix(),
                            line_number,
                            cls.number(match.group("n")),
                        )
                    )
        return found


class TestDocumentCounts:
    @pytest.mark.parametrize("claim, pattern, truth", CLAIMS, ids=[c[0] for c in CLAIMS])
    def test_every_stated_count_is_the_shipped_count(self, claim, pattern, truth) -> None:
        expected = truth()
        wrong = [
            f"{path}:{line} says {value}"
            for path, line, value in DocumentClaims.stated(pattern)
            if value != expected
        ]
        assert not wrong, f"{claim}: the code has {expected:,}; " + "; ".join(wrong)

    @pytest.mark.parametrize("claim, pattern, truth", CLAIMS, ids=[c[0] for c in CLAIMS])
    def test_every_claim_is_still_made_somewhere(self, claim, pattern, truth) -> None:
        """A pattern no document matches checks nothing, and would pass after the sentence it
        guarded was reworded into a form it cannot see."""
        assert DocumentClaims.stated(pattern), (
            f"no document states {claim!r} any more; update or remove the claim"
        )

    def test_word_and_digit_forms_both_parse(self) -> None:
        assert DocumentClaims.number("Thirteen") == 13
        assert DocumentClaims.number("1,082") == 1082
        assert DocumentClaims.number("1%2C333") == 1333

    def test_no_document_states_a_share_of_the_pack(self) -> None:
        """A percentage of the whole moves whenever any domain does, and no generator owns it."""
        share = re.compile(r"\d+% of (?:everything Cordon ships|the pack)\b")
        hits = [
            f"{p.relative_to(ROOT)}:{i}"
            for p in DocumentClaims.documents()
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
            if share.search(line)
        ]
        assert not hits, hits
