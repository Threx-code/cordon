"""What kind of finding a rule id is, by its first word: content, policy, advisory or operational.

The bench counts a block as a malware-class block unless the rule that made it is a policy or an advisory one (a leaked
secret, a policy breach, a known vulnerability): those are reported apart. A prefix nobody has classified counts as
content, the safe side: a block made by a rule family the bench has never heard of is a block, not nothing. And it is
found: a test lists every prefix the scanner's rules and detectors can emit and fails on one that is not named here, so a
new family is classified by a person the day it appears, not discovered in a number.
"""

from __future__ import annotations

from typing import Final

CONTENT: Final = "content"
POLICY: Final = "policy"
ADVISORY: Final = "advisory"
OPERATIONAL: Final = "operational"

CLASSES: Final = {
    "MALWARE.": CONTENT,
    "SUSPECT.": CONTENT,
    "CAP.": CONTENT,
    "LEARNED.": CONTENT,
    "SECRET.": POLICY,
    "POLICY.": POLICY,
    "VULNERABLE.": ADVISORY,
    "OPERATIONAL.": OPERATIONAL,
    "INTEL.": OPERATIONAL,
    "CORDON.": OPERATIONAL,
    "INTERNAL.": OPERATIONAL,
}
"""Rule id prefix (the first word and its dot) -> class."""

APART: Final = frozenset({POLICY, ADVISORY})
"""The classes a benign block is reported apart for, not as a malware-class block."""


class RulePrefixes:
    @staticmethod
    def prefix(rule_id: str) -> str:
        head, dot, _ = str(rule_id).partition(".")
        return f"{head}{dot}"

    @classmethod
    def classify(cls, rule_id: str) -> str:
        """The rule's class; an unclassified prefix is content."""
        return CLASSES.get(cls.prefix(rule_id), CONTENT)

    @classmethod
    def counts_as_malware_class(cls, rule_id: str) -> bool:
        return cls.classify(rule_id) not in APART

    @classmethod
    def unclassified(cls, rule_ids: list[str]) -> list[str]:
        """The prefixes of `rule_ids` that CLASSES does not name, sorted."""
        return sorted({cls.prefix(r) for r in rule_ids} - set(CLASSES))
