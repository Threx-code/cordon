"""A rule may not assert more than its pattern can establish.

Three defects in this branch shared one shape, and it was not a coding error in
any of them -- each rule matched exactly what it was written to match. What was
wrong was the sentence next to it:

* `SUSPECT.AZURE.OPEN_INGRESS` said "a security rule admits the whole internet"
  of a rule whose action was Deny.
* `MALWARE.CI.SECRET_EXFIL` said "there is no legitimate reason to serialise the
  entire context" of a pattern GitHub's own documentation leads people to, and
  fired on Microsoft's module registry at critical.
* The advisory detector said "known-malicious release" of npm's tombstone for a
  name it had already taken away.

A finding is read by somebody deciding whether to stop a release. An observation
that overstates itself spends the reader's trust once and does not get it back,
so the message has to be true of every file the pattern matches -- not of the
case that prompted the rule.

Absolute language is the tell, and it is cheap to check. This does not make a
message correct; it makes an unqualified claim something a person chose rather
than something that drifted in when a rule was narrowed and its prose was not.
"""

from __future__ import annotations

import re

import pytest

from cordon_scanner.core.registry import Registry
from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.rules.loader import RuleLoader

ABSOLUTE = re.compile(
    r"\b(?:no legitimate|never legitimate|no benign|cannot be legitimate"
    r"|always (?:means|indicates|is)|is (?:always|invariably)"
    r"|there is no (?:reason|other)|nothing (?:legitimate|else) )",
    re.IGNORECASE,
)

#: Rules whose absolute phrasing is about the world, not about the match.
#:
#: `CAP.EGRESS.CHANNEL.001` says an allow-list of method names "always is -- a
#: list the attacker can read too", which is a statement about allow-lists.
#: `SUSPECT.EXFIL.DNS.001` says DNS "is the channel that survives environments
#: where nothing else gets out", which is a statement about DNS. Neither claims
#: anything unconditional about the file it matched.
ABOUT_THE_WORLD = frozenset(
    {
        "CAP.EGRESS.CHANNEL.001",
        "SUSPECT.EXFIL.DNS.001",
    }
)


def every_rule() -> list:
    detector = list(RuleCatalogue.from_detectors(Registry().detectors()))
    pack = [getattr(r, "rule", r) for p in RuleLoader.load_builtin() for r in p.rules]
    return detector + pack


def test_there_are_rules_to_check() -> None:
    assert len(every_rule()) > 1000


@pytest.mark.parametrize("rule", every_rule(), ids=lambda r: r.id)
def test_a_message_does_not_claim_more_than_it_can_know(rule) -> None:
    if rule.id in ABOUT_THE_WORLD:
        return
    match = ABSOLUTE.search(getattr(rule, "message", "") or "")
    assert match is None, (
        f"{rule.id} asserts {match.group(0)!r}. A message has to be true of every "
        f"file the pattern matches, not of the case that prompted the rule. If the "
        f"claim really is unconditional, add the rule to ABOUT_THE_WORLD with the "
        f"reason; otherwise say what was observed."
    )


def test_the_exemptions_are_all_still_shipped() -> None:
    """A frozen list rots into a lie unless something checks it."""
    ids = {rule.id for rule in every_rule()}
    assert ids >= ABOUT_THE_WORLD, (
        f"exempted rules that no longer exist: {sorted(ABOUT_THE_WORLD - ids)}"
    )
