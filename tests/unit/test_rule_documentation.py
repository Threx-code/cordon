"""Every rule the tool can emit says what it means and who says so.

Two fields on `DeclaredRule` were empty for a large part of the rule set and
nothing noticed, because nothing looked. `cordon rules show` is where a reader
goes before a scan has run -- to decide whether a rule applies to them, to
argue with it, or to quote it to somebody who has to approve the change -- and
for 99 rules it printed a title and a remediation and no explanation, while
`references` did not exist on the type at all.

The count is the point: a gap in one rule is an omission, a gap in ninety-nine
is a missing guarantee. These tests make it a guarantee.
"""

from __future__ import annotations

import re

import pytest

from cordon_scanner.core.registry import Registry
from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.rules.loader import RuleLoader


def declared() -> tuple:
    return RuleCatalogue.from_detectors(Registry().detectors())


#: Rules whose claim no external document covers.
#:
#: These four report on the scan itself -- a registry that could not be reached,
#: a graph that was not finished, history that could not be read. There is no
#: standards-body page for "the lookup failed", and inventing a plausible link
#: would be worse than the gap: a reference is there to be followed, and one
#: that does not answer the question reads as authority and delivers nothing.
NO_EXTERNAL_AUTHORITY = frozenset(
    {
        "OPERATIONAL.REGISTRY.NOT_ASKED.001",
        "OPERATIONAL.REGISTRY.NO_SOURCE.001",
        "OPERATIONAL.REGISTRY.UNREACHABLE.001",
        "OPERATIONAL.VCS.UNREADABLE.001",
    }
)


def test_the_catalogue_is_not_empty() -> None:
    """Guards everything below from passing vacuously."""
    assert len(declared()) > 1000


@pytest.mark.parametrize("rule", declared(), ids=lambda r: r.id)
def test_every_rule_explains_itself(rule) -> None:
    message = (rule.message or "").strip()
    assert message, (
        f"{rule.id} has no message, so `cordon rules show {rule.id}` prints a "
        f"title and nothing that says what it means."
    )
    assert len(message) >= 60, f"{rule.id}: {message!r} is too short to explain anything"


@pytest.mark.parametrize("rule", declared(), ids=lambda r: r.id)
def test_every_rule_says_who_says_so(rule) -> None:
    if rule.id in NO_EXTERNAL_AUTHORITY:
        return
    assert rule.references, (
        f"{rule.id} carries no reference. A finding asserts that something is a "
        f"problem; a reference is what a reader follows when they do not take "
        f"that on trust. Add one from `core.references`, or list the rule in "
        f"NO_EXTERNAL_AUTHORITY with the reason."
    )


@pytest.mark.parametrize("rule", declared(), ids=lambda r: r.id)
def test_references_are_plausible_urls(rule) -> None:
    for link in rule.references:
        assert link.startswith("https://"), f"{rule.id}: {link!r} is not an https URL"
        assert " " not in link, f"{rule.id}: {link!r} contains a space"


def test_the_exemptions_are_all_still_shipped() -> None:
    """A frozen list rots into a lie unless something checks it."""
    ids = {rule.id for rule in declared()}
    assert ids >= NO_EXTERNAL_AUTHORITY, (
        f"exempted rules that no longer exist: {sorted(NO_EXTERNAL_AUTHORITY - ids)}"
    )


def test_messages_do_not_run_words_together() -> None:
    """Adjacent string literals need a trailing space or the words collide.

    A wrapped message written as `"...over a" "network..."` reads as
    `over anetwork` and every test that only checks the field is non-empty
    passes. Caught by eye once; checked here from now on.
    """
    collisions = []
    for rule in declared():
        for word in re.findall(r"\b[a-z]{2,}[A-Z][a-z]{2,}\b", rule.message or ""):
            # Identifiers a message names on purpose, which are camelCase
            # because the thing they name is.
            if word not in {
                "CycloneDX",
                "JFrog",
                "GitHub",
                "GitLab",
                "networkAcls",
                "allUsers",
            }:
                collisions.append(f"{rule.id}: {word!r}")
    assert not collisions, "words run together in a message: " + ", ".join(collisions[:10])


def test_pack_rules_keep_their_references() -> None:
    """Pack rules have carried references since the loader was written; this is
    what stops a refactor quietly dropping them."""
    packs = [rule for pack in RuleLoader.load_builtin() for rule in pack.rules]
    composites = [r for r in packs if r.id.startswith(("SUSPECT.", "MALWARE."))]
    assert composites, "no composite rules loaded"
    # `CompiledRule` wraps the declaration it was built from.
    assert any(getattr(r, "rule", r).references for r in composites)
