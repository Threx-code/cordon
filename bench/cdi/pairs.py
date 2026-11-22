"""Release-pair facts (learning loop row LL-2): what changed between a release and the last CLEAN release before it.

A takeover or a poisoned update shows as a change, not as a shape: the same package, a new version, and something it never had.
From two `facts` records (the same facts version) of one package, `PairFacts.of` names the six changes the loop learns from:

    capability     a capability in a place that runs (an install hook or entry, an import entry, an agent tool ...) or in a
                   file nothing reaches, that the previous release did not have in that place
    hook           a lifecycle hook kind, or a program a hook runs, that the previous release did not have
    binary         a native or compiled file (a node addon, a shared library, an executable, wasm ...) the previous release did
                   not ship
    host           a URL host or domain a file names that the previous release did not (the digests of facts version 3; no name)
    dependency     more direct or local dependencies than the previous release
    publisher      the registry says another account published it (the caller says so: the scan cannot)

The previous release must be the last CLEAN one (`previous_is_clean`): a pair against a malicious predecessor measures nothing
(the first pre-test of the version-change idea found 148 of 167 malicious units already had a malicious predecessor), and a pair
against an arbitrary old version measures drift. The caller chooses it; this refuses a pair that is not declared clean.

The record carries counts and closed-vocabulary terms, never a name, a host or a path. `PairTerms` reads it as terms for the
change detectors (G6, `bench/cdi/distill.py`); nothing here is evaluated by the scanner, which has no previous release offline.

Binaries: a facts record lists only files with a capability, a finding or an unread state, so a native file with none of them is not
in it. When both records carry `package.extensions` (a count per extension class) the binaries are counted from that; otherwise from
the file entries, which undercounts quiet binaries. The scanner's export does not write `extensions` yet."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.report.facts import ScanFacts
from cordon_scanner.rules.fact_terms import UNREACHED, FactTerms

if TYPE_CHECKING:
    from collections.abc import Iterable

PAIR_VERSION: Final = "1"
Term = tuple[str, ...]


class PairFacts:
    #: Extension classes (of the facts record's closed list) that are compiled code a package ships.
    BINARY_EXTENSIONS: ClassVar[frozenset[str]] = frozenset(
        {"node", "so", "dll", "dylib", "exe", "bin", "wasm", "jar", "class", "pyc"}
    )

    @staticmethod
    def of(
        previous: Mapping[str, Any],
        current: Mapping[str, Any],
        *,
        previous_is_clean: bool,
        publisher_changed: bool = False,
    ) -> dict[str, Any]:
        """The pair record of a release against the last clean release before it, canonical and with its digest."""
        if not previous_is_clean:
            raise ValueError(
                "a pair is made against the last clean release; this one is not declared clean"
            )
        versions = {str(previous.get("facts_version", "")), str(current.get("facts_version", ""))}
        if len(versions) != 1 or "" in versions:
            raise ValueError(
                "the two records are of different facts versions; rebuild the older at the current head"
            )
        before, after = FactTerms.of_facts(previous), FactTerms.of_facts(current)
        added = sorted(t for t in after - before if t[0] == "file")
        record: dict[str, Any] = {
            "pair_version": PAIR_VERSION,
            "facts_version": next(iter(versions)),
            "previous": str(previous.get("digest", "")),
            "current": str(current.get("digest", "")),
            "new_capabilities": [list(t[1:]) for t in added if t[1] in FactTerms.PLACES],
            "new_unreached_capabilities": [list(t[1:]) for t in added if t[1] == UNREACHED],
            "new_hook_kinds": sorted(
                PairFacts._hook_kinds(current) - PairFacts._hook_kinds(previous)
            ),
            "new_hook_programs": sorted(
                PairFacts._programs(current) - PairFacts._programs(previous)
            ),
            "new_binary_files": PairFacts._binaries(previous, current),
            "new_hosts": len(
                PairFacts._digests(current, "hosts") - PairFacts._digests(previous, "hosts")
            ),
            "new_domains": len(
                PairFacts._digests(current, "domains") - PairFacts._digests(previous, "domains")
            ),
            "new_direct_dependencies": PairFacts._more(previous, current, "direct"),
            "new_local_dependencies": PairFacts._more(previous, current, "local"),
            "publisher_changed": bool(publisher_changed),
        }
        record["digest"] = hashlib.sha256(ScanFacts.canonical(record)).hexdigest()
        return record

    @staticmethod
    def _hook_kinds(facts: Mapping[str, Any]) -> set[str]:
        return {str(h.get("kind", "")) for h in facts.get("package", {}).get("hooks", ())} - {""}

    @staticmethod
    def _programs(facts: Mapping[str, Any]) -> set[str]:
        return {
            str(p) for h in facts.get("package", {}).get("hooks", ()) for p in h.get("programs", ())
        }

    @staticmethod
    def _digests(facts: Mapping[str, Any], field: str) -> set[str]:
        return {str(d) for f in facts.get("files", ()) for d in f.get(field, ())}

    @staticmethod
    def _more(previous: Mapping[str, Any], current: Mapping[str, Any], field: str) -> int:
        def count(facts: Mapping[str, Any]) -> int:
            return int(facts.get("package", {}).get("dependencies", {}).get(field, 0))

        return max(0, count(current) - count(previous))

    @staticmethod
    def _binaries(previous: Mapping[str, Any], current: Mapping[str, Any]) -> int:
        before, after = (
            previous.get("package", {}).get("extensions"),
            current.get("package", {}).get("extensions"),
        )
        if isinstance(before, Mapping) and isinstance(after, Mapping):
            return sum(
                max(0, int(after.get(ext, 0)) - int(before.get(ext, 0)))
                for ext in PairFacts.BINARY_EXTENSIONS
            )
        known = {str(f.get("key", "")) for f in previous.get("files", ())}
        return sum(
            1
            for f in current.get("files", ())
            if str(f.get("ext", "")) in PairFacts.BINARY_EXTENSIONS
            and str(f.get("key", "")) not in known
        )


class PairTerms:
    """A pair record as the terms a change detector is made of: the scanner's own vocabulary of change, no identity."""

    #: Change kinds the detectors may not use. The publisher flag is withheld: the term policy (LL-66) keeps publishers to
    #: stratification, and whether a bare 'the publisher changed' flag is allowed is for the lead to decide.
    WITHHELD: ClassVar[frozenset[str]] = frozenset({"publisher"})

    @staticmethod
    def of(pair: Mapping[str, Any]) -> set[Term]:
        terms: set[Term] = set()
        for entry in pair.get("new_capabilities", ()):
            terms.add(("change", "capability", *entry))
        for entry in pair.get("new_unreached_capabilities", ()):
            terms.add(("change", "capability", *entry))
        terms |= {("change", "hook", str(k)) for k in pair.get("new_hook_kinds", ())}
        terms |= {("change", "hook_program", str(p)) for p in pair.get("new_hook_programs", ())}
        flags: Iterable[tuple[str, Any]] = (
            ("binary", pair.get("new_binary_files", 0)),
            ("host", pair.get("new_hosts", 0)),
            ("domain", pair.get("new_domains", 0)),
            (
                "dependency",
                int(pair.get("new_direct_dependencies", 0))
                + int(pair.get("new_local_dependencies", 0)),
            ),
            ("publisher", pair.get("publisher_changed", False)),
        )
        terms |= {("change", name) for name, value in flags if value}
        return {t for t in terms if t[1] not in PairTerms.WITHHELD}


__all__ = ["PAIR_VERSION", "PairFacts", "PairTerms"]
