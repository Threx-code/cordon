"""The terms a package-scope rule is written in, defined once for the scanner and for the learning loop.

A package-scope composite (`match: {kind: composite, scope: package}`) is a conjunction of facts about the
whole scanned package, not about one file's text: "a file nothing reaches that both spawns a process and
reaches the network", "an install entry that reads a credential", "the package has a preinstall hook". The
learning loop's distiller (`bench/cdi/distill.py`) searches for such conjunctions over `facts/v1` records
(`report/facts.py`), and the scanner evaluates the ones that ship (`decide/package_rules.py`). Both
read the terms through this module, so what was learned and what is checked cannot drift apart.

A term is a tuple:

    ("file", where, capability[, capability])   a file in WHERE has the capability (or both): where is `any`,
                                                `unreached` (in no place the package runs from) or one place
                                                (`ScanContext.PLACES`), or the way a file is reached (`reach:KIND`, `FileReach.KINDS`:
                                                placed, declared_entry, hook_command, require_chain, path_string,
                                                stem_only, unreached: nothing reaches it at all)
    ("package_rule", rule_id)                   a finding about the whole package with that rule id
    ("hook", kind)                              a lifecycle hook of that kind (preinstall, postinstall, ...)
    ("target", kind)                            what was scanned: a published package, a source tree, an image, ... (`TARGETS`)

What a rule may NOT be written in: names, hosts, ages, publishers, programs. An identity belongs to threat
intel (it is exact, and it ages); age and publisher only stratify measurement (learning loop LL-19, LL-66)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any, ClassVar, Final

from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.errors import RulePackError

Term = tuple[str, ...]


class UnknownTermVersion(ValueError):
    """A term written for a newer meaning than this scanner reads: the rule is skipped and said, never evaluated with the old meaning."""


class RuleSkipped(RulePackError):
    """One rule of a pack this scanner cannot evaluate: the pack still loads without it."""


ANY: Final = "any"
UNREACHED: Final = "unreached"
REACH_PREFIX: Final = "reach:"
_REACH: Final = frozenset(
    {
        "placed",
        "declared_entry",
        "hook_command",
        "require_chain",
        "path_string",
        "stem_only",
        "unreached",
    }
)
_RULE_ID: Final = re.compile(r"[A-Z0-9_.\-]{1,96}")
LEARNED_PREFIX: Final = "LEARNED."
_HOOK_KIND: Final = re.compile(r"[a-z][a-z0-9_\-]{0,31}")


class FactTerms:
    """Terms from facts, and terms from a rule's written form."""

    @staticmethod
    def fires(match: Any, has: Callable[[Term], bool]) -> bool:
        """Whether a package-scope composite match is satisfied where `has(term)` says which terms hold: every `all` term, one of the `any` terms when there are any, and none of the `unless` terms. The scan and the pack's own fact-vector tests both decide through this."""
        all_of = [FactTerms.of_spec(t) for t in match.all_of]
        any_of = [FactTerms.of_spec(t) for t in match.any_of]
        unless = [FactTerms.of_spec(t) for t in match.unless]
        return (
            all(has(t) for t in all_of)
            and (not any_of or any(has(t) for t in any_of))
            and not any(has(t) for t in unless)
        )

    PLACES: ClassVar[frozenset[str]] = frozenset(
        {
            "install_hook",
            "install_entry",
            "import_entry",
            "library_entry",
            "library_closure",
            "agent_tool",
            "skill_named",
            "startup_closure",
            "ci_hook",
        }
    )
    """The places of `ScanContext.PLACES`, by the names the facts export uses."""

    REACH: ClassVar[frozenset[str]] = _REACH
    """How a code file is reached, by the names `decide/reach.py` gives (a closed list; `facts_version` 2 carries it per file)."""

    WHERE: ClassVar[frozenset[str]] = (
        PLACES | {ANY, UNREACHED} | frozenset(REACH_PREFIX + kind for kind in _REACH)
    )
    KINDS: ClassVar[frozenset[str]] = frozenset({"file", "package_rule", "hook", "target"})
    VERSIONS: ClassVar[dict[str, int]] = {"file": 1, "package_rule": 1, "hook": 1, "target": 1}
    """The semantics version of each term kind this scanner reads. A term is written `kind` (version 1) or `kind@N`; a version above this one is a meaning the scanner does not know."""
    TARGETS: ClassVar[frozenset[str]] = frozenset(
        {"source", "package", "archive", "image", "host", "sbom"}
    )
    """What a scan can be of (`ScanResult.target_kind`): the same file is reached differently in a published package and in a source tree, so a rule may name the kind."""

    NOT_COMPUTABLE: ClassVar[frozenset[str]] = frozenset({"change"})
    """Term kinds the scanner cannot compute from one release: a `change` term is over a release pair, and the scanner has no previous release. Every kind in `KINDS` is scanner-computable; a pack rule over one of these is refused, and such a detector ships feed-side or through `--previous-facts`."""
    REFUSED: ClassVar[frozenset[str]] = frozenset(
        {"name", "host", "age", "publisher", "program", "absent", "absence", "missing", "no"}
    )
    """Kinds of term no rule and no distilled detector may use: identities belong to intel, age and publisher only stratify, and an absence (no tests, no repository link, no README) is metadata that stands in for age or publisher, not a behaviour."""
    CAPABILITIES: ClassVar[frozenset[str]] = frozenset(str(c) for c in Capability)

    @staticmethod
    def of_file(
        reached: bool,
        places: Iterable[str],
        capabilities: Iterable[str],
        reach: str | None = None,
    ) -> set[Term]:
        """Every term one file satisfies: each of its capabilities and each pair, anywhere, in each of its
        places, as unreached when no place reaches it, and under the way it is reached (`reach:KIND`)."""
        wheres = [ANY, *([] if reached else [UNREACHED]), *sorted(set(places))]
        if reach in _REACH:
            wheres.append(REACH_PREFIX + str(reach))
        caps = sorted(set(capabilities))
        sets: list[tuple[str, ...]] = [(c,) for c in caps]
        sets += list(itertools.combinations(caps, 2))
        return {("file", where, *cs) for where in wheres for cs in sets}

    @staticmethod
    def file_satisfies(
        reached: bool,
        places: Iterable[str],
        capabilities: Iterable[str],
        term: Term,
        reach: str | None = None,
    ) -> bool:
        """Whether one file satisfies one file term: `term in of_file(...)`, without building every term of the
        file (a package-scope rule asks a few terms of every file; a file can hold dozens of capability pairs)."""
        if len(term) < 3 or term[0] != "file" or not 1 <= len(term) - 2 <= 2:
            return False
        where, wanted = term[1], set(term[2:])
        if not wanted <= set(capabilities):
            return False
        if where == ANY:
            return True
        if where == UNREACHED:
            return not reached
        if where.startswith(REACH_PREFIX):
            return reach in _REACH and where == REACH_PREFIX + str(reach)
        return where in set(places)

    @staticmethod
    def of_package(rules: Iterable[str], hooks: Iterable[str]) -> set[Term]:
        terms: set[Term] = {("package_rule", r) for r in rules if not r.startswith(LEARNED_PREFIX)}
        terms |= {("hook", h) for h in hooks}
        return terms

    @staticmethod
    def of_facts(record: Mapping[str, Any]) -> set[Term]:
        """Every term a `facts/v1` record satisfies."""
        terms: set[Term] = set()
        for f in record.get("files", ()):
            terms |= FactTerms.of_file(
                bool(f.get("reached")),
                f.get("places", ()),
                f.get("capabilities", ()),
                f.get("reach"),
            )
        package = record.get("package", {})
        terms |= FactTerms.of_package(
            package.get("rules", {}), (str(h.get("kind", "")) for h in package.get("hooks", ()))
        )
        if record.get("target_kind") in FactTerms.TARGETS:
            terms.add(("target", str(record["target_kind"])))
        return terms

    @classmethod
    def check_version(cls, kind: str, at: str, written: str) -> None:
        """Nothing for a term with no version or one this scanner reads; `UnknownTermVersion` for a newer one; `ValueError` for a version that is not a whole number from 1."""
        if not at:
            return
        if not re.fullmatch(r"[1-9][0-9]{0,3}", written):
            raise ValueError(f"term version {written!r} is not a whole number from 1")
        known = cls.VERSIONS.get(kind)
        if known is not None and int(written) > known:
            raise UnknownTermVersion(
                f"term {kind} is written for version {written}; this scanner reads version {known}"
            )

    @staticmethod
    def of_spec(spec: Any) -> Term:
        """The term a rule writes as `{file: {where, capabilities}}`, `{package_rule: ID}` or `{hook: KIND}`.
        Anything else is an error naming what was wrong, never a term that silently matches nothing."""
        if not isinstance(spec, Mapping) or len(spec) != 1:
            raise ValueError(
                "a package term is a mapping with exactly one key: file, package_rule or hook"
            )
        (key, value), *_ = spec.items()
        kind, at, written = str(key).partition("@")
        FactTerms.check_version(kind, at, written)
        if kind in FactTerms.REFUSED:
            raise ValueError(
                f"refused term kind: {kind} (identities belong to intel; age and publisher only stratify; an absence is metadata, not behaviour)"
            )
        if kind in FactTerms.NOT_COMPUTABLE:
            raise ValueError(
                f"term kind {kind} is over a release pair and not scanner-computable: the scanner has no previous release"
            )
        if kind == "file":
            if not isinstance(value, Mapping):
                raise ValueError("a file term is {where: ..., capabilities: [...]}")
            where = str(value.get("where", ANY))
            if where not in FactTerms.WHERE:
                raise ValueError(
                    f"unknown where {where!r}; expected one of: {', '.join(sorted(FactTerms.WHERE))}"
                )
            raw = value.get("capabilities", ())
            caps = sorted({str(c) for c in (raw if isinstance(raw, list | tuple) else (raw,))})
            if not 1 <= len(caps) <= 2:
                raise ValueError("a file term names one or two capabilities")
            unknown = [c for c in caps if c not in FactTerms.CAPABILITIES]
            if unknown:
                raise ValueError(f"unknown capability {unknown[0]!r}")
            return ("file", where, *caps)
        if kind == "package_rule":
            if not _RULE_ID.fullmatch(str(value)):
                raise ValueError(f"not a rule id: {value!r}")
            if str(value).startswith(LEARNED_PREFIX):
                raise ValueError("a learned rule is never built on another learned rule's findings")
            return ("package_rule", str(value))
        if kind == "hook":
            if not _HOOK_KIND.fullmatch(str(value)):
                raise ValueError(f"not a hook kind: {value!r}")
            return ("hook", str(value))
        if kind == "target":
            if value not in FactTerms.TARGETS:
                raise ValueError(
                    f"not a scan target: {value!r}; expected one of: {', '.join(sorted(FactTerms.TARGETS))}"
                )
            return ("target", str(value))
        raise ValueError(
            f"unknown term kind {kind!r}; expected one of: {', '.join(sorted(FactTerms.KINDS))}"
        )


__all__ = ["ANY", "LEARNED_PREFIX", "REACH_PREFIX", "UNREACHED", "FactTerms", "Term"]
