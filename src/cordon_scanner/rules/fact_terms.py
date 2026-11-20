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

What a rule may NOT be written in: names, hosts, ages, publishers, programs. An identity belongs to threat
intel (it is exact, and it ages); age and publisher only stratify measurement (learning loop LL-19, LL-66)."""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterable, Mapping
from typing import Any, ClassVar, Final

from cordon_scanner.foundation.capabilities import Capability

Term = tuple[str, ...]

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
    KINDS: ClassVar[frozenset[str]] = frozenset({"file", "package_rule", "hook"})
    REFUSED: ClassVar[frozenset[str]] = frozenset({"name", "host", "age", "publisher", "program"})
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
        return terms

    @staticmethod
    def of_spec(spec: Any) -> Term:
        """The term a rule writes as `{file: {where, capabilities}}`, `{package_rule: ID}` or `{hook: KIND}`.
        Anything else is an error naming what was wrong, never a term that silently matches nothing."""
        if not isinstance(spec, Mapping) or len(spec) != 1:
            raise ValueError(
                "a package term is a mapping with exactly one key: file, package_rule or hook"
            )
        (kind, value), *_ = spec.items()
        if kind in FactTerms.REFUSED:
            raise ValueError(
                f"refused term kind: {kind} (identities belong to intel; age and publisher only stratify)"
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
        raise ValueError(
            f"unknown term kind {kind!r}; expected one of: {', '.join(sorted(FactTerms.KINDS))}"
        )


__all__ = ["ANY", "LEARNED_PREFIX", "REACH_PREFIX", "UNREACHED", "FactTerms", "Term"]
