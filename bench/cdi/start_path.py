"""Start-path teaching: what the teacher saw run that the static facts call unreached.

Static facts mark a file `reached` when an entry (an install hook, an import entry, an agent tool ...) leads to it. A file nothing
reaches is ignored by the rules that need a reach. When the teacher (the isolated analysis service) saw such a file RUN, the reach
analysis missed a way of starting it. That is a reading gap, and it is taught to the reader through the same item the census opens:

    kind   START_PATH_UNREACHED
    form   the start mechanism class the teacher observed, from a closed list (a computed path, a dynamic import, an eval, a spawned
           interpreter, a plugin hook ...)

The unit's eligibility is the census's own: a held, fresh or sealed unit keeps an item open and opens none. Nothing here reads a
package: an observation is a file key from the facts record and the class of the mechanism."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Final

from bench.cdi.census import READING_GAP, ROUTES, Census, MissRow, Verdict

KIND: Final = "START_PATH_UNREACHED"
MECHANISMS: Final = frozenset(
    {
        "computed_path",
        "dynamic_import",
        "eval",
        "spawned_interpreter",
        "plugin_hook",
        "config_driven",
        "env_driven",
    }
)


class UnknownMechanism(ValueError):
    """The start mechanism class is not one of the closed list."""


class StartPaths:
    @staticmethod
    def unreached_runs(facts: Mapping[str, Any], executed: Iterable[Mapping[str, str]]) -> list[tuple[str, str]]:
        """The (kind, mechanism class) of each file the teacher saw run that the facts record calls unreached.

        `executed` is `{"file": <the facts file key>, "mechanism": <a class of MECHANISMS>}` for each file seen to run. A file
        the facts reach, or one the record does not list, gives nothing."""
        unreached = {str(f.get("key")) for f in facts.get("files", ()) if f.get("reached") is False}
        found: set[tuple[str, str]] = set()
        for run in executed:
            mechanism = str(run.get("mechanism", ""))
            if mechanism not in MECHANISMS:
                raise UnknownMechanism(f"{mechanism!r} is not a start mechanism class")
            if str(run.get("file")) in unreached:
                found.add((KIND, mechanism))
        return sorted(found)

    @classmethod
    def verdicts(cls, observations: Iterable[Mapping[str, Any]]) -> list[Verdict]:
        """One reading-gap verdict, routed to the reader when the unit may inform it, for each unit with an unreached file seen to
        run. An observation has `row` (a `MissRow`) and `executed`."""
        out: list[Verdict] = []
        for observation in observations:
            row: MissRow = observation["row"]
            gaps = tuple(cls.unreached_runs(row.facts, observation["executed"]))
            if not gaps:
                continue
            eligible, held = Census.eligibility(row)
            route = ROUTES[READING_GAP] if eligible else "counted_only"
            out.append(Verdict(row.key, row.family, READING_GAP, gaps, None, eligible, held, route))
        return sorted(out, key=lambda v: v.key)
