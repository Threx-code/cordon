"""The query language behind `match: {kind: ast}`.

Why this exists. Every rule in the pack matched bytes -- `regex`, `literal`,
`entropy`, and `composite` over the three -- and a byte pattern loses to the
cheapest refactor there is. `os.system(cmd)` is matched; `f = os.system` on one
line and `f(cmd)` on the next is not, because the call site says `f`. Neither is
`getattr(os, "sys" + "tem")(cmd)`, where the primitive's name does not appear in
the file at all. `detect/pyast.py` already resolved all of that -- but only for
its own fixed `PRIMITIVES` table, which a rule author cannot add to.

So the vocabulary declared `kind: ast` and the loader refused it, on the correct
grounds that a rule which silently never fires is worse than one that fails to
load. This is that kind, implemented.

**What a query says.** Deliberately small -- three keys, and the same argument
that the composite language makes for staying small applies here with more
force: a rule is read by somebody deciding whether a security finding is
justified, and a query language rich enough to be clever is one nobody can
review.

    match:
      kind: ast
      calls: [os.system, subprocess.run]     # resolved names, not written ones
      argument_matches: 'curl|wget'          # over the folded arguments
      argument_index: 0                      # optional, narrows to one argument

**What it does not do.** It does not replace the regex tier: Python is the only
language with a parser here, so every other language keeps byte matching and
this runs beside it. It answers "is this call made", not "does this value reach
that call" -- dataflow is a different and much larger thing, and claiming it
with a name-resolution pass would be the overstatement this project's own
documentation is careful to avoid elsewhere.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.pyast import AstCall

MAX_CALLS = 4096
"""How many resolved calls to consider in one file.

A generated file with a hundred thousand call sites is generated, and the first
few thousand say whatever there is to say. Bounded for the same reason every
other traversal here is: an unbounded loop over attacker-supplied input is a
denial of service against the machine running the scan."""


@dataclass(frozen=True, slots=True)
class AstQuery:
    """A compiled `kind: ast` match."""

    calls: frozenset[str]
    """Resolved dotted names, any of which satisfies the query."""

    argument_matches: re.Pattern[str] | None = None
    """An optional pattern over the call's folded arguments.

    Compiled through `PatternCompiler.validate_pattern` like every other
    pattern in the pack, so an `ast` rule cannot smuggle in the catastrophic
    backtracking a `regex` rule is refused for."""

    argument_index: int | None = None
    """Which argument the pattern applies to. `None` means any of them,
    including keywords, which is what most rules want."""

    argument_constructed: bool = False
    """When true, the call matches only if an argument is a BUILT expression --
    a concatenation, an f-string, a slice, a nested call -- rather than a plain
    literal or name.

    This is what lets an `ast` rule stay as precise as the regex tier without
    being defeated by an aliased import. `resolve(name)` where `name` is a
    fixed host is ordinary; `resolve(blob[i:] + ".exfil.invalid")` carries data
    in the argument, and only the second is exfiltration. See
    `AstCall.has_constructed_argument`."""

    def matching(self, calls: Iterable[AstCall]) -> list[AstCall]:
        """The calls that satisfy this query, in source order."""
        found: list[AstCall] = []
        for index, call in enumerate(calls):
            if index >= MAX_CALLS:
                break
            if call.name not in self.calls:
                continue
            if self.argument_constructed and not call.has_constructed_argument:
                continue
            if self.argument_matches is None:
                found.append(call)
                continue
            if self.argument_index is None:
                subject = call.argument_text
            elif self.argument_index < len(call.arguments):
                subject = call.arguments[self.argument_index]
            else:
                # The argument the rule asks about was not passed. Not a match,
                # and not an error: `subprocess.run(cmd)` and
                # `subprocess.run(cmd, shell=True)` are the same call with
                # different arity, and a rule about the second must not fire on
                # the first.
                continue
            if subject and self.argument_matches.search(subject):
                found.append(call)
        return found


__all__ = ["MAX_CALLS", "AstQuery"]
