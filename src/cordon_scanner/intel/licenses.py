"""Classifying a declared licence as permissive, copyleft, or unknown.

Scoped the same way `intel/versions.py` and `detect/sbom.py` are scoped:
real coverage over the common cases, honest about the rest, rather than a
partial implementation of the full complexity. The simplifications are stated
rather than left for a reader to discover:

**A curated identifier table with a small SPDX-expression evaluator on top.**
A manifest field is at least as likely to hold `"MIT"`, `"MIT License"` or a
legacy npm `licenses: [{"type": "MIT"}]` array as a well-formed expression, so
the base is a table of the spellings actually seen in the wild. But compound
SPDX expressions (`(MIT OR Apache-2.0)`, `GPL-2.0-or-later WITH
Classpath-exception-2.0`) are common enough that treating them all as `UNKNOWN`
was itself a source of both misses and noise: a dependency offered as `(MIT OR
GPL-2.0)` is one the consumer may take under MIT, and reporting it as copyleft
is a false positive. So `OR` resolves to the least restrictive operand (the
choice is the licensee's), `AND` to the most restrictive (every obligation
applies at once), and a `WITH` exception is stripped to its base licence --
which is conservative, since exceptions only ever loosen. An operand the table
does not know still degrades to `UNKNOWN` rather than a guess.

**Classification is a curated list, not a legal opinion.** Whether a licence
creates an obligation depends on how a dependency is linked and distributed,
which this tool cannot observe. What it reports is the identifier's own
category as licence-compliance tooling conventionally groups it, which is a
fact about the identifier, not a legal conclusion about this project's use of
it -- the same distinction `SUSPECT.*` rules draw between "this looks like an
attack" and "this is one".

**Network copyleft is its own category** because it is the one that most often
surprises: AGPL, SSPL, OSL and the EUPL reach a service offered over a network,
where ordinary copyleft's obligations turn on *distribution* a hosted service
never performs. A company that can safely depend on GPL internal tooling can be
obligated by an AGPL dependency in its SaaS backend, so the two are not the
same finding.
"""

from __future__ import annotations

import enum
import re


class LicenseCategory(enum.StrEnum):
    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    COPYLEFT = "copyleft"
    NETWORK_COPYLEFT = "network_copyleft"
    UNKNOWN = "unknown"


#: How restrictive each category is, for resolving compound expressions. Higher
#: binds more. UNKNOWN is deliberately absent -- it is not a point on this scale
#: but the absence of one, and the evaluator handles it separately.
_RESTRICTIVENESS: dict[LicenseCategory, int] = {
    LicenseCategory.PERMISSIVE: 0,
    LicenseCategory.WEAK_COPYLEFT: 1,
    LicenseCategory.COPYLEFT: 2,
    LicenseCategory.NETWORK_COPYLEFT: 3,
}


_PERMISSIVE = frozenset(
    {
        "MIT",
        "MIT-0",
        "Apache-2.0",
        "Apache-1.1",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-3-Clause-Clear",
        "0BSD",
        "ISC",
        "Unlicense",
        "CC0-1.0",
        "Python-2.0",
        "Zlib",
        "BSL-1.0",
        "WTFPL",
        "PSF-2.0",
        "blessing",
        "Artistic-2.0",
    }
)

_WEAK_COPYLEFT = frozenset(
    {
        "LGPL-2.0-only",
        "LGPL-2.0-or-later",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MPL-1.1",
        "MPL-2.0",
        "EPL-1.0",
        "EPL-2.0",
        "CDDL-1.0",
        "CDDL-1.1",
    }
)

_COPYLEFT = frozenset(
    {
        "GPL-1.0-only",
        "GPL-1.0-or-later",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "CC-BY-SA-4.0",
        "CC-BY-SA-3.0",
    }
)

#: Copyleft that reaches network use, not only distribution. The distinction
#: this whole category exists to draw: a hosted service distributes nothing, so
#: ordinary GPL's obligations do not trigger -- but AGPL, SSPL, OSL and the EUPL
#: are written to reach exactly that case. For a company shipping SaaS this is
#: the licence class most likely to create an obligation it did not expect.
_NETWORK_COPYLEFT = frozenset(
    {
        "AGPL-1.0-only",
        "AGPL-1.0-or-later",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "SSPL-1.0",
        "OSL-1.0",
        "OSL-2.0",
        "OSL-2.1",
        "OSL-3.0",
        "EUPL-1.1",
        "EUPL-1.2",
        "RPL-1.5",
    }
)

#: Common non-SPDX spellings a manifest field actually contains, mapped to
#: the SPDX identifier the tables above key on. Lowercased, punctuation and
#: whitespace normalised, before lookup -- see `normalize`.
_ALIASES: dict[str, str] = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "new bsd license": "BSD-3-Clause",
    "gplv2": "GPL-2.0-only",
    "gpl v2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gpl2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl v3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl3": "GPL-3.0-only",
    "gnu general public license v2.0": "GPL-2.0-only",
    "gnu general public license v3.0": "GPL-3.0-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "gnu affero general public license v3.0": "AGPL-3.0-only",
    "mozilla public license 2.0": "MPL-2.0",
    "server side public license": "SSPL-1.0",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "isc license": "ISC",
}

_PUNCTUATION_RE = re.compile(r"[^a-z0-9.+]+")


def normalize(raw: str | None) -> str | None:
    """The best SPDX identifier guess for a declared license string.

    `None` in, `None` out. An unrecognised spelling is returned unchanged
    (trimmed) rather than as `None` -- `classify` then reports it as
    `UNKNOWN` explicitly, which is a different, checkable claim from "this
    dependency declares no license", and a caller wanting to know which one
    happened needs the string preserved.
    """
    if not raw:
        return None
    candidate = raw.strip()
    if not candidate:
        return None

    key = _PUNCTUATION_RE.sub(" ", candidate.lower()).strip()
    if key in _ALIASES:
        return _ALIASES[key]

    # Already SPDX-shaped (case differs, e.g. "mit" or "APACHE-2.0")? Match
    # against the known tables case-insensitively before giving up.
    upper_candidate = candidate.upper()
    for table in (_PERMISSIVE, _WEAK_COPYLEFT, _COPYLEFT):
        for spdx_id in table:
            if spdx_id.upper() == upper_candidate:
                return spdx_id

    return candidate


def _classify_atom(raw: str | None) -> LicenseCategory:
    """The category of a SINGLE licence identifier, normalising first."""
    normalized = normalize(raw)
    if normalized is None:
        return LicenseCategory.UNKNOWN
    if normalized in _PERMISSIVE:
        return LicenseCategory.PERMISSIVE
    if normalized in _WEAK_COPYLEFT:
        return LicenseCategory.WEAK_COPYLEFT
    if normalized in _COPYLEFT:
        return LicenseCategory.COPYLEFT
    if normalized in _NETWORK_COPYLEFT:
        return LicenseCategory.NETWORK_COPYLEFT
    return LicenseCategory.UNKNOWN


_EXPRESSION_HINT = re.compile(r"(?i)(?:\bOR\b|\bAND\b|\bWITH\b|[()])")


def _split_top_level(expression: str, operator: str) -> list[str] | None:
    """Split on an operator that appears outside any parentheses, or None.

    None rather than a one-element list when the operator is absent, so the
    caller can tell "no split happened" from "split into one", which decides
    whether to recurse or bottom out at an atom.
    """
    parts: list[str] = []
    depth = 0
    token = f" {operator} "
    current = []
    i = 0
    upper = expression.upper()
    while i < len(expression):
        char = expression[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if depth == 0 and upper[i : i + len(token)] == token:
            parts.append("".join(current))
            current = []
            i += len(token)
            continue
        current.append(char)
        i += 1
    parts.append("".join(current))
    return parts if len(parts) > 1 else None


def _classify_expression(expression: str, depth: int = 0) -> LicenseCategory:
    """Evaluate an SPDX expression to a single category.

    `OR` is the licensee's choice, so it resolves to the LEAST restrictive
    operand -- `(MIT OR GPL-2.0)` is available under MIT and is not a copyleft
    obligation. `AND` applies every operand at once, so it resolves to the MOST
    restrictive. A `WITH` exception only ever loosens, so its base licence is a
    safe upper bound. Unknown operands are handled conservatively per operator.
    """
    text = expression.strip()
    if depth > 8:  # A malformed deeply-nested expression is not worth chasing.
        return LicenseCategory.UNKNOWN
    while text.startswith("(") and text.endswith(")"):
        # Strip a fully-enclosing pair, but only if it actually encloses -- not
        # `(A) AND (B)`, where the outer parens are two separate groups.
        inner = text[1:-1]
        d = 0
        encloses = True
        for j, char in enumerate(inner):
            d += (char == "(") - (char == ")")
            if d < 0 and j < len(inner) - 1:
                encloses = False
                break
        text = inner.strip() if encloses and d == 0 else text
        if not (encloses and d == 0):
            break

    # OR binds looser than AND in SPDX, so split on it first: the OR-operands
    # are whole AND-expressions.
    or_parts = _split_top_level(text, "OR")
    if or_parts:
        cats = [_classify_expression(p, depth + 1) for p in or_parts]
        known = [c for c in cats if c is not LicenseCategory.UNKNOWN]
        # The consumer may take any operand, so the effective obligation is the
        # least restrictive one they could choose. A known permissive operand
        # settles it regardless of an unknown alongside it.
        if known:
            return min(known, key=lambda c: _RESTRICTIVENESS[c])
        return LicenseCategory.UNKNOWN

    and_parts = _split_top_level(text, "AND")
    if and_parts:
        cats = [_classify_expression(p, depth + 1) for p in and_parts]
        known = [c for c in cats if c is not LicenseCategory.UNKNOWN]
        # Every operand's obligations apply together, so the effective category
        # is the most restrictive. An unknown operand cannot lower that, so the
        # max over the known operands is a sound floor.
        if known:
            return max(known, key=lambda c: _RESTRICTIVENESS[c])
        return LicenseCategory.UNKNOWN

    with_parts = _split_top_level(text, "WITH")
    if with_parts:
        # `<licence> WITH <exception>`. The exception loosens, so the base is an
        # upper bound on the obligation.
        return _classify_expression(with_parts[0], depth + 1)

    return _classify_atom(text)


def classify(raw: str | None) -> LicenseCategory:
    """The category of a declared license string or SPDX expression.

    A bare identifier goes straight to the table; an expression (one containing
    `OR`, `AND`, `WITH` or parentheses) is evaluated operand by operand. The
    `or-later` suffix in identifiers like `GPL-3.0-or-later` is deliberately not
    treated as the `OR` operator -- it is part of the identifier, and the
    expression split matches only a free-standing ` OR `.
    """
    if not raw or not raw.strip():
        return LicenseCategory.UNKNOWN
    if _EXPRESSION_HINT.search(raw):
        return _classify_expression(raw)
    return _classify_atom(raw)


__all__ = ["LicenseCategory", "classify", "normalize"]
