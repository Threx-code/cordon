"""Per-ecosystem version ordering, for matching a resolved dependency against
an advisory's affected range.

`Advisory.versions` (see `advisories.py`) is an exact list and stays one: a
compromised release is a short, known, discrete set, and enumerating it needs
no comparator at all. A CVE is a different shape. OSV, GHSA and NVD describe
one as a *range* -- introduced at this version, fixed at that one -- because
enumerating every affected release of an actively maintained package is
neither stable (new releases keep landing inside the window) nor something an
export can do once and have stay true. Matching a range needs to know, for a
given ecosystem, what "between" means.

Hand-rolled rather than a dependency. `packaging` for PEP 440, `semver` for
SemVer, a Maven library for Maven's ordering -- each would add exactly one
thing to a package whose core has zero runtime dependencies by governing
constraint (C1 in `docs/01-ARCHITECTURE.md`), and each covers one ecosystem
where this file needs five. Every scheme implemented here is a public,
versioned specification (SemVer 2.0.0, PEP 440, Maven's `ComparableVersion`,
RubyGems' `Gem::Version`) rather than something inferred from examples, and
each is covered by its own test module against known-ordering fixtures drawn
from the specification, not just from what this project happened to see.

Every entry point here takes a version string from a scanned target's own
lockfile -- attacker-controlled, like everything else that crosses this
boundary. Nothing below raises on malformed input; an unparsed segment falls
back to a string comparison rather than an exception, and `MAX_VERSION_LENGTH`
bounds the work a single comparison can be made to do, the same way
`max_line_bytes` bounds a line: cheaply, before any parsing starts, rather
than by hoping every parser degrades gracefully on its own.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any

MAX_VERSION_LENGTH = 256
"""A version string longer than this is compared as opaque text.

No real published version approaches this. A lockfile entry that does is
either corrupt or hostile, and neither deserves a parser's attention -- this
bound is checked before any regex or split runs, so the cost of a pathological
string is capped at a length check.
"""

_SEMVER_ECOSYSTEMS = frozenset({"npm", "cargo", "gomod", "nuget", "pub", "composer", "cocoapods"})
_MAVEN_ECOSYSTEMS = frozenset({"maven", "gradle"})

_TokenKey = tuple[int, int, str]
"""The shape every token-comparison key here reduces to: a category (numeric
vs qualifier and, for Maven, a qualifier's rank), a numeric value, and a
string tiebreak. Shared so `_compare_padded_tokens` can stay generic over
both Maven's and RubyGems' key functions."""


def compare(ecosystem: str, a: str, b: str) -> int:
    """-1 if `a` orders before `b`, 0 if equal, 1 if `a` orders after `b`.

    Falls back to plain string equality/ordering for an ecosystem with no
    scheme implemented here, and for either input once it fails to parse
    under the scheme that is. A wrong ordering on unparseable input would
    silently mismatch an advisory; a same-or-string-order fallback instead
    degrades to "cannot tell", which affects the match rather than fabricates
    one it is not confident of.
    """
    if a == b:
        return 0
    if len(a) > MAX_VERSION_LENGTH or len(b) > MAX_VERSION_LENGTH:
        return _compare_raw(a, b)

    if ecosystem == "pypi":
        return _compare_keys(_pep440_key(a), _pep440_key(b), a, b)
    if ecosystem in _MAVEN_ECOSYSTEMS:
        return _compare_padded_tokens(a, b, _TOKEN_RE, _maven_token_key, _MAVEN_QUALIFIER_PAD)
    if ecosystem == "rubygems":
        # No release-equivalent qualifier in this scheme (see the module
        # note above): a missing segment always beats a real qualifier
        # segment, which is exactly what the numeric-zero pad already
        # encodes, since "numeric" outranks "qualifier" at every position.
        return _compare_padded_tokens(a, b, _TOKEN_RE, _rubygems_segment_key, _NUMERIC_ZERO_PAD)
    if ecosystem in _SEMVER_ECOSYSTEMS:
        return _compare_keys(_semver_key(a), _semver_key(b), a, b)
    return _compare_raw(a, b)


def in_range(
    ecosystem: str,
    version: str,
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool:
    """Whether `version` falls inside an OSV-shaped affected range.

    OSV's own vocabulary: `introduced` is inclusive, `fixed` is exclusive (the
    version named is the first one that is *not* affected), `last_affected`
    is inclusive. A range with no `introduced` is open at the bottom -- OSV
    uses `"0"` for that case by convention, which every comparator here
    already orders before any real release, so no special case is needed.
    """
    if introduced and compare(ecosystem, version, introduced) < 0:
        return False
    if fixed and compare(ecosystem, version, fixed) >= 0:
        return False
    return not (last_affected and compare(ecosystem, version, last_affected) > 0)


def _compare_raw(a: str, b: str) -> int:
    return -1 if a < b else (1 if a > b else 0)


def _compare_keys(key_a: object | None, key_b: object | None, raw_a: str, raw_b: str) -> int:
    if key_a is None or key_b is None:
        return _compare_raw(raw_a, raw_b)
    try:
        if key_a < key_b:  # type: ignore[operator]
            return -1
        if key_a > key_b:  # type: ignore[operator]
            return 1
        return 0
    except TypeError:
        # Heterogeneous tuples from two inputs that parsed under the same
        # scheme but produced differently-shaped keys (rare, but a hand-rolled
        # parser earns no benefit of the doubt). Never allowed to raise past
        # this boundary.
        return _compare_raw(raw_a, raw_b)


def _compare_padded_tokens(
    a: str,
    b: str,
    token_re: re.Pattern[str],
    key_fn: Callable[[str], _TokenKey],
    qualifier_pad: _TokenKey,
) -> int:
    """Compare two token lists of possibly different length.

    The shared problem behind Maven's `1.0` == `1.0-final` and RubyGems'
    `1.0.pre` < `1.0`: whichever version has fewer tokens is missing a
    trailing one, and what a missing token is *equivalent to* depends on
    what kind of token the other side actually has there -- a missing
    numeric segment is a `0` (`1.0` == `1.0.0`), a missing qualifier segment
    is scheme-specific (`qualifier_pad`: Maven's release-equivalent rank for
    Maven, an always-inferior sentinel for RubyGems, where any bare suffix
    is a prerelease marker and there is no release-equivalent qualifier to
    pad with). Plain tuple comparison of differently-sized tuples gets this
    wrong in both directions, which is what made the first version of this
    function fail its own tests.
    """
    tokens_a = token_re.findall(a)
    tokens_b = token_re.findall(b)
    if not tokens_a or not tokens_b:
        return _compare_raw(a, b)

    for i in range(max(len(tokens_a), len(tokens_b))):
        if i < len(tokens_a) and i < len(tokens_b):
            key_a, key_b = key_fn(tokens_a[i]), key_fn(tokens_b[i])
        elif i < len(tokens_a):
            key_a = key_fn(tokens_a[i])
            key_b = _NUMERIC_ZERO_PAD if tokens_a[i].isdigit() else qualifier_pad
        else:
            key_b = key_fn(tokens_b[i])
            key_a = _NUMERIC_ZERO_PAD if tokens_b[i].isdigit() else qualifier_pad
        if key_a != key_b:
            return -1 if key_a < key_b else 1
    return 0


_NUMERIC_ZERO_PAD = (1, 0, "")
"""What a missing numeric segment is equivalent to: the value zero."""


# -- SemVer 2.0.0 -------------------------------------------------------
#
# https://semver.org/. Covers npm, Cargo, Go modules (after stripping the
# mandatory `v` prefix -- a Go pseudo-version such as
# `v0.0.0-20200101000000-abcdef123456` parses as a normal SemVer prerelease
# of `0.0.0` and sorts low, which is the right shape even though nothing here
# knows it is a pseudo-version specifically), NuGet (SemVer 2 since NuGet 4.3,
# with a tolerated fourth legacy `System.Version` component), Dart/pub,
# Composer and CocoaPods, all of which publish SemVer-shaped versions in
# practice even where their constraint *syntax* differs.

_SEMVER_RE = re.compile(
    r"""^v?
    (?P<major>0|[1-9]\d*)
    \.(?P<minor>0|[1-9]\d*)
    \.(?P<patch>0|[1-9]\d*)
    (?:\.(?P<extra>0|[1-9]\d*))?
    (?:-(?P<prerelease>[0-9A-Za-z.-]+))?
    (?:\+(?P<build>[0-9A-Za-z.-]+))?
    $""",
    re.VERBOSE,
)

_SEMVER_LOOSE_RE = re.compile(
    r"""^v?
    (?P<major>\d+)
    (?:\.(?P<minor>\d+))?
    (?:\.(?P<patch>\d+))?
    (?:-(?P<prerelease>[0-9A-Za-z.-]+))?
    (?:\+(?P<build>[0-9A-Za-z.-]+))?
    $""",
    re.VERBOSE,
)


def _semver_prerelease_key(prerelease: str | None) -> tuple[Any, ...]:
    if prerelease is None:
        # No prerelease sorts after any prerelease of the same core version.
        return (1,)
    identifiers = prerelease.split(".")
    keyed: list[tuple[int, int, str]] = []
    for ident in identifiers:
        if ident.isdigit():
            keyed.append((0, int(ident), ""))
        else:
            keyed.append((1, 0, ident))
    return (0, tuple(keyed))


def _semver_key(version: str) -> tuple[Any, ...] | None:
    match = _SEMVER_RE.match(version) or _SEMVER_LOOSE_RE.match(version)
    if not match:
        return None
    groups = match.groupdict()
    core = tuple(int(groups.get(name) or 0) for name in ("major", "minor", "patch", "extra"))
    return (core, _semver_prerelease_key(groups.get("prerelease")))


# -- PEP 440 --------------------------------------------------------------
#
# https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions
# Reproduces that appendix's normalisation rules rather than its exact regex,
# which is written for `re.VERBOSE` matching over the full grammar including
# local version identifiers. Local segments are parsed but not weighted into
# ordering beyond a final string tiebreak: they exist to distinguish rebuilds
# of the same public version, which is a question this module is never asked.
#
# The release and local segments are capped at 16 repeats
# (`rules/loader.py`'s `LARGE_REPEAT`) rather than left as `*`.
# `tests/unit/test_pattern_safety.py` sweeps every compiled pattern in the
# package -- including this one -- through the same catastrophic-backtracking
# validator a YAML rule pack is refused for, and `X+(?:sep X+)*` is exactly
# the nested-unbounded shape it exists to catch, even though `.` and `-`
# disambiguate the two `+`s enough that this specific instance was never
# exploitable. No real version has more than a handful of segments, so the
# cap costs nothing real.

_PEP440_RE = re.compile(
    r"""^\s*
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+){0,16})
    (?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]+)?)?
    (?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-zA-Z0-9]+(?:[-_.][a-zA-Z0-9]+){0,16}))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

_PEP440_PRE_ALIASES = {
    "alpha": "a",
    "beta": "b",
    "c": "rc",
    "pre": "rc",
    "preview": "rc",
}


class _NegativeInfinity:
    """Sorts below everything, including another instance's ordinary peers."""

    def __lt__(self, other: object) -> bool:
        return True

    def __gt__(self, other: object) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _NegativeInfinity)

    def __hash__(self) -> int:
        return hash("_NegativeInfinity")


class _Infinity:
    """Sorts above everything, including another instance's ordinary peers."""

    def __lt__(self, other: object) -> bool:
        return False

    def __gt__(self, other: object) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Infinity)

    def __hash__(self) -> int:
        return hash("_Infinity")


_NEG_INF = _NegativeInfinity()
_INF = _Infinity()


def _pep440_key(version: str) -> tuple[Any, ...] | None:
    """Follows the ordering `packaging.version.Version` implements.

    The subtlety worth documenting: pre/post/dev are not three independent
    axes compared in a fixed priority order -- `1.0a2.dev1` (a prerelease
    that is *itself* still in development) needs its `pre` field to win the
    comparison against `1.0a1` before `dev` is ever consulted, which only
    happens if `pre` sits earlier in the key tuple than `dev` and a bare
    dev-release (`1.0.dev1`, no `pre` at all) is handled as a special case
    of the `pre` field instead: `pre` is `-inf` when a version is *purely* a
    dev release (dev set, pre and post both absent), `+inf` when there is no
    prerelease marker at all (an ordinary or post release outranks any
    prerelease of the same series), and the real `(letter, number)` pair
    otherwise. An earlier version of this function compared `dev` ahead of
    `pre` unconditionally and ordered `1.0a2.dev1` before `1.0a1` -- backwards.
    """
    match = _PEP440_RE.match(version)
    if not match:
        return None
    g = match.groupdict()

    epoch = int(g["epoch"]) if g["epoch"] else 0
    # Trailing zero release segments are insignificant under PEP 440:
    # `1.0` == `1.0.0`. Stripped here rather than padded, because padding to
    # equal length needs to know the other version's length -- stripping
    # needs only this one.
    release_parts = [int(part) for part in g["release"].split(".")]
    while len(release_parts) > 1 and release_parts[-1] == 0:
        release_parts.pop()
    release = tuple(release_parts)

    has_pre = bool(g["pre_l"])
    has_post = bool(g["post"])
    has_dev = g["dev_n"] is not None or bool(g["dev"])

    if has_pre:
        label = _PEP440_PRE_ALIASES.get(g["pre_l"].lower(), g["pre_l"].lower())
        pre_n = int(g["pre_n"]) if g["pre_n"] else 0
        pre: object = (label, pre_n)
    elif not has_post and has_dev:
        pre = _NEG_INF
    else:
        pre = _INF

    post_n = g["post_n1"] or g["post_n2"]
    post: object = int(post_n) if (has_post and post_n) else (0 if has_post else _NEG_INF)

    dev: object = int(g["dev_n"]) if (has_dev and g["dev_n"]) else (0 if has_dev else _INF)

    return (epoch, release, pre, post, dev, g["local"] or "")


# -- Maven `ComparableVersion` (subset) ------------------------------------
#
# https://maven.apache.org/ref/current/maven-core/artifact-version.html
# Covers Maven and Gradle, which share the same coordinate/version model.
#
# Not a full reimplementation of `ComparableVersion` -- that class's handling
# of trailing null items (`1.0` == `1.0.0` == `1-0` == `1.0.0.0`) and of
# qualifiers immediately after a dash versus immediately after a dot differ in
# ways that only change ordering in cases a supply-chain scan is unlikely to
# turn on. What this keeps faithfully from the specification is the part a
# wrong answer here would be dangerous on: numeric segments compare
# numerically and always outrank a qualifier segment in the same position
# except for the recognised release-equivalent qualifiers, and the qualifier
# ranking itself (alpha < beta < milestone < rc/cr < snapshot < "" (release)
# < sp) is exact.
_MAVEN_QUALIFIER_RANK = {
    "alpha": 0,
    "beta": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": 5,
    "final": 5,
    "ga": 5,
    "release": 5,
    "sp": 6,
}

# Shared by Maven and RubyGems below: both tokenise a version into runs of
# digits and runs of letters, treating every other character as a separator.
_TOKEN_RE = re.compile(r"[0-9]+|[A-Za-z]+")


def _maven_token_key(token: str) -> _TokenKey:
    if token.isdigit():
        return (1, int(token), "")
    rank = _MAVEN_QUALIFIER_RANK.get(token.lower())
    if rank is not None:
        return (0, rank, "")
    # An unrecognised qualifier sorts after every recognised one and among
    # its own kind alphabetically -- unknown is not the same claim as "newer".
    return (0, len(_MAVEN_QUALIFIER_RANK), token.lower())


_MAVEN_QUALIFIER_PAD = _maven_token_key("")
"""What a missing trailing qualifier is equivalent to: Maven's own release
rank. `1.0` and `1.0-final` compare equal because both reduce to this."""


# -- RubyGems `Gem::Version` ------------------------------------------------
#
# https://github.com/rubygems/rubygems/blob/master/lib/rubygems/version.rb
# Tokenised the same way as Maven above. A numeric segment always outranks a
# string segment at the same position, so a prerelease suffix such as `.pre`
# or `.rc1` sorts before the release it precedes -- and unlike Maven, RubyGems
# has no release-equivalent qualifier, so a *missing* trailing segment beats
# any qualifier the other side has there: `1.0` > `1.0.pre`, never equal.


def _rubygems_segment_key(token: str) -> _TokenKey:
    if token.isdigit():
        return (1, int(token), "")
    return (0, 0, token)


def sort_key(ecosystem: str, version: str) -> Any:
    """A key suitable for `sorted(..., key=...)` within one ecosystem.

    Maven and RubyGems compare pairwise (see `_compare_padded_tokens`), so
    there is no single per-version key for them independent of what they are
    being compared against; this wraps `compare` with `functools.cmp_to_key`
    for every ecosystem uniformly rather than maintaining two code paths that
    could disagree with each other.
    """

    def _cmp(a: str, b: str) -> int:
        return compare(ecosystem, a, b)

    return functools.cmp_to_key(_cmp)(version)


__all__ = ["MAX_VERSION_LENGTH", "compare", "in_range", "sort_key"]
