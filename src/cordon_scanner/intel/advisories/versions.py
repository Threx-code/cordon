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
import itertools
import re
from collections.abc import Callable
from typing import Any, ClassVar, Final

MAX_VERSION_LENGTH = 256
"""A version string longer than this is compared as opaque text.

No real published version approaches this. A lockfile entry that does is
either corrupt or hostile, and neither deserves a parser's attention -- this
bound is checked before any regex or split runs, so the cost of a pathological
string is capped at a length check.
"""

#: A tag with no version in it: a commit (hex with at least one letter: a run of digits alone is a number, such as a
#: date tag `20241231`) or a name with no digit (`latest`, `bookworm`, `main`).
_NOT_A_VERSION: Final = re.compile(r"^(?=[0-9a-f]*[a-f])[0-9a-f]{7,64}$|^[^0-9]*$")
#: A packaging revision is not part of the release: Homebrew's `_1`, vcpkg's `#2`.
_PACKAGING_REVISION: Final = re.compile(r"(?:_\d+|#\d+)$")

_TokenKey = tuple[int, int, str]
"""The shape every token-comparison key here reduces to: a category (numeric
vs qualifier and, for Maven, a qualifier's rank), a numeric value, and a
string tiebreak. Shared so `_compare_padded_tokens` can stay generic over
both Maven's and RubyGems' key functions."""


class Versions:
    """Ordering versions within an ecosystem."""

    #: Every ecosystem's version scheme, by the method that compares under it, one entry each (a key not here, such
    #: as an advisory's own `cpe`, is compared as raw strings). A new ecosystem is an entry; a new scheme, a method.
    #:   _semver      SemVer, by each ecosystem's own rule: Hex (Elixir's `Version`), Helm (Chart.yaml's version
    #:                must be SemVer 2), Julia (`VersionNumber`), Actions' release tags (`v4`, `v4.1.2`, read
    #:                loosely: `v4` is `4.0.0`)
    #:   _libversion  upstream releases with no scheme of their own, compared as Repology compares them across
    #:                distributions, which is what NVD's ranges are written in; also CRAN (`package_version`), Hackage
    #:                (the PVP) and the Bazel Central Registry (`1.2.3.bcr.1`)
    #:   _tag         an image tag: a release when both carry one, else "cannot tell"
    #:   _nix         Nix's own `builtins.compareVersions`, for an input pinned at a release; a commit or a name, as text
    #:   _debian      opam's order, which is Debian's
    SCHEMES: ClassVar[dict[str, str]] = {
        "npm": "_semver",
        "pypi": "_pep440",
        "cargo": "_semver",
        "rubygems": "_rubygems",
        "nuget": "_semver",
        "gomod": "_semver",
        "maven": "_maven",
        "gradle": "_maven",
        "composer": "_semver",
        "pub": "_semver",
        "hex": "_semver",
        "cocoapods": "_semver",
        "swift": "_semver",
        "conda": "_libversion",
        "cran": "_libversion",
        "conan": "_libversion",
        "vcpkg": "_libversion",
        "homebrew": "_libversion",
        "nix": "_nix",
        "julia": "_semver",
        "hackage": "_libversion",
        "opam": "_debian",
        "helm": "_semver",
        "terraform": "_semver",
        "ansible": "_semver",
        "actions": "_semver",
        "image": "_tag",
        "bazel": "_libversion",
        # An editor extension's version is SemVer: the Marketplace and Open VSX both require it.
        "vscode": "_semver",
        "cpe": "_libversion",
    }

    @staticmethod
    # A pure function of three strings, asked the same question thousands of times in a scan:
    # deciding the version to upgrade to checks every `fixed` version against every advisory.
    @functools.lru_cache(maxsize=1 << 16)
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
            return Versions._compare_raw(a, b)

        scheme = Versions.SCHEMES.get(ecosystem)
        if scheme is None:
            return Versions._compare_raw(a, b)
        compared: int = getattr(Versions, scheme)(ecosystem, a, b)
        return compared

    @staticmethod
    def _pep440(ecosystem: str, a: str, b: str) -> int:
        return Versions._compare_keys(Versions._pep440_key(a), Versions._pep440_key(b), a, b)

    @staticmethod
    def _maven(ecosystem: str, a: str, b: str) -> int:
        return Versions._compare_padded_tokens(
            a, b, _TOKEN_RE, Versions._maven_token_key, _MAVEN_QUALIFIER_PAD
        )

    @staticmethod
    def _rubygems(ecosystem: str, a: str, b: str) -> int:
        # No release-equivalent qualifier in this scheme (see the module
        # note above): a missing segment always beats a real qualifier
        # segment, which is exactly what the numeric-zero pad already
        # encodes, since "numeric" outranks "qualifier" at every position.
        return Versions._compare_padded_tokens(
            a, b, _TOKEN_RE, Versions._rubygems_segment_key, _NUMERIC_ZERO_PAD
        )

    @staticmethod
    def _semver(ecosystem: str, a: str, b: str) -> int:
        return Versions._compare_keys(Versions._semver_key(a), Versions._semver_key(b), a, b)

    @staticmethod
    def _nix(ecosystem: str, a: str, b: str) -> int:
        """Nix's `builtins.compareVersions`: components split at `.` and `-` and between digits and letters; two numbers
        compare by value, `pre` is below everything, a number is above a word, words compare as text, and a version that
        runs out of components is the lower. A commit or a name has no version: compared as text."""
        if _NOT_A_VERSION.match(a) or _NOT_A_VERSION.match(b):
            return Versions._compare_raw(a, b)

        def parts(text: str) -> list[str]:
            # Runs of digits and of other characters; `.` and `-` only separate them (linear, no pattern).
            found: list[str] = []
            for digits, run in itertools.groupby(text, str.isdigit):
                chunk = "".join(run)
                if digits:
                    found.append(chunk)
                else:
                    found.extend(p for p in chunk.replace("-", ".").split(".") if p)
            return found

        def less(x: str, y: str) -> bool:
            if x.isdigit() and y.isdigit():
                nx, ny = x.lstrip("0"), y.lstrip("0")
                return (len(nx), nx) < (len(ny), ny)
            if x == "" and y.isdigit():
                return True
            if x == "pre" and y != "pre":
                return True
            if y == "pre":
                return False
            if y.isdigit():
                return True
            if x.isdigit():
                return False
            return x < y

        left, right = parts(a), parts(b)
        for i in range(max(len(left), len(right))):
            x = left[i] if i < len(left) else ""
            y = right[i] if i < len(right) else ""
            if less(x, y):
                return -1
            if less(y, x):
                return 1
        return 0

    @staticmethod
    def _tag(ecosystem: str, a: str, b: str) -> int:
        """An image tag: its release (`1.25.3`) and its variant (`-debian-12-r0`, `-slim`, `-alpine`). Releases compare
        as releases; a variant is not a pre-release, so of two equal releases the variant decides only between
        themselves (`1.25.3-debian-12-r0` is release 1.25.3, never before it). A name (`latest`) or a commit has no
        release, and compares as plain text, "cannot tell"."""
        if _NOT_A_VERSION.match(a) or _NOT_A_VERSION.match(b):
            return Versions._compare_raw(a, b)
        left, right = Versions._release_of(a), Versions._release_of(b)
        if left is None or right is None or Versions._pre(left[1]) or Versions._pre(right[1]):
            # No release to read, or a pre-release (`-rc1`, `-beta2`): ordered as releases are, before its release.
            return LibVersion.compare(a, b)
        released = LibVersion.compare(left[0], right[0])
        if released:
            return released
        return Versions._variant_order(left[1], right[1])

    #: The words that make a tag's suffix a pre-release of its release rather than a variant of it.
    PRE_RELEASE: ClassVar[tuple[str, ...]] = (
        "rc",
        "alpha",
        "beta",
        "pre",
        "dev",
        "snapshot",
        "preview",
        "a",
        "b",
    )

    @staticmethod
    def _pre(variant: str) -> bool:
        """Whether a tag's suffix is a pre-release: its first word, after the separator, is a pre-release marker."""
        word = ""
        for char in variant.lstrip("-._+").lower():
            if not char.isalpha():
                break
            word += char
        return word in Versions.PRE_RELEASE

    @staticmethod
    def _variant_order(x: str, y: str) -> int:
        """Two variants of one release (`-debian-12-r2`, `-debian-12-r10`): runs of digits by value, the rest as text."""
        left = ["".join(r) for _, r in itertools.groupby(x, str.isdigit)]
        right = ["".join(r) for _, r in itertools.groupby(y, str.isdigit)]
        for p, q in zip(left, right, strict=False):
            if p.isdigit() and q.isdigit():
                np_, nq = p.lstrip("0"), q.lstrip("0")
                if (len(np_), np_) != (len(nq), nq):
                    return -1 if (len(np_), np_) < (len(nq), nq) else 1
            elif p != q:
                return -1 if p < q else 1
        return (len(left) > len(right)) - (len(left) < len(right))

    @staticmethod
    def _release_of(tag: str) -> tuple[str, str] | None:
        """An image tag's release and its variant (`1.25.3`, `-debian-12-r0`): dotted numbers from the start, an
        optional `v` before them; None when the tag does not start with a number."""
        start = 1 if tag[:1] in ("v", "V") else 0
        end = start
        while end < len(tag) and (
            tag[end].isdigit()
            or (tag[end] == "." and end + 1 < len(tag) and tag[end + 1].isdigit() and end > start)
        ):
            end += 1
        if end == start or not tag[start].isdigit():
            return None
        return tag[start:end], tag[end:]

    @staticmethod
    def _debian(ecosystem: str, a: str, b: str) -> int:
        """opam's ordering, which is Debian's: alternating runs of non-digits and digits. Non-digit runs compare
        character by character, `~` before the end of the run, the end before letters, letters before every other
        character; digit runs compare as numbers."""

        def order(c: str) -> int:
            if c == "~":
                return -1
            if c.isalpha():
                return ord(c)
            return ord(c) + 256

        def runs(text: str) -> list[str]:
            # Alternating runs of digits and of everything else (linear, no pattern).
            return ["".join(run) for _, run in itertools.groupby(text, str.isdigit)]

        left, right = runs(a), runs(b)
        if left and left[0][0].isdigit():
            left.insert(0, "")
        if right and right[0][0].isdigit():
            right.insert(0, "")
        for i in range(max(len(left), len(right))):
            x = left[i] if i < len(left) else ""
            y = right[i] if i < len(right) else ""
            # Digits: by value, without int() (a run of thousands of digits is valid text).
            if i % 2:
                nx, ny = x.lstrip("0"), y.lstrip("0")
                if (len(nx), nx) != (len(ny), ny):
                    return -1 if (len(nx), nx) < (len(ny), ny) else 1
                continue
            for j in range(max(len(x), len(y))):
                cx = order(x[j]) if j < len(x) else 0
                cy = order(y[j]) if j < len(y) else 0
                if cx != cy:
                    return -1 if cx < cy else 1
        return 0

    @staticmethod
    def _libversion(ecosystem: str, a: str, b: str) -> int:
        return LibVersion.compare(
            _PACKAGING_REVISION.sub("", a) if ecosystem != "cpe" else a,
            _PACKAGING_REVISION.sub("", b) if ecosystem != "cpe" else b,
        )

    @staticmethod
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
        # `"0"` is OSV's spelling of "no lower bound", not a version to compare against. Compared as
        # a release, every prerelease of 0.0.0 sorts below it -- and a Go pseudo-version,
        # `v0.0.0-20180724234803-3673e40ba225`, is exactly that, so every module pinned to a commit
        # rather than a tag fell outside every open-ended advisory and matched none of them.
        if (
            introduced
            and introduced != "0"
            and Versions.compare(ecosystem, version, introduced) < 0
        ):
            return False
        if fixed and Versions.compare(ecosystem, version, fixed) >= 0:
            return False
        return not (last_affected and Versions.compare(ecosystem, version, last_affected) > 0)

    @staticmethod
    def _compare_raw(a: str, b: str) -> int:
        return -1 if a < b else (1 if a > b else 0)

    @staticmethod
    def _compare_keys(key_a: object | None, key_b: object | None, raw_a: str, raw_b: str) -> int:
        if key_a is None or key_b is None:
            return Versions._compare_raw(raw_a, raw_b)
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
            return Versions._compare_raw(raw_a, raw_b)

    @staticmethod
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
            return Versions._compare_raw(a, b)

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

    @staticmethod
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

    @staticmethod
    def _semver_key(version: str) -> tuple[Any, ...] | None:
        match = _SEMVER_RE.match(version) or _SEMVER_LOOSE_RE.match(version)
        if not match:
            return None
        groups = match.groupdict()
        core = tuple(int(groups.get(name) or 0) for name in ("major", "minor", "patch", "extra"))
        return (core, Versions._semver_prerelease_key(groups.get("prerelease")))

    @staticmethod
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

    @staticmethod
    def _maven_token_key(token: str) -> _TokenKey:
        if token.isdigit():
            return (1, int(token), "")
        rank = _MAVEN_QUALIFIER_RANK.get(token.lower())
        if rank is not None:
            return (0, rank, "")
        # An unrecognised qualifier sorts after every recognised one and among
        # its own kind alphabetically -- unknown is not the same claim as "newer".
        return (0, len(_MAVEN_QUALIFIER_RANK), token.lower())

    # -- RubyGems `Gem::Version` ------------------------------------------------
    #
    # https://github.com/rubygems/rubygems/blob/master/lib/rubygems/version.rb
    # Tokenised the same way as Maven above. A numeric segment always outranks a
    # string segment at the same position, so a prerelease suffix such as `.pre`
    # or `.rc1` sorts before the release it precedes -- and unlike Maven, RubyGems
    # has no release-equivalent qualifier, so a *missing* trailing segment beats
    # any qualifier the other side has there: `1.0` > `1.0.pre`, never equal.

    @staticmethod
    def _rubygems_segment_key(token: str) -> _TokenKey:
        if token.isdigit():
            return (1, int(token), "")
        return (0, 0, token)

    @staticmethod
    def sort_key(ecosystem: str, version: str) -> Any:
        """A key suitable for `sorted(..., key=...)` within one ecosystem.

        Maven and RubyGems compare pairwise (see `_compare_padded_tokens`), so
        there is no single per-version key for them independent of what they are
        being compared against; this wraps `compare` with `functools.cmp_to_key`
        for every ecosystem uniformly rather than maintaining two code paths that
        could disagree with each other.
        """

        def _cmp(a: str, b: str) -> int:
            return Versions.compare(ecosystem, a, b)

        return functools.cmp_to_key(_cmp)(version)


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
# `tests/unit/rules/test_pattern_safety.py` sweeps every compiled pattern in the
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


_MAVEN_QUALIFIER_PAD = Versions._maven_token_key("")
"""What a missing trailing qualifier is equivalent to: Maven's own release
rank. `1.0` and `1.0-final` compare equal because both reduce to this."""


__all__ = ["MAX_VERSION_LENGTH", "Versions"]


class LibVersion:
    """Repology's libversion algorithm (github.com/repology/libversion, doc/ALGORITHM.md), which
    compares the versions of one project as every distribution spells them.

    A version splits into components at every character that is not a letter or digit, and again
    where letters meet digits (`1.0alpha2`: 1, 0, alpha, 2). Each component has a rank:

        pre-release  <  zero  <  post-release  <  non-zero  <  letter suffix

    `alpha`, `beta`, `rc`, `pre` are pre-releases; `post`, `patch`, `pl`, `errata` are
    post-releases; any other word straight after a number and not followed by one is a letter
    suffix (`1.0a` after `1.0`), and elsewhere a pre-release. The shorter version is padded with zeros
    (`1.0` is `1.0.0`). Within a rank, numbers compare as numbers and words by their first letter,
    ignoring case (`alpha` is `a`)."""

    PRE_RELEASE: Final = 1
    ZERO: Final = 2
    POST_RELEASE: Final = 3
    NONZERO: Final = 4
    LETTER_SUFFIX: Final = 5
    POST_WORDS: Final = frozenset({"post", "patch", "pl", "errata"})
    PRE_WORDS: Final = frozenset({"alpha", "beta", "rc", "pre"})

    @staticmethod
    def components(version: str) -> list[tuple[int, int, str]]:
        """`(rank, number, first letter)` per component."""
        out: list[tuple[int, int, str]] = []
        for segment in re.split(r"[^A-Za-z0-9]+", version):
            parts = re.findall(r"[0-9]+|[A-Za-z]+", segment)
            for index, part in enumerate(parts):
                if part.isdigit():
                    number = int(part)
                    out.append((LibVersion.NONZERO if number else LibVersion.ZERO, number, ""))
                    continue
                word = part.lower()
                follows_number = index > 0 and parts[index - 1].isdigit()
                followed_by_number = index + 1 < len(parts) and parts[index + 1].isdigit()
                if word in LibVersion.POST_WORDS:
                    rank = LibVersion.POST_RELEASE
                elif word in LibVersion.PRE_WORDS:
                    rank = LibVersion.PRE_RELEASE
                elif follows_number and not followed_by_number and len(parts) == index + 1:
                    rank = LibVersion.LETTER_SUFFIX
                else:
                    rank = LibVersion.PRE_RELEASE
                out.append((rank, 0, word[0]))
        return out

    @staticmethod
    def compare(a: str, b: str) -> int:
        left, right = LibVersion.components(a), LibVersion.components(b)
        padding = (LibVersion.ZERO, 0, "")
        for index in range(max(len(left), len(right))):
            x = left[index] if index < len(left) else padding
            y = right[index] if index < len(right) else padding
            if x != y:
                return -1 if x < y else 1
        return 0
