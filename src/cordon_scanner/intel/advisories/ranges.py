"""Whether a declared version range admits a given release.

A manifest without a lockfile names ranges, and what installs is the highest release each range
admits on the day of the install. A compromised release published inside a range a popular package
already declares is therefore installed by every consumer who resolves fresh -- which is how a worm
spreads through dependents without touching their code. This answers the one question that needs:
does `^1.11.21` admit `1.11.22`?

Every ecosystem whose installer resolves a range upward is read in its own syntax (npm, PEP 440,
Maven intervals, Cargo, Julia, pub, Helm, Composer, Conan, the `~>` family, conda, Cabal, opam,
SwiftPM, R and Ansible); each one where no install resolves upward says why in `NO_RANGES`.
Anything this does not parse answers False: a range nobody can read is not evidence that a
malicious release would be installed.
"""

from __future__ import annotations

import re
from typing import ClassVar, Final

from cordon_scanner.intel.advisories.versions import Versions

_NPM_PARTIAL: Final = re.compile(
    r"^v?(?P<major>\d{1,9}|[xX*])(?:\.(?P<minor>\d{1,9}|[xX*]))?(?:\.(?P<patch>\d{1,9}|[xX*]))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]{1,64}))?(?:\+[0-9A-Za-z.-]{1,64})?$"
)
_NPM_COMPARATOR: Final = re.compile(r"^(?P<op><=|>=|<|>|=|\^|~>|~)?\s{0,4}(?P<version>\S{1,80})$")


class VersionRanges:
    """Whether a version satisfies an ecosystem's range syntax."""

    @staticmethod
    def admits(ecosystem: str, spec: str, version: str) -> bool:
        """Whether `spec` admits `version` under the ecosystem's range syntax."""
        spec = spec.strip()
        syntax = VersionRanges.SYNTAX.get(ecosystem)
        if syntax is None:
            return False
        reader = getattr(VersionRanges, syntax, None) or getattr(ComparatorRanges, syntax)
        admitted: bool = reader(ecosystem, spec, version)
        return admitted

    #: Each ecosystem's range syntax, by the method that reads it. A new syntax is an entry and a
    #: method. An ecosystem not here admits nothing, and each has a reason in `NO_RANGES`.
    SYNTAX: ClassVar[dict[str, str]] = {
        "npm": "_npm_syntax",
        "pypi": "_pep440_syntax",
        "maven": "_interval_admits",
        "gradle": "_interval_admits",
        "nuget": "_interval_admits",
        "cargo": "_caret_default_syntax",
        "julia": "_julia_syntax",
        "pub": "_pub_syntax",
        "helm": "_helm_syntax",
        "composer": "_composer_syntax",
        "conan": "_conan_syntax",
        "rubygems": "_pessimistic_syntax",
        "hex": "_pessimistic_syntax",
        "cocoapods": "_pessimistic_syntax",
        "terraform": "_pessimistic_syntax",
        "ansible": "_comparator_syntax",
        "conda": "_conda_syntax",
        "cran": "_comparator_syntax",
        "hackage": "_hackage_syntax",
        "opam": "_opam_syntax",
        "swift": "_swift_syntax",
    }

    #: Ecosystems where a declared version is never a range an install resolves upward, each with why.
    NO_RANGES: ClassVar[dict[str, str]] = {
        "gomod": "a require line is a minimum, and minimal version selection installs exactly the "
        "highest minimum any module states, never a newer release on its own",
        "bazel": "a bazel_dep version is a minimum resolved by minimal version selection, as Go's is",
        "vcpkg": "`version>=` is a minimum resolved against the baseline the manifest pins, so a "
        "new release is installed only when someone moves the baseline",
        "nix": "a flake input names a reference, and the lock file pins the revision it resolved to",
        "actions": "a `uses:` reference names a tag, branch or commit, not a range; a moving tag "
        "is judged by the pinning rules",
        "image": "an image reference names a tag or a digest, not a range; a moving tag is judged "
        "by the pinning rules",
        "homebrew": "a formula installs its one current version; Brewfile lines name no versions",
        "vscode": "an extension recommendation names an identifier, never a version range",
    }

    @staticmethod
    def _npm_syntax(ecosystem: str, spec: str, version: str) -> bool:
        return VersionRanges._npm_admits(spec, version)

    @staticmethod
    def _pep440_syntax(ecosystem: str, spec: str, version: str) -> bool:
        return VersionRanges._pep440_admits(spec, version)

    # -- SemVer families read as npm reads them, after each one's own spelling ---------------------

    @staticmethod
    def _caret_default_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """Cargo: comma-separated requirements that must all hold; a bare version is a caret
        requirement (`1.2` is `^1.2`), and `=` is exact."""
        parts = [p.strip() for p in spec.split(",")]
        return VersionRanges._npm_admits(
            " ".join(VersionRanges._caret_if_bare(p) for p in parts), version
        )

    @staticmethod
    def _julia_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """Julia's `[compat]`: comma-separated entries, ANY of which may hold; a bare version is a
        caret entry, `~` a tilde one, `=` exact, and `≥`/`≤` are written for `>=`/`<=`."""
        spec = spec.replace("≥", ">=").replace("≤", "<=")
        parts = [p.strip() for p in spec.split(",")]
        return VersionRanges._npm_admits(
            " || ".join(VersionRanges._caret_if_bare(p) for p in parts), version
        )

    @staticmethod
    def _pub_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """pub: `^1.2.3`, comparators separated by spaces, `any`; a bare version is exact."""
        return VersionRanges._npm_admits("*" if spec == "any" else spec, version)

    @staticmethod
    def _helm_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """Helm chart dependencies (Masterminds semver): npm's forms, with `,` also joining."""
        return VersionRanges._npm_admits(spec.replace(",", " "), version)

    @staticmethod
    def _conan_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """Conan 2 ranges (`>=1.2 <2`, `~1.2`, `^1.2`, `||`); options after a comma do not narrow."""
        return VersionRanges._npm_admits(spec.split(",", 1)[0].strip(), version)

    @staticmethod
    def _composer_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """Composer: `||` or `|` between alternatives, `,` or spaces joining; `~1.2` lets only the
        last stated part grow (`>=1.2 <2.0`), unlike npm's; `@stable` flags and `v` do not narrow."""
        if spec.startswith("dev-") or len(spec) > 256:
            return False
        alternatives = re.split(r"\s{0,4}\|\|?\s{0,4}", re.sub(r"@[a-zA-Z]{1,16}", "", spec))
        out = []
        for alternative in alternatives:
            text = re.sub(r"(<=|>=|<|>|=|\^|~|!=)\s{1,4}", r"\1", alternative).replace(",", " ")
            tokens = text.split()
            out.append(
                " ".join(
                    VersionRanges._composer_token(t, hyphen="-" in tokens[max(0, i - 1) : i + 2])
                    for i, t in enumerate(tokens)
                )
            )
        return VersionRanges._npm_admits(" || ".join(out), version.lstrip("v"))

    #: A comparator on a short version (`<=1.4`, `1.2`): Composer reads `1.4` as exactly 1.4.0.
    _COMPOSER_SHORT: Final = re.compile(r"(<=|>=|<|>|=|!=)?v?(\d{1,9}(?:\.\d{1,9})?)")

    @staticmethod
    def _composer_token(token: str, *, hyphen: bool = False) -> str:
        """One Composer constraint as npm writes it: a short version padded to its exact release
        (`<=1.4` is `<=1.4.0`), except in a hyphen range, whose short upper end is a wildcard in
        Composer as in npm; `~1.2` as `>=1.2 <2`."""
        short = VersionRanges._COMPOSER_SHORT.fullmatch(token)
        if short and not hyphen:
            pieces = short.group(2).split(".")
            return (short.group(1) or "") + ".".join(pieces + ["0"] * (3 - len(pieces)))
        if not token.startswith("~") or token.startswith("~>"):
            return token
        base = token[1:].lstrip("v")
        upper = ComparatorRanges._pessimistic_upper(base)
        return f">={base} <{upper}-0" if upper else token

    @staticmethod
    def _caret_if_bare(part: str) -> str:
        return f"^{part}" if part[:1].isdigit() else part

    # -- Maven, Gradle and NuGet intervals ---------------------------------------------------------

    _INTERVAL: Final = re.compile(
        r"([\[\(])\s{0,4}([^,\[\]\(\)]{0,64}?)\s{0,4}(?:,\s{0,4}([^,\[\]\(\)]{0,64}?)\s{0,4})?([\]\)])"
    )

    @staticmethod
    def _interval_admits(ecosystem: str, spec: str, version: str) -> bool:
        """Maven's (and NuGet's) interval notation: `[1.0,2.0)`, `(,1.5]`, `[2.0]`, and unions
        `[1.0,1.2),[1.5,)`. A bare version is a soft requirement that names one version.

        Compared with the ecosystem's own ordering (`intel/versions.py`), so `1.0-SNAPSHOT` sorts
        before `1.0` and `1.0-alpha` before `1.0-beta`, as Maven sorts them."""
        if len(spec) > 256 or not version:
            return False
        if not spec.startswith(("[", "(")):
            return Versions.compare(ecosystem, spec, version) == 0 if spec else False
        intervals = VersionRanges._INTERVAL.findall(spec)
        if not intervals:
            return False
        for opening, low, high, closing in intervals:
            if not high and "," not in spec[spec.find(opening) :].split(closing, 1)[0]:
                # `[2.0]`: exactly this version.
                if (
                    opening == "["
                    and closing == "]"
                    and low
                    and Versions.compare(ecosystem, version, low) == 0
                ):
                    return True
                continue
            above = not low or (
                Versions.compare(ecosystem, version, low) >= 0
                if opening == "["
                else Versions.compare(ecosystem, version, low) > 0
            )
            below = not high or (
                Versions.compare(ecosystem, version, high) <= 0
                if closing == "]"
                else Versions.compare(ecosystem, version, high) < 0
            )
            if above and below:
                return True
        return False

    # -- npm ---------------------------------------------------------------------------------------

    @staticmethod
    def _npm_admits(spec: str, version: str) -> bool:
        if len(spec) > 256 or spec.startswith(
            ("file:", "link:", "workspace:", "git", "http", "npm:")
        ):
            return False
        candidate = _NPM_PARTIAL.match(version)
        if candidate is None or any(
            candidate.group(k) in (None, "x", "X", "*") for k in ("major", "minor", "patch")
        ):
            return False
        return any(
            VersionRanges._npm_set_admits(part.strip(), version, candidate.group("pre"))
            for part in spec.split("||")
        )

    @staticmethod
    def _npm_set_admits(part: str, version: str, prerelease: str | None) -> bool:
        if part in ("", "*", "x", "X", "latest"):
            return prerelease is None
        hyphen = re.fullmatch(r"(\S{1,80})\s{1,4}-\s{1,4}(\S{1,80})", part)
        comparators: list[tuple[str, str]] = []
        if hyphen:
            comparators += VersionRanges._bounds(">=", hyphen.group(1)) or []
            upper = VersionRanges._bounds("<=", hyphen.group(2))
            if upper is None:
                return False
            comparators += upper
        else:
            # `>= 1.2.3` and `>=1.2.3` alike: glue an operator to the version after it.
            tokens = re.sub(r"(<=|>=|<|>|=|\^|~>|~)\s{1,4}", r"\1", part).split()
            for token in tokens:
                match = _NPM_COMPARATOR.match(token)
                if match is None:
                    return False
                bounds = VersionRanges._bounds(match.group("op") or "", match.group("version"))
                if bounds is None:
                    return False
                comparators += bounds
        if prerelease is not None:
            # npm admits a prerelease only through a comparator naming the same major.minor.patch
            # with a prerelease of its own.
            core = version.split("-", 1)[0].lstrip("v")
            if not any("-" in bound and bound.split("-", 1)[0] == core for _, bound in comparators):
                return False
        return all(VersionRanges._holds(op, version, bound) for op, bound in comparators)

    @staticmethod
    def _bounds(op: str, text: str) -> list[tuple[str, str]] | None:
        """A comparator, expanded to plain `>=`/`<`/`<=`/`>`/`=` bounds on full versions."""
        match = _NPM_PARTIAL.match(text)
        if match is None:
            return None
        pre = match.group("pre")
        parts = [match.group(k) for k in ("major", "minor", "patch")]
        wild = [p is None or p in ("x", "X", "*") for p in parts]
        nums = [0 if w else int(p) for p, w in zip(parts, wild, strict=True)]
        full = f"{nums[0]}.{nums[1]}.{nums[2]}" + (f"-{pre}" if pre else "")
        if wild[0]:
            return [] if op in ("", "=", ">=", "<=", "^", "~", "~>") else None
        if op in ("", "="):
            if not any(wild):
                return [("=", full)]
            return VersionRanges._x_range(nums, wild)
        if op == "^":
            if nums[0] > 0 or wild[1]:
                upper = f"{nums[0] + 1}.0.0"
            elif nums[1] > 0 or wild[2]:
                upper = f"0.{nums[1] + 1}.0"
            else:
                upper = f"0.0.{nums[2] + 1}"
            return [(">=", full), ("<", f"{upper}-0")]
        if op in ("~", "~>"):
            upper = f"{nums[0] + 1}.0.0" if wild[1] else f"{nums[0]}.{nums[1] + 1}.0"
            return [(">=", full), ("<", f"{upper}-0")]
        if op in (">=", "<"):
            return [(op, full)]
        if op == ">":
            if any(wild):
                # `>1.2` is `>=1.3.0`.
                upper = VersionRanges._x_range(nums, wild)[1][1]
                return [(">=", upper)]
            return [(">", full)]
        if op == "<=":
            if any(wild):
                return [("<", VersionRanges._x_range(nums, wild)[1][1])]
            return [("<=", full)]
        return None

    @staticmethod
    def _x_range(nums: list[int], wild: list[bool]) -> list[tuple[str, str]]:
        low = f"{nums[0]}.{nums[1]}.{nums[2]}"
        upper = f"{nums[0] + 1}.0.0" if wild[1] else f"{nums[0]}.{nums[1] + 1}.0"
        return [(">=", low), ("<", f"{upper}-0")]

    @staticmethod
    def _holds(op: str, version: str, bound: str) -> bool:
        order = Versions.compare("npm", version.lstrip("v"), bound)
        return {
            "=": order == 0,
            ">=": order >= 0,
            ">": order > 0,
            "<": order < 0,
            "<=": order <= 0,
        }[op]

    @staticmethod
    def _pep440_admits(spec: str, version: str) -> bool:
        spec = spec.split(";", 1)[0].strip()
        if not spec or len(spec) > 256:
            return False
        for clause in spec.split(","):
            match = _PEP440_CLAUSE.match(clause.strip())
            if match is None:
                return False
            op, bound = match.group("op"), match.group("version")
            if op == "===":
                if version != bound:
                    return False
            elif bound.endswith(".*"):
                prefix = bound[:-2]
                inside = version == prefix or version.startswith(prefix + ".")
                if (op == "==" and not inside) or (op == "!=" and inside) or op not in ("==", "!="):
                    return False
            elif op == "~=":
                pieces = bound.split(".")
                if len(pieces) < 2:
                    return False
                prefix = ".".join(pieces[:-1])
                if Versions.compare("pypi", version, bound) < 0 or not (
                    version == prefix or version.startswith(prefix + ".")
                ):
                    return False
            else:
                order = Versions.compare("pypi", version, bound)
                ok = {
                    "==": order == 0,
                    "!=": order != 0,
                    ">=": order >= 0,
                    "<=": order <= 0,
                    ">": order > 0,
                    "<": order < 0,
                }[op]
                if not ok:
                    return False
        return True


class ComparatorRanges:
    """Range syntaxes that are lists of comparators, compared in the ecosystem's own version order:
    the `~>` family, conda, Cabal, opam, R, Ansible and SwiftPM (`VersionRanges.SYNTAX` names them)."""

    @staticmethod
    def _pessimistic_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """RubyGems, Hex, CocoaPods and Terraform: requirements joined by `,` (Hex: `and`/`or`);
        `~> 1.2` is `>= 1.2, < 2`, `~> 1.2.3` is `>= 1.2.3, < 1.3`; a bare version is exact."""
        alternatives = re.split(r"\s{1,4}or\s{1,4}", spec)
        return any(
            ComparatorRanges._all_hold(
                ecosystem, re.split(r"\s{0,4},\s{0,4}|\s{1,4}and\s{1,4}", alt), version
            )
            for alt in alternatives
        )

    @staticmethod
    def _comparator_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """Ansible collections and R packages: comparators joined by `,` (R writes `(>= 1.2)`)."""
        return ComparatorRanges._all_hold(ecosystem, spec.strip("() ").split(","), version)

    @staticmethod
    def _conda_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """conda: `|` between alternatives, `,` joining; `1.2.*`, and a bare or `=` version admits
        its own later parts (`1.2` admits `1.2.5`)."""
        return any(
            ComparatorRanges._all_hold(ecosystem, alt.split(","), version, prefix_bare=True)
            for alt in spec.split("|")
        )

    @staticmethod
    def _hackage_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """Cabal: `&&` joining, `||` between alternatives, `==1.2.*`, and `^>=1.2.3`, which admits
        up to the next major version as the PVP counts it (`<1.3`)."""
        if spec.strip() in ("-any", "any"):
            return True
        return any(
            ComparatorRanges._all_hold(ecosystem, alt.split("&&"), version)
            for alt in spec.split("||")
        )

    @staticmethod
    def _opam_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """opam: `>= "1.2" & < "2.0"`, `|` between alternatives; quoted versions."""
        if "(" in spec or "!" in spec.replace("!=", ""):
            return False
        text = spec.strip("{} ").replace('"', "")
        return any(
            ComparatorRanges._all_hold(ecosystem, alt.split("&"), version)
            for alt in text.split("|")
        )

    @staticmethod
    def _swift_syntax(ecosystem: str, spec: str, version: str) -> bool:
        """SwiftPM, as the manifest reader states a requirement: `>= 1.2.3, < next major`,
        `>= 1.2.3, < next minor`, `>= 1.0.0, < 2.0.0`, a bare exact version, or `*`."""
        found = re.fullmatch(r">=\s{0,4}(\S{1,80}),\s{0,4}<\s{0,4}next (major|minor)", spec)
        if found:
            tilde = found.group(2) == "minor"
            return VersionRanges._npm_admits(f"{'~' if tilde else '^'}{found.group(1)}", version)
        return ComparatorRanges._all_hold(ecosystem, spec.split(","), version)

    @staticmethod
    def _all_hold(
        ecosystem: str, clauses: list[str], version: str, *, prefix_bare: bool = False
    ) -> bool:
        """Every comparator clause holds for `version` in the ecosystem's own version order; a
        clause nobody can read answers False, as an unreadable range always does here."""
        if not version or sum(len(c) for c in clauses) > 256:
            return False
        read = [c.strip() for c in clauses if c.strip()]
        return bool(read) and all(
            ComparatorRanges._clause_holds(ecosystem, c, version, prefix_bare) for c in read
        )

    _CLAUSE: Final = re.compile(
        r"^(?P<op>\^>=|~>|===|==|!=|>=|<=|~=|>|<|=)?\s{0,4}(?P<v>[^\s,]{1,80})$"
    )

    @staticmethod
    def _clause_holds(ecosystem: str, clause: str, version: str, prefix_bare: bool) -> bool:
        match = ComparatorRanges._CLAUSE.match(clause)
        if match is None:
            return False
        op, bound = match.group("op") or "", match.group("v")
        if bound in ("*", "any"):
            return op in ("", "==", "=", ">=")
        if bound.endswith(".*") or (prefix_bare and op in ("", "=")):
            prefix = bound.removesuffix(".*")
            inside = version == prefix or version.startswith(prefix + ".")
            return inside if op != "!=" else not inside
        if op in ("~>", "~=", "^>="):
            upper = ComparatorRanges._pessimistic_upper(bound, pvp=op == "^>=")
            if upper is None:
                return False
            return (
                ComparatorRanges._order(ecosystem, version, bound) >= 0
                and ComparatorRanges._order(ecosystem, version, upper) < 0
            )
        order = ComparatorRanges._order(ecosystem, version, bound)
        return {
            "": order == 0,
            "=": order == 0,
            "==": order == 0,
            "===": version == bound,
            "!=": order != 0,
            ">=": order >= 0,
            "<=": order <= 0,
            ">": order > 0,
            "<": order < 0,
        }[op]

    @staticmethod
    def _pessimistic_upper(bound: str, *, pvp: bool = False) -> str | None:
        """The first version a pessimistic bound excludes: the last stated part dropped and the one
        before it raised (`1.2.3` -> `1.3`, `1.2` -> `2`); the PVP's major is the first two parts."""
        parts = re.match(r"\d{1,9}(?:\.\d{1,9}){0,8}", bound)
        if parts is None:
            return None
        nums = [int(n) for n in parts.group(0).split(".")]
        if pvp:
            nums = [*nums, 0][:2]
            return f"{nums[0]}.{nums[1] + 1}"
        if len(nums) > 1:
            nums = nums[:-1]
        nums[-1] += 1
        return ".".join(str(n) for n in nums)

    @staticmethod
    def _order(ecosystem: str, a: str, b: str) -> int:
        """`Versions.compare`, with a SemVer scheme's short versions padded (`1.2` as `1.2.0`)."""
        if Versions.SCHEMES.get(ecosystem) == "_semver":
            a, b = ComparatorRanges._padded(a), ComparatorRanges._padded(b)
        return Versions.compare(ecosystem, a, b)

    @staticmethod
    def _padded(text: str) -> str:
        core = re.fullmatch(r"v?(\d{1,9}(?:\.\d{1,9})?)", text)
        if core is None:
            return text
        pieces = core.group(1).split(".")
        return ".".join(pieces + ["0"] * (3 - len(pieces)))


# -- PEP 440 -----------------------------------------------------------------------------------

_PEP440_CLAUSE: Final = re.compile(
    r"^(?P<op>===|==|!=|~=|>=|<=|>|<)\s{0,4}(?P<version>[^\s,;]{1,80})$"
)


__all__ = ["ComparatorRanges", "VersionRanges"]
