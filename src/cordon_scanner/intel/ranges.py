"""Whether a declared version range admits a given release.

A manifest without a lockfile names ranges, and what installs is the highest release each range
admits on the day of the install. A compromised release published inside a range a popular package
already declares is therefore installed by every consumer who resolves fresh -- which is how a worm
spreads through dependents without touching their code. This answers the one question that needs:
does `^1.11.21` admit `1.11.22`?

npm ranges (`^`, `~`, x-ranges, comparators, hyphen ranges, `||`) and PEP 440 specifiers (`==` with
`.*`, `!=`, `~=`, `===`, comparators). Anything this does not parse answers False: a range nobody can
read is not evidence that a malicious release would be installed.
"""

from __future__ import annotations

import re
from typing import Final

from cordon_scanner.intel.versions import Versions

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
        if ecosystem == "npm":
            return VersionRanges._npm_admits(spec, version)
        if ecosystem == "pypi":
            return VersionRanges._pep440_admits(spec, version)
        if ecosystem in ("maven", "gradle", "nuget"):
            return VersionRanges._interval_admits(ecosystem, spec, version)
        return False

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


# -- PEP 440 -----------------------------------------------------------------------------------

_PEP440_CLAUSE: Final = re.compile(
    r"^(?P<op>===|==|!=|~=|>=|<=|>|<)\s{0,4}(?P<version>[^\s,;]{1,80})$"
)


__all__ = ["VersionRanges"]
