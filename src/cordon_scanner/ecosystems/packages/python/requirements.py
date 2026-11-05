"""Python requirements as pip and PEP 508 write them: a requirement line's name, specifier, extras
and markers, and a project's declared metadata."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from cordon_scanner.ecosystems.base import (
    DeclaredDependency,
)
from cordon_scanner.foundation.models import Scope

# PEP 508: strip the version specifier, extras and environment marker from a
# requirement to recover the bare name.
_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")

_INLINE_OPTION = re.compile(r"\s-{1,2}[A-Za-z]")
"""The start of a pip option following a requirement on the same line.

`req==1.0 --hash=sha256:...` and `req==1.0 --global-option=x` are both legal.
Anything from here on describes how to install the requirement, not which
requirement it is.
"""


class PypiManifest:
    """Requirement lines and pyproject metadata."""

    @staticmethod
    def _cut_options(text: str) -> str:
        """Drop the environment marker and any same-line pip options."""
        body = text.split(";", 1)[0]
        option = _INLINE_OPTION.search(body)
        if option is not None:
            body = body[: option.start()]
        return body.strip().rstrip("\\").strip()

    @staticmethod
    def _version_of(text: str) -> str:
        """The pinned version alone, with no trailing options or continuation."""
        return PypiManifest._cut_options(text)

    @staticmethod
    def _spec_of(text: str) -> str:
        """The version specifier alone, with no trailing options."""
        return PypiManifest._cut_options(text)

    @staticmethod
    def _in_requirements_dir(path: str) -> bool:
        """Is this file inside a `requirements/` directory, at any depth?

        `requirements/base.txt` at the root and `backend/requirements/base.txt` in a monorepo are
        the same file to a reader and have to be the same file here.
        """
        return "requirements" in PurePosixPath(path).parts[:-1]

    @staticmethod
    def _repository_of(project: dict[str, object]) -> str | None:
        """The source repository a `pyproject.toml` claims.

        PyPI has no single field for it: projects put the repository under
        `project.urls` with any of several keys, and which one is used varies by
        generator. The order here is most-specific first, so a project declaring
        both a homepage and a repository is read as claiming the repository.
        """
        urls = project.get("urls")
        if not isinstance(urls, dict):
            return None
        for key in ("Repository", "Source", "Source Code", "source", "repository", "Homepage"):
            value = urls.get(key)
            if isinstance(value, str) and value:
                return value
        return None


_PEP508_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]{0,200}[A-Za-z0-9])?)")
_EGG = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]{0,200})")


class PypiRequirement:
    """A PEP 508 requirement: `name[extra1,extra2] (>=1,<2) ; marker` or `name @ url ; marker`.

    Everything a requirement says is kept: the extras (each can pull in dependencies of its own),
    the environment marker (`sys_platform == "win32"`, `python_version < "3.11"`: the conditions
    under which it is installed at all), and a direct URL or VCS reference.
    """

    @staticmethod
    def parse(text: str) -> tuple[str, tuple[str, ...], str, str | None, bool] | None:
        """`(name, extras, spec, marker, is_url)`, or None when no name can be read."""
        body = text.strip()
        if not body or body.startswith("-"):
            return None
        marker: str | None = None
        # The marker follows the first `;`. In the URL form PEP 508 requires whitespace before it,
        # because a URL may itself contain `;`.
        at_url = re.search(r"\s@\s|^[^\s\[]+(?:\[[^\]]*\])?\s*@", body)
        if at_url:
            split = re.search(r"\s;", body)
            if split:
                body, marker = body[: split.start()], body[split.end() :]
        elif ";" in body:
            body, _, marker = body.partition(";")
        matched = _PEP508_NAME.match(body)
        if not matched:
            return None
        name = matched.group(1)
        rest = body[matched.end() :].lstrip()
        extras: tuple[str, ...] = ()
        if rest.startswith("["):
            close = rest.find("]")
            if close < 0:
                return None
            extras = tuple(e.strip() for e in rest[1:close].split(",") if e.strip())
            rest = rest[close + 1 :].lstrip()
        if rest.startswith("@"):
            return name, extras, rest[1:].strip(), (marker or "").strip() or None, True
        spec = PypiManifest._cut_options(rest).strip()
        if spec.startswith("(") and spec.endswith(")"):
            spec = spec[1:-1].strip()
        return name, extras, spec or "*", (marker or "").strip() or None, False

    @staticmethod
    def declared(text: str, scope: Scope, field_name: str) -> DeclaredDependency | None:
        parsed = PypiRequirement.parse(text)
        if parsed is None:
            return None
        name, extras, spec, marker, _ = parsed
        return DeclaredDependency(
            name=name,
            spec=spec,
            scope=scope,
            field_name=field_name,
            platform=(marker,) if marker else (),
            extras=extras,
        )

    @staticmethod
    def editable(target: str, field_name: str) -> DeclaredDependency:
        """`-e .`, `-e ./libs/x`, `-e git+https://host/repo.git@ref#egg=name`: installed in place.
        The name is the `#egg=` fragment when there is one, otherwise the directory's own."""
        text = target.strip()
        egg = _EGG.search(text)
        if egg:
            name = egg.group(1)
        else:
            name = text.rstrip("/").rpartition("/")[2] or "."
            name = "." if name in (".", "") else name
        return DeclaredDependency(
            name=name, spec=text, scope=Scope.RUNTIME, field_name=field_name, editable=True
        )


_NORMALIZE = re.compile(r"[-_.]+")

_REQUIREMENT_NAME = re.compile(r"[\s<>=!~;\[\(]")
"""The first character of a requirement string that cannot belong to a name."""
