"""Whether a vulnerable dependency is actually reached from first-party code.

The single biggest complaint about vulnerability scanners is noise: a report
lists a CVE in a package three levels down that the project never calls, at the
same severity as one in a function it invokes on every request. Reachability is
the answer, and this is its first, coarsest tier -- import reachability: is the
flagged package imported by the code in this repository at all?

Two rules keep it honest.

It annotates, it never suppresses. A finding is not removed for being
unreached; its severity is lowered and it is tagged, so a team can gate on
"reached only" while the unreached ones stay in the report where a reviewer can
still see them. Silently dropping a finding on a reachability guess is the exact
"looks clean but was not looked at" failure this project is built against.

Unknown is not unreached. Import reachability cannot see a dynamic import, a
package imported under a name it does not publish, or a path that runs through a
dependency rather than through first-party code. So the only finding it lowers
is one on a TRANSITIVE dependency that first-party code does not import -- a
package pulled in by something else and not named here. A direct dependency not
seen imported is left UNKNOWN, not lowered, because the import may be dynamic or
renamed. And this applies to a vulnerability, never to a known-malicious
package: a compromised release must not be installed whether or not it is
called, so its severity does not move.

The precise tier -- is the vulnerable *symbol* on a call path -- builds on the
`AstProvider` call resolution and is a later layer; this one needs only the set
of imported module names, which is cheap.
"""

from __future__ import annotations

import ast
import enum
import re
from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.core.models import Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.core.models import Dependency, Finding
    from cordon_scanner.detect.base import Unit

VULNERABLE_RULE = "VULNERABLE.DEPENDENCY.KNOWN.001"


class Reachability(enum.StrEnum):
    IMPORTED = "imported"
    NOT_IMPORTED = "not_imported"
    UNKNOWN = "unknown"


#: PyPI distribution names whose import name differs. Without these a real import
#: would be missed and the finding wrongly lowered. Small and common on purpose:
#: an unlisted mismatch falls to UNKNOWN (not lowered), which is the safe
#: direction.
_IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "beautifulsoup4": ("bs4",),
    "pillow": ("PIL",),
    "pyyaml": ("yaml",),
    "python-dateutil": ("dateutil",),
    "scikit-learn": ("sklearn",),
    "msgpack-python": ("msgpack",),
    "opencv-python": ("cv2",),
    "protobuf": ("google",),
    "setuptools": ("setuptools", "pkg_resources"),
}

_SEVERITY_DOWN: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
    Severity.INFO: Severity.INFO,
}


def annotate(
    findings: list[Finding],
    units: Sequence[Unit],
    dependencies: tuple[Dependency, ...],
) -> list[Finding]:
    """Return the findings with vulnerability findings annotated by reachability."""
    imports = collect_imports(units)
    by_purl = {d.purl: d for d in dependencies}
    out: list[Finding] = []
    for finding in findings:
        dep = by_purl.get(finding.location.package or "")
        if finding.rule_id == VULNERABLE_RULE and dep is not None:
            out.append(_annotated(finding, _verdict(dep, imports)))
        else:
            out.append(finding)
    return out


def collect_imports(units: Sequence[Unit]) -> set[str]:
    """Every module name imported by the first-party source in the scan."""
    from cordon_scanner.detect.base import FileUnit

    imports: set[str] = set()
    for unit in units:
        if not isinstance(unit, FileUnit):
            continue
        text = unit.content.text
        if unit.language == "python":
            imports |= _python_imports(text)
        elif unit.language in ("javascript", "typescript"):
            imports |= _js_imports(text)
    return imports


def _verdict(dep: Dependency, imports: set[str]) -> Reachability:
    candidates = _import_candidates(dep.name)
    if candidates & imports:
        return Reachability.IMPORTED
    # Not imported. Only a transitive dependency is lowered: a direct one the
    # code does not appear to import may still import it dynamically or under a
    # different name, which import reachability cannot rule out.
    if not dep.direct:
        return Reachability.NOT_IMPORTED
    return Reachability.UNKNOWN


def _import_candidates(name: str) -> set[str]:
    normalized = name.lower().replace("_", "-")
    candidates = {name, normalized, normalized.replace("-", "_")}
    candidates |= set(_IMPORT_ALIASES.get(normalized, ()))
    # A scoped npm package imports under its full `@scope/name`; an unscoped one
    # under its name. Its subpaths (`lodash/fp`) import the package, so the bare
    # name covers them.
    return candidates


def _annotated(finding: Finding, verdict: Reachability) -> Finding:
    note = {
        Reachability.IMPORTED: (
            " Reachability: this package is imported by first-party code in the scan."
        ),
        Reachability.NOT_IMPORTED: (
            " Reachability: this transitive dependency is not imported by first-party code, "
            "so it is unlikely to be reached -- an import-level check, not a call-graph proof, "
            "so it is lowered rather than dropped."
        ),
        Reachability.UNKNOWN: (
            " Reachability: could not be determined (a direct dependency not seen imported may "
            "be loaded dynamically or under another name), so severity is unchanged."
        ),
    }[verdict]

    severity = finding.severity
    if verdict is Reachability.NOT_IMPORTED:
        severity = _SEVERITY_DOWN[finding.severity]

    metadata = (*finding.evidence.metadata, ("reachability", verdict.value))
    return replace(
        finding,
        severity=severity,
        message=finding.message + note,
        evidence=replace(finding.evidence, metadata=metadata),
    )


def _python_imports(text: str) -> set[str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module.split(".", 1)[0])
    return modules


_JS_IMPORT = re.compile(
    r"""(?:require\s*\(\s*|from\s+|import\s+)['"]([^'"]{1,200})['"]""",
)


def _js_imports(text: str) -> set[str]:
    modules: set[str] = set()
    for match in _JS_IMPORT.finditer(text):
        spec = match.group(1)
        if spec.startswith("."):
            continue  # a relative path is first-party, not a dependency
        parts = spec.split("/")
        # `@scope/name/sub` -> `@scope/name`; `lodash/fp` -> `lodash`.
        modules.add("/".join(parts[:2]) if spec.startswith("@") else parts[0])
    return modules


__all__ = ["Reachability", "annotate", "collect_imports"]
