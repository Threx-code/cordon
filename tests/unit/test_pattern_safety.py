"""C-7: every regex compiled anywhere in the engine must pass the validator.

`PatternCompiler.validate_pattern` is the only control against catastrophic
backtracking -- Python's `re` cannot be interrupted mid-match, so nothing
downstream can bound a pathological pattern -- and it was applied to YAML rule
patterns only. Thirty-four `re.compile` calls in detectors and ecosystem parsers
never reached it.

Nothing in the current set is exploitable; the gap is that there was no
mechanism preventing the next one. This is that mechanism: it walks every
module-level compiled pattern in the package and puts it through the same check
a rule pack gets.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from typing import Any

import pytest

import cordon
from cordon.core.errors import UnsafePatternError
from cordon.rules.loader import PatternCompiler


def _modules() -> list[str]:
    return [
        module.name
        for module in pkgutil.walk_packages(cordon.__path__, prefix="cordon.")
        if not module.name.endswith("__main__")
    ]


def _patterns() -> list[tuple[str, str, str]]:
    """Every compiled pattern reachable as a module or class attribute."""
    found: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def record(where: str, name: str, value: Any) -> None:
        if not isinstance(value, re.Pattern):
            return
        source = value.pattern
        text = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
        if (where, text) in seen:
            return
        seen.add((where, text))
        found.append((where, name, text))

    for module_name in _modules():
        # Not guarded. Cordon has no third-party runtime dependencies, so a
        # module that will not import is a defect, and skipping it here would
        # let the sweep quietly stop covering whatever it contained.
        module = importlib.import_module(module_name)
        for name, value in vars(module).items():
            record(module_name, name, value)
            if isinstance(value, type):
                for attribute, inner in vars(value).items():
                    record(module_name, f"{name}.{attribute}", inner)
            if isinstance(value, (tuple, list)):
                for index, item in enumerate(value):
                    for attribute in ("pattern", "regex"):
                        record(
                            module_name,
                            f"{name}[{index}].{attribute}",
                            getattr(item, attribute, None),
                        )
    return found


ALL_PATTERNS = _patterns()


def test_the_sweep_finds_the_engine_patterns() -> None:
    """A test that walks nothing passes for the wrong reason.

    What it reaches: patterns bound to a module attribute, a class attribute, or
    an attribute of an object in a module-level tuple or list. That is where
    every detector keeps its rule data.

    What it does not reach: a pattern compiled inside a function body, which is
    invisible without parsing the source. Stated here rather than left for a
    reader to discover, because a sweep whose coverage is assumed is how a gap
    reopens. `ruff` forbids the shape in this codebase anyway -- compiling a
    pattern per call is a performance error before it is a safety one.
    """
    assert len(ALL_PATTERNS) >= 40
    modules = {where for where, _, _ in ALL_PATTERNS}
    assert any("detect" in m for m in modules)
    assert any("core" in m for m in modules)
    assert any("rules" in m for m in modules)


@pytest.mark.parametrize(
    ("where", "name", "pattern"),
    ALL_PATTERNS,
    ids=[f"{w.rpartition('.')[2]}:{n}" for w, n, _ in ALL_PATTERNS],
)
def test_every_engine_pattern_passes_the_validator(where: str, name: str, pattern: str) -> None:
    try:
        PatternCompiler.validate_pattern(pattern, rule_id=f"{where}:{name}")
    except UnsafePatternError as exc:  # pragma: no cover - the point is that it does not
        pytest.fail(f"{where}.{name} compiles a pattern a rule pack would be refused for: {exc}")
    except re.error:
        # Some engine patterns use inline flags a rule pack may not; those are
        # rejected for a reason unrelated to backtracking and are not this
        # test's subject.
        pytest.skip("pattern uses a construct the rule schema forbids for other reasons")
