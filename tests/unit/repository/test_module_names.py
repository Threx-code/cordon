"""No module binds one name twice at its top level.

The second binding wins at import, silently: `detect/agents/agent_intent.py` once defined
`_LOCAL_HOST` as a bare-host pattern and then again as a URL pattern, so the checks written for the
first read the second, and every local host looked like somewhere data leaves to (review 98,
2026-10-20). A name means one thing; give the other a name of its own.
"""

from __future__ import annotations

import ast
import collections

from support import ROOT as REPO


class TestModuleNames:
    def test_no_top_level_name_is_assigned_twice(self) -> None:
        twice = []
        for path in sorted((REPO / "src").rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            seen: collections.Counter[str] = collections.Counter()
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(node, ast.Assign):
                    seen.update(t.id for t in node.targets if isinstance(t, ast.Name))
                elif (
                    isinstance(node, ast.AnnAssign)
                    and node.value is not None
                    and isinstance(node.target, ast.Name)
                ):
                    seen[node.target.id] += 1
            rel = path.relative_to(REPO).as_posix()
            twice += [f"{rel}: {name}" for name, n in seen.items() if n > 1 and name != "__all__"]
        assert not twice, twice
