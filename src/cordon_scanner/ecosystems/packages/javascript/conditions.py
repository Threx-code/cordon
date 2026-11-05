"""What an npm-family lockfile entry says it installs on: its `os`, `cpu`, `libc` and `engines`
conditions. Read by npm's, pnpm's and bun's lockfiles alike, so it sits below all three."""

from __future__ import annotations

from typing import Any


class NpmConditions:
    @staticmethod
    def platform(meta: dict[str, Any]) -> tuple[str, ...]:
        """`os`, `cpu` and `libc` as conditions: `os: darwin`, `cpu: !arm`."""
        out: list[str] = []
        for field in ("os", "cpu", "libc"):
            values = meta.get(field)
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                listed = [str(v) for v in values if isinstance(v, (str, int))]
                if listed:
                    out.append(f"{field}: {', '.join(listed)}")
        engines = meta.get("engines")
        if isinstance(engines, dict) and isinstance(engines.get("node"), str):
            out.append(f"node: {engines['node']}")
        return tuple(out)
