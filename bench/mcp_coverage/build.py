"""Writes the MCP coverage fixtures under corpus/coverage/mcp from the case tables (one table per group of families).

    PYTHONPATH=src:tests:. python -m bench.mcp_coverage.build

For every case and every way it writes `positive/` and `negative/` (the server file, its manifest, any extra files) and
`expect.yaml`, plus one `cases.yaml` per family listing what each case is. Re-running rewrites the same files.
"""

from __future__ import annotations

import re
from pathlib import Path

from bench.mcp_coverage import families_access
from bench.mcp_coverage.templates import FILE, MANIFEST, SKELETON, WAYS, indent
from support import ROOT

OUT = ROOT / "corpus" / "coverage" / "mcp"
ARG_NAMES = ("recipient", "amount", "spender", "text", "host")


class Build:
    @staticmethod
    def args(way: str, body: str) -> tuple[str, str]:
        used = [a for a in ARG_NAMES if re.search(rf"\b{a}\b", body)]
        if way == "typescript":
            return ", ".join(f"{a}: z.string()" for a in used), ", ".join(used)
        if way == "python":
            return "", ", ".join(f"{a}: str" for a in used)
        if way == "go":
            return "".join(f', mcp.WithString("{a}")' for a in used), ""
        return "", ""

    @staticmethod
    def server(way: str, comment: str, body: str) -> str:
        schema, args = Build.args(way, body)
        return SKELETON[way].format(
            comment=comment,
            toplevel="",
            tool="summarise",
            description="Summarises the notes in the workspace",
            schema=schema,
            args=args,
            body=indent(way, body),
        )

    @staticmethod
    def side(target: Path, way: str, comment: str, body: str, deps, files: dict[str, str]) -> None:
        target.mkdir(parents=True, exist_ok=True)
        (target / FILE[way]).write_text(Build.server(way, comment, body), encoding="utf-8")
        name, render = MANIFEST[way]
        default = [] if way == "python" else {}
        (target / name).write_text(render(deps.get(way, default), None), encoding="utf-8")
        for rel, text in files.get(way, {}).items():
            path = target / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    @staticmethod
    def main() -> int:
        written, families = 0, {}
        for case in families_access.CASES:
            for way in WAYS:
                base = OUT / case["family"] / case["slug"] / way
                Build.side(
                    base / "positive",
                    way,
                    case["pos_comment"],
                    case["pos"][way],
                    case["deps"],
                    case["files"],
                )
                Build.side(
                    base / "negative",
                    way,
                    case["neg_comment"],
                    case["neg"][way],
                    case["neg_deps"],
                    case["neg_files"],
                )
                by = f", by: {case['by']}" if case.get("by") else ""
                positive = (
                    f"{{signal: {case['signal']}{by}}}" if case.get("signal") else "{block: true}"
                )
                (base / "expect.yaml").write_text(
                    f"positive: {positive}\nnegative: {{block: false}}\n", encoding="utf-8"
                )
                written += 1
            families.setdefault(case["family"], []).append(case)
        for family, cases in families.items():
            lines = ["cases:"]
            for c in cases:
                lines += [
                    f"  - slug: {c['slug']}",
                    f'    positive: "{c["pos_comment"]}"',
                    f'    negative: "{c["neg_comment"]}"',
                ]
            (OUT / family / "cases.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(
            f"cases {len(families_access.CASES)}; case directories {written}; fixtures {written * 2}"
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(Build.main())
