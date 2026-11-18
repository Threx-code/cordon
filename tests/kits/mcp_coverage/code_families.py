"""Writes the coverage fixtures of one technique family from its case table.

    python tests/kits/mcp_coverage/code_families.py mcp/<family> [mcp/<family> ...]

The source of every fixture is `corpus/coverage/mcp/<family>/cases.yaml`; the files under
`corpus/coverage/mcp/<family>/<sub-technique>/<way>/{positive,negative}/` are generated from it and are not edited by hand.
Each fixture is one small complete MCP server written with its way's official SDK (TypeScript: `McpServer`; Python:
FastMCP; Go: mcp-go; Rust: rmcp), with the manifest that makes it a package, and one tool whose body (or whose module
level) carries the sub-technique or its legitimate look-alike. Line 1 of every source file says what it is. Nothing here
runs a fixture: the scanner reads them.

Table format (`cases.yaml`):

    family: t5
    sub_techniques:
      - slug: http-post-literal-host
        positive: one line saying what the positive fixture does
        negative: one line saying what the legitimate look-alike does
        expect: {block: true}            # optional: {signal: <finding class>} where the technique is a signal only
        packages: {typescript: [nodemailer], python: [], go: [], rust: []}   # optional extra dependencies
        ways:
          typescript:
            positive: {imports: "...", top: "...", body: "..."}
            negative: {imports: "...", top: "...", body: "..."}
          python: ...   go: ...   rust: ...
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

import yaml

WAYS = ("typescript", "python", "go", "rust")
FILES = {"typescript": "server.ts", "python": "server.py", "go": "main.go", "rust": "main.rs"}


class Fixtures:
    @staticmethod
    def indented(text: str, prefix: str) -> str:
        lines = textwrap.dedent(text or "").strip("\n").splitlines()
        return "\n".join(prefix + line if line.strip() else line for line in lines)

    @classmethod
    def section(cls, text: str, prefix: str = "", before: str = "", after: str = "") -> str:
        body = cls.indented(text, prefix)
        return f"{before}{body}\n{after}" if body.strip() else ""

    @classmethod
    def typescript(cls, note: str, case: dict[str, str]) -> str:
        return (
            f"// {note}\n"
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            'import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";\n'
            'import { z } from "zod";\n'
            f"{cls.section(case.get('imports', ''))}"
            f"{cls.section(case.get('top', ''), before=chr(10))}"
            "\n"
            'const server = new McpServer({ name: "fixture-server", version: "1.0.0" });\n'
            "\n"
            'server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {\n'
            f"{cls.section(case.get('body', ''), '  ')}"
            '  return { content: [{ type: "text", text: "done" }] };\n'
            "});\n"
            "\n"
            "await server.connect(new StdioServerTransport());\n"
        )

    @classmethod
    def python(cls, note: str, case: dict[str, str]) -> str:
        return (
            f"# {note}\n"
            "from mcp.server.fastmcp import FastMCP\n"
            f"{cls.section(case.get('imports', ''))}"
            "\n"
            'mcp = FastMCP("fixture-server")\n'
            f"{cls.section(case.get('top', ''), before=chr(10))}"
            "\n"
            "@mcp.tool()\n"
            "def run_task(input: str) -> str:\n"
            '    """Runs one step of the documented task."""\n'
            f"{cls.section(case.get('body', ''), '    ')}"
            '    return "done"\n'
            "\n"
            "\n"
            'if __name__ == "__main__":\n'
            "    mcp.run()\n"
        )

    @classmethod
    def go(cls, note: str, case: dict[str, str]) -> str:
        imports = "".join(
            f"\t{line.strip()}\n"
            for line in textwrap.dedent(case.get("imports", "")).strip().splitlines()
            if line.strip()
        )
        return (
            f"// {note}\n"
            "package main\n"
            "\n"
            "import (\n"
            '\t"context"\n'
            f"{imports}"
            "\n"
            '\t"github.com/mark3labs/mcp-go/mcp"\n'
            '\t"github.com/mark3labs/mcp-go/server"\n'
            ")\n"
            f"{cls.section(case.get('top', ''), before=chr(10))}"
            "\n"
            "func runTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {\n"
            '\tinput, _ := req.Params.Arguments["input"].(string)\n'
            "\t_ = input\n"
            f"{cls.section(case.get('body', ''), chr(9))}"
            '\treturn mcp.NewToolResultText("done"), nil\n'
            "}\n"
            "\n"
            "func main() {\n"
            '\ts := server.NewMCPServer("fixture-server", "1.0.0")\n'
            '\ts.AddTool(mcp.NewTool("run_task", mcp.WithDescription("Runs one step of the documented task"), mcp.WithString("input")), runTask)\n'
            "\t_ = server.ServeStdio(s)\n"
            "}\n"
        )

    @classmethod
    def rust(cls, note: str, case: dict[str, str]) -> str:
        return (
            f"// {note}\n"
            "use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};\n"
            f"{cls.section(case.get('imports', ''))}"
            "\n"
            "#[derive(Clone)]\n"
            "struct FixtureServer;\n"
            f"{cls.section(case.get('top', ''), before=chr(10))}"
            "\n"
            "#[tool(tool_box)]\n"
            "impl FixtureServer {\n"
            '    #[tool(description = "Runs one step of the documented task")]\n'
            "    async fn run_task(&self, #[tool(param)] input: String) -> String {\n"
            "        let _ = &input;\n"
            f"{cls.section(case.get('body', ''), '        ')}"
            '        "done".to_string()\n'
            "    }\n"
            "}\n"
            "\n"
            "#[tool(tool_box)]\n"
            "impl ServerHandler for FixtureServer {}\n"
            "\n"
            "#[tokio::main]\n"
            "async fn main() -> Result<(), Box<dyn std::error::Error>> {\n"
            "    let service = FixtureServer.serve(stdio()).await?;\n"
            "    service.waiting().await?;\n"
            "    Ok(())\n"
            "}\n"
        )

    @staticmethod
    def manifest(way: str, extra: list[str]) -> tuple[str, str]:
        """(file name, text) of the minimal manifest of a way, with the SDK dependency and any extra ones."""
        if way == "typescript":
            deps = [
                '"@modelcontextprotocol/sdk": "^1.0.0"',
                '"zod": "^3.23.0"',
                *(f'"{d}": "*"' for d in extra),
            ]
            body = ",\n    ".join(deps)
            return "package.json", (
                '{\n  "name": "fixture-server",\n  "version": "1.0.0",\n  "type": "module",\n'
                f'  "dependencies": {{\n    {body}\n  }}\n}}\n'
            )
        if way == "python":
            listed = ", ".join(f'"{d}"' for d in ["mcp>=1.0", *extra])
            return "pyproject.toml", (
                f'[project]\nname = "fixture-server"\nversion = "1.0.0"\ndependencies = [{listed}]\n'
            )
        if way == "go":
            requires = "".join(f"\t{d} v0.0.0\n" for d in ["github.com/mark3labs/mcp-go", *extra])
            return "go.mod", f"module fixture/server\n\ngo 1.22\n\nrequire (\n{requires})\n"
        crates = "\n".join(
            [
                'rmcp = "0.1"',
                'tokio = { version = "1", features = ["full"] }',
                *(f'{d} = "*"' for d in extra),
            ]
        )
        return (
            "Cargo.toml",
            f'[package]\nname = "fixture-server"\nversion = "1.0.0"\nedition = "2021"\n\n[dependencies]\n{crates}\n',
        )

    @classmethod
    def write(cls, root: Path, family_dir: str) -> int:
        table = yaml.safe_load(
            (root / "corpus" / "coverage" / family_dir / "cases.yaml").read_text(encoding="utf-8")
        )
        written = 0
        for sub in table["sub_techniques"]:
            expect = sub.get("expect") or {"block": True}
            packages: dict[str, list[str]] = sub.get("packages") or {}
            for way in WAYS:
                way_dir = root / "corpus" / "coverage" / family_dir / sub["slug"] / way
                for kind in ("positive", "negative"):
                    case: dict[str, Any] = sub["ways"][way][kind]
                    directory = way_dir / kind
                    directory.mkdir(parents=True, exist_ok=True)
                    note = str(sub[kind]).strip().rstrip(".")
                    render = getattr(cls, way)
                    (directory / FILES[way]).write_text(render(note, case), encoding="utf-8")
                    name, text = cls.manifest(way, packages.get(way, []))
                    (directory / name).write_text(text, encoding="utf-8")
                    written += 2
                positive = (
                    "{"
                    + ", ".join(
                        f"{k}: {str(v).lower() if isinstance(v, bool) else v}"
                        for k, v in expect.items()
                    )
                    + "}"
                )
                (way_dir / "expect.yaml").write_text(
                    f"positive: {positive}\nnegative: {{block: false}}\n", encoding="utf-8"
                )
                written += 1
        return written


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    total = 0
    for family_dir in sys.argv[1:]:
        count = Fixtures.write(root, family_dir)
        total += count
        print(f"{family_dir}: {count} files")
    print(f"total {total} files")


if __name__ == "__main__":
    main()
