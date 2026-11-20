"""The files a manifest of a tree names as the code that runs (`DeclaredEntries`), and what that decides for a cloned repository.

A repository is no published package, and its install, import and agent places are every file that could be one. The package verdict's
model cannot read a file over 1,000,000 bytes or past the first 50 of a place, so a padded entry file is invisible to it. For a published
package that is a gap; for a repository the gap is for the files a manifest names as an entry (an MCP server is very often scanned as
a clone), never for every file that could be one (the cordon repository's own history scan went incomplete on 24 files nothing runs).
Inert text: a few lines of JavaScript or Python and comment padding, never run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.engine.entries import DeclaredEntries
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from kits.padding import Padding

SERVER_JS = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";\n'
    'import { spawnSync } from "node:child_process";\n'
    'const server = new McpServer({ name: "probe", version: "1.0.0" });\n'
    'server.tool("run", "Runs a thing", {}, async () => { spawnSync("make", ["build"]); '
    'await fetch("https://t.example.invalid/ping"); return { content: [{ type: "text", text: "done" }] }; });\n'
    "await server.connect(new StdioServerTransport());\n"
)
SERVER_PY = (
    "from mcp.server.fastmcp import FastMCP\nimport subprocess\nimport requests\n\n"
    'mcp = FastMCP("probe")\n\n\n@mcp.tool()\ndef run(cmd: str) -> str:\n    """Runs a thing."""\n'
    '    requests.get("https://t.example.invalid/ping")\n    subprocess.run(["make", "build"], check=False)\n'
    '    return "done"\n\n\ndef main() -> None:\n    mcp.run()\n'
)


class Kit:
    @staticmethod
    def units(files: dict[str, str]) -> list[FileUnit]:
        return [
            FileUnit(content=FileContent.from_bytes(path, text.encode()))
            for path, text in files.items()
        ]

    @staticmethod
    def named(files: dict[str, str]) -> set[str]:
        return set(DeclaredEntries.of(Kit.units(files)))

    @staticmethod
    def blind_notes(tmp_path: Path, files: dict[str, str]) -> tuple[bool, list[str]]:
        for name, text in files.items():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        notes = [
            f.location.path
            for f in result.findings
            if "package verdict could not read" in f.message
        ]
        return result.content_complete, notes


class TestWhatAManifestNames:
    def test_package_json_main_bin_exports_and_scripts(self) -> None:
        manifest = json.dumps(
            {
                "main": "./lib/main.js",
                "bin": {"tool": "bin/tool.js"},
                "exports": {".": {"import": "./esm/index.mjs", "require": "./cjs/index.cjs"}},
                "scripts": {"start": "node server/start.js --port 80", "test": "mocha"},
            }
        )
        files = dict.fromkeys(
            [
                "lib/main.js",
                "bin/tool.js",
                "esm/index.mjs",
                "cjs/index.cjs",
                "server/start.js",
                "lib/other.js",
            ],
            "x\n",
        )
        assert Kit.named({"package.json": manifest, **files}) == {
            "lib/main.js",
            "bin/tool.js",
            "esm/index.mjs",
            "cjs/index.cjs",
            "server/start.js",
        }

    def test_a_manifest_names_files_relative_to_its_own_folder(self) -> None:
        files = {
            "sub/package.json": json.dumps({"main": "index.js"}),
            "sub/index.js": "x\n",
            "index.js": "x\n",
        }
        assert Kit.named(files) == {"sub/index.js"}

    def test_pyproject_scripts_name_a_module_file_or_package(self) -> None:
        toml = '[project]\nname = "p"\n[project.scripts]\np = "pkg.cli.main:run"\nq = "other:go"\n'
        files = {
            "pyproject.toml": toml,
            "pkg/cli/main.py": "x\n",
            "src/other/__init__.py": "x\n",
            "pkg/cli/unnamed.py": "x\n",
        }
        assert Kit.named(files) == {"pkg/cli/main.py", "src/other/__init__.py"}

    def test_setup_py_entry_points(self) -> None:
        setup = "setup(name='p', entry_points={'console_scripts': ['p = pkg.run:main']})\n"
        assert Kit.named({"setup.py": setup, "pkg/run.py": "x\n", "pkg/other.py": "x\n"}) == {
            "pkg/run.py"
        }

    def test_an_mcp_configuration_names_the_files_in_a_servers_arguments(self) -> None:
        config = json.dumps(
            {
                "mcpServers": {
                    "a": {"command": "node", "args": ["tools/server.js", "--flag"]},
                    "b": {"command": "uvx", "args": ["pkg"]},
                }
            }
        )
        files = {".cursor/mcp.json": config, "tools/server.js": "x\n", "tools/other.js": "x\n"}
        assert Kit.named(files) == {"tools/server.js"}

    def test_a_dockerfile_names_what_entrypoint_and_cmd_run(self) -> None:
        dockerfile = 'FROM node:20\nCOPY . /app\nRUN node build.js\nENTRYPOINT ["node", "app/serve.js"]\nCMD ["python", "run.py"]\n'
        files = {
            "Dockerfile": dockerfile,
            "app/serve.js": "x\n",
            "run.py": "x\n",
            "build.js": "x\n",
        }
        assert Kit.named(files) == {"app/serve.js", "run.py"}

    def test_a_dependency_and_a_file_nothing_names_are_not_named(self) -> None:
        files = {
            "node_modules/dep/package.json": json.dumps({"main": "i.js"}),
            "node_modules/dep/i.js": "x\n",
            "lib/free.js": "x\n",
        }
        assert Kit.named(files) == set()

    def test_a_manifest_that_does_not_parse_names_nothing(self) -> None:
        assert (
            Kit.named(
                {
                    "package.json": "{not json",
                    "index.js": "x\n",
                    "pyproject.toml": "= = =",
                    "mcp.json": "[",
                }
            )
            == set()
        )


class TestACloneIsIncompleteForTheEntryItNames:
    PADDING = 1_300_000

    @pytest.mark.parametrize(
        "files",
        [
            {
                "package.json": json.dumps(
                    {
                        "name": "p",
                        "version": "1.0.0",
                        "main": "server.js",
                        "type": "module",
                        "scripts": {"start": "node server.js"},
                        "dependencies": {"@modelcontextprotocol/sdk": "^1.17.0"},
                    }
                ),
                "server.js": Padding.lines(PADDING) + SERVER_JS,
            },
            {
                "pyproject.toml": '[project]\nname = "p"\nversion = "1.0.0"\n[project.scripts]\np = "server:main"\n',
                "server.py": Padding.lines(PADDING, "#") + SERVER_PY,
            },
        ],
        ids=["javascript", "python"],
    )
    def test_a_padded_entry_file_of_a_cloned_mcp_server_is_a_gap(
        self, tmp_path: Path, files: dict[str, str]
    ) -> None:
        complete, notes = Kit.blind_notes(tmp_path, files)
        assert not complete
        assert [n.rpartition("/")[2] for n in notes] == [
            next(k for k in files if k.startswith("server."))
        ]

    def test_the_same_padding_in_a_file_no_manifest_names_is_not(self, tmp_path: Path) -> None:
        manifest = json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"})
        files = {
            "package.json": manifest,
            "index.js": "module.exports = 1;\n",
            "server.js": Padding.lines(self.PADDING) + SERVER_JS,
        }
        complete, notes = Kit.blind_notes(tmp_path, files)
        assert notes == []
        assert complete

    def test_a_large_tree_of_files_that_could_be_entries_is_complete(self, tmp_path: Path) -> None:
        files = {f"agents/tool{index}.py": SERVER_PY for index in range(70)}
        complete, notes = Kit.blind_notes(tmp_path, files)
        assert notes == []
        assert complete
