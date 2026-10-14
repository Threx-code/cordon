"""The MCP-security benchmark reads each dataset's own layout into one row shape.

```
  dataset          laid out as                                        one unit is
  ──────────────   ────────────────────────────────────────────────   ──────────────────────────────
  mcptox           pure_tool.json + response_all.json                 one tool description
  mcp-variants     malicious-mcp-variants/<attack>/<server>/          one server directory
                   reference-mcp-servers/<category>/<server>/         (a repeat or an empty one: no)
  agentdefense     tool_poisoning/*.json, benign_baseline/*.json      one tools/call record
  mcpsafetybench   benchmark/configs/**/*.json, mcp/servers/<srv>/    one task that changes a server
  mcpsecbench      code/<server>.py                                   one server file
  cieveme          servers/ + targets/*.json                          servers/
```

Every directory here is built from placeholder text; no dataset is read.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bench"))

from mcp_poisoning import (
    AgentDefense,
    CieveMe,
    Loaded,
    McpPoisoningBench,
    McpSafetyBench,
    McpSecBench,
    McpTox,
    McpVariants,
)

PLACEHOLDER = "placeholder description"


class Layout:
    @staticmethod
    def write(path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    @classmethod
    def json(cls, path: Path, data: object) -> Path:
        return cls.write(path, json.dumps(data))

    @staticmethod
    def shape(row: dict) -> None:
        assert {"malicious", "dataset", "server", "name", "category"} <= set(row)
        assert ("description" in row) + ("path" in row) + ("code" in row) == 1


class TestMcpTox:
    def test_poisoned_and_legitimate_tools(self, tmp_path: Path) -> None:
        Layout.json(
            tmp_path / "pure_tool.json",
            [
                {
                    "0": {
                        "server_name": "s",
                        "tool_name": "t",
                        "tool_content": f" {PLACEHOLDER} ",
                        "security risk": "risk-a",
                        "paradigm": "p1",
                    }
                }
            ],
        )
        prompt = f"Tool: read\nDescription: {PLACEHOLDER}\nArguments: x\n"
        Layout.json(
            tmp_path / "response_all.json",
            {"servers": {"1": {"server_name": "s", "clean_system_promot": prompt * 2}}},
        )
        rows = McpTox.load(tmp_path).rows
        assert [(r["malicious"], r["name"], r["category"]) for r in rows] == [
            (True, "t", "risk-a"),
            (False, "read", ""),
        ]
        assert rows[0]["description"] == PLACEHOLDER
        for row in rows:
            Layout.shape(row)

    def test_the_rendered_server_parses_with_parameters(self) -> None:
        text = McpTox.server_file(
            "my-tool", 'a """quoted""" \\ text', {"url": "string"}, {"mode": "fast", "n": 2}
        )
        tree = ast.parse(text)
        tool = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
        assert tool.name == "my_tool"
        assert [a.arg for a in tool.args.args] == ["url", "mode", "n"]
        doc = ast.get_docstring(tool)
        assert doc is not None and '"""quoted"""' in doc and "url: string" in doc


class TestMcpVariants:
    def test_a_server_is_one_directory_below_its_attack_or_category(self, tmp_path: Path) -> None:
        bad = tmp_path / McpVariants.MALICIOUS
        good = tmp_path / McpVariants.REFERENCE
        Layout.write(bad / "Attack A" / "srv1" / "src" / "server.py", "# placeholder\n")
        (bad / "Attack A" / "empty-submodule").mkdir(parents=True)
        Layout.write(
            bad / "variant_name_mapping.csv",
            "attack_directory,final_impact_location,attack_unit,variant_index,"
            "original_server_name,labelled_variant_directory\n"
            "Attack A,Execution,AttackA,01,srv1,srv1\n",
        )
        Layout.write(good / "cat1" / "ref_abc1234_python" / "README.md", "placeholder\n")
        Layout.write(good / "cat2" / "ref_abc1234_python" / "README.md", "placeholder\n")
        Layout.write(good / "cat2" / "crawl_summary.json", "{}")
        loaded = McpVariants.load(tmp_path)
        assert [(r["malicious"], r["server"], r["category"]) for r in loaded.rows] == [
            (True, "srv1", "Attack A"),
            (False, "ref_abc1234_python", "cat1"),
        ]
        assert loaded.rows[0]["stage"] == "Execution"
        assert Path(loaded.rows[0]["path"]).name == "srv1"
        reasons = sorted(e["reason"] for e in loaded.excluded)
        assert len(reasons) == 2
        assert reasons[0].startswith("empty directory")
        assert reasons[1].startswith("the same server as cat1/")
        for row in loaded.rows:
            Layout.shape(row)


class TestAgentDefense:
    @staticmethod
    def record(rid: str, category: str, key: str, arguments: dict) -> dict:
        return {
            "id": rid,
            "category": category,
            "subcategory": "sub",
            "description": PLACEHOLDER,
            "metadata": {"tool_name": "tool_x"},
            key: {"method": "tools/call", "params": {"name": "tool_x", "arguments": arguments}},
        }

    def test_calls_on_both_sides_rendered_with_their_arguments(self, tmp_path: Path) -> None:
        record = self.record
        Layout.json(
            tmp_path / "tool_poisoning" / "tool_poisoning_attacks.json",
            [
                record("a1", "backdoored_tools", "mcp_request", {"action": "placeholder"}),
                record("a2", "backdoored_tools", "mcp_request", {"action": "placeholder"}),
            ],
        )
        Layout.json(
            tmp_path / "benign_baseline" / "benign_baseline.json",
            [record("b1", "normal_operations", "mcp_request", {"path": "./placeholder"})],
        )
        Layout.json(
            tmp_path / "benign_baseline" / "expanded_benign_operations.json",
            {"tests": [record("b2", "benign", "request", {"query": "placeholder"})]},
        )
        loaded = AgentDefense.load(tmp_path)
        assert [(r["malicious"], r["server"]) for r in loaded.rows] == [
            (True, "a1"),
            (False, "b1"),
            (False, "b2"),
        ]
        assert loaded.rows[0]["defaults"] == {"action": "placeholder"}
        assert [e["unit"] for e in loaded.excluded] == ["a2"]
        for row in loaded.rows:
            Layout.shape(row)


class TestMcpSafetyBench:
    def test_only_tasks_that_change_a_server_are_units(self, tmp_path: Path) -> None:
        configs = tmp_path / "mcpuniverse" / "benchmark" / "configs" / "test" / "domain"
        Layout.json(
            configs / "t1.json",
            {
                "category": "Stealth Attack",
                "attack_category": "Tool Poisoning-X",
                "mcp_server_modifications": [
                    {"tool_name": "nav", "modification_description": PLACEHOLDER}
                ],
            },
        )
        Layout.json(
            configs / "t2.json",
            {
                "category": "Disruption Attack",
                "attack_category": "Function Return Injection",
                "mcp_server_modifications": [
                    {"tool_name": "nav", "modification_return": "placeholder {preview}"}
                ],
            },
        )
        Layout.json(
            configs / "t3.json",
            {
                "category": "Disruption Attack",
                "attack_category": "Tool Shadowing",
                "mcp_server_additions": {
                    "tool_name": "extra",
                    "description": PLACEHOLDER,
                    "input_parameters": {"a": "string"},
                    "implementation_code": f'def extra(a: str):\n    """{PLACEHOLDER}"""\n'
                    "    return a",
                },
            },
        )
        Layout.json(
            configs / "t4.json",
            {
                "category": "Disruption Attack",
                "attack_category": "Rug Pull Attack",
                "mcp_server_update": {
                    "tool_name": "nav",
                    "implementation_code": "def nav(url: str):\n    return url",
                },
            },
        )
        Layout.json(
            configs / "t5.json", {"category": "Stealth Attack", "attack_category": "Replay"}
        )
        Layout.write(
            tmp_path / "mcpuniverse" / "mcp" / "servers" / "echo" / "server.py", "# placeholder\n"
        )
        loaded = McpSafetyBench.load(tmp_path)
        assert [(r["malicious"], r["category"]) for r in loaded.rows] == [
            (True, "Tool Poisoning-X"),
            (True, "Function Return Injection"),
            (True, "Tool Shadowing"),
            (True, "Rug Pull Attack"),
            (False, ""),
        ]
        for row in loaded.rows[:4]:
            tree = ast.parse(row["code"])
            assert any(isinstance(n, ast.FunctionDef) for n in tree.body)
        assert PLACEHOLDER in loaded.rows[0]["code"]
        assert [e["unit"] for e in loaded.excluded] == ["test/domain/t5.json"]
        for row in loaded.rows:
            Layout.shape(row)


class TestMcpSecBenchAndCieveMe:
    def test_each_server_file_is_a_unit_and_harness_files_are_not(self, tmp_path: Path) -> None:
        for name in ("maliciousadd.py", "addserver.py", "client.py", "mitm.py"):
            Layout.write(tmp_path / "code" / name, "# placeholder\n")
        loaded = McpSecBench.load(tmp_path)
        assert [(r["name"], r["malicious"]) for r in loaded.rows] == [
            ("maliciousadd.py", True),
            ("addserver.py", False),
        ]
        assert sorted(e["unit"] for e in loaded.excluded) == ["client.py", "mitm.py"]

    def test_the_demo_server_directory_is_the_unit(self, tmp_path: Path) -> None:
        Layout.write(tmp_path / "servers" / "vulnerable_demo_server.py", "# placeholder\n")
        Layout.json(tmp_path / "targets" / "vulnerable-demo.json", {})
        Layout.json(tmp_path / "targets" / "other-public.json", {})
        loaded = CieveMe.load(tmp_path)
        assert [(r["server"], Path(r["path"]).name) for r in loaded.rows] == [
            ("vulnerable-demo", "servers")
        ]
        assert [e["unit"] for e in loaded.excluded] == ["other-public.json"]


class TestRunAndSummary:
    def test_a_file_unit_is_scanned_alone_in_a_fresh_directory(self, tmp_path: Path) -> None:
        source = Layout.write(tmp_path / "code" / "srv.py", "# placeholder\n")
        Layout.write(tmp_path / "code" / "other.py", "# placeholder\n")
        work = tmp_path / "work"
        work.mkdir()
        target = McpPoisoningBench.materialise({"path": str(source)}, work)
        assert sorted(p.name for p in target.iterdir()) == ["srv.py"]
        row = {"name": "t", "description": PLACEHOLDER}
        rendered = McpPoisoningBench.materialise(row, tmp_path / "work")
        text = (rendered / "server.py").read_text(encoding="utf-8")
        assert PLACEHOLDER in text

    def test_timeouts_and_errors_are_listed_not_dropped(self) -> None:
        base = {"dataset": "d", "name": "n", "category": "c", "rules": [], "findings": None}
        rows = [
            {**base, "server": "a", "malicious": True, "status": "ok", "blocked": True},
            {**base, "server": "b", "malicious": True, "status": "timeout", "blocked": None},
            {**base, "server": "c", "malicious": False, "status": "error", "blocked": None},
            {**base, "server": "d", "malicious": False, "status": "ok", "blocked": False},
        ]
        for row in rows:
            row["flagged"] = row["blocked"]
        summary = McpPoisoningBench.summarise(rows)
        assert summary["units"]["malicious"] == 2 and summary["units"]["scanned"] == 2
        assert summary["units"]["timeouts"] == ["d:b:n"]
        assert [e["unit"] for e in summary["units"]["errors"]] == ["d:c:n"]
        assert summary["malicious"]["blocked"]["of"] == 1
        assert summary["benign"]["not_blocked"]["rate"] == 1.0

    def test_a_dependency_cve_alone_is_not_counted_as_catching_the_attack(self) -> None:
        cve = {"rule": "VULNERABLE.DEPENDENCY.KNOWN.001", "blocks": True}
        attack = {"rule": "SUSPECT.EXFIL.001", "blocks": True}
        note = {"rule": "SUSPECT.EXFIL.001", "blocks": False}
        assert not McpPoisoningBench.beyond_dependencies({"findings": [cve, note]})
        assert McpPoisoningBench.beyond_dependencies({"findings": [cve, attack]})
        assert not McpPoisoningBench.beyond_dependencies({"findings": None})

    def test_every_dataset_has_a_loader(self) -> None:
        assert sorted(McpPoisoningBench.LOADERS) == sorted(
            ["mcptox", "mcp-variants", "agentdefense", "mcpsafetybench", "mcpsecbench", "cieveme"]
        )
        assert isinstance(Loaded(), Loaded)
