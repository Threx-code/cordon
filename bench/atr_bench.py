#!/usr/bin/env python3
"""Cordon against every test case in the Agent Threat Rules (ATR) catalogue.

ATR (https://github.com/Agent-Threat-Rule/agent-threat-rules, MIT) is the open catalogue of AI
agent threats: each rule carries the attack text it must catch (true positives), the benign text
it must not (true negatives), and evasions. ATR rules watch live agent traffic. Cordon reads
repositories, so each test case is planted where text of that kind reaches an agent from a
repository, on the scan path the rule declares (`tags.scan_target`), as ATR's own engine and
specification (section 5.2) evaluate it:

    text, rule for SKILL.md files   -> agent instruction files and a skill
      (scan_target skill, both or none)
    text, rule for MCP traffic      -> a tool in the repository's own MCP server (Node, Python)
      (scan_target mcp, both, or an event type such as llm_io)
    tool_description, tool_response,
    tool_name                       -> a tool in the repository's own MCP server
    tool_args, tool_call commands   -> an agent hook and an MCP launch command
    agent_output                    -> out of scope: text the model writes is not in a repository
    runtime rules                   -> out of scope: scan_target runtime, and agent traces and
                                       behaviour over time, describe a running agent, not a file

ATR's engine runs only `skill` and `both` rules on a SKILL.md file; its own measurement of letting
the others through there was 265 benign skills flagged instead of 1, with no recall gained.
Planting an MCP-traffic rule's text only in a CLAUDE.md would test it where its authors say it
must not run.

    python bench/atr_bench.py --atr /path/to/agent-threat-rules [--json out.json] [--workers 6]

A planted attack is DETECTED when the scan reports something at MEDIUM or above that the same
carrier holding harmless text does not; a planted benign text is CLEAN when it adds nothing at
MEDIUM or above. A case counts once, by its best carrier for an attack and its worst for benign
text: an attack is caught if any place it can live catches it, and benign text is clean only if
no place it can live raises an alarm.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

HARMLESS = "Use four spaces for indentation and run the tests before committing."


class AtrCarriers:
    """Where each kind of ATR test text reaches an agent from a repository."""

    @staticmethod
    def _md(text: str) -> str:
        return f"# Project guide\n\n{HARMLESS}\n\n{text}\n"

    @staticmethod
    def _settings_hook(command: str) -> dict[str, str]:
        return {
            ".claude/settings.json": json.dumps(
                {
                    "hooks": {
                        "PostToolUse": [
                            {"matcher": "*", "hooks": [{"type": "command", "command": command}]}
                        ]
                    }
                },
                indent=2,
            )
        }

    @staticmethod
    def _mcp_args(command: str) -> dict[str, str]:
        return {
            ".mcp.json": json.dumps(
                {"mcpServers": {"helper": {"command": "sh", "args": ["-c", command]}}}, indent=2
            )
        }

    @staticmethod
    def _node_tool(name: str, description: str) -> dict[str, str]:
        return {
            ".mcp.json": json.dumps(
                {"mcpServers": {"notes": {"command": "node", "args": ["mcp/server.js"]}}}
            ),
            "mcp/server.js": (
                'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n\n'
                'const server = new McpServer({ name: "notes", version: "1.0.0" });\n\n'
                f"server.tool({{\n  name: {json.dumps(name)},\n  description: {json.dumps(description)},\n"
                '  handler: async () => ({ content: [{ type: "text", text: "ok" }] }),\n});\n'
            ),
        }

    @staticmethod
    def _python_tool(name: str, description: str) -> dict[str, str]:
        safe = description.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
        ident = "".join(c if c.isalnum() else "_" for c in name) or "tool"
        if not ident[0].isalpha():
            ident = "t_" + ident
        return {
            ".mcp.json": json.dumps(
                {"mcpServers": {"notes": {"command": "python", "args": ["mcp/server.py"]}}}
            ),
            "mcp/server.py": (
                "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP('notes')\n\n\n"
                f'@mcp.tool()\ndef {ident}(text: str) -> str:\n    """{safe}"""\n    return "ok"\n'
            ),
        }


TEXT_CARRIERS: dict[str, Callable[[str], dict[str, str]]] = {
    "CLAUDE.md": lambda t: {"CLAUDE.md": AtrCarriers._md(t)},
    "AGENTS.md": lambda t: {"AGENTS.md": AtrCarriers._md(t)},
    "cursor rule": lambda t: {
        ".cursor/rules/project.mdc": "---\nalwaysApply: true\n---\n\n" + AtrCarriers._md(t)
    },
    "copilot-instructions": lambda t: {".github/copilot-instructions.md": AtrCarriers._md(t)},
    "skill": lambda t: {
        ".claude/skills/helper/SKILL.md": "---\nname: helper\ndescription: Helper\n---\n\n"
        + AtrCarriers._md(t)
    },
}
TOOL_CARRIERS: dict[str, Callable[[str, str], dict[str, str]]] = {
    "mcp tool, node": AtrCarriers._node_tool,
    "mcp tool, python": AtrCarriers._python_tool,
}
COMMAND_CARRIERS: dict[str, Callable[[str], dict[str, str]]] = {
    "agent hook": AtrCarriers._settings_hook,
    "mcp launch": AtrCarriers._mcp_args,
}


@dataclass
class TestCase:
    rule: str
    category: str
    kind: str  # attack | benign | evasion
    channel: str
    text: str
    tool_name: str = ""
    target: str = ""
    """The rule's `scan_target`: `skill`, `both`, `mcp`, an event type, or empty for all paths."""
    carriers: dict[str, dict[str, str]] = field(default_factory=dict)


class AtrBench:
    """Plants every ATR test case, scans it, and scores detection and precision."""

    @staticmethod
    def _command_of(args: Any) -> str:
        """The shell command inside tool arguments, when there is one."""
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                return args
        if isinstance(args, dict):
            for key in ("command", "cmd", "script", "code", "shell"):
                if isinstance(args.get(key), str):
                    return str(args[key])
            return json.dumps(args)
        return str(args)

    @staticmethod
    def load(atr: Path) -> tuple[list[TestCase], Counter[str]]:
        cases: list[TestCase] = []
        skipped: Counter[str] = Counter()
        for path in sorted((atr / "rules").rglob("*.yaml")):
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                skipped["unparseable rule"] += 1
                continue
            if not isinstance(rule, dict) or "id" not in rule or rule.get("status") == "deprecated":
                continue
            category = (rule.get("tags") or {}).get("category") or path.parent.name
            target = str((rule.get("tags") or {}).get("scan_target") or "")
            source = str((rule.get("agent_source") or {}).get("type") or "")
            runtime = target == "runtime" or source in ("agent_trace", "agent_behavior")
            # A bare `input` goes to the field the rule reads, as ATR's own harness feeds it.
            fields = [
                str(c.get("field"))
                for c in (rule.get("detection") or {}).get("conditions") or ()
                if isinstance(c, dict)
            ]
            home = next((f for f in fields if f in _PLANTABLE), "content")
            tests = rule.get("test_cases") or {}
            for kind, key in (
                ("attack", "true_positives"),
                ("benign", "true_negatives"),
                ("evasion", "evasion_tests"),
            ):
                for raw in tests.get(key) or ():
                    if not isinstance(raw, dict):
                        continue
                    if kind == "evasion" and raw.get("expected") not in (None, "triggered"):
                        # An evasion the rule documents as getting past it is still an attack.
                        pass
                    case = AtrBench._case(rule["id"], category, kind, raw, home)
                    if case is None:
                        skipped[f"{kind}: no plantable text"] += 1
                        continue
                    if case.channel == "agent_output":
                        skipped[f"{kind}: agent output (out of scope)"] += 1
                        continue
                    if runtime:
                        skipped[f"{kind}: runtime rule (out of scope)"] += 1
                        continue
                    case.target = target
                    cases.append(case)
        return cases, skipped

    @staticmethod
    def _case(
        rule: str, category: str, kind: str, raw: dict[str, Any], home: str = "content"
    ) -> TestCase | None:
        value = raw.get("input")
        if isinstance(value, dict):
            raw = {**raw, **value}
            if isinstance(value.get("response"), str):
                raw.setdefault("tool_response", value["response"])
            value = None
        for channel in (
            "tool_description",
            "tool_response",
            "content",
            "user_input",
            "agent_output",
        ):
            if isinstance(raw.get(channel), str):
                return TestCase(
                    rule, category, kind, channel, raw[channel], str(raw.get("tool_name") or "")
                )
        if raw.get("tool_args") is not None or isinstance(raw.get("tool_call"), dict):
            args = raw.get("tool_args")
            if args is None:
                args = raw["tool_call"].get("args") or raw["tool_call"].get("arguments")
            name = str(raw.get("tool_name") or (raw.get("tool_call") or {}).get("name") or "")
            return TestCase(rule, category, kind, "tool_args", AtrBench._command_of(args), name)
        if isinstance(raw.get("tool_name"), str):
            return TestCase(rule, category, kind, "tool_name", "", raw["tool_name"])
        if isinstance(value, str):
            if home == "tool_name":
                return TestCase(rule, category, kind, "tool_name", "", value)
            if home == "tool_args":
                return TestCase(rule, category, kind, "tool_args", AtrBench._command_of(value))
            return TestCase(rule, category, kind, home, value)
        return None

    @staticmethod
    def plant(case: TestCase) -> None:
        if case.channel in ("tool_description", "tool_response", "tool_name"):
            name = case.tool_name or "save_note"
            description = case.text or "Saves a note."
            case.carriers = {
                label: make(name, description) for label, make in TOOL_CARRIERS.items()
            }
        elif case.channel == "tool_args":
            case.carriers = {label: make(case.text) for label, make in COMMAND_CARRIERS.items()}
        else:
            static = case.target in ("", "skill", "both")
            mcp = case.target != "skill"
            if static:
                case.carriers = {label: make(case.text) for label, make in TEXT_CARRIERS.items()}
            if mcp:
                name = case.tool_name or "save_note"
                case.carriers |= {
                    label: make(name, case.text) for label, make in TOOL_CARRIERS.items()
                }

    @staticmethod
    def _scan(files: dict[str, str]) -> list[str]:
        global _SCANNER
        if _SCANNER is None:
            from cordon_scanner import Scanner
            from cordon_scanner.core.config import Config

            _SCANNER = Scanner(Config.default().with_overrides(use_cache=False))
        with tempfile.TemporaryDirectory(prefix="atr-") as work:
            root = Path(work)
            for rel, body in files.items():
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8", errors="surrogatepass")
            report = _SCANNER.scan(root)
        return sorted(
            {
                f"{f.rule_id}/{f.severity.name}"
                for f in report.findings
                if f.severity.name in ("MEDIUM", "HIGH", "CRITICAL")
                and not f.rule_id.startswith(("OPERATIONAL.", "POLICY.COVERAGE"))
            }
        )

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument(
            "--atr", type=Path, required=True, help="a checkout of agent-threat-rules"
        )
        parser.add_argument("--workers", type=int, default=6)
        parser.add_argument("--json", type=Path)
        parser.add_argument(
            "--misses", type=int, default=0, help="print up to N wrong answers per kind"
        )
        args = parser.parse_args()

        cases, skipped = AtrBench.load(args.atr)
        for case in cases:
            AtrBench.plant(case)

        # What each carrier reports holding harmless text: never credited to a planted case.
        baseline_jobs = {label: make(HARMLESS) for label, make in TEXT_CARRIERS.items()}
        baseline_jobs |= {
            label: make("save_note", "Saves a note.") for label, make in TOOL_CARRIERS.items()
        }
        # An unfamiliar command, so each carrier's own "a hook or launch exists" finding is background
        # and only what the planted text adds is credited.
        baseline_jobs |= {
            label: make("acme-sync --once") for label, make in COMMAND_CARRIERS.items()
        }

        jobs: list[dict[str, str]] = list(baseline_jobs.values())
        index: list[tuple[int, str]] = []
        for n, case in enumerate(cases):
            for label, files in case.carriers.items():
                jobs.append(files)
                index.append((n, label))
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(AtrBench._scan, jobs, chunksize=32))
        background = {label: set(results[i]) for i, label in enumerate(baseline_jobs)}
        per_case: dict[int, dict[str, list[str]]] = defaultdict(dict)
        for (n, label), rules in zip(index, results[len(baseline_jobs) :], strict=True):
            per_case[n][label] = [r for r in rules if r not in background[label]]

        rows = []
        for n, case in enumerate(cases):
            reported = per_case[n]
            correct = (
                not any(reported.values()) if case.kind == "benign" else any(reported.values())
            )
            rows.append(
                {
                    "rule": case.rule,
                    "category": case.category,
                    "kind": case.kind,
                    "channel": case.channel,
                    "correct": correct,
                    "reported": reported,
                    "text": case.text[:300],
                }
            )

        def rate(selected: list[dict[str, Any]]) -> str:
            if not selected:
                return "-"
            ok = sum(1 for r in selected if r["correct"])
            return f"{ok}/{len(selected)} ({ok / len(selected):.1%})"

        print(f"ATR test cases planted: {len(cases)}  (skipped: {dict(skipped)})")
        for kind, label in (
            ("attack", "attacks detected"),
            ("evasion", "evasions detected"),
            ("benign", "benign left clean"),
        ):
            print(f"  {label:20} {rate([r for r in rows if r['kind'] == kind])}")
        print("\nBy ATR category (attacks detected | benign clean)")
        for category in sorted({r["category"] for r in rows}):
            mine = [r for r in rows if r["category"] == category]
            print(
                f"  {category:22} {rate([r for r in mine if r['kind'] != 'benign']):>22} | "
                f"{rate([r for r in mine if r['kind'] == 'benign'])}"
            )
        print("\nBy channel (attacks detected | benign clean)")
        for channel in sorted({r["channel"] for r in rows}):
            mine = [r for r in rows if r["channel"] == channel]
            print(
                f"  {channel:22} {rate([r for r in mine if r['kind'] != 'benign']):>22} | "
                f"{rate([r for r in mine if r['kind'] == 'benign'])}"
            )
        if args.misses:
            for kind in ("attack", "evasion", "benign"):
                wrong = [r for r in rows if r["kind"] == kind and not r["correct"]][: args.misses]
                print(f"\nWrong: {kind}")
                for r in wrong:
                    print(
                        f"  {r['rule']} [{r['category']}/{r['channel']}] {r['text'][:140]!r} {r['reported'] if kind == 'benign' else ''}"
                    )
        if args.json:
            args.json.write_text(json.dumps(rows, indent=1))
        return 0


_PLANTABLE = (
    "tool_description",
    "tool_response",
    "tool_name",
    "tool_args",
    "content",
    "user_input",
)


_SCANNER: Any = None


if __name__ == "__main__":
    sys.exit(AtrBench.main())
