#!/usr/bin/env python3
"""Cordon on six public MCP-security datasets: poisoned tools, malicious servers, and the benign side.

```
  dataset (commit)          unit                                     malicious          benign
  ───────────────────────   ──────────────────────────────────────   ────────────────   ────────────────────
  mcptox (f85189f)          one tool description, rendered           pure_tool.json     the same servers'
                                                                                        legitimate tools
  mcp-variants (e8303ec)    one server directory                     <attack>/<srv>/    reference-mcp-servers
                                                                                        /<category>/<srv>/
  agentdefense (b5dfdf3)    one tools/call record, rendered          tool_poisoning/    benign_baseline/
  mcpsafetybench (7872437)  one task's server-side change, rendered  configs/test/      mcp/servers/<srv>/
  mcpsecbench (7612c5a)     one server file, alone in a directory    code/*.py          code/*.py
  cieveme (b894356)         servers/ (one deliberately broken one)   servers/           (none shipped)
        │
        ▼   a directory scanned as a repository root, or a rendered FastMCP server file
            (`McpTox.server_file`) in a fresh directory; offline, one process per unit, 300 s cap
  Cordon's default gate (`PublicSkills.scan`: blocked; flagged = blocked or any MEDIUM+ finding)
        │
        ▼
  per dataset and overall: malicious blocked / flagged, benign not blocked / no warning (Wilson 95%),
  recall by attack category, every benign unit blocked with the rule and file that blocked it,
  every LOW+ finding on a malicious unit the gate let through, and every timeout or error
```

    docker run --rm --network none --cpus 4 -w /tmp -v cordon-bench-public:/p:ro \\
      -v "$SRC:/src:ro" -v "$PWD/bench:/b:ro" -v OUT:/out -e PYTHONPATH=/src \\
      -e CORDON_CACHE_DIR=/tmp/c -e PYTHONDONTWRITEBYTECODE=1 python:3.12-slim \\
      python /b/mcp_poisoning.py /p --datasets mcptox,mcp-variants --out /out --workers 4

`/p` holds one checkout per dataset, under the directory names in each loader's `DIRECTORY`.
Nothing in a dataset is run, imported or installed: descriptions and code are read as text, and
no dataset file is copied into this repository.
"""

from __future__ import annotations

import argparse
import csv
import json
import multiprocessing
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suites"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from public_skills import PublicSkills

_PROMPT_TOOL = re.compile(
    r"Tool: (?P<name>[^\n]+)\nDescription: (?P<description>.*?)\nArguments:", re.S
)


@dataclass
class Loaded:
    """What a dataset loader read: the units to scan, and what it left out and why."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    excluded: list[dict[str, Any]] = field(default_factory=list)


class Files:
    @staticmethod
    def has_content(path: Path) -> bool:
        """A directory holding at least one file (an unresolved git submodule holds none)."""
        return any(files for _, _, files in os.walk(path))

    @staticmethod
    def identifier(name: str) -> str:
        safe = re.sub(r"\W", "_", name) or "tool"
        return f"_{safe}" if safe[0].isdigit() else safe


class McpTox:
    """Reading the benchmark into (kind, server, name, description, risk, paradigm) rows."""

    NAME = "mcptox"
    DIRECTORY = "mcptox"
    HEADER = 'from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP("server")\n\n'

    @staticmethod
    def poisoned(root: Path) -> list[dict[str, Any]]:
        rows = []
        for server in json.loads((root / "pure_tool.json").read_text(encoding="utf-8")):
            for case in server.values():
                rows.append(
                    {
                        "malicious": True,
                        "dataset": McpTox.NAME,
                        "server": case["server_name"],
                        "name": case["tool_name"],
                        "description": case["tool_content"].strip(),
                        "category": case["security risk"],
                        "risk": case["security risk"],
                        "paradigm": case["paradigm"],
                    }
                )
        return rows

    @staticmethod
    def legitimate(root: Path) -> list[dict[str, Any]]:
        data = json.loads((root / "response_all.json").read_text(encoding="utf-8"))
        rows, seen = [], set()
        for server in data["servers"].values():
            for match in _PROMPT_TOOL.finditer(server["clean_system_promot"]):
                key = (server["server_name"], match.group("name").strip())
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "malicious": False,
                        "dataset": McpTox.NAME,
                        "server": key[0],
                        "name": key[1],
                        "description": match.group("description").strip(),
                        "category": "",
                        "risk": "",
                        "paradigm": "",
                    }
                )
        return rows

    @classmethod
    def load(cls, root: Path) -> Loaded:
        return Loaded(cls.poisoned(root) + cls.legitimate(root))

    @staticmethod
    def tool(
        name: str,
        description: str,
        params: dict[str, str] | None = None,
        defaults: dict[str, Any] | None = None,
    ) -> str:
        """One FastMCP tool whose docstring is the description.

        `params` (name -> type or description text) become typed arguments listed under `Args:`
        in the docstring, the shape a FastMCP tool publishes its input schema in; `defaults`
        (name -> value) become arguments with that default, which FastMCP publishes as the
        schema's `default`.
        """
        signature, documented = [], []
        for param, text in (params or {}).items():
            signature.append(f"{Files.identifier(param)}: str")
            documented.append(f"        {param}: {text}")
        for param, value in (defaults or {}).items():
            signature.append(f"{Files.identifier(param)}: object = {value!r}")
        body = description
        if documented:
            body += "\n\n    Args:\n" + "\n".join(documented) + "\n    "
        doc = body.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
        return (
            "\n@mcp.tool()\n"
            f"def {Files.identifier(name)}({', '.join(signature)}) -> str:\n"
            f'    """{doc}"""\n'
            '    return ""\n'
        )

    @classmethod
    def server_file(
        cls,
        name: str,
        description: str,
        params: dict[str, str] | None = None,
        defaults: dict[str, Any] | None = None,
    ) -> str:
        """A FastMCP server declaring one tool whose docstring is the description."""
        return cls.HEADER + cls.tool(name, description, params, defaults)


class McpVariants:
    """yms0527/awesome-mcp-servers: real servers, and copies of them with an attack inserted.

    One unit is one server directory: `malicious-mcp-variants/<attack>/<server>/` and
    `reference-mcp-servers/<category>/<server>/`. A reference server filed under several
    categories is one server, scanned once. A directory with no file in it is a git submodule
    the repository records without content (a 160000 tree entry, no `.gitmodules`): there is
    nothing to scan, so it is listed as excluded.
    """

    NAME = "mcp-variants"
    DIRECTORY = "mcp-variants"
    MALICIOUS = "malicious-mcp-variants"
    REFERENCE = "reference-mcp-servers"

    @classmethod
    def stages(cls, root: Path) -> dict[tuple[str, str], str]:
        mapping = root / cls.MALICIOUS / "variant_name_mapping.csv"
        if not mapping.is_file():
            return {}
        with mapping.open(encoding="utf-8", newline="") as handle:
            return {
                (row["attack_directory"], row["labelled_variant_directory"]): row[
                    "final_impact_location"
                ]
                for row in csv.DictReader(handle)
            }

    @classmethod
    def load(cls, root: Path) -> Loaded:
        loaded = Loaded()
        stages = cls.stages(root)
        for attack in sorted(p for p in (root / cls.MALICIOUS).iterdir() if p.is_dir()):
            for server in sorted(p for p in attack.iterdir() if p.is_dir()):
                row = {
                    "malicious": True,
                    "dataset": cls.NAME,
                    "server": server.name,
                    "name": server.name,
                    "category": attack.name,
                    "stage": stages.get((attack.name, server.name), ""),
                    "path": str(server),
                }
                cls.keep(loaded, row, server)
        seen: dict[str, str] = {}
        for category in sorted(p for p in (root / cls.REFERENCE).iterdir() if p.is_dir()):
            for server in sorted(p for p in category.iterdir() if p.is_dir()):
                if server.name in seen:
                    loaded.excluded.append(
                        {
                            "dataset": cls.NAME,
                            "malicious": False,
                            "unit": f"{category.name}/{server.name}",
                            "reason": f"the same server as {seen[server.name]}/{server.name}",
                        }
                    )
                    continue
                seen[server.name] = category.name
                row = {
                    "malicious": False,
                    "dataset": cls.NAME,
                    "server": server.name,
                    "name": server.name,
                    "category": category.name,
                    "path": str(server),
                }
                cls.keep(loaded, row, server)
        return loaded

    @staticmethod
    def keep(loaded: Loaded, row: dict[str, Any], server: Path) -> None:
        if Files.has_content(server):
            loaded.rows.append(row)
        else:
            loaded.excluded.append(
                {
                    "dataset": row["dataset"],
                    "malicious": row["malicious"],
                    "unit": f"{row['category']}/{server.name}",
                    "reason": "empty directory (a git submodule recorded without content)",
                }
            )


class AgentDefense:
    """AgentDefense-Bench: tool-poisoning and benign records, every one a `tools/call` request.

    No record carries a tool definition a server publishes (no `tools/list` response, no
    `inputSchema`): each is a call an agent makes, with the record's own one-line `description`
    and the call's arguments. That is what is rendered, on both sides alike: the description as
    the docstring, each argument as a parameter whose default is the call's value.
    `tool_poisoning_attacks.json` is the union of the three per-category files, so only it is
    read; `benign_baseline.json` is the union of normal_operations, edge_cases and stress_tests.
    """

    NAME = "agentdefense"
    DIRECTORY = "agentdefense"

    @classmethod
    def row(cls, record: dict[str, Any], request: dict[str, Any], malicious: bool) -> dict:
        params = request.get("params") or {}
        return {
            "malicious": malicious,
            "dataset": cls.NAME,
            "server": record.get("id", ""),
            "name": (record.get("metadata") or {}).get("tool_name") or params.get("name", "tool"),
            "description": str(record.get("description", "")).strip(),
            "defaults": params.get("arguments") or {},
            "category": record.get("category", ""),
            "subcategory": record.get("subcategory", ""),
        }

    @classmethod
    def load(cls, root: Path) -> Loaded:
        loaded = Loaded()
        attacks = root / "tool_poisoning" / "tool_poisoning_attacks.json"
        for record in json.loads(attacks.read_text(encoding="utf-8")):
            loaded.rows.append(cls.row(record, record["mcp_request"], True))
        baseline = root / "benign_baseline" / "benign_baseline.json"
        for record in json.loads(baseline.read_text(encoding="utf-8")):
            loaded.rows.append(cls.row(record, record["mcp_request"], False))
        expanded = root / "benign_baseline" / "expanded_benign_operations.json"
        if expanded.is_file():
            for record in json.loads(expanded.read_text(encoding="utf-8"))["tests"]:
                loaded.rows.append(cls.row(record, record["request"], False))
        Dedupe.rows(loaded)
        return loaded


class McpSafetyBench:
    """MCP-SafetyBench: the server-side half of each task, as the runner writes it into a server.

    A task that changes a server is one malicious unit: a replaced tool description
    (`mcp_server_modifications[].modification_description`), a replaced return value
    (`modification_return`, which the runner pastes in as the tool's return statement), an added
    tool (`mcp_server_additions`, whose `implementation_code` is inserted under `@mcp.tool()`),
    or a rug pull (`mcp_server_update.implementation_code`). A task whose attack lives in the
    user prompt, the host or the runtime (credential theft, remote access, replay, intent
    injection, data tampering, identity spoofing, ...) leaves no server artefact and is excluded.
    The benign units are the benchmark's own servers, `mcpuniverse/mcp/servers/<server>/`.
    """

    NAME = "mcpsafetybench"
    DIRECTORY = "mcpsafetybench"

    @staticmethod
    def code(task: dict[str, Any]) -> str | None:
        """The server file a task's changes amount to, or None when it changes no server."""
        parts = []
        for change in task.get("mcp_server_modifications") or []:
            name = change.get("tool_name", "tool")
            if change.get("modification_description"):
                parts.append(McpTox.tool(name, change["modification_description"]))
            if change.get("modification_return") is not None:
                parts.append(
                    "\n@mcp.tool()\n"
                    f"def {Files.identifier(name)}() -> str:\n"
                    f"    return {str(change['modification_return'])!r}\n"
                )
        additions = task.get("mcp_server_additions") or {}
        tools = [additions] if "tool_name" in additions else additions.get("tools", [])
        update = task.get("mcp_server_update") or {}
        for tool in [*tools, update]:
            if tool.get("implementation_code"):
                parts.append(f"\n# tool: {tool.get('tool_name', '')}\n@mcp.tool()\n")
                parts.append(tool["implementation_code"].rstrip("\n") + "\n")
        return McpTox.HEADER + "".join(parts) if parts else None

    @classmethod
    def load(cls, root: Path) -> Loaded:
        loaded = Loaded()
        configs = root / "mcpuniverse" / "benchmark" / "configs"
        for path in sorted(configs.rglob("*.json")):
            task = json.loads(path.read_text(encoding="utf-8"))
            unit = path.relative_to(configs).as_posix()
            code = cls.code(task)
            attack = task.get("attack_category")
            if code is None:
                loaded.excluded.append(
                    {
                        "dataset": cls.NAME,
                        "malicious": attack is not None,
                        "unit": unit,
                        "category": attack or task.get("category", ""),
                        "reason": "no server-side artefact (the attack is in the prompt, the "
                        "host or the runtime)"
                        if attack
                        else "no attack (a general task)",
                    }
                )
                continue
            changed = [m.get("tool_name", "") for m in task.get("mcp_server_modifications") or []]
            added = (task.get("mcp_server_additions") or {}).get("tool_name", "")
            loaded.rows.append(
                {
                    "malicious": True,
                    "dataset": cls.NAME,
                    "server": unit,
                    "name": ",".join(changed) or added or "",
                    "category": attack or "",
                    "paradigm": task.get("category", ""),
                    "code": code,
                }
            )
        servers = root / "mcpuniverse" / "mcp" / "servers"
        for server in sorted(p for p in servers.iterdir() if p.is_dir()):
            loaded.rows.append(
                {
                    "malicious": False,
                    "dataset": cls.NAME,
                    "server": server.name,
                    "name": server.name,
                    "category": "",
                    "path": str(server),
                }
            )
        Dedupe.rows(loaded)
        return loaded


class McpSecBench:
    """MCPSecBench: a handful of single-file servers in `code/`, each scanned alone."""

    NAME = "mcpsecbench"
    DIRECTORY = "mcpsecbench"
    SERVERS: ClassVar[dict[str, tuple[bool, str]]] = {
        "maliciousadd.py": (True, "Malicious server (poisoning, shadowing, rug pull, ...)"),
        "squatting.py": (True, "Server Name Squatting"),
        "cve-2025-6514.py": (True, "Malicious OAuth server (CVE-2025-6514)"),
        "sse.py": (True, "Configuration Drift"),
        "addserver.py": (False, ""),
        "download.py": (False, ""),
    }
    NOT_SERVERS: ClassVar[dict[str, str]] = {
        "client.py": "the benchmark's MCP client",
        "main.py": "the benchmark's test driver",
        "mitm.py": "a man-in-the-middle proxy (a network attack tool, not a server)",
        "index.js": "a DNS-rebinding web page (not a server)",
        "claude_desktop_config.json": "the harness's host configuration",
        "cursor_config.json": "the harness's host configuration",
    }

    @classmethod
    def load(cls, root: Path) -> Loaded:
        loaded = Loaded()
        code = root / "code"
        for name, (malicious, category) in cls.SERVERS.items():
            if (code / name).is_file():
                loaded.rows.append(
                    {
                        "malicious": malicious,
                        "dataset": cls.NAME,
                        "server": name,
                        "name": name,
                        "category": category,
                        "path": str(code / name),
                    }
                )
        for name, reason in cls.NOT_SERVERS.items():
            if (code / name).is_file():
                loaded.excluded.append(
                    {"dataset": cls.NAME, "malicious": None, "unit": name, "reason": reason}
                )
        return loaded


class CieveMe:
    """CieveMe/mcp-security-benchmark: one deliberately insecure server; the rest are npm targets."""

    NAME = "cieveme"
    DIRECTORY = "cieveme"

    @classmethod
    def load(cls, root: Path) -> Loaded:
        loaded = Loaded()
        servers = root / "servers"
        if servers.is_dir() and Files.has_content(servers):
            loaded.rows.append(
                {
                    "malicious": True,
                    "dataset": cls.NAME,
                    "server": "vulnerable-demo",
                    "name": "vulnerable_demo_server.py",
                    "category": "Deliberately insecure server (canary)",
                    "path": str(servers),
                }
            )
        for target in sorted((root / "targets").glob("*.json")):
            if target.stem != "vulnerable-demo":
                loaded.excluded.append(
                    {
                        "dataset": cls.NAME,
                        "malicious": False,
                        "unit": target.name,
                        "reason": "a published package the harness names, not in the repository",
                    }
                )
        return loaded


class Dedupe:
    @staticmethod
    def key(row: dict[str, Any]) -> str:
        fields = ("malicious", "name", "description", "defaults", "code", "path")
        return json.dumps([row.get(f) for f in fields], sort_keys=True, default=str)

    @classmethod
    def rows(cls, loaded: Loaded) -> None:
        """Identical artefacts on the same side are one unit; the repeats are listed as excluded."""
        kept, seen = [], {}
        for row in loaded.rows:
            key = cls.key(row)
            if key in seen:
                loaded.excluded.append(
                    {
                        "dataset": row["dataset"],
                        "malicious": row["malicious"],
                        "unit": row["server"],
                        "category": row.get("category", ""),
                        "reason": f"identical artefact to {seen[key]}",
                    }
                )
                continue
            seen[key] = row["server"]
            kept.append(row)
        loaded.rows = kept


class McpPoisoningBench:
    LOADERS: ClassVar[dict[str, Any]] = {
        loader.NAME: loader
        for loader in (McpTox, McpVariants, AgentDefense, McpSafetyBench, McpSecBench, CieveMe)
    }
    TIMEOUT = 300.0
    DETAIL_LIMIT = 80
    SCANNED = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    HOUSEKEEPING = ("OPERATIONAL.", "POLICY.COVERAGE")
    """About the scan itself (stale feeds, coverage), as `PublicSkills.scan` leaves them out."""
    DEPENDENCY_CVES = ("VULNERABLE.DEPENDENCY.",)

    @staticmethod
    def unit(row: dict[str, Any]) -> str:
        return f"{row['dataset']}:{row['server']}:{row['name']}"

    @staticmethod
    def materialise(row: dict[str, Any], work: Path) -> Path:
        """The directory a unit is scanned as: the dataset's own, or one written for it."""
        if "path" in row:
            source = Path(row["path"])
            if source.is_dir():
                return source
            shutil.copyfile(source, work / source.name)
            return work
        if "code" in row:
            (work / "server.py").write_text(row["code"], encoding="utf-8")
            return work
        (work / "server.py").write_text(
            McpTox.server_file(
                row["name"], row["description"], row.get("params"), row.get("defaults")
            ),
            encoding="utf-8",
        )
        return work

    @staticmethod
    def order(entry: dict[str, Any]) -> tuple:
        return (not entry["blocks"], entry["rule"], entry["path"], entry["line"] or 0)

    @classmethod
    def findings(cls, target: Path) -> list[dict[str, Any]]:
        """Every LOW+ finding on a target: rule, severity, file, line, and whether it blocks."""
        from cordon_scanner import Scanner
        from cordon_scanner.decide.policy import PolicyGate
        from cordon_scanner.foundation.config.settings import Config

        overrides: dict[str, Any] = {"use_cache": False}
        # `--judge` (the operator's model, as `cordon-scanner --judge`): set once in the parent
        # and inherited by every worker, so one run measures one configuration.
        if os.environ.get("CORDON_BENCH_JUDGE"):
            overrides["judge"] = os.environ["CORDON_BENCH_JUDGE"]
            overrides["judge_blocks"] = os.environ.get("CORDON_BENCH_JUDGE_BLOCKS") == "1"
        config = Config.default().with_overrides(**overrides)
        result = Scanner(config).scan(target)
        seen, out = set(), []
        for f in result.findings:
            blocks = PolicyGate._fails(f, config.policy)
            if not blocks and (
                f.severity.name not in cls.SCANNED or f.rule_id.startswith(cls.HOUSEKEEPING)
            ):
                continue
            entry = {
                "rule": f.rule_id,
                "severity": f.severity.name,
                "path": f.location.path,
                "line": f.location.line,
                "blocks": blocks,
            }
            key = (entry["rule"], entry["path"], entry["line"])
            if key not in seen:
                seen.add(key)
                out.append(entry)
        return sorted(out, key=cls.order)[: cls.DETAIL_LIMIT]

    @classmethod
    def one(cls, row: dict[str, Any]) -> dict[str, Any]:
        """Scan one unit: the gate's verdict, and every LOW+ finding with where it is."""
        from cordon_scanner.detect.agents.agents import McpServerSource

        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="mcpbench-") as work:
            target = cls.materialise(row, Path(work))
            _, blocked, flagged, rules = PublicSkills.scan(str(target))
            detail = cls.findings(target)
        classify = getattr(McpServerSource, "_poisoned_description", None)
        reason = None
        if "description" in row and classify is not None:
            reason = classify(row["description"])
        return {
            **{k: v for k, v in row.items() if k != "code"},
            "status": "ok",
            "blocked": blocked,
            "flagged": flagged,
            "rules": rules,
            "classifier": reason,
            "findings": detail,
            "seconds": round(time.monotonic() - started, 2),
        }

    @classmethod
    def child(cls, row: dict[str, Any], conn: Any) -> None:
        try:
            conn.send(cls.one(row))
        except BaseException as exc:  # reported as the unit's error, never swallowed  # noqa: BLE001
            conn.send({"status": "error", "error": f"{type(exc).__name__}: {exc}"[:500]})
        finally:
            conn.close()

    @classmethod
    def failed(cls, row: dict[str, Any], outcome: dict[str, Any], seconds: float) -> dict:
        return {
            **{k: v for k, v in row.items() if k != "code"},
            **outcome,
            "blocked": None,
            "flagged": None,
            "rules": [],
            "classifier": None,
            "findings": None,
            "seconds": round(seconds, 2),
        }

    @classmethod
    def run(
        cls, rows: list[dict[str, Any]], workers: int, timeout: float, log: Any = None
    ) -> list[dict[str, Any]]:
        """Each unit in its own forked process, killed at `timeout`; results keep row order."""
        context = multiprocessing.get_context("fork")
        results: list[dict[str, Any] | None] = [None] * len(rows)
        pending = list(range(len(rows)))
        running: dict[int, tuple[Any, Any, float]] = {}
        done = 0
        while pending or running:
            while pending and len(running) < workers:
                index = pending.pop(0)
                parent, child = context.Pipe(duplex=False)
                process = context.Process(target=cls.child, args=(rows[index], child))
                process.start()
                child.close()
                running[index] = (process, parent, time.monotonic())
            time.sleep(0.02)
            for index, (process, parent, started) in list(running.items()):
                outcome = None
                if parent.poll():
                    try:
                        outcome = parent.recv()
                    except EOFError:
                        outcome = {"status": "error", "error": "the worker exited without a result"}
                elif not process.is_alive():
                    outcome = {
                        "status": "error",
                        "error": f"the worker exited with code {process.exitcode}",
                    }
                elif time.monotonic() - started > timeout:
                    process.kill()
                    outcome = {"status": "timeout", "error": f"over {timeout:.0f} s"}
                if outcome is None:
                    continue
                process.join(5)
                parent.close()
                del running[index]
                if outcome.get("status") != "ok":
                    outcome = cls.failed(rows[index], outcome, time.monotonic() - started)
                results[index] = outcome
                done += 1
                if log is not None and (done % 50 == 0 or done == len(rows)):
                    log.write(f"  {done}/{len(rows)}\n")
                    log.flush()
        return [r for r in results if r is not None]

    @classmethod
    def beyond_dependencies(cls, row: dict[str, Any]) -> bool:
        """Blocked by something other than a known-vulnerable dependency.

        A real server's lockfile carrying a published CVE fails the default gate whether or not
        anyone tampered with the server, so on a server-directory dataset it says nothing about
        the attack; this is the verdict with those findings set aside.
        """
        return any(
            f["blocks"] and not f["rule"].startswith(cls.DEPENDENCY_CVES)
            for f in row.get("findings") or []
        )

    @classmethod
    def rates(cls, rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "blocked": PublicSkills.rate(sum(bool(r["blocked"]) for r in rows), len(rows)),
            "flagged": PublicSkills.rate(sum(bool(r["flagged"]) for r in rows), len(rows)),
            "blocked_beyond_dependencies": PublicSkills.rate(
                sum(cls.beyond_dependencies(r) for r in rows), len(rows)
            ),
        }

    @classmethod
    def summarise(cls, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Rates over the units that finished; timeouts and errors are counted and listed."""
        rate = PublicSkills.rate
        scanned = [r for r in rows if r["status"] == "ok"]
        bad = [r for r in scanned if r["malicious"]]
        good = [r for r in scanned if not r["malicious"]]
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in bad:
            groups[f"category:{r.get('category', '')}"].append(r)
            for key in ("paradigm", "stage"):
                if r.get(key):
                    groups[f"{key}:{r[key]}"].append(r)
        summary: dict[str, Any] = {
            "units": {
                "malicious": sum(1 for r in rows if r["malicious"]),
                "benign": sum(1 for r in rows if not r["malicious"]),
                "scanned": len(scanned),
                "timeouts": [cls.unit(r) for r in rows if r["status"] == "timeout"],
                "errors": [
                    {"unit": cls.unit(r), "error": r.get("error")}
                    for r in rows
                    if r["status"] == "error"
                ],
            },
            "malicious": cls.rates(bad),
            "benign": {
                "not_blocked": rate(sum(not r["blocked"] for r in good), len(good)),
                "no_warning": rate(sum(not r["flagged"] for r in good), len(good)),
                "not_blocked_beyond_dependencies": rate(
                    sum(not cls.beyond_dependencies(r) for r in good), len(good)
                ),
            },
            "recall_by": {k: cls.rates(v) for k, v in sorted(groups.items())},
            "missed_by_category": dict(
                Counter(r.get("category", "") for r in bad if not r["blocked"]).most_common()
            ),
            "benign_blocked": [
                {
                    "unit": cls.unit(r),
                    "category": r.get("category", ""),
                    "rules": r["rules"],
                    "blocking": [
                        {k: f[k] for k in ("rule", "severity", "path", "line")}
                        for f in r["findings"] or []
                        if f["blocks"]
                    ],
                }
                for r in good
                if r["blocked"]
            ],
        }
        described = [r for r in scanned if "description" in r]
        if described:
            summary["classifier"] = {
                "malicious_caught": rate(
                    sum(r["classifier"] is not None for r in described if r["malicious"]),
                    sum(1 for r in described if r["malicious"]),
                ),
                "benign_clean": rate(
                    sum(r["classifier"] is None for r in described if not r["malicious"]),
                    sum(1 for r in described if not r["malicious"]),
                ),
            }
        return summary

    @classmethod
    def main(cls) -> int:
        ap = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        ap.add_argument("base", type=Path, help="the directory holding each dataset's checkout")
        ap.add_argument("--datasets", default=",".join(cls.LOADERS))
        ap.add_argument("--out", type=Path, default=Path())
        ap.add_argument("--workers", type=int, default=4)
        ap.add_argument("--timeout", type=float, default=cls.TIMEOUT)
        ap.add_argument("--limit", type=int, default=0, help="at most this many units per dataset")
        ap.add_argument("--judge", help="judge agent-facing text with this model, as --judge does")
        ap.add_argument("--judge-blocks", action="store_true", help="a malicious verdict blocks")
        args = ap.parse_args()
        if args.judge:
            os.environ["CORDON_BENCH_JUDGE"] = args.judge
            os.environ["CORDON_BENCH_JUDGE_BLOCKS"] = "1" if args.judge_blocks else "0"
        names = [n.strip() for n in args.datasets.split(",") if n.strip()]
        unknown = [n for n in names if n not in cls.LOADERS]
        if unknown:
            ap.error(f"unknown dataset(s) {unknown}; known: {sorted(cls.LOADERS)}")
        import cordon_scanner  # noqa: F401  -- imported once, before the workers fork

        args.out.mkdir(parents=True, exist_ok=True)
        everything, report = [], {}
        for name in names:
            loader = cls.LOADERS[name]
            loaded = loader.load(args.base / loader.DIRECTORY)
            rows = loaded.rows[: args.limit] if args.limit else loaded.rows
            sys.stderr.write(f"{name}: {len(rows)} units, {len(loaded.excluded)} excluded\n")
            results = cls.run(rows, args.workers, args.timeout, sys.stderr)
            everything.extend(results)
            (args.out / f"{name}-rows.jsonl").write_text(
                "".join(json.dumps(r, default=str) + "\n" for r in results), encoding="utf-8"
            )
            summary = {**cls.summarise(results), "excluded": loaded.excluded}
            (args.out / f"{name}-summary.json").write_text(
                json.dumps(summary, indent=2, default=str), encoding="utf-8"
            )
            report[name] = summary
        report["overall"] = cls.summarise(everything)
        (args.out / "summary.json").write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
        brief = {
            k: {f: v[f] for f in ("units", "malicious", "benign") if f in v}
            for k, v in report.items()
        }
        print(json.dumps(brief, indent=2, default=str))
        return 0


if __name__ == "__main__":
    raise SystemExit(McpPoisoningBench.main())
