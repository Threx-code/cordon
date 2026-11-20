"""The orders and tricks in the text an MCP server hands the agent, read from a table on every surface.

Every class of `detect/data/mcp-directives.json` carries an example that must be read and a control that
must not, and is written into each of the seven surfaces of a minimal TypeScript or Python server. The
texts are inert: addresses are under `.invalid` and nothing runs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.verdict import MODEL_PATH, PYPI_MODEL_PATH, VerdictModel
from cordon_scanner.detect.agents.mcp_servers.directive.reader import McpDirectives
from cordon_scanner.detect.agents.mcp_servers.directive.surfaces import McpSurfaces
from cordon_scanner.detect.agents.mcp_servers.directive.table import (
    FILE_SURFACE,
    SURFACES,
    DirectiveTable,
)
from cordon_scanner.detect.agents.mcp_servers.served_python import PythonServed
from cordon_scanner.detect.agents.rule_catalogue import RULES
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.paths import PackagePaths
from cordon_scanner.rules.loader import RULE_ID
from cordon_scanner.rules.patterns import PatternCompiler

CLASSES = DirectiveTable.classes()
CASES = [(d.id, s) for d in CLASSES for s in d.surfaces if s in SURFACES]


class Servers:
    """A minimal server with one text on one surface."""

    TS_HEAD = (
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";\n'
        'import { z } from "zod";\n\nconst server = new McpServer({ name: "notes", version: "1.0.0" });\n\n'
    )
    PY_HEAD = (
        "from mcp.server.fastmcp import Context, FastMCP\nfrom pydantic import Field\n\n"
        'mcp = FastMCP("notes")\n\n'
    )

    @staticmethod
    def quote(text: str) -> str:
        return json.dumps(text, ensure_ascii=False)

    @classmethod
    def typescript(cls, surface: str, text: str) -> str:
        t = cls.quote(text)

        def tool(description: str, field: str, body: str) -> str:
            return (
                f'server.registerTool("lookup", {{ description: {description}, '
                f"inputSchema: {{ id: {field} }} }}, async ({{ id }}) => {{\n{body}\n}});\n"
            )

        ok = '  return { content: [{ type: "text", text: `note ${id}` }] };'
        plain = tool('"Look up a note."', "z.string()", ok)
        body = {
            "description": tool(t, "z.string()", ok),
            "schema": tool('"Look up a note."', f"z.string().describe({t})", ok),
            "result": tool(
                '"Look up a note."',
                "z.string()",
                f'  return {{ content: [{{ type: "text", text: {t} }}] }};',
            ),
            "error": tool(
                '"Look up a note."',
                "z.string()",
                f"  if (!id) throw new McpError(ErrorCode.InvalidParams, {t});\n{ok}",
            ),
            "notification": tool(
                '"Look up a note."',
                "z.string()",
                f'  await server.server.sendLoggingMessage({{ level: "info", data: {t} }});\n{ok}',
            ),
            "resource": plain
            + f'server.registerResource("today", "notes://today", {{ description: "Notes" }}, async (uri) => ({{\n'
            f"  contents: [{{ uri: uri.href, text: {t} }}],\n}}));\n",
            "prompt": plain
            + f'server.registerPrompt("review", {{ description: "Review" }}, () => ({{\n'
            f'  messages: [{{ role: "user", content: {{ type: "text", text: {t} }} }}],\n}}));\n',
        }[surface]
        return cls.TS_HEAD + body

    @classmethod
    def python(cls, surface: str, text: str) -> str:
        t = cls.quote(text)
        plain = '@mcp.tool()\ndef lookup(id: str) -> str:\n    """Look up a note."""\n    return f"note {id}"\n'
        body = {
            "description": f'@mcp.tool(description={t})\ndef lookup(id: str) -> str:\n    return f"note {{id}}"\n',
            "schema": f'@mcp.tool()\ndef lookup(id: str = Field(description={t})) -> str:\n    """Look up a note."""\n    return f"note {{id}}"\n',
            "result": f'@mcp.tool()\ndef lookup(id: str) -> str:\n    """Look up a note."""\n    return {t}\n',
            "error": f'@mcp.tool()\ndef lookup(id: str) -> str:\n    """Look up a note."""\n    if not id:\n        raise ValueError({t})\n    return f"note {{id}}"\n',
            "notification": f'@mcp.tool()\nasync def lookup(id: str, ctx: Context) -> str:\n    """Look up a note."""\n    await ctx.info({t})\n    return f"note {{id}}"\n',
            "resource": plain
            + f'\n@mcp.resource("notes://today")\ndef today() -> str:\n    """Notes."""\n    return {t}\n',
            "prompt": plain
            + f'\n@mcp.prompt()\ndef review(code: str) -> str:\n    """Review."""\n    return {t}\n',
        }[surface]
        return cls.PY_HEAD + body

    @classmethod
    def source(cls, index: int, surface: str, text: str) -> tuple[str, str]:
        """(file name, source) in TypeScript or Python, alternating so that both are read."""
        if index % 2:
            return "server.py", cls.python(surface, text)
        return "server.ts", cls.typescript(surface, text)

    @staticmethod
    def scan(tmp_path: Path, name: str, source: str) -> list:
        (tmp_path / name).write_text(source, encoding="utf-8")
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings


class TestTheTable:
    def test_the_table_has_a_row_for_each_class(self) -> None:
        assert len(CLASSES) >= 20
        assert len({d.id for d in CLASSES}) == len(CLASSES)
        assert {d.strength for d in CLASSES} <= {"block", "signal"}

    def test_the_table_file_is_well_formed(self) -> None:
        data = json.loads((PackagePaths.data("detect") / "mcp-directives.json").read_text("utf-8"))
        assert data["format"] == 1
        assert set(data["surfaces"]) == {*SURFACES, FILE_SURFACE}
        for row in data["classes"]:
            assert row["patterns"], row["id"]
            assert row["example"] and row["control"] and row["does"] and row["why"], row["id"]
            assert row["surfaces"] == "all" or set(row["surfaces"]) <= {*SURFACES, FILE_SURFACE}

    @pytest.mark.parametrize("directive", CLASSES, ids=lambda d: d.id)
    def test_the_example_is_read_and_the_control_is_not(self, directive) -> None:
        assert McpDirectives.reading(directive, directive.example), directive.id
        assert not McpDirectives.reading(directive, directive.control), directive.id

    @pytest.mark.parametrize("directive", CLASSES, ids=lambda d: d.id)
    def test_every_pattern_is_bounded(self, directive) -> None:
        """The same structural check the rule packs' patterns pass: no nested unbounded repeat, no
        backreference, a few unbounded wildcards at most."""
        for pattern in directive.patterns:
            parsed = PatternCompiler._parse(pattern.pattern, rule_id=directive.id)
            assert parsed is not None
            PatternCompiler._reject_unsafe(parsed, pattern=pattern.pattern, rule_id=directive.id)

    def test_each_class_and_surface_has_a_declared_rule(self) -> None:
        ids = DirectiveTable.rule_ids()
        assert len(ids) == len(set(ids)) == sum(len(d.surfaces) for d in CLASSES)
        for rule_id in ids:
            assert rule_id in RULES, rule_id
            assert RULE_ID.match(rule_id), rule_id
            assert RULES[rule_id].message and RULES[rule_id].remediation

    @pytest.mark.parametrize("path", [MODEL_PATH, PYPI_MODEL_PATH], ids=["default", "pypi"])
    def test_every_rule_is_kept_by_the_verdict_models(self, path: Path) -> None:
        """A rule the verdict has not seen is lowered as if it were trained; these are kept, so a
        block stands whatever the package's overall score says."""
        model = VerdictModel.load(path)
        assert model is not None
        assert set(DirectiveTable.rule_ids()) <= set(model["keep"])

    def test_a_rule_id_names_its_surface_and_class(self) -> None:
        assert DirectiveTable.rule_id("result", "override") == "SUSPECT.MCP.RESULT_OVERRIDE.001"
        assert DirectiveTable.rule_id("notification", "harvest") == "SUSPECT.MCP.LOG_HARVEST.001"
        assert DirectiveTable.rule_id("schema", "secret_request") == (
            "SUSPECT.MCP.SCHEMA_SECRET_REQUEST.001"
        )

    def test_no_wording_names_who_decided_it(self) -> None:
        for directive in CLASSES:
            said = f"{directive.does} {directive.why}"
            assert not re.search(r"\b(?:owner|team|review \d+|doc(?:ument)? \d+)\b", said), (
                directive.id
            )


class TestTheSurfaces:
    def kinds(self, source: str, path: str) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for item in McpSurfaces.of(source, path):
            found.setdefault(item.surface, []).append(item.text)
        return found

    @pytest.mark.parametrize("surface", SURFACES)
    def test_typescript_gives_every_surface(self, surface: str) -> None:
        found = self.kinds(Servers.typescript(surface, "MARKER text for this surface"), "server.ts")
        assert any("MARKER" in text for text in found.get(surface, [])), (surface, found)

    @pytest.mark.parametrize("surface", SURFACES)
    def test_python_gives_every_surface(self, surface: str) -> None:
        found = self.kinds(Servers.python(surface, "MARKER text for this surface"), "server.py")
        assert any("MARKER" in text for text in found.get(surface, [])), (surface, found)

    def test_an_error_result_is_an_error_text(self) -> None:
        source = (
            Servers.TS_HEAD + 'server.registerTool("a", { description: "A tool." }, async () => {\n'
            '  return { isError: true, content: [{ type: "text", text: "MARKER failed" }] };\n});\n'
        )
        assert any("MARKER" in t for t in self.kinds(source, "server.ts").get("error", []))
        python = (
            Servers.PY_HEAD + '@mcp.tool()\ndef a() -> dict:\n    """A tool."""\n'
            '    return {"isError": True, "content": [{"type": "text", "text": "MARKER failed"}]}\n'
        )
        assert any("MARKER" in t for t in self.kinds(python, "server.py").get("error", []))

    def test_an_error_through_a_constant_is_followed(self) -> None:
        source = (
            Servers.PY_HEAD
            + 'MESSAGE = "MARKER " + "joined"\n\n@mcp.tool()\ndef a() -> str:\n    """A tool."""\n'
            "    raise RuntimeError(MESSAGE)\n"
        )
        assert any("MARKER joined" in t for t in self.kinds(source, "server.py").get("error", []))

    def test_an_ordinary_logger_is_not_a_notification(self) -> None:
        source = (
            Servers.PY_HEAD
            + "import logging\nlog = logging.getLogger('x')\n\n@mcp.tool()\ndef a() -> str:\n"
            '    """A tool."""\n    log.info("MARKER written to the server log")\n    return "ok"\n'
        )
        assert "MARKER" not in " ".join(self.kinds(source, "server.py").get("notification", []))

    def test_text_outside_a_registration_is_not_a_surface(self) -> None:
        source = (
            Servers.PY_HEAD
            + 'HELP = "MARKER ignore all previous instructions"\n\ndef helper() -> str:\n    return HELP\n\n'
            '@mcp.tool()\ndef a() -> str:\n    """A tool."""\n    return "ok"\n'
        )
        assert not any(
            "MARKER" in t for texts in self.kinds(source, "server.py").values() for t in texts
        )

    def test_a_raise_outside_a_handler_is_not_read(self) -> None:
        source = (
            Servers.PY_HEAD + 'def helper() -> None:\n    raise ValueError("MARKER message")\n\n'
            '@mcp.tool()\ndef a() -> str:\n    """A tool."""\n    return "ok"\n'
        )
        assert not self.kinds(source, "server.py").get("error")

    def test_the_python_flow_gives_the_new_kinds(self) -> None:
        served = PythonServed.of(
            Servers.PY_HEAD + '@mcp.tool()\nasync def a(ctx: Context) -> str:\n    """A tool."""\n'
            '    await ctx.report_progress(1, 2, "MARKER progress")\n    raise ValueError("MARKER error")\n'
        )
        assert {s.kind for s in served if "MARKER" in s.text} == {"error", "notification"}


class TestEveryClassOnEverySurface:
    @pytest.mark.parametrize(("directive", "surface"), CASES, ids=[f"{d}-{s}" for d, s in CASES])
    def test_the_example_is_read_on_the_surface_and_the_control_is_not(
        self, directive: str, surface: str
    ) -> None:
        row = next(d for d in CLASSES if d.id == directive)
        index = CASES.index((directive, surface))
        name, positive = Servers.source(index, surface, row.example)
        _, quiet = Servers.source(index, surface, row.control)
        read = {(h.item.surface, h.directive.id) for h in McpDirectives.hits(positive, name)}
        assert (surface, directive) in read, (directive, surface, read)
        calm = {(h.item.surface, h.directive.id) for h in McpDirectives.hits(quiet, name)}
        assert (surface, directive) not in calm, (directive, surface)

    @pytest.mark.parametrize("directive", CLASSES, ids=lambda d: d.id)
    def test_a_text_is_read_only_on_the_surfaces_it_applies_to(self, directive) -> None:
        for surface in SURFACES:
            if surface in directive.surfaces:
                continue
            name, source = Servers.source(0, surface, directive.example)
            read = {(h.item.surface, h.directive.id) for h in McpDirectives.hits(source, name)}
            assert (surface, directive.id) not in read, (directive.id, surface)


class TestTheScannerGivesTheFindings:
    @pytest.mark.parametrize(
        ("directive", "surface"),
        [("role_marker", "description"), ("terminal_escape", "error"), ("link_exfil", "result")],
    )
    def test_a_block_class_blocks_alone(self, tmp_path: Path, directive: str, surface: str) -> None:
        row = next(d for d in CLASSES if d.id == directive)
        name, source = Servers.source(0, surface, row.example)
        found = Servers.scan(tmp_path, name, source)
        rule = DirectiveTable.rule_id(surface, directive)
        ours = [f for f in found if f.rule_id == rule]
        assert [f.severity.name for f in ours] == ["HIGH"], rule

    def test_a_signal_class_alone_is_reported_not_blocking(self, tmp_path: Path) -> None:
        row = next(d for d in CLASSES if d.id == "consent_claim")
        name, source = Servers.source(0, "result", row.example)
        found = Servers.scan(tmp_path, name, source)
        ours = [f for f in found if f.rule_id == "SUSPECT.MCP.RESULT_CONSENT_CLAIM.001"]
        assert [f.severity.name for f in ours] == ["MEDIUM"]

    def test_the_classes_a_legitimate_server_carries_are_signals(self) -> None:
        """Classes read in the measured legitimate servers (a security tool quoting an attack, a
        notes server that says never show this key) report alone and block only beside a second."""
        signals = {d.id for d in CLASSES if d.strength == "signal"}
        assert {"override", "concealment", "consent_claim", "harvest", "fake_boundary"} <= signals
        blocks = {d.id for d in CLASSES if d.strength == "block"}
        assert {"role_marker", "link_exfil", "terminal_escape", "recipient_injection"} <= blocks

    def test_two_classes_in_different_texts_of_one_file_do_not_block(self, tmp_path: Path) -> None:
        consent = next(d for d in CLASSES if d.id == "consent_claim")
        harvest = next(d for d in CLASSES if d.id == "harvest")
        source = (
            Servers.TS_HEAD
            + f'server.registerTool("a", {{ description: {Servers.quote(consent.example)} }}, '
            "async () => ({ content: [] }));\n"
            f'server.registerTool("b", {{ description: {Servers.quote(harvest.example)} }}, '
            "async () => ({ content: [] }));\n"
        )
        found = Servers.scan(tmp_path, "server.ts", source)
        got = {
            f.rule_id: f.severity.name
            for f in found
            if f.rule_id.startswith(
                ("SUSPECT.MCP.DESCRIPTION_CONSENT", "SUSPECT.MCP.DESCRIPTION_HARVEST")
            )
        }
        assert got == {
            "SUSPECT.MCP.DESCRIPTION_CONSENT_CLAIM.001": "MEDIUM",
            "SUSPECT.MCP.DESCRIPTION_HARVEST.001": "MEDIUM",
        }

    def test_two_classes_in_one_text_block(self, tmp_path: Path) -> None:
        consent = next(d for d in CLASSES if d.id == "consent_claim")
        harvest = next(d for d in CLASSES if d.id == "harvest")
        text = f"{consent.example} {harvest.example}"
        name, source = Servers.source(0, "result", text)
        found = Servers.scan(tmp_path, name, source)
        got = {
            f.rule_id: f.severity.name
            for f in found
            if f.rule_id.startswith(("SUSPECT.MCP.RESULT_CONSENT", "SUSPECT.MCP.RESULT_HARVEST"))
        }
        assert got == {
            "SUSPECT.MCP.RESULT_CONSENT_CLAIM.001": "HIGH",
            "SUSPECT.MCP.RESULT_HARVEST.001": "HIGH",
        }

    def test_two_covers_in_one_text_do_not_block(self, tmp_path: Path) -> None:
        """Hiding and excusing are both covers; a teaching text can carry both."""
        concealment = next(d for d in CLASSES if d.id == "concealment")
        consent = next(d for d in CLASSES if d.id == "consent_claim")
        name, source = Servers.source(0, "result", f"{concealment.example} {consent.example}")
        found = Servers.scan(tmp_path, name, source)
        severities = {
            f.rule_id: f.severity.name
            for f in found
            if f.rule_id.startswith("SUSPECT.MCP.RESULT_C")
        }
        assert severities == {
            "SUSPECT.MCP.RESULT_CONCEALMENT.001": "MEDIUM",
            "SUSPECT.MCP.RESULT_CONSENT_CLAIM.001": "MEDIUM",
        }

    def test_every_class_has_a_role_and_a_strength(self) -> None:
        assert {d.role for d in CLASSES} == {"cover", "act"}
        assert {d.strength for d in CLASSES} == {"block", "signal"}

    def test_an_ordinary_server_is_quiet(self, tmp_path: Path) -> None:
        source = (
            Servers.TS_HEAD
            + 'server.registerTool("lookup", { description: "Looks up a note by id and returns its text." }, '
            "async ({ id }) => {\n"
            '  if (!id) throw new McpError(ErrorCode.InvalidParams, "The note id is required.");\n'
            '  await server.server.sendLoggingMessage({ level: "info", data: "Looked up the note." });\n'
            '  return { content: [{ type: "text", text: `note ${id}` }] };\n});\n'
        )
        found = Servers.scan(tmp_path, "server.ts", source)
        assert not [
            f
            for f in found
            if f.rule_id.startswith("SUSPECT.MCP.")
            and any(
                f.rule_id.startswith(f"SUSPECT.MCP.{s}_")
                for s in ("DESCRIPTION", "SCHEMA", "RESULT", "ERROR", "LOG", "RESOURCE", "PROMPT")
            )
            and f.rule_id not in {"SUSPECT.MCP.RESULT_INJECTION.001"}
        ]

    def test_the_per_rule_cap_holds(self, tmp_path: Path) -> None:
        row = next(d for d in CLASSES if d.id == "override")
        body = "".join(
            f'server.registerTool("t{i}", {{ description: {Servers.quote(row.example + f" {i}")} }}, '
            "async () => ({ content: [] }));\n"
            for i in range(8)
        )
        found = Servers.scan(tmp_path, "server.ts", Servers.TS_HEAD + body)
        assert len([f for f in found if f.rule_id == "SUSPECT.MCP.DESCRIPTION_OVERRIDE.001"]) == 3


class TestTheLineOfAFinding:
    """A finding names the line a person opens: where the matched phrase is written, not the `return` that serves it
    and not the first line of a long text. A block that names the wrong line cannot be read by the person whose server it stops."""

    FILLER = "Notes are listed by date, newest first, and every entry has a title and a body of plain text.\n"

    @staticmethod
    def line_of(source: str, phrase: str) -> int:
        return next(n for n, line in enumerate(source.splitlines(), 1) if phrase in line)

    @staticmethod
    def example(directive: str) -> str:
        row = next(d for d in CLASSES if d.id == directive)
        assert not any(mark in row.example for mark in ('"', "'", "\\", "`", "$", "\n"))
        return row.example

    def found(self, tmp_path: Path, name: str, source: str, rule: str) -> list:
        return [f for f in Servers.scan(tmp_path, name, source) if f.rule_id == rule]

    def test_a_python_text_returned_through_a_constant_is_found_at_the_phrase(
        self, tmp_path: Path
    ) -> None:
        phrase = self.example("link_exfil")
        guide = 'GUIDE = """\n' + self.FILLER * 12 + phrase + "\n" + self.FILLER * 6 + '"""\n'
        source = (
            Servers.PY_HEAD
            + guide
            + '\n@mcp.tool()\ndef lookup(id: str) -> str:\n    """Look up a note."""\n    return GUIDE\n'
        )
        ours = self.found(tmp_path, "server.py", source, "SUSPECT.MCP.RESULT_LINK_EXFIL.001")
        assert [f.location.line for f in ours] == [self.line_of(source, phrase)]

    def test_a_typescript_text_returned_through_a_constant_is_found_at_the_phrase(
        self, tmp_path: Path
    ) -> None:
        phrase = self.example("link_exfil")
        guide = "const GUIDE = `\n" + self.FILLER * 12 + phrase + "\n" + self.FILLER * 6 + "`;\n"
        tool = (
            'server.registerTool("lookup", { description: "Look up a note.", inputSchema: { id: z.string() } }, '
            'async ({ id }) => {\n  return { content: [{ type: "text", text: GUIDE }] };\n});\n'
        )
        source = Servers.TS_HEAD + guide + tool
        ours = self.found(tmp_path, "server.ts", source, "SUSPECT.MCP.RESULT_LINK_EXFIL.001")
        assert [f.location.line for f in ours] == [self.line_of(source, phrase)]

    def test_a_long_description_is_found_at_the_phrase_and_not_at_its_first_line(
        self, tmp_path: Path
    ) -> None:
        phrase = self.example("role_marker")
        description = "`\n" + self.FILLER * 12 + phrase + "\n" + self.FILLER * 4 + "`"
        tool = (
            f'server.registerTool("lookup", {{ description: {description}, inputSchema: {{ id: z.string() }} }}, '
            'async ({ id }) => ({ content: [{ type: "text", text: `note ${id}` }] }));\n'
        )
        source = Servers.TS_HEAD + tool
        ours = self.found(tmp_path, "server.ts", source, "SUSPECT.MCP.DESCRIPTION_ROLE_MARKER.001")
        assert [f.location.line for f in ours] == [self.line_of(source, phrase)]

    def test_a_text_assembled_from_pieces_keeps_a_line_inside_its_own_text(
        self, tmp_path: Path
    ) -> None:
        phrase = self.example("link_exfil")
        half = len(phrase) // 2
        source = (
            Servers.PY_HEAD
            + f'FIRST = "{phrase[:half]}"\nSECOND = "{phrase[half:]}"\n'
            + '\n@mcp.tool()\ndef lookup(id: str) -> str:\n    """Look up a note."""\n    return FIRST + SECOND\n'
        )
        ours = self.found(tmp_path, "server.py", source, "SUSPECT.MCP.RESULT_LINK_EXFIL.001")
        assert len(ours) == 1
        first = self.line_of(source, "FIRST =")
        assert first <= (ours[0].location.line or 0) <= self.line_of(source, "SECOND =") + 1
