"""Where an MCP server's source registers its tools: the spans an agent's view of a tool comes from.

A tool's description and its result reach the agent; any other string in the file does not. Read
from every `description` key and every `return` of a file that names the SDK, the rule judged an
agent CLI's own prompts, a library's error text and a parameter object nobody registers (note 68,
fix 1: 10 of 18 npm false alarms of SUSPECT.MCP.TOOL_DESCRIPTION.001 were no tool's text). The
registration is followed to its parts, so moving the text out of the call evades nothing:

```
  .tool( / .registerTool( / .addTool( / setRequestHandler(CallTool|ListTools ...)   ──► the call's span
  { name, description, inputSchema | input_schema | parameters }                      ──► the object's span
  @<server>.tool / .call_tool / .list_tools  def ...:                                ──► the function's body
        │
        ├─ an identifier the span passes (a handler, a description constant) ──► its definition's span
        ▼
  descriptions = `description` values and the second argument of `.tool(name, "...")` inside a span
  returns      = `return` / `text:` literals inside a span or a named handler's body
```

A JSON manifest declares its tools as data, so it is read whole, as before.
"""

from __future__ import annotations

import re
from typing import Final

#: A call that registers a tool, or the handler for listing or calling them (TypeScript SDK, FastMCP
#: for TypeScript, the low-level `Server`).
_REGISTER_CALL: Final = re.compile(
    r"\.(?:tool|registerTool|addTool)[ \t]{0,8}\(|\bsetRequestHandler[ \t]{0,8}\([ \t\n]{0,40}"
    r"(?:\w{1,40}\.)?(?:CallToolRequestSchema|ListToolsRequestSchema)\b"
)

#: A tool object's own schema key, beside its `name`: the object is a tool definition.
_SCHEMA_KEY: Final = re.compile(
    r"""["']?\b(?:inputSchema|input_schema|parameters)\b["']?[ \t]{0,8}:"""
)

#: A Python decorator that makes the next function a tool, or the server's tool handler.
_PY_DECORATOR: Final = re.compile(
    r"(?m)^(?P<indent>[ \t]{0,40})@\w{1,40}(?:\.\w{1,40}){0,4}\.(?:tool|call_tool|list_tools)\b"
)
_PY_DEF: Final = re.compile(r"(?m)^(?P<indent>[ \t]{0,40})(?:async[ \t]{1,4})?def[ \t]")

#: An identifier handed to a registration as an argument or a value.
_PASSED_NAME: Final = re.compile(
    r"[(,:][ \t\n]{0,40}(?P<name>[A-Za-z_$][\w$]{0,60})[ \t\n]{0,40}[,)}]"
)

_SPAN_REACH: Final = 400_000
_MAX_SPANS: Final = 2_000


class ToolRegistrations:
    """The spans of a source file that hold what its tools hand the agent."""

    @staticmethod
    def spans(text: str) -> list[tuple[int, int]]:
        """Every registration's span, the definitions of the identifiers they pass included,
        merged and sorted. Bounded: at most `_MAX_SPANS` spans of `_SPAN_REACH` characters."""
        found: list[tuple[int, int]] = []
        for match in _REGISTER_CALL.finditer(text):
            open_at = text.find("(", match.start())
            if open_at >= 0:
                found.append((match.start(), ToolRegistrations.close_of(text, open_at)))
            if len(found) >= _MAX_SPANS:
                break
        for match in _SCHEMA_KEY.finditer(text):
            span = ToolRegistrations._enclosing_object(text, match.start())
            if span is not None and re.search(
                r"""["']?\bname\b["']?[ \t]{0,8}:""", text[span[0] : span[1]]
            ):
                found.append(span)
            if len(found) >= _MAX_SPANS:
                break
        found.extend(ToolRegistrations._python_tools(text))
        named = {
            m.group("name")
            for start, end in found
            for m in _PASSED_NAME.finditer(text, start, min(end, start + _SPAN_REACH))
        }
        found.extend(ToolRegistrations._definitions(text, named))
        return ToolRegistrations._merged(found)

    @staticmethod
    def inside(spans: list[tuple[int, int]], offset: int) -> bool:
        return any(start <= offset < end for start, end in spans)

    @staticmethod
    def close_of(text: str, open_at: int) -> int:
        """The offset just past the bracket that closes the one at `open_at`, skipping strings and
        comments; the reach's end when it does not close within it."""
        end = min(len(text), open_at + _SPAN_REACH)
        depth, index = 0, open_at
        while index < end:
            char = text[index]
            if char in "'\"`":
                index = ToolRegistrations._past_string(text, index, end)
                continue
            if char == "/" and text.startswith(("//", "/*"), index):
                close = "\n" if text[index + 1] == "/" else "*/"
                found = text.find(close, index + 2, end)
                index = end if found < 0 else found + len(close)
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        return end

    @staticmethod
    def _past_string(text: str, index: int, end: int) -> int:
        quote = text[index]
        cursor = index + 1
        while cursor < end and text[cursor] != quote:
            if text[cursor] == "\\":
                cursor += 1
            elif text[cursor] == "\n" and quote != "`":
                break
            cursor += 1
        return cursor + 1

    @staticmethod
    def _enclosing_object(text: str, offset: int) -> tuple[int, int] | None:
        """The `{ ... }` that holds `offset`, read back at most `_SPAN_REACH` characters."""
        depth, floor = 0, max(0, offset - _SPAN_REACH)
        for index in range(offset - 1, floor - 1, -1):
            char = text[index]
            if char == "}":
                depth += 1
            elif char == "{":
                if depth == 0:
                    return index, ToolRegistrations.close_of(text, index)
                depth -= 1
        return None

    @staticmethod
    def _python_tools(text: str) -> list[tuple[int, int]]:
        """Each decorated tool function's body: from the decorator to the next line indented no
        deeper than the decorator."""
        spans: list[tuple[int, int]] = []
        for match in _PY_DECORATOR.finditer(text):
            spans.append((match.start(), ToolRegistrations._python_block_end(text, match)))
            if len(spans) >= _MAX_SPANS:
                break
        return spans

    @staticmethod
    def _python_block_end(text: str, match: re.Match[str]) -> int:
        indent = len(match.group("indent"))
        definition = _PY_DEF.search(text, match.end())
        if definition is None:
            return match.end()
        line_end = text.find("\n", definition.end())
        index = len(text) if line_end < 0 else line_end + 1
        limit = min(len(text), match.start() + _SPAN_REACH)
        while index < limit:
            nl = text.find("\n", index)
            line = text[index : len(text) if nl < 0 else nl]
            stripped = line.strip()
            if (
                stripped
                and not stripped.startswith(("#", ")", "]", "}"))
                and len(line) - len(line.lstrip()) <= indent
            ):
                return index
            if nl < 0:
                return len(text)
            index = nl + 1
        return limit

    @staticmethod
    def _definitions(text: str, names: set[str]) -> list[tuple[int, int]]:
        """Where each passed identifier is defined: a function, a method, an arrow function or a
        constant, to the end of its body or its statement."""
        spans: list[tuple[int, int]] = []
        for name in sorted(names)[:200]:
            escaped = re.escape(name)
            definition = re.compile(
                rf"(?:\bfunction\*?[ \t]{{1,4}}{escaped}[ \t]{{0,4}}\(|\b(?:const|let|var)[ \t]{{1,4}}"
                rf"{escaped}[ \t]{{0,8}}(?::[^=\n]{{1,200}})?=|^[ \t]{{0,40}}(?:async[ \t]{{1,4}})?{escaped}"
                rf"[ \t]{{0,4}}\([^)\n]{{0,300}}\)[ \t]{{0,4}}(?::[^{{\n]{{1,200}})?\{{|\bdef[ \t]{{1,4}}{escaped}\b)",
                re.MULTILINE,
            )
            for match in definition.finditer(text):
                spans.append((match.start(), ToolRegistrations._definition_end(text, match.end())))
                if len(spans) >= _MAX_SPANS:
                    return spans
        return spans

    @staticmethod
    def _definition_end(text: str, index: int) -> int:
        """The end of the body or value that starts at `index`: its first bracket's close, or the
        statement's end when the value is a plain literal."""
        end = min(len(text), index + _SPAN_REACH)
        cursor = index
        while cursor < end:
            char = text[cursor]
            if char in "([{":
                return ToolRegistrations.close_of(text, cursor)
            if char in "'\"`":
                cursor = ToolRegistrations._past_string(text, cursor, end)
                continue
            if char in ";\n" and text[index:cursor].strip():
                return cursor
            cursor += 1
        return end

    @staticmethod
    def _merged(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged


__all__ = ["ToolRegistrations"]
