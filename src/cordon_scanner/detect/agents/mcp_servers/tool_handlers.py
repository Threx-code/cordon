"""Which functions of an MCP server's Python source are its tools, and what a tool says of itself.

`@mcp.tool()` marks one; the SDK's low-level API hands every tool to ONE handler, `@server.call_tool()`,
which chooses among them by name -- also written `server.call_tool()(handler)` or `server.call_tool =
handler`, which no decorator shows. The handler rules (`McpCode`) read what a tool does with the agent's
input; this is where they learn which functions those are, and whether the tool says it runs commands.
"""

from __future__ import annotations

import ast
import re
from typing import Final

#: `@mcp.tool()`, and the SDK's low-level `@server.call_tool()` (on FastMCP's inner `_mcp_server` too).
_TOOL_DECORATOR: Final = re.compile(r"\btool\b|\.tool\(|tool\s*$|\bcall_tool\b")


class ToolHandlers:
    @staticmethod
    def mark_registered(tree: ast.Module) -> None:
        """Flag the functions the SDK's low-level `call_tool` is handed without a decorator:
        `server.call_tool()(handler)` and `server.call_tool = handler`. The decorator form is read
        from the function itself (`_TOOL_DECORATOR`); these two are read from where it is registered."""
        registered: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Call)
                and isinstance(node.func.func, ast.Attribute)
                and node.func.func.attr == "call_tool"
                and node.args
                and isinstance(node.args[0], ast.Name)
            ):
                registered.add(node.args[0].id)
            elif (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Attribute) and t.attr == "call_tool" for t in node.targets
                )
                and isinstance(node.value, ast.Name)
            ):
                registered.add(node.value.id)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in registered:
                node.registered_tool = True  # type: ignore[union-attr]

    @staticmethod
    def is_dispatcher(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Whether the function is the one handler the SDK's low-level API gives every tool, which
        chooses among them by name."""
        return bool(getattr(function, "registered_tool", False)) or any(
            re.search(r"\bcall_tool\b", ast.unparse(d)) for d in function.decorator_list
        )

    @staticmethod
    def listed_text(tree: ast.Module) -> str:
        """What the tool list of a low-level server says: the strings of the functions registered with
        `list_tools`, which hold each tool's name and description."""
        parts: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and any(
                re.search(r"\blist_tools\b", ast.unparse(d)) for d in node.decorator_list
            ):
                parts.extend(
                    c.value[:300]
                    for c in ast.walk(node)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)
                )
        return " ".join(parts)[:4000]

    @classmethod
    def said(cls, function: ast.FunctionDef | ast.AsyncFunctionDef, listed: str) -> str:
        """What a tool says of itself: its name and docstring; for a dispatcher, also the names it
        compares its tool name with and the tool list's own words (it is one function for every tool)."""
        said = function.name + " " + (ast.get_docstring(function) or "")[:600]
        if cls.is_dispatcher(function):
            said += " " + listed
            said += (
                " "
                + " ".join(
                    c.value[:300]
                    for c in ast.walk(function)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)
                )[:2000]
            )
        return said

    @staticmethod
    def is_tool(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return getattr(function, "registered_tool", False) or any(
            _TOOL_DECORATOR.search(ast.unparse(d)) for d in function.decorator_list
        )
