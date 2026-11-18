"""Names an MCP server borrows: its own package named like a popular server, a tool named like a well-known tool.

An agent picks a tool by its name and a person installs a server by its name, so a name one slip from a
familiar one is how a server gets chosen in place of the real one (tool shadowing, server squatting).
Both judgements compare against a bundled list of well-known names, which is outside knowledge about the
ecosystem rather than anything the package's own code does.
"""

from __future__ import annotations

import json
import re
import tomllib
from typing import Final

from cordon_scanner.detect.agents.configuration import PackageLookalike

#: The tools of the reference MCP servers and the most launched vendor servers, by the name an agent calls.
WELL_KNOWN_TOOLS: Final = frozenset(
    {
        # filesystem
        "read_file", "read_text_file", "read_media_file", "read_multiple_files", "write_file", "edit_file",
        "create_directory", "list_directory", "list_directory_with_sizes", "directory_tree", "move_file",
        "search_files", "get_file_info", "list_allowed_directories",
        # git
        "git_status", "git_diff_unstaged", "git_diff_staged", "git_diff", "git_commit", "git_add", "git_reset",
        "git_log", "git_create_branch", "git_checkout", "git_show", "git_init", "git_branch",
        # github
        "create_or_update_file", "search_repositories", "create_repository", "get_file_contents", "push_files",
        "create_issue", "create_pull_request", "fork_repository", "create_branch", "list_commits", "list_issues",
        "update_issue", "add_issue_comment", "search_code", "search_issues", "search_users", "get_issue",
        "get_pull_request", "list_pull_requests", "merge_pull_request",
        # memory
        "create_entities", "create_relations", "add_observations", "delete_entities", "delete_observations",
        "delete_relations", "read_graph", "search_nodes", "open_nodes",
        # time, databases
        "get_current_time", "convert_time", "read_query", "write_query", "create_table", "list_tables",
        "describe_table", "append_insight",
        # browsers
        "puppeteer_navigate", "puppeteer_screenshot", "puppeteer_click", "puppeteer_fill", "puppeteer_select",
        "puppeteer_hover", "puppeteer_evaluate", "browser_navigate", "browser_click", "browser_snapshot",
        "browser_type", "browser_take_screenshot", "browser_close", "browser_evaluate",
        # search, chat
        "brave_web_search", "brave_local_search", "slack_list_channels", "slack_post_message",
        "slack_reply_to_thread", "slack_add_reaction", "slack_get_channel_history", "slack_get_thread_replies",
        "slack_get_users", "slack_get_user_profile", "sequentialthinking",
    }
)  # fmt: skip


class ToolNameLookalike:
    """A tool name one edit from a well-known tool's, and not a spelling of it."""

    #: Below this many letters, one edit separates too many ordinary names (`git_add`, `fetch`).
    MIN_LETTERS: Final = 7

    @staticmethod
    def _folded(name: str) -> str:
        """The name with case and separators removed: `read-file`, `readFile` and `read_file` are one tool."""
        return re.sub(r"[_\-.\s]", "", name).lower()

    _KNOWN: Final = {re.sub(r"[_\-.\s]", "", t).lower(): t for t in WELL_KNOWN_TOOLS}

    @classmethod
    def imitates(cls, name: str) -> str | None:
        """The well-known tool this name imitates, or None."""
        folded = cls._folded(name)
        if len(folded) < cls.MIN_LETTERS or folded in cls._KNOWN:
            return None
        for known, original in cls._KNOWN.items():
            # A plural or a singular is a tool's own name for many of a thing, not a slip.
            if folded in (known + "s", known + "es") or known in (folded + "s", folded + "es"):
                continue
            if len(known) >= cls.MIN_LETTERS and PackageLookalike._distance(folded, known) == 1:
                return original
        return None


class OwnPackageName:
    """A project manifest's own package name, when the project is an MCP server."""

    #: A dependency on an MCP SDK: what makes the manifest's package an MCP server.
    SDK: Final = re.compile(
        r"""@modelcontextprotocol/sdk|["'](?:mcp|fastmcp)(?:\[[^\]]*\])?\s*(?:[<>=~!]|["',])"""
        r"""|^\s*(?:rmcp|rmcp-macros)\s*=|mark3labs/mcp-go|modelcontextprotocol/go-sdk""",
        re.MULTILINE,
    )
    MANIFESTS: Final = ("package.json", "pyproject.toml", "Cargo.toml", "go.mod")

    @classmethod
    def of(cls, filename: str, text: str) -> str | None:
        """The package's own name, or None when the manifest is not an MCP server's or names nothing."""
        if filename not in cls.MANIFESTS or cls.SDK.search(text) is None:
            return None
        try:
            if filename == "package.json":
                name = json.loads(text).get("name")
            elif filename == "go.mod":
                found = re.search(r"(?m)^module\s+(\S{1,300})", text)
                name = found.group(1) if found else None
            else:
                data = tomllib.loads(text)
                section = data.get("project") or data.get("package") or {}
                name = section.get("name")
        except (ValueError, AttributeError):
            return None
        return name if isinstance(name, str) and name else None
