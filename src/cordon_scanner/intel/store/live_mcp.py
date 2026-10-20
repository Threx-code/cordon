"""What a remote MCP server serves now, and whether it is what was approved (advanced gap M6).

A tool description is read by the agent as an instruction, and the server decides it at request
time: a server reviewed on Monday can describe its `search` tool differently on Tuesday -- the
"rug pull" -- and nothing in the repository changes. Cordon reads tool descriptions from a
server's source where the repository has it; this reads what a remote server actually hands an
agent, over MCP's Streamable HTTP transport:

    POST <url>  initialize          ->  protocol version, the session id header
    POST <url>  notifications/initialized
    POST <url>  tools/list  (cursor)  ->  name, description, inputSchema, per page

and compares each tool's fingerprint (SHA-256 over its name, description, input schema and
annotations, canonical JSON) with the ones recorded in `.cordon/mcp-tools.json` when the
servers were approved (`cordon-scanner agent mcp-approve`).

Only remote servers, over https, and only when the operator allows the network: a local stdio
server is read by running it, which is running the package under review, and that is not done.
Requests are bounded (size, time, pages), follow no redirect, and send no credential the
configuration does not name.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

PROTOCOL_VERSION: Final = "2025-06-18"
MAX_RESPONSE_BYTES: Final = 4 << 20
MAX_PAGES: Final = 20
MAX_TOOLS: Final = 2_000
TIMEOUT_SECONDS: Final = 20
APPROVALS: Final = ".cordon/mcp-tools.json"
#: Where the configurations name a remote server: `url` (most), `serverUrl` (Windsurf),
#: `httpUrl` (Gemini CLI).
URL_KEYS: Final = ("url", "serverUrl", "httpUrl")


class LiveMcpError(Exception):
    """The server could not be read. The message is safe to print: it never carries a header."""


@dataclass(frozen=True)
class ServedTool:
    name: str
    description: str
    fingerprint: str

    @staticmethod
    def of(tool: dict[str, Any]) -> ServedTool:
        canonical = json.dumps(
            {k: tool.get(k) for k in ("name", "description", "inputSchema", "annotations")},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return ServedTool(
            str(tool.get("name", "")),
            str(tool.get("description") or ""),
            "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class LiveMcp:
    """A minimal, read-only MCP client: initialize, then list tools."""

    @staticmethod
    def remote_url(server: dict[str, Any]) -> str | None:
        for key in URL_KEYS:
            value = server.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _post(
        url: str, message: dict[str, Any], session: str | None
    ) -> tuple[dict[str, Any] | None, str | None]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL_VERSION,
            "User-Agent": "cordon-scanner (read-only MCP tool listing)",
        }
        if session:
            headers["Mcp-Session-Id"] = session
        request = urllib.request.Request(  # noqa: S310 - scheme checked by the caller
            url, data=json.dumps(message).encode(), headers=headers, method="POST"
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                kind = response.headers.get("Content-Type", "")
                session = response.headers.get("Mcp-Session-Id") or session
        except urllib.error.HTTPError as exc:
            raise LiveMcpError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise LiveMcpError(
                f"{type(exc).__name__} reaching {urllib.parse.urlsplit(url).netloc}"
            ) from exc
        if len(body) > MAX_RESPONSE_BYTES:
            raise LiveMcpError(f"the response exceeded {MAX_RESPONSE_BYTES} bytes")
        if "id" not in message:
            return None, session  # a notification: no answer is expected
        return LiveMcp._answer(body.decode("utf-8", "replace"), kind, message["id"]), session

    @staticmethod
    def _answer(text: str, kind: str, wanted: int) -> dict[str, Any]:
        """The JSON-RPC response with this id, from a JSON body or an event stream."""
        candidates: list[str] = []
        if "text/event-stream" in kind:
            data: list[str] = []
            for line in [*text.splitlines(), ""]:
                if line.startswith("data:"):
                    data.append(line[5:].lstrip())
                elif not line and data:
                    candidates.append("\n".join(data))
                    data = []
        else:
            candidates.append(text)
        for candidate in candidates:
            try:
                document = json.loads(candidate)
            except ValueError:
                continue
            for item in document if isinstance(document, list) else [document]:
                if isinstance(item, dict) and item.get("id") == wanted:
                    if isinstance(item.get("error"), dict):
                        raise LiveMcpError(
                            f"the server answered with an error: {str(item['error'].get('message', ''))[:120]}"
                        )
                    result = item.get("result")
                    if isinstance(result, dict):
                        return result
        raise LiveMcpError("the server sent no answer to the request")

    @staticmethod
    def tools(url: str) -> list[ServedTool]:
        """Every tool the server serves now, in its order."""
        if urllib.parse.urlsplit(url).scheme != "https":
            raise LiveMcpError("only https MCP servers are read")
        _, session = LiveMcp._post(
            url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "cordon-scanner", "version": "1"},
                },
            },
            None,
        )
        LiveMcp._post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
        tools: list[ServedTool] = []
        cursor: str | None = None
        for page in range(MAX_PAGES):
            params = {"cursor": cursor} if cursor else {}
            result, session = LiveMcp._post(
                url,
                {"jsonrpc": "2.0", "id": 2 + page, "method": "tools/list", "params": params},
                session,
            )
            if result is None:
                raise LiveMcpError("the server sent no tools/list answer")
            tools += [ServedTool.of(t) for t in result.get("tools") or [] if isinstance(t, dict)]
            cursor = result.get("nextCursor") if isinstance(result.get("nextCursor"), str) else None
            if not cursor or len(tools) >= MAX_TOOLS:
                break
        return tools[:MAX_TOOLS]


class McpApprovals:
    """`.cordon/mcp-tools.json`: each approved server's URL and its tools' fingerprints."""

    @staticmethod
    def load(root: Path) -> dict[str, Any] | None:
        path = root / APPROVALS
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return (
            document
            if isinstance(document, dict) and isinstance(document.get("servers"), dict)
            else None
        )

    @staticmethod
    def record(url: str, tools: list[ServedTool]) -> dict[str, Any]:
        return {
            "url": url,
            "tools": {
                t.name: {"fingerprint": t.fingerprint, "description": t.description} for t in tools
            },
        }

    @staticmethod
    def write(root: Path, servers: dict[str, dict[str, Any]]) -> Path:
        path = root / APPROVALS
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"version": 1, "servers": servers}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    @staticmethod
    def differences(approved: dict[str, Any], tools: list[ServedTool]) -> list[tuple[str, str]]:
        """`(kind, tool)` for each change since approval: `added`, `changed`, `removed`."""
        listed = approved.get("tools")
        recorded: dict[str, Any] = listed if isinstance(listed, dict) else {}
        served = {t.name: t for t in tools}
        out: list[tuple[str, str]] = []
        for name, tool in served.items():
            entry = recorded.get(name)
            if not isinstance(entry, dict):
                out.append(("added", name))
            elif entry.get("fingerprint") != tool.fingerprint:
                out.append(("changed", name))
        out += [("removed", name) for name in recorded if name not in served]
        return out


__all__ = ["APPROVALS", "LiveMcp", "LiveMcpError", "McpApprovals", "ServedTool"]
