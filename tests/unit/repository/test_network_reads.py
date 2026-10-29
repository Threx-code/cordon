"""Every network response's body is read through `Download`, within a budget for the whole body.

A socket timeout bounds one read, not a download: a server that sends a byte now and then holds a
plain `response.read` for as long as it likes (`foundation/network/downloads.py`). This finds every
response a module opens -- `urllib.request.urlopen(...)`, an opener's `open(...)` -- and every
`HTTPError` it catches, and fails on a `.read` of any of them that does not go through `Download`.
"""

from __future__ import annotations

import ast
from pathlib import Path

from support import ROOT

PACKAGE = ROOT / "src" / "cordon_scanner"


class NetworkReads:
    """The plain reads of network responses in one module."""

    @staticmethod
    def opens_a_response(call: ast.expr) -> bool:
        """`urlopen(...)`, or an opener's `open(...)` however the opener is reached: a name, an
        attribute (`cls._opener.open`), a call (`build_opener(...).open`), an expression
        (`(opener or Redirects.opener(config).open)(...)`). A path's or an archive's `open` is not."""
        if not isinstance(call, ast.Call):
            return False
        text = ast.unparse(call.func)
        return "urlopen" in text or ("open" in text and "opener" in text.lower())

    @staticmethod
    def found(path: Path) -> list[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        responses: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if NetworkReads.opens_a_response(item.context_expr) and isinstance(
                        item.optional_vars, ast.Name
                    ):
                        responses.add(item.optional_vars.id)
            elif isinstance(node, ast.Assign) and NetworkReads.opens_a_response(node.value):
                responses |= {t.id for t in node.targets if isinstance(t, ast.Name)}
            elif isinstance(node, ast.ExceptHandler) and node.name:
                caught = node.type
                caught_name = (
                    caught.attr if isinstance(caught, ast.Attribute) else getattr(caught, "id", "")
                )
                if caught_name == "HTTPError":
                    responses.add(node.name)
        reads = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"read", "read1", "readline", "readlines"}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in responses
            ):
                reads.append(
                    f"{path.relative_to(PACKAGE)}:{node.lineno} {node.func.value.id}.{node.func.attr}"
                )
        return reads


class TestNetworkReads:
    def test_every_response_body_is_read_through_download(self) -> None:
        found = [
            read
            for path in sorted(PACKAGE.rglob("*.py"))
            if path.relative_to(PACKAGE).as_posix() != "foundation/network/downloads.py"
            for read in NetworkReads.found(path)
        ]
        assert not found, (
            "read a network response through foundation.downloads.Download:\n" + "\n".join(found)
        )

    def test_the_finder_sees_a_plain_read(self, tmp_path) -> None:
        sample = tmp_path / "sample.py"
        sample.write_text(
            "import urllib.request\n"
            "def get(url):\n"
            "    with urllib.request.urlopen(url, timeout=3) as response:\n"
            "        return response.read(1024)\n",
            encoding="utf-8",
        )
        original = NetworkReads.found.__globals__["PACKAGE"]
        NetworkReads.found.__globals__["PACKAGE"] = tmp_path
        try:
            assert NetworkReads.found(sample) == ["sample.py:4 response.read"]
        finally:
            NetworkReads.found.__globals__["PACKAGE"] = original
