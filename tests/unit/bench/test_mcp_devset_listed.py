"""The devset reads a list of archives as one source, and `--as-scanned` keeps a text per server.

The lines are set on the texts a server would be scored on: a description two servers share is read
in both. The training set drops the repeat, so a server whose descriptions were all met before it
would count for nothing against the line.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))
sys.path.insert(0, str(REPO / "bench" / "suites"))
sys.path.insert(0, str(REPO / "bench" / "tools"))
sys.path.insert(0, str(REPO / "bench"))

from mcp_devset import McpDevset

SERVER = (
    "import {{ McpServer }} from '@modelcontextprotocol/sdk/server/mcp.js';\n"
    "const server = new McpServer({{ name: 'x', version: '1' }});\n"
    "server.tool('read', '{text}', {{}}, async () => ({{ content: [] }}));\n"
    "const about = {{ description: '{text}' }};\n"
)


class Archives:
    @staticmethod
    def make(root: Path, name: str, text: str) -> None:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = SERVER.format(text=text).encode()
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo("package/index.js")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class TestListedArchives:
    def test_each_listed_archive_is_a_server_of_its_own_source(self, tmp_path: Path) -> None:
        Archives.make(tmp_path, "q/a/one.tgz", "Read a file from the workspace.")
        Archives.make(tmp_path, "r/b/one.tgz", "List the open issues of a repository.")
        rows = list(
            McpDevset.listed("census", ["q/a/one.tgz", "r/b/one.tgz"], tmp_path, as_scanned=True)
        )
        assert {r["group"] for r in rows} == {"q/a/one.tgz", "r/b/one.tgz"}
        assert {r["source"] for r in rows} == {"census"}
        assert {r["label"] for r in rows} == {0}

    def test_the_half_is_that_of_the_file_name_as_a_corpus_archive_has_it(
        self, tmp_path: Path
    ) -> None:
        Archives.make(tmp_path, "q/a/one.tgz", "Read a file from the workspace.")
        row = next(McpDevset.listed("corpus", ["q/a/one.tgz"], tmp_path, as_scanned=True))
        assert row["half"] == McpDevset.half("corpus", "one.tgz")


class TestUnique:
    @staticmethod
    def two_servers(tmp_path: Path) -> list[dict]:
        Archives.make(tmp_path, "a.tgz", "Read a file from the workspace.")
        Archives.make(tmp_path, "b.tgz", "Read a file from the workspace.")
        return list(McpDevset.listed("census", ["a.tgz", "b.tgz"], tmp_path, as_scanned=True))

    def test_a_text_two_servers_share_is_kept_once_for_training(self, tmp_path: Path) -> None:
        rows = list(McpDevset.unique(iter(self.two_servers(tmp_path)), per_server=False))
        assert [r["group"] for r in rows] == ["a.tgz"]

    def test_a_text_two_servers_share_is_kept_for_each_when_the_lines_are_set(
        self, tmp_path: Path
    ) -> None:
        rows = list(McpDevset.unique(iter(self.two_servers(tmp_path)), per_server=True))
        assert [r["group"] for r in rows] == ["a.tgz", "b.tgz"]

    def test_a_text_a_server_repeats_is_kept_once_either_way(self, tmp_path: Path) -> None:
        row = self.two_servers(tmp_path)[0]
        assert len(list(McpDevset.unique(iter([row, dict(row)]), per_server=True))) == 1


class TestAsScanned:
    def test_a_description_outside_every_registration_is_read_for_training_only(
        self, tmp_path: Path
    ) -> None:
        data = (SERVER.format(text="Search the documentation.")).encode()
        data += b"const banner = { description: 'Not a tool, a banner for the CLI.' };\n"
        with tarfile.open(tmp_path / "c.tgz", "w:gz") as archive:
            info = tarfile.TarInfo("package/index.js")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        wide = {r["text"] for r in McpDevset.archive(tmp_path / "c.tgz", "census", "c", "c")}
        scanned = {
            r["text"] for r in McpDevset.archive(tmp_path / "c.tgz", "census", "c", "c", True)
        }
        assert "Not a tool, a banner for the CLI." in wide
        assert scanned == {"Search the documentation."}
