"""`deps --exclude` and `sbom generate --exclude`: a repository's own record without its fixtures.

Cordon's records job inventoried the whole repository, test fixtures included, and three
deliberately unreadable fixtures marked its own bill of materials incomplete, and every
fixture's packages were listed as Cordon's own.
"""

from __future__ import annotations

import json

from cordon_scanner.cli.main import CommandLine
from cordon_scanner.core.errors import ExitCode

LOCK = {
    "name": "app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"{name}": "1.0.0"}},
        "node_modules/{name}": {"version": "1.0.0"},
    },
}


class Project:
    @staticmethod
    def lock(directory, name: str) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        text = json.dumps(LOCK).replace("{name}", name)
        (directory / "package-lock.json").write_text(text, encoding="utf-8")

    @staticmethod
    def make(tmp_path):
        Project.lock(tmp_path, "real-dependency")
        Project.lock(tmp_path / "samples" / "case", "fixture-dependency")
        # A fixture that cannot be read, as a parser's negative case is: the damage a version
        # bump did to editors/vscode/package-lock.json, quotes escaped inside JSON.
        broken = tmp_path / "samples" / "broken"
        Project.lock(broken, "unreadable")
        lock = broken / "package-lock.json"
        lock.write_text(
            lock.read_text(encoding="utf-8").replace('"1.0.0"', '\\"1.0.0\\"', 1),
            encoding="utf-8",
        )
        return tmp_path


class TestDepsExclude:
    def test_excluded_paths_are_not_in_the_graph(self, tmp_path, capsys) -> None:
        root = Project.make(tmp_path)
        code = CommandLine.run(["deps", "--format", "json", "--exclude", "samples/**", str(root)])
        payload = json.loads(capsys.readouterr().out)
        assert code == int(ExitCode.CLEAN)
        assert payload["complete"] is True
        names = {d["name"] for d in payload["dependencies"]}
        assert "real-dependency" in names and "fixture-dependency" not in names

    def test_without_it_the_fixtures_are_in_the_graph(self, tmp_path, capsys) -> None:
        root = Project.make(tmp_path)
        CommandLine.run(["deps", "--format", "json", str(root)])
        names = {d["name"] for d in json.loads(capsys.readouterr().out)["dependencies"]}
        assert {"real-dependency", "fixture-dependency"} <= names


class TestSbomExclude:
    def test_excluded_paths_are_not_components(self, tmp_path) -> None:
        root = Project.make(tmp_path)
        out = tmp_path / "bom.json"
        code = CommandLine.run(
            ["sbom", "generate", "--exclude", "samples/**", "-o", str(out), str(root)]
        )
        assert code == int(ExitCode.CLEAN)
        names = {c.get("name") for c in json.loads(out.read_text(encoding="utf-8"))["components"]}
        assert "real-dependency" in names and "fixture-dependency" not in names


class TestSbomCount:
    def test_both_formats_report_the_components_they_wrote(self, tmp_path, capsys) -> None:
        # The count read CycloneDX's `components` from an SPDX document, which has none: axios's
        # SPDX bill of 1,252 packages was reported as "0 component(s)".
        root = Project.make(tmp_path)
        counts = {}
        for fmt in ("cyclonedx", "spdx"):
            out = tmp_path / f"bom.{fmt}.json"
            CommandLine.run(["sbom", "generate", "--format", fmt, "-o", str(out), str(root)])
            message = capsys.readouterr().out
            document = json.loads(out.read_text(encoding="utf-8"))
            listed = (
                len(document["components"])
                if fmt == "cyclonedx"
                else len(document["packages"]) - 1  # less the root the document describes
            )
            assert f"({listed} component(s), {fmt})" in message
            counts[fmt] = listed
        assert counts["cyclonedx"] == counts["spdx"] > 0
