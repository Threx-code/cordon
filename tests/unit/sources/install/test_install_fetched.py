"""Tools whose fetch runs no package code (`sources/install/managers/fetched.py`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.sources.install.managers.fetched import FetchedTree


class TestWhatFetches:
    @pytest.mark.parametrize(
        ("tool", "args", "fetches"),
        [
            ("terraform", ["init"], True),
            ("tofu", ["get"], True),
            ("terraform", ["plan"], False),
            ("helm", ["dependency", "build", "chart"], True),
            ("helm", ["dep", "up"], True),
            ("helm", ["template", "chart"], False),
            ("ansible-galaxy", ["collection", "install", "community.general"], True),
            ("ansible-galaxy", ["install", "-r", "requirements.yml"], True),
            ("ansible-galaxy", ["collection", "list"], False),
        ],
    )
    def test_the_commands_that_fetch(self, tool: str, args: list[str], fetches: bool) -> None:
        assert FetchedTree.installs(tool, args) is fetches


class TestWhereTheyWrite:
    def test_terraform_writes_its_data_dir_and_lock(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("TF_DATA_DIR", raising=False)
        places = FetchedTree.places("terraform", ["init"], tmp_path)
        assert places.directories == (tmp_path / ".terraform",)
        assert places.locks == (tmp_path / ".terraform.lock.hcl",)

    def test_helm_writes_the_charts_folder_of_the_chart_named(self, tmp_path: Path) -> None:
        places = FetchedTree.places(
            "helm", ["dependency", "build", "web", "--skip-refresh"], tmp_path
        )
        assert places.directories == (tmp_path / "web" / "charts",)
        assert places.locks == (tmp_path / "web" / "Chart.lock",)

    def test_galaxy_writes_the_path_it_is_given(self, tmp_path: Path) -> None:
        places = FetchedTree.places(
            "ansible-galaxy", ["install", "-p", str(tmp_path / "c")], tmp_path
        )
        assert places.directories == (tmp_path / "c",)


class TestAFetch:
    @staticmethod
    def project(tmp_path: Path) -> Path:
        (tmp_path / ".terraform" / "providers").mkdir(parents=True)
        (tmp_path / ".terraform" / "providers" / "old").write_bytes(b"kept")
        (tmp_path / ".terraform.lock.hcl").write_text("# before\n", encoding="utf-8")
        return tmp_path

    @staticmethod
    def fetch(project: Path):
        def run() -> int:
            (project / ".terraform" / "providers" / "new").write_bytes(b"fetched")
            (project / ".terraform.lock.hcl").write_text("# after\n", encoding="utf-8")
            return 0

        return run

    def test_only_what_it_wrote_is_scanned(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("TF_DATA_DIR", raising=False)
        project = self.project(tmp_path / "p")
        scanned: list[list[str]] = []

        def scan(staged: Path) -> bool:
            scanned.append(sorted(p.name for p in staged.rglob("*") if p.is_file()))
            return True

        code = FetchedTree.run("terraform", ["init"], project, self.fetch(project), scan, tmp_path)
        assert code == 0 and scanned == [["new"]]
        assert (project / ".terraform.lock.hcl").read_text(encoding="utf-8") == "# after\n"

    def test_a_block_removes_what_it_wrote_and_puts_the_lock_back(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.delenv("TF_DATA_DIR", raising=False)
        project = self.project(tmp_path / "p")
        code = FetchedTree.run(
            "terraform", ["init"], project, self.fetch(project), lambda staged: False, tmp_path
        )
        assert code == 1
        assert not (project / ".terraform" / "providers" / "new").exists()
        assert (project / ".terraform" / "providers" / "old").read_bytes() == b"kept"
        assert (project / ".terraform.lock.hcl").read_text(encoding="utf-8") == "# before\n"

    def test_a_refusal_while_scanning_undoes_it_too(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("TF_DATA_DIR", raising=False)
        project = self.project(tmp_path / "p")

        def scan(staged: Path) -> bool:
            raise RuntimeError("scan failed")

        with pytest.raises(RuntimeError):
            FetchedTree.run("terraform", ["init"], project, self.fetch(project), scan, tmp_path)
        assert not (project / ".terraform" / "providers" / "new").exists()
        assert (project / ".terraform.lock.hcl").read_text(encoding="utf-8") == "# before\n"
