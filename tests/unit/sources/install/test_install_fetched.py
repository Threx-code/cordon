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


@pytest.mark.skipif(
    not hasattr(__import__("os"), "mkfifo"), reason="links and FIFOs are POSIX here"
)
class TestWhatAFetchWritesThatIsNotAFile:
    """S3 (reviews/release-080/SECURITY-HARDENING.md): a fetch can write links and special files.
    The guard neither skips them nor hangs on them."""

    @staticmethod
    def places(project: Path):
        from cordon_scanner.sources.install.managers.fetched import FetchedPlaces

        return FetchedPlaces("terraform", (project / ".terraform",), ())

    @staticmethod
    def fetch_writing(make) -> int:
        make()
        return 0

    def test_a_linked_directory_is_scanned_not_skipped(self, tmp_path: Path) -> None:
        # Terraform's plugin cache: the provider is a link into a directory elsewhere.
        cache = tmp_path / "cache" / "provider"
        cache.mkdir(parents=True)
        (cache / "terraform-provider-x").write_bytes(b"provider")
        project = tmp_path / "p"
        (project / ".terraform").mkdir(parents=True)
        seen: list[set[str]] = []

        def scan(staged: Path) -> bool:
            seen.append({p.name for p in staged.rglob("*") if p.is_file()})
            return True

        def make() -> None:
            (project / ".terraform" / "providers").symlink_to(cache, target_is_directory=True)

        FetchedTree.run(
            "terraform", ["init"], project, lambda: self.fetch_writing(make), scan, tmp_path / "s"
        )
        assert seen == [{"terraform-provider-x"}]

    def test_a_fifo_is_refused_without_hanging(self, tmp_path: Path) -> None:
        import os

        from cordon_scanner.sources.install.plan import InstallRefused

        project = tmp_path / "p"
        (project / ".terraform").mkdir(parents=True)
        fifo = project / ".terraform" / "pipe"

        with pytest.raises(InstallRefused, match="not a regular file"):
            FetchedTree.run(
                "terraform",
                ["init"],
                project,
                lambda: self.fetch_writing(lambda: os.mkfifo(fifo)),
                lambda staged: True,
                tmp_path / "s",
            )
        assert not fifo.exists()

    def test_a_link_to_a_special_file_is_refused(self, tmp_path: Path) -> None:
        from cordon_scanner.sources.install.plan import InstallRefused

        project = tmp_path / "p"
        (project / ".terraform").mkdir(parents=True)
        link = project / ".terraform" / "zero"
        with pytest.raises(InstallRefused, match="not a regular file"):
            FetchedTree.run(
                "terraform",
                ["init"],
                project,
                lambda: self.fetch_writing(lambda: link.symlink_to("/dev/zero")),
                lambda staged: True,
                tmp_path / "s",
            )
        assert not link.is_symlink()

    def test_a_link_loop_ends(self, tmp_path: Path) -> None:
        project = tmp_path / "p"
        data = project / ".terraform"
        data.mkdir(parents=True)
        (data / "loop").symlink_to(data, target_is_directory=True)
        (data / "a.tf").write_text("x", encoding="utf-8")
        snap = FetchedTree.snapshot(self.places(project))
        assert {p for p, v in snap.items() if not v.startswith(FetchedTree.LINK)} == {data / "a.tf"}

    def test_a_link_to_the_whole_disk_is_refused_by_size(self, tmp_path: Path, monkeypatch) -> None:
        from cordon_scanner.sources.install.plan import InstallRefused

        monkeypatch.setattr(FetchedTree, "MAX_FILES", 50)
        big = tmp_path / "big"
        big.mkdir()
        for i in range(60):
            (big / f"f{i}").write_bytes(b"x")
        project = tmp_path / "p"
        (project / ".terraform").mkdir(parents=True)
        with pytest.raises(InstallRefused, match="more than 50 files"):
            FetchedTree.run(
                "terraform",
                ["init"],
                project,
                lambda: self.fetch_writing(
                    lambda: (project / ".terraform" / "all").symlink_to(big)
                ),
                lambda staged: True,
                tmp_path / "s",
            )
