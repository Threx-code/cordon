"""The digest of `.claude/skills/deploy/` equals the golden tree digest, computed locally.

The golden is the sha256 of the sorted listing `<path>\\0<mode>\\0<sha256 of content>\\n` worked out here by hand (not by the code under
test) for a two-file folder, so a change to the rule shows as a change to the golden.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.resolve.skill import SkillResolver

GOLDEN = "sha256:96c601e291af52c74a8125dd1639c4d0c5a7cf8430185bdbc9bc821d85815551"
SKILL_MD = b"# Deploy\nRun the deploy script.\n"
RUN_SH = b"#!/bin/sh\necho deploy\n"
GOLDEN_NO_EXECUTABLE = "sha256:a59bf7cc0835afd2536de393d36d1b1467b31b5c4c70b66f5bc188ee72c6e9e6"
"""The same folder with the script at mode 644, which is how Windows reads it: Windows has no executable bit."""
POSIX_MODES = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows has no executable bit: every file reads as 644 there (TestOnWindows pins that)",
)


class Folder:
    @staticmethod
    def deploy(root: Path, *, executable: bool = True) -> Path:
        folder = root / ".claude" / "skills" / "deploy"
        (folder / "scripts").mkdir(parents=True)
        (folder / "SKILL.md").write_bytes(SKILL_MD)
        script = folder / "scripts" / "run.sh"
        script.write_bytes(RUN_SH)
        script.chmod(0o755 if executable else 0o644)
        (folder / "SKILL.md").chmod(0o644)
        return folder


class TestTheGoldenFolder:
    @POSIX_MODES
    def test_the_digest_is_the_hand_computed_listing_digest(self, tmp_path: Path) -> None:
        by_hand = hashlib.sha256(
            b"SKILL.md\x00644\x00"
            + hashlib.sha256(SKILL_MD).hexdigest().encode()
            + b"\nscripts/run.sh\x00755\x00"
            + hashlib.sha256(RUN_SH).hexdigest().encode()
            + b"\n"
        ).hexdigest()
        assert "sha256:" + by_hand == GOLDEN
        folder = Folder.deploy(tmp_path)
        found = SkillResolver.resolve(folder, root=tmp_path)
        assert found.resolved and found.digest == GOLDEN
        assert found.subject_id == "skill:local/.claude/skills/deploy"
        assert found.kind == "agent_skill"

    @POSIX_MODES
    def test_it_is_the_same_digest_whatever_the_umask_the_times_and_the_order_of_creation(
        self, tmp_path: Path
    ) -> None:
        first = Folder.deploy(tmp_path / "one")
        other = tmp_path / "two" / ".claude" / "skills" / "deploy"
        (other / "scripts").mkdir(parents=True)
        script = other / "scripts" / "run.sh"
        script.write_bytes(RUN_SH)
        script.chmod(0o775)  # group-writable, as another umask would leave it
        (other / "SKILL.md").write_bytes(SKILL_MD)
        (other / "SKILL.md").chmod(0o664)
        os.utime(other / "SKILL.md", (1, 1))
        assert SkillResolver.resolve(first).digest == SkillResolver.resolve(other).digest == GOLDEN


class TestWhatMovesTheDigest:
    def test_a_changed_byte_a_renamed_file_an_added_file_and_the_executable_bit(
        self, tmp_path: Path
    ) -> None:
        seen = {GOLDEN}
        variants = {
            "content": lambda folder: (folder / "SKILL.md").write_bytes(SKILL_MD + b" "),
            "rename": lambda folder: (folder / "SKILL.md").rename(folder / "skill.md"),
            "added": lambda folder: (folder / "extra.txt").write_bytes(b""),
            "mode": lambda folder: (folder / "scripts" / "run.sh").chmod(0o644),
            "hidden": lambda folder: (folder / ".hidden").write_bytes(b"x"),
        }
        for name, change in variants.items():
            folder = Folder.deploy(tmp_path / name)
            change(folder)
            found = SkillResolver.resolve(folder)
            assert found.resolved and found.digest not in seen, name
            seen.add(str(found.digest))

    @POSIX_MODES
    def test_git_metadata_is_not_part_of_the_skill(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        (folder / ".git").mkdir()
        (folder / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main\n")
        assert SkillResolver.resolve(folder).digest == GOLDEN


class TestWhatIsRefusedNeverGivesADigestOfPartOfTheFolder:
    def test_a_symbolic_link_to_a_file(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        (folder / "link").symlink_to(tmp_path / "elsewhere")
        found = SkillResolver.resolve(folder)
        assert (found.resolved, found.reason, found.digest) == (False, "symlink", None)

    def test_a_symbolic_link_to_a_folder_is_not_followed(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_bytes(b"s")
        (folder / "out").symlink_to(outside, target_is_directory=True)
        assert SkillResolver.resolve(folder).reason == "symlink"

    def test_the_folder_itself_a_link(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        link = tmp_path / "linked-skill"
        link.symlink_to(folder, target_is_directory=True)
        assert SkillResolver.resolve(link).reason == "symlink"

    def test_a_path_that_is_not_a_folder(self, tmp_path: Path) -> None:
        (tmp_path / "file").write_bytes(b"x")
        assert SkillResolver.resolve(tmp_path / "file").reason == "not_a_folder"
        assert SkillResolver.resolve(tmp_path / "missing").reason == "not_a_folder"

    def test_a_folder_with_too_many_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Folder.deploy(tmp_path)
        monkeypatch.setattr(SkillResolver, "MAX_FILES", 1)
        assert SkillResolver.resolve(folder).reason == "too_large"

    def test_a_folder_with_too_many_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Folder.deploy(tmp_path)
        monkeypatch.setattr(SkillResolver, "MAX_BYTES", 10)
        assert SkillResolver.resolve(folder).reason == "too_large"

    def test_a_file_that_cannot_be_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        folder = Folder.deploy(tmp_path)
        real = Path.read_bytes

        def refuse(path: Path) -> bytes:
            if path.name == "SKILL.md":
                raise PermissionError(13, "denied")
            return real(path)

        monkeypatch.setattr(Path, "read_bytes", refuse)
        found = SkillResolver.resolve(folder)
        assert (found.resolved, found.reason, found.digest) == (False, "unreadable", None)

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Windows cannot hold a file name with a backslash"
    )
    def test_a_file_name_the_tree_rule_does_not_take(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        (folder / "a\\b").write_bytes(b"x")
        assert SkillResolver.resolve(folder).reason == "unsupported_path"


class TestTheSubject:
    def test_the_locator_is_the_folder_relative_to_the_root(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        assert (
            SkillResolver.resolve(folder, root=tmp_path).subject_id
            == "skill:local/.claude/skills/deploy"
        )
        assert SkillResolver.resolve(folder).subject_id == "skill:local/deploy"

    def test_a_folder_outside_the_root_is_unparseable(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path / "a")
        found = SkillResolver.resolve(folder, root=tmp_path / "b")
        assert (found.resolved, found.reason) == (False, "unparseable")


class TestTheTreeRule:
    @POSIX_MODES
    def test_the_digest_equals_the_tree_rule_over_the_same_entries(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        expected = ArtifactDigests.of_tree(
            [("scripts/run.sh", "755", RUN_SH), ("SKILL.md", "644", SKILL_MD)]
        )
        assert SkillResolver.resolve(folder).digest == expected == GOLDEN


class TestTheFolderWithoutAnExecutableBit:
    def test_the_digest_is_the_hand_computed_listing_with_every_file_at_644(
        self, tmp_path: Path
    ) -> None:
        by_hand = hashlib.sha256(
            b"SKILL.md\x00644\x00"
            + hashlib.sha256(SKILL_MD).hexdigest().encode()
            + b"\nscripts/run.sh\x00644\x00"
            + hashlib.sha256(RUN_SH).hexdigest().encode()
            + b"\n"
        ).hexdigest()
        assert "sha256:" + by_hand == GOLDEN_NO_EXECUTABLE != GOLDEN
        assert (
            SkillResolver.resolve(Folder.deploy(tmp_path, executable=False)).digest
            == GOLDEN_NO_EXECUTABLE
        )

    @pytest.mark.skipif(
        sys.platform != "win32", reason="the executable bit exists here: see TestTheGoldenFolder"
    )
    def test_on_windows_a_script_reads_as_644_whatever_chmod_was_asked(
        self, tmp_path: Path
    ) -> None:
        assert SkillResolver.resolve(Folder.deploy(tmp_path)).digest == GOLDEN_NO_EXECUTABLE


class TestWhereTheModeComesFromWhenTheFileSystemHasNoExecuteBit:
    """On Windows the mode is git's recorded mode inside a git working tree and 644 otherwise, so a checkout gives the digest a POSIX one does.

    The platform is simulated by `NO_EXEC_BIT`; the folder lives in a real git repository whose index says the script is executable while the
    file on disk is not."""

    @staticmethod
    def repository(root: Path, *, executable: bool) -> Path:
        from cordon_scanner.sources.git import GitRepository

        folder = Folder.deploy(root, executable=False)
        repo = GitRepository(root)
        repo.run(["init", "-q"])
        repo.run(["add", "-A"])
        if executable:
            repo.run(["update-index", "--chmod=+x", ".claude/skills/deploy/scripts/run.sh"])
        return folder

    @pytest.fixture(autouse=True)
    def _no_execute_bit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(SkillResolver, "NO_EXEC_BIT", True)

    def test_a_script_git_records_as_executable_gives_the_golden_digest_though_the_file_is_not(
        self, tmp_path: Path
    ) -> None:
        folder = self.repository(tmp_path, executable=True)
        assert SkillResolver.resolve(folder, root=tmp_path).digest == GOLDEN

    def test_a_script_git_records_as_not_executable_gives_the_no_executable_digest(
        self, tmp_path: Path
    ) -> None:
        folder = self.repository(tmp_path, executable=False)
        assert SkillResolver.resolve(folder, root=tmp_path).digest == GOLDEN_NO_EXECUTABLE

    def test_a_folder_outside_any_git_tree_reads_every_file_as_644(self, tmp_path: Path) -> None:
        folder = Folder.deploy(tmp_path)
        assert SkillResolver.resolve(folder, root=tmp_path).digest == GOLDEN_NO_EXECUTABLE

    def test_a_file_git_does_not_list_reads_as_644(self, tmp_path: Path) -> None:
        folder = self.repository(tmp_path, executable=True)
        (folder / "scripts" / "extra.sh").write_bytes(b"echo extra\n")
        modes = SkillResolver.recorded_modes(folder)
        assert modes == {"SKILL.md": "644", "scripts/run.sh": "755"}

    def test_git_that_cannot_be_asked_gives_no_record_not_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources.git import GitRepository

        def refuse(self: GitRepository, args: list[str], **kw: object) -> str:
            raise OSError("no git")

        monkeypatch.setattr(GitRepository, "run", refuse)
        folder = Folder.deploy(tmp_path)
        assert SkillResolver.recorded_modes(folder) == {}
        assert SkillResolver.resolve(folder, root=tmp_path).digest == GOLDEN_NO_EXECUTABLE


class TestTheSameDigestOnEveryOperatingSystem:
    """The golden digest is the one this machine's own rule gives, with no simulated platform: the CI runners for Linux, macOS and Windows
    each run this test, so one folder is one digest on all three."""

    def test_a_git_checkout_of_the_deploy_folder_gives_the_golden_digest(
        self, tmp_path: Path
    ) -> None:
        from cordon_scanner.sources.git import GitRepository

        folder = Folder.deploy(
            tmp_path
        )  # a POSIX file system keeps the execute bit on disk; Windows has none, so git's record carries it
        repo = GitRepository(tmp_path)
        repo.run(["init", "-q"])
        repo.run(["add", "-A"])
        repo.run(["update-index", "--chmod=+x", ".claude/skills/deploy/scripts/run.sh"])
        assert SkillResolver.resolve(folder, root=tmp_path).digest == GOLDEN
