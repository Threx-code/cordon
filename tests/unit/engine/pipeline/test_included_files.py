"""A file a manifest includes (pip's `-r` and `-c`, a Go workspace's modules) is never dropped
unsaid: one whose parse raises, and one past the include depth, is said once as
OPERATIONAL.PARSER.FAILED, a content cause, so the scan blocks (item 26; design note
26-included-files.md). Before, `Graph.included` skipped either with nothing recorded, and every
dependency declared there went unchecked in a complete scan."""

from __future__ import annotations

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.ecosystems.packages.pypi import PypiEcosystem
from cordon_scanner.engine.pipeline.graph import Graph
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import ExitCode


class IncludeKit:
    @staticmethod
    def scan(root):
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(root)

    @staticmethod
    def failed_at(result) -> set[str]:
        return {
            f.location.path for f in result.findings if f.rule_id == "OPERATIONAL.PARSER.FAILED"
        }


class TestAnIncludedFileIsNeverDroppedUnsaid:
    def test_an_include_whose_parse_raises_blocks(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "requirements.txt").write_text(
            "-r extra.txt\nrequests==2.31.0\n", encoding="utf-8"
        )
        (tmp_path / "extra.txt").write_text("leftpad==1.0\n", encoding="utf-8")
        real = PypiEcosystem.parse_included

        def parse_included(self, content):
            if content.path.endswith("extra.txt"):
                raise ValueError("an include the parser cannot read")
            return real(self, content)

        monkeypatch.setattr(PypiEcosystem, "parse_included", parse_included)
        result = IncludeKit.scan(tmp_path)
        assert "extra.txt" in IncludeKit.failed_at(result)
        assert result.content_complete is False
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.INCOMPLETE

    def test_an_include_past_the_depth_bound_blocks(self, tmp_path) -> None:
        depth = Graph.MAX_INCLUDE_DEPTH + 2
        (tmp_path / "requirements.txt").write_text("-r r1.txt\n", encoding="utf-8")
        for i in range(1, depth + 1):
            nested = f"-r r{i + 1}.txt\n" if i < depth else ""
            (tmp_path / f"r{i}.txt").write_text(f"{nested}pkg{i}==1.0\n", encoding="utf-8")
        result = IncludeKit.scan(tmp_path)
        assert IncludeKit.failed_at(result), (
            "an include past the depth bound was not followed, and nothing said so"
        )
        assert result.content_complete is False
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.INCOMPLETE

    @staticmethod
    def chain(tmp_path, length: int, last: str | None) -> None:
        """requirements.txt -> r1.txt -> ... -> r{length}.txt, the last including `last`."""
        (tmp_path / "requirements.txt").write_text("-r r1.txt\n", encoding="utf-8")
        for i in range(1, length + 1):
            nested = f"-r r{i + 1}.txt\n" if i < length else (f"-r {last}\n" if last else "")
            (tmp_path / f"r{i}.txt").write_text(f"{nested}pkg{i}==1.0\n", encoding="utf-8")

    def test_a_cycle_at_the_bound_blocks_nothing(self, tmp_path) -> None:
        # The last file at the bound includes one already read: nothing went unread.
        self.chain(tmp_path, Graph.MAX_INCLUDE_DEPTH, "r1.txt")
        result = IncludeKit.scan(tmp_path)
        assert not IncludeKit.failed_at(result)
        assert result.content_complete is True

    def test_leaving_the_tree_at_the_bound_is_as_below_it(self, tmp_path) -> None:
        deep, shallow = tmp_path / "deep", tmp_path / "shallow"
        deep.mkdir()
        shallow.mkdir()
        self.chain(deep, Graph.MAX_INCLUDE_DEPTH, "../x.txt")
        self.chain(shallow, 3, "../x.txt")
        a, b = IncludeKit.scan(deep), IncludeKit.scan(shallow)
        assert (IncludeKit.failed_at(a), a.content_complete) == (
            IncludeKit.failed_at(b),
            b.content_complete,
        )

    def test_a_real_file_past_the_bound_still_blocks(self, tmp_path) -> None:
        self.chain(tmp_path, Graph.MAX_INCLUDE_DEPTH + 1, None)
        result = IncludeKit.scan(tmp_path)
        assert IncludeKit.failed_at(result)
        assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.INCOMPLETE

    def test_a_pinned_requirements_file_still_follows_its_includes(self, tmp_path) -> None:
        # Fully pinned, so read as a lockfile and its project counted as covered: its `-r` was
        # never followed, and base.txt's evilpkg went unchecked in a complete scan.
        (tmp_path / "requirements.txt").write_text(
            "-r base.txt\nrequests==2.31.0\n", encoding="utf-8"
        )
        (tmp_path / "base.txt").write_text("evilpkg==1.0\n", encoding="utf-8")
        result = IncludeKit.scan(tmp_path)
        names = {d.name for d in result.dependencies}
        assert {"requests", "evilpkg"} <= names

    def test_a_valid_chain_records_nothing_new(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "-r base.txt\nrequests==2.31.0\n", encoding="utf-8"
        )
        (tmp_path / "base.txt").write_text("-c constraints.txt\nurllib3==2.0.7\n", encoding="utf-8")
        (tmp_path / "constraints.txt").write_text("idna==3.6\n", encoding="utf-8")
        result = IncludeKit.scan(tmp_path)
        assert not IncludeKit.failed_at(result)
        assert result.content_complete is True
        names = {d.name for d in result.dependencies}
        assert {"requests", "urllib3"} <= names
