"""A package whose code that runs on its own the verdict model could not read is incomplete, and the model lowers nothing for it
(`Ceilings.feature_blind`, note 52).

The verdict model is fitted to features that leave out a file over the profile's size at an install, import or agent place, and over the
per-place file count (`decide/feature_schema.py` hashes the extractor, so the caps cannot move without a refit). A payload padded past
the size is invisible to the features: the model neither adds the block it would add nor may it hold the findings as a warning, and its
silence is never a pass: the scan is incomplete, an operational gap that blocks by default. Inert text: a few lines of JavaScript and
comment padding, never run.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.detect.code.reached_flows import ReachedFlows
from cordon_scanner.engine.isolation.analysis_facts import PROFILE_BYTES
from cordon_scanner.engine.pipeline.ceilings import Ceilings
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.models import Severity
from kits.padding import Padding

RULE = "SUSPECT.INSTALL.SCRIPT.001"
NOTE = "OPERATIONAL.FILE.TRUNCATED"


class Kit:
    @staticmethod
    def unit(path: str, size: int) -> FileUnit:
        return FileUnit(content=FileContent(path=path, raw=b"x", size=size))

    @staticmethod
    def ctx(
        hook: tuple[str, ...] = (),
        entry: tuple[str, ...] = (),
        imported: tuple[str, ...] = (),
        agent: tuple[str, ...] = (),
    ) -> SimpleNamespace:
        return SimpleNamespace(
            install_hook_paths=frozenset(hook),
            install_entry_paths=frozenset(entry),
            import_entry_paths=frozenset(imported),
            agent_run_paths=frozenset(agent),
        )

    @staticmethod
    def scan(
        tmp_path: Path,
        scripts: dict[str, str],
        files: dict[str, str],
        deps: dict[str, str] | None = None,
    ):
        manifest = {"name": "p", "version": "1.0.0", "scripts": scripts}
        if deps:
            manifest["dependencies"] = deps
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("package/package.json", json.dumps(manifest)),
                *(("package/" + k, v) for k, v in files.items()),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(target)

    @staticmethod
    def hook_grade(tmp_path: Path) -> Severity:
        """The grade of the hook finding for a package whose hook is a dependency's program (held as a warning when small)."""
        result = Kit.scan(
            tmp_path,
            {"postinstall": "bip40"},
            {"index.js": "module.exports = 1;\n"},
            {"bip40": "^1.0.0"},
        )
        return max(f.severity for f in result.findings if f.rule_id == RULE)


class TestWhatTheModelCouldNotRead:
    def test_a_place_file_over_the_profile_size_is_blind(self) -> None:
        units = [Kit.unit("package/install.js", PROFILE_BYTES + 1)]
        blind = Ceilings.feature_blind(units, Kit.ctx(entry=("package/install.js",)))
        assert [path for path, _why in blind] == ["package/install.js"]

    @pytest.mark.parametrize("place", ["hook", "entry", "imported", "agent"])
    def test_each_place_counts(self, place: str) -> None:
        units = [Kit.unit("package/a.js", PROFILE_BYTES + 1)]
        assert len(Ceilings.feature_blind(units, Kit.ctx(**{place: ("package/a.js",)}))) == 1

    def test_a_file_at_the_size_is_read(self) -> None:
        units = [Kit.unit("package/install.js", PROFILE_BYTES)]
        assert Ceilings.feature_blind(units, Kit.ctx(entry=("package/install.js",))) == []

    def test_a_large_file_no_place_names_is_not(self) -> None:
        units = [Kit.unit("package/dist/bundle.js", 5_000_000)]
        assert Ceilings.feature_blind(units, Kit.ctx(entry=("package/install.js",))) == []

    def test_the_file_past_the_per_place_count_is_blind(self) -> None:
        names = tuple(f"package/f{i}.js" for i in range(ReachedFlows.FILES + 1))
        units = [Kit.unit(n, 100) for n in names]
        blind = Ceilings.feature_blind(units, Kit.ctx(imported=names))
        assert [path for path, _why in blind] == [names[-1]]
        assert "first" in blind[0][1]

    def test_files_past_the_per_place_count_are_all_blind(self) -> None:
        names = tuple(f"package/f{i}.js" for i in range(ReachedFlows.FILES + 3))
        units = [Kit.unit(n, 100) for n in names]
        assert len(Ceilings.feature_blind(units, Kit.ctx(imported=names))) == 3

    def test_an_oversize_file_does_not_use_up_the_count(self) -> None:
        # The profile skips an oversize file without counting it: fifty small ones are still all read.
        names = tuple(f"package/f{i}.js" for i in range(ReachedFlows.FILES + 1))
        units = [
            Kit.unit("package/big.js", PROFILE_BYTES + 1),
            *(Kit.unit(n, 100) for n in names[:-1]),
        ]
        blind = Ceilings.feature_blind(units, Kit.ctx(imported=("package/big.js", *names)))
        assert [path for path, _why in blind] == ["package/big.js"]

    def test_a_small_package_is_not(self) -> None:
        units = [Kit.unit("package/index.js", 20)]
        assert Ceilings.feature_blind(units, Kit.ctx(imported=("package/index.js",))) == []

    def test_the_note_is_a_gap_that_names_the_file(self) -> None:
        note = Ceilings.blind_note("package/install.js", "it is over the size")
        assert note.rule_id == NOTE
        assert note.location.path == "package/install.js"
        assert "incomplete" in note.message


class TestTheVerdictLowersNothingForIt:
    def test_a_small_package_is_held_as_a_warning(self, tmp_path: Path) -> None:
        # The control: the verdict does lower this hook's grade when it could read everything.
        assert Kit.hook_grade(tmp_path) < Severity.HIGH

    def test_a_blind_package_keeps_the_rules_grade(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            Ceilings, "feature_blind", staticmethod(lambda units, ctx: [("package/index.js", "x")])
        )
        assert Kit.hook_grade(tmp_path) >= Severity.HIGH

    def test_the_verdict_says_how_many(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        both = [("package/index.js", "x"), ("package/b.js", "y")]
        monkeypatch.setattr(Ceilings, "feature_blind", staticmethod(lambda units, ctx: both))
        result = Kit.scan(
            tmp_path,
            {"postinstall": "bip40"},
            {"index.js": "module.exports = 1;\n"},
            {"bip40": "^1.0.0"},
        )
        assert result.verdict["lift_withheld"] == 2


class TestAPaddedFileAtAnInstallPlace:
    """The evasion, end to end: the model adds a block for a package that spawns a program and reaches the network at an install place
    (0.67, `SUSPECT.VERDICT.MODEL.001`); behind 1.3 MB of comments the same code scored 0.16 and nothing was reported, because the file's
    capabilities were not features. Now the unread file is a gap: the scan is incomplete and says which file."""

    CODE = "const cp = require('child_process');\ncp.spawnSync('make', ['build']);\nfetch('https://t.example.invalid/ping');\n"

    @staticmethod
    def scan(tmp_path: Path, text: str):
        return Kit.scan(
            tmp_path,
            {"postinstall": "node install.js"},
            {"index.js": "module.exports = 1;\n", "install.js": text},
        )

    def test_the_small_file_is_blocked_and_complete(self, tmp_path: Path) -> None:
        result = self.scan(tmp_path, self.CODE)
        assert any(f.severity >= Severity.HIGH for f in result.findings)
        assert result.content_complete

    def test_the_padded_file_makes_the_scan_incomplete(self, tmp_path: Path) -> None:
        result = self.scan(tmp_path, Padding.lines(1_300_000) + self.CODE)
        assert not result.content_complete
        notes = [
            f
            for f in result.findings
            if f.rule_id == NOTE and "package verdict could not read" in f.message
        ]
        assert [f.location.path.rsplit("/", 1)[-1] for f in notes] == ["install.js"]

    def test_a_large_file_the_hook_does_not_run_does_not(self, tmp_path: Path) -> None:
        result = Kit.scan(
            tmp_path,
            {"postinstall": "node install.js"},
            {
                "index.js": "module.exports = 1;\n",
                "install.js": self.CODE,
                "docs/big.js": Padding.lines(1_300_000),
            },
        )
        assert not [f for f in result.findings if "package verdict could not read" in f.message]
