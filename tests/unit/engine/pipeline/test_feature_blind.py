"""The package verdict lowers nothing for a package whose code that runs on its own it could not read (`Ceilings.feature_blind`, note 52).

The verdict model is fitted to features that leave out a file over the profile's size at an install, import or agent place, and over the
per-place file count (`decide/feature_schema.py` hashes the extractor, so the caps cannot move without a refit). A payload padded past
the size hides from the features; the model must not then hold the package's findings as a warning. Inert text: a few lines of JavaScript
and comment padding, never run.
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
    def severity(tmp_path: Path, files: dict[str, str]) -> Severity:
        """The grade of the hook finding for a package whose hook is a dependency's program (held as a warning when small)."""
        manifest = {
            "name": "p",
            "version": "1.0.0",
            "scripts": {"postinstall": "bip40"},
            "dependencies": {"bip40": "^1.0.0"},
        }
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
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        return max(f.severity for f in found if f.rule_id == RULE)


class TestWhatTheModelCouldNotRead:
    def test_a_place_file_over_the_profile_size_is_blind(self) -> None:
        units = [Kit.unit("package/install.js", PROFILE_BYTES + 1)]
        assert Ceilings.feature_blind(units, Kit.ctx(entry=("package/install.js",))) == 1

    @pytest.mark.parametrize("place", ["hook", "entry", "imported", "agent"])
    def test_each_place_counts(self, place: str) -> None:
        units = [Kit.unit("package/a.js", PROFILE_BYTES + 1)]
        assert Ceilings.feature_blind(units, Kit.ctx(**{place: ("package/a.js",)})) == 1

    def test_a_file_at_the_size_is_read(self) -> None:
        units = [Kit.unit("package/install.js", PROFILE_BYTES)]
        assert Ceilings.feature_blind(units, Kit.ctx(entry=("package/install.js",))) == 0

    def test_a_large_file_no_place_names_is_not(self) -> None:
        units = [Kit.unit("package/dist/bundle.js", 5_000_000)]
        assert Ceilings.feature_blind(units, Kit.ctx(entry=("package/install.js",))) == 0

    def test_files_past_the_per_place_count_are_blind(self) -> None:
        names = tuple(f"package/f{i}.js" for i in range(ReachedFlows.FILES + 3))
        units = [Kit.unit(n, 100) for n in names]
        assert Ceilings.feature_blind(units, Kit.ctx(imported=names)) == 3

    def test_a_small_package_is_not(self) -> None:
        units = [Kit.unit("package/index.js", 20)]
        assert Ceilings.feature_blind(units, Kit.ctx(imported=("package/index.js",))) == 0


class TestTheVerdictLowersNothingForIt:
    def test_a_small_package_is_held_as_a_warning(self, tmp_path: Path) -> None:
        # The control: the verdict does lower this hook's grade when it could read everything.
        assert Kit.severity(tmp_path, {"index.js": "module.exports = 1;\n"}) < Severity.HIGH

    def test_a_blind_package_keeps_the_rules_grade(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Ceilings, "feature_blind", staticmethod(lambda units, ctx: 1))
        assert Kit.severity(tmp_path, {"index.js": "module.exports = 1;\n"}) >= Severity.HIGH

    def test_the_verdict_says_why(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Ceilings, "feature_blind", staticmethod(lambda units, ctx: 2))
        manifest = {
            "name": "p",
            "version": "1.0.0",
            "scripts": {"postinstall": "bip40"},
            "dependencies": {"bip40": "^1.0.0"},
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("package/package.json", json.dumps(manifest)),
                ("package/index.js", "module.exports = 1;\n"),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        verdict = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).verdict
        assert verdict["lift_withheld"] == 2


class TestAPaddedFileAtAnInstallPlace:
    """The shape of the evasion, end to end: the model adds a block for a package that spawns a program and reaches the network, and padding
    the file past the profile's size takes the block away, because its capabilities are no longer features. Fixed by a refit at the new
    schema, or by a block for the unread file (the lead's decision, note 52 section 7): until then the case is pinned as a known gap."""

    CODE = "const cp = require('child_process');\ncp.spawnSync('make', ['build']);\nfetch('https://t.example.invalid/ping');\n"

    @staticmethod
    def blocked(tmp_path: Path, text: str) -> bool:
        manifest = {"name": "p", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, body in (
                ("package/package.json", json.dumps(manifest)),
                ("package/index.js", "module.exports = 1;\n"),
                ("package/install.js", text),
            ):
                data = body.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings
        return any(f.severity >= Severity.HIGH for f in found)

    def test_the_small_file_is_blocked(self, tmp_path: Path) -> None:
        assert self.blocked(tmp_path, self.CODE)

    @pytest.mark.xfail(
        strict=True,
        reason="the profile's size cap is fitted into the verdict model: refit at the new schema or block the unread file",
    )
    def test_the_padded_file_must_stay_blocked(self, tmp_path: Path) -> None:
        assert self.blocked(tmp_path, Padding.lines(1_300_000) + self.CODE)
