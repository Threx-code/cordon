"""`scripts/checks/stale_reasons.py`: every dated reason is found, and one older than the limit fails the recheck.

Every case passes its own `today`: nothing here depends on the date the suite runs."""

from __future__ import annotations

import datetime
import importlib.util
from pathlib import Path

from support import ROOT


class Kit:
    @staticmethod
    def module():
        spec = importlib.util.spec_from_file_location(
            "stale_reasons", ROOT / "scripts/checks/stale_reasons.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.StaleReasons

    @staticmethod
    def tree(tmp_path: Path, text: str) -> Path:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "reasons.py").write_text(text, encoding="utf-8")
        record = tmp_path / "tests/unit/ecosystems/coverage"
        record.mkdir(parents=True)
        (record / "narrow_sites.json").write_text(
            '[{"site": "x", "ids": ["npm"], "reason": "read on 2026-02-01: the dataset has npm only"}]',
            encoding="utf-8",
        )
        return tmp_path


class TestStaleReasons:
    TEXT = (
        'A = "no signature was found (checked 2026-11-25)"\nB = "checked 2026-01-10 on the docs"\n'
    )

    def test_every_dated_reason_is_found(self, tmp_path: Path) -> None:
        found = Kit.module().dated(Kit.tree(tmp_path, self.TEXT))
        assert sorted(d.isoformat() for _, _, d in found) == [
            "2026-01-10",
            "2026-02-01",
            "2026-11-25",
        ]

    def test_only_a_reason_past_the_limit_is_stale(self, tmp_path: Path) -> None:
        root = Kit.tree(tmp_path, self.TEXT)
        stale = Kit.module().stale(root, datetime.date(2026, 6, 1), 120)
        assert [d.isoformat() for _, _, d in stale] == ["2026-01-10"]

    def test_a_fresh_tree_passes(self, tmp_path: Path) -> None:
        root = Kit.tree(tmp_path, 'A = "checked 2026-11-25"\n')
        assert Kit.module().stale(root, datetime.date(2026, 3, 1), 120) == []

    def test_the_real_tree_holds_dated_reasons(self) -> None:
        assert Kit.module().dated(ROOT), "no dated reason was found in the source"
