"""One file matched by several processes at once (`detect/binary/rule_pool`): the answer is the
serial answer, match for match and string for string; the file's bounds are the file's, summed over
the shares; a worker's refusal refuses the file. Workers are real processes started with spawn."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places
from cordon_scanner.detect.binary.rule_engine.lang import RuleError
from cordon_scanner.detect.binary.rule_files import RuleFileEngine
from cordon_scanner.detect.binary.rule_pool import RulePool

RULES = "\n".join(
    [
        "global rule g { condition: filesize > 10 }",
        'rule a { strings: $a = "alpha" condition: #a > 2 }',
        'rule b { strings: $b = "bravo" condition: $b and a }',
        'rule c_one { strings: $c = "charlie" condition: $c }',
        "rule c_two { strings: $d = { 64 65 6C 74 61 } condition: @d[1] > 0 }",
        "rule any_c { condition: any of (c_*) }",
        *(
            f'rule r{i} {{ strings: $s = "tok{i:03d}" nocase wide ascii condition: $s }}'
            for i in range(40)
        ),
    ]
)


class Kit:
    @staticmethod
    def engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workers: int = 3) -> RuleFileEngine:
        monkeypatch.setattr(RulePool, "MIN_RULES", 2)
        path = tmp_path / "r.yar"
        path.write_text(RULES, encoding="utf-8")
        return RuleFileEngine(str(path), use_cache=False, workers=workers)

    @staticmethod
    def data() -> bytes:
        parts = [
            b"alpha " * 5,
            b"bravo ",
            b"charlie ",
            b"delta ",
            b"TOK007 ",
            "tok012".encode("utf-16-le"),
        ]
        return b"x" * (RulePool.LARGE + 7) + b" ".join(parts) * 3


class TestThePool:
    def test_the_pool_answers_as_the_serial_match(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        engine = Kit.engine(tmp_path, monkeypatch)
        try:
            assert engine.pool is not None and len(engine.pool.shares) == 3
            data = Kit.data()
            serial = engine.rules.match(data, given=engine.given)
            pooled = engine.pool.match(data, 60.0)
            assert [m.rule for m in pooled] == [m.rule for m in serial]
            assert pooled == serial
            assert {"g", "a", "b", "c_one", "c_two", "any_c", "r7", "r12"} <= {
                m.rule for m in pooled
            }
        finally:
            engine.pool.close() if engine.pool else None

    def test_the_files_bound_is_summed_over_the_shares(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each share stays under the bound on its own; together they pass it, so the file is
        refused, as one serial match would have refused it."""
        engine = Kit.engine(tmp_path, monkeypatch)
        try:
            assert engine.pool is not None
            data = Kit.data()
            spent: dict[str, int] = {}
            engine.rules.match(data, given=engine.given, spent=spent)
            monkeypatch.setattr(Places, "MOST", spent["places"] - 1)  # the parent's bound only
            with pytest.raises(RuleError):
                engine.pool.match(data, 60.0)
        finally:
            engine.pool.close() if engine.pool else None

    def test_a_workers_refusal_refuses_the_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A worker that runs out of the time allowed refuses the file, as the serial match does."""
        engine = Kit.engine(tmp_path, monkeypatch)
        try:
            assert engine.pool is not None
            with pytest.raises(RuleError):
                engine.pool.match(Kit.data() * 8, 1e-9)
        finally:
            engine.pool.close() if engine.pool else None

    def test_one_worker_or_a_small_file_takes_the_serial_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert Kit.engine(tmp_path, monkeypatch, workers=1).pool is None
        engine = Kit.engine(tmp_path, monkeypatch)
        try:
            assert engine.match(b"alpha alpha alpha and some more") == engine.rules.match(
                b"alpha alpha alpha and some more", given=engine.given
            )
            assert engine.pool is not None and engine.pool._executor is None  # never started
        finally:
            engine.pool.close() if engine.pool else None
