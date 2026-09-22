"""The generated policy set has to be accounted for, and has to be current.

A data file that decides what a scan reports can be edited, and an edit that
removes a policy leaves a scan that is green with a count that still looks
healthy. That is the argument `intel/advisories.py` makes for its own digest
manifest, and it applies here for the same reason: this set is five times the
size of the hand-written table and nobody reads it.
"""

from __future__ import annotations

import gzip
import json

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.detect import iac_policies
from cordon_scanner.detect.iac_policies import (
    DATA_DIR,
    GENERATED_DIGESTS,
    GENERATED_META,
    GENERATED_NAME,
)

TERRAFORM = 'resource "aws_db_instance" "main" {\n  identifier = "prod"\n}\n'


@pytest.fixture
def clean_caches():
    """The loaders are process-cached, which these tests deliberately defeat."""
    iac_policies.generated_rows.cache_clear()
    iac_policies.generated_meta.cache_clear()
    iac_policies._REFUSED.clear()
    yield
    iac_policies.generated_rows.cache_clear()
    iac_policies.generated_meta.cache_clear()
    iac_policies._REFUSED.clear()


class TestTheManifestShips:
    def test_every_generated_file_is_recorded(self) -> None:
        recorded = json.loads((DATA_DIR / GENERATED_DIGESTS).read_text(encoding="utf-8"))
        present = {p.name for p in DATA_DIR.glob("iac-policies*") if p.name != GENERATED_DIGESTS}
        assert set(recorded) == present

    def test_the_recorded_digests_are_the_files(self) -> None:
        import hashlib

        recorded = json.loads((DATA_DIR / GENERATED_DIGESTS).read_text(encoding="utf-8"))
        for name, digest in recorded.items():
            actual = hashlib.sha256((DATA_DIR / name).read_bytes()).hexdigest()
            assert actual == digest, f"{name} does not match the manifest shipped with it"

    def test_the_set_records_when_it_was_built(self) -> None:
        meta = json.loads((DATA_DIR / GENERATED_META).read_text(encoding="utf-8"))
        assert meta.get("built_at"), "no build date: a scan cannot say how old this is"


class TestAnEditedSetIsRefused:
    """Half a policy set is worse than none: the count still looks healthy."""

    def test_a_changed_file_is_not_loaded(self, tmp_path, monkeypatch, clean_caches) -> None:
        tampered = tmp_path / "data"
        tampered.mkdir()
        rows = json.loads(gzip.decompress((DATA_DIR / GENERATED_NAME).read_bytes()))
        with gzip.GzipFile(tampered / GENERATED_NAME, "wb", mtime=0) as handle:
            handle.write(json.dumps(rows[:10]).encode("utf-8"))
        (tampered / GENERATED_DIGESTS).write_text(
            (DATA_DIR / GENERATED_DIGESTS).read_text(encoding="utf-8"), encoding="utf-8"
        )
        monkeypatch.setattr(iac_policies, "DATA_DIR", tampered)

        assert iac_policies.generated_rows() == {}
        assert GENERATED_NAME in iac_policies.refused_files()

    def test_the_scan_reports_the_refusal_and_calls_itself_partial(
        self, tmp_path, monkeypatch, clean_caches
    ) -> None:
        tampered = tmp_path / "data"
        tampered.mkdir()
        with gzip.GzipFile(tampered / GENERATED_NAME, "wb", mtime=0) as handle:
            handle.write(b"[]")
        (tampered / GENERATED_DIGESTS).write_text(
            json.dumps({GENERATED_NAME: "0" * 64}), encoding="utf-8"
        )
        monkeypatch.setattr(iac_policies, "DATA_DIR", tampered)

        project = tmp_path / "repo"
        project.mkdir()
        (project / "main.tf").write_text(TERRAFORM, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(project)

        assert "OPERATIONAL.IAC.POLICIES_REFUSED" in {f.rule_id for f in result.findings}
        assert result.complete is False

    def test_an_absent_manifest_is_not_a_refusal(self, tmp_path, monkeypatch, clean_caches) -> None:
        """A checkout that never ran the generator has neither file."""
        empty = tmp_path / "data"
        empty.mkdir()
        monkeypatch.setattr(iac_policies, "DATA_DIR", empty)
        assert iac_policies.generated_rows() == {}
        assert iac_policies.refused_files() == ()


class TestAStaleSetSaysSo:
    def test_an_old_build_is_reported(self, tmp_path, monkeypatch, clean_caches) -> None:
        aged = tmp_path / "data"
        aged.mkdir()
        for name in (GENERATED_NAME, GENERATED_DIGESTS):
            (aged / name).write_bytes((DATA_DIR / name).read_bytes())
        meta = json.loads((DATA_DIR / GENERATED_META).read_text(encoding="utf-8"))
        meta["built_at"] = "2020-01-01T00:00:00Z"
        (aged / GENERATED_META).write_text(json.dumps(meta), encoding="utf-8")
        monkeypatch.setattr(iac_policies, "DATA_DIR", aged)

        project = tmp_path / "repo"
        project.mkdir()
        (project / "main.tf").write_text(TERRAFORM, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(project)

        stale = [f for f in result.findings if f.rule_id == "OPERATIONAL.IAC.POLICIES_STALE"]
        assert len(stale) == 1
        assert "provider schemas" in stale[0].message

    def test_the_shipped_set_is_not_stale(self, clean_caches) -> None:
        """If this fails, the set needs regenerating before the release."""
        from datetime import UTC, datetime

        from cordon_scanner.detect.iac import STALE_AFTER_DAYS

        built = datetime.fromisoformat(
            str(iac_policies.generated_meta()["built_at"]).replace("Z", "+00:00")
        )
        assert (datetime.now(UTC) - built).days <= STALE_AFTER_DAYS

    def test_a_repository_with_no_infrastructure_hears_nothing(self, tmp_path) -> None:
        """A note about infrastructure policy on a repository with none is a
        line every reader learns to skip."""
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert not [f for f in result.findings if f.rule_id.startswith("OPERATIONAL.IAC.")]
