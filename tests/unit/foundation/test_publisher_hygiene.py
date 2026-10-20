"""A published package's own repository hygiene is its publisher's (review 98, FP-8)."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity

WORKFLOW = (
    "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: some-org/deploy-action@v1\n      - run: npm test\n"
)


class HygieneKit:
    @staticmethod
    def policy(target: Path) -> list:
        # INFO is below the default reporting threshold; shown here so the demotion is visible.
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        result = Scanner(config).scan(target)
        return [f for f in result.findings if f.rule_id == "POLICY.CI.UNPINNED_ACTION.001"]


class TestPublisherHygiene:
    def test_in_a_published_package_it_is_info(self, tmp_path: Path) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in (
                ("p-1.0.0/PKG-INFO", "Metadata-Version: 2.1\nName: p\nVersion: 1.0.0\n"),
                ("p-1.0.0/.github/workflows/ci.yml", WORKFLOW),
            ):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tar.gz"
        target.write_bytes(buffer.getvalue())
        found = HygieneKit.policy(target)
        assert found and all(f.severity is Severity.INFO for f in found)

    def test_in_a_repository_it_keeps_its_grade(self, tmp_path: Path) -> None:
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW, encoding="utf-8")
        found = HygieneKit.policy(tmp_path)
        assert found and any(f.severity > Severity.INFO for f in found)
