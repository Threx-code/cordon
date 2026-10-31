"""An archive scan applies the operator's suppressions and the folds over repeated findings, as a
directory scan does (`ResultFolding.settled`): a package is not graded one way packed and another
unpacked. Before, `ArchiveStages.verdict` skipped both."""

from __future__ import annotations

import io
import tarfile
from dataclasses import replace
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.formats.restricted_yaml import RestrictedYamlParser

MARK = "CORDON-SETTLE-PROBE-0001"


class Kit:
    @staticmethod
    def package(root: Path) -> tuple[Path, Path]:
        """The same package, as a directory and as the tarball npm would publish."""
        files = {
            "package/package.json": b'{"name": "settle-probe", "version": "1.0.0"}',
            "package/index.js": f"module.exports = '{MARK}';\n".encode(),
        }
        unpacked = root / "unpacked"
        for name, data in files.items():
            path = unpacked / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        tarball = root / "settle-probe-1.0.0.tgz"
        with tarfile.open(tarball, "w:gz") as tf:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return unpacked / "package", tarball

    @staticmethod
    def config(root: Path, suppress: str | None) -> Config:
        rules = root / "r.yar"
        rules.write_text(f'rule probe {{ strings: $m = "{MARK}" condition: $m }}', encoding="utf-8")
        text = ""
        if suppress is not None:
            text = (
                "suppressions:\n"
                "  - rule: SUSPECT.RULEFILE.MATCH.001\n"
                f"    path: {suppress}\n"
                f"    justification: {'a probe accepted for this test ' * 2}\n"
                "    expires: 2099-01-01\n"
            )
        config = Config.from_dict(
            RestrictedYamlParser._load_yaml_subset(text, source="t") if text else {}, source="t"
        )
        return replace(config, rule_file=str(rules), offline=True)

    @staticmethod
    def probe(result: object) -> object:
        return next(
            f
            for f in result.findings
            if f.rule_id == "SUSPECT.RULEFILE.MATCH.001"  # type: ignore[attr-defined]
        )


class TestAnArchiveIsSettledAsADirectory:
    def test_the_operators_suppression_applies_to_the_archive(self, tmp_path: Path) -> None:
        """The member named as it is within the archive, the path it has unpacked."""
        _, tarball = Kit.package(tmp_path)
        result = Scanner(Kit.config(tmp_path, "package/index.js")).scan(tarball)
        assert Kit.probe(result).suppressed is not None  # type: ignore[attr-defined]

    def test_without_one_the_finding_stands(self, tmp_path: Path) -> None:
        _, tarball = Kit.package(tmp_path)
        result = Scanner(Kit.config(tmp_path, None)).scan(tarball)
        assert Kit.probe(result).suppressed is None  # type: ignore[attr-defined]

    def test_the_same_suppression_covers_the_package_unpacked(self, tmp_path: Path) -> None:
        unpacked, _ = Kit.package(tmp_path)
        result = Scanner(Kit.config(tmp_path, "index.js")).scan(unpacked)
        assert Kit.probe(result).suppressed is not None  # type: ignore[attr-defined]
