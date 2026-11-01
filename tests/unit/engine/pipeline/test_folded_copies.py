"""engine.pipeline.results: identical copies fold into one finding naming every copy, and folding
never becomes a hiding place. An operator suppressing one copy (a vendored fixture), or accepting one
copy's gap, leaves every other copy blocking, named, in a directory scan and an archive scan alike."""

from __future__ import annotations

import io
import tarfile
from datetime import date, timedelta

import pytest

from cordon_scanner import Config, Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.foundation.models import Suppression

DECODE = "b64" + "decode"  # spelled apart so this file is not itself a decode-then-run
PLANT = (
    "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
    f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
).encode()
RULE = "SUSPECT.DECODE_EXEC.001"


class Copies:
    """Two byte-identical files, as a directory or as one archive's members."""

    NAMES = ("pkg/a.py", "pkg/b.py")  # pkg/a.py sorts first: the copy a fold keeps

    @staticmethod
    def directory(tmp_path, data: bytes = PLANT, names: tuple[str, ...] = NAMES):
        root = tmp_path / "tree"
        for name in names:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)
        return root, ""

    @staticmethod
    def archive(tmp_path, data: bytes = PLANT, names: tuple[str, ...] = NAMES):
        path = tmp_path / "copies-1.0.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name in names:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path, "copies-1.0.tar.gz!"

    @staticmethod
    def suppression(rule: str, path: str) -> Suppression:
        return Suppression(
            rule=rule,
            path=path,
            justification="a vendored test fixture, reviewed and not shipped to installs",
            expires=(date.today() + timedelta(days=30)).isoformat(),
            approved_by="security@example.org",
        )

    @staticmethod
    def scan(target, config: Config):
        result = Scanner(config).scan(target)
        return result, PolicyGate.evaluate(result, config.policy)


class TestASuppressedCopyHidesNoOther:
    @pytest.mark.parametrize("make", [Copies.directory, Copies.archive])
    def test_the_other_copy_still_blocks_and_is_named(self, tmp_path, make) -> None:
        target, prefix = make(tmp_path)
        config = Config.default().with_overrides(use_cache=False)
        config = config.with_overrides(
            suppressions=(Copies.suppression(RULE, prefix + Copies.NAMES[0]),)
        )
        result, verdict = Copies.scan(target, config)
        live = {
            f.location.path for f in result.findings if f.rule_id == RULE and not f.is_suppressed
        }
        # before: the fold kept the suppressed first copy, so the other was hidden with it
        assert live == {prefix + Copies.NAMES[1]}
        assert verdict.exit_code is not ExitCode.CLEAN
