"""Published packages' install hooks that run a popular build tool, the package's own install, a
file operation inside the package, or a message (review 98, the benign long tail's remaining
install-script blocks). The evasions keep the shape and change what actually runs."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity

RULE = "SUSPECT.INSTALL.SCRIPT.001"


class HookKit:
    @staticmethod
    def findings(tmp_path: Path, scripts: dict[str, str], deps: dict[str, str] | None = None):
        manifest = {"name": "p", "version": "1.0.0", "scripts": scripts}
        if deps:
            manifest["dependencies"] = deps
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
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return [f for f in result.findings if f.rule_id == RULE]


class TestBuildStepsAreNotBlocked:
    @pytest.mark.parametrize(
        ("scripts", "deps"),
        [
            ({"postinstall": "gulp"}, {"gulp": "^4.0.0"}),
            ({"install": "coffee -c ."}, {"coffee-script": "~1.12.0"}),
            (
                {"postinstall": "node_modules/.bin/webpack src/web.js > build/out.js"},
                {"webpack": "^5.0.0"},
            ),
            ({"postinstall": "umi generate tmp"}, {"umi": "^3.0.0"}),
            ({"postinstall": "npx jetify"}, {"jetifier": "^2.0.0"}),
            ({"postinstall": "cd client && npm install && cd .."}, None),
            ({"install": "(cd node_modules/theme && npm install)"}, None),
            ({"postinstall": "chmod u+x ffmpeg"}, None),
            ({"postinstall": "touch ./node_modules/marker"}, None),
            ({"postinstall": "rm -rf dist/"}, None),
            ({"postinstall": "cat index.json"}, None),
            ({"postinstall": "node -e \"console.log('installed! Run: npx setup-i18n')\""}, None),
        ],
    )
    def test_nothing_blocks(self, tmp_path: Path, scripts: dict, deps: dict | None) -> None:
        found = HookKit.findings(tmp_path, scripts, deps)
        assert all(f.severity < Severity.HIGH for f in found), [f.severity for f in found]

    def test_a_pack_hook_is_author_time(self, tmp_path: Path) -> None:
        found = HookKit.findings(tmp_path, {"postpack": 'rm -rf dist && node -e "x()"'})
        assert all(f.severity < Severity.HIGH for f in found)


class TestWhatStillBlocks:
    @pytest.mark.parametrize(
        ("scripts", "deps"),
        [
            # A declared dependency's command, when that dependency is not an established package.
            ({"postinstall": "bip40"}, {"bip40": "^1.0.0"}),
            # An interpreter shares a name with a popular package (`@types/node`): `vant`'s
            # compromised releases ran a file that is not in the package.
            ({"postinstall": "node lib/utils/support.js"}, {"@types/node": "^20.0.0"}),
            ({"postinstall": "bun x.ts"}, {"bun": "^1.0.0"}),
            # A popular tool's name, its package from somewhere other than the registry.
            ({"postinstall": "gulp"}, {"gulp": "github:someone/gulp"}),
            # A popular tool not declared at all: whatever is on PATH under that name runs.
            ({"postinstall": "webpack"}, None),
            # A popular tool whose output leaves the package.
            ({"postinstall": "gulp > ~/.profile"}, {"gulp": "^4.0.0"}),
            # Installing a named package is not the package's own install.
            ({"preinstall": "npm install some-helper"}, None),
            # A file made inside the package, then run.
            ({"postinstall": "chmod u+x tool && ./tool"}, None),
            # A file operation outside it.
            ({"postinstall": "touch ~/.marker"}, None),
            ({"postinstall": "rm -rf ../../src"}, None),
            ({"postinstall": "cat ~/.npmrc"}, None),
        ],
    )
    def test_blocks(self, tmp_path: Path, scripts: dict, deps: dict | None, verdict_off) -> None:
        # The rule's grade, with the package verdict off: a minimal synthetic package here is one
        # the verdict holds as a warning (pinned in test_verdict_features.py); this asserts the
        # rule still grades the hook HIGH, so a regression to MEDIUM cannot pass silently.
        found = HookKit.findings(tmp_path, scripts, deps)
        assert any(f.severity >= Severity.HIGH for f in found)
