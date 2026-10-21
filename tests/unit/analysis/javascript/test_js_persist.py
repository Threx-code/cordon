"""JsPersistence: a JavaScript line that names a persistence location only in a literal no sink
receives (review 98 G6, benign npm); one whose literal is written, copied or run keeps its hit."""

from __future__ import annotations

import json

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.javascript.js_persist import JsPersistence
from cordon_scanner.foundation.config import Config

RULE = "MALWARE.INSTALL.PERSIST.001"


class PersistHelpers:
    @staticmethod
    def line_of(source: str, needle: str) -> int:
        return next(i for i, line in enumerate(source.splitlines(), 1) if needle in line)

    @staticmethod
    def rules(tmp_path, install: str) -> set[str]:
        manifest = {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        (tmp_path / "install.js").write_text(install, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


line_of = PersistHelpers.line_of


class TestNamedOnly:
    @pytest.mark.parametrize(
        ("source", "needle"),
        [
            # The plist of the service a CLI manages, read to report on it.
            (
                "const fs = require('fs');\nconst path = require('path');\n"
                "const p = path.join(home, 'Library', 'LaunchAgents', 'hub.plist');\n"
                "const text = fs.readFileSync(p, 'utf8');\n",
                "LaunchAgents",
            ),
            # Tested for before it is read: `if (` is not a call.
            (
                "const fs = require('fs');\n"
                "const p = require('path').join(home, 'Library', 'LaunchAgents', 'hub.plist');\n"
                "if (fs.existsSync(p)) console.log(fs.readFileSync(p, 'utf8'));\n",
                "LaunchAgents",
            ),
            # A form field's type, kept in the page's configuration.
            ("this.config = { columns: [{ type: 'crontab', name: 'schedule' }] };\n", "crontab"),
            # A tip printed for a person.
            ("console.log(`Tip: add it to ~/.bashrc`);\n", "bashrc"),
        ],
    )
    def test_a_location_named_and_never_written(self, source: str, needle: str) -> None:
        assert line_of(source, needle) in JsPersistence.named_only_lines(source)


class TestWritten:
    @pytest.mark.parametrize(
        ("source", "needle"),
        [
            (
                "const fs = require('fs');\n"
                "const rc = require('os').homedir() + '/.bashrc';\n"
                "fs.appendFileSync(rc, line);\n",
                ".bashrc",
            ),
            (
                "const fs = require('fs');\n"
                "function put(where, body) { fs.writeFileSync(where, body); }\n"
                "put('/etc/systemd/system/agent.service', unit);\n",
                "systemd",
            ),
            (
                "const { execSync } = require('child_process');\n"
                "const cmd = 'systemctl enable agent';\n"
                "execSync(cmd);\n",
                "systemctl",
            ),
            (
                "const { install } = require('./service');\n"
                "install('~/Library/LaunchAgents/agent.plist');\n",
                "LaunchAgents",
            ),
        ],
    )
    def test_a_location_written_keeps_its_hit(self, source: str, needle: str) -> None:
        assert line_of(source, needle) not in JsPersistence.named_only_lines(source)

    def test_a_literal_handed_to_a_call_outside_the_file_keeps_its_hit(self) -> None:
        # What `render` does with it is not read here: it counts as written (fail-safe).
        source = "const columns = [{ type: 'crontab', name: 'schedule' }];\nrender(columns);\n"
        assert line_of(source, "crontab") not in JsPersistence.named_only_lines(source)

    def test_a_word_in_code_keeps_its_hit(self) -> None:
        source = "const crontab = require('crontab');\ncrontab.load(cb);\n"
        assert line_of(source, "require") not in JsPersistence.named_only_lines(source)


class TestEndToEnd:
    def test_an_install_script_that_only_reads_its_service_plist_does_not_block(
        self, tmp_path
    ) -> None:
        install = (
            "const fs = require('fs');\nconst os = require('os');\nconst path = require('path');\n"
            "const p = path.join(os.homedir(), 'Library', 'LaunchAgents', 'hub.plist');\n"
            "if (fs.existsSync(p)) console.log(fs.readFileSync(p, 'utf8'));\n"
        )
        assert RULE not in PersistHelpers.rules(tmp_path, install)

    def test_an_install_script_that_writes_one_still_blocks(self, tmp_path) -> None:
        install = (
            "const fs = require('fs');\nconst os = require('os');\nconst path = require('path');\n"
            "const p = path.join(os.homedir(), 'Library', 'LaunchAgents', 'hub.plist');\n"
            "fs.writeFileSync(p, plist);\n"
        )
        assert RULE in PersistHelpers.rules(tmp_path, install)


class TestBudget:
    def test_past_its_budget_a_file_keeps_every_hit(self, monkeypatch) -> None:
        from cordon_scanner.analysis.javascript import js_persist

        source = (
            "const fs = require('fs');\n"
            "function show(where) { console.log(where); }\n"
            "show('~/Library/LaunchAgents/hub.plist');\n"
            "render(count);\n"
        )
        assert line_of(source, "LaunchAgents") in JsPersistence.named_only_lines(source)
        monkeypatch.setattr(js_persist, "BUDGET", 0)
        assert JsPersistence.named_only_lines(source) == frozenset()
