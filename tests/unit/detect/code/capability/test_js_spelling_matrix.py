"""Every way JavaScript writes each capability primitive, and the label the scanner must give it
(review 98, 17-PROOF-REVIEW: the spelling matrix).

Rules were written from the samples that got past them, one spelling at a time, so a primitive
written another way -- `Buffer.from(x, "hex")` beside `"base64"`, `require("dns").resolve` beside
`dns.resolve`, a path built one segment per argument -- went unlabelled until a sample used it,
and every composite that needed it stayed silent. This table is the other direction: the
spellings the language allows, enumerated per primitive, each read as an install script (the
context the composites see). A new spelling found in a miss is added HERE first, then to the rule.

One primitive per snippet, each a rule's test positive: nothing here is a sample.

Deliberately NOT labelled, each measured or decided where its rule says why:

    {...process.env}            how every program hands a child process its environment
                                (`CAP.JS.CREDENTIAL.001`: esbuild's postinstall)
    process.env.USER            read by every CLI that greets its user; USERNAME, LOGNAME,
                                COMPUTERNAME and HOSTNAME are labelled
    setTimeout(name, ms)        a string and a callback are the same token; `setTimeout("...")`
                                with a literal is labelled
    ~/.gitconfig                holds credentials only with a `credential` section
                                (`capabilities-malware-iocs.yaml`)
    /etc/passwd                 a path-traversal test string in every security library
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.code.capability.detector import CapabilityDetector
from cordon_scanner.foundation.config.settings import Config
from unit.foundation.test_npm_work_half_classes import Npm

CP = "child_" + "process"

SPELLINGS: dict[str, list[str]] = {
    "spawn": [
        f"require('{CP}').exec(c);",
        f"require('node:{CP}').execSync(c);",
        f"const cp = require('{CP}'); cp.spawn(c, a);",
        f"const {{ exec }} = require('{CP}'); exec(c);",
        f"const {{ execSync: run }} = require('{CP}'); run(c);",
        f"import {{ exec }} from '{CP}'; exec(c);",
        f"import {{ spawnSync }} from 'node:{CP}'; spawnSync(c, a);",
        f"import * as cp from '{CP}'; cp.execFileSync(c, a);",
        f"import cp from '{CP}'; cp.fork(f);",
        f"const cp = await import('{CP}'); cp.exec(c);",
        f"const {{ exec }} = await import('node:{CP}'); exec(c);",
        "const cp = require('child_' + 'process'); cp.exec(c);",
        f"const m = '{CP}'; require(m).exec(c);",
        f"require('{CP}')['ex' + 'ec'](c);",
        f"const cp = module.require('{CP}'); cp.exec(c);",
        "process.binding('spawn_sync').spawn(o);",
    ],
    "execute": [
        "eval(s);",
        "(0, eval)(s);",
        "globalThis['ev' + 'al'](s);",
        "new Function(s)();",
        "Function(s)();",
        "const vm = require('vm'); vm.runInThisContext(s);",
        "import vm from 'node:vm'; vm.runInNewContext(s);",
        "import { runInThisContext } from 'vm'; runInThisContext(s);",
        "new (require('vm').Script)(s).runInThisContext();",
        "const m = new module.constructor(); m._compile(s, f);",
        "require('module').prototype._compile.call(m, s, f);",
    ],
    "decode": [
        "Buffer.from(x, 'base64');",
        "Buffer.from(x, 'base64url');",
        "Buffer.from(x, 'hex');",
        'Buffer.from(x, "hex").toString();',
        "atob(x);",
        "new TextDecoder().decode(Uint8Array.from(atob(x), c => c.charCodeAt(0)));",
        "String.fromCharCode(...x.match(/../g).map(h => parseInt(h, 16)));",
        "require('zlib').inflateSync(Buffer.from(x, 'base64'));",
        "decodeURIComponent(escape(x));",
        "require('crypto').createDecipheriv(a, k, i);",
    ],
    "egress": [
        "require('https').get(u);",
        "require('node:http').request(o);",
        "const https = require('https'); https.request(o);",
        "import https from 'https'; https.get(u);",
        "import { request } from 'node:https'; request(o);",
        "import * as http from 'http'; http.get(u);",
        "fetch(u);",
        "await fetch(u, { method: 'POST', body: b });",
        "const axios = require('axios'); axios.post(u, b);",
        "import axios from 'axios'; axios.get(u);",
        "new XMLHttpRequest();",
        "require('undici').request(u);",
        "require('got')(u);",
        "require('node-fetch')(u);",
        "require('request').post(u);",
        "require('dns').resolve(h, cb);",
        "require('dns').lookup(h, cb);",
        "const { lookup } = require('dns'); lookup(h, cb);",
        "import dns from 'node:dns'; dns.resolveTxt(h, cb);",
        "import { promises as dns } from 'dns'; await dns.resolve4(h);",
        "const net = require('net'); net.connect(p, h);",
        "new (require('net').Socket)().connect(p, h);",
        "import { createConnection } from 'net'; createConnection(p, h);",
        "require('tls').connect(p, h);",
        "require('dgram').createSocket('udp4').send(b, p, h);",
        "new WebSocket(u);",
    ],
    "reconnaissance": [
        "require('os').hostname();",
        "require('os').userInfo();",
        "const os = require('os'); os.networkInterfaces();",
        "import os from 'os'; os.hostname();",
        "import { userInfo } from 'node:os'; userInfo();",
        "const { hostname } = require('os'); hostname();",
        "process.env.COMPUTERNAME;",
        "process.env['USERNAME'];",
    ],
    "credential": [
        "fs.readFileSync(path.join(os.homedir(), '.npmrc'));",
        "fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'));",
        "fs.readFileSync(`${process.env.HOME}/.aws/credentials`);",
        "fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'));",
        "fs.promises.readFile(path.join(home, '.config', 'gh', 'hosts.yml'));",
        "fs.readFileSync(path.join(os.homedir(), '.docker', 'config.json'));",
        "fs.readFileSync(path.join(os.homedir(), '.kube', 'config'));",
        "fs.readFileSync(path.join(local, 'Google', 'Chrome', 'User Data', 'Default', 'Login Data'));",
        "fs.readdirSync(path.join(appdata, 'Exodus', 'exodus.wallet'));",
        "fs.readFileSync(path.join(os.homedir(), '.bash_history'));",
        "JSON.stringify(process.env);",
        "Object.entries(process.env);",
        "Buffer.from(JSON.stringify(process.env)).toString('base64');",
    ],
    "persist": [
        "fs.appendFileSync(path.join(os.homedir(), '.bashrc'), l);",
        "fs.writeFileSync(path.join(os.homedir(), '.zshrc'), l);",
        "fs.writeFileSync(path.join(os.homedir(), 'Library', 'LaunchAgents', n), p);",
        "fs.writeFileSync(path.join(os.homedir(), '.config', 'systemd', 'user', n), u);",
        "fs.writeFileSync(path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', n), p);",
    ],
}

PRELUDE = "const fs = require('fs'); const path = require('path'); const os = require('os');\n"


class TestSpellingMatrix:
    @staticmethod
    def capabilities(tmp_path, monkeypatch, snippet: str) -> set[str]:
        """The capabilities the detector gives `x.js` when a postinstall runs it."""
        seen: set[str] = set()
        labelled = CapabilityDetector.labelled

        def spy(self, unit, ctx, *args, **kwargs):
            out = labelled(self, unit, ctx, *args, **kwargs)
            if unit.path.endswith("/x.js") and out:
                seen.update(hit.capability.value for hit in out[0])
            return out

        monkeypatch.setattr(CapabilityDetector, "labelled", spy)
        target = Npm.build(
            tmp_path,
            "matrix",
            {"version": "1.0.0", "scripts": {"postinstall": "node x.js"}},
            {"x.js": PRELUDE + snippet + "\n"},
        )
        Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return seen

    @pytest.mark.parametrize(
        ("capability", "snippet"),
        [
            (capability, snippet)
            for capability, snippets in SPELLINGS.items()
            for snippet in snippets
        ],
    )
    def test_every_spelling_is_labelled(
        self, tmp_path, monkeypatch, capability: str, snippet: str
    ) -> None:
        assert capability in self.capabilities(tmp_path, monkeypatch, snippet)
