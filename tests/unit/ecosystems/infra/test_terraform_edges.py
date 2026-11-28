"""The Terraform reader on text that is cut short or odd: every refusal of the lexer and parser, computed keys, providers by source form, and the lock file's refusals (`ecosystems/infra/terraform.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.ecosystems.infra.terraform import HclLexer, HclParser, TerraformProviders
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits

ZH = "zh:" + "d" * 64


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["terraform"]

    @staticmethod
    def manifest(text: str, path: str = "main.tf") -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc(path, text))


class TestLexerRefusals:
    @pytest.mark.parametrize(
        ("text", "why"),
        [
            ("/* never ends", "an unterminated comment"),
            ("a = <<EOT\nabc\n", "an unterminated heredoc"),
            ("é = 1", "an unreadable identifier"),
            ("a = ²", "an unreadable number"),
            ('a = "abc\nb = 1', "a string that does not close on its line"),
            ('a = "x ${ abc', "an interpolation that does not close"),
        ],
    )
    def test_text_the_lexer_cannot_read_is_refused_with_its_reason(
        self, text: str, why: str
    ) -> None:
        with pytest.raises(ValueError, match=why):
            HclLexer.tokens(text)

    def test_more_tokens_than_the_limit_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(HclLexer, "MAX_TOKENS", 3)
        with pytest.raises(ValueError, match="more tokens than a configuration holds"):
            HclLexer.tokens("a = b + c + d + e")

    def test_a_string_inside_an_interpolation_is_read_whole(self) -> None:
        tokens = HclLexer.tokens('a = "x ${ "y}" } z"')
        assert tokens[-1] == ("template", 'x ${ "y}" } z')


class TestParserRefusals:
    def test_blocks_nested_past_the_limit_are_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(HclParser, "MAX_DEPTH", 2)
        manifest = _Kit.manifest("a {\n b {\n c {\n d {\n }\n }\n }\n}\n")
        assert "blocks nested too deeply" in manifest.parse_error

    def test_an_object_item_without_a_separator_is_refused(self) -> None:
        assert "an object item without = or :" in _Kit.manifest("a = { b c }\n").parse_error

    def test_a_tuple_that_does_not_close_is_refused(self) -> None:
        assert "a tuple that does not close" in _Kit.manifest("a = [1, 2\n").parse_error

    def test_a_computed_object_key_is_read_past(self) -> None:
        manifest = _Kit.manifest('locals {\n  m = { (var.k) = 1, "b" = 2 }\n}\n')
        assert not manifest.parse_error


class TestModulesAndProviders:
    def test_a_module_whose_source_is_a_git_ssh_address_is_a_git_source(self) -> None:
        manifest = _Kit.manifest(
            'module "m" {\n  source = "git@github.com:org/repo.git?ref=v1"\n}\n'
        )
        [dependency] = manifest.dependencies
        assert (dependency.name, dependency.spec) == (
            "repo",
            "git+ssh://git@github.com/org/repo.git#v1",
        )

    def test_a_module_whose_source_is_not_a_literal_is_skipped(self) -> None:
        manifest = _Kit.manifest('module "m" {\n  source = var.where\n}\n')
        assert manifest.dependencies == ()

    @pytest.mark.parametrize(
        ("source", "name", "registry"),
        [
            ("hashicorp/aws", "hashicorp/aws", None),
            ("aws", "hashicorp/aws", None),
            ("registry.terraform.io/hashicorp/aws", "hashicorp/aws", None),
            (
                "registry.example.invalid/acme/thing",
                "registry.example.invalid/acme/thing",
                "registry:registry.example.invalid",
            ),
        ],
    )
    def test_a_provider_source_is_named_by_its_address(
        self, source: str, name: str, registry: str | None
    ) -> None:
        assert TerraformProviders.address(source) == (name, registry)

    def test_a_provider_used_with_an_explicit_alias_counts_as_used(self) -> None:
        text = 'resource "google_x" "a" {\n  provider = google-beta.west\n}\n'
        manifest = _Kit.manifest(text)
        assert "google-beta" in " ".join(d.name for d in manifest.dependencies)


class TestLockFile:
    def lock(self, text: str) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc(".terraform.lock.hcl", text))

    def test_a_locked_provider_without_a_version_is_refused(self) -> None:
        text = 'provider "registry.terraform.io/hashicorp/aws" {\n  hashes = ["h1:abc"]\n}\n'
        assert self.lock(text).parse_error == "a locked provider without its version"

    def test_a_block_that_is_not_a_provider_is_ignored(self) -> None:
        text = (
            'terraform {\n}\nprovider "registry.terraform.io/hashicorp/aws" {\n'
            f'  version = "5.0.0"\n  hashes = ["h1:abc", "{ZH}"]\n}}\n'
        )
        [entry] = self.lock(text).entries
        assert (entry.name, entry.version, entry.integrity) == ("hashicorp/aws", "5.0.0", ZH)

    def test_a_lock_that_names_providers_it_cannot_read_is_an_error(self) -> None:
        assert "providers could not be read" in self.lock("provider {\n}\n").parse_error


class TestMoreTerraform:
    def test_a_number_used_as_an_object_key_is_read_past(self) -> None:
        assert not _Kit.manifest('locals {\n  m = { 1 = "a", b = 2 }\n}\n').parse_error

    def test_a_file_that_is_not_among_the_files_given_is_still_read(self) -> None:
        content = _Kit.fc("m/main.tf", 'provider "aws" {\n}\n')
        manifest = _Kit.adapter().parse_in_tree(content, {})
        assert not manifest.parse_error
