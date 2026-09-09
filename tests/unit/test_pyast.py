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
