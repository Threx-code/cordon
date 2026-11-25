"""Decoded data run as code when a package is imported.

Importing a library loads code that is already readable on the machine. One that, while it is being
imported, decodes something -- base64, hex, a compressed blob, a marshalled code object, a rot13 or
`codecs` round-trip -- and hands the result to `exec`, `eval` or `compile` has shipped code that
cannot be read until it runs: the standard second stage of an obfuscated loader. Decoding alone is
ordinary (a bundled asset, an embedded key), and so is `exec` alone (a plugin system); it is the
decoded value reaching the code-running call, at load, that is reported.

Measured at the flow (14 Nov, the 0.8.0 combined gate's rows): in a package's top-level
`__init__.py` it newly catches 5 half-A PyPI malware the rules passed, for 0 of 16,663 benign
packages the rules passed, selected on one half and held on the other. What runs at load is what
`FetchRunAtLoad` reads (module level, class bodies, the helpers the module level calls, a function
handed by name to a call that runs at load). The value is followed through plain assignments in the
file, so `code = b64decode(s); exec(code)` and `exec(zlib.decompress(b64decode(s)))` are the same.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.flows.implants.fetch_run_at_load import FetchRunAtLoad
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class DecodeExecAtLoad:
    """`lines(tree)`: the first load-time `exec`/`eval`/`compile` whose argument is decoded data."""

    DECODE: ClassVar[frozenset[str]] = frozenset(
        {
            *(
                f"base64.{m}"
                for m in (
                    "b64decode",
                    "b32decode",
                    "b16decode",
                    "b85decode",
                    "a85decode",
                    "urlsafe_b64decode",
                    "decodebytes",
                    "standard_b64decode",
                )
            ),
            "codecs.decode",
            "binascii.unhexlify",
            "binascii.a2b_base64",
            "binascii.a2b_hex",
            "bytes.fromhex",
            "zlib.decompress",
            "gzip.decompress",
            "bz2.decompress",
            "lzma.decompress",
            "marshal.loads",
        }
    )
    RUN: ClassVar[frozenset[str]] = frozenset({"exec", "eval", "compile"})
    #: The byte codecs `str.decode` / `bytes.decode` named in Python 2 code (`blob.decode('base64')`).
    CODECS: ClassVar[frozenset[str]] = frozenset(
        {"base64", "base_64", "hex", "rot13", "rot_13", "zlib", "bz2", "uu"}
    )

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        if not isinstance(tree, ast.Module):
            return []
        loaded = FetchRunAtLoad._load_time_lines(tree)
        if not loaded:
            return []
        aliases = FetchRunAtLoad._aliases(tree)
        decoded = cls._decoded_names(tree, aliases)
        hits = []
        for node in PythonSyntax.walked_of(tree, ast.Call):
            if not isinstance(node, ast.Call) or node.lineno not in loaded or not node.args:
                continue
            if FetchRunAtLoad._resolved(node.func, aliases) not in cls.RUN:
                continue
            if cls._carries(node.args[0], decoded, aliases):
                hits.append(node.lineno)
        return [min(hits)] if hits else []

    @classmethod
    def _is_decode(cls, node: ast.AST, aliases: dict[str, str]) -> bool:
        if not isinstance(node, ast.Call):
            return False
        if FetchRunAtLoad._resolved(node.func, aliases) in cls.DECODE:
            return True
        if not isinstance(node.func, ast.Attribute):
            return False
        # `bytes.fromhex` on a value, and the Python 2 `blob.decode('base64')` codec style.
        if node.func.attr == "fromhex":
            return True
        if node.func.attr != "decode" or not node.args:
            return False
        codec = node.args[0]
        return (
            isinstance(codec, ast.Constant)
            and str(codec.value).lower().replace("-", "_") in cls.CODECS
        )

    @classmethod
    def _carries(cls, node: ast.AST, decoded: frozenset[str], aliases: dict[str, str]) -> bool:
        """Whether `node` holds a decode call or a name assigned from decoded data."""
        for n in ast.walk(node):
            if cls._is_decode(n, aliases):
                return True
            if isinstance(n, ast.Name) and n.id in decoded:
                return True
        return False

    @classmethod
    def _decoded_names(cls, tree: ast.Module, aliases: dict[str, str]) -> frozenset[str]:
        """Names assigned from decoded data, followed through plain assignments in the file."""
        names: set[str] = set()
        assigns = [n for n in PythonSyntax.walked_of(tree, ast.Assign) if isinstance(n, ast.Assign)]
        changed = True
        while changed:
            changed = False
            for node in assigns:
                if cls._carries(node.value, frozenset(names), aliases):
                    for target in node.targets:
                        for t in ast.walk(target):
                            if isinstance(t, ast.Name) and t.id not in names:
                                names.add(t.id)
                                changed = True
        return frozenset(names)


__all__ = ["DecodeExecAtLoad"]
