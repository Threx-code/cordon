"""Run the module-function differential's calls through one engine.

With ``function_args.py``: a fixed battery of ``pe.*`` calls (absent names, out-of-range RVAs, ordinal,
regex and delayed forms) plus the per-file "hitting" calls built from ``args.json``, each run as a
``console.log`` rule through either our engine or the reference. The two runs are compared; the
reference's output is kept as ``functions.json`` only once it is confirmed identical to ours, and
``test_rule_pe.py`` replays it through our engine. The reference is imported only when this is asked to
run it.

A maintainer's tool, not part of Cordon. Run inside Docker, from the repository root, once per engine:
    # ours
    docker run --rm -v "$PWD:/pkg" -w /pkg python:3.12-slim \
      python scripts/reference/function_differential.py ours \
        tests/unit/data/rule_reference/modules args.json functions-ours.json
    # the reference
    docker run --rm -v "$PWD:/pkg" -w /pkg python:3.12-slim sh -c \
      "pip install -q yara-python==4.5.1 && python scripts/reference/function_differential.py reference \
         tests/unit/data/rule_reference/modules args.json functions.json"
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

sys.path.insert(0, str(Path("src")))  # run from the repository root, as the README shows


class FunctionDifferential:
    """The console.log calls (a fixed battery plus per-file hitting calls) and one engine's output."""

    #: the fixed calls every file is asked, covering the forms the readers' function paths must agree on
    BASE: ClassVar[tuple[tuple[str, str], ...]] = (
        ("imphash", "pe.imphash()"),
        ("is_dll", "pe.is_dll()"),
        ("is_32", "pe.is_32bit()"),
        ("is_64", "pe.is_64bit()"),
        ("checksum", "pe.calculate_checksum()"),
        ("rva0", "pe.rva_to_offset(0)"),
        ("rva1000", "pe.rva_to_offset(0x1000)"),
        ("rva2000", "pe.rva_to_offset(0x2000)"),
        ("rvabig", "pe.rva_to_offset(0x7fffffff)"),
        ("sec_text", 'pe.section_index(".text")'),
        ("sec_data", 'pe.section_index(".data")'),
        ("sec_rdata", 'pe.section_index(".rdata")'),
        ("sec_absent", 'pe.section_index(".zzzz")'),
        ("sec_addr1000", "pe.section_index(0x1000)"),
        ("sec_addr0", "pe.section_index(0)"),
        ("exp_main", 'pe.exports("main")'),
        ("exp_dllmain", 'pe.exports("DllMain")'),
        ("exp_re", "pe.exports(/.*/)"),
        ("exp_ord1", "pe.exports(1)"),
        ("expidx_main", 'pe.exports_index("main")'),
        ("imp_k32_cf", 'pe.imports("kernel32.dll", "CreateFileW")'),
        ("imp_k32_cf_case", 'pe.imports("KERNEL32.DLL", "createfilew")'),
        ("imp_k32_count", 'pe.imports("kernel32.dll")'),
        ("imp_absent", 'pe.imports("absent-xyz.dll", "nope")'),
        ("imp_ord", 'pe.imports("ws2_32.dll", 115)'),
        ("imp_flag_k32", 'pe.imports(3, "kernel32.dll", "CreateFileW")'),
        ("imp_re", "pe.imports(/kernel32/i, /Create/)"),
        ("imprva_k32", 'pe.import_rva("kernel32.dll", "CreateFileW")'),
        ("delrva_k32", 'pe.delayed_import_rva("kernel32.dll", "CreateFileW")'),
        ("locale_1033", "pe.locale(1033)"),
        ("locale_9", "pe.locale(9)"),
        ("language_9", "pe.language(9)"),
        ("nsec", "pe.number_of_sections"),
    )

    @staticmethod
    def run(engine: str, modules_dir: Path, args_path: Path, out_path: Path) -> None:
        """Run every file's calls through ``engine`` ("ours" or "reference") and write the results."""
        args = json.loads(args_path.read_text(encoding="utf-8"))
        execute = (
            FunctionDifferential._ours() if engine == "ours" else FunctionDifferential._reference()
        )
        result: dict[str, Any] = {}
        for name, hitting in args.items():
            calls = [list(call) for call in FunctionDifferential._calls(hitting)]
            source = FunctionDifferential._source(calls)
            data = (modules_dir / name).read_bytes()
            result[name] = {"calls": calls, "logs": execute(source, data)}
        out_path.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        counts = {name: len(entry["logs"]) for name, entry in result.items()}
        print(f"{engine}: {len(result)} fixtures, logs {counts}")

    @staticmethod
    def _calls(hitting: dict[str, Any]) -> list[tuple[str, str]]:
        return list(FunctionDifferential.BASE) + FunctionDifferential._hitting_calls(hitting)

    @staticmethod
    def _hitting_calls(hitting: dict[str, Any]) -> list[tuple[str, str]]:
        """Calls built from the arguments ``function_args.py`` found to resolve in this file."""
        out: list[tuple[str, str]] = []
        if hitting.get("imp_dll") and hitting.get("imp_fn"):
            dll, fn = (
                FunctionDifferential._literal(hitting["imp_dll"]),
                FunctionDifferential._literal(hitting["imp_fn"]),
            )
            out += [
                ("imp_hit", f"pe.imports({dll}, {fn})"),
                ("impcount_hit", f"pe.imports({dll})"),
                ("imprva_hit", f"pe.import_rva({dll}, {fn})"),
            ]
        if hitting.get("exp_name"):
            name = FunctionDifferential._literal(hitting["exp_name"])
            out += [("exp_hit", f"pe.exports({name})"), ("expidx_hit", f"pe.exports_index({name})")]
        if hitting.get("sec_name"):
            out.append(
                (
                    "sec_hit",
                    f"pe.section_index({FunctionDifferential._literal(hitting['sec_name'])})",
                )
            )
        if hitting.get("in_rva") is not None:
            out.append(("rva_hit", f"pe.rva_to_offset({hitting['in_rva']})"))
        return out

    @staticmethod
    def _literal(text: str) -> str:
        """``text`` as a double-quoted rule-string literal."""
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

    @staticmethod
    def _source(calls: list[list[str]]) -> str:
        rules = "\n".join(
            f'rule r{i} {{ condition: console.log("{label}=", {expr}) }}'
            for i, (label, expr) in enumerate(calls)
        )
        return 'import "pe"\nimport "console"\n' + rules

    @staticmethod
    def _ours() -> Callable[[str, bytes], list[str]]:
        from cordon_scanner.detect.binary.rule_lang import Rules

        def execute(source: str, data: bytes) -> list[str]:
            logs: list[str] = []
            Rules.compile(source).match(data, console=logs.append)
            return sorted(logs)

        return execute

    @staticmethod
    def _reference() -> Callable[[str, bytes], list[str]]:
        # the reference; only this measurement path needs it installed
        import yara  # type: ignore[import-not-found]

        def execute(source: str, data: bytes) -> list[str]:
            logs: list[str] = []

            def collect(message: str) -> int:
                logs.append(message)
                return int(yara.CALLBACK_CONTINUE)

            yara.compile(source=source).match(data=data, console_callback=collect, timeout=30)
            return sorted(logs)

        return execute


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] not in ("ours", "reference"):
        raise SystemExit(
            "usage: function_differential.py <ours|reference> <modules_dir> <args.json> <out.json>"
        )
    FunctionDifferential.run(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
