"""Process-injection imports in a language binding (review 98, FP-10)."""

from __future__ import annotations

from cordon_scanner.detect.binary.imports import ImportCapabilities, ImportTable

INJECT = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")


class TestABinding:
    def test_a_python_extension_is_one(self) -> None:
        table = ImportTable("PE", ("KERNEL32.dll", "python311.dll"), (*INJECT, "PyArg_ParseTuple"))
        assert ImportCapabilities.is_binding(table)

    def test_a_node_addon_is_one(self) -> None:
        assert ImportCapabilities.is_binding(
            ImportTable("ELF", ("libc.so.6",), (*INJECT, "napi_create_function"))
        )

    def test_a_program_that_only_injects_is_not(self) -> None:
        table = ImportTable("PE", ("KERNEL32.dll",), INJECT)
        assert not ImportCapabilities.is_binding(table)
        verdicts = ImportCapabilities.verdicts(ImportCapabilities.profile(table))
        assert any(rule == "SUSPECT.BINARY.PROCESS_INJECTION.001" for rule, _ in verdicts)
