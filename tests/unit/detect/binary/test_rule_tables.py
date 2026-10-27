"""Named constants and ordinal-to-name resolution for the binary readers (rule_tables)."""

from __future__ import annotations

from cordon_scanner.detect.binary.rule_tables import Tables


class TestTables:
    def test_pe_spot_values(self) -> None:
        assert Tables.PE["MACHINE_AMD64"] == 34404
        assert Tables.PE["IMAGE_DIRECTORY_ENTRY_SECURITY"] == 4
        assert Tables.PE["SECTION_MEM_WRITE"] == 2147483648
        assert Tables.PE["IMPORT_ANY"] == -1
        assert Tables.PE["RESOURCE_TYPE_MANIFEST"] == 24

    def test_elf_spot_values(self) -> None:
        assert Tables.ELF["EM_X86_64"] == 62
        assert Tables.ELF["PT_GNU_STACK"] == 1685382481
        assert Tables.ELF["SHT_DYNSYM"] == 11

    def test_ordinal_name_winsock(self) -> None:
        assert Tables.ordinal_name(b"ws2_32.dll", 1) == b"accept"
        assert Tables.ordinal_name(b"WSOCK32.DLL", 115) == b"WSAStartup"

    def test_ordinal_name_oleaut(self) -> None:
        assert Tables.ordinal_name(b"oleaut32.dll", 2) == b"SysAllocString"
        assert Tables.ordinal_name(b"OLEAUT32.DLL", 443) == b"UnRegisterTypeLibForUser"

    def test_ordinal_name_unknown_is_ord(self) -> None:
        assert (
            Tables.ordinal_name(b"ws2_32.dll", 100000) == b"ord100000"
        )  # known library, no such ordinal
        assert Tables.ordinal_name(b"kernel32.dll", 5) == b"ord5"  # library with no ordinal table
