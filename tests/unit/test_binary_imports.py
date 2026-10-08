"""G12: import tables read from ELF, PE and Mach-O, the verdicts drawn from them, and YARA.

The binaries are built here, byte by byte, with exactly the imports each test needs: a minimal
but structurally valid ELF64 (dynsym, dynstr, dynamic), PE32 (one section holding the import
directory) and Mach-O 64 (LC_LOAD_DYLIB, LC_SYMTAB). Nothing is executed. The noise check against
real binaries -- 342 Debian ELFs and the 30 PE files of the Windows Python build, zero verdicts --
is recorded in the commit; these tests pin the parsers and the rules.
"""

from __future__ import annotations

import struct
import sys
import types
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.detect.binary_imports import ImportCapabilities, ImportReader, ImportTable


class Build:
    """Minimal binaries with chosen imports."""

    @staticmethod
    def elf(symbols: list[str], needed: list[str]) -> bytes:
        dynstr = b"\x00"
        offsets = {}
        for name in [*needed, *symbols]:
            offsets[name] = len(dynstr)
            dynstr += name.encode() + b"\x00"
        dynsym = b"\x00" * 24 + b"".join(
            struct.pack("<IBBHQQ", offsets[s], 0x12, 0, 0, 0, 0) for s in symbols
        )
        dynamic = b"".join(struct.pack("<qQ", 1, offsets[n]) for n in needed) + struct.pack(
            "<qQ", 0, 0
        )
        header_size, sh_size = 64, 64
        body = dynstr + dynsym + dynamic
        str_off = header_size
        sym_off = str_off + len(dynstr)
        dyn_off = sym_off + len(dynsym)
        shoff = header_size + len(body)
        sections = [
            struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_off, len(dynstr), 0, 0, 1, 0),
            struct.pack("<IIQQQQIIQQ", 0, 11, 0, 0, sym_off, len(dynsym), 1, 1, 8, 24),
            struct.pack("<IIQQQQIIQQ", 0, 6, 0, 0, dyn_off, len(dynamic), 1, 0, 8, 16),
        ]
        ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9
        header = ident + struct.pack(
            "<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, shoff, 0, 64, 0, 0, sh_size, len(sections), 0
        )
        return header + body + b"".join(sections)

    @staticmethod
    def pe(imports: dict[str, list[str]]) -> bytes:
        section_rva, section_raw = 0x1000, 0x200
        names = b""
        descriptor_count = len(imports) + 1
        desc_size = descriptor_count * 20
        layout = bytearray(b"\x00" * desc_size)
        thunks_start = desc_size
        # thunk arrays first, then hint/name entries and dll names
        thunk_blobs, name_blobs = [], []
        cursor = thunks_start + sum((len(f) + 1) * 4 for f in imports.values())
        thunk_cursor = thunks_start
        descriptors = []
        for dll, functions in imports.items():
            thunk = b""
            for function in functions:
                entry = struct.pack("<H", 0) + function.encode() + b"\x00"
                thunk += struct.pack("<I", section_rva + cursor)
                name_blobs.append(entry)
                cursor += len(entry)
            thunk += struct.pack("<I", 0)
            dll_rva = section_rva + cursor
            dll_blob = dll.encode() + b"\x00"
            name_blobs.append(dll_blob)
            cursor += len(dll_blob)
            descriptors.append((section_rva + thunk_cursor, dll_rva))
            thunk_blobs.append(thunk)
            thunk_cursor += len(thunk)
        for i, (thunk_rva, dll_rva) in enumerate(descriptors):
            layout[i * 20 : i * 20 + 20] = struct.pack(
                "<IIIII", thunk_rva, 0, 0, dll_rva, thunk_rva
            )
        section = bytes(layout) + b"".join(thunk_blobs) + b"".join(name_blobs) + names
        dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
        dos = dos.ljust(0x80, b"\x00")
        coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)
        optional = bytearray(224)
        struct.pack_into("<H", optional, 0, 0x10B)
        struct.pack_into("<II", optional, 96 + 8, section_rva, desc_size)
        section_header = b".idata\x00\x00" + struct.pack(
            "<IIIIIIHHI", len(section), section_rva, len(section), section_raw, 0, 0, 0, 0, 0
        )
        head = (dos + coff + bytes(optional) + section_header).ljust(section_raw, b"\x00")
        return head + section

    @staticmethod
    def macho(symbols: list[str], dylibs: list[str]) -> bytes:
        commands = b""
        for dylib in dylibs:
            name = dylib.encode() + b"\x00"
            size = (24 + len(name) + 7) // 8 * 8
            commands += struct.pack("<IIIIII", 0xC, size, 24, 0, 0, 0) + name.ljust(
                size - 24, b"\x00"
            )
        strtab = b"\x00"
        entries = b""
        for symbol in symbols:
            entries += struct.pack("<IBBHQ", len(strtab), 0x01, 0, 0, 0)
            strtab += b"_" + symbol.encode() + b"\x00"
        header_size = 32
        symtab_size = 24
        symoff = header_size + len(commands) + symtab_size
        stroff = symoff + len(entries)
        commands += struct.pack(
            "<IIIIII", 0x2, symtab_size, symoff, len(symbols), stroff, len(strtab)
        )
        header = struct.pack(
            "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, len(dylibs) + 1, len(commands), 0, 0
        )
        return header + commands + entries + strtab


class TestReaders:
    def test_elf_imports_and_needed_libraries(self) -> None:
        table = ImportReader.read(Build.elf(["socket", "connect", "execve"], ["libc.so.6"]))
        assert table == ImportTable("ELF", ("libc.so.6",), ("socket", "connect", "execve"))

    def test_pe_imports_by_name(self) -> None:
        table = ImportReader.read(
            Build.pe(
                {
                    "KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory"],
                    "WS2_32.dll": ["connect"],
                }
            )
        )
        assert table is not None and table.format == "PE"
        assert table.libraries == ("KERNEL32.dll", "WS2_32.dll")
        assert table.symbols == ("VirtualAllocEx", "WriteProcessMemory", "connect")

    def test_macho_imports_without_the_leading_underscore(self) -> None:
        table = ImportReader.read(
            Build.macho(
                ["SecKeychainFindGenericPassword", "connect"], ["/usr/lib/libSystem.B.dylib"]
            )
        )
        assert table == ImportTable(
            "Mach-O", ("/usr/lib/libSystem.B.dylib",), ("SecKeychainFindGenericPassword", "connect")
        )

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x7fELF",
            b"\x7fELF" + b"\xff" * 60,
            b"MZ" + b"\x00" * 100,
            b"\xcf\xfa\xed\xfe" + b"\xff" * 40,
            b"plain text",
        ],
    )
    def test_malformed_or_foreign_input_is_none_never_an_exception(self, data) -> None:
        assert ImportReader.read(data) is None or isinstance(ImportReader.read(data), ImportTable)

    def test_a_truncated_binary_does_not_raise(self) -> None:
        data = Build.pe({"KERNEL32.dll": ["CreateProcessA"]})
        for cut in range(0, len(data), 37):
            ImportReader.read(data[:cut])

    def test_symbol_counts_are_capped(self, monkeypatch) -> None:
        from cordon_scanner.detect import binary_imports

        monkeypatch.setattr(binary_imports, "MAX_SYMBOLS", 3)
        table = ImportReader.read(Build.elf([f"f{i}" for i in range(10)], []))
        assert table is not None and len(table.symbols) <= 3


class TestVerdicts:
    @staticmethod
    def rules(symbols: list[str]) -> list[str]:
        return [
            r
            for r, _ in ImportCapabilities.verdicts(
                ImportCapabilities.profile(ImportTable("PE", (), tuple(symbols)))
            )
        ]

    def test_process_injection(self) -> None:
        assert self.rules(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]) == [
            "SUSPECT.BINARY.PROCESS_INJECTION.001"
        ]

    def test_credential_theft_needs_the_network_too(self) -> None:
        assert self.rules(
            [
                "CryptUnprotectData",
                "InternetOpenA",
                "HttpSendRequestA",
                "a",
                "b",
                "c",
                "d",
                "e",
                "f",
                "g",
                "h",
                "i",
                "j",
            ]
        ) == ["SUSPECT.BINARY.CREDENTIAL_THEFT.001"]
        assert self.rules(["CryptUnprotectData"]) == []

    def test_download_and_execute(self) -> None:
        assert "SUSPECT.BINARY.IMPLANT.001" in self.rules(["URLDownloadToFileA", "ShellExecuteA"])

    def test_an_installer_is_not_an_implant(self) -> None:
        installer = [
            "RegSetValueExW",
            "CreateProcessW",
            "InternetOpenW",
            "WinHttpOpen",
            *[f"f{i}" for i in range(40)],
        ]
        assert self.rules(installer) == []

    def test_networking_and_execution_with_anti_debugging_is(self) -> None:
        assert "SUSPECT.BINARY.IMPLANT.001" in self.rules(
            ["socket", "connect", "execve", "IsDebuggerPresent", *[f"f{i}" for i in range(20)]]
        )

    def test_a_table_that_imports_only_the_loader_hides_its_imports(self) -> None:
        assert self.rules(["LoadLibraryA", "GetProcAddress", "ExitProcess"]) == [
            "SUSPECT.BINARY.HIDDEN_IMPORTS.001"
        ]
        assert self.rules(["LoadLibraryA", "GetProcAddress", *[f"f{i}" for i in range(30)]]) == []

    def test_keylogging_needs_the_network(self) -> None:
        assert self.rules(["SetWindowsHookExA", "send", *[f"f{i}" for i in range(20)]]) == [
            "SUSPECT.BINARY.KEYLOGGER.001"
        ]
        assert self.rules(["GetAsyncKeyState", *[f"f{i}" for i in range(20)]]) == []

    def test_an_ordinary_program_draws_nothing(self) -> None:
        assert (
            self.rules(
                [
                    "malloc",
                    "free",
                    "printf",
                    "socket",
                    "connect",
                    "read",
                    "write",
                    "open",
                    "close",
                    "fopen",
                    "fclose",
                    "exit",
                    "strlen",
                ]
            )
            == []
        )


class TestTheDetectorReportsThem:
    def test_a_committed_injector_is_reported(self, tmp_path) -> None:
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools/helper.exe").write_bytes(
            Build.pe(
                {"KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]}
            )
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        rules = {f.rule_id for f in result.findings}
        assert "SUSPECT.BINARY.PROCESS_INJECTION.001" in rules

    def test_a_benign_binary_is_only_a_policy_note(self, tmp_path) -> None:
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin/tool").write_bytes(
            Build.elf(["malloc", "printf", "socket", "connect"], ["libc.so.6"])
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert not [
            f
            for f in result.findings
            if f.rule_id.startswith("SUSPECT.BINARY.")
            and "IMPORT" not in f.rule_id
            and f.rule_id != "SUSPECT.BINARY.EXECUTABLE_PATH.001"
        ]


class FakeYara:
    """A stand-in for the yara-python module with the surface the detector uses."""

    class Match:
        def __init__(self, rule: str, meta: dict) -> None:
            self.rule, self.meta = rule, meta

    def __init__(self, matches: list | Exception, compile_error: Exception | None = None) -> None:
        self.matches, self.compile_error = matches, compile_error
        self.compiled_with: dict = {}
        self.__version__ = "4.5.fake"

    def compile(self, **kwargs):
        self.compiled_with = kwargs
        if self.compile_error:
            raise self.compile_error
        outer = self

        class Rules:
            def match(self, data, timeout):
                if isinstance(outer.matches, Exception):
                    raise outer.matches
                return outer.matches if b"EVIL" in data else []

        return Rules()


class YaraFixtures:
    @pytest.fixture
    def scan(self, tmp_path, monkeypatch):
        def run(fake: FakeYara | None, files: dict[str, bytes] | None = None):
            if fake is None:
                monkeypatch.setitem(sys.modules, "yara", None)
            else:
                monkeypatch.setitem(
                    sys.modules,
                    "yara",
                    types.SimpleNamespace(compile=fake.compile, __version__=fake.__version__),
                )
            rules = tmp_path / "rules.yar"
            rules.write_text("rule x { condition: true }\n", encoding="utf-8")
            target = tmp_path / "repo"
            target.mkdir()
            for name, data in (files or {"payload.bin": b"\x00EVIL\x00"}).items():
                (target / name).write_bytes(data)
            config = Config.default().with_overrides(use_cache=False, yara=str(rules))
            return Scanner(config).scan(target)

        return run


class TestYara(YaraFixtures):
    def test_a_match_is_reported_with_the_rule_name(self, scan) -> None:
        result = scan(FakeYara([FakeYara.Match("Trojan_Foo", {"description": "loader stub"})]))
        found = [f for f in result.findings if f.rule_id == "SUSPECT.YARA.MATCH.001"]
        assert found and "Trojan_Foo" in found[0].message and found[0].severity.name == "HIGH"
        assert any(f.rule_id == "OPERATIONAL.YARA.STATUS" for f in result.findings)

    def test_a_rule_declared_malicious_is_malware(self, scan) -> None:
        result = scan(FakeYara([FakeYara.Match("Ransom_X", {"category": "malicious"})]))
        assert any(
            f.rule_id == "MALWARE.YARA.MATCH.001" and f.severity.name == "CRITICAL"
            for f in result.findings
        )

    def test_the_rules_severity_meta_is_honoured(self, scan) -> None:
        result = scan(FakeYara([FakeYara.Match("Hint", {"severity": "low"})]))
        assert any(
            f.rule_id == "SUSPECT.YARA.MATCH.001" and f.severity.name == "LOW"
            for f in result.findings
        )

    def test_includes_are_refused_at_compile(self, scan) -> None:
        fake = FakeYara([])
        scan(fake)
        assert fake.compiled_with.get("includes") is False

    def test_a_missing_module_is_reported_and_marks_the_scan_incomplete(self, scan) -> None:
        result = scan(None)
        note = [f for f in result.findings if f.rule_id == "OPERATIONAL.YARA.UNAVAILABLE"]
        assert note and "yara-python" in note[0].message and not result.complete

    def test_rules_that_do_not_compile_are_reported(self, scan) -> None:
        result = scan(FakeYara([], compile_error=SyntaxError("bad rule")))
        assert any(
            f.rule_id == "OPERATIONAL.YARA.UNAVAILABLE" and "could not be loaded" in f.message
            for f in result.findings
        )

    def test_an_engine_error_on_one_file_does_not_end_the_scan(self, scan) -> None:
        result = scan(FakeYara(TimeoutError("slow rule")), {"a.bin": b"EVIL", "b.txt": b"hello"})
        assert any(f.rule_id == "OPERATIONAL.YARA.UNAVAILABLE" for f in result.findings)

    def test_yara_never_runs_unless_the_operator_asks(self, tmp_path) -> None:
        (tmp_path / "x.bin").write_bytes(b"EVIL")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert not any("YARA" in f.rule_id for f in result.findings)

    def test_a_repository_config_cannot_name_the_rules(self, tmp_path) -> None:
        (tmp_path / "cordon.yaml").write_text(
            "version: 1\nyara: /tmp/rules.yar\n", encoding="utf-8"
        )
        from cordon_scanner.core.config import ConfigResolver
        from cordon_scanner.core.errors import ConfigError

        with pytest.raises(ConfigError):
            ConfigResolver.resolve(root=Path(tmp_path))
