"""G12: import tables read from ELF, PE and Mach-O, the verdicts drawn from them, and rule files.

The binaries are built here, byte by byte, with exactly the imports each test needs: a minimal
but structurally valid ELF64 (dynsym, dynstr, dynamic), PE32 (one section holding the import
directory) and Mach-O 64 (LC_LOAD_DYLIB, LC_SYMTAB). Nothing is executed. The noise check against
real binaries -- 342 Debian ELFs and the 30 PE files of the Windows Python build, zero verdicts --
is recorded in the commit; these tests pin the parsers and the rules.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.detect.binary.binary_imports import (
    ImportCapabilities,
    ImportReader,
    ImportTable,
)
from cordon_scanner.foundation.config import Config
from cordon_scanner.foundation.models import Severity


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
        from cordon_scanner.detect.binary import binary_imports

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

    def test_reading_one_named_keychain_item_is_a_keyring_not_a_stealer(self) -> None:
        # A wallet SDK's table, abridged (review 98, CDI): its own secret, then the network.
        sdk = ["CredReadW", "SecItemCopyMatching", "connect", "send", *[f"f{i}" for i in range(20)]]
        assert self.rules(sdk) == []

    def test_a_named_item_beside_a_browsers_secret_store_is(self) -> None:
        profile = ImportCapabilities.profile(
            ImportTable("Mach-O", (), ("SecKeychainFindGenericPassword", "connect", "send"))
        )
        assert [r for r, _ in ImportCapabilities.verdicts(profile, b"\0Chrome Safe Storage\0")] == [
            "SUSPECT.BINARY.CREDENTIAL_THEFT.001"
        ]

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
            [
                "socket",
                "connect",
                "execve",
                "CheckRemoteDebuggerPresent",
                *[f"f{i}" for i in range(20)],
            ]
        )
        assert "SUSPECT.BINARY.IMPLANT.001" in self.rules(
            [
                "socket",
                "connect",
                "CreateProcessW",
                "IsDebuggerPresent",
                "NtQueryInformationProcess",
                *[f"f{i}" for i in range(20)],
            ]
        )

    def test_the_c_runtimes_own_debugger_imports_are_not_anti_debugging(self) -> None:
        # adb.exe's table, abridged: a network tool that starts processes, with the two calls
        # MSVC's startup code imports into every program (review 98 P2).
        adb = [
            "WSAStartup",
            "socket",
            "connect",
            "getaddrinfo",
            "send",
            "CreateProcessW",
            "IsDebuggerPresent",
            "OutputDebugStringA",
            *[f"f{i}" for i in range(20)],
        ]
        assert "SUSPECT.BINARY.IMPLANT.001" not in self.rules(adb)

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

    @staticmethod
    def injection_severity(tmp_path, name: str, extra: bytes) -> Severity:
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / name).write_bytes(
            Build.pe(
                {"KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]}
            )
            + extra
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return next(
            f.severity
            for f in result.findings
            if f.rule_id == "SUSPECT.BINARY.PROCESS_INJECTION.001"
        )

    def test_the_cygwin_runtime_is_reported_below_the_gate(self, tmp_path) -> None:
        assert (
            self.injection_severity(tmp_path, "cygwin1.dll", b"\0cygwin_internal\0")
            == Severity.MEDIUM
        )

    def test_the_cygwin_name_without_its_runtime_is_not(self, tmp_path) -> None:
        assert self.injection_severity(tmp_path, "cygwin1.dll", b"") == Severity.HIGH

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


class RuleFileFixtures:
    """Real rules, compiled and matched by Cordon's own engine (`detect/binary/rule_engine/lang`)."""

    @pytest.fixture
    def scan(self, tmp_path):
        def run(rules_text: str, files: dict[str, bytes] | None = None):
            rules = tmp_path / "rules.yar"
            rules.write_text(rules_text, encoding="utf-8")
            target = tmp_path / "repo"
            target.mkdir(exist_ok=True)
            for name, data in (files or {"payload.bin": b"\x00EVIL\x00"}).items():
                (target / name).write_bytes(data)
            config = Config.default().with_overrides(use_cache=False, rule_file=str(rules))
            return Scanner(config).scan(target)

        return run

    @staticmethod
    def rule(name: str, meta: str = "") -> str:
        return (
            f'rule {name} {{ meta: {meta} strings: $e = "EVIL" condition: $e }}\n'
            if meta
            else (f'rule {name} {{ strings: $e = "EVIL" condition: $e }}\n')
        )


class TestRuleFile(RuleFileFixtures):
    def test_a_match_is_reported_with_the_rule_name(self, scan) -> None:
        result = scan(self.rule("Trojan_Foo", 'description = "loader stub"'))
        found = [f for f in result.findings if f.rule_id == "SUSPECT.RULEFILE.MATCH.001"]
        assert found and "Trojan_Foo" in found[0].message and found[0].severity.name == "HIGH"
        assert "loader stub" in found[0].message
        assert any(f.rule_id == "OPERATIONAL.RULEFILE.STATUS" for f in result.findings)

    def test_a_file_the_rule_does_not_match_is_not_reported(self, scan) -> None:
        result = scan(self.rule("Trojan_Foo"), {"clean.bin": b"nothing here"})
        assert not [f for f in result.findings if f.rule_id == "SUSPECT.RULEFILE.MATCH.001"]

    def test_a_rule_declared_malicious_is_malware(self, scan) -> None:
        result = scan(self.rule("Ransom_X", 'category = "malicious"'))
        assert any(
            f.rule_id == "MALWARE.RULEFILE.MATCH.001" and f.severity.name == "CRITICAL"
            for f in result.findings
        )

    def test_the_rules_severity_meta_is_honoured(self, scan) -> None:
        result = scan(self.rule("Hint", 'severity = "low"'))
        assert any(
            f.rule_id == "SUSPECT.RULEFILE.MATCH.001" and f.severity.name == "LOW"
            for f in result.findings
        )

    def test_includes_are_refused(self, scan) -> None:
        result = scan('include "/etc/other.yar"\n' + self.rule("x"))
        assert any(
            f.rule_id == "OPERATIONAL.RULEFILE.UNAVAILABLE" and "include" in f.message
            for f in result.findings
        )

    def test_a_module_the_engine_does_not_implement_is_reported_and_marks_the_scan_incomplete(
        self, scan
    ) -> None:
        result = scan('import "cuckoo"\nrule x { condition: true }\n')
        note = [f for f in result.findings if f.rule_id == "OPERATIONAL.RULEFILE.UNAVAILABLE"]
        assert note and "cuckoo" in note[0].message and not result.complete

    def test_rules_that_do_not_compile_are_reported(self, scan) -> None:
        result = scan("rule broken { condition: }\n")
        assert any(
            f.rule_id == "OPERATIONAL.RULEFILE.UNAVAILABLE" and "could not be loaded" in f.message
            for f in result.findings
        )

    def test_an_engine_error_on_one_file_does_not_end_the_scan(self, scan, monkeypatch) -> None:
        from cordon_scanner.detect.binary.rule_engine import lang

        original = lang.Rules.match

        def match(self, data, timeout=None):
            if b"EVIL" in data:
                raise lang.RuleError("matching took longer than the time allowed")
            return original(self, data, timeout)

        monkeypatch.setattr(lang.Rules, "match", match)
        result = scan(self.rule("x"), {"a.bin": b"EVIL", "b.txt": b"hello"})
        assert any(f.rule_id == "OPERATIONAL.RULEFILE.UNAVAILABLE" for f in result.findings)

    def test_a_rule_file_never_runs_unless_the_operator_asks(self, tmp_path) -> None:
        (tmp_path / "x.bin").write_bytes(b"EVIL")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        assert not any("RULEFILE" in f.rule_id for f in result.findings)

    def test_a_repository_config_cannot_name_the_rules(self, tmp_path) -> None:
        (tmp_path / "cordon.yaml").write_text(
            "version: 1\nrule_file: /tmp/rules.yar\n", encoding="utf-8"
        )
        from cordon_scanner.foundation.config_resolver import ConfigResolver
        from cordon_scanner.foundation.errors import ConfigError

        with pytest.raises(ConfigError):
            ConfigResolver.resolve(root=Path(tmp_path))


class TestRenamedNames:
    """The names this detector had before 0.7.0 keep working for a release."""

    def test_the_old_flag_still_names_the_rule_file_and_warns(self, tmp_path, capsys) -> None:
        from cordon_scanner.cli.main import CommandLine

        rules = tmp_path / "rules.yar"
        rules.write_text('rule x { strings: $e = "EVIL" condition: $e }\n', encoding="utf-8")
        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.bin").write_bytes(b"EVIL")
        out = tmp_path / "out.json"
        CommandLine.main(
            ["scan", str(target), "--yara", str(rules), "--no-cache", "-q", "--format", "json",
             "--output", str(out), "--progress", "never"]
        )  # fmt: skip
        assert "--yara and CORDON_YARA are deprecated" in capsys.readouterr().err
        assert "SUSPECT.RULEFILE.MATCH.001" in out.read_text(encoding="utf-8")

    def test_an_old_rule_id_still_suppresses_its_finding(self) -> None:
        from cordon_scanner.decide.policy import SuppressionMatcher
        from cordon_scanner.foundation.models import Suppression

        finding = TestRenamedNames.finding("SUSPECT.RULEFILE.MATCH.001")
        old = Suppression(
            rule="SUSPECT.YARA.MATCH.001", path="a.bin", justification="x" * 40,
            expires="2099-01-01",
        )  # fmt: skip
        assert SuppressionMatcher._matches(finding, old)

    def test_a_renamed_rule_keeps_its_fingerprints(self) -> None:
        new = TestRenamedNames.finding("SUSPECT.RULEFILE.MATCH.001")
        old = TestRenamedNames.finding("SUSPECT.YARA.MATCH.001")
        assert new.fingerprint == old.fingerprint

    def test_an_old_detector_id_in_a_config_names_the_new_detector(self, tmp_path) -> None:
        from cordon_scanner.foundation.config_resolver import ConfigResolver

        (tmp_path / "cordon.yaml").write_text(
            "version: 1\nscan:\n  detectors:\n    yara: false\n", encoding="utf-8"
        )
        config = ConfigResolver.resolve(root=Path(tmp_path))
        assert config.detectors.get("rule-file") is False and "yara" not in config.detectors

    @staticmethod
    def finding(rule_id: str) -> Any:
        from cordon_scanner.foundation.models import (
            Category,
            Confidence,
            Evidence,
            EvidenceKind,
            Explanation,
            Finding,
            Location,
            RedactionMode,
            RiskScore,
            Severity,
        )

        return Finding(
            rule_id=rule_id,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message="m",
            location=Location(path="a.bin"),
            evidence=Evidence(
                kind=EvidenceKind.HASH, match_hash="ab", redaction=RedactionMode.HASH_ONLY
            ),
            risk=RiskScore(value=50, base=50, confidence_multiplier=1.0),
            remediation="r",
            explanation=Explanation(summary="s", matched_rule=rule_id),
            detector="rule-file",
        )
