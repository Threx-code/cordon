"""The compiled-program facts of a package (`BinaryFeatures`)."""

from __future__ import annotations

import os

from cordon_scanner.detect.binary.features import BinaryFeatures

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
PE = b"MZ" + b"\x00" * 62


class Fixture:
    @staticmethod
    def reader(data: bytes) -> tuple[int, object]:
        return len(data), lambda offset, length: data[offset : offset + length]

    @staticmethod
    def features(*blobs: bytes) -> dict[str, float]:
        return BinaryFeatures.of([Fixture.reader(b) for b in blobs])  # type: ignore[misc]


class TestFormats:
    def test_each_format_is_counted(self) -> None:
        facts = Fixture.features(ELF, PE, PE)
        assert facts["exe_elf"] == 1.0
        assert facts["exe_pe"] == 2.0

    def test_a_file_that_is_no_program_gives_nothing(self) -> None:
        assert Fixture.features(b"hello, world\n") == {}

    def test_the_builder_is_read_from_its_marks(self) -> None:
        facts = Fixture.features(ELF + b'\x00Go build ID: "x"\x00')
        assert facts["exe_lang_go"] == 1.0


class TestBehaviours:
    def test_a_group_counts_distinct_names_on_its_list(self) -> None:
        blob = PE + b"\x00GetAsyncKeyState\x00SetWindowsHookExW\x00GetAsyncKeyState\x00"
        assert Fixture.features(blob)["exe_group_keystrokes"] == 2.0

    def test_a_string_value_is_never_a_key(self) -> None:
        blob = ELF + b"\x00https://zqxmarkerhost.example/a\x00 10.1.2.3 \x00"
        facts = Fixture.features(blob)
        assert facts["exe_shape_url"] == 1.0
        assert facts["exe_shape_ip"] == 1.0
        assert not any("zqxmarker" in k for k in facts)

    def test_a_packer_signature_is_a_fact(self) -> None:
        assert Fixture.features(ELF + b"UPX!")["exe_packed"] == 1.0


class TestWindows:
    def test_a_name_across_a_window_cut_is_found(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(BinaryFeatures, "WINDOW", 1024)
        blob = ELF + b"\x00" * (1024 - len(ELF) - 4) + b"WriteProcessMemory\x00"
        assert Fixture.features(blob)["exe_group_injection"] == 1.0

    def test_a_shape_in_the_overlap_is_counted_once(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr(BinaryFeatures, "WINDOW", 1024)
        blob = ELF + b"\x00" * 900 + b"https://a.example\x00" + b"\x00" * 2000
        assert Fixture.features(blob)["exe_shape_url"] == 1.0

    def test_random_bytes_read_as_high_entropy(self) -> None:
        blob = ELF + os.urandom(64 * 1024)
        assert Fixture.features(blob)["exe_high_entropy"] >= 9.0

    def test_counts_are_capped(self) -> None:
        blob = ELF + b"".join(b"\x00https://h%d.example\x00" % i for i in range(200))
        assert Fixture.features(blob)["exe_shape_url"] == BinaryFeatures.CAP


class TestStrings:
    def test_a_wide_string_is_read_as_well(self) -> None:
        wide = "Software\\Microsoft\\Windows\\CurrentVersion\\Run".encode("utf-16-le")
        assert (
            Fixture.features(PE + b"\x00\x00" + wide + b"\x00\x00")["exe_group_persistence"] == 1.0
        )

    def test_a_name_split_by_bytes_that_are_no_text_is_not_found(self) -> None:
        assert "exe_group_injection" not in Fixture.features(ELF + b"WriteProc\x01essMemory")


class TestWords:
    BODY = b"\x00GetAsyncKeyState\x00CreateRemoteThread\x00send report to "

    def test_the_words_a_program_names_are_hashed_keys(self) -> None:
        facts = Fixture.features(ELF + self.BODY + b"https://zqxhost.example/zqxpath\x00")
        assert f"exe_tok_{BinaryFeatures.hashed(b'GetAsyncKeyState')}" in facts
        assert not any(k.startswith("exe_tok_") and not k[8:].isdigit() for k in facts)

    def test_where_it_sends_is_never_a_word(self) -> None:
        facts = Fixture.features(
            ELF + self.BODY + b"https://zqxhost.example/zqxpath zqxbare.com\x00"
        )
        hashes = {
            BinaryFeatures.hashed(w) for w in (b"zqxhost", b"zqxpath", b"zqxbare", b"example")
        }
        assert not any(f"exe_tok_{h}" in facts for h in hashes)

    def test_two_hosts_give_the_same_words(self) -> None:
        one = Fixture.features(ELF + self.BODY + b"https://alpha.example/a\x00")
        two = Fixture.features(ELF + self.BODY + b"https://bravo.example/b\x00")
        assert one == two
