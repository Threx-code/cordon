"""The DEX reader (modules.formats.dex) on a dex built here byte by byte: four strings, one type, one
prototype, one field, one method, one class with class data naming a static field and a direct method with
a code item, and a map list; the one reading rules depend on (a string's bytes from one past its length's
first byte, the 0x80000 id bound); and the reader's own strict readings where the reference's are
accidents (tables read on their own, an entry that does not resolve leaving nothing, a varint of at most
five bytes). The shared class data test pins the run design: N classes pointing at one class data give the
same entries N times over, decoded once. The values asserted are worked from the format and the reference's
declared names; the recorded-reference differential joins the review harness once the reference image
exists."""

from __future__ import annotations

import struct
from typing import Any

from cordon_scanner.detect.binary.modules.formats.dex import Dex, DexTables
from cordon_scanner.detect.binary.modules.values import Data

NO_INDEX = DexTables.INTEGERS["NO_INDEX"]


class Build:
    """A dex laid out in the format's order: header, id tables, class_defs, string data, class data, a
    code item, the map list."""

    STRINGS = (b"Lcom/A;", b"run", b"V", b"x")

    @staticmethod
    def uleb(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return bytes(out)

    @staticmethod
    def dex(
        strings: tuple[bytes, ...] = STRINGS,
        *,
        method_diff: int = 0,
        class_data: bool = True,
        map_list: bool = True,
    ) -> bytes:
        count = len(strings)
        string_ids_at = 112
        type_ids_at = string_ids_at + 4 * count
        proto_ids_at = type_ids_at + 4
        field_ids_at = proto_ids_at + 12
        method_ids_at = field_ids_at + 8
        class_defs_at = method_ids_at + 8
        data_at = class_defs_at + 32
        string_data, offsets = b"", []
        for s in strings:
            offsets.append(data_at + len(string_data))
            string_data += Build.uleb(len(s)) + s + b"\x00"
        class_data_at = data_at + len(string_data)
        code_at = (class_data_at + 16 + 7) & ~7
        counts = Build.uleb(1) + Build.uleb(0) + Build.uleb(1) + Build.uleb(0)
        field = Build.uleb(0) + Build.uleb(0x9)
        method = Build.uleb(method_diff) + Build.uleb(0x1) + Build.uleb(code_at)
        body = counts + field + method
        code = struct.pack("<4H2I", 1, 0, 0, 0, 0, 2) + b"\x0e\x00\x0e\x00"
        map_at = code_at + len(code)
        map_bytes = struct.pack("<I", 1) + struct.pack("<2H2I", 0, 0, 1, 0)
        file_size = map_at + len(map_bytes)
        header = (
            b"dex\n035\x00" + struct.pack("<I", 0x1234) + b"\xab" * 20
            + struct.pack("<20I", file_size, 0x70, 0x12345678, 0, 0, map_at if map_list else 0,
                          count, string_ids_at, 1, type_ids_at, 1, proto_ids_at, 1, field_ids_at,
                          1, method_ids_at, 1, class_defs_at, file_size - data_at, data_at)
        )  # fmt: skip
        tables = (
            struct.pack(f"<{count}I", *offsets)
            + struct.pack("<I", 0)  # type 0: descriptor string 0
            + struct.pack("<3I", 2, 0, 0)  # proto 0: shorty "V", returns type 0
            + struct.pack("<2HI", 0, 0, 3)  # field 0: class 0, type 0, name "x"
            + struct.pack("<2HI", 0, 0, 1)  # method 0: class 0, proto 0, name "run"
            + struct.pack(
                "<8I", 0, 1, NO_INDEX, 0, NO_INDEX, 0, class_data_at if class_data else 0, 0
            )
        )
        out = header + tables + string_data + body
        return out.ljust(code_at, b"\x00") + code + map_bytes

    @staticmethod
    def shared(classes: int, methods: int) -> bytes:
        """`classes` class definitions all pointing at one class data of `methods` direct methods, each
        naming method 0."""
        strings = (b"Lcom/A;", b"run", b"V")
        string_ids_at = 112
        type_ids_at = string_ids_at + 12
        proto_ids_at = type_ids_at + 4
        field_ids_at = proto_ids_at + 12
        method_ids_at = field_ids_at + 8
        class_defs_at = method_ids_at + 8
        data_at = class_defs_at + 32 * classes
        string_data, offsets = b"", []
        for s in strings:
            offsets.append(data_at + len(string_data))
            string_data += Build.uleb(len(s)) + s + b"\x00"
        class_data_at = data_at + len(string_data)
        body = Build.uleb(0) + Build.uleb(0) + Build.uleb(methods) + Build.uleb(0)
        body += (Build.uleb(0) + Build.uleb(1) + Build.uleb(0)) * methods
        file_size = class_data_at + len(body)
        header = (
            b"dex\n035\x00" + struct.pack("<I", 0) + b"\x00" * 20
            + struct.pack("<20I", file_size, 0x70, 0x12345678, 0, 0, 0, 3, string_ids_at, 1, type_ids_at,
                          1, proto_ids_at, 1, field_ids_at, 1, method_ids_at, classes, class_defs_at,
                          file_size - data_at, data_at)
        )  # fmt: skip
        tables = (
            struct.pack("<3I", *offsets) + struct.pack("<I", 0) + struct.pack("<3I", 2, 0, 0)
            + struct.pack("<2HI", 0, 0, 1) + struct.pack("<2HI", 0, 0, 1)
            + b"".join(
                struct.pack("<8I", 0, 1, NO_INDEX, 0, NO_INDEX, 0, class_data_at, 0) for _ in range(classes)
            )
        )  # fmt: skip
        return header + tables + string_data + body

    @staticmethod
    def patched(data: bytes, at: int, value: int) -> bytes:
        """`data` with the 32-bit header field at `at` set to `value`."""
        return data[:at] + struct.pack("<I", value) + data[at + 4 :]


class Regex:
    """A regular-expression argument as the engine hands one over: `run(text)` is the match's end, or -1."""

    def __init__(self, needle: bytes) -> None:
        self.needle = needle

    def run(self, text: bytes) -> int:
        at = text.find(self.needle)
        return -1 if at < 0 else at + len(self.needle)


class TestValues:
    def test_header_tables_class_data_and_names(self) -> None:
        d = Dex.data(Build.dex())
        h = d["header"]
        assert (h["magic"], h["checksum"], h["signature"], h["header_size"], h["endian_tag"]) == (
            b"dex\n035\x00", 0x1234, b"\xab" * 20, 0x70, 0x12345678
        )  # fmt: skip
        assert h["string_ids_size"] == 4 and h["class_defs_size"] == 1
        assert d["string_ids"][1] == {
            "offset": d["string_ids"][1]["offset"],
            "size": 3,
            "value": b"run",
        }
        assert d["type_ids"][0] == {"descriptor_idx": 0}
        assert d["proto_ids"][0] == {"shorty_idx": 2, "return_type_idx": 0, "parameters_offset": 0}
        assert d["field_ids"][0] == {"class_idx": 0, "type_idx": 0, "name_idx": 3}
        assert d["method_ids"][0] == {"class_idx": 0, "proto_idx": 0, "name_idx": 1}
        assert (
            d["class_defs"][0]["super_class_idx"] == NO_INDEX
            and d["class_defs"][0]["access_flags"] == 1
        )
        assert d["class_data_item"][0] == {
            "static_fields_size": 1, "instance_fields_size": 0, "direct_methods_size": 1, "virtual_methods_size": 0
        }  # fmt: skip
        assert d["number_of_fields"] == 1
        assert d["field"][0] == {
            "class_name": b"Lcom/A;", "name": b"x", "proto": b"Lcom/A;", "static": 1, "instance": 0,
            "field_idx_diff": 0, "access_flags": 0x9,
        }  # fmt: skip
        assert d["number_of_methods"] == 1
        m = d["method"][0]
        assert {k: v for k, v in m.items() if k != "code_item"} == {
            "class_name": b"Lcom/A;", "name": b"run", "proto": b"V", "direct": 1, "virtual": 0,
            "method_idx_diff": 0, "access_flags": 0x1, "code_off": m["code_off"],
        }  # fmt: skip
        assert m["code_item"] == {
            "registers_size": 1, "ins_size": 0, "outs_size": 0, "tries_size": 0, "debug_info_off": 0,
            "insns_size": 2, "insns": b"\x0e\x00\x0e\x00",
        }  # fmt: skip
        assert d["map_list"] == {
            "size": 1,
            "map_item": {0: {"type": 0, "unused": 0, "size": 1, "offset": 0}},
        }

    def test_has_method_and_has_class(self) -> None:
        d = Dex.data(Build.dex())
        by_name, by_class_and_name, by_regex, by_class_and_regex = d["has_method"]
        assert by_name(b"run") == 1 and by_name(b"walk") == 0 and by_name(b"run\x00") == 0
        assert (
            by_class_and_name(b"Lcom/A;", b"run") == 1
            and by_class_and_name(b"Lcom/B;", b"run") == 0
        )
        assert by_regex(Regex(b"ru")) == 1 and by_regex(Regex(b"zz")) == 0
        assert by_class_and_regex(Regex(b"com/A"), Regex(b"run")) == 1
        assert by_class_and_regex(Regex(b"com/B"), Regex(b"run")) == 0
        class_by_name, class_by_regex = d["has_class"]
        assert class_by_name(b"Lcom/A;") == 1 and class_by_name(b"Lcom/B;") == 0
        assert class_by_regex(Regex(b"A;")) == 1 and class_by_regex(Regex(b"B;")) == 0

    def test_conforms_to_the_declared_schema(self) -> None:
        for data in (
            Build.dex(),
            Build.dex(class_data=False),
            Build.dex()[:200],
            Build.shared(3, 4),
            b"no",
        ):
            assert Data.conforms(Dex.SCHEMA, Dex.data(data)) == []


class TestSharedClassData:
    def test_classes_sharing_one_class_data_give_its_entries_once_each(self) -> None:
        """N classes pointing at one class data: number_of_methods is N times the data's methods, and
        method[i] is the data's entry i modulo that count, the same object decoded once."""
        one = Dex.data(Build.shared(1, 50))
        many = Dex.data(Build.shared(7, 50))
        assert one["number_of_methods"] == 50 and many["number_of_methods"] == 350
        assert len(many["class_data_item"]) == 7 and all(
            many["class_data_item"][c]["direct_methods_size"] == 50 for c in range(7)
        )
        for i in (0, 49, 50, 123, 349):
            assert many["method"][i] == one["method"][i % 50]
        assert many["method"][0] is many["method"][100]  # one decode, shared
        assert 350 not in many["method"] and len(many["method"]) == 350
        assert many["has_method"][0](b"run") == 1 and many["has_class"][0](b"Lcom/A;") == 1
        assert sorted(many["method"]) == list(range(350))


class TestBounds:
    def test_not_a_dex_gives_the_constants_alone(self) -> None:
        d = Dex.data(b"PK\x03\x04 an apk is a zip, not a dex")
        assert d["header"] == {} and d["method"] == {} and "number_of_methods" not in d
        assert d["DEX_FILE_MAGIC_035"] == b"dex\n035\x00" and d["ACC_NATIVE"] == 0x100
        assert d["has_method"][0](b"run") is None and d["has_class"][1](Regex(b"A")) is None
        assert "header_size" not in Dex.data(Build.dex()[:111])["header"]

    def test_each_table_is_read_on_its_own(self) -> None:
        """A table outside the file is empty and the others are still read (the reference stops at the
        first); a class whose data is cut off contributes nothing and the totals are still counted."""
        full = Build.dex()
        no_types = Dex.data(Build.patched(full, 68, 0xFFFFFF00))  # type_ids_offset past the end
        assert no_types["type_ids"] == {} and no_types["proto_ids"] == {
            0: {"shorty_idx": 2, "return_type_idx": 0, "parameters_offset": 0}
        }
        assert no_types["method"][0]["name"] == b"run" and "class_name" not in no_types["method"][0]
        cut = Dex.data(full[: Dex.data(full)["string_ids"][2]["offset"]])
        assert set(cut["string_ids"]) == {0, 1} and cut["type_ids"] == {0: {"descriptor_idx": 0}}
        assert (
            cut["class_defs"] != {}
            and cut["number_of_methods"] == 0
            and cut["class_data_item"] == {}
        )
        table_cut = Dex.data(full[:120])  # no id table fits
        assert table_cut["header"]["string_ids_size"] == 4 and table_cut["string_ids"] == {}

    def test_a_string_is_read_from_one_past_its_length_whatever_the_length_took(self) -> None:
        """A length of 130 takes two varint bytes; the reference starts the value one byte in, and rules
        see that value."""
        long = b"L" + b"y" * 129
        d = Dex.data(Build.dex((b"Lcom/A;", b"run", b"V", long)))
        assert d["string_ids"][3]["size"] == 130
        assert d["string_ids"][3]["value"] == b"\x01" + long[:129]

    def test_an_entry_whose_id_is_past_the_table_leaves_nothing(self) -> None:
        """The reference leaves the entry's decoded fields at the next index, uncounted."""
        d = Dex.data(Build.dex(method_diff=5))
        assert d["number_of_methods"] == 0 and len(d["method"]) == 0 and 0 not in d["method"]
        assert (
            d["has_method"][0](b"run") == 0 and d["class_data_item"][0]["direct_methods_size"] == 1
        )

    def test_an_id_past_the_reference_bound_resolves_to_nothing(self) -> None:
        d = Dex.data(Build.dex(method_diff=DexTables.MAX_INDEX + 1))
        assert d["number_of_methods"] == 0

    def test_no_class_data_and_no_map(self) -> None:
        d = Dex.data(Build.dex(class_data=False, map_list=False))
        assert (
            d["number_of_methods"] == 0
            and d["number_of_fields"] == 0
            and d["class_data_item"] == {}
        )
        assert d["map_list"] == {"map_item": {}}

    def test_a_varint_is_at_most_five_bytes_with_the_fifth_in_range(self) -> None:
        reader = Dex(
            b"\x7f" + b"\x80\x01" + b"\xff\xff\xff\xff\x0f" + b"\xff\xff\xff\xff\xff" + b"\x80", {}
        )
        assert reader.varint(0) == (0x7F, 1)
        assert reader.varint(1) == (0x80, 2)
        assert reader.varint(3) == (0xFFFFFFFF, 5)
        assert (
            reader.varint(8) is None
        )  # a fifth byte past the 32-bit range (the reference keeps its bits)
        assert reader.varint(13) is None  # a continuation at the end of the file
        assert reader.varint(14) is None

    def test_a_decoded_value_type_check(self) -> None:
        out: dict[str, Any] = Dex.data(Build.dex())
        assert all(
            isinstance(v, bytes) for v in (out["DEX_FILE_MAGIC_039"], out["header"]["magic"])
        )
