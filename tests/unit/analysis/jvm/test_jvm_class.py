"""A compiled Java class read through its constant pool (`detect/jvm_class.py`, review 98).

The pool is built byte by byte as JVMS 4.4 lays it out: what is tested is that the reader finds a
called method by owner and name, and a string constant -- what the capability detector judges.
"""

from __future__ import annotations

import struct

from cordon_scanner.analysis.jvm.jvm_class import JvmClass


class Pool:
    @staticmethod
    def utf8(text: str) -> bytes:
        body = text.encode()
        return bytes([1]) + struct.pack(">H", len(body)) + body

    @classmethod
    def fetch_and_evaluate(cls) -> bytes:
        entries = [
            cls.utf8("groovy/lang/GroovyShell"),  # 1
            bytes([7]) + struct.pack(">H", 1),  # 2 Class
            cls.utf8("evaluate"),  # 3
            cls.utf8("(Ljava/lang/String;)Ljava/lang/Object;"),  # 4
            bytes([12]) + struct.pack(">HH", 3, 4),  # 5 NameAndType
            bytes([10]) + struct.pack(">HH", 2, 5),  # 6 Methodref
            cls.utf8("https://example.invalid/x"),  # 7
            bytes([8]) + struct.pack(">H", 7),  # 8 String
            bytes([5]) + struct.pack(">q", 7),  # 9-10 Long, two slots
            cls.utf8("unused"),  # 11
        ]
        return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, 12) + b"".join(entries)


class TestTheReader:
    def test_a_called_method_and_a_string_constant(self):
        refs = JvmClass.references(Pool.fetch_and_evaluate())
        assert refs is not None
        assert "groovy/lang/GroovyShell.evaluate" in refs.calls
        assert refs.strings == ("https://example.invalid/x",)

    def test_a_fat_mach_o_is_not_a_class(self):
        assert JvmClass.references(b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 40) is None

    def test_a_truncated_pool_reads_as_nothing(self):
        assert JvmClass.references(Pool.fetch_and_evaluate()[:30]) is None
