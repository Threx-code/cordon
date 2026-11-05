"""What a binary says of itself: its machine, and whether it carries a signature -- and a jar's own
checksum where it is the artifact it names."""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

import pytest

from cordon_scanner.images.binmeta import BinaryFacts, BinaryMetadata


class FactsHelpers:
    """Executable headers built to the formats' layouts."""

    @staticmethod
    def elf(machine: int, *, big: bool = False) -> bytes:
        order = ">" if big else "<"
        return (
            b"\x7fELF"
            + bytes([2, 2 if big else 1, 1])
            + bytes(9)
            + struct.pack(order + "HH", 2, machine)
            + bytes(64)
        )

    @staticmethod
    def pe(machine: int, *, signed: bool, wide: bool = True) -> bytes:
        header = bytearray(0x400)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", header, 0x84, machine)
        optional = 0x80 + 24
        struct.pack_into("<H", header, optional, 0x20B if wide else 0x10B)
        certificate = optional + (112 if wide else 96) + 8 * 4
        if signed:
            struct.pack_into("<II", header, certificate, 0x300, 0x80)
        return bytes(header)

    @staticmethod
    def macho(cpu: int, *, signed: bool) -> bytes:
        commands = [struct.pack("<II", 0x19, 72) + bytes(64)]  # LC_SEGMENT_64
        if signed:
            commands.append(struct.pack("<IIII", 0x1D, 16, 0x1000, 0x100))  # LC_CODE_SIGNATURE
        body = b"".join(commands)
        # mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved.
        return (
            b"\xcf\xfa\xed\xfe"
            + struct.pack("<iiiIIII", cpu, 3, 2, len(commands), len(body), 0, 0)
            + body
        )

    @staticmethod
    def jar(*, signed: bool, artifacts: int = 1) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            for index in range(artifacts):
                archive.writestr(
                    f"META-INF/maven/org.acme/lib{index}/pom.properties",
                    f"groupId=org.acme\nartifactId=lib{index}\nversion=1.{index}.0\n",
                )
            if signed:
                archive.writestr("META-INF/ACME.SF", "Signature-Version: 1.0\n")
                archive.writestr("META-INF/ACME.RSA", b"\x30\x82")
        return buffer.getvalue()


class TestArchitectureAndSignature:
    @pytest.mark.conformance("x", "x.binary", "image.binaries")
    @pytest.mark.parametrize(
        ("machine", "architecture"),
        [(0x3E, "amd64"), (0xB7, "arm64"), (0xF3, "riscv64"), (0x9999, "machine 0x9999")],
    )
    def test_elf(self, machine, architecture) -> None:
        assert BinaryFacts.describe(FactsHelpers.elf(machine)) == (
            f"architecture {architecture}",
            "unsigned: ELF carries no signature of its own",
        )

    def test_a_big_endian_elf(self) -> None:
        assert BinaryFacts.describe(FactsHelpers.elf(0x16, big=True))[0] == "architecture s390x"

    @pytest.mark.conformance("x", "x.binary")
    def test_pe_and_its_authenticode_table(self) -> None:
        assert BinaryFacts.describe(FactsHelpers.pe(0x8664, signed=True)) == (
            "architecture amd64",
            "signed (an Authenticode signature is present, not verified)",
        )
        assert BinaryFacts.describe(FactsHelpers.pe(0xAA64, signed=False)) == (
            "architecture arm64",
            "unsigned",
        )
        assert (
            BinaryFacts.describe(FactsHelpers.pe(0x14C, signed=True, wide=False))[0]
            == "architecture 386"
        )

    @pytest.mark.conformance("x", "x.binary")
    def test_mach_o_and_its_code_signature(self) -> None:
        assert BinaryFacts.describe(FactsHelpers.macho(0x0100000C, signed=True)) == (
            "architecture arm64",
            "signed (a code signature is present, not verified)",
        )
        assert BinaryFacts.describe(FactsHelpers.macho(0x01000007, signed=False)) == (
            "architecture amd64",
            "unsigned",
        )
        universal = (
            b"\xca\xfe\xba\xbe"
            + struct.pack(">I", 2)
            + struct.pack(">iiIII", 0x01000007, 3, 0, 0, 0)
            + struct.pack(">iiIII", 0x0100000C, 0, 0, 0, 0)
        )
        assert BinaryFacts.describe(universal) == ("architecture amd64+arm64 (universal)",)

    def test_what_is_not_an_executable_says_nothing(self) -> None:
        # A Java class file shares the universal binary's magic; its version number is large.
        assert BinaryFacts.describe(b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + bytes(32)) == ()
        assert BinaryFacts.describe(b"MZ" + bytes(10)) == ()
        assert BinaryFacts.describe(b"#!/bin/sh\n") == ()


class TestJars:
    @pytest.mark.conformance("x", "x.binary")
    def test_a_jar_that_is_its_artifact_carries_its_checksum_and_signature(self) -> None:
        data = FactsHelpers.jar(signed=True)
        [package] = BinaryMetadata.extract("app/lib/lib0-1.0.0.jar", data)
        assert (package.ecosystem, package.name, package.version) == (
            "maven",
            "org.acme:lib0",
            "1.0.0",
        )
        assert package.integrity == "sha1:" + hashlib.sha1(data, usedforsecurity=False).hexdigest()
        assert package.platform == ("signed jar (a signature block is present, not verified)",)

    def test_a_shaded_jar_is_not_any_one_of_its_artifacts(self) -> None:
        packages = BinaryMetadata.extract("app.jar", FactsHelpers.jar(signed=False, artifacts=3))
        assert len(packages) == 3 and {p.integrity for p in packages} == {None}
        assert {p.platform for p in packages} == {("unsigned jar",)}

    def test_a_signature_file_without_its_block_is_not_a_signature(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "META-INF/maven/org.acme/x/pom.properties",
                "groupId=org.acme\nartifactId=x\nversion=1\n",
            )
            archive.writestr("META-INF/ACME.SF", "Signature-Version: 1.0\n")
        [package] = BinaryMetadata.extract("x.jar", buffer.getvalue())
        assert package.platform == ("unsigned jar",)
