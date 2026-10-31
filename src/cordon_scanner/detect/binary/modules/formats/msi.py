"""The Windows Installer reader for cordon-rule: the `msi` module's values as a condition sees them.

An installer package is a compound file whose `\\x05DigitalSignature` stream holds an Authenticode PKCS#7
signature over the package: the first sector's header with its class id and version fields zeroed, then
every stream's bytes in directory order except the signature streams themselves. The signature is read
and checked by the package's own Authenticode reader (`modules.signature`, the one `pe.signatures` uses),
so `signatures[]` carries the same record as a PE's, and `is_signed` says whether any signature was read.
The names are YARA-X's (`is_signed`, `signatures[]` as `pe.Signature`); the reading is ours, on the
compound-file listing `olecf` gives.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, ClassVar

from cordon_scanner.analysis.formats.ole import CompoundFile
from cordon_scanner.detect.binary.modules.formats.olecf import Olecf
from cordon_scanner.detect.binary.modules.signature import SIGNATURE, Signatures
from cordon_scanner.detect.binary.modules.values import Record, Scalar, Seq

BOOL = Scalar.BOOL


class Msi:
    """The `msi` module reader."""

    SIGNATURE_STREAMS: ClassVar[frozenset[str]] = frozenset(
        {"digitalsignature", "msidigitalsignatureex"}
    )
    SCHEMA: ClassVar[Record] = Record({"is_signed": BOOL, "signatures": Seq(SIGNATURE)})

    @staticmethod
    def data(file: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {"is_signed": False, "signatures": {}}
        compound = Olecf.compound(file)
        if compound is None:
            return out
        listing = Olecf.listing(compound)
        signature = next(
            (
                Olecf.stream(compound, entry)
                for name, entry in listing
                if name.lower() == "digitalsignature"
            ),
            None,
        )
        if not signature:
            return out
        found = Signatures.parse(signature, int(time.time()))
        Signatures.check_digests(found, lambda name: Msi.digest(name, compound, listing))
        records, _any_valid = Signatures.records(found)
        out["signatures"] = records
        out["is_signed"] = bool(records)
        return out

    @staticmethod
    def digest(name: str, compound: CompoundFile, listing: list[tuple[str, Any]]) -> bytes | None:
        """The package's Authenticode digest with hash `name`: the first sector with bytes 8 to 27
        zeroed, then each stream in directory order but the signature streams, fed as read."""
        try:
            hasher = hashlib.new(name)
        except ValueError:
            return None
        sector = compound.sector
        header = compound.data[:sector]
        if len(header) < sector:
            return None
        hasher.update(header[:8])
        hasher.update(bytes(20))
        hasher.update(header[28:])
        for stream_name, entry in listing:
            if stream_name.lower() in Msi.SIGNATURE_STREAMS:
                continue
            data = Olecf.stream(compound, entry)
            if data is not None:
                hasher.update(data)
        return hasher.digest()


__all__ = ["Msi"]
