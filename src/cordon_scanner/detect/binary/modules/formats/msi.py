"""The Windows Installer reader for cordon-rule: the `msi` module's values as a condition sees them.

An installer package is a compound file whose `\\x05DigitalSignature` stream holds an Authenticode PKCS#7
signature. What is signed is the package's directory tree from the root: each storage's children in the
order of their names' UTF-16 bytes (a name that begins another comes first), every stream's bytes but the
signature streams', and each storage's class id after its children. A package with an
`\\x05MsiDigitalSignatureEx` stream also signs its metadata: the same walk's names, class ids, stream
sizes, state bits and times, hashed first and that digest fed before the content. The signature is read
and checked by the package's own Authenticode reader (`modules.signature`, the one `pe.signatures` uses),
so `signatures[]` carries the same record as a PE's, and `is_signed` says whether any signature was read.
The names are YARA-X's (`is_signed`, `signatures[]` as `pe.Signature`, a Microsoft timestamp's chain from
every certificate the signature bundles); the reading is ours, on the compound-file listing `olecf` gives.

Named difference from YARA-X's reading: YARA-X hashes the header sector (class id and state bits zeroed),
then the streams, storages and the root's mini stream in directory order, and no metadata, which is not
what a signer signs, so its `file_digest` never equals the signed digest and `verified` is false on a
correctly signed package (measured on GitHub CLI 2.102.0's installer). Ours computes the signed content;
`length_of_chain` is kept beside `chain`, as the PE record has it.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, ClassVar

from cordon_scanner.analysis.formats import FormatError
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
        found = Signatures.parse(signature, int(time.time()), bundled=True)
        Signatures.check_digests(found, lambda name: Msi.digest(name, compound, listing))
        records, _any_valid = Signatures.records(found)
        out["signatures"] = records
        out["is_signed"] = bool(records)
        return out

    @staticmethod
    def digest(name: str, compound: CompoundFile, listing: list[tuple[str, Any]]) -> bytes | None:
        """The package's Authenticode digest with hash `name`: the metadata's digest first where the
        package signs its metadata, then the content walk; None where a stream cannot be read."""
        try:
            hasher = hashlib.new(name)
        except ValueError:
            return None
        if not compound.records:
            return None
        try:
            if any(n.lower() == "msidigitalsignatureex" for n, _ in listing):
                metadata = hashlib.new(name)
                Msi._walk(compound, metadata, metadata=True)
                hasher.update(metadata.digest())
            Msi._walk(compound, hasher, metadata=False)
        except (FormatError, ValueError, IndexError):
            return None
        return hasher.digest()

    @staticmethod
    def _walk(compound: CompoundFile, hasher: Any, *, metadata: bool) -> None:
        """The tree from the root, storages entered and left in name order: a stream's bytes (or its
        record's metadata), a storage's metadata on entry or its class id on leaving. A record seen
        twice, or past the table, is not walked again."""
        records = compound.records
        seen: set[int] = {0}
        work: list[tuple[str, int]] = [("enter", 0)]
        while work:
            step, index = work.pop()
            record = records[index]
            if step == "leave":
                hasher.update(record[80:96])
                continue
            if step == "stream":
                if metadata:
                    Msi._metadata(hasher, record, root=False)
                else:
                    hasher.update(compound.open(compound.directory[index]))
                continue
            if metadata:
                Msi._metadata(hasher, record, root=index == 0)
            if not metadata:
                work.append(("leave", index))
            for child in reversed(Msi._children(records, index, seen)):
                kind = records[child][66]
                if kind == 1:
                    work.append(("enter", child))
                elif kind == 2 and Msi._name(records[child]).lower() not in Msi.SIGNATURE_STREAMS:
                    work.append(("stream", child))

    @staticmethod
    def _children(records: list[bytes], index: int, seen: set[int]) -> list[int]:
        """A storage's children (its sibling tree from the child link), in their names' byte order."""
        found: list[int] = []
        pending = [int.from_bytes(records[index][76:80], "little")]
        while pending:
            at = pending.pop()
            if at >= len(records) or at in seen:
                continue
            seen.add(at)
            found.append(at)
            record = records[at]
            pending += [
                int.from_bytes(record[68:72], "little"),
                int.from_bytes(record[72:76], "little"),
            ]
        return sorted(found, key=lambda at: Msi._raw_name(records[at]))

    @staticmethod
    def _raw_name(record: bytes) -> bytes:
        return record[: max(min(int.from_bytes(record[64:66], "little"), 64) - 2, 0)]

    @staticmethod
    def _name(record: bytes) -> str:
        """A record's name without the leading control character a signature stream's name carries."""
        text = Msi._raw_name(record).decode("utf-16-le", "replace")
        return text[1:] if text[:1] and text[0] < "\x20" else text

    @staticmethod
    def _metadata(hasher: Any, record: bytes, *, root: bool) -> None:
        """What the metadata digest reads of a record: the name (not the root's), the class id (a
        storage's or the root's) or the size (a stream's, its low half), the state bits, the times."""
        if not root:
            hasher.update(Msi._raw_name(record))
        hasher.update(record[80:96] if record[66] != 2 else record[120:124])
        hasher.update(record[96:100])
        if not root:
            hasher.update(record[100:116])


__all__ = ["Msi"]
