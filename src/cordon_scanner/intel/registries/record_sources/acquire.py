"""Acquiring a registry record: fetch the name's documents through the ecosystem's `RecordSource` and keep the record (`intel acquire`).

Here, not on `RegistryRecord`, so the record model (`registry_record`) imports nothing of the sources that build it."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cordon_scanner.intel.registries.record_sources.base import RecordFetch
from cordon_scanner.intel.registries.record_sources.table import RecordSources

if TYPE_CHECKING:
    from cordon_scanner.intel.registries.registry_record import RegistryRecord


class RecordAcquire:
    @staticmethod
    def acquire(
        ecosystem: str, name: str, version: str, *, token: str | None = None
    ) -> RegistryRecord | None:
        """Fetch the name's registry documents and keep the record as of `version`. Network. Every ecosystem is read through its
        `RecordSource`: the same fetch, the same builder, the same store. `token` is the user's own, for a host API's commit dates."""
        source = RecordSources.of(ecosystem)
        if source is None:
            return None
        documents = RecordFetch.documents(source, name, version, token=token)
        record = source.record(name, version, documents) if documents is not None else None
        if record is not None:
            record.save()
        return record
