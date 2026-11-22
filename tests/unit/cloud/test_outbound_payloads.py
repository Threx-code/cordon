"""Rows BP-7-14 and BP-16-4: what the execution plane uploads, and in what form a name leaves.

* BP-7-14: an upload is kept until the control plane has it (an at-least-once outbox), deduplicated by the sha256 of its bytes: the
  same envelope uploaded twice is stored once, and a network drop in the middle of an upload loses nothing.
* BP-16-4: a private name (a private registry, one of the tenant's internal namespaces) leaves only as its keyed hash, unless the
  tenant opted in to plain names; a public one stays plain; with no key to hash by, a private name is withheld, never sent plain.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from cordon_scanner.cloud.local_runtime import NamePolicy
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.private_names import PrivateNames
from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
from kits.bundle_kit import T0, Kit, Platform, Upstream
from kits.tenant_keys import StaticTenantKeys

PRIVATE_NAME = "pkg:npm/%40acme/billing-internal"
KEYS = StaticTenantKeys()


class Things:
    @staticmethod
    def artifact(subject: str = PRIVATE_NAME, **more: str) -> ArtifactRef:
        return ArtifactRef(
            kind="package",
            subject_id=subject,
            digest=ArtifactDigests.of_bytes(subject.encode()),
            ecosystem="npm",
            version="1.2.3",
            released_at="2026-06-01T00:00:00Z",
            **more,
        )

    @staticmethod
    def runtime(tmp_path: Path, names: NamePolicy | None):
        platform = Platform()
        store = LocalStore(tmp_path)
        runtime = Kit.runtime(platform, store, names=names)
        runtime.accept([Kit.first(platform)], T0)
        return runtime, store

    @staticmethod
    def uploaded(runtime, store: LocalStore, artifact: ArtifactRef) -> bytes:
        runtime.ask(
            "ci_gate",
            artifact,
            EvidenceSet(),
            T0 + timedelta(minutes=1),
            environment="production",
            scope_path=("acme",),
        )
        (item,) = store.pending()
        return item.body


class TestTheOutboxDeduplicatesByTheSha:
    def test_the_same_upload_queued_twice_is_kept_once(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        assert store.enqueue("decision", b"one envelope") and store.enqueue(
            "decision", b"one envelope"
        )
        assert len(store.pending()) == 1

    def test_the_same_bytes_as_another_kind_are_another_upload(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        store.enqueue("decision", b"bytes")
        store.enqueue("evidence", b"bytes")
        assert len(store.pending()) == 2

    def test_a_full_outbox_still_accepts_what_it_already_holds(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path, max_pending=1)
        assert store.enqueue("decision", b"kept")
        assert store.enqueue("decision", b"kept") and store.refused() == 0
        assert not store.enqueue("decision", b"another") and store.refused() == 1

    def test_the_receiver_stores_an_envelope_uploaded_twice_once(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        store.enqueue("decision", b"envelope")
        upstream = Upstream()
        store.drain(upstream)
        store.enqueue("decision", b"envelope")  # the same envelope again, after the first was sent
        store.drain(upstream)
        assert len(upstream.received) == 1 and upstream.calls == 2

    def test_a_drop_in_the_middle_of_an_upload_loses_nothing(self, tmp_path: Path) -> None:
        store = LocalStore(tmp_path)
        for number in range(4):
            store.enqueue("decision", f"envelope {number}".encode())
        upstream = Upstream(fail_on=2)
        assert store.drain(upstream).left == 3
        assert store.drain(upstream).left == 0
        assert len(upstream.received) == 4


class TestAPrivateNameLeavesOnlyHashed:
    def test_a_name_from_a_private_registry_is_the_keyed_hash(self, tmp_path: Path) -> None:
        runtime, store = Things.runtime(tmp_path, NamePolicy("tenant-1", KEYS))
        body = Things.uploaded(runtime, store, Things.artifact(registry="npm.corp.example.com"))
        document = json.loads(body)
        assert document["subject"] == PrivateNames.hashed(PRIVATE_NAME, "tenant-1", KEYS)
        assert document["subject"].startswith("hash:pkg/")
        assert b"billing-internal" not in body and PRIVATE_NAME.encode() not in body

    def test_a_name_in_one_of_the_tenants_internal_namespaces_is_hashed(
        self, tmp_path: Path
    ) -> None:
        names = NamePolicy("tenant-1", KEYS, internal_namespaces=("@acme",))
        runtime, store = Things.runtime(tmp_path, names)
        body = Things.uploaded(
            runtime, store, Things.artifact(namespace="@acme", registry="registry.npmjs.org")
        )
        assert (
            json.loads(body)["subject"].startswith("hash:pkg/") and b"billing-internal" not in body
        )

    def test_a_public_name_stays_plain(self, tmp_path: Path) -> None:
        runtime, store = Things.runtime(tmp_path, NamePolicy("tenant-1", KEYS))
        body = Things.uploaded(
            runtime, store, Things.artifact("pkg:npm/left-pad", registry="registry.npmjs.org")
        )
        assert json.loads(body)["subject"] == "pkg:npm/left-pad"

    def test_a_tenant_that_opted_in_sends_private_names_plain(self, tmp_path: Path) -> None:
        runtime, store = Things.runtime(tmp_path, NamePolicy("tenant-1", KEYS, plain_opt_in=True))
        body = Things.uploaded(runtime, store, Things.artifact(registry="npm.corp.example.com"))
        assert json.loads(body)["subject"] == PRIVATE_NAME

    def test_with_no_key_to_hash_by_a_private_name_is_withheld_never_sent_plain(
        self, tmp_path: Path
    ) -> None:
        runtime, store = Things.runtime(tmp_path, None)
        body = Things.uploaded(runtime, store, Things.artifact(registry="npm.corp.example.com"))
        assert json.loads(body)["subject"] is None and b"billing-internal" not in body

    def test_with_no_key_a_public_name_is_plain(self, tmp_path: Path) -> None:
        runtime, store = Things.runtime(tmp_path, None)
        body = Things.uploaded(
            runtime, store, Things.artifact("pkg:npm/left-pad", registry="registry.npmjs.org")
        )
        assert json.loads(body)["subject"] == "pkg:npm/left-pad"

    def test_the_digest_and_the_version_travel_and_the_decision_names_no_package(
        self, tmp_path: Path
    ) -> None:
        runtime, store = Things.runtime(tmp_path, NamePolicy("tenant-1", KEYS))
        artifact = Things.artifact(registry="npm.corp.example.com")
        document = json.loads(Things.uploaded(runtime, store, artifact))
        assert document["digest"] == artifact.digest and document["version"] == "1.2.3"
        assert "billing-internal" not in json.dumps(document["decision"])

    @pytest.mark.parametrize("registry", [None, "registry.npmjs.org", "pypi.org", "ghcr.io"])
    def test_a_known_public_registry_or_none_is_never_private(self, registry: str | None) -> None:
        assert PrivateNames.is_private(registry=registry) is False
