"""`ContractData`: the JSON the console and the backend read equals what the registries say, and the
manifest pins every file (design spec M0; a consumer keeps the same test on its generated copy)."""

from __future__ import annotations

import hashlib
import json

from cordon_scanner.contracts.manifest import CONTRACTS_VERSION, ContractData
from cordon_scanner.contracts.reason_codes import ReasonCodes
from cordon_scanner.contracts.subjects import SubjectKind


class TestTheShippedFiles:
    def test_every_file_is_what_the_registries_generate_now(self) -> None:
        assert ContractData.problems() == []

    def test_the_manifest_lists_every_file_with_its_sha256_and_the_version(self) -> None:
        shipped = ContractData._shipped
        manifest = json.loads(shipped("manifest.json"))
        assert manifest["contracts_version"] == CONTRACTS_VERSION
        listed = manifest["files"]
        assert sorted(listed) == sorted(p for p in ContractData.expected() if p != "manifest.json")
        for path, digest in listed.items():
            assert digest == "sha256:" + hashlib.sha256(shipped(path).encode("utf-8")).hexdigest()


class TestTheData:
    def test_every_reason_code_is_listed_with_a_title_a_severity_and_a_state(self) -> None:
        listed = json.loads(ContractData.generated()["data/reason-codes.json"])
        codes = {entry["code"]: entry for entry in listed["codes"]}
        assert set(codes) == {entry.code for entry in ReasonCodes.ALL}
        for entry in codes.values():
            assert entry["title"] and entry["explanation"]
            assert entry["severity"] in ReasonCodes.SEVERITIES
            assert entry["state"] == "active"
        assert listed["retired"] == []

    def test_every_subject_kind_is_listed_with_its_prefix_and_parts(self) -> None:
        listed = json.loads(ContractData.generated()["data/subject-kinds.json"])
        assert [row["kind"] for row in listed["kinds"]] == [kind.value for kind in SubjectKind]
        assert all(row["id_prefix"] and row["required"] for row in listed["kinds"])

    def test_the_choices_are_the_ones_canonical_id_accepts(self) -> None:
        listed = json.loads(ContractData.generated()["data/subject-kinds.json"])
        choices = {row["kind"]: row["choices"] for row in listed["kinds"]}
        assert choices["mcp_server"]["transport"] == ["npm", "pypi", "oci", "remote", "local"]
        assert choices["ci_action"]["host"] == ["github", "gitlab"]
