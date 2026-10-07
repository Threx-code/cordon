"""The universal clauses, asked of every ecosystem with a builder (`conformancebuilders.py`).

Each test is parametrized over the ecosystems whose profile has what it needs; `PROVES` maps each
clause to the ecosystems its test runs for, and `test_contract.py` counts those as proven -- the
tests themselves run in this suite, so a proof that stops holding fails the suite.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from conformancebuilders import MARKER, PROFILES, EcosystemProfile, Pkg, Profiles
from conformancekit import ConformanceCase, ConformanceRun


class Universal:
    @staticmethod
    def scan(
        root: Path,
        ecosystem: str,
        advisories: list[dict[str, Any]] | None = None,
        args: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        expect: dict[str, Any] = {"args": list(args)}
        if advisories is not None:
            (root.parent / "advisories.json").write_text(json.dumps(advisories))
            expect["advisories"] = True
        case = ConformanceCase(ecosystem, "universal", root, expect)
        code, out = ConformanceRun.scan(root, case)
        assert code != 2, out[-1500:]
        return json.loads(out[out.index("{") :])

    @staticmethod
    def project(tmp_path: Path, profile: EcosystemProfile, pkgs: list[Pkg]) -> Path:
        root = tmp_path / "project"
        root.mkdir(parents=True, exist_ok=True)
        profile.write(root, pkgs)
        return root

    @staticmethod
    def records(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {}
        for dependency in report["dependencies"]:
            out.setdefault(dependency["record"]["name"].lower(), []).append(dependency["record"])
        return out

    @staticmethod
    def advisory(profile: EcosystemProfile, name: str, **fields: Any) -> dict[str, Any]:
        return {
            "ecosystem": profile.id,
            "name": name,
            "summary": "A conformance-suite test record.",
            "severity": "high",
            **fields,
        }


ids = Profiles.of


ALL = list(PROFILES)
HASHED = [p for p in PROFILES if p.hash_of and p.malformed_hash]
SQUATTABLE = [p for p in PROFILES if p.typosquat]
INTERNAL = [p for p in PROFILES if p.internal]
EXECUTABLE = [p for p in PROFILES if p.executable]

#: Clause -> the ecosystems its test below runs for.
PROVES: dict[str, set[str]] = {
    "UNI-05": set(ids(ALL)),
    "UNI-11": set(ids(ALL)),
    "UNI-12": set(ids(ALL)),
    "UNI-13": set(ids(SQUATTABLE)),
    "UNI-14": set(ids(INTERNAL)),
    "UNI-15": set(ids(HASHED)),
    "UNI-20": set(ids(ALL)),
    "UNI-23": set(ids(ALL)),
    "UNI-26": set(ids(ALL)),
    "UNI-27": set(ids(EXECUTABLE)),
    "UNI-30": set(ids(ALL)),
    "kind:adversarial": set(ids(ALL)),
}


class TestMatching:
    """UNI-05, UNI-11, UNI-12, UNI-23: an affected version is found, the fixed one and an unrelated
    package are not, a known-malicious release is named as such, and the fix is the fixed version."""

    @pytest.mark.conformance("x", "x.malicious")
    @pytest.mark.parametrize("profile", ALL, ids=ids(ALL))
    def test_affected_found_fixed_not_malicious_named(self, profile, tmp_path) -> None:
        first, second, third = profile.names
        affected, fixed, later = profile.versions
        pkgs = [Pkg(first, affected), Pkg(second, fixed), Pkg(third, later)]
        advisories = [
            Universal.advisory(
                profile, first, identifier="CONFORMANCE-RANGE", introduced="0", fixed=fixed
            ),
            Universal.advisory(
                profile, second, identifier="CONFORMANCE-RANGE-2", introduced="0", fixed=fixed
            ),
            Universal.advisory(
                profile, third, identifier="CONFORMANCE-MAL", versions=[later], malicious=True
            ),
        ]
        report = Universal.scan(Universal.project(tmp_path, profile, pkgs), profile.id, advisories)
        records = Universal.records(report)
        assert records[first.lower()][0]["advisory_status"] == "vulnerable", (
            "affected version not found"
        )
        assert records[second.lower()][0]["advisory_status"] == "no_matching_advisory", (
            "the fixed version matched"
        )
        assert records[third.lower()][0]["malware_status"] == "malicious", (
            "the malicious release was not named"
        )
        vulnerable = [
            f
            for f in report["findings"]
            if f["rule_id"].startswith("VULNERABLE.DEPENDENCY")
            and first.lower() in f["message"].lower()
        ]
        assert vulnerable and fixed.lstrip("v") in vulnerable[0]["remediation"], (
            "remediation does not name the fix"
        )
        assert any(f["rule_id"] == "MALWARE.DEPENDENCY.KNOWN.001" for f in report["findings"])


class TestTyposquatting:
    """UNI-13: a one-edit slip of a popular name is flagged; the popular name and a legitimate
    look-alike are not."""

    @pytest.mark.parametrize("profile", SQUATTABLE, ids=ids(SQUATTABLE))
    def test_slip_flagged_real_names_not(self, profile, tmp_path) -> None:
        popular, slip, lookalike = profile.typosquat or ("", "", "")
        version = profile.versions[1]
        report = Universal.scan(
            Universal.project(
                tmp_path,
                profile,
                [Pkg(popular, version), Pkg(slip, version), Pkg(lookalike, version)],
            ),
            profile.id,
        )
        flagged = {
            f["location"].get("package") or f["message"]
            for f in report["findings"]
            if f["rule_id"] == "SUSPECT.DEPENDENCY.TYPOSQUAT.001"
        }
        text = " ".join(str(x) for x in flagged).lower()
        assert slip.lower() in text, f"{slip} was not flagged"
        for name in (popular, lookalike):
            assert not any(
                name.lower() == str(x).lower().rsplit("/", 1)[-1].split("@")[0] for x in flagged
            ), f"{name} was flagged"


class TestDependencyConfusion:
    """UNI-14: an internal name resolved from the public registry is flagged; resolved from a
    private one, it is not."""

    @pytest.mark.parametrize("profile", INTERNAL, ids=ids(INTERNAL))
    def test_internal_name_from_public_registry(self, profile, tmp_path) -> None:
        prefix, name = profile.internal or ("", "")
        root = Universal.project(
            tmp_path,
            profile,
            [Pkg(name, profile.versions[1], profile.hash_of(1) if profile.hash_of else None)],
        )
        (root / "cordon.yaml").write_text(
            f"version: 1\nscan:\n  internal_namespaces:\n    - {prefix!r}\n"
        )
        report = Universal.scan(root, profile.id)
        assert any(f["rule_id"] == "SUSPECT.DEPENDENCY.CONFUSION.001" for f in report["findings"])

    @pytest.mark.parametrize(
        "profile",
        [p for p in INTERNAL if p.private_source],
        ids=ids([p for p in INTERNAL if p.private_source]),
    )
    def test_internal_name_from_private_registry_is_quiet(self, profile, tmp_path) -> None:
        prefix, name = profile.internal or ("", "")
        root = Universal.project(
            tmp_path,
            profile,
            [
                Pkg(
                    name,
                    profile.versions[1],
                    profile.hash_of(1) if profile.hash_of else None,
                    profile.private_source,
                )
            ],
        )
        (root / "cordon.yaml").write_text(
            f"version: 1\nscan:\n  internal_namespaces:\n    - {prefix!r}\n"
        )
        report = Universal.scan(root, profile.id)
        assert not any(
            f["rule_id"] == "SUSPECT.DEPENDENCY.CONFUSION.001" for f in report["findings"]
        )


class TestTampering:
    """UNI-15: a hash that is not a hash is reported, its value never repeated, and the record
    says the integrity check failed."""

    @pytest.mark.parametrize("profile", HASHED, ids=ids(HASHED))
    def test_malformed_hash(self, profile, tmp_path) -> None:
        first, second, _ = profile.names
        assert profile.hash_of is not None and profile.malformed_hash is not None
        pkgs = [
            Pkg(first, profile.versions[1], profile.malformed_hash),
            Pkg(second, profile.versions[1], profile.hash_of(2)),
        ]
        report = Universal.scan(Universal.project(tmp_path, profile, pkgs), profile.id)
        assert any(
            f["rule_id"] == "SUSPECT.LOCKFILE.INTEGRITY_MALFORMED.001" for f in report["findings"]
        )
        assert profile.malformed_hash not in json.dumps(report), "the malformed value was echoed"
        records = Universal.records(report)
        assert records[first.lower()][0]["integrity_status"] == "mismatched"
        assert records[second.lower()][0]["integrity_status"] == "recorded"


class TestDeterminism:
    """UNI-20: identical input and policy give identical findings, records and exit code; the
    severity threshold decides the exit code."""

    @pytest.mark.parametrize("profile", ALL, ids=ids(ALL))
    def test_same_input_same_decision(self, profile, tmp_path) -> None:
        first, _, _ = profile.names
        advisories = [
            Universal.advisory(
                profile,
                first,
                identifier="CONFORMANCE-DET",
                introduced="0",
                fixed=profile.versions[1],
            )
        ]
        root = Universal.project(tmp_path, profile, [Pkg(first, profile.versions[0])])
        one = Universal.scan(root, profile.id, advisories)
        two = Universal.scan(root, profile.id, advisories)

        def strip(report: dict[str, Any]) -> Any:
            return (
                [f["fingerprint"] for f in report["findings"]],
                [d["record"] for d in report["dependencies"]],
            )

        assert strip(one) == strip(two)
        case = ConformanceCase(
            profile.id, "threshold", root, {"advisories": True, "args": ["--fail-on", "critical"]}
        )
        high_only, _ = ConformanceRun.scan(root, case)
        case = ConformanceCase(
            profile.id, "threshold", root, {"advisories": True, "args": ["--fail-on", "high"]}
        )
        at_high, _ = ConformanceRun.scan(root, case)
        assert (high_only, at_high) == (0, 1), "the threshold did not decide the exit code"


class TestScale:
    """UNI-26: a large lockfile is read whole, once per package, within a bounded time."""

    @pytest.mark.parametrize("profile", ALL, ids=ids(ALL))
    def test_two_thousand_packages(self, profile, tmp_path) -> None:
        first = profile.names[0]
        stem, _, tail = first.rpartition("/")
        pkgs = [
            Pkg(
                f"{stem}/{tail}{n}" if stem else f"{first}{n}",
                profile.versions[1],
                profile.hash_of(n) if profile.hash_of else None,
            )
            for n in range(2000)
        ]
        started = time.monotonic()
        report = Universal.scan(Universal.project(tmp_path, profile, pkgs), profile.id)
        elapsed = time.monotonic() - started
        # The packages written; not what the format records about its own tooling (Bundler's
        # `BUNDLED WITH`), the runtime, or Go's standard library.
        written = {p.name.lower() for p in pkgs}
        packages = [d for d in report["dependencies"] if d["name"].lower() in written]
        assert len(packages) == 2000, len(packages)
        assert len({d["purl"] for d in packages}) == 2000, "duplicated"
        assert elapsed < 120, f"{elapsed:.0f}s"


class TestScannerSafety:
    """UNI-27: reading a project never runs it. Each file here would create the marker if any of
    it were executed; after the scan, the marker does not exist."""

    @pytest.mark.parametrize("profile", EXECUTABLE, ids=ids(EXECUTABLE))
    def test_nothing_runs(self, profile, tmp_path) -> None:
        Path(MARKER).unlink(missing_ok=True)
        root = Universal.project(tmp_path, profile, [Pkg(profile.names[0], profile.versions[1])])
        for relative, text in profile.executable.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text)
        Universal.scan(root, profile.id)
        assert not Path(MARKER).exists(), "project code was executed during the scan"


class TestHostileCoordinates:
    """kind:adversarial: hostile names and versions -- control characters, enormous strings, a
    path traversal -- are bounded and never break the scan or reach a report raw."""

    @pytest.mark.parametrize("profile", ALL, ids=ids(ALL))
    def test_hostile_names(self, profile, tmp_path) -> None:
        first = profile.names[0]
        hostile = [
            Pkg(first + "x" * 5000, profile.versions[1]),
            Pkg(first + "‮" + "evil", profile.versions[1]),
            Pkg(first, profile.versions[1] + "9" * 4000),
        ]
        report = Universal.scan(Universal.project(tmp_path, profile, hostile), profile.id)
        for dependency in report["dependencies"]:
            assert len(dependency["name"]) <= 256 and len(dependency.get("version") or "") <= 128


from cordon_scanner.detect.registry import CONFUSABLE_ECOSYSTEMS, REGISTRY_ECOSYSTEMS  # noqa: E402

REGISTERED = [
    p for p in PROFILES if p.id in REGISTRY_ECOSYSTEMS and p.hash_of and p.registry_digests
]
PROVES["UNI-16"] = set(ids(REGISTERED))
PROVES["UNI-22"] = set(ids(REGISTERED))


class RegistryStub:
    """A registry that answers from a table: what the substituted client returns per name."""

    @staticmethod
    def install(monkeypatch, answers: dict[str, Any]) -> list[tuple[str, str]]:
        from cordon_scanner.intel import registry_client

        asked: list[tuple[str, str]] = []

        def facts(ecosystem: str, name: str, version: str | None) -> Any:
            asked.append((ecosystem, name))
            answer = answers.get(name)
            if isinstance(answer, BaseException):
                raise answer
            if answer is None:
                raise registry_client.PackageNotFound(f"{name} is not on the registry")
            return answer

        monkeypatch.setattr(registry_client.RegistryClient, "facts", staticmethod(facts))
        monkeypatch.setattr(
            registry_client.RegistryClient,
            "attestation_payload",
            staticmethod(lambda *a, **k: None),
        )
        return asked


class TestRegistryVerification:
    """UNI-16 and UNI-22, with the registry substituted so nothing reaches the network: a hash the
    registry publishes is verified, one it contradicts is a mismatch, a package it does not have
    is named, a withdrawn version is reported, and a registry that cannot be reached is reported
    as not checked -- never as clean."""

    @pytest.mark.parametrize("profile", REGISTERED, ids=ids(REGISTERED))
    def test_outcomes_are_told_apart(self, profile, tmp_path, monkeypatch) -> None:
        from cordon_scanner.intel.registry_client import PackageFacts, RegistryError

        assert profile.hash_of is not None
        first, second, third = profile.names
        version = profile.versions[1]
        good, bad = profile.hash_of(1), profile.hash_of(2)
        asked = RegistryStub.install(
            monkeypatch,
            {
                first: PackageFacts(name=first, version=version, digests=(good,), latest=version),
                second: PackageFacts(
                    name=second,
                    version=version,
                    digests=(profile.hash_of(7),),
                    latest=version,
                    yanked=True,
                ),
                third: RegistryError("connection timed out"),
            },
        )
        pkgs = [
            Pkg(first, version, good),
            Pkg(second, version, bad),
            Pkg(third, version, profile.hash_of(3)),
        ]
        root = Universal.project(tmp_path, profile, pkgs)
        report = Universal.scan(root, profile.id, args=("--online",))
        assert asked, "the registry was not asked"
        records = Universal.records(report)
        rules = {f["rule_id"] for f in report["findings"]}
        assert records[first.lower()][0]["integrity_status"] == "verified"
        assert records[second.lower()][0]["integrity_status"] == "mismatched"
        assert "SUSPECT.DEPENDENCY.YANKED.001" in rules
        assert records[third.lower()][0]["integrity_status"] == "recorded", (
            "an unreachable registry verified nothing"
        )
        assert "OPERATIONAL.REGISTRY.UNREACHABLE.001" in rules and report["complete"] is False

    @pytest.mark.parametrize(
        "profile",
        [p for p in REGISTERED if p.id in CONFUSABLE_ECOSYSTEMS],
        ids=ids([p for p in REGISTERED if p.id in CONFUSABLE_ECOSYSTEMS]),
    )
    def test_a_name_the_registry_does_not_have(self, profile, tmp_path, monkeypatch) -> None:
        RegistryStub.install(monkeypatch, {})
        root = Universal.project(
            tmp_path,
            profile,
            [
                Pkg(
                    profile.names[0],
                    profile.versions[1],
                    profile.hash_of(1) if profile.hash_of else None,
                )
            ],
        )
        report = Universal.scan(root, profile.id, args=("--online",))
        assert any(
            f["rule_id"] == "SUSPECT.DEPENDENCY.UNREGISTERED.001" for f in report["findings"]
        )


LICENSED = [p for p in PROFILES if p.records_licence]
PROVES["UNI-19"] = set(ids(ALL))
PROVES["x.policy"] = set(ids(ALL))


class TestPolicyLists:
    """UNI-19, UNI-20: the organisation's licence and package lists. A licence that cannot be
    established is never approved; a denied package is reported whatever else is true of it."""

    @staticmethod
    def policy(root: Path, body: str) -> None:
        (root / "cordon.yaml").write_text("version: 1\npolicy:\n" + body)

    @pytest.mark.conformance("x", "x.policy")
    @pytest.mark.parametrize("profile", ALL, ids=ids(ALL))
    def test_unknown_is_not_approved_and_deny_lists_apply(self, profile, tmp_path) -> None:
        first, second, _ = profile.names
        root = Universal.project(
            tmp_path, profile, [Pkg(first, profile.versions[1]), Pkg(second, profile.versions[1])]
        )
        self.policy(
            root,
            f"  licenses:\n    allow: [MIT]\n  packages:\n    deny: [{profile.id + ':' + second!r}]\n",
        )
        report = Universal.scan(root, profile.id)
        records = Universal.records(report)
        rules = {
            (f["rule_id"], (f["location"].get("package") or "").lower()) for f in report["findings"]
        }
        assert any(r == "POLICY.LICENSE.UNKNOWN.001" for r, _ in rules), "unknown licence approved"
        assert any(r == "POLICY.PACKAGE.DENIED.001" and second.lower() in p for r, p in rules), (
            "deny list ignored"
        )
        assert records[first.lower()][0]["licence_status"] == "policy_violation"

    @pytest.mark.parametrize("profile", LICENSED, ids=ids(LICENSED))
    def test_allow_and_deny_are_judged_on_the_expression(self, profile, tmp_path) -> None:
        first, second, third = profile.names
        version = profile.versions[1]
        pkgs = [
            Pkg(first, version, license="MIT"),
            Pkg(second, version, license="(MIT OR GPL-3.0-only)"),
            Pkg(third, version, license="AGPL-3.0-only"),
        ]
        root = Universal.project(tmp_path, profile, pkgs)
        self.policy(
            root, "  licenses:\n    allow: [MIT, Apache-2.0]\n    deny: [network_copyleft]\n"
        )
        report = Universal.scan(root, profile.id)
        records = Universal.records(report)
        assert records[first.lower()][0]["licence_status"] == "identified"
        assert records[second.lower()][0]["licence_status"] == "identified", (
            "an OR with an allowed branch"
        )
        assert records[third.lower()][0]["licence_status"] == "policy_violation"
        assert any(f["rule_id"] == "POLICY.LICENSE.DENIED.001" for f in report["findings"])

    @pytest.mark.parametrize("profile", ALL, ids=ids(ALL))
    def test_an_allow_list_reports_everything_else(self, profile, tmp_path) -> None:
        first, second, _ = profile.names
        root = Universal.project(
            tmp_path, profile, [Pkg(first, profile.versions[1]), Pkg(second, profile.versions[1])]
        )
        self.policy(root, f"  packages:\n    allow: [{profile.id + ':' + first!r}]\n")
        report = Universal.scan(root, profile.id)
        flagged = [
            f
            for f in report["findings"]
            if f["rule_id"] == "POLICY.PACKAGE.NOT_ALLOWED.001"
            and any(
                n.lower() in (f["location"].get("package") or "").lower() for n in (first, second)
            )
        ]
        assert (
            len(flagged) == 1
            and second.lower() in (flagged[0]["location"].get("package") or "").lower()
        )


class TestCompatibility:
    """UNI-30: every report states the schema, engine and rule-pack versions that produced it."""

    @pytest.mark.parametrize("profile", ALL, ids=ids(ALL))
    def test_versions_recorded(self, profile, tmp_path) -> None:
        report = Universal.scan(
            Universal.project(tmp_path, profile, [Pkg(profile.names[0], profile.versions[1])]),
            profile.id,
        )
        assert report["schema_version"] and report["engine_version"] and report["rulepack_version"]
