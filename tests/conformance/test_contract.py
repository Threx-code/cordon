"""Each ecosystem's coverage of its support contract, measured, and held at the required level.

A clause is met when something in this suite proves it -- a conformance case that lists it, a test
marked `@pytest.mark.conformance(<ecosystem>, <clause>, ...)`, or one of the checks every case goes
through (`test_cases.py`) -- or when the contract says it does not apply and why. Coverage is
met clauses over all clauses, per ecosystem; below `REQUIRED_COVERAGE` the suite fails and names
what is missing. Proofs are read statically, so this test does not depend on test order; the
proving tests themselves run in the same suite, so a proof that stops passing fails the suite too.
"""

from __future__ import annotations

import ast
from pathlib import Path

from conformancekit import ConformanceCase
from cordon_scanner.ecosystems.contract import (
    CONTRACTS,
    CROSS_CUTTING,
    REQUIRED_COVERAGE,
    UNIVERSAL,
)

TESTS = Path(__file__).resolve().parents[1]
#: Proven for an ecosystem by every one of its valid cases passing through `test_cases.py`.
EVERY_CASE: tuple[str, ...] = ("UNI-03", "UNI-21", "UNI-24", "UNI-25", "UNI-29")
KINDS = ("valid", "invalid", "edge", "adversarial", "regression", "real-world")


class Proofs:
    @staticmethod
    def same_kind(ecosystem: str, representative: str, path: str) -> bool:
        """Whether `path` is a file of the kind a contract's representative name stands for:
        `app.csproj` is any project file the ecosystem's `**/*.csproj` glob matches, and the
        real file is `src/App/App.csproj`."""
        from cordon_scanner.core.walker import PathGlob
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        implementation = EcosystemRegistry.get(ecosystem)
        if implementation is None:
            return False
        for glob in (*implementation.manifest_globs, *implementation.lockfile_globs):
            if (
                "*" in glob.rpartition("/")[2]
                and PathGlob.matches(representative, glob)
                and PathGlob.matches(path, glob)
            ):
                return True
        return False

    @staticmethod
    def markers() -> dict[str, set[str]]:
        """`@pytest.mark.conformance("npm", "UNI-16", ...)` anywhere under tests/."""
        found: dict[str, set[str]] = {}
        for path in TESTS.rglob("test_*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not (isinstance(func, ast.Attribute) and func.attr == "conformance"):
                    continue
                values = [
                    a.value
                    for a in node.args
                    if isinstance(a, ast.Constant) and isinstance(a.value, str)
                ]
                if len(values) >= 2:
                    found.setdefault(values[0], set()).update(values[1:])
        return found

    @staticmethod
    def collect() -> dict[str, set[str]]:
        proofs: dict[str, set[str]] = {}
        for case in ConformanceCase.all():
            proven = proofs.setdefault(case.ecosystem, set())
            for clause in case.covers:
                proven.add(f"{case.ecosystem}.{clause}" if clause.startswith("file:") else clause)
            kinds = set(case.expect.get("kinds") or ())
            if kinds & {"valid", "real-world"}:
                proven.update(EVERY_CASE)
            proven.update(f"kind:{k}" for k in kinds)
            if "invalid" not in kinds and kinds & {"valid", "real-world"}:
                proven.add("kind:invalid")  # every valid case is also run truncated and corrupted
        everywhere = Proofs.markers().pop("*", set())
        for ecosystem, clauses in Proofs.markers().items():
            proofs.setdefault(ecosystem, set()).update(clauses)
        # The universal tests, each run for the ecosystems listed against its clause.
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "conformance_universal", Path(__file__).parent / "test_universal.py"
        )
        if spec is not None and spec.loader is not None:
            universal = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(universal)
            for clause, ecosystems in universal.PROVES.items():
                for ecosystem in ecosystems:
                    proofs.setdefault(ecosystem, set()).add(clause)
        for contract in CONTRACTS:
            proofs.setdefault(contract.id, set()).update(everywhere)
        for contract in CONTRACTS:
            proven = proofs[contract.id]
            if all(f"kind:{k}" in proven for k in KINDS):
                proven.add("UNI-28")
        return proofs


class Coverage:
    @staticmethod
    def of(contract_id: str) -> tuple[float, list[str]]:
        contract = next(c for c in CONTRACTS if c.id == contract_id)
        proven = Proofs.collect().get(contract_id, set())
        missing = []
        clauses = contract.clause_ids()
        for clause in clauses:
            if clause in proven or clause in contract.not_applicable:
                continue
            if clause.startswith(f"{contract.id}.file:"):
                pattern = clause.split(":", 1)[1]
                if any(f.pattern == pattern and f.not_applicable for f in contract.files):
                    continue
            missing.append(clause)
        return (len(clauses) - len(missing)) / len(clauses), missing

    @staticmethod
    def table() -> list[tuple[str, float, list[str]]]:
        return [(c.id, *Coverage.of(c.id)) for c in CONTRACTS]


class TestTheContract:
    def test_every_ecosystem_meets_the_required_coverage(self) -> None:
        short = [
            f"{eco}: {rate:.1%} -- missing {', '.join(missing)}"
            for eco, rate, missing in Coverage.table()
            if rate < REQUIRED_COVERAGE
        ]
        assert not short, "\n".join(short)

    def test_not_applicable_always_says_why(self) -> None:
        for contract in CONTRACTS:
            for clause, reason in contract.not_applicable.items():
                assert len(reason) > 20, f"{contract.id} {clause}: no reason"
                assert clause in UNIVERSAL or clause in contract.specific, (
                    f"{contract.id}: {clause} is no clause"
                )

    def test_proofs_name_real_clauses(self) -> None:
        """A typo in `covers:` would prove nothing and count for nothing; refuse it instead."""
        for contract in CONTRACTS:
            valid = set(contract.clause_ids()) | {"UNI-28"}
            for case in ConformanceCase.all():
                if case.ecosystem != contract.id:
                    continue
                for clause in case.covers:
                    named = f"{contract.id}.{clause}" if clause.startswith("file:") else clause
                    assert named in valid or clause in CROSS_CUTTING, (
                        f"{case.id}: {clause!r} is not a clause"
                    )
                    if clause.startswith("file:"):
                        pattern = clause.split(":", 1)[1]
                        assert (case.path / pattern).is_file() or any(
                            p.name == Path(pattern).name
                            or Proofs.same_kind(
                                contract.id, pattern, p.relative_to(case.path).as_posix()
                            )
                            for p in case.project_files()
                        ), f"{case.id}: covers {clause} without the file"

    def test_the_cross_cutting_areas_are_proven(self) -> None:
        proven = set(Proofs.markers().get("x", set()))
        for case in ConformanceCase.all():
            proven.update(c for c in case.covers if c in CROSS_CUTTING)
        missing = sorted(set(CROSS_CUTTING) - proven)
        rate = 1 - len(missing) / len(CROSS_CUTTING)
        assert rate >= REQUIRED_COVERAGE, f"cross-cutting {rate:.1%}: missing {missing}"

    def test_every_case_belongs_to_a_contract(self) -> None:
        ids = {c.id for c in CONTRACTS}
        for case in ConformanceCase.all():
            assert case.ecosystem in ids, case.id
