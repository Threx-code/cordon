"""A fixture with a CI-variable gate around sensitive code yields a candidate; one without a gate is refused."""

from __future__ import annotations

import pytest
from bench.cdi.candidate import CandidateFactory, FactoryRejection
from bench.cdi.test_cdi_skeleton import Build

from cordon_scanner.analysis.gates.env_gates import EnvGates

GATED = 'import os, subprocess\nif os.environ.get("CI"):\n    subprocess.run(["true"])\n'


class TestEnvGateCandidate:
    def test_a_gated_fixture_yields_a_shadow_candidate(self) -> None:
        candidate = CandidateFactory.env_gate_candidate(
            [Build.miss()],
            EnvGates.of_python(GATED),
            train_dataset_digest="sha256:aa",
            manifests=Build.manifests("train"),
        )
        assert candidate["status"] == "proposed" and "CI->process" in candidate["evidence"]

    def test_a_source_without_a_gate_is_refused(self) -> None:
        with pytest.raises(FactoryRejection):
            CandidateFactory.env_gate_candidate(
                [Build.miss()],
                EnvGates.of_python("print(1)\n"),
                train_dataset_digest="sha256:aa",
                manifests=Build.manifests("train"),
            )
