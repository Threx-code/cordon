"""A release that says where it came from, and one that does not.

The check is a conjunction of a positive and a negative, which is the shape
that goes wrong quietly: a publish step nobody recognised reads as a project
that does not publish, and an attestation step nobody recognised reads as one
that publishes without provenance. Both directions are tested here, because
only one of them produces a finding and the other produces silence -- and
silence from a missed publish step is indistinguishable from silence from a
project with nothing to publish.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.models import Category

RULE = "POLICY.RELEASE.NO_PROVENANCE.001"


def workflow(tmp_path, body: str, *, name: str = "release.yml"):
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(body, encoding="utf-8")
    return tmp_path


def ids_for(root) -> list[str]:
    return [f.rule_id for f in Scanner().scan(root).findings]


class TestAPublishStepWithoutProvenance:
    @pytest.mark.parametrize(
        "step",
        [
            "npm publish --access public",
            "pnpm publish",
            "yarn npm publish",
            "twine upload dist/*",
            "cargo publish",
            "gem push pkg/example.gem",
            "dotnet nuget push out/example.nupkg",
            "./gradlew publishToSonatype",
            "mvn --batch-mode deploy",
        ],
    )
    def test_it_is_reported(self, tmp_path, step: str) -> None:
        root = workflow(tmp_path, f"jobs:\n  release:\n    steps:\n      - run: {step}\n")
        assert RULE in ids_for(root)

    def test_the_official_pypi_action_counts_as_publishing(self, tmp_path) -> None:
        root = workflow(
            tmp_path,
            "jobs:\n  release:\n    steps:\n      - uses: pypa/gh-action-pypi-publish@v1\n",
        )
        assert RULE in ids_for(root)

    def test_it_is_policy_and_low(self, tmp_path) -> None:
        """Nothing here is evidence of an attack. Most projects publish without
        provenance, and a rule that shouted about it would be a rule people
        turn off."""
        root = workflow(tmp_path, "jobs:\n  release:\n    steps:\n      - run: npm publish\n")
        found = [f for f in Scanner().scan(root).findings if f.rule_id == RULE]
        assert [f.category for f in found] == [Category.POLICY]
        assert found[0].severity.name == "LOW"

    def test_it_points_at_the_publish_step(self, tmp_path) -> None:
        root = workflow(
            tmp_path,
            "jobs:\n  release:\n    steps:\n      - run: npm ci\n      - run: npm publish\n",
        )
        found = [f for f in Scanner().scan(root).findings if f.rule_id == RULE]
        assert [f.location.line for f in found] == [5]


class TestAPublishStepWithProvenance:
    @pytest.mark.parametrize(
        "attestation",
        [
            "      - run: npm publish --provenance",
            "      - uses: actions/attest-build-provenance@v1",
            "      - uses: slsa-framework/slsa-github-generator/.github/workflows/generic@v2",
            "      - uses: sigstore/gh-action-sigstore-python@v3",
            "      - run: cosign sign-blob dist/example.tgz",
            "      - run: gh attestation verify dist/example.tgz",
        ],
    )
    def test_it_is_not(self, tmp_path, attestation: str) -> None:
        body = (
            "permissions:\n  id-token: write\njobs:\n  release:\n    steps:\n"
            "      - run: npm publish\n" + attestation + "\n"
        )
        assert RULE not in ids_for(workflow(tmp_path, body))


class TestWhatIsNotARelease:
    def test_a_workflow_that_publishes_nothing_is_silent(self, tmp_path) -> None:
        root = workflow(
            tmp_path, "jobs:\n  test:\n    steps:\n      - run: npm test\n", name="ci.yml"
        )
        assert RULE not in ids_for(root)

    def test_a_job_merely_named_release_is_not_a_publish(self, tmp_path) -> None:
        """`release`, `deploy` and `publish` are job names in workflows that
        ship nothing. Keying on them would report the wrong files in both
        directions."""
        root = workflow(
            tmp_path,
            "jobs:\n  release:\n    steps:\n      - run: gh release create v1.0.0\n",
        )
        assert RULE not in ids_for(root)

    def test_a_makefile_that_publishes_is_not_reported(self, tmp_path) -> None:
        """A Makefile has no provenance story to look for, and reporting its
        absence would be reporting that a feature of GitHub Actions is missing
        from something that is not GitHub Actions."""
        (tmp_path / "Makefile").write_text("publish:\n\tnpm publish\n", encoding="utf-8")
        assert RULE not in ids_for(tmp_path)
