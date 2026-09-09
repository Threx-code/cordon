"""What a release publishes besides the code.

A supply-chain scanner that ships unsigned, undescribed artefacts is arguing
against itself. Three things travel with a release and each answers a different
question a consumer is entitled to ask:

**SBOM** -- what is in it. "Zero third-party runtime dependencies" is a claim,
and a claim nobody can check is marketing.

**Signature** -- who published it. Keyless, so there is no signing key to
protect, rotate or leak.

**Provenance** -- how it was built. Not "was this signed by the project" but
"was this built by the process the project describes", which is the question a
compromised maintainer account does not survive.

These tests assert the release workflow still does all three, and that the SBOM
generator produces documents that parse and say true things. They cannot verify
a signature that has not been made yet; what they can stop is the steps being
removed or quietly reordered.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from support import requires_workflows

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
GENERATOR = ROOT / "scripts" / "generate_sbom.py"


class TestSbomGenerator:
    def generate(self, tmp_path: Path) -> tuple[dict, dict]:
        (tmp_path / "cordon_scanner-0.1.0-py3-none-any.whl").write_bytes(b"not really a wheel")
        (tmp_path / "cordon_scanner-0.1.0.tar.gz").write_bytes(b"not really an sdist")
        subprocess.run(
            [sys.executable, str(GENERATOR), "--dist", str(tmp_path), "--out", str(tmp_path)],
            check=True,
            capture_output=True,
        )
        return (
            json.loads((tmp_path / "sbom.cdx.json").read_text(encoding="utf-8")),
            json.loads((tmp_path / "sbom.spdx.json").read_text(encoding="utf-8")),
        )

    def test_both_formats_are_produced(self, tmp_path: Path) -> None:
        """Neither is a superset of the other, and an organisation standardised
        on one should not have to convert."""
        cdx, spdx = self.generate(tmp_path)
        assert cdx["bomFormat"] == "CycloneDX"
        assert spdx["spdxVersion"].startswith("SPDX-")

    def test_the_version_matches_the_package(self, tmp_path: Path) -> None:
        import cordon_scanner

        cdx, spdx = self.generate(tmp_path)
        assert cdx["metadata"]["component"]["version"] == cordon_scanner.__version__
        assert spdx["packages"][0]["versionInfo"] == cordon_scanner.__version__

    def test_it_records_the_digests_of_the_files(self, tmp_path: Path) -> None:
        """An SBOM describing a version but not the bytes lets a consumer verify
        the dependency list of something other than what they downloaded."""
        cdx, spdx = self.generate(tmp_path)
        assert len(cdx["metadata"]["component"]["hashes"]) == 2
        assert len(spdx["packages"][0]["checksums"]) == 2
        for entry in cdx["metadata"]["component"]["hashes"]:
            assert len(entry["content"]) == 64

    def test_the_dependency_list_is_empty_and_that_is_the_claim(self, tmp_path: Path) -> None:
        cdx, _ = self.generate(tmp_path)
        assert cdx["components"] == []
        assert cdx["dependencies"][0]["dependsOn"] == []

    def test_check_mode_fails_if_a_runtime_dependency_appears(self) -> None:
        """The claim is verified against packaging metadata rather than
        restated, so it cannot drift from the truth."""
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, result.stderr
        assert "empty" in result.stdout

    def test_it_needs_no_third_party_package(self) -> None:
        """A tool whose argument is that build dependencies are attack surface
        should not add one in order to publish the list of its dependencies."""
        source = GENERATOR.read_text(encoding="utf-8")
        for line in source.splitlines():
            if line.startswith(("import ", "from ")) and "cordon" not in line:
                module = line.split()[1].split(".")[0]
                assert module in set(sys.stdlib_module_names) | {"__future__"}, module


@requires_workflows
class TestReleaseWorkflow:
    def body(self) -> str:
        return RELEASE.read_text(encoding="utf-8")

    def test_it_generates_an_sbom(self) -> None:
        assert "generate_sbom.py" in self.body()

    def test_it_signs_the_artefacts(self) -> None:
        text = self.body()
        assert "sigstore" in text
        assert "sbom.cdx.json" in text, "the SBOM is signed too, or it proves nothing"

    def test_it_attests_provenance(self) -> None:
        assert "attest-build-provenance" in self.body()

    def test_it_publishes_with_attestations(self) -> None:
        assert "attestations: true" in self.body()

    def test_publishing_waits_for_the_attestation(self) -> None:
        """Publishing first would put an unattested artefact on the index for
        however long the attestation takes, which is the window that matters."""
        assert "needs: [build, attest]" in self.body()

    def test_the_build_is_reproducible(self) -> None:
        """A fixed timestamp is what lets a third party rebuild from the tag and
        compare digests with the SBOM."""
        assert "SOURCE_DATE_EPOCH" in self.body()

    @pytest.mark.parametrize(
        "step", ["pin_action_requirements.py", "--from-dist", "--from-pypi --check"]
    )
    def test_the_action_pin_is_still_generated(self, step: str) -> None:
        assert step in self.body()


@requires_workflows
class TestBuildToolchainIsPinned:
    """The build runs in the job that holds the publishing identity.

    `pipx run build` and `requires = ["setuptools>=77"]` resolved from PyPI at
    release time, unpinned and unhashed, so a compromised `build` or
    `setuptools` release would execute there. For a supply-chain scanner that is
    not one risk among several -- it is the attack the tool exists to describe,
    aimed at the tool.
    """

    PINS = ROOT / "requirements-build.txt"

    def test_the_pin_file_exists_and_carries_hashes(self) -> None:
        text = self.PINS.read_text(encoding="utf-8")
        entries = [line for line in text.splitlines() if "==" in line and not line.startswith("#")]
        assert entries, "no pinned build dependency"
        assert text.count("--hash=sha256:") >= len(entries)

    def test_every_pin_is_exact(self) -> None:
        """A range is not a pin. `>=` here would let the resolver pick whatever
        was newest at release time, which is the thing being prevented."""
        for line in self.PINS.read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or not line.strip() or line.strip().startswith("--hash"):
                continue
            assert "==" in line, line
            assert ">=" not in line and "~=" not in line, line

    def test_the_release_installs_it_with_require_hashes(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        assert "--require-hashes -r requirements-build.txt" in text

    def test_the_release_builds_without_isolation(self) -> None:
        """Build isolation would fetch its own copy of the toolchain from PyPI,
        which is exactly what the pin exists to prevent."""
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        assert "--no-isolation" in text
        # Comments are excluded: the workflow explains what it stopped doing,
        # and a check that cannot tell an instruction from an explanation of one
        # would fail on the explanation.
        commands = [
            line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")
        ]
        assert not any("pipx run build" in line for line in commands)

    def test_security_md_does_not_overclaim(self) -> None:
        """It said development dependencies were pinned. They are not, and
        saying so was worse than the gap: a reader who believes it does not
        check."""
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        assert "Development dependencies are not pinned" in text
        assert "build toolchain is pinned by hash" in text.lower()
