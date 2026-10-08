"""`scripts/bump_cordon_pins.py`: every pin of Cordon moved to one release (advanced gap E4)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "bump_cordon_pins", ROOT / "scripts" / "bump_cordon_pins.py"
)
assert _spec is not None and _spec.loader is not None
bump_module = importlib.util.module_from_spec(_spec)
sys.modules["bump_cordon_pins"] = bump_module
_spec.loader.exec_module(bump_module)

OLD, NEW = "a" * 40, "b" * 40
RELEASE = bump_module.Release("0.5.3", NEW, ("c" * 64, "d" * 64), "sha256:" + "e" * 64)


class TestEachPinForm:
    def test_the_action_by_commit(self) -> None:
        text = f"      - uses: Threx-code/cordon/action@{OLD} # v0.5.2\n      - uses: actions/checkout@{OLD}\n"
        updated, bump = bump_module.CordonPins.bump(".github/workflows/ci.yml", text, RELEASE)
        assert f"Threx-code/cordon/action@{NEW}  # v0.5.3" in updated
        assert f"actions/checkout@{OLD}" in updated  # not Cordon: untouched
        assert len(bump.changes) == 1

    def test_pip_with_hashes(self) -> None:
        text = "cordon-scanner==0.5.2 \\\n    --hash=sha256:" + "0" * 64 + "\nrequests==2.32.3\n"
        updated, _ = bump_module.CordonPins.bump("requirements.txt", text, RELEASE)
        assert updated == (
            "cordon-scanner==0.5.3 \\\n    --hash=sha256:"
            + "c" * 64
            + " \\\n    --hash=sha256:"
            + "d" * 64
            + "\nrequests==2.32.3\n"
        )

    def test_pre_commit_rev_under_the_cordon_repo_only(self) -> None:
        text = (
            "repos:\n  - repo: https://github.com/Threx-code/cordon\n    rev: v0.5.2\n    hooks:\n      - id: cordon\n"
            "  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: v4.6.0\n"
        )
        updated, _ = bump_module.CordonPins.bump(".pre-commit-config.yaml", text, RELEASE)
        assert "rev: v0.5.3\n    hooks" in updated and "rev: v4.6.0" in updated

    def test_the_runner_image_by_digest(self) -> None:
        text = "image: ghcr.io/threx-code/cordon-runner:0.5.2@sha256:" + "1" * 64 + "\n"
        updated, _ = bump_module.CordonPins.bump(".gitlab-ci.yml", text, RELEASE)
        assert updated.endswith("@sha256:" + "e" * 64 + "\n")


class TestARepository:
    def test_current_is_left_alone_and_a_readme_is_never_touched(self, tmp_path) -> None:
        (tmp_path / ".github/workflows").mkdir(parents=True)
        (tmp_path / ".github/workflows/ci.yml").write_text(
            f"uses: Threx-code/cordon/action@{NEW}  # v0.5.3\n", encoding="utf-8"
        )
        (tmp_path / "README.md").write_text(
            f"uses: Threx-code/cordon/action@{OLD}\n", encoding="utf-8"
        )
        assert bump_module.CordonPins.run(tmp_path, RELEASE) == []
        assert OLD in (tmp_path / "README.md").read_text(encoding="utf-8")

    def test_the_workflow_template_passes_values_through_the_environment(self) -> None:
        workflow = (ROOT / "ci" / "github" / "cordon-pin-bump.yml").read_text(encoding="utf-8")
        for block in workflow.split("run: |")[1:]:
            script = block.split("\n      - name:", 1)[0]
            assert "${{" not in script, "a value interpolated into a script is an injection"
