"""Rules the suite declared and never named.

An audit of the 1,216 detector-declared rules found ten that no test and no
corpus sample mentioned anywhere. Each of them fires today -- that was checked
before this file was written, so none of these is a bug report. The point is
that nothing would have said so if they had stopped.

That matters more here than it would elsewhere. This project's whole argument
about rule packs is that a detection rule fails silently by nature: it stops
matching, the scan still succeeds, and the gate is green precisely because the
check is broken. `cordon-scanner rules test` enforces samples for pack rules and
`test_iac_policies.py` proves all 1,081 infrastructure policies against their
own; a rule declared in Python carries neither guarantee, and these ten had
nothing else either.

The five below are the ones a file on disk can demonstrate. The other five
report on a registry lookup or an attestation check rather than on file
content, and are covered in `test_coverage_notices.py` against a substituted
client -- no network, for the reason `test_registry_detector.py` gives.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config


def scan(root) -> set[str]:
    config = Config.default().with_overrides(use_cache=False)
    return {f.rule_id for f in Scanner(config).scan(root).findings}


CASES: dict[str, tuple[str, str, str]] = {
    "POLICY.K8S.NET_ADMIN.001": (
        "pod.yaml",
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n  containers:\n"
        '    - name: app\n      securityContext:\n        capabilities:\n          add: ["NET_ADMIN"]\n',
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n  containers:\n"
        '    - name: app\n      securityContext:\n        capabilities:\n          drop: ["ALL"]\n',
    ),
    "POLICY.K8S.SERVICE_ACCOUNT_TOKEN.001": (
        "sa.yaml",
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
        "  automountServiceAccountToken: true\n  containers:\n    - name: app\n",
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n"
        "  automountServiceAccountToken: false\n  containers:\n    - name: app\n",
    ),
    "SUSPECT.HELM.UNTRUSTED_REPOSITORY.001": (
        "Chart.yaml",
        "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n"
        "  - name: redis\n    version: 1.0.0\n    repository: http://charts.example.invalid\n",
        "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n"
        "  - name: redis\n    version: 1.0.0\n    repository: https://charts.example.invalid\n",
    ),
    "SUSPECT.VCS.HOOKS_PATH.001": (
        ".gitconfig",
        "[core]\n\thooksPath = .githooks\n",
        "[core]\n\tautocrlf = input\n",
    ),
    "POLICY.DEPENDENCY.SOURCE.001": (
        "requirements.txt",
        "requests @ git+https://github.com/psf/requests.git@main\n",
        "requests==2.32.3\n",
    ),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_the_rule_still_fires(tmp_path, rule_id: str) -> None:
    filename, reported, _ = CASES[rule_id]
    (tmp_path / filename).write_text(reported, encoding="utf-8")
    assert rule_id in scan(tmp_path), (
        f"{rule_id} did not fire on the shape it is about. A rule that stops "
        f"matching reports nothing and looks exactly like a clean scan."
    )


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_the_rule_leaves_the_careful_spelling_alone(tmp_path, rule_id: str) -> None:
    """The other half, and equally load-bearing: a rule that fires on the
    documented safe form is worse than no rule, because the projects it accuses
    are the ones that read the documentation."""
    filename, _, clean = CASES[rule_id]
    (tmp_path / filename).write_text(clean, encoding="utf-8")
    assert rule_id not in scan(tmp_path)
