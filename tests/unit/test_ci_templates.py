"""The CI templates install the scanner they are released with, hash-verified, and never pipe a
download into a shell."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from cordon_scanner.version import __version__

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = sorted(
    p
    for p in (ROOT / "ci").rglob("*")
    if p.is_file() and p.suffix in (".yml", ".yaml", ".groovy", ".sh")
)


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: str(p.relative_to(ROOT)))
class TestEveryTemplate:
    def test_it_names_the_version_it_ships_with(self, template: Path) -> None:
        text = template.read_text(encoding="utf-8")
        versions = set(re.findall(r"(?<![\d.])(\d+\.\d+\.\d+)(?![\d.])", text)) - {"3.12"}
        assert versions <= {__version__}, (
            f"{template.name} names {sorted(versions)}, the release is {__version__}"
        )

    def test_it_never_pipes_a_download_into_a_shell(self, template: Path) -> None:
        text = template.read_text(encoding="utf-8")
        assert not re.search(r"(?:curl|wget)[^\n|]*\|\s*(?:ba|z)?sh\b", text)

    def test_any_pip_install_requires_hashes(self, template: Path) -> None:
        for line in template.read_text(encoding="utf-8").splitlines():
            if re.search(r"pip install[^\n]*\bcordon-scanner(?:==|[\s\"']|$)", line):
                pytest.fail(f"{template.name} installs by name, unverified: {line.strip()}")
        text = template.read_text(encoding="utf-8")
        if "pip install" in text:
            assert "--require-hashes" in text and "--no-deps" in text


def test_every_platform_the_backlog_names_has_a_template() -> None:
    names = {str(p.relative_to(ROOT / "ci")) for p in TEMPLATES}
    for expected in (
        "gitlab/cordon.gitlab-ci.yml",
        "bitbucket/pipe.sh",
        "azure/cordon-task.yml",
        "circleci/orb.yml",
        "jenkins/vars/cordonScan.groovy",
    ):
        assert expected in names


def test_the_air_gapped_routes_never_reach_for_the_network() -> None:
    """R4: a runner with no internet must not hang on the intel feed or a download."""
    generic = (ROOT / "ci" / "generic" / "scan.sh").read_text(encoding="utf-8")
    assert "--network none" in generic and "CORDON_OFFLINE=1" in generic
    gitlab = (ROOT / "ci" / "gitlab" / "cordon.gitlab-ci.yml").read_text(encoding="utf-8")
    airgapped = gitlab.split(".cordon-airgapped:", 1)[1]
    assert 'CORDON_OFFLINE: "1"' in airgapped
    assert "curl" not in airgapped, "it must not inherit the download of the hash pin"


def test_each_report_names_its_own_destination(tmp_path, capsys) -> None:
    """Every multi-format CI template writes several reports; each message must name the file it
    wrote, not the last destination on the command line."""
    from cordon_scanner.cli.main import main

    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    sarif, junit = tmp_path / "out.sarif", tmp_path / "out.xml"
    main(["scan", str(tmp_path), "--format", f"sarif:{sarif}", "--format", f"junit:{junit}"])
    err = capsys.readouterr().err
    assert f"wrote sarif report to {sarif}" in err
    assert f"wrote junit report to {junit}" in err
