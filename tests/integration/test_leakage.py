"""What a finding is allowed to carry out of the repository.

A finding travels further than the file it came from: into CI logs, into
pull-request comments, into SARIF uploaded to a third party. The redactor
governs *evidence*, and it is tested hard in `tests/unit/test_redact.py`. This
file is about everything that is not evidence.

Package coordinates, parse-error text and detector-failure messages are all
copied into reports verbatim, by design -- a dependency finding whose package
name were masked would say nothing. That makes every parser a publication
channel, and a parser that reads one field too far publishes whatever was next
on the line.

The tests are therefore a canary hunt rather than an assertion about any one
parser. A distinctive string is planted in the position each parser is most
likely to over-read, the scan is run, and the string must appear in no output
in any format. Written this way because the leak that prompted it was in the
one parser nobody would have thought to check, and the next one will be too.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cordon_scanner.ecosystems.base import Coordinate, DeclaredDependency, LockEntry

CANARY = "ghp_" + "kR9mT2nQ8vL4xW7yZ3bC6dF1gH5jK0pS9rT2"
"""Fabricated, with the shape of a real token so nothing treats it as filler."""

HOSTILE_FILES: dict[str, str] = {
    # Each value places the canary where that parser could over-read it: after
    # a legal same-line option, after a syntax error, in a field a parser might
    # take wholesale.
    "requirements.txt": f"req==1.0 --hash=sha256:{CANARY}\nb==2.0 --global-option={CANARY}\n",
    "pyproject.toml": (
        '[project]\nname = "x"\ndependencies = ["req >=1.0 --config-settings=' + CANARY + '"]\n'
    ),
    "package.json": '{"name":"x" "tok":"' + CANARY + '"}',
    "setup.py": f'setup(name="{CANARY}"\n',
    "composer.json": '{"name":"x" ' + CANARY + "}",
    "go.mod": f"module x\nrequire ( {CANARY}\n",
    "Gemfile.lock": f"GEM\n  remote: {CANARY}\n  {{bad\n",
    "a.js": f'eval(atob("{CANARY}"))\n',
    "b.py": f'import os\nos.system("curl {CANARY}")\n',
    ".github/workflows/w.yml": f"on: push\njobs:\n  a: &{CANARY}\n",
}

FORMATS = ("json", "sarif", "markdown", "text")


@pytest.fixture(scope="module")
def hostile_repository(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("leakage")
    for name, body in HOSTILE_FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


class TestNoCanaryReachesAReport:
    @pytest.mark.parametrize("fmt", FORMATS)
    def test_the_canary_appears_in_no_output(self, hostile_repository: Path, fmt: str) -> None:
        """Regression: `req==1.0 --hash=<x>` is a legal requirements line, and
        reading the version as everything after `==` published the whole tail as
        `pkg:pypi/req@1.0 --hash=<x>` in all four formats at once."""
        out = hostile_repository / f"result.{fmt}"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(hostile_repository),
                "--format",
                fmt,
                "--output",
                str(out),
                "--no-cache",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        published = (
            (out.read_text(encoding="utf-8") if out.exists() else "")
            + result.stdout
            + result.stderr
        )
        assert published, "the scan produced nothing, so this proves nothing"
        assert CANARY not in published

    def test_the_scan_actually_ran(self, hostile_repository: Path) -> None:
        """A canary hunt over an empty report passes for the wrong reason."""
        out = hostile_repository / "check.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(hostile_repository),
                "--format",
                "json",
                "--output",
                str(out),
                "--no-cache",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["findings"], "no findings, so no report path was exercised"
        assert report["dependencies"], "no coordinates, so the leaking field was never populated"


class TestCoordinateBounds:
    """The model-level bound, tested directly.

    The parsers above are the current callers; the bound exists so that a parser
    written later cannot reintroduce the same leak without touching this file.
    """

    def test_a_version_stops_at_the_first_space(self) -> None:
        entry = LockEntry(name="req", version=f"1.0 --hash=sha256:{CANARY}")
        assert entry.version == "1.0"

    def test_a_name_stops_at_the_first_space(self) -> None:
        assert LockEntry(name=f"req {CANARY}", version="1.0").name == "req"

    def test_a_long_name_is_bounded(self) -> None:
        assert len(LockEntry(name="a" * 5000, version="1").name) == Coordinate.MAX_NAME

    def test_a_long_version_is_bounded(self) -> None:
        assert len(LockEntry(name="a", version="1" * 5000).version) == Coordinate.MAX_VERSION

    def test_a_spec_keeps_its_internal_spaces(self) -> None:
        """A version range is not a token. Cutting one at the first space would
        turn `>=1.0, <2.0` into `>=1.0,` and silently change what was
        required."""
        assert DeclaredDependency(name="req", spec=">=1.0, <2.0").spec == ">=1.0, <2.0"

    def test_a_spec_is_still_bounded(self) -> None:
        assert len(DeclaredDependency(name="r", spec="x" * 5000).spec) == Coordinate.MAX_SPEC

    def test_a_spec_is_flattened_to_one_line(self) -> None:
        """Newlines in a coordinate break every line-oriented report format and
        let a value forge what looks like a second finding."""
        assert "\n" not in DeclaredDependency(name="r", spec=f"1.0\n{CANARY}").spec

    def test_ordinary_coordinates_are_untouched(self) -> None:
        entry = LockEntry(name="@scope/pkg", version="1.2.3-rc.1+build.5")
        assert (entry.name, entry.version) == ("@scope/pkg", "1.2.3-rc.1+build.5")

    def test_an_empty_coordinate_stays_empty(self) -> None:
        assert LockEntry(name="", version="   ").version == ""


class TestRequirementsParsing:
    """The specific over-read, at the parser rather than the model."""

    def parse(self, body: str) -> tuple[tuple[str, str], ...]:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.ecosystems.pypi import PypiEcosystem

        graph = PypiEcosystem().parse_lockfile(
            FileContent.from_bytes("requirements.txt", body.encode())
        )
        return tuple((e.name, e.version) for e in graph.entries)

    def test_an_inline_hash_is_not_part_of_the_version(self) -> None:
        assert self.parse(f"req==1.0 --hash=sha256:{CANARY}\n") == (("req", "1.0"),)

    def test_a_continuation_hash_is_still_read(self) -> None:
        """The multi-line form is the common one and must keep working."""
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.ecosystems.pypi import PypiEcosystem

        graph = PypiEcosystem().parse_lockfile(
            FileContent.from_bytes("requirements.txt", b"req==1.0 \\\n    --hash=sha256:abc123\n")
        )
        assert graph.entries[0].version == "1.0"
        assert graph.entries[0].integrity == "sha256:abc123"

    def test_an_environment_marker_is_still_dropped(self) -> None:
        assert self.parse('req==1.0 ; python_version < "3.11"\n') == (("req", "1.0"),)

    def test_a_plain_pin_is_unchanged(self) -> None:
        assert self.parse("req==1.0\n") == (("req", "1.0"),)
