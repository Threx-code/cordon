"""The training lane installs only from a hash-locked requirements file, and a requirement that is not pinned and hashed is refused."""

from __future__ import annotations

import re

from support import ROOT

LANE = ROOT / "bench" / "model"
HASHED = re.compile(r"^[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+-]+ \\$")


class Lock:
    @staticmethod
    def problems(text: str) -> list[str]:
        """The requirements of a lock file that are not pinned with `==` and followed by at least one sha256 hash."""
        found: list[str] = []
        blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", "\n" + text)
        for block in blocks:
            lines = [
                line
                for line in block.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if not lines:
                continue
            pinned = HASHED.match(lines[0].rstrip()) or re.match(
                r"^[A-Za-z0-9_.-]+==\S+$", lines[0].strip()
            )
            hashed = any("--hash=sha256:" in line for line in lines)
            if not pinned or not hashed:
                found.append(lines[0].strip())
        return found


class TestTheTrainingLaneInstallsOnlyFromTheLock:
    def test_every_pip_install_of_the_dockerfile_is_hash_locked_or_a_local_path_without_dependencies(
        self,
    ) -> None:
        text = (LANE / "Dockerfile").read_text(encoding="utf-8").replace("\\\n", " ")
        installs = [
            ln
            for ln in text.splitlines()
            if "pip install" in ln and not ln.lstrip().startswith("#")
        ]
        assert installs
        for line in installs:
            assert "--require-hashes -r" in line or ("--no-deps /pkg" in line), line

    def test_the_lock_file_pins_and_hashes_every_requirement(self) -> None:
        text = (LANE / "requirements.txt").read_text(encoding="utf-8")
        assert text.count("--hash=sha256:") >= 12
        assert Lock.problems(text) == []

    def test_every_library_the_lane_names_is_in_the_lock(self) -> None:
        wanted = {
            line.split("==")[0].lower()
            for line in (LANE / "requirements.in").read_text(encoding="utf-8").splitlines()
            if "==" in line
        }
        locked = {
            m.group(1).lower()
            for m in re.finditer(
                r"^([A-Za-z0-9_.-]+)==",
                (LANE / "requirements.txt").read_text(encoding="utf-8"),
                re.M,
            )
        }
        assert wanted <= locked

    def test_an_unpinned_or_unhashed_requirement_is_refused(self) -> None:
        assert Lock.problems("numpy>=2 \\\n    --hash=sha256:" + "a" * 64 + "\n") != []
        assert Lock.problems("numpy==2.1.3\n") != []
        assert Lock.problems("numpy==2.1.3 \\\n    --hash=sha256:" + "a" * 64 + "\n") == []
