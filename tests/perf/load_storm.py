"""A load reproduction: many `cordon scan` runs at once of the same archives, sharing a small temp area, and what exit codes they end in.

The same four archives must end the same way however many scans run beside them. Each archive holds one member too big to hold in memory, so a scan keeps it on disk in the temp area; with
more scans than the temp area can hold at once, the scans have to wait for each other rather than refuse a member. A run prints the exit codes it saw and, for each, the rule ids its report
carried. It is not a test (it needs a temp area of a known size): run it in a container with the temp area limited, for example

    docker run --rm --network none --tmpfs /tmp:size=256m,exec --tmpfs /data:size=800m,exec -e STORM_DIR=/data \\
        -v "$PWD/src:/s:ro" -v "$PWD/tests/perf:/code:ro" -e PYTHONPATH=/s <image> python /code/load_storm.py 12 2 70

through the repository's safe-run wrapper where it applies. Arguments: scans at once, rounds, size of the big member in MB. Every archive is invented (random bytes).
"""

from __future__ import annotations

import collections
import concurrent.futures
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


class Storm:
    ARCHIVES = 4
    RULE = re.compile(r"OPERATIONAL\.[A-Z_.]+|Cause class: \w+|reason: \w+")

    def __init__(self, scans: int, rounds: int, megabytes: int) -> None:
        self.scans, self.rounds = scans, rounds
        self.root = Path(tempfile.mkdtemp(prefix="storm", dir=os.environ.get("STORM_DIR")))
        self.archives = [self.make(i, megabytes) for i in range(self.ARCHIVES)]
        (self.root / "home").mkdir()
        self.env = dict(
            os.environ,
            CORDON_CACHE_DIR=str(self.root / "cache"),
            HOME=str(self.root / "home"),
            PYTHONDONTWRITEBYTECODE="1",
        )
        self.codes: collections.Counter[int] = collections.Counter()
        self.rules: collections.Counter[tuple[int, str]] = collections.Counter()

    def make(self, index: int, megabytes: int) -> Path:
        path = self.root / f"pkg{index}.tgz"
        manifest = json.dumps(
            {"name": f"p{index}", "version": "1.0.0", "main": "index.js"}
        ).encode()
        blob = (b"// padding %d\n" % index) * 8 + os.urandom(megabytes * 1024 * 1024)
        with tarfile.open(path, "w:gz") as archive:
            for name, data in (("package/package.json", manifest), ("package/data.bin", blob)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path

    def one(self, number: int) -> tuple[int, set[str]]:
        target = self.archives[number % len(self.archives)]
        command = [sys.executable, "-m", "cordon_scanner", "scan", "--format", "json", str(target)]
        done = subprocess.run(
            command, env=self.env, capture_output=True, text=True, timeout=900, check=False
        )
        return done.returncode, set(self.RULE.findall(done.stdout + done.stderr))

    def run(self) -> None:
        for _ in range(self.rounds):
            with concurrent.futures.ThreadPoolExecutor(self.scans) as pool:
                for code, rules in pool.map(self.one, range(self.scans)):
                    self.codes[code] += 1
                    for rule in rules:
                        self.rules[(code, rule)] += 1

    def report(self) -> str:
        lines = [f"exit codes: {dict(sorted(self.codes.items()))}"]
        lines += [
            f"exit {code} carries {rule}: {n}" for (code, rule), n in sorted(self.rules.items())
        ]
        return "\n".join(lines)


if __name__ == "__main__":
    storm = Storm(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    storm.run()
    print(storm.report())
