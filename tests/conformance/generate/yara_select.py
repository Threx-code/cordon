"""Chooses which of the fetched GuardDog rules ship in Cordon's built-in YARA pack.

Each `threat-*` rule from `generate/yara_pack.sh` is compiled alone and matched against benign
input -- the benign corpus, and every real-world project in the conformance cases -- honouring the
rule's own `path_include`. It ships only if it matched none of that, none of the 14,992 benign
PyPI packages `yara_evaluate.py` measured it on (MEASUREMENT.json), and at least one of the known
malicious packages: the pack is opt-in, and what it reports must be worth reading. The rest are written, unchanged, into one file
(`rules/yara/cordon-builtin.yar`) beside a manifest of what was kept, what was dropped and why.
Run inside Docker only:

    docker run --rm -v "$PWD:/pkg" -w /pkg python:3.12-slim sh -c \\
      "pip install -q yara-python==4.5.1 && python tests/conformance/generate/yara_select.py"
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

import yara  # type: ignore[import-not-found]

PACKAGE = Path("/pkg")
UPSTREAM = PACKAGE / "src/cordon_scanner/rules/yara/upstream"
PACK = PACKAGE / "src/cordon_scanner/rules/yara/cordon-builtin.yar"
MANIFEST = PACKAGE / "src/cordon_scanner/rules/yara/MANIFEST.json"
BENIGN = [
    PACKAGE / "corpus/benign",
    *sorted((PACKAGE / "tests/conformance/cases").glob("*/real-*")),
]
MAX_FILE = 4 << 20


class Selection:
    """The benign files, each rule's matches over them, and the pack written from the survivors."""

    @staticmethod
    def benign_files() -> list[Path]:
        files: list[Path] = []
        for root in BENIGN:
            files += [p for p in root.rglob("*") if p.is_file() and p.stat().st_size <= MAX_FILE]
        return files

    @staticmethod
    def applies(meta: dict, path: Path) -> bool:
        wanted = meta.get("path_include")
        if not isinstance(wanted, str) or not wanted.strip():
            return True
        return any(
            fnmatch.fnmatchcase(path.name.lower(), g.strip().lower())
            for g in wanted.split(",")
            if g.strip()
        )

    @staticmethod
    def benign_hits(source: Path, files: list[Path]) -> list[str]:
        rules = yara.compile(filepath=str(source), includes=False)
        hits: list[str] = []
        for path in files:
            for match in rules.match(data=path.read_bytes(), timeout=10):
                if Selection.applies(match.meta, path):
                    hits.append(path.relative_to(PACKAGE).as_posix())
        return hits

    @staticmethod
    def run() -> None:
        measurement = json.loads((PACK.parent / "MEASUREMENT.json").read_text(encoding="utf-8"))
        files = Selection.benign_files()
        kept: list[str] = []
        dropped: dict[str, str] = {}
        for source in sorted(UPSTREAM.glob("threat-*.yar")):
            try:
                hits = Selection.benign_hits(source, files)
            except yara.Error as exc:
                dropped[source.name] = (
                    f"does not compile with yara-python {yara.__version__}: {exc}"
                )
                continue
            names = re.findall(r"(?m)^rule\s+(\w+)", source.read_text(encoding="utf-8"))
            measured = [
                measurement["rules"].get(name, {"benign_hits": 0, "malicious_hits": 0})
                for name in names
            ]
            if hits:
                dropped[source.name] = f"matched {len(hits)} benign file(s), first {hits[0]}"
            elif any(m["benign_hits"] for m in measured):
                dropped[source.name] = (
                    f"matched {sum(m['benign_hits'] for m in measured)} of {measurement['benign_packages']} benign PyPI packages"
                )
            elif not any(m["malicious_hits"] for m in measured):
                dropped[source.name] = (
                    f"matched none of {measurement['malicious_packages']} known-malicious packages"
                )
            else:
                kept.append(source.name)
        commit = (UPSTREAM / "COMMIT").read_text(encoding="utf-8").strip()
        header = (
            "// Cordon's built-in YARA pack (`--yara builtin`). Rules by the GuardDog Team, Datadog,\n"
            f"// from github.com/DataDog/guarddog at {commit}, Apache License 2.0 (upstream/LICENSE),\n"
            "// unchanged. Chosen by tests/conformance/generate/yara_select.py: see MANIFEST.json.\n\n"
        )
        PACK.write_text(
            header + "\n".join((UPSTREAM / name).read_text(encoding="utf-8") for name in kept),
            encoding="utf-8",
        )
        yara.compile(filepath=str(PACK), includes=False)
        MANIFEST.write_text(
            json.dumps(
                {
                    "upstream": "https://github.com/DataDog/guarddog",
                    "commit": commit,
                    "licence": "Apache-2.0",
                    "benign_files": len(files),
                    "kept": kept,
                    "dropped": dropped,
                },
                indent=1,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"{len(files)} benign files; kept {len(kept)}, dropped {len(dropped)}")
        for name, why in dropped.items():
            print(" dropped", name, "--", why)


Selection.run()
