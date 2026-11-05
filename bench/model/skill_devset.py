#!/usr/bin/env python3
"""The skill model's development set, rebuilt with every row placed (see `mcp_devset.py`).

```
  source     malskill-ci | malskill-pi | malskill-mixed | malskill-wild | malskill-benign
             asb | asb-benign (MaliciousSkillBench) | corpus-skill (public SKILL.md files)
  dataset    malskillbench | maliciousskillbench | corpus
  group      what a split keeps on one side: MalSkillBench's base skill (its generated
             variants `<skill>__CI_B4`, `<skill>__PI_B10` are one skill attacked several ways),
             the benchmark id for MaliciousSkillBench, the repository for a public skill
  label      1 = written against the user, 0 = an ordinary skill
  half       work | holdout by a hash of (dataset, group)
```

    docker run --rm --network none -v cordon-bench-public:/p:ro -v cordon-bench-skills:/k:ro \\
      -v "$PWD:/s:ro" -v OUT:/o -e PYTHONPATH=/s/src:/s/bench/tools python:3.12-slim \\
      python /s/bench/model/skill_devset.py --public /p --skills /k/skills --out /o/skills.jsonl \\
      --held /o/held-sha256.txt

DataDog's ai-skills set is not read here: it is the test that no training ever saw. Nor are the
other held-out sets: a public skill in the evaluation half (`AgentConfigCorpus.half_of`), and any
text listed in `--held` (sha256 of the first 40,000 characters, one per line: the skills
inventory's held half). The shipped model was trained before this, on 47,040 of the evaluation
half's skills, so its finals score only the skills it never trained on (`finals-skills-*-unseen`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path

GENERATED = re.compile(r"__(?P<vector>CI|PI|MIXED)_(?P<behaviour>B\d+)$")
MAX_TEXT = 40_000


class SkillDevset:
    @staticmethod
    def half(dataset: str, group: str) -> str:
        digest = hashlib.sha256(f"{dataset}:{group}".encode()).digest()
        return "holdout" if digest[0] % 2 else "work"

    @classmethod
    def row(cls, source: str, dataset: str, group: str, label: int, text: str) -> dict:
        return {
            "source": source,
            "dataset": dataset,
            "group": group,
            "label": label,
            "channel": "skill",
            "half": cls.half(dataset, group),
            "text": text[:MAX_TEXT],
        }

    @classmethod
    def malskillbench(cls, root: Path) -> Iterator[dict]:
        for side, label in (("malware", 1), ("benign", 0)):
            for skill in sorted((root / "Dataset" / "Skills" / side).iterdir()):
                text_path = skill / "SKILL.md"
                if not text_path.is_file():
                    continue
                text = text_path.read_text(encoding="utf-8", errors="replace")
                generated = GENERATED.search(skill.name)
                base = skill.name[: generated.start()] if generated else skill.name
                if label:
                    source = (
                        f"malskill-{generated.group('vector').lower()}"
                        if generated
                        else "malskill-wild"
                    )
                else:
                    source = "malskill-benign"
                yield cls.row(source, "malskillbench", base, label, text)

    @classmethod
    def maliciousskillbench(cls, jsonl: Path) -> Iterator[dict]:
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            label = 1 if row["label"] == "1" else 0
            yield cls.row(
                "asb" if label else "asb-benign",
                "maliciousskillbench",
                row["id"],
                label,
                row["text"],
            )

    @classmethod
    def corpus(cls, root: Path) -> Iterator[dict]:
        from fetch_agent_configs import AgentConfigCorpus

        for folder in sorted(root.iterdir()):
            repository = "__".join(folder.name.split("__")[:2])
            if AgentConfigCorpus.half_of(repository.replace("__", "/", 1)) == "evaluate":
                continue
            path = folder / "SKILL.md"
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            yield cls.row("corpus-skill", "corpus", repository, 0, text)

    @classmethod
    def main(cls) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("--public", type=Path, required=True)
        parser.add_argument("--skills", type=Path, required=True)
        parser.add_argument("--out", type=Path, required=True)
        parser.add_argument("--held", type=Path, help="sha256 of held-out texts, one per line")
        args = parser.parse_args()
        held = set(args.held.read_text(encoding="utf-8").split()) if args.held else set()
        counts: dict[str, int] = {}
        with args.out.open("w", encoding="utf-8") as out:
            for rows in (
                cls.malskillbench(args.public / "malskillbench"),
                cls.maliciousskillbench(args.public / "maliciousskillbench.jsonl"),
                cls.corpus(args.skills),
            ):
                for row in rows:
                    if hashlib.sha256(row["text"].encode("utf-8", "replace")).hexdigest() in held:
                        continue
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
                    counts[row["source"]] = counts.get(row["source"], 0) + 1
        print(json.dumps(counts, indent=2, sort_keys=True))


if __name__ == "__main__":
    SkillDevset.main()
