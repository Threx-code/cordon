#!/usr/bin/env python3
"""The labelled agent-text dataset for Cordon's judge model: passages, never run.

    attack     ATR's true positives (pinned commit, MIT), each with its rule's category
    benign     ATR's true negatives -- written to sit close to the attacks -- and its benign corpus,
               and passages of real published skills (the calibrate half by repository)
    skills     whole skills for skill-level evaluation: DataDog's malicious skills (dev and held
               halves by name) and real skills of the evaluate half

The ATR split is by rule (sha256 of the rule id), so no paraphrase of a held-out rule's attack is
trained on. Real skills are split by repository, as everywhere else in the benchmark.

    docker run --rm --network none -v cordon-bench-atr:/atr:ro -v cordon-bench-skills:/corpus:ro \\
      -v cordon-bench-data:/data:ro -v "$PWD/bench:/bench:ro" -v cordon-model-work:/work \\
      cordon-model:next python /bench/model/text_dataset.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suites"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch_agent_configs import AgentConfigCorpus
from run import Harness

MAX_PASSAGE = 1200


class TextDataset:
    @staticmethod
    def half(key: str) -> str:
        return "train" if hashlib.sha256(key.encode()).digest()[0] % 2 == 0 else "held"

    @staticmethod
    def passages(text: str) -> list[str]:
        """Paragraphs, each cut to a bounded passage: what the model reads and quotes from."""
        out = []
        for block in re.split(r"\n\s*\n", text):
            block = block.strip()
            if len(block) < 12:
                continue
            for start in range(0, len(block), MAX_PASSAGE):
                out.append(block[start : start + MAX_PASSAGE])
        return out

    @staticmethod
    def atr(root: Path) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for path in sorted(root.glob("rules/**/*.yaml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            category = path.relative_to(root / "rules").parts[0]
            split = TextDataset.half(str(document.get("id") or path.name))
            cases = document.get("test_cases") or {}
            for label, key in ((1, "true_positives"), (0, "true_negatives")):
                for case in cases.get(key) or ():
                    text = case.get("input") if isinstance(case, dict) else None
                    if isinstance(text, str) and text.strip():
                        rows.append(
                            {
                                "text": text[:MAX_PASSAGE],
                                "label": label,
                                "category": category if label else "benign",
                                "source": f"atr-{key}",
                                "split": split,
                            }
                        )
        for path in sorted(root.glob("data/benign-corpus-extended/*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    text = json.loads(line).get("text")
                except ValueError:
                    continue
                if isinstance(text, str) and text.strip():
                    rows.append(
                        {
                            "text": text[:MAX_PASSAGE],
                            "label": 0,
                            "category": "benign",
                            "source": "atr-benign-corpus",
                            "split": TextDataset.half(text),
                        }
                    )
        return rows

    @staticmethod
    def real_skills(corpus: Path, which: str, count: int, seed: int) -> list[tuple[str, str]]:
        seen: set[str] = set()
        chosen: list[tuple[str, str]] = []
        for directory in sorted(corpus.iterdir()):
            if AgentConfigCorpus.half_of("/".join(directory.name.split("__")[:2])) != which:
                continue
            skill = directory / "SKILL.md"
            if not skill.is_file():
                continue
            text = skill.read_text(encoding="utf-8", errors="replace")
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            chosen.append((directory.name, text))
        random.Random(seed).shuffle(chosen)  # noqa: S311 - a reproducible sample, not a secret
        return chosen[:count]

    @staticmethod
    def malicious_skills(data: Path) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        work = Path(tempfile.mkdtemp())
        for name, archive, _ in [
            s for s in Harness.malware_samples(data) if "/ai-skills/" in str(s[1])
        ]:
            target = Harness._unzip_datadog(archive, work / hashlib.md5(name.encode()).hexdigest())  # noqa: S324 - a directory name
            if target is None:
                continue
            texts = []
            for path in sorted(Path(target).rglob("*.md")):
                texts.append(path.read_text(encoding="utf-8", errors="replace"))
            sample = name.split("/")[-1].removesuffix(".zip")
            rows.append(
                {
                    "name": sample,
                    "text": "\n\n".join(texts),
                    "label": 1,
                    "half": "dev" if hashlib.sha256(name.encode()).digest()[0] % 2 == 0 else "held",
                }
            )
        return rows

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--atr", type=Path, default=next(Path("/atr").iterdir(), Path("/atr")))
        parser.add_argument("--corpus", type=Path, default=Path("/corpus/skills"))
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--out", type=Path, default=Path("/work/text"))
        parser.add_argument("--train-skills", type=int, default=20000)
        parser.add_argument("--eval-skills", type=int, default=10000)
        args = parser.parse_args()
        args.out.mkdir(parents=True, exist_ok=True)
        passages = TextDataset.atr(args.atr)
        # One shuffled list of the calibrate half, cut into disjoint parts: the skills the model is
        # trained on are never the ones its threshold is set on.
        calibrate = TextDataset.real_skills(
            args.corpus, "calibrate", args.train_skills + 5000, 20261011
        )
        for name, text in calibrate[: args.train_skills]:
            for passage in TextDataset.passages(text):
                passages.append(
                    {
                        "text": passage,
                        "label": 0,
                        "category": "benign",
                        "source": "real-skill",
                        "split": TextDataset.half(name),
                        "skill": name,
                    }
                )
        (args.out / "passages.jsonl").write_text(
            "\n".join(json.dumps(p) for p in passages) + "\n", encoding="utf-8"
        )
        skills = [
            {"name": n, "text": t, "label": 0, "half": "evaluate"}
            for n, t in TextDataset.real_skills(args.corpus, "evaluate", args.eval_skills, 7)
        ]
        skills += [
            {"name": n, "text": t, "label": 0, "half": "calibrate"}
            for n, t in calibrate[args.train_skills :]
        ]
        skills += TextDataset.malicious_skills(args.data)
        (args.out / "skills.jsonl").write_text(
            "\n".join(json.dumps(s) for s in skills) + "\n", encoding="utf-8"
        )
        by: dict[str, int] = {}
        for p in passages:
            key = f"passage label={p['label']} {p['source']} split={p['split']}"
            by[key] = by.get(key, 0) + 1
        for s in skills:
            key = f"skill label={s['label']} half={s['half']}"
            by[key] = by.get(key, 0) + 1
        for key in sorted(by):
            print(f"{by[key]:8d}  {key}")
        return 0


if __name__ == "__main__":
    sys.exit(TextDataset.main())
