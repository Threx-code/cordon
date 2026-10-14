"""A labelled corpus of agent-directed text from public datasets, for the learned text models.

    docker run --rm -v cordon-bench-text:/t -v "$PWD:/w:ro" python:3.12-slim sh -c \\
      'pip -q install pyarrow==17.0.0 && python /w/bench/model/agent_text_corpus.py /t /t/corpus/agent-text.jsonl'

Every row is `{label, source, group, half, channel, text}`: label 1 for text written to make a model
act against its instructions (prompt injection, jailbreak), 0 for ordinary requests and messages.
Rows are deduplicated on their normalised text, cut to `MAX_CHARS`, and split into a work and a
holdout half by a stable hash, so a model trained on `work` is measured on text it has not seen.

Each source is capped (`CAPS`) so one campaign cannot teach the model its vocabulary: LLMail-Inject's
460K attempts all target one email agent's `send_email`, and uncapped they would be most of the
attack half. The sources whose text never enters training -- MCPTox, MCP-SafetyBench, MalSkillBench's
holdout, DataDog's skills, AgentDefense -- are not read here at all.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

MAX_CHARS = 4000
CAPS = {
    "llmail-inject": 120_000,
    "prompt-injection-534k": 150_000,
    "spml": 90_000,
    "oasst2": 90_000,
    "alpaca": 52_000,
    "hackaprompt": 250_000,
    "ultrachat": 150_000,
    "wizardlm": 100_000,
}


class Sources:
    """Each public dataset, as (label, source, group, text) rows."""

    @staticmethod
    def parquet(root: Path, name: str) -> Iterator[dict]:
        import pyarrow.parquet as pq

        for file in sorted((root / name).rglob("*.parquet")):
            yield from pq.read_table(file).to_pylist()

    @classmethod
    def all(cls, root: Path) -> Iterator[tuple[int, str, str, str]]:
        data = root / "microsoft__llmail-inject-challenge" / "data"
        for phase in ("labelled_unique_submissions_phase1.json", "labelled_unique_submissions_phase2.json"):
            if (data / phase).is_file():
                # Keyed by the submitted email; the value is its label.
                for text, meta in json.loads((data / phase).read_text(encoding="utf-8")).items():
                    if isinstance(meta, dict) and str(meta.get("attack_attempt")) == "True":
                        yield 1, "llmail-inject", "", text
        if (data / "emails_for_fp_tests.json").is_file():
            for index, text in enumerate(json.loads((data / "emails_for_fp_tests.json").read_text(encoding="utf-8"))):
                yield 0, "llmail-benign", f"llmail-fp:{index}", text
        for row in cls.parquet(root, "geekyrakshit__prompt-injection-dataset"):
            yield int(str(row["label"]) == "1"), "prompt-injection-534k", "", row["prompt"]
        for name, source in (("xTRam1__safe-guard-prompt-injection", "safe-guard"),
                             ("deepset__prompt-injections", "deepset"),
                             ("JasperLS__prompt-injections", "jasperls")):
            for row in cls.parquet(root, name):
                yield int(str(row["label"]) == "1"), source, "", row["text"]
        for row in cls.parquet(root, "Lakera__gandalf_ignore_instructions"):
            yield 1, "gandalf", "", row["text"]
        for row in cls.parquet(root, "TrustAIRLab__in-the-wild-jailbreak-prompts"):
            yield int(str(row.get("jailbreak")) == "True"), "in-the-wild", "", row["prompt"]
        for file in (root / "jackhhao__jailbreak-classification" / "default").glob("*full*.csv"):
            with file.open(encoding="utf-8", errors="replace") as handle:
                for row in csv.DictReader(handle):
                    yield int(row.get("type") == "jailbreak"), "jailbreak-classification", "", row["prompt"]
        spml = root / "reshabhs__SPML_Chatbot_Prompt_Injection" / "spml_prompt_injection.csv"
        if spml.is_file():
            with spml.open(encoding="utf-8", errors="replace") as handle:
                for row in csv.DictReader(handle):
                    yield int(str(row.get("Prompt injection")) == "1"), "spml", "", row["User Prompt"]
        # HackAPrompt's submissions (the competition's cleaned release): every row is an attempt to
        # override a model's instructions. Its label is whether that attempt beat one model, so the
        # same text appears under both; by intent each is an attack.
        for row in cls.parquet(root, "imoxto__prompt_injection_cleaned_dataset-v2"):
            yield 1, "hackaprompt", "", row["text"]
        for row in cls.parquet(root, "jayavibhav__prompt-injection"):
            yield int(str(row["label"]) == "1"), "jayavibhav", "", row["text"]
        for row in cls.parquet(root, "HuggingFaceH4__ultrachat_200k"):
            yield 0, "ultrachat", "", row["prompt"]
        for file in (root / "WizardLMTeam__WizardLM_evol_instruct_V2_196k").glob("*.json"):
            for row in json.loads(file.read_text(encoding="utf-8")):
                turns = row.get("conversations") or []
                if turns and turns[0].get("from") == "human":
                    yield 0, "wizardlm", "", turns[0].get("value", "")
        for row in cls.parquet(root, "OpenAssistant__oasst2"):
            if row.get("role") == "prompter" and str(row.get("deleted")) != "True":
                yield 0, "oasst2", "", row["text"]
        for row in cls.parquet(root, "tatsu-lab__alpaca"):
            yield 0, "alpaca", "", (row["instruction"] + "\n" + (row.get("input") or "")).strip()
        for file in (root / "databricks__databricks-dolly-15k").glob("*.jsonl"):
            with file.open(encoding="utf-8") as handle:
                for line in handle:
                    row = json.loads(line)
                    yield 0, "dolly", "", (row["instruction"] + "\n" + (row.get("context") or "")).strip()


class Corpus:
    @staticmethod
    def key(text: str) -> str:
        return hashlib.sha256(re.sub(r"\s+", " ", text.lower()).strip().encode()).hexdigest()

    @staticmethod
    def build(root: Path, out: Path) -> Counter:
        seen: set[str] = set()
        kept: Counter = Counter()
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as handle:
            for label, source, group, text in Sources.all(root):
                if not isinstance(text, str) or len(text.strip()) < 8:
                    continue
                key = Corpus.key(text)
                if key in seen or kept[(source, label)] >= CAPS.get(source, 10**9):
                    continue
                seen.add(key)
                kept[(source, label)] += 1
                half = "holdout" if int(key[:8], 16) % 2 else "work"
                handle.write(json.dumps({
                    "label": label, "source": source, "group": group or f"{source}:{key[:12]}",
                    "half": half, "channel": "prompt", "text": text[:MAX_CHARS],
                }) + "\n")
        return kept


if __name__ == "__main__":
    counts = Corpus.build(Path(sys.argv[1]), Path(sys.argv[2]))
    for (source, label), n in sorted(counts.items()):
        print(f"{source:28} label={label} {n}")
    print("total", sum(counts.values()))
