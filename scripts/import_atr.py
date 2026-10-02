#!/usr/bin/env python3
"""Build `intel/data/atr-rules.json.gz` from a checkout of the Agent Threat Rules catalogue.

ATR (https://github.com/Agent-Threat-Rule/agent-threat-rules, MIT licensed) is the open catalogue
of AI agent threats: prompt injection, tool poisoning, context exfiltration, agent manipulation and
more, each rule a set of regular expressions over a named text field with its own true-positive and
true-negative test cases. Cordon evaluates them over the text a repository hands an agent; see
`detect/agent_threats.py`.

    python scripts/import_atr.py --atr /path/to/agent-threat-rules

Needs PyYAML, which the scanner itself does not. What it does to each rule:

1. Keeps the regex conditions over fields a repository can carry (`content`, `user_input`,
   `tool_description`, `tool_response`, `tool_name`, `tool_args`). Runtime-only fields -- traces,
   behavioural metrics, the model's own output -- are dropped.
2. Translates ATR's dialect (ECMAScript with a leading inline-flag group) to Python's: named groups
   and backreferences are respelled, the flag group becomes flags. A pattern Python cannot compile
   (variable-width lookbehind) drops that condition.
3. Times every pattern against inputs built to make a backtracking engine go exponential, in a
   worker process that is killed when it overruns, and drops any pattern slower than
   `BUDGET_SECONDS` on any of them. ATR's specification asks engines to refuse such patterns; a
   scanner reading hostile repositories cannot afford one.
4. Re-runs each rule's own test cases through the translated patterns and drops a rule that no
   longer catches its true positives, so a translation fault cannot ship as silent coverage loss.
5. Measures each rule's false-positive rate over ATR's benign corpus -- published skills,
   conversations, papers, package descriptions, confirmed in-the-wild false positives -- and records
   it. ATR's own quality standard calls a rule production-grade at or below 0.5% and demotes it
   above 2%; `detect/agents.py` grades a match by the same lines. Every condition is run over every
   sample whatever its field, so a rule is charged with any benign text it would flag anywhere.

6. With `--instruction-corpus`, measures each rule again over real instruction files -- the
   calibration half of `bench/fetch_agent_configs.py`'s corpus -- and records that rate too. An
   instruction file is written to the agent by design and is full of commands, so a rule can be
   clean on ATR's corpus and still flag ordinary CLAUDE.md files; in instruction files a rule
   counts only when it is production-grade by this measurement as well.

A rule whose combinator is `all` and lost any condition is dropped entirely: evaluating the rest
would be a different, looser rule.
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import json
import multiprocessing as mp
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cordon_scanner.intel import atr

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "src" / "cordon_scanner" / "intel" / "data"
TARGET = DATA / "atr-rules.json.gz"
MANIFEST = DATA / "advisories-digests.json"

FIELDS = {
    "content": "text",
    "user_input": "text",
    "tool_description": "tool",
    "tool_response": "tool",
    "tool_name": "tool_name",
    "tool_args": "command",
    "tool_input": "command",
}
"""ATR field -> the kind of repository text it is evaluated over (see `detect/agent_threats.py`)."""

BUDGET_SECONDS = 0.1
CHUNK = 4096
"""The largest piece of text one pattern is run over at scan time. The timing inputs are this long."""

_ADVERSARIAL = [
    "a" * CHUNK,
    " " * CHUNK,
    ("a " * (CHUNK // 2)),
    ("ignore " * (CHUNK // 7)),
    ("aaaa" * (CHUNK // 4 - 1)) + "!",
    ("\n" * CHUNK),
    ("x." * (CHUNK // 2)),
    ("A1-" * (CHUNK // 3)),
    ("you must " * (CHUNK // 9)),
    ("\\" * CHUNK),
    ('"' + "a" * (CHUNK - 2) + '"'),
    ("<" + "a" * (CHUNK - 2)),
    ("http://" + "a." * (CHUNK // 2 - 4)),
]


def translate(pattern: str) -> tuple[str, str]:
    """ECMAScript pattern with an optional leading `(?ims)` -> (python pattern, flags)."""
    flags = ""
    found = re.match(r"^\(\?([ims]+)\)", pattern)
    if found:
        flags = found.group(1)
        pattern = pattern[found.end() :]
    pattern = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", pattern)
    pattern = re.sub(r"\\k<([A-Za-z_]\w*)>", r"(?P=\1)", pattern)
    pattern = _split_lookbehinds(pattern)
    return pattern, "".join(sorted(set(flags)))


_ALTERNATION_LOOKBEHIND = re.compile(r"\(\?<!\\b\(\?:([^()]*)\)\\s\)")


def _split_lookbehinds(pattern: str) -> str:
    """`(?<!\\b(?:they|user|for example)\\s)`, which ECMAScript allows and Python's fixed-width
    lookbehind does not, as one fixed-width lookbehind per alternative: not preceded by any of
    them is not preceded by each of them."""
    return _ALTERNATION_LOOKBEHIND.sub(
        lambda m: "".join(f"(?<!\\b{word}\\s)" for word in m.group(1).split("|")), pattern
    )


PORTS: dict[str, tuple[tuple[str, str], ...]] = {
    # -- Python cannot compile the original --------------------------------------------------
    # A positive variable-width lookbehind, "mcpServers within 500 characters before", becomes
    # the same 500 characters consumed in front: a match exists exactly when one did before.
    "ATR-2026-02300": ((r"(?<=\bmcpServers\b[\s\S]{0,500})", r"\bmcpServers\b[\s\S]{0,500}?"),),
    "ATR-2026-02304#1": (
        (
            r"(?<=\b(?:WebFetch|fetch(?:_url)?|curl|wget|GET|POST|download(?:ing)?|(?:send|issue|make)\s+(?:a\s+|an\s+)?(?:web)?fetch|request(?:ing)?)\b[\s\S]{0,30}?)",
            r"\b(?:WebFetch|fetch(?:_url)?|curl|wget|GET|POST|download(?:ing)?|(?:send|issue|make)\s+(?:a\s+|an\s+)?(?:web)?fetch|request(?:ing)?)\b[\s\S]{0,30}?",
        ),
    ),
    # ECMAScript reads `\1` in a pattern with no group 1 as the octal escape U+0001.
    # And at least forty words before the marker is the last forty of them before it.
    "ATR-2026-00290#3": ((r"(?:(?:\w+\s+){40,})\1{3,}", r"(?<!\w)(?:\w+\s+){40}\x01{3,}"),),
    # -- The original backtracks quadratically or worse on hostile input ------------------------
    # Each rewrite matches exactly the texts the original matched; what changes is where the
    # engine is allowed to start trying.
    #
    # Two lookaheads over the whole text, tried at every position: anchored at the start, each
    # is tried once, and both hold somewhere in the text exactly when they did before.
    "ATR-2026-00063#4": ((r"(?=[\s\S]*(?<![a-z])\.env)", r"\A(?=[\s\S]*?(?<![a-z])\.env)"),),
    # Two or more letters before the character: then the last two of them are right before it.
    "ATR-2026-00086#3": ((r"|[a-zA-Z]{2,}[\uF900-\uFAFF]", r"|[a-zA-Z]{2}[\uF900-\uFAFF]"),),
    # Optional words in front change nothing about whether the rest matches.
    "ATR-2026-00139#0": (
        (r"(?:fyi|btw|heads up)?\s*(?:the\s+)?(?:orchestrator", r"(?:orchestrator"),
    ),
    # `\s*` after a line start reaches across later line breaks; starting at the last of them
    # instead, with blanks other than a line break, finds the same matches.
    "ATR-2026-00149#3": ((r"(?:^|[\n;&|])\s*", r"(?:^|[\n;&|])[^\S\n]*"),),
    "ATR-2026-00256#4": (
        (
            r"(?:^|\\n|\n)\s*[A-Za-z0-9+/]{80,}",
            r"(?:^|\\n|\n)[^\S\n]*(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}",
        ),
    ),
    "ATR-2026-00282#0": ((r"(?:^|\n)\s*", r"(?:^|\n)[^\S\n]*"),),
    "ATR-2026-00282#4": ((r"(?:^|\n)\s*(?:>\s*)+", r"(?:^|\n)[^\S\n]*(?:>\s*)+"),),
    "ATR-2026-00264#3": ((r"(?:^|\n|\\n)\s*>+", r"(?:^|\n|\\n)[^\S\n]*>+"),),
    "ATR-2026-00282#1": (
        (r"\n\s*-{3,}\s*\n", r"\n[^\S\n]*-{3,}[^\S\n]*\n"),
        (r"\n\s*={3,}\s*\n", r"\n[^\S\n]*={3,}[^\S\n]*\n"),
        (r"\n\s*\*{3,}\s*\n", r"\n[^\S\n]*\*{3,}[^\S\n]*\n"),
        (r"\n\s*#{3,}\s*\n", r"\n[^\S\n]*#{3,}[^\S\n]*\n"),
    ),
    "ATR-2026-00446": ((r"(?:^|[\n\r])\s*", r"(?:^|[\n\r])[^\S\n\r]*"),),
    "ATR-2026-00450#2": ((r"^\s*(?:SYSTEM", r"^[^\S\n]*(?:SYSTEM"),),
    # A run of characters tried from every position inside it: from the start of the run only.
    # The run's later characters are still reachable by backtracking, so nothing is lost.
    "ATR-2026-00223#2": ((r"[A-Za-z0-9+/]{50,}=*", r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{50,}=*"),),
    "ATR-2026-00328#3": ((r"\w+\s+Mode\s+", r"(?<!\w)\w+\s+Mode\s+"),),
    "ATR-2026-00394#2": ((r"[A-Za-z]{2,}\x08", r"[A-Za-z]{2}\x08"),),
    "ATR-2026-00330#2": (
        (r"[A-Z][A-Z0-9]+\s+(?:respond", r"(?<![A-Z])[A-Z][A-Z0-9]+\s+(?:respond"),
    ),
    "ATR-2026-02261#0": (
        (r"(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)", r"(?<![\w$])([A-Za-z_$][\w$]*)"),
    ),
    # Five or more backslashes: the last five of them are as good a start as the first, and the
    # rest of the pattern is bounded from there.
    "ATR-2026-00508#1": ((r"(\\{5,}|\\n{3,})", r"(\\{5}|\\n{3,}+)"),),
    # A leading run that may be empty adds nothing to whether the rest matches.
    "ATR-2026-01307#1": ((r"[\w.-]*(?:1time", r"(?:1time"),),
    "ATR-2026-01307#0": (
        (r"\b[a-zA-Z0-9.-]+\.(?:rebind", r"(?<![a-zA-Z0-9.-])[a-zA-Z0-9.-]+\.(?:rebind"),
    ),
}
"""Hand-ported patterns, by rule or by `rule#condition`: (original fragment, replacement) pairs
applied after translation. A port that no longer finds its fragment fails the import, so an
upstream change to a ported pattern is noticed rather than shipped unported."""


APPLIED_PORTS: set[str] = set()
"""Port keys whose fragment was found; any key not in it at the end of an import is stale."""


def port(rule_id: str, index: int, pattern: str) -> tuple[str, bool]:
    """`pattern` with any hand port for this condition applied, and whether one was."""
    key = f"{rule_id}#{index}" if f"{rule_id}#{index}" in PORTS else rule_id
    ported = pattern
    for original, replacement in PORTS.get(key, ()):
        if original in ported:
            ported = ported.replace(original, replacement)
            APPLIED_PORTS.add(key)
    return ported, ported != pattern


compile_flags = atr.AtrText.flags_of
"""ATR's reference engine compiles every pattern case-insensitive; so does the scanner."""


def _time_worker(jobs: mp.Queue, done: mp.Queue) -> None:  # type: ignore[type-arg]
    while True:
        job = jobs.get()
        if job is None:
            return
        key, pattern, flags = job
        compiled = re.compile(pattern, compile_flags(flags))
        slowest = 0.0
        for text in _ADVERSARIAL:
            # The best of three, so a busy machine does not make a linear pattern look slow.
            best = float("inf")
            for _ in range(3):
                started = time.perf_counter()
                compiled.search(text)
                best = min(best, time.perf_counter() - started)
                if best > BUDGET_SECONDS * 10:
                    break
            slowest = max(slowest, best)
        done.put((key, slowest))


def screen(patterns: dict[str, tuple[str, str]]) -> dict[str, float]:
    """Seconds each pattern took at worst; `inf` for one that had to be killed."""
    timings: dict[str, float] = {}
    pending = list(patterns.items())
    while pending:
        jobs: mp.Queue = mp.Queue()  # type: ignore[type-arg]
        done: mp.Queue = mp.Queue()  # type: ignore[type-arg]
        for key, (pattern, flags) in pending:
            jobs.put((key, pattern, flags))
        jobs.put(None)
        worker = mp.Process(target=_time_worker, args=(jobs, done), daemon=True)
        worker.start()
        finished = 0
        while finished < len(pending):
            try:
                key, seconds = done.get(timeout=max(2.0, BUDGET_SECONDS * 40))
            except Exception:
                break
            timings[key] = seconds
            finished += 1
        worker.kill()
        worker.join()
        remaining = [(k, v) for k, v in pending if k not in timings]
        if remaining:
            # The first pattern not answered is the one the worker was stuck on.
            timings[remaining[0][0]] = float("inf")
            remaining = remaining[1:]
        pending = remaining
    return timings


def _inputs(case: Any) -> dict[str, str]:
    """A test case's text by ATR field."""
    if not isinstance(case, dict):
        return {}
    merged = dict(case)
    structured = merged.get("input") if isinstance(merged.get("input"), dict) else None
    if structured is not None:
        merged.update(merged.pop("input"))
    if isinstance(merged.get("response"), str):
        merged.setdefault("tool_response", merged["response"])
    out: dict[str, str] = {}
    for field in FIELDS:
        value = merged.get(field)
        if isinstance(value, str):
            out[field] = value
        elif value is not None and field in ("tool_args", "tool_input"):
            out[field] = json.dumps(value)
    if isinstance(merged.get("input"), str):
        # A bare `input` is offered to whatever field the rule reads, as ATR's harness does.
        out["*"] = merged["input"]
    elif structured is not None:
        # A structured input is also read as its JSON encoding, as ATR's harness reads it.
        out["*"] = json.dumps(structured)
    if isinstance(merged.get("tool_call"), dict):
        call = merged["tool_call"]
        out.setdefault("tool_name", str(call.get("name") or ""))
        args = call.get("args") or call.get("arguments")
        if args is not None:
            out.setdefault("tool_args", args if isinstance(args, str) else json.dumps(args))
    return out


ALL_KINDS = (*atr.TEXT_KINDS, "tool_name")


def as_rule(rule: dict[str, Any]) -> atr.AtrRule:
    """The scanner's view of a rule being imported."""
    return atr.AtrRule(
        rule_id=rule["id"],
        title=rule["title"],
        category=rule["category"],
        severity=rule["severity"],
        status=rule["status"],
        every=rule["condition"] == "all",
        conditions=tuple(
            atr.Condition(
                atr.KINDS[c["field"]], re.compile(c["pattern"], compile_flags(c["flags"]))
            )
            for c in rule["conditions"]
        ),
        benign_rate=0.0,
        outside_code=rule["outside_code"],
    )


def matches(rule: dict[str, Any], fields: dict[str, str]) -> bool:
    """Whether the scanner would flag any text in this test case with this rule.

    The scanner checks every piece of agent-facing text against every family but tool names
    (`atr.TEXT_KINDS`), and tool names against their own; a test case's fields are read the same.
    """
    compiled = as_rule(rule)
    for field, text in fields.items():
        kinds = ("tool_name",) if field == "tool_name" else ALL_KINDS
        if text and atr.AtrEngine.rule_matches(compiled, text, kinds):
            return True
    return False


_MEASURE_RULES: list[dict[str, Any]] = []
_MEASURE_SAMPLES: list[atr.Prepared] = []


def _measure_one(index: int) -> int:
    rule = as_rule(_MEASURE_RULES[index])
    return sum(
        1
        for sample in _MEASURE_SAMPLES
        if atr.AtrEngine.rule_span(rule, sample, ALL_KINDS) is not None
    )


def benign_samples(checkout: Path) -> list[str]:
    samples: list[str] = []
    for path in sorted((checkout / "data" / "benign-corpus-extended").glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            with contextlib.suppress(ValueError):
                record = json.loads(line)
                text = record.get("text") if isinstance(record, dict) else None
                if isinstance(text, str) and text.strip():
                    samples.append(text)
    return samples


def measure(rules: list[dict[str, Any]], samples: list[str], workers: int) -> list[int]:
    global _MEASURE_RULES, _MEASURE_SAMPLES
    _MEASURE_RULES, _MEASURE_SAMPLES = rules, [atr.AtrText.prepare(s) for s in samples]
    with mp.get_context("fork").Pool(workers) as pool:
        return pool.map(_measure_one, range(len(rules)), chunksize=4)


def instruction_samples(corpus: Path) -> list[str]:
    """The calibration half's instruction files, as text."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bench"))
    from fetch_agent_configs import INSTRUCTION_FILES, half_of

    samples = []
    for repo in sorted((corpus / "files").iterdir()):
        if not repo.is_dir() or half_of(repo.name.replace("__", "/", 1)) != "calibrate":
            continue
        for path in sorted(repo.rglob("*")):
            if path.is_file() and path.name in INSTRUCTION_FILES:
                samples.append(path.read_text(encoding="utf-8", errors="replace"))
    return samples


def head_commit(checkout: Path) -> str:
    """The commit a git checkout has out, read from `.git` without running git."""
    git = checkout / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head
        ref = head[5:]
        if (git / ref).is_file():
            return (git / ref).read_text(encoding="utf-8").strip()
        for line in (git / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + ref):
                return line.split(" ", 1)[0]
    except OSError:
        pass
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--atr", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=mp.cpu_count())
    parser.add_argument(
        "--instruction-corpus",
        type=Path,
        help="bench/fetch_agent_configs.py output; its calibration half grades rules in instruction files",
    )
    args = parser.parse_args()

    commit = head_commit(args.atr)
    dropped: dict[str, list[str]] = {}
    candidates: list[dict[str, Any]] = []
    tests: dict[str, dict[str, list[dict[str, str]]]] = {}
    patterns: dict[str, tuple[str, str]] = {}

    for path in sorted((args.atr / "rules").rglob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            dropped.setdefault("unparseable", []).append(path.name)
            continue
        if not isinstance(document, dict) or "id" not in document:
            continue
        rule_id = str(document["id"])
        if document.get("status") == "deprecated":
            dropped.setdefault("deprecated", []).append(rule_id)
            continue
        detection = document.get("detection") or {}
        combinator = str(detection.get("condition") or "any")
        if combinator not in ("any", "all"):
            dropped.setdefault("boolean expression combinator", []).append(rule_id)
            continue
        kept = []
        lost = 0
        for n, condition in enumerate(detection.get("conditions") or ()):
            if not isinstance(condition, dict):
                lost += 1
                continue
            field = condition.get("field")
            if condition.get("operator") != "regex" or field not in FIELDS:
                lost += 1
                continue
            pattern, flags = translate(str(condition.get("value") or ""))
            pattern, ported = port(rule_id, n, pattern)
            try:
                re.compile(pattern, compile_flags(flags))
            except re.error:
                dropped.setdefault("pattern Python cannot compile", []).append(f"{rule_id}#{n}")
                lost += 1
                continue
            key = f"{rule_id}#{n}"
            patterns[key] = (pattern, flags)
            kept.append(
                {"key": key, "field": field, "pattern": pattern, "flags": flags, "ported": ported}
            )
        if not kept or (combinator == "all" and lost):
            dropped.setdefault("no condition a repository can carry", []).append(rule_id)
            continue
        tags = document.get("tags") or {}
        candidates.append(
            {
                "id": rule_id,
                "title": str(document.get("title") or "").strip(),
                "category": str(tags.get("category") or path.parent.name),
                "severity": str(document.get("severity") or "medium").lower(),
                "status": str(document.get("status") or "experimental"),
                "condition": combinator,
                "conditions": kept,
                "outside_code": tags.get("suppress_in_code_blocks") is True,
            }
        )
        cases = document.get("test_cases") or {}
        tests[rule_id] = {
            "positive": [_inputs(c) for c in cases.get("true_positives") or ()],
            "negative": [_inputs(c) for c in cases.get("true_negatives") or ()],
        }

    print(f"timing {len(patterns)} patterns against backtracking inputs...", flush=True)
    timings = screen(patterns)
    rules: list[dict[str, Any]] = []
    for rule in candidates:
        fast = [
            c for c in rule["conditions"] if timings.get(c["key"], float("inf")) <= BUDGET_SECONDS
        ]
        for slow in (c for c in rule["conditions"] if c not in fast):
            dropped.setdefault("pattern too slow on hostile input", []).append(slow["key"])
        if not fast or (rule["condition"] == "all" and len(fast) < len(rule["conditions"])):
            dropped.setdefault("every usable pattern too slow", []).append(rule["id"])
            continue
        rule["conditions"] = [
            {k: c[k] for k in ("field", "pattern", "flags", "ported")} for c in fast
        ]
        positives = [p for p in tests[rule["id"]]["positive"] if p]
        caught = sum(1 for p in positives if matches(rule, p))
        if positives and caught == 0:
            dropped.setdefault("translation catches none of its own true positives", []).append(
                rule["id"]
            )
            continue
        rules.append(rule)

    stale = sorted(set(PORTS) - APPLIED_PORTS)
    if stale:
        print(f"refusing to write: ports whose original pattern changed upstream: {stale}")
        return 1
    samples = benign_samples(args.atr)
    print(f"measuring {len(rules)} rules over {len(samples)} benign samples...", flush=True)
    for rule, hits in zip(rules, measure(rules, samples, args.workers), strict=True):
        rule["benign_hits"] = hits
    instruction_count = 0
    if args.instruction_corpus:
        instructions = instruction_samples(args.instruction_corpus)
        instruction_count = len(instructions)
        print(
            f"measuring {len(rules)} rules over {instruction_count} real instruction files...",
            flush=True,
        )
        for rule, hits in zip(rules, measure(rules, instructions, args.workers), strict=True):
            rule["instruction_hits"] = hits
    document = {
        "generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "benign_samples": len(samples),
        "instruction_samples": instruction_count,
        "source": "https://github.com/Agent-Threat-Rule/agent-threat-rules",
        "commit": commit,
        "license": "MIT",
        "rules": rules,
        "dropped": {reason: sorted(ids) for reason, ids in sorted(dropped.items())},
    }
    TARGET.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    digests = json.loads(MANIFEST.read_text(encoding="utf-8"))
    digests[TARGET.name] = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    MANIFEST.write_text(json.dumps(digests, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(rules)} rules to {TARGET} (ATR {commit[:12]})")
    for reason, ids in sorted(dropped.items()):
        print(f"  dropped, {reason}: {len(ids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
