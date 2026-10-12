#!/usr/bin/env python3
"""Malicious AI-agent skills: what Cordon blocks, judged against criteria fixed before its verdicts.

```
  DataDog ai-skills (204, labelled malicious) ──┬── evidence  (regexes below, NOT Cordon's rules)
                                                │       │
                                                │   adjudicate: D1..D5, reviewed overrides
                                                │       │
                                                └── scan ──┴──► blocked share of the DEMONSTRABLY
                                                                 malicious, per half
  real public skills (bench/fetch_skills.py) ───── scan ───────► false-block share, per half
```

Every split is by a hash of the name, fixed before any rule was written against it:
  malicious skills: sha256(name)[0] even -> "dev" (studied), odd -> "held" (reported)
  real skills:      AgentConfigCorpus.half_of(repository) -> "calibrate" / "evaluate"

Demonstrably malicious means the skill's own files show one of:
  D1 dropper      downloads and runs code
  D2 theft        code that reads a secret AND sends it to a host that is not local
  D3 concealment  hides what it does from the user, AND D1, D2 or D4
  D4 destruction  wipes the home directory, a disk or the filesystem
  D1 counts a download run by code, by a hook, or by an instruction that runs it unasked; a
     documented installer a person chooses to run is risky and warns (`syncause`, below).
  D5 campaign     a member of ClawHavoc, the publicly documented skill-malware campaign
  D6 control      runs commands sent from elsewhere, or plants an access bypass for an outsider
  D7 on load      code that runs because the skill is parsed (`---js` front matter)
  D8 override     tells the agent to drop its safety rules AND to hide that from the user
The regexes below find D1-D5 in most samples. Every sample they did not mark was then read in full,
and those meeting a criterion are in READ_BY_HAND with the evidence; that reading added samples
Cordon missed as well as ones it caught, and it is why the cisco "exfiltrator" fixture stays out
(a generic API_KEY sent to one host is the shape of every API client; only its comments say more).
A labelled sample with none of these is counted in the dataset-wide rate, not the demonstrable
one; the DataDog set also labels risky-but-legitimate skills (an SMTP sender, a scheduler) and other
scanners' test fixtures. Overrides, each read by hand and each giving its reason, are below.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-skills:/corpus:ro \\
      -v "$PWD:/s:ro" -v OUT:/out cordon-prepush:<tag> sh -c \\
      'cp -r /s /tmp/w && PYTHONPATH=/tmp/w/src:/tmp/w/bench python /tmp/w/bench/skills_measure.py'

Writes /out/skills.json (every verdict, finding rule ids only) and prints the rates. Nothing in a
sample is executed; the network is off.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fetch_agent_configs import AgentConfigCorpus
from run import Harness

SEED = 20261011
SEND = re.compile(
    r"(?i)(requests\.(post|put)|urllib\.request\.urlopen|http\.client|fetch\(|axios\.(post|put)"
    r"|XMLHttpRequest|socket\.(connect|send)|smtplib|curl\s[^\n]*(-d|--data|-F|-T|--upload)"
    r"|wget\s[^\n]*--post|Invoke-WebRequest|webhook)"
)
SECRET = re.compile(
    r"(?i)(os\.environ(?!\.get\(\s*['\"](HOME|PATH|USER|LANG))|process\.env\b|getenv\(|\.ssh/|id_rsa"
    r"|\.aws/|credentials|keychain|security find-|\.env\b|cookies?\(|wallet|seed phrase|private.?key"
    r"|browser.*(login|cookie)|Login Data|\.npmrc|\.git-credentials|/etc/passwd)"
)
DLEXEC = re.compile(
    r"(?i)((curl|wget|iwr|irm)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh|base64\s+-[dD][^\n]{0,60}\|\s*(ba|z)?sh"
    r"|extract[^\n]{0,80}pass|chmod \+x[^\n]{0,80}&&|xattr -[dc]|powershell[^\n]{0,40}-enc)"
)
COVERT = re.compile(
    r"(?i)((do not|don't|never)\s+(tell|inform|mention|reveal|notify)[^\n]{0,40}user"
    r"|without (the user'?s? )?(knowledge|consent|asking|telling)|silently|in the background without"
    r"|hide (this|the) (from|instruction))"
)
DESTROY = re.compile(
    r"(?i)(rm\s+-rf\s+(/|~|\$HOME)|mkfs|dd if=/dev/(zero|random) of=/dev|:\(\)\{|format c:|del /[sq])"
)
LOCAL = re.compile(r"(?i)localhost|127\.0\.0\.1|example\.(com|org|invalid)|attacker\.example")
CAMPAIGN = re.compile(
    r"(?i)openclaw-(thiagoruss0|hightower6eu|jordanprater)|netcode-openclaw-skills-old-fork"
)

OWN_SERVICE = "sends a credential only to the service that issued it (an API client)"
OVERRIDES: dict[str, str] = {
    **dict.fromkeys(
        (
            "sanjay3290-ai-skills-skills-gmail",
            "sanjay3290-ai-skills-skills-google-drive",
            "sanjay3290-ai-skills-skills-google-sheets",
            "sanjay3290-postgres-skill-skills-gmail",
            "sanjay3290-postgres-skill-skills-google-calendar",
            "sanjay3290-postgres-skill-skills-google-chat",
            "sanjay3290-postgres-skill-skills-google-docs",
            "sanjay3290-postgres-skill-skills-google-sheets",
            "shuliuzhenhua-sys-shuliu-skills-skills-banana-proxy",
            "ralph-wren-omni-recall",
            "mvanhorn-clawdbot-skill-parallel",
            "manojbajaj95-gtm-skills-skills-leadgenius-api",
        ),
        OWN_SERVICE,
    ),
    "plugins-world-pw-skills-pw-image-generation": "uploads the user's generated image to an image host: its function",
    "plurigrid-asi-skills-vercel-deploy": "uploads the project to Vercel to deploy it, .env excluded: its function",
    "alfredang-skills-start-app": "'do NOT silently retry' and a cache rm -rf: the patterns misread, nothing harmful",
    "syncause-debug-skill-skills-syncause-debugger": "curl | bash of the vendor's pinned installer in a reference doc: risky, warns",
}

#: Samples the regexes did not mark, read in full and found to meet a criterion, with the evidence.
READ_BY_HAND: dict[str, tuple[str, str]] = {
    "3bkader-gpt-malicious-skill-poc": (
        "D7",
        "SKILL.md front matter is `---js`: a parser that honours it runs the code",
    ),
    "3bkader-gpt-malicious-skill-poc-malicious-skill-poc": ("D7", "the same `---js` front matter"),
    "Charpup-skill-security-auditor-backdoor-skill": (
        "D6",
        "a listener and a connection that run the commands they receive",
    ),
    "Charpup-skill-security-auditor-data-exfiltration-skill": (
        "D2",
        "reads .env, shell profiles and secrets.yaml and sends them to an outside host",
    ),
    "Charpup-skill-security-auditor-network-egress-skill": ("D1", "executes what a server returns"),
    "Charpup-skill-security-auditor-privilege-escalation-skill": (
        "D4",
        "appends to /etc/shadow, flushes the firewall, disables SELinux, opens / to everyone",
    ),
    "cisco-ai-defense-skill-scanner-environment-secrets": (
        "D2",
        "collects every secret-named environment variable and posts them out",
    ),
    "cisco-ai-defense-skill-scanner-magic-string-trigger": (
        "D6",
        "on a trigger string, executes a fetched payload and opens a shell to an outside host",
    ),
    "cybertechajju-version-demo-helper": (
        "D2",
        "instructs sending ~/.ssh/id_rsa, encoded, to an outside host",
    ),
    "cybertechajju-version-demo-skills-helper": ("D2", "the same instruction"),
    "ronyparra-fake-dep-check-skill": (
        "D2",
        "instructs posting secret-named environment variables and .env values to workers.dev",
    ),
    "natemcgrady-slack-gif-creator-slack-gif-creator": (
        "D1",
        "downloads a script from tmpfiles.org and runs it each time a GIF is saved",
    ),
    "clawsights-clawsights-skills-clawsights": (
        "D2",
        "sends the user's GitHub token to a host that is not GitHub, hidden from the user",
    ),
    "clawsights-clawsights-dot-agents-skills-clawsights": ("D2", "the same instruction"),
    "ZackKorman-skills-openclaw-admin-security-breakglass": (
        "D6",
        "instructs inserting an access-control bypass for a hard-coded number",
    ),
    "arjenschwarz-agentic-coding-claude-skills-project-init": (
        "D1",
        "installs a session hook that pipes a remote script into bash on every start",
    ),
    "cisco-ai-defense-skill-scanner-jailbreak-override": (
        "D8",
        "drop safety and content policy, and do not tell the user",
    ),
}


class SkillsMeasure:
    @staticmethod
    def half_of_malicious(name: str) -> str:
        return "dev" if hashlib.sha256(name.encode()).digest()[0] % 2 == 0 else "held"

    @staticmethod
    def malicious(data: Path, work: Path) -> list[tuple[str, Path]]:
        out = []
        for name, archive, _ in Harness.malware_samples(data):
            if "/ai-skills/" not in str(archive):
                continue
            target = Harness._unzip_datadog(archive, work / hashlib.md5(name.encode()).hexdigest())  # noqa: S324
            if target is not None:
                out.append((name, Path(target)))
        return out

    @staticmethod
    def evidence(name: str, root: Path) -> dict[str, Any]:
        def lines(text: str, pattern: re.Pattern[str]) -> list[str]:
            return [
                re.sub(r"[A-Za-z0-9+/=]{40,}", "<B64>", x.strip())[:140]
                for x in text.splitlines()
                if pattern.search(x)
            ][:3]

        rec: dict[str, Any] = {
            "send": [],
            "secret_in_sender": [],
            "dlexec": [],
            "covert": [],
            "destroy": [],
        }
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in (
                ".py",
                ".js",
                ".ts",
                ".mjs",
                ".sh",
                ".md",
                ".ps1",
                ".rb",
                ".json",
                ".txt",
            ):
                continue
            text = path.read_text("utf-8", "replace")
            sent = lines(text, SEND)
            if sent and path.suffix != ".md":
                rec["send"] += sent
                rec["secret_in_sender"] += lines(text, SECRET)
            rec["dlexec"] += lines(text, DLEXEC)
            rec["covert"] += lines(text, COVERT)
            rec["destroy"] += lines(text, DESTROY)
        d1 = bool(rec["dlexec"])
        d2 = bool([s for s in rec["send"] if not LOCAL.search(s)] and rec["secret_in_sender"])
        d4 = bool(rec["destroy"])
        d3 = bool(rec["covert"]) and (d1 or d2 or d4)
        d5 = bool(CAMPAIGN.search(name))
        reasons = [k for k, v in (("D1", d1), ("D2", d2), ("D3", d3), ("D4", d4), ("D5", d5)) if v]
        short = name.split("/")[-1].removesuffix(".zip")
        if short in READ_BY_HAND:
            reasons = sorted({*reasons, READ_BY_HAND[short][0]})
        return {"reasons": [] if short in OVERRIDES else reasons, "override": OVERRIDES.get(short)}

    @staticmethod
    def scan(path: Path) -> dict[str, Any]:
        out = subprocess.run(
            [
                "cordon-scanner",
                "scan",
                str(path),
                "--offline",
                "--no-color",
                "--quiet",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        ).stdout
        try:
            report = json.loads(out[out.index("{") :])
        except ValueError:
            return {"verdict": "error", "rules": []}
        findings = report.get("findings", [])
        blocking = any(
            f.get("severity") in ("high", "critical") or f.get("category") == "malicious"
            for f in findings
        )
        warning = any(f.get("severity") == "medium" for f in findings)
        return {
            "verdict": "block" if blocking else "warn" if warning else "pass",
            "rules": sorted(
                {
                    f"{f['rule_id']}/{f.get('severity')}"
                    for f in findings
                    if f.get("severity") != "info"
                }
            ),
        }

    @staticmethod
    def real(corpus: Path, excluded: set[str], draw: int) -> dict[str, list[tuple[str, Path]]]:
        halves: dict[str, list[tuple[str, Path]]] = {"calibrate": [], "evaluate": []}
        seen: set[str] = set()
        for skill in sorted(corpus.iterdir()):
            md = skill / "SKILL.md"
            if not md.exists():
                continue
            digest = hashlib.sha256(md.read_bytes()).hexdigest()
            if digest in seen or digest in excluded:
                continue
            seen.add(digest)
            repository = "/".join(skill.name.split("__")[:2])
            halves.setdefault(AgentConfigCorpus.half_of(repository), []).append((skill.name, skill))
        return {h: SkillsMeasure._draw(rows, draw) for h, rows in halves.items()}

    @staticmethod
    def _draw(rows: list[tuple[str, Path]], draw: int) -> list[tuple[str, Path]]:
        """A reproducible sample, not a secret: the seed is published so anyone draws the same."""
        return random.Random(SEED).sample(rows, min(draw, len(rows)))  # noqa: S311

    @classmethod
    def main(cls) -> int:
        parser = argparse.ArgumentParser(
            description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument("--data", type=Path, default=Path("/data"))
        parser.add_argument("--corpus", type=Path, default=Path("/corpus/skills"))
        parser.add_argument("--out", type=Path, default=Path("/out"))
        parser.add_argument(
            "--draw",
            type=int,
            default=int(os.environ.get("DRAW", "5000")),
            help="real skills per half",
        )
        parser.add_argument("--workers", type=int, default=6)
        args = parser.parse_args()
        work = Path(tempfile.mkdtemp())
        malicious = cls.malicious(args.data, work)
        excluded = {
            hashlib.sha256(md.read_bytes()).hexdigest()
            for _, root in malicious
            for md in root.rglob("SKILL.md")
        }
        real = cls.real(args.corpus, excluded, args.draw) if args.corpus.exists() else {}
        with ThreadPoolExecutor(args.workers) as pool:
            mal_rows = [
                {
                    "name": n.split("/")[-1].removesuffix(".zip"),
                    "half": cls.half_of_malicious(n),
                    **cls.evidence(n, p),
                    **v,
                }
                for (n, p), v in zip(
                    malicious, pool.map(lambda item: cls.scan(item[1]), malicious), strict=True
                )
            ]
            real_rows = {
                h: [
                    {"name": n, **v}
                    for (n, _), v in zip(
                        rows, pool.map(lambda item: cls.scan(item[1]), rows), strict=True
                    )
                ]
                for h, rows in real.items()
            }
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "skills.json").write_text(
            json.dumps({"malicious": mal_rows, "real": real_rows}, indent=1), encoding="utf-8"
        )
        for half in ("dev", "held", "all"):
            pick = [r for r in mal_rows if half in ("all", r["half"])]
            demo = [r for r in pick if r["reasons"]]
            blocked = sum(r["verdict"] == "block" for r in demo)
            print(
                f"malicious {half:4s}: demonstrable {blocked}/{len(demo)} blocked ({blocked / max(len(demo), 1):.1%}); "
                f"dataset-wide {sum(r['verdict'] == 'block' for r in pick)}/{len(pick)} blocked, "
                f"{sum(r['verdict'] != 'pass' for r in pick)} flagged"
            )
        for half, rows in real_rows.items():
            blocked = sum(r["verdict"] == "block" for r in rows)
            print(
                f"real {half:9s}: {blocked}/{len(rows)} blocked ({blocked / max(len(rows), 1):.2%}), "
                f"{sum(r['verdict'] == 'warn' for r in rows)} warned"
            )
        missed = [r for r in mal_rows if r["reasons"] and r["verdict"] != "block"]
        print("demonstrable not blocked:")
        for r in missed:
            print(f"  {r['half']} {r['verdict']} {r['reasons']} {r['name'][:80]} {r['rules'][:4]}")
        print(
            "blocking rules on real skills:",
            Counter(
                rule
                for rows in real_rows.values()
                for r in rows
                if r["verdict"] == "block"
                for rule in r["rules"]
                if rule.endswith(("/high", "/critical"))
            ).most_common(15),
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(SkillsMeasure.main())
