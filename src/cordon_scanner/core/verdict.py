"""One decision for a scanned package: block, warn or record -- learned, with a floor it cannot move.

Each rule reports what it sees in one file. Whether a package should fail a build is a different
question, and answering it rule by rule meant any one of 1,400 rules could block alone: measured on
the 234,509-unit benign corpus, single findings blocked 1-6% of every ecosystem while a lot of real
malware also showed only one (review 98). A requirement of two signals cut false blocks and lost a
fifth of the malware. What separates the two is the combination -- which rules, how strong, in what
kind of package -- and that is learned, on one half of the data and measured on the other.

```
  findings ──► per code rule, its strongest severity ┐
  package  ──► size, files, docs/tests/types, hook,   ├─► monotone trees ─► p(malicious)
              dependencies, version shape            ┘        (`data/verdict.json.gz`)
       │
       ▼
  floor: a MALWARE.* finding at high or confirmed confidence is never re-graded
  p >= block  -> what trips the gate still blocks; with no such finding, the verdict itself blocks
  p <  block  -> suspicious findings that would block are held at MEDIUM (a warning)
  p <  warn   -> code findings are recorded at LOW
```

The trees are monotone in every finding: a stronger or an extra finding never lowers the score. The
package context can lower it -- a documented, tested library is not what malware looks like -- which
is exactly why the floor exists: context an attacker controls never overrules a finding that is
malicious on its own.

Without the model file nothing is re-graded; the features are still computed and reported, which is
how the training data is made by the same code that scores it.
"""

from __future__ import annotations

import functools
import gzip
import json
import math
import re
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.core.models import Category, Confidence, Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

MODEL_PATH: Final = Path(__file__).resolve().parent.parent / "detect" / "data" / "verdict.json.gz"

_CODE_SUFFIXES: Final = (
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".py",
    ".rb",
    ".php",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".sh",
    ".ps1",
    ".lua",
    ".pl",
)
_INFRA: Final = ("SUSPECT.IAC.", "SUSPECT.K8S.", "SUSPECT.CFN.")


class VerdictFeatures:
    """What the model reads: the findings, and the package they are in."""

    PACKAGE: ClassVar[tuple[str, ...]] = (
        "n_files",
        "log_bytes",
        "n_code",
        "code_share",
        "max_code_share",
        "has_readme",
        "has_license",
        "has_types",
        "has_tests",
        "has_changelog",
        "has_map",
        "min_files",
        "hook",
        "n_deps",
        "version_odd",
        "name_digits",
        "skill",
        "agent_text",
    )

    @staticmethod
    def is_code(rule: str) -> bool:
        return rule.startswith(("MALWARE.", "SUSPECT.")) and not rule.startswith(_INFRA)

    @staticmethod
    def rules(findings: Sequence[Finding]) -> dict[str, int]:
        """Each code rule's strongest severity (0 info .. 4 critical); known-package intel excluded,
        so the verdict is about content."""
        best: dict[str, int] = {}
        for finding in findings:
            rule = finding.rule_id
            if VerdictFeatures.is_code(rule) and ".KNOWN" not in rule:
                best[rule] = max(best.get(rule, 0), int(finding.severity))
        return best

    #: What a package says it is, from its name, description and keywords.
    PURPOSE: ClassVar[dict[str, re.Pattern[str]]] = {
        name: re.compile(pattern, re.IGNORECASE)
        for name, pattern in {
            "math": r"\b(?:math|number|bignum|decimal|float|calc|arithmetic|matrix|statistics|random)\b",
            "text": r"\b(?:string|text|format|formatter|slug|case|parse|parser|template|markdown|i18n|locale|unicode|emoji)\b",
            "ui": r"\b(?:color|colour|style|css|theme|icon|font|ui|component|button|react|vue|angular|svelte|tailwind|animation)\b",
            "time": r"\b(?:date|time|clock|cron|calendar|timezone|duration)\b",
            "log": r"\b(?:log|logger|logging|debug|trace|console)\b",
            "test": r"\b(?:test|mock|assert|jest|mocha|chai|spec|fixture)\b",
            "build": r"\b(?:build|bundle|webpack|rollup|vite|babel|eslint|prettier|lint|compile|transpile|plugin|loader|preset)\b",
            "http": r"\b(?:http|api|client|sdk|fetch|request|rest|graphql|webhook|proxy|axios)\b",
            "cli": r"\b(?:cli|command|terminal|shell|tool|devtools|script)\b",
            "crypto": r"\b(?:wallet|crypto|web3|ether|ethereum|solana|bitcoin|token|defi|nft|blockchain|swap|dex)\b",
            "ai": r"\b(?:ai|llm|gpt|openai|claude|agent|mcp|copilot|chat)\b",
        }.items()
    }
    #: What the package's own code can do. Bounded patterns over bounded text; flags, not counts.
    ABILITY: ClassVar[dict[str, re.Pattern[bytes]]] = {
        name: re.compile(pattern, re.IGNORECASE)
        for name, pattern in {
            "network": rb"require\(['\"](?:https?|net|tls|dgram|axios|node-fetch|undici|got|request)['\"]\)|\bfetch\(|XMLHttpRequest|new WebSocket\(|import requests|urllib\.request|socket\.socket",
            "process": rb"child_process|execSync|spawnSync|\bspawn\(|subprocess\.|os\.system\(|os\.popen\(",
            "env": rb"process\.env\b|os\.environ",
            "recon": rb"os\.(?:hostname|userInfo|networkInterfaces)\(|platform\.node\(|getpass\.getuser|socket\.gethostname",
            "secret_paths": rb"\.ssh/|id_rsa|\.aws/|\.npmrc|\.pypirc|\.git-credentials|\.kube/config|Login Data|Local State|wallet\.dat|Local Storage[/\\]leveldb",
            "wallet_keys": rb"privateKey|secretKey|mnemonic|seedPhrase",
            "decode": rb"atob\(|Buffer\.from\([^)]{0,120}(?:base64|hex)|fromCharCode|b64decode|zlib\.decompress",
            "dynamic": rb"\beval\(|new Function\(|vm\.run|exec\(compile|__import__\(",
            "exfil_host": rb"discord(?:app)?\.com/api/webhooks|api\.telegram\.org|webhook\.site|pastebin\.com|ngrok|pipedream|oast\.|burpcollaborator",
            "raw_ip": rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        }.items()
    }
    _PLAIN: ClassVar[tuple[str, ...]] = ("math", "text", "ui", "time", "log", "test")

    @staticmethod
    def package(
        paths_sizes: Sequence[tuple[str, int]],
        manifests: dict[str, bytes],
        sources: Sequence[tuple[str, bytes]] = (),
    ) -> dict[str, float]:
        names = [p.rsplit("!", 1)[-1] for p, _ in paths_sizes]
        sizes = [s for _, s in paths_sizes]
        total = sum(sizes) or 1
        code = [s for n, s in zip(names, sizes, strict=True) if n.lower().endswith(_CODE_SUFFIXES)]
        code_bytes = sum(code)
        features: dict[str, float] = {
            "n_files": len(names),
            "log_bytes": len(str(total)),
            "n_code": len(code),
            "code_share": round(code_bytes / total, 3),
            "max_code_share": round(max(code, default=0) / max(code_bytes, 1), 3),
            "has_readme": float(any(re.search(r"(?i)(^|/)readme", n) for n in names)),
            "has_license": float(
                any(re.search(r"(?i)(^|/)(license|licence|copying)", n) for n in names)
            ),
            "has_types": float(any(n.endswith(".d.ts") for n in names)),
            "has_tests": float(
                any(re.search(r"(?i)(^|/)(tests?|__tests__|spec)/", n) for n in names)
            ),
            "has_changelog": float(
                any(re.search(r"(?i)(^|/)(changelog|history|changes)", n) for n in names)
            ),
            "has_map": float(any(n.endswith(".map") for n in names)),
            "min_files": float(len(names) <= 3),
            "hook": 0.0,
            "n_deps": 0.0,
            "version_odd": 0.0,
            "name_digits": 0.0,
            # What the package is to an agent: a skill (a SKILL.md near the top), or documents
            # an agent reads as instructions. Malicious skills are judged against other skills.
            "skill": float(
                any(n.rsplit("/", 1)[-1].upper() == "SKILL.MD" and n.count("/") <= 3 for n in names)
            ),
            "agent_text": float(
                any(
                    re.search(r"(?i)(^|/)(AGENTS|CLAUDE|GEMINI)\.md$|\.mdc$|/\.cursor/rules/", n)
                    for n in names
                )
            ),
        }
        for path, data in sorted(manifests.items(), key=lambda kv: kv[0].count("/")):
            base = path.rsplit("!", 1)[-1]
            if base.endswith("package.json"):
                try:
                    manifest = json.loads(data)
                except ValueError:
                    continue
                if not isinstance(manifest, dict):
                    continue
                scripts = manifest.get("scripts") or {}
                features["hook"] = float(
                    isinstance(scripts, dict)
                    and any(k in scripts for k in ("preinstall", "install", "postinstall"))
                )
                deps = manifest.get("dependencies") or {}
                features["n_deps"] = float(min(len(deps) if isinstance(deps, dict) else 0, 50))
                version = str(manifest.get("version", ""))
                features["version_odd"] = float(
                    bool(re.match(r"^(?:0\.0\.\d+|\d{2,}\.\d+\.\d+|1\.0\.0)$", version))
                )
                features["name_digits"] = float(
                    bool(re.search(r"\d{2,}", str(manifest.get("name", ""))))
                )
                VerdictFeatures._purpose(features, manifest)
                break
            if base.endswith("setup.py"):
                features["hook"] = max(
                    features["hook"],
                    float(
                        bool(re.search(rb"cmdclass|class \w+\((?:install|develop|egg_info)", data))
                    ),
                )
        VerdictFeatures._ability(features, sources)
        return features

    @staticmethod
    def _purpose(features: dict[str, float], manifest: dict[str, Any]) -> None:
        """What the package claims to be (review 98: library malware is a small utility whose code
        can do what no such utility needs)."""
        description = str(manifest.get("description") or "")
        keywords = manifest.get("keywords") or []
        claim = (
            " ".join(
                [str(manifest.get("name") or ""), description]
                + [str(k) for k in (keywords if isinstance(keywords, list) else [])]
            )
            .replace("-", " ")
            .replace("_", " ")
        )
        for name, pattern in VerdictFeatures.PURPOSE.items():
            features[f"purpose_{name}"] = float(bool(pattern.search(claim[:2000])))
        features["desc_len"] = float(min(len(description), 400))
        features["has_repo"] = float(bool(manifest.get("repository")))

    @staticmethod
    def _ability(features: dict[str, float], sources: Sequence[tuple[str, bytes]]) -> None:
        """What the package's own code can do, and the mismatch with what it claims."""
        own = [
            data
            for path, data in sources
            if "node_modules/" not in path and "/test" not in path and "site-packages/" not in path
        ][:400]
        found = dict.fromkeys(VerdictFeatures.ABILITY, 0.0)
        for data in own:
            head = data[:2_000_000]
            for name, pattern in VerdictFeatures.ABILITY.items():
                if not found[name] and pattern.search(head):
                    found[name] = 1.0
        features.update({f"can_{name}": value for name, value in found.items()})
        plain = any(features.get(f"purpose_{name}", 0.0) for name in VerdictFeatures._PLAIN)
        sensitive = (
            found["secret_paths"] + found["wallet_keys"] + found["exfil_host"] + found["raw_ip"]
        )
        features["plain_with_sensitive"] = float(plain and sensitive > 0)
        features["plain_with_process_net"] = float(
            plain and bool(found["process"]) and bool(found["network"])
        )


class VerdictModel:
    """Gradient-boosted trees shipped as data, evaluated here without a dependency."""

    @staticmethod
    @functools.cache
    def load(path: Path = MODEL_PATH) -> dict[str, Any] | None:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                return json.load(handle)
        except OSError:
            return None

    @staticmethod
    def vector(
        model: dict[str, Any], rules: dict[str, int], package: dict[str, float]
    ) -> list[float]:
        vocab: list[str] = model["vocab"]
        v = [float(rules.get(rule, 0)) for rule in vocab]
        v += [float(package.get(name, 0.0)) for name in VerdictFeatures.PACKAGE]
        families = {r.split(".")[1] for r, s in rules.items() if s >= int(Severity.MEDIUM)}
        v += [float(len(families)), float(max(rules.values(), default=0)), 1.0]
        return v

    @staticmethod
    def score(model: dict[str, Any], vector: Sequence[float]) -> float:
        raw = float(model["baseline"])
        for tree in model["trees"]:
            node = 0
            while True:
                n = tree[node]
                if n["leaf"]:
                    raw += n["value"]
                    break
                x = vector[n["feature"]]
                node = (
                    n["left"]
                    if (x <= n["threshold"] if not math.isnan(x) else n["missing_left"])
                    else n["right"]
                )
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, raw))))


class Verdict:
    FLOOR_CONFIDENCE: ClassVar[frozenset[Confidence]] = frozenset(
        {Confidence.HIGH, Confidence.CONFIRMED}
    )
    RULE: ClassVar[str] = "SUSPECT.VERDICT.MODEL.001"

    @staticmethod
    def floored(finding: Finding, floor: frozenset[str] | None = None) -> bool:
        """Malicious on its own: never re-graded by anything the package says about itself.

        With a model, the floor is the rules it ships as never having fired on a benign unit of
        its training half (`bench/model/verdict_train.py`); a rule that did is the model's to weigh
        until its own precision is fixed. Without one, every MALWARE.* finding at high confidence.
        """
        if ".KNOWN" in finding.rule_id or finding.confidence not in Verdict.FLOOR_CONFIDENCE:
            return False
        if floor is not None:
            return finding.rule_id in floor
        return finding.rule_id.startswith("MALWARE.")

    @staticmethod
    def area(package: dict[str, float], manifests: dict[str, bytes], rules: dict[str, int]) -> str:
        """Which thresholds a package answers to: an agent skill, an MCP server, or a package.

        Benign skills, MCP servers and libraries carry different findings by nature -- a skill's
        instructions address the agent, a server's handlers run commands -- so each kind has its
        own line, set on its own benign sets (`bench/model/verdict_train.py`).
        """
        if package.get("skill"):
            return "skill"
        if any(rule.startswith("SUSPECT.MCP.") for rule in rules) or any(
            re.search(rb"@modelcontextprotocol/sdk|[\"']mcp(?:\[cli\])?[>=<~\"' ]|fastmcp", data)
            for data in manifests.values()
        ):
            return "mcp"
        return "package"

    @staticmethod
    def decide(
        findings: list[Finding],
        paths_sizes: Sequence[tuple[str, int]],
        manifests: dict[str, bytes],
        sources: Sequence[tuple[str, bytes]] = (),
    ) -> tuple[list[Finding], dict[str, Any]]:
        """Findings re-graded by the package verdict, and the verdict to report."""
        rules = VerdictFeatures.rules(findings)
        package = VerdictFeatures.package(paths_sizes, manifests, sources)
        summary: dict[str, Any] = {"rules": rules, "package": package}
        model = VerdictModel.load()
        if model is None or not rules:
            return findings, summary
        score = VerdictModel.score(model, VerdictModel.vector(model, rules, package))
        area = Verdict.area(package, manifests, rules)
        per_area = model["thresholds"].get("areas", {}).get(area)
        block, warn = (
            (float(per_area["block"]), float(per_area["warn"]))
            if per_area
            else (float(model["thresholds"]["block"]), float(model["thresholds"]["warn"]))
        )
        summary.update(
            score=round(score, 4),
            block=block,
            warn=warn,
            area=area,
            model=model.get("version", ""),
        )
        floor = frozenset(model["floor"]) if "floor" in model else None
        out: list[Finding] = []
        for finding in findings:
            code = VerdictFeatures.is_code(finding.rule_id) and ".KNOWN" not in finding.rule_id
            if not code or Verdict.floored(finding, floor) or score >= block:
                out.append(finding)
                continue
            if score < warn and finding.severity > Severity.LOW:
                finding = replace(
                    finding,
                    severity=Severity.LOW,
                    message=finding.message
                    + f" Recorded by the package verdict: {score:.2f} against a warning threshold "
                    f"of {warn:.2f}, from every finding in the package and what kind of package it is.",
                )
            elif finding.severity > Severity.MEDIUM and finding.category is not Category.MALICIOUS:
                finding = replace(
                    finding,
                    severity=Severity.MEDIUM,
                    message=finding.message
                    + f" Held at MEDIUM by the package verdict: {score:.2f} against a blocking "
                    f"threshold of {block:.2f}.",
                )
            out.append(finding)
        return out, summary
