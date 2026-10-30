"""The verdict model's features: what it reads of a scan's findings and its package facts,
built in one place. Here, below both the verdict and the feature schema, so the schema can read
the extractor and the verdict can stamp its records with the schema, without either importing
the other (review 27, F3)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.models import Confidence, Finding, Severity
from cordon_scanner.foundation.paths import PackagePaths

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

MODEL_PATH: Final = PackagePaths.data("detect") / "verdict.json.gz"

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

    #: Package facts an attacker adds for nothing -- a README, a licence, tests, a changelog, a
    #: repository link, a description, a plain version. Measured in review 98: a model that read
    #: them lost 2.4 points of malware when each sample was given them. They are reported, never
    #: scored, so they can neither block nor clear a package.
    COSMETIC: ClassVar[frozenset[str]] = frozenset(
        {
            "has_readme",
            "has_license",
            "has_tests",
            "has_changelog",
            "has_types",
            "has_repo",
            "desc_len",
            "min_files",
            "version_odd",
            "name_digits",
        }
    )
    #: Where a finding was made: an agent skill's instructions, other prose, a manifest, code.
    _PLACES: ClassVar[tuple[tuple[str, tuple[str, ...]], ...]] = (
        ("skilltext", ("skill.md",)),
        ("text", (".md", ".mdc", ".txt", ".rst")),
        ("manifest", ("package.json", "setup.py", "pyproject.toml", ".gemspec", "cargo.toml")),
    )
    #: The verdict's own finding, never its own evidence.
    OWN_RULE: ClassVar[str] = "SUSPECT.VERDICT.MODEL.001"

    #: Findings that are intelligence about a named package, not a reading of its content: a
    #: known-malicious release, an extension Microsoft removed from its Marketplace, a variant of a
    #: campaign the feed already condemned (`detect/supply/campaign_sibling.py`: a match against
    #: what was condemned before, not this package's code). They always stand, and they are never
    #: the model's evidence -- the verdict is about content.
    INTEL: ClassVar[tuple[str, ...]] = (".KNOWN", ".EXTENSION.REMOVED.", ".CAMPAIGN.SIBLING.")

    @staticmethod
    def is_intel(rule: str) -> bool:
        return any(marker in rule for marker in VerdictFeatures.INTEL)

    #: The intent layer's finding (`core/intent.py`) is added after the verdict and is never its
    #: evidence: the two weigh some of the same facts, and one must not recount the other.
    LATER_RULES: ClassVar[frozenset[str]] = frozenset({"SUSPECT.INTENT.UNEXPLAINED_EFFECT.001"})

    @staticmethod
    def is_code(rule: str) -> bool:
        return (
            rule.startswith(("MALWARE.", "SUSPECT."))
            and not rule.startswith(_INFRA)
            and not VerdictFeatures.is_intel(rule)
            and rule != VerdictFeatures.OWN_RULE
            and rule not in VerdictFeatures.LATER_RULES
        )

    @staticmethod
    def rules(findings: Sequence[Finding]) -> dict[str, int]:
        """Each code rule's strongest severity (0 info .. 4 critical); known-package intel excluded,
        so the verdict is about content."""
        best: dict[str, int] = {}
        for finding in findings:
            rule = finding.rule_id
            if VerdictFeatures.is_code(rule):
                best[rule] = max(best.get(rule, 0), int(finding.severity))
        return best

    @staticmethod
    def place(path: str) -> str:
        name = path.rpartition("!")[2].lower()
        for place, suffixes in VerdictFeatures._PLACES:
            if name.endswith(suffixes):
                return place
        return "code"

    #: Findings that mark where the scan could NOT read the code -- the analysis-COVERAGE axis
    #: (review 98 P8 (b)). They are counted even though they are not code findings: a verdict made
    #: over low coverage is "unknown", and an "unknown" on a bar-1 sample is a miss, not a catch.
    #: (failed deobfuscation and unresolved dynamic require/import are added when their detectors
    #: report a finding; minified-byte concentration is already `pkg:max_code_share`/`pkg:has_map`.)
    COVERAGE_RULES: ClassVar[dict[str, str]] = {
        "OPERATIONAL.FILE.TRUNCATED": "capped",
        "OPERATIONAL.FILE.TIMEOUT": "capped",
        "SUSPECT.INSTALL.UNEXAMINED.001": "unexamined",
        "SUSPECT.BINARY.NATIVE_IN_PURE_WHEEL.001": "native_run",
    }

    @staticmethod
    def evidence(
        findings: Iterable[tuple[str, int, int, str, str]], package: dict[str, float]
    ) -> dict[str, float]:
        """What the model scores, from (rule, severity, confidence, category, path) per finding.

        For each rule, rule family, place and category: the strongest severity and how many times.
        Every one only rises with another or a stronger finding, which is what lets the trees be
        monotone in them. Then the package facts that are not cosmetic, and the coverage axis.
        """
        out: dict[str, float] = {}
        for rule, severity, confidence, category, path in findings:
            cover = VerdictFeatures.COVERAGE_RULES.get(rule)
            if cover is not None:
                out[f"cov:{cover}"] = out.get(f"cov:{cover}", 0.0) + 1.0
                out["cov"] = out.get("cov", 0.0) + 1.0
            if not VerdictFeatures.is_code(rule):
                continue
            family = ".".join(rule.split(".")[:2])
            for key in (
                f"r:{rule}",
                f"fam:{family}",
                f"w:{VerdictFeatures.place(path)}",
                f"cat:{category}",
            ):
                out[key] = max(out.get(key, 0.0), float(severity))
                out[key + "#n"] = out.get(key + "#n", 0.0) + 1.0
            out["max"] = max(out.get("max", 0.0), float(severity))
            if severity >= int(Severity.HIGH) and confidence >= int(Confidence.MEDIUM):
                out["gate"] = out.get("gate", 0.0) + 1.0
        for name, value in package.items():
            if name not in VerdictFeatures.COSMETIC and isinstance(value, int | float):
                out[f"pkg:{name}"] = float(value)
        return out

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
                    manifest = ScannedJson.loads(data)
                except (ValueError, RecursionError):
                    # Malformed, or nested past ScannedJson's limit: no features from it. Read
                    # here outside any detector's isolation, a RecursionError once ended the whole
                    # scan, exit 2; the manifest's own readers report it.
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
                VerdictFeatures._dependencies_used(features, manifest, sources)
                break
            if base.endswith("setup.py"):
                features["hook"] = max(
                    features["hook"],
                    float(
                        bool(re.search(rb"cmdclass|class \w+\((?:install|develop|egg_info)", data))
                    ),
                )
        VerdictFeatures._ability(features, sources)
        VerdictFeatures._skill_claim(features, manifests)
        return features

    #: What a skill's own description says it reaches: the claims an attacker would have to make
    #: to explain its scripts, and that an honest skill makes because it needs them.
    SKILL_CLAIM: ClassVar[dict[str, re.Pattern[str]]] = {
        name: re.compile(pattern, re.IGNORECASE)
        for name, pattern in {
            "network": r"\b(?:api|http|web|url|download|upload|fetch|online|search|browse|"
            r"webhook|slack|github|notion|google|cloud|server|service|remote|sync)\b",
            "credentials": r"\b(?:token|key|secret|credential|password|auth|oauth|login|"
            r"wallet|keychain|ssh|vault)\b",
            "shell": r"\b(?:shell|terminal|command|install|deploy|docker|kubectl|git|run|"
            r"execute|script|process|system|automation)\b",
            "files": r"\b(?:file|folder|directory|document|pdf|csv|excel|image|disk|backup)\b",
        }.items()
    }
    _FRONT_FIELD: ClassVar[re.Pattern[str]] = re.compile(
        r"^(name|description)\s*:\s*(.+?)\s*$", re.MULTILINE
    )

    @staticmethod
    def _skill_claim(features: dict[str, float], manifests: dict[str, bytes]) -> None:
        """What a skill says it does, beside what its scripts can do (review 98, `13` STEP 2b).

        A skill's front matter is the claim its user approves; its scripts are what runs. A
        description-behaviour mismatch is published as weak on its own (ATR-2026-00061, 52.58%
        false positives), so these are facts the verdict weighs, never a verdict: what the
        description claims, how much it says, and the plain claim beside scripts that reach
        secrets, a process or the network (`agent_can_*` from the capability profile).
        """
        skills = [
            data
            for path, data in manifests.items()
            if path.rsplit("!", 1)[-1].rsplit("/", 1)[-1] == "SKILL.md"
            and path.rsplit("!", 1)[-1].count("/") <= 3
        ]
        if not skills:
            return
        text = min(skills, key=len)[:20_000].decode("utf-8", "replace")
        front = text.split("---", 2)[1] if text.startswith("---") and text.count("---") >= 2 else ""
        fields = {
            k.lower(): v.strip("'\" ") for k, v in VerdictFeatures._FRONT_FIELD.findall(front)
        }
        description = fields.get("description", "")
        claim = f"{fields.get('name', '')} {description}".replace("-", " ").replace("_", " ")
        features["skill_front_matter"] = float(bool(front))
        features["skill_desc_len"] = float(min(len(description), 600))
        for name, pattern in VerdictFeatures.SKILL_CLAIM.items():
            features[f"skill_claims_{name}"] = float(bool(pattern.search(claim)))
        for name, pattern in VerdictFeatures.PURPOSE.items():
            features[f"purpose_{name}"] = max(
                features.get(f"purpose_{name}", 0.0), float(bool(pattern.search(claim[:2000])))
            )

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

    #: A module name in quotes: what `require`, `import` and a bundler's map name a dependency by.
    _QUOTED_MODULE: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"[\"'`]((?:@[\w.-]{1,80}/)?[\w.-]{1,120})(?:/[^\"'`\s]{0,200})?[\"'`]"
    )

    @staticmethod
    def _dependencies_used(
        features: dict[str, float], manifest: dict[str, Any], sources: Sequence[tuple[str, bytes]]
    ) -> None:
        """Runtime dependencies the package's own code never names, and those that are not
        established packages either.

        A compromised release can carry nothing but one new dependency whose install hook is the
        payload (axios 1.14.1, March 2026; the PhantomRaven packages): the package's own content
        is clean, and the one trace is a dependency nothing in it uses. Type packages are left out:
        they are named by no code.
        """
        from cordon_scanner.intel.registries.real import RealPackages

        deps = manifest.get("dependencies") or {}
        if not isinstance(deps, dict):
            deps = {}
        wanted = {str(d) for d in deps if not str(d).startswith("@types/")}
        named: set[str] = set()
        scripts = manifest.get("scripts") or {}
        for value in scripts.values() if isinstance(scripts, dict) else ():
            named.update(w for w in re.split(r"[\s;&|()]+", str(value)) if w in wanted)
        for path, data in sources:
            if "node_modules/" in path or len(named) == len(wanted):
                continue
            for m in VerdictFeatures._QUOTED_MODULE.finditer(data[:2_000_000]):
                name = m.group(1).decode("utf-8", "replace")
                if name in wanted:
                    named.add(name)
        unused = wanted - named
        known = RealPackages.real_packages("npm")
        features["deps_unused"] = float(min(len(unused), 20))
        features["deps_unused_unknown"] = float(min(sum(d not in known for d in unused), 20))
        features["deps_unknown"] = float(min(sum(d not in known for d in wanted), 20))

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


__all__ = ["VerdictFeatures"]
