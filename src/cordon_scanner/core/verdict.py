"""One decision for a scanned package: block or hold -- learned, with a floor it cannot move.

Each rule reports what it sees in one file. Whether a package should fail a build is a different
question, and answering it rule by rule meant any one of 1,400 rules could block alone: measured on
the 234,509-unit benign corpus, single findings blocked 1-7% of most ecosystems while a lot of real
malware also showed only one (review 98). What separates the two is the combination -- which rules,
how strong, where they fired, in what kind of package -- and that is learned on one half of the
data and measured on the other.

```
  findings ──► per rule / family / place / category: strongest severity and count ┐
  package  ──► size, files, hook, dependencies, what it claims and can do          ├─► trees
              (not the cosmetic facts an attacker adds for free: README, licence,  ┘     │
               tests, changelog, repository, description)                     p(malicious)
       │                                                                                 │
       ▼                                                                                 ▼
  floor: known-malware intel, and MALWARE.* rules that never fired on a benign unit,
         are never re-graded
  p >= block of its area (skill, MCP server, npm, PyPI, Open VSX, any other package)
         -> what trips the gate still blocks, and the verdict itself blocks
  p <  block -> every other code finding is held at MEDIUM, suspicious (a warning)
```

The trees are monotone in every finding: a stronger or an extra finding never lowers the score.
Each area's line is set so its own benign units are blocked at most at the shipped share, counted
against every unit of that ecosystem in the corpus (`bench/model/verdict_train.py`).

Without the model file nothing is re-graded; the features are still computed and reported, which is
how the training data is made by the same code that scores it.
"""

from __future__ import annotations

import array
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
    from collections.abc import Iterable, Sequence

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
    #: known-malicious release, an extension Microsoft removed from its Marketplace. They always
    #: stand, and they are never the model's evidence -- the verdict is about content.
    INTEL: ClassVar[tuple[str, ...]] = (".KNOWN", ".EXTENSION.REMOVED.")

    @staticmethod
    def is_intel(rule: str) -> bool:
        return any(marker in rule for marker in VerdictFeatures.INTEL)

    @staticmethod
    def is_code(rule: str) -> bool:
        return (
            rule.startswith(("MALWARE.", "SUSPECT."))
            and not rule.startswith(_INFRA)
            and not VerdictFeatures.is_intel(rule)
            and rule != VerdictFeatures.OWN_RULE
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

    @staticmethod
    def evidence(
        findings: Iterable[tuple[str, int, int, str, str]], package: dict[str, float]
    ) -> dict[str, float]:
        """What the model scores, from (rule, severity, confidence, category, path) per finding.

        For each rule, rule family, place and category: the strongest severity and how many times.
        Every one only rises with another or a stronger finding, which is what lets the trees be
        monotone in them. Then the package facts that are not cosmetic.
        """
        out: dict[str, float] = {}
        for rule, severity, confidence, category, path in findings:
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
        from cordon_scanner.intel.real import RealPackages

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


class VerdictModel:
    """Gradient-boosted trees shipped as data, evaluated here without a dependency.

    `detect/data/verdict.json.gz` (`bench/model/verdict_train.py`): the feature names in order, the
    trees, trees of its own for an area that needs them (`by_area`), a line per area, the floor,
    and a manifest of what it was trained and measured on.
    """

    FORMAT: ClassVar[int] = 2

    @staticmethod
    @functools.cache
    def load(path: Path = MODEL_PATH) -> dict[str, Any] | None:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                model = json.load(handle)
        except OSError:
            return None
        return model if model.get("format") == VerdictModel.FORMAT else None

    @staticmethod
    def score(model: dict[str, Any], features: dict[str, float]) -> float:
        # In single precision, as the trees were fitted: a value near a split would otherwise fall
        # on the other side of it.
        vector = array.array("f", [features.get(name, 0.0) for name in model["features"]])
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
    RULE: ClassVar[str] = VerdictFeatures.OWN_RULE
    #: The line every package without one of its own answers to: the strictest of them all.
    FALLBACK: ClassVar[str] = "package"
    _PYPI: ClassVar[re.Pattern[str]] = re.compile(r"^[^/]+/PKG-INFO$|^[^/]+\.dist-info/METADATA$")
    #: Each ecosystem's layout, read on the outermost archive only (a jar bundled in a Gradle
    #: repository is not a Maven release), measured on the benign corpus (2026-10-19). Release
    #: formats first: a gem's `metadata.gz`, a crate's `Cargo.toml.orig`, a nupkg's `.nuspec`, a
    #: jar's manifest, a Go module zip, a conda package's `info/`, a Hex tarball, an Ansible
    #: collection's `FILES.json`, an image export. Then project layouts, one directory deep at most.
    #: Benign code of each carries different findings by nature, so each answers to its own line.
    _ECOSYSTEMS: ClassVar[tuple[tuple[str, re.Pattern[str]], ...]] = tuple(
        (name, re.compile(layout))
        for name, layout in (
            ("rubygems", r"^metadata\.gz$"),
            ("crates", r"^[^/]+-\d[^/]*/Cargo\.toml\.orig$"),
            ("nuget", r"^[^/]+\.nuspec$"),
            ("maven", r"^META-INF/(?:MANIFEST\.MF$|maven/)"),
            ("go", r"^(?:[^/]+/)*[^/@]+@v\d[^/]*/"),
            ("conda", r"^info/index\.json$|^info-[^/]+\.tar\.zst$"),
            ("hex", r"^metadata\.config$"),
            ("galaxy", r"^FILES\.json$"),
            ("image", r"^image-config/|^sha256:[0-9a-f]{64}$|^blobs/sha256/"),
            ("packagist", r"^[^/]+/composer\.json$"),
            ("cran", r"^[^/]+/DESCRIPTION$"),
            ("pub", r"^(?:[^/]+/)?pubspec\.yaml$"),
            ("swift", r"^(?:[^/]+/)?Package\.swift$"),
            ("cocoapods", r"^(?:[^/]+/)?[^/]+\.podspec(?:\.json)?$"),
            ("hackage", r"^(?:[^/]+/)?[^/]+\.cabal$"),
            ("helm", r"^(?:[^/]+/)?Chart\.yaml$"),
            ("conan", r"^(?:[^/]+/)?conanfile\.py$"),
            ("vcpkg", r"^(?:[^/]+/)?(?:vcpkg\.json|portfile\.cmake)$"),
            ("opam", r"^(?:[^/]+/)?(?:[^/]+\.opam|opam|dune-project|_oasis|OMakeroot)$"),
            ("julia", r"^(?:[^/]+/)?(?:Julia)?Project\.toml$"),
            ("bazel", r"^(?:[^/]+/)?(?:MODULE\.bazel|WORKSPACE(?:\.bazel)?)$"),
            ("gradle", r"^(?:[^/]+/){0,2}(?:settings|build)\.gradle(?:\.kts)?$"),
            ("nix", r"^(?:[^/]+/)?(?:flake|default)\.nix$"),
            ("homebrew", r"^(?:[^/]+/)?(?:Formula|Casks)/(?:[^/]+/)*[^/]+\.rb$"),
            ("terraform", r"^(?:[^/]+/)?[^/]+\.tf$"),
        )
    )
    #: After skills: an npm tarball whose root folder is the package (`@types/*` use the name, not
    #: `package/`). Only a `.tgz` itself: a directory with a `package.json` in it is not a release.
    _NPM_NAMED_ROOT: ClassVar[re.Pattern[str]] = re.compile(r"^[^/]+/package\.json$")
    #: Last, after skills: nearly every repository has workflows.
    _ACTIONS: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:[^/]+/)?(?:action\.ya?ml|\.github/workflows/[^/]+\.ya?ml)$"
    )
    _MCP: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"@modelcontextprotocol/sdk|[\"']mcp(?:\[cli\])?[>=<~\"' ]|fastmcp"
    )

    @staticmethod
    def floored(finding: Finding, floor: frozenset[str]) -> bool:
        """Never re-graded: anything that is not a code finding, known-malware intel, and the rules
        the model ships as malicious on their own (they fired on no benign unit of its training
        half, `bench/model/verdict_train.py`)."""
        if not VerdictFeatures.is_code(finding.rule_id):
            return True
        return finding.rule_id in floor and finding.confidence in Verdict.FLOOR_CONFIDENCE

    @staticmethod
    def area(
        names: Sequence[str],
        manifests: dict[str, bytes],
        package: dict[str, float],
        rules: dict[str, int],
    ) -> str:
        """Which line a package answers to: an agent skill, an MCP server, a package of a registry
        recognised by its layout (npm, PyPI, Open VSX, `_ECOSYSTEMS`, `_ACTIONS`), or any other.

        Benign skills, MCP servers and libraries of each registry carry different findings by
        nature, so each has its own line, set on its own benign units. Anything not recognised
        answers to the strictest line, so a wrong guess can only make the verdict more cautious.
        """
        if any(rule.startswith("SUSPECT.MCP.") for rule in rules) or any(
            Verdict._MCP.search(data) for data in manifests.values()
        ):
            return "mcp"
        # A registry package that also ships a skill is still judged as a package of its registry.
        # The outermost archive only: what is bundled inside it is not what it is.
        inner = [parts[-1] for parts in (n.split("!") for n in names) if len(parts) <= 2]
        if any(n in ("extension.vsixmanifest", "extension/package.json") for n in inner):
            return "openvsx"
        if "package/package.json" in inner:
            return "npm"
        if any(Verdict._PYPI.match(n) for n in inner):
            return "pypi"
        for ecosystem, layout in Verdict._ECOSYSTEMS:
            if any(layout.match(n) for n in inner):
                return ecosystem
        if package.get("skill"):
            return "skill"
        if any(
            len(parts) == 2
            and parts[0].endswith(".tgz")
            and Verdict._NPM_NAMED_ROOT.match(parts[1])
            for parts in (n.split("!") for n in names)
        ):
            return "npm"
        if any(Verdict._ACTIONS.match(n) for n in inner):
            return "actions"
        return Verdict.FALLBACK

    @staticmethod
    def decide(
        findings: list[Finding],
        paths_sizes: Sequence[tuple[str, int]],
        manifests: dict[str, bytes],
        sources: Sequence[tuple[str, bytes]] = (),
        profile: dict[str, float] | None = None,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """Findings re-graded by the package verdict, and the verdict to report.

        `profile` is what the code that runs on its own can do (`Engine._capability_profile`),
        read as package facts beside the rest."""
        rules = VerdictFeatures.rules(findings)
        package = {**VerdictFeatures.package(paths_sizes, manifests, sources), **(profile or {})}
        if package.get("skill_front_matter"):
            # The skill's claim beside what its scripts can do (`VerdictFeatures._skill_claim`).
            reaches = {
                name[len("agent_can_") :]
                for name, v in package.items()
                if name.startswith("agent_can_") and v
            }
            package["skill_unclaimed_network"] = float(
                bool(reaches & {"egress", "network"}) and not package.get("skill_claims_network")
            )
            package["skill_unclaimed_credentials"] = float(
                "credential" in reaches and not package.get("skill_claims_credentials")
            )
            package["skill_unclaimed_process"] = float(
                bool(reaches & {"spawn", "execute", "runs_download"})
                and not package.get("skill_claims_shell")
            )
        area = Verdict.area([p for p, _ in paths_sizes], manifests, package, rules)
        summary: dict[str, Any] = {"rules": rules, "package": package, "area": area}
        model = VerdictModel.load()
        if model is None:
            return findings, summary
        # The second review (`intel/registry_record.py`): where the registry's record of this
        # release was acquired, its own trees score the package -- content-free malware has no
        # finding for the content verdict to weigh. It may add a block, never lift one.
        registry = model.get("registry")
        reviewed = (
            registry is not None and package.get("reg_known") and area in registry.get("areas", {})
        )
        if not rules and not reviewed:
            return findings, summary
        features = VerdictFeatures.evidence(
            (
                (f.rule_id, int(f.severity), int(f.confidence), str(f.category), f.location.path)
                for f in findings
            ),
            package,
        )
        if reviewed:
            summary.update(
                registry_score=round(VerdictModel.score(registry, features), 4),
                registry_block=float(registry["areas"][area]),
            )
        if not rules:
            return findings, summary
        if "scope" in model and area not in model["scope"]:
            # A model judges only the ecosystems it was trained and measured on; every other
            # package keeps its findings exactly as the rules graded them.
            return findings, summary
        # An area with trees of its own (agent skills read nothing like libraries) is scored by them.
        score = VerdictModel.score(model.get("by_area", {}).get(area, model), features)
        areas = model["areas"]
        block = float(areas.get(area, areas[Verdict.FALLBACK]))
        summary.update(score=round(score, 4), block=block, model=model.get("version", ""))
        # In an area the model does not yet separate as well as the findings alone, it may add a
        # block but never lift one: nothing that blocked without the verdict passes with it.
        if score >= block or area in model.get("add_only", ()):
            return findings, summary
        floor = frozenset(model["floor"])
        out: list[Finding] = []
        for finding in findings:
            if not Verdict.floored(finding, floor) and (
                finding.severity > Severity.MEDIUM or finding.category is Category.MALICIOUS
            ):
                finding = replace(
                    finding,
                    severity=min(finding.severity, Severity.MEDIUM),
                    category=Category.SUSPICIOUS,
                    message=finding.message
                    + f" Held as a warning by the package verdict: {score:.2f} against a blocking "
                    f"line of {block:.2f} for {area}, from every finding in the package and what "
                    "kind of package it is.",
                )
            out.append(finding)
        return out, summary
