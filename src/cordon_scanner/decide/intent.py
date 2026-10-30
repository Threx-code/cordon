"""Intent: is every effect a package has on the machine explained by what it says it is, and by the
user asking for it? (review 98, `19-INTENT-ANALYSIS.md`)

A rule asks whether code contains a pattern; an attacker answers by writing the pattern another
way. Spellings, splits and obfuscation change how code is written, not what it does, when it runs,
or what the package claims to be. This layer reads those, from content alone:

```
  scan ──► facts (content only, allowlisted: E6)            weights (`detect/data/intent.json.gz`,
            verdict facts       install_can_egress, hook...  measured on study half A only: M2)
            trigger   t:<when>:<effect>   install | import       │ rows: benign rate, family-weighted
                                          | export | bin | test  │ malware rate, Wilson bounds,
                                          | unreached            │ conservative ratio (M1), cost
            concealment  conceal:<kind>   computed names, loader │ class (M6), group (E1), kept
            gates        gate:<kind>      env / time checks      │ under cross-validation (M8)
            purpose mismatch  m:<when>:<effect>  ◄── envelopes ──┤ purpose envelopes (benign npm)
                 │                                               │ threshold: benign 95% upper
                 ▼                                               ▼ bound <= 0.5% (T5)
  per group: its strongest present row (E1) ── sum of log weights, cosmetic total capped (M6)
                 │
     score >= threshold ──► SUSPECT.INTENT.UNEXPLAINED_EFFECT.001 (high, never critical), listing
                            every contributing fact, its weight and cost class (M4)
     a running file not read ──► verdict.intent "unknown" with its cause, never a pass (E5)
```

It runs after the rules and the package verdict and only adds a finding: it never lowers, holds
or removes one (E4), and rule outcomes are never its facts (M7). Without a weights file, or for a
package of an ecosystem the weights were not measured on (M3), the facts are still computed and
reported under the verdict's `intent` key -- which is how the training data is made by the same
code that scores it -- and nothing is decided.

What it does not claim: that no attack passes. Passing requires an effect that looks necessary for
the stated purpose, runs only when the user asks, and is not hidden. Known limits (A1, A5, A6,
A8): downloaders whose job is fetching code, payloads in a dependency or a later release, payloads
as remote data steering benign code, and offline probing of an open scanner.
"""

from __future__ import annotations

import bisect
import functools
import gzip
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.foundation.formats.scanned_json import ScannedJson
from cordon_scanner.foundation.paths import PackagePaths

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from cordon_scanner.detect.base import FileUnit, ScanContext

MODEL_PATH: Final = PackagePaths.data("detect") / "intent.json.gz"
RULE: Final = "SUSPECT.INTENT.UNEXPLAINED_EFFECT.001"


class IntentFacts:
    """The fact model: which facts exist, what each costs to fake, and which group it is in."""

    #: Bumped whenever a fact is computed differently: a weights file measured on other facts is
    #: not applied (S3). The weights file records it beside the scanner commit.
    VERSION: ClassVar[int] = 2

    #: Effects, each in the group a correlated other is in (E1): an install script that reaches the
    #: network by `https.get` and by `fetch` has one network effect, not two.
    EFFECT_GROUP: ClassVar[dict[str, str]] = {
        "egress": "network",
        "fetch_exec": "network",
        "runs_download": "network",
        "spawn": "process",
        "execute": "process",
        "credential": "secrets",
        "wallet": "secrets",
        "reconnaissance": "recon",
        "decode": "decode",
        "decompress": "decode",
        "deserialize": "decode",
        "dynamic_dispatch": "dynamic",
        "flow": "flow",
        "persist": "persist",
        "destroy": "destroy",
        "mine": "mine",
        "agent": "agent",
        "anti_analysis": "evasion",
        "delay": "evasion",
        "targeting": "evasion",
    }
    #: When an effect runs (19, step 2.1). `install` and `import` run unasked (the top level of
    #: what an install or a `require` loads); `export` is behind a function of an imported file,
    #: run when the user calls it; `bin` runs when the user runs the command; `test` is test code;
    #: `unreached` is code nothing runs on its own: a function of install code nothing calls, a
    #: shipped file nothing loads.
    TRIGGERS: ClassVar[tuple[str, ...]] = (
        "install",
        "import",
        "export",
        "bin",
        "test",
        "unreached",
    )
    #: Triggers that run without the user asking for the effect.
    UNASKED: ClassVar[frozenset[str]] = frozenset({"install", "import"})
    #: Cost classes (M6). An effect is what the code does: removing it removes the attack. A
    #: structural fact is how the code is arranged. A claim is what the package says it is. A
    #: cosmetic fact is packaging anyone adds in a minute.
    COSTS: ClassVar[tuple[str, ...]] = ("effect", "structural", "claim", "cosmetic")
    #: Provenance (E6): every fact the allowlist admits is computed from the package's content.
    CONTENT: ClassVar[str] = "content"
    PURPOSES: ClassVar[tuple[str, ...]] = (
        "math",
        "text",
        "ui",
        "time",
        "log",
        "test",
        "build",
        "http",
        "cli",
        "crypto",
        "ai",
    )
    #: What the verdict's whole-package patterns name (`VerdictFeatures.ABILITY`).
    ABILITIES: ClassVar[frozenset[str]] = frozenset(
        {
            "network",
            "process",
            "env",
            "recon",
            "secret_paths",
            "wallet_keys",
            "decode",
            "dynamic",
            "exfil_host",
            "raw_ip",
        }
    )
    COSMETIC: ClassVar[frozenset[str]] = frozenset(
        {
            "has_readme",
            "has_license",
            "has_types",
            "has_tests",
            "has_changelog",
            "has_map",
            "has_repo",
            "min_files",
            "version_odd",
            "name_digits",
            "agent_text",
        }
    )
    #: Facts from outside the package's content never weigh here (E6): what the registry recorded,
    #: intelligence, the publisher, the scanner's own log size (a measurement artefact the first
    #: matrix caught, ratio 215), and dependency facts read against the bundled list of real
    #: packages. Rejected before the allowlist is consulted, so no future fact of these families
    #: can enter by matching a pattern below.
    EXTERNAL: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:reg_|intel|known|advisory|publisher|registry|log_bytes|deps_unknown|deps_unused_unknown)"
    )
    #: Counts read as facts at fixed cuts: `<=` for the cosmetic sizes, `>=` for breadth.
    AT_MOST: ClassVar[dict[str, tuple[float, ...]]] = {
        "n_files": (1, 3, 10),
        "n_code": (0, 1, 3),
        "n_deps": (0, 3),
        "desc_len": (0, 20),
    }
    AT_LEAST: ClassVar[dict[str, tuple[float, ...]]] = {
        "install_capabilities": (2, 4),
        "import_capabilities": (2, 4),
        "agent_capabilities": (2, 4),
        "code_share": (0.1, 0.5, 0.9),
        "max_code_share": (0.5, 0.9),
        "deps_unused": (1,),
    }
    #: Kinds of concealment (`IntentObserver._concealment`).
    CONCEALMENT: ClassVar[tuple[str, ...]] = (
        "loader",
        "computed_require",
        "computed_call",
        "charcode",
        "obfuscator_names",
    )
    GATES: ClassVar[tuple[str, ...]] = ("env", "time")

    _CUT: ClassVar[re.Pattern[str]] = re.compile(r"^(?P<base>[a-z_]+)(?P<op><=|>=)(?P<cut>[\d.]+)$")

    @staticmethod
    @functools.cache
    def classify(name: str) -> tuple[str, str] | None:
        """`(cost class, group)` of a fact Cordon may weigh, or None: the allowlist (E6, M7).

        A name not described here is not a fact. Rule ids never are: the layer adds evidence
        beside the rules, it does not recount them.
        """
        if IntentFacts.EXTERNAL.match(name):
            return None
        groups = IntentFacts.EFFECT_GROUP
        kind, _, rest = name.partition(":")
        if kind in ("t", "m"):
            trigger, _, effect = rest.partition(":")
            if trigger in IntentFacts.TRIGGERS and effect in groups:
                return "effect", f"{trigger}:{groups[effect]}"
            return None
        if kind == "conceal" and rest.partition(":")[0] in IntentFacts.CONCEALMENT:
            return "structural", "conceal"
        if kind == "gate" and rest in IntentFacts.GATES:
            return "structural", "gate"
        if ":" in name:
            return None
        cut = IntentFacts._CUT.match(name)
        if cut is not None:
            base, op = cut["base"], cut["op"]
            cuts = (IntentFacts.AT_MOST if op == "<=" else IntentFacts.AT_LEAST).get(base, ())
            if float(cut["cut"]) not in cuts:
                return None
            if op == "<=":
                return "cosmetic", f"cosmetic:{base}"
            place = base.partition("_")[0]
            if base.endswith("_capabilities"):
                return "effect", f"{place}:breadth"
            if base == "deps_unused":
                return "structural", "structure:deps"
            return "structural", "structure:share"
        for place in ("install", "import", "agent"):
            effect = name.removeprefix(f"{place}_can_")
            if effect != name:
                return ("effect", f"{place}:{groups[effect]}") if effect in groups else None
        if name.startswith("can_") and name[4:] in IntentFacts.ABILITIES:
            return "effect", f"any:{name[4:]}"
        if name in ("plain_with_sensitive", "plain_with_process_net"):
            return "effect", "any:plain"
        if name == "hook":
            return "effect", "install:hook"
        if name.startswith("skill_unclaimed_"):
            return "effect", "agent:unclaimed"
        if name.startswith("purpose_") and name[8:] in IntentFacts.PURPOSES:
            return "claim", "claim:purpose"
        if name.startswith("skill_claims_"):
            return "claim", "claim:skill"
        if name in IntentFacts.COSMETIC:
            return "cosmetic", f"cosmetic:{name}"
        return None

    @staticmethod
    def provenance(name: str) -> str:
        """`content` for a fact computed from the package's content, `external` for anything else:
        the registry, intelligence, the scanner's own logs, a rule's outcome (E6, M7)."""
        return IntentFacts.CONTENT if IntentFacts.classify(name) is not None else "external"

    @staticmethod
    def base(package: dict[str, Any]) -> set[str]:
        """The verdict's package facts (`VerdictFeatures.package`, the capability profile) as the
        present facts the allowlist admits: a flag when above zero, a count at its cuts."""
        out: set[str] = set()
        for name, value in package.items():
            if isinstance(value, bool) or not isinstance(value, int | float):
                continue
            if IntentFacts.EXTERNAL.match(name):
                continue
            for cut in IntentFacts.AT_MOST.get(name, ()):
                if value <= cut:
                    out.add(f"{name}<={IntentFacts._cut(cut)}")
            for cut in IntentFacts.AT_LEAST.get(name, ()):
                if value >= cut:
                    out.add(f"{name}>={IntentFacts._cut(cut)}")
            if value > 0 and name not in IntentFacts.AT_MOST and name not in IntentFacts.AT_LEAST:
                out.add(name)
        return {name for name in out if IntentFacts.classify(name) is not None}

    @staticmethod
    def _cut(cut: float) -> str:
        return str(int(cut)) if float(cut).is_integer() else str(cut)

    @staticmethod
    def admitted(facts: Iterable[str]) -> set[str]:
        """Only the facts the allowlist admits; anything else is dropped, whatever produced it."""
        return {name for name in facts if IntentFacts.provenance(name) == IntentFacts.CONTENT}

    @staticmethod
    def claimed(facts: Iterable[str]) -> list[str]:
        """The purposes a package claims, `none` when it claims none of them."""
        present = set(facts)
        return [p for p in IntentFacts.PURPOSES if f"purpose_{p}" in present] or ["none"]

    @staticmethod
    def mismatched(
        facts: Iterable[str], envelopes: dict[str, Any], limit: float, min_n: int
    ) -> set[str]:
        """Purpose mismatch: `m:<when>:<effect>` for each effect benign packages of every purpose
        this one claims rarely have -- the 95% upper bound of their rate under `limit` (A1/E9).

        The bound, not the rate: a purpose seen on few benign packages explains everything until
        it has been measured. A package claiming several purposes is explained by any of them. A
        purpose measured on fewer than `min_n` packages is not consulted; when none of the claimed
        ones is, the envelope of all benign packages stands in.
        """
        present = set(facts)
        claimed = IntentFacts.claimed(present)
        measured = [
            envelopes[p] for p in claimed if p in envelopes and envelopes[p].get("n", 0) >= min_n
        ]
        if not measured and "all" in envelopes:
            measured = [envelopes["all"]]
        if not measured:
            return set()
        out: set[str] = set()
        for name in present:
            if not name.startswith("t:") or name.split(":")[1] == "test":
                continue
            upper = max(float(e.get("upper", {}).get(name, e.get("zero", 1.0))) for e in measured)
            if upper < limit:
                out.add("m:" + name[2:])
        return out


@dataclass
class Observation:
    """What `IntentObserver` read: the new facts, and the running files it could not read (E5)."""

    facts: set[str] = field(default_factory=set)
    unexamined: list[str] = field(default_factory=list)
    files: int = 0


class IntentObserver:
    """The facts no rule computes: when each effect runs, concealment, and gates (19, step 2)."""

    #: Files above this are not read: the reach analysis (`JsFlow.deferred_spans`) stops there.
    MAX_BYTES: ClassVar[int] = 1_500_000
    #: Files labelled per package, running files first. The files that run on their own are a
    #: handful in any real package; a bundle of thousands is not read past this.
    MAX_FILES: ClassVar[int] = 120
    _CODE: ClassVar[tuple[str, ...]] = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".py", ".sh")
    _JS: ClassVar[tuple[str, ...]] = (".js", ".cjs", ".mjs")
    _TEST: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|/)(?:tests?|__tests__|specs?|__mocks__|fixtures?|examples?)/|\.(?:test|spec)\.[cm]?[jt]s$"
    )
    #: Ways to load a module without naming the loader: what `require` would do, reached through
    #: the module system's internals.
    _LOADER: ClassVar[re.Pattern[str]] = re.compile(
        r"module\s*\.\s*constructor\s*\.\s*_load|Module\s*\.\s*_load\s*\(|process\s*\.\s*mainModule"
        r"|process\s*\.\s*binding\s*\(|module\s*\.\s*require\s*\("
    )
    _ESCAPE: ClassVar[re.Pattern[str]] = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
    _OBFUSCATOR_NAME: ClassVar[re.Pattern[str]] = re.compile(r"\b_0x[0-9a-f]{4,}\b")
    #: A condition reading the machine or the environment the code runs in (E10).
    _GATE: ClassVar[dict[str, re.Pattern[str]]] = {
        "env": re.compile(
            r"process\s*\.\s*(?:env|platform|arch|getuid)\b|\b(?:platform|hostname|userInfo|homedir"
            r"|networkInterfaces|cpus|totalmem|release|type|arch)\s*\(\s*\)"
        ),
        "time": re.compile(
            r"\bDate\s*\.\s*(?:now|parse)\b|\bnew\s+Date\b|\.\s*get(?:Time|Hours|Day|Date|Month"
            r"|FullYear|UTCHours|UTCDay|UTCDate)\s*\(|performance\s*\.\s*now\b"
        ),
    }
    #: Per kilobyte, past which concealment is dense (`conceal:<kind>:dense`).
    _DENSE: ClassVar[dict[str, float]] = {"computed_call": 1.0, "charcode": 2.0}

    @staticmethod
    def applies(ctx: ScanContext) -> bool:
        """npm first (M3): every other ecosystem gets its facts once they are measured there."""
        return ctx.distribution == "npm"

    @staticmethod
    def member(path: str) -> str:
        return path.rpartition("!")[2]

    @staticmethod
    def entries(units: Sequence[FileUnit]) -> tuple[set[str], set[str]]:
        """`(imported, commands)`: the files `require()` loads first -- npm's `main` (or
        `index.js`) and `exports` targets -- and the files npm links as commands, which run when
        the user runs the command. `PackageEntries.of` holds both as one set."""
        manifest = next((u for u in units if u.path.endswith("!package/package.json")), None)
        if manifest is None:
            return set(), set()
        try:
            document = ScannedJson.loads(manifest.content.text)
        except (ValueError, RecursionError):  # malformed, or nested past ScannedJson's limit
            return set(), set()
        if not isinstance(document, dict):
            return set(), set()
        paths = {u.path for u in units}
        root = manifest.path[: -len("package.json")]

        def resolve(value: object) -> set[str]:
            found: set[str] = set()
            for target in ScannedJson.strings(value):
                if "*" not in target:
                    base = root + target.strip().removeprefix("./").rstrip("/")
                    found.update(c for c in (base, f"{base}.js", f"{base}/index.js") if c in paths)
            return found

        imported = resolve(document.get("main") or "index.js") | resolve(document.get("exports"))
        return imported, resolve(document.get("bin"))

    @staticmethod
    def observe(
        units: Sequence[FileUnit],
        ctx: ScanContext,
        label: Callable[[FileUnit], Iterable[tuple[str, int]] | None],
        closure: Callable[[set[str]], set[str]],
    ) -> Observation:
        """The trigger, concealment and gate facts of a package.

        `label(unit)` gives each effect the file has, as `(capability, byte offset)` (it may raise:
        that file is then unexamined); `closure(seeds)` is the first-party files the seeds load,
        whose top level runs when they do.
        """
        install = set(ctx.install_hook_paths | ctx.install_entry_paths)
        imported, bins = IntentObserver.entries(units)
        imported |= closure(imported)
        own = [
            u
            for u in units
            if "node_modules/" not in IntentObserver.member(u.path)
            and IntentObserver.member(u.path).lower().endswith(IntentObserver._CODE)
        ]

        def rank(u: FileUnit) -> tuple[int, str]:
            if u.path in install:
                return 0, u.path
            if u.path in imported:
                return 1, u.path
            if u.path in bins:
                return 2, u.path
            return (4 if IntentObserver._TEST.search(IntentObserver.member(u.path)) else 3), u.path

        out = Observation()
        for index, unit in enumerate(sorted(own, key=rank)):
            running = unit.path in install or unit.path in imported
            name = IntentObserver.member(unit.path)
            if index >= IntentObserver.MAX_FILES:
                if running:
                    out.unexamined.append(f"{name}: past the {IntentObserver.MAX_FILES}-file limit")
                continue
            content = unit.content
            if content.size > IntentObserver.MAX_BYTES or content.truncated or content.is_binary:
                if running:
                    why = (
                        "binary" if content.is_binary else f"{content.size:,} bytes, past the limit"
                    )
                    out.unexamined.append(f"{name}: {why}")
                continue
            try:
                effects = list(label(unit) or ())
            except Exception:  # a file not read is reported, never a scan failure  # noqa: BLE001
                if running:
                    out.unexamined.append(f"{name}: could not be analysed")
                continue
            out.files += 1
            roles = IntentObserver._roles(unit.path, name, install, imported, bins)
            text = content.text
            js = name.lower().endswith(IntentObserver._JS)
            spans = _Spans(IntentObserver._deferred(text) if js else [])
            offsets = [(cap, IntentObserver._char(content.raw, at)) for cap, at in effects]
            for cap, at in offsets:
                if cap not in IntentFacts.EFFECT_GROUP:
                    continue
                # Where a module is imported is not where it is used: the effect runs where its
                # binding does, so it is deferred only when every use is.
                places = (IntentObserver._uses(text, at) if js else None) or [at]
                deferred = all(
                    spans.covers(p)
                    or (
                        unit.path in install
                        and not ctx.install_hook_reaches(unit.path, text.count("\n", 0, p) + 1)
                    )
                    for p in places
                )
                for role in roles:
                    out.facts.add(f"t:{IntentObserver._trigger(role, deferred)}:{cap}")
            if running and js:
                out.facts |= IntentObserver._concealment(text)
                # The checks themselves (`anti_analysis`, `delay`, `targeting`) are not what
                # they guard.
                guarded = [
                    at
                    for cap, at in offsets
                    if IntentFacts.EFFECT_GROUP.get(cap, "evasion") != "evasion"
                ]
                out.facts |= IntentObserver._gates(text, guarded)
        return out

    _REQUIRE_SITE: ClassVar[re.Pattern[str]] = re.compile(r"(?:require|import)\s*\(")
    #: `const x = require(...)`, `let { a, b: c } = await import(...)`: ends where the import is.
    _BOUND_BEFORE: ClassVar[re.Pattern[str]] = re.compile(
        r"\b(?:const|let|var)\s+(?:(?P<name>[A-Za-z_$][\w$]*)|\{(?P<names>[^{}]{0,400})\})\s*="
        r"\s*(?:await\s+)?$"
    )
    #: `import x from 'm'`, `import * as x from 'm'`, `import x, { a, b as c } from 'm'`.
    _BOUND_AFTER: ClassVar[re.Pattern[str]] = re.compile(
        r"import\s+(?:\*\s*as\s+(?P<name>[A-Za-z_$][\w$]*)|(?P<default>[A-Za-z_$][\w$]*)?\s*,?\s*"
        r"(?:\{(?P<names>[^{}]{0,400})\})?)\s*from\b"
    )

    @staticmethod
    def _uses(text: str, at: int) -> list[int] | None:
        """Where the binding an import at `at` creates is used, or None when `at` is not a bound
        import (`require('x').get(...)` used where it stands, or no import at all)."""
        if IntentObserver._REQUIRE_SITE.match(text, at):
            bound = IntentObserver._BOUND_BEFORE.search(text, max(0, at - 600), at)
        else:
            bound = IntentObserver._BOUND_AFTER.match(text, at)
        if bound is None:
            return None
        found = bound.groupdict()
        names = [found[g] for g in ("name", "default") if found.get(g)]
        for part in (found.get("names") or "").split(","):
            local = part.split(":")[-1].split(" as ")[-1].split("=")[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", local):
                names.append(local)
        if not names:
            return None
        end = text.find("\n", at)
        pattern = re.compile(r"(?<![\w$.])(?:" + "|".join(map(re.escape, names)) + r")(?![\w$])")
        return [m.start() for m in pattern.finditer(text, end if end > 0 else len(text))][:200]

    @staticmethod
    def _deferred(text: str) -> list[tuple[int, int]]:
        from cordon_scanner.analysis.javascript.js_flow import JsFlow

        return JsFlow.deferred_spans(text) or []

    @staticmethod
    def _roles(
        path: str, name: str, install: set[str], imported: set[str], bins: set[str]
    ) -> list[str]:
        roles = [
            role
            for role, paths in (("install", install), ("import", imported), ("bin", bins))
            if path in paths
        ]
        if roles:
            return roles
        return ["test" if IntentObserver._TEST.search(name) else "unreached"]

    @staticmethod
    def _trigger(role: str, deferred: bool) -> str:
        if role == "install":
            return "unreached" if deferred else "install"
        if role == "import":
            return "export" if deferred else "import"
        return role

    @staticmethod
    def _char(raw: bytes, offset: int) -> int:
        """A byte offset into `raw` as an offset into its decoded text."""
        if offset <= 0:
            return 0
        if raw.isascii():
            return offset
        return len(raw[:offset].decode("utf-8", "replace"))

    @staticmethod
    def _concealment(text: str) -> set[str]:
        """Effort spent hiding names, against what the code needs (A3): a module loaded through
        the module system's internals, a `require` of a computed name, a member called by a
        computed or quoted name where a plain one would do, character codes and escapes spelling
        text, and obfuscator-generated identifiers. Counted per file, relative to its size."""
        from cordon_scanner.analysis.javascript.js_eval import JsEval

        tokens = JsEval.tokens(text)
        counts = dict.fromkeys(IntentFacts.CONCEALMENT, 0)
        counts["loader"] = len(IntentObserver._LOADER.findall(text))
        counts["obfuscator_names"] = len(set(IntentObserver._OBFUSCATOR_NAME.findall(text)))
        counts["charcode"] = len(IntentObserver._ESCAPE.findall(text))
        n = len(tokens)

        def punct(i: int, value: str) -> bool:
            return 0 <= i < n and tokens[i].kind == "punct" and tokens[i].value == value

        for i, tok in enumerate(tokens):
            if tok.kind == "name":
                if tok.value == "fromCharCode":
                    counts["charcode"] += 1
                elif (
                    tok.value in ("require", "import")
                    and punct(i + 1, "(")
                    and not punct(i - 1, ".")
                    and not (i + 3 < n and tokens[i + 2].kind == "str" and punct(i + 3, ")"))
                    and not (i + 3 < n and tokens[i + 2].kind == "tmpl" and punct(i + 3, ")"))
                ):
                    counts["computed_require"] += 1
            elif (
                punct(i, "]")
                and punct(i + 1, "(")
                and i >= 2
                and not (tokens[i - 1].kind == "num" and punct(i - 2, "["))
            ):
                # `x[k](...)`: a member called by a name computed or spelled as a string.
                counts["computed_call"] += 1
        kilobytes = max(len(text) / 1024, 1.0)
        out: set[str] = set()
        for kind, count in counts.items():
            if count <= 0:
                continue
            out.add(f"conceal:{kind}")
            dense = IntentObserver._DENSE.get(kind)
            if dense is not None and count / kilobytes >= dense:
                out.add(f"conceal:{kind}:dense")
        return {f for f in out if IntentFacts.classify(f) is not None}

    @staticmethod
    def _gates(text: str, effects: Sequence[int]) -> set[str]:
        """A check of the environment or the clock deciding whether an effect runs (E10): the
        effect inside an `if` reading it, or in a file an `if` reading it returns or exits from."""
        if not effects:
            return set()
        from cordon_scanner.analysis.javascript.js_eval import JsEval

        tokens = JsEval.tokens(text)
        n = len(tokens)
        match = [-1] * n
        stack: list[int] = []
        for i, tok in enumerate(tokens):
            if tok.kind == "punct" and tok.value in ("(", "[", "{"):
                stack.append(i)
            elif tok.kind == "punct" and tok.value in (")", "]", "}") and stack:
                j = stack.pop()
                match[i], match[j] = j, i
        ordered = sorted(effects)
        out: set[str] = set()
        for i, tok in enumerate(tokens):
            if not (tok.kind == "name" and tok.value == "if" and i + 1 < n and match[i + 1] > i):
                continue
            close = match[i + 1]
            condition = text[tokens[i + 1].start : tokens[close].end]
            kinds = [k for k, pattern in IntentObserver._GATE.items() if pattern.search(condition)]
            if not kinds:
                continue
            body = close + 1
            if body >= n:
                continue
            if tokens[body].kind == "punct" and tokens[body].value == "{" and match[body] > body:
                end = match[body]
            else:
                end = body
                while end < n and not (tokens[end].kind == "punct" and tokens[end].value == ";"):
                    if tokens[end].kind == "punct" and tokens[end].value in ("(", "[", "{"):
                        end = max(match[end], end)
                    end += 1
                end = min(end, n - 1)
            start_at, end_at = tokens[body].start, tokens[end].end
            inside = bisect.bisect_left(ordered, start_at) < bisect.bisect_right(ordered, end_at)
            exits = any(
                tokens[k].kind == "name" and tokens[k].value in ("return", "throw", "exit")
                for k in range(body, min(end + 1, body + 40, n))
            )
            # A check that returns or exits decides whether the rest of the file runs: every effect
            # of the file is behind it, wherever its module was required.
            if inside or exits:
                out.update(f"gate:{k}" for k in kinds)
        return out


class _Spans:
    """Possibly nested character spans: whether an offset falls in any of them."""

    def __init__(self, spans: Sequence[tuple[int, int]]) -> None:
        ordered = sorted(spans)
        self.starts = [a for a, _ in ordered]
        # The furthest end among the spans starting at or before each one: an offset is covered
        # exactly when some span starting at or before it ends after it.
        self.reach: list[int] = []
        best = -1
        for _, b in ordered:
            best = max(best, b)
            self.reach.append(best)

    def covers(self, at: int) -> bool:
        i = bisect.bisect_right(self.starts, at)
        return i > 0 and self.reach[i - 1] > at


class IntentWeights:
    """The weights file: data, versioned, shipped like `verdict.json.gz` (19, step 3).

    `bench/model/intent_build.py` writes it from study data only (half A). The loader refuses any
    file a rule of the design does not hold for, so a bad build leaves the layer inert rather than
    deciding on unmeasured weights.
    """

    FORMAT: ClassVar[int] = 1
    #: Rows need this many malware families (E2).
    MIN_FAMILIES: ClassVar[int] = 5
    #: No row weighs more than this ratio, however rare its fact is in benign code (E2).
    CAP: ClassVar[float] = 50.0
    #: The benign block rate the threshold may have, as a 95% upper bound (T5).
    BENIGN_BAR: ClassVar[float] = 0.005

    @staticmethod
    @functools.cache
    def load(path: Path = MODEL_PATH) -> dict[str, Any] | None:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                model = json.load(handle)
        except (OSError, ValueError):
            return None
        return model if not IntentWeights.problems(model) else None

    @staticmethod
    def problems(model: Any) -> list[str]:
        """Every way the file breaks the design's rules; empty when it may be applied."""
        if not isinstance(model, dict):
            return ["not an object"]
        out: list[str] = []
        if model.get("format") != IntentWeights.FORMAT:
            out.append(f"format {model.get('format')!r} is not {IntentWeights.FORMAT}")
        if model.get("facts_version") != IntentFacts.VERSION:
            out.append(
                f"facts version {model.get('facts_version')!r} is not {IntentFacts.VERSION} (S3)"
            )
        for key in ("scanner_commit", "dataset", "date", "version"):
            if not model.get(key):
                out.append(f"no {key} (S3/E8)")
        scope = model.get("scope")
        if not isinstance(scope, list) or not scope:
            out.append("no scope (M3)")
        threshold = model.get("threshold")
        cheap_cap = model.get("cheap_cap")
        if not isinstance(threshold, int | float) or threshold <= 0:
            out.append("no positive threshold")
        elif not isinstance(cheap_cap, int | float) or not 0 <= cheap_cap < threshold:
            out.append("cosmetic cap must be under the threshold: cosmetic never blocks alone (M6)")
        benign = model.get("threshold_benign") or {}
        if (
            not isinstance(benign.get("upper"), int | float)
            or benign["upper"] > IntentWeights.BENIGN_BAR
        ):
            out.append("threshold's benign 95% upper bound not at most 0.5% (T5)")
        rows = model.get("rows")
        if not isinstance(rows, dict):
            return [*out, "no rows"]
        cap = math.log(IntentWeights.CAP)
        for name, row in rows.items():
            known = IntentFacts.classify(name)
            if known is None:
                out.append(f"{name}: not an admitted content fact (E6/M7)")
                continue
            if not isinstance(row, dict):
                out.append(f"{name}: not a row")
                continue
            if (row.get("cost"), row.get("group")) != known:
                out.append(f"{name}: cost class or group is not {known}")
            if row.get("provenance") != IntentFacts.CONTENT:
                out.append(f"{name}: provenance is not content (E6)")
            if int(row.get("families", 0)) < IntentWeights.MIN_FAMILIES:
                out.append(f"{name}: fewer than {IntentWeights.MIN_FAMILIES} families (E2)")
            weight, ratio = row.get("weight"), row.get("ratio")
            if not isinstance(weight, int | float) or not 0 < weight <= cap + 1e-9:
                out.append(f"{name}: weight outside (0, ln {IntentWeights.CAP:g}] (M1/E2)")
            elif not isinstance(ratio, int | float) or ratio <= 1:
                out.append(f"{name}: conservative ratio not above 1 (M1)")
            elif abs(weight - math.log(min(IntentWeights.CAP, ratio))) > 1e-6:
                out.append(f"{name}: weight is not the log of its conservative ratio (M1)")
            if not row.get("kept"):
                out.append(f"{name}: not kept under cross-validation (M8)")
        envelopes = model.get("envelopes")
        if not isinstance(envelopes, dict):
            out.append("no purpose envelopes")
        return out


@dataclass(frozen=True)
class Contribution:
    fact: str
    weight: float
    cost: str
    group: str


class IntentScore:
    """The combiner (19, step 4)."""

    @staticmethod
    def contributions(facts: Iterable[str], model: dict[str, Any]) -> list[Contribution]:
        """Each group's strongest present row (E1), strongest first, ties by name."""
        rows = model["rows"]
        best: dict[str, Contribution] = {}
        for name in sorted(set(facts)):
            row = rows.get(name)
            if row is None:
                continue
            c = Contribution(name, float(row["weight"]), row["cost"], row["group"])
            held = best.get(c.group)
            if held is None or c.weight > held.weight:
                best[c.group] = c
        return sorted(best.values(), key=lambda c: (-c.weight, c.fact))

    @staticmethod
    def score(contributions: Sequence[Contribution], model: dict[str, Any]) -> float:
        """The sum of log weights, the cosmetic facts' total capped (M6)."""
        cosmetic = sum(c.weight for c in contributions if c.cost == "cosmetic")
        rest = sum(c.weight for c in contributions if c.cost != "cosmetic")
        return rest + min(cosmetic, float(model["cheap_cap"]))

    @staticmethod
    def crosses(score: float, model: dict[str, Any]) -> bool:
        """At or over the threshold. Cosmetic facts never cross alone: the loader holds their cap
        under the threshold (M6)."""
        return score >= float(model["threshold"])


class Intent:
    """The layer: facts, the weights, the decision, and what the verdict reports."""

    @staticmethod
    def review(
        package: dict[str, Any], area: str, observation: Observation | None
    ) -> dict[str, Any] | None:
        """The verdict's `intent` entry; None when the layer does not apply to this package.

        `decision` is `block` (over the threshold), `unknown` (a running file was not read and
        what was read does not cross: E5; its cause is under `unexamined`), or absent. Deterministic: sorted facts, a fixed order of
        contributions, rounded scores.
        """
        if observation is None:
            return None
        facts = IntentFacts.base(package) | IntentFacts.admitted(observation.facts)
        summary: dict[str, Any] = {
            "facts_version": IntentFacts.VERSION,
            "facts": sorted(facts),
            "files": observation.files,
        }
        if observation.unexamined:
            summary["unexamined"] = sorted(observation.unexamined)[:20]
        model = IntentWeights.load()
        if model is None or area not in model["scope"]:
            return summary
        derived = IntentFacts.mismatched(
            facts,
            model["envelopes"],
            float(model.get("mismatch_limit", 0.01)),
            int(model.get("envelope_min_n", 50)),
        )
        contributions = IntentScore.contributions(facts | derived, model)
        score = IntentScore.score(contributions, model)
        summary.update(
            weights=model["version"],
            mismatch=sorted(derived),
            score=round(score, 4),
            threshold=float(model["threshold"]),
            contributions=[
                {"fact": c.fact, "weight": round(c.weight, 4), "cost": c.cost}
                for c in contributions
            ],
        )
        if IntentScore.crosses(score, model):
            summary["decision"] = "block"
        elif observation.unexamined:
            summary["decision"] = "unknown"
        return summary

    @staticmethod
    def message(summary: dict[str, Any], area: str) -> str:
        listed = "; ".join(
            f"{c['fact']} ({c['cost']}, {c['weight']:.2f})" for c in summary["contributions"]
        )
        return (
            f"This package's effects are not explained by what it says it is or by its user asking "
            f"for them: the facts below score {summary['score']:.2f} against the line of "
            f"{summary['threshold']:.2f} measured for {area} (weights {summary['weights']}). "
            f"Contributing, with cost class and log weight: {listed}."
        )
