#!/usr/bin/env python3
"""Measure the false-positive rate against real third-party code.

The test that decides whether this product works, and the only one a corpus
cannot stand in for. A corpus sample is written alongside the rule it exercises
and tends to be shaped the way that rule expects, so it shows a rule CAN fire
rather than that it fires on the right things. Code nobody here wrote is the only
honest input.

    python3 scripts/measure_noise.py                 # every repository
    python3 scripts/measure_noise.py --language go rust
    python3 scripts/measure_noise.py --limit 10
    python3 scripts/measure_noise.py --report out.json

One repository on disk at a time: shallow clone, scan, record, delete. A hundred
projects would otherwise be tens of gigabytes, and the whole point is to be able
to run this routinely rather than once.

## What it does and does not claim

It reports what cordon says about each repository. It cannot tell a false positive
from a true one -- `MALWARE.EXFIL.001` in a penetration-testing tool is correct --
so the output is a triage worksheet, not a verdict. What makes it useful is the
shape of the distribution: a rule firing on forty unrelated projects is a rule
that is wrong, whatever any individual case looks like, and that is visible here
and nowhere else.

`--baseline` writes the current per-rule counts, and a later run compares against
them, so a change that adds noise somewhere nobody was looking shows up as a
number going the wrong way.

## Choosing the repositories

Widely used, actively maintained, and spread across every ecosystem cordon
supports -- including the six where today nothing has ever been measured, which is
the gap this exists to close. Deliberately NOT a list of projects chosen because
they scan cleanly: several here are security tools, and a security tool's own
signature file is the canonical false positive for the obfuscation rules.

Size matters as much as breadth. A rule that is quiet on a thousand-file project
and noisy on a hundred-thousand-file monorepo is noisy, and only the second kind
of repository shows it.
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Target:
    """One repository to measure against."""

    name: str
    url: str
    language: str
    note: str = ""


#: The corpus. Grouped by the ecosystem each one exercises, because the gaps are
#: per-ecosystem: the allowlist changed for eleven and had been measured on three.
TARGETS: tuple[Target, ...] = (
    # -- Python ---------------------------------------------------------------
    Target("django", "https://github.com/django/django", "python"),
    Target("flask", "https://github.com/pallets/flask", "python"),
    Target("requests", "https://github.com/psf/requests", "python"),
    Target("fastapi", "https://github.com/fastapi/fastapi", "python"),
    Target("pydantic", "https://github.com/pydantic/pydantic", "python"),
    Target("celery", "https://github.com/celery/celery", "python"),
    Target("sqlalchemy", "https://github.com/sqlalchemy/sqlalchemy", "python"),
    Target("httpx", "https://github.com/encode/httpx", "python"),
    Target("poetry", "https://github.com/python-poetry/poetry", "python"),
    Target("black", "https://github.com/psf/black", "python"),
    Target("scrapy", "https://github.com/scrapy/scrapy", "python"),
    Target("boto3", "https://github.com/boto/boto3", "python"),
    Target("ansible", "https://github.com/ansible/ansible", "python", "large, many YAML fixtures"),
    Target("airflow", "https://github.com/apache/airflow", "python", "very large monorepo"),
    Target("bandit", "https://github.com/PyCQA/bandit", "python", "security tool: signatures"),
    Target("semgrep", "https://github.com/semgrep/semgrep", "python", "security tool: rule packs"),
    # -- JavaScript and TypeScript -------------------------------------------
    Target("react", "https://github.com/facebook/react", "javascript"),
    Target("vue", "https://github.com/vuejs/core", "javascript"),
    Target("svelte", "https://github.com/sveltejs/svelte", "javascript"),
    Target("express", "https://github.com/expressjs/express", "javascript"),
    Target("axios", "https://github.com/axios/axios", "javascript"),
    Target("lodash", "https://github.com/lodash/lodash", "javascript"),
    Target("eslint", "https://github.com/eslint/eslint", "javascript"),
    Target("webpack", "https://github.com/webpack/webpack", "javascript"),
    Target("vite", "https://github.com/vitejs/vite", "javascript"),
    Target("next.js", "https://github.com/vercel/next.js", "typescript", "very large monorepo"),
    Target("typescript", "https://github.com/microsoft/TypeScript", "typescript", "very large"),
    Target("nest", "https://github.com/nestjs/nest", "typescript"),
    Target("prettier", "https://github.com/prettier/prettier", "javascript"),
    Target("jest", "https://github.com/jestjs/jest", "typescript"),
    Target("retire.js", "https://github.com/RetireJS/retire.js", "javascript", "security tool"),
    # -- Go -------------------------------------------------------------------
    Target("kubernetes", "https://github.com/kubernetes/kubernetes", "go", "very large"),
    Target("moby", "https://github.com/moby/moby", "go"),
    Target("prometheus", "https://github.com/prometheus/prometheus", "go"),
    Target("grafana", "https://github.com/grafana/grafana", "go", "large, polyglot"),
    Target("gin", "https://github.com/gin-gonic/gin", "go"),
    Target("cobra", "https://github.com/spf13/cobra", "go"),
    Target("terraform", "https://github.com/hashicorp/terraform", "go"),
    Target("vault", "https://github.com/hashicorp/vault", "go", "secrets everywhere by design"),
    Target("trivy", "https://github.com/aquasecurity/trivy", "go", "security tool: signatures"),
    Target("gitleaks", "https://github.com/gitleaks/gitleaks", "go", "secret-scanner patterns"),
    # -- Rust -----------------------------------------------------------------
    Target("tokio", "https://github.com/tokio-rs/tokio", "rust"),
    Target("serde", "https://github.com/serde-rs/serde", "rust"),
    Target("ripgrep", "https://github.com/BurntSushi/ripgrep", "rust"),
    Target("clap", "https://github.com/clap-rs/clap", "rust"),
    Target("axum", "https://github.com/tokio-rs/axum", "rust"),
    Target("rustls", "https://github.com/rustls/rustls", "rust", "crypto: key material in tests"),
    Target("alacritty", "https://github.com/alacritty/alacritty", "rust"),
    Target("deno", "https://github.com/denoland/deno", "rust", "large, polyglot"),
    # -- Java and Kotlin -----------------------------------------------------
    Target("spring-boot", "https://github.com/spring-projects/spring-boot", "java", "large"),
    Target("guava", "https://github.com/google/guava", "java"),
    Target("okhttp", "https://github.com/square/okhttp", "java"),
    Target("retrofit", "https://github.com/square/retrofit", "java"),
    Target("jackson-databind", "https://github.com/FasterXML/jackson-databind", "java"),
    Target("elasticsearch", "https://github.com/elastic/elasticsearch", "java", "very large"),
    Target("kotlin-coroutines", "https://github.com/Kotlin/kotlinx.coroutines", "kotlin"),
    Target("ktor", "https://github.com/ktorio/ktor", "kotlin"),
    # -- Ruby -----------------------------------------------------------------
    Target("rails", "https://github.com/rails/rails", "ruby", "large monorepo"),
    Target("sinatra", "https://github.com/sinatra/sinatra", "ruby"),
    Target("sidekiq", "https://github.com/sidekiq/sidekiq", "ruby"),
    Target("devise", "https://github.com/heartcombo/devise", "ruby", "auth: credential names"),
    Target("rspec-core", "https://github.com/rspec/rspec-core", "ruby"),
    Target("brakeman", "https://github.com/presidentbeef/brakeman", "ruby", "security tool"),
    # -- PHP ------------------------------------------------------------------
    Target("laravel", "https://github.com/laravel/framework", "php", "large"),
    Target("symfony", "https://github.com/symfony/symfony", "php", "very large monorepo"),
    Target("composer", "https://github.com/composer/composer", "php"),
    Target("guzzle", "https://github.com/guzzle/guzzle", "php"),
    Target("phpunit", "https://github.com/sebastianbergmann/phpunit", "php"),
    # -- C# and .NET ----------------------------------------------------------
    Target("aspnetcore", "https://github.com/dotnet/aspnetcore", "csharp", "very large"),
    Target("efcore", "https://github.com/dotnet/efcore", "csharp"),
    Target("newtonsoft-json", "https://github.com/JamesNK/Newtonsoft.Json", "csharp"),
    Target("serilog", "https://github.com/serilog/serilog", "csharp"),
    Target("polly", "https://github.com/App-vNext/Polly", "csharp"),
    # -- Swift and Objective-C -----------------------------------------------
    Target("alamofire", "https://github.com/Alamofire/Alamofire", "swift"),
    Target("swift-nio", "https://github.com/apple/swift-nio", "swift"),
    Target("vapor", "https://github.com/vapor/vapor", "swift"),
    Target("kingfisher", "https://github.com/onevcat/Kingfisher", "swift"),
    Target("rxswift", "https://github.com/ReactiveX/RxSwift", "swift"),
    # -- Dart and Flutter ----------------------------------------------------
    Target("flutter", "https://github.com/flutter/flutter", "dart", "very large"),
    Target("dio", "https://github.com/cfug/dio", "dart"),
    Target("riverpod", "https://github.com/rrousselGit/riverpod", "dart"),
    Target("bloc", "https://github.com/felangel/bloc", "dart"),
    # -- Infrastructure, containers, CI --------------------------------------
    Target("helm", "https://github.com/helm/helm", "go", "chart templates"),
    Target("argo-cd", "https://github.com/argoproj/argo-cd", "go", "K8s manifests throughout"),
    Target("istio", "https://github.com/istio/istio", "go", "very large, IaC heavy"),
    Target(
        "ansible-collections",
        "https://github.com/ansible-collections/community.general",
        "python",
        "thousands of YAML",
    ),
    Target("docker-compose", "https://github.com/docker/compose", "go"),
    Target("github-actions-runner", "https://github.com/actions/runner", "csharp", "CI workflows"),
    # -- Deliberately awkward -------------------------------------------------
    Target("openssl", "https://github.com/openssl/openssl", "c", "PEM fixtures, .cnf templates"),
    Target("curl", "https://github.com/curl/curl", "c", "egress verbs everywhere"),
    Target("nmap", "https://github.com/nmap/nmap", "c", "offensive tool by design"),
    Target(
        "metasploit", "https://github.com/rapid7/metasploit-framework", "ruby", "exploit corpus"
    ),
    Target("sqlmap", "https://github.com/sqlmapproject/sqlmap", "python", "offensive tool"),
    Target("thc-hydra", "https://github.com/vanhauser-thc/thc-hydra", "c", "credential tooling"),
    Target("detect-secrets", "https://github.com/Yelp/detect-secrets", "python", "secret patterns"),
    Target("trufflehog", "https://github.com/trufflesecurity/trufflehog", "go", "secret patterns"),
    Target(
        "awesome-honeypots",
        "https://github.com/paralax/awesome-honeypots",
        "markdown",
        "prose only",
    ),
    Target(
        "public-apis",
        "https://github.com/public-apis/public-apis",
        "markdown",
        "huge markdown table",
    ),
)


def clone(target: Target, into: Path, *, timeout: int) -> bool:
    """Shallow single-branch clone, with no hooks and no submodules.

    `--depth 1` because history is not what is being measured and a full clone of
    the larger targets here is gigabytes. The VCS detector reads recent history, so
    it sees one commit and reports nothing -- which is the right trade: this harness
    measures the content rules, and a repository's own hook configuration is not
    what a third-party clone can tell us anything about.

    Submodules are deliberately skipped. They are somebody else's code again, they
    multiply the clone size unpredictably, and a submodule nobody here chose is not
    evidence about these rules.
    """
    git = shutil.which("git")
    if git is None:  # pragma: no cover - checked in main before any target runs
        return False
    return (
        subprocess.run(  # noqa: S603
            [
                git,
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--no-tags",
                "--recurse-submodules=no",
                # A clone must not be able to run anything. `core.hooksPath` to a
                # directory that does not exist is belt and braces next to
                # `--depth 1`, and costs nothing.
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "advice.detachedHead=false",
                target.url,
                str(into),
            ],
            capture_output=True,
            timeout=timeout,
            check=False,
        ).returncode
        == 0
    )


def scan(path: Path, *, timeout: int) -> dict | None:
    """Run the scanner from this checkout, not from whatever is installed."""
    environment = {
        "PYTHONPATH": str(ROOT / "src"),
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        # The measurement has to be of the current code, not of a cache written by
        # an earlier build of it. `--no-cache` is passed as well; this keeps a
        # stray cache directory out of the picture entirely.
        "CORDON_CACHE_DIR": str(path / ".cordon-cache"),
        "HOME": str(path),
    }
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "cordon_scanner",
            "scan",
            ".",
            "--no-cache",
            "--format",
            "json",
            "--quiet",
        ],
        cwd=path,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=environment,
    )
    # Exit 1 means findings, which is the normal outcome here. 2 and 3 are the
    # scanner's own failures and have nothing to report.
    if completed.returncode not in (0, 1, 4):
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None


def measure(
    targets: list[Target],
    *,
    clone_timeout: int,
    scan_timeout: int,
    checkpoint: Path | None = None,
    done: dict | None = None,
) -> dict:
    results: dict[str, dict] = dict(done or {})
    for index, target in enumerate(targets, start=1):
        print(f"[{index}/{len(targets)}] {target.name} ({target.language})", flush=True)
        with tempfile.TemporaryDirectory(prefix=f"noise-{target.name}-") as workspace:
            checkout = Path(workspace) / "repo"
            started = time.monotonic()
            if not clone(target, checkout, timeout=clone_timeout):
                print("    clone failed", flush=True)
                results[target.name] = {"error": "clone failed", "language": target.language}
                continue
            cloned = time.monotonic() - started

            files = sum(1 for _ in checkout.rglob("*") if _.is_file())
            started = time.monotonic()
            try:
                payload = scan(checkout, timeout=scan_timeout)
            except subprocess.TimeoutExpired:
                print(f"    scan timed out after {scan_timeout}s", flush=True)
                results[target.name] = {
                    "error": f"scan timed out after {scan_timeout}s",
                    "language": target.language,
                    "files": files,
                }
                continue
            elapsed = time.monotonic() - started

            if payload is None:
                print("    scan failed", flush=True)
                results[target.name] = {"error": "scan failed", "language": target.language}
                continue

            findings = payload.get("findings", [])
            by_rule = collections.Counter((f["rule_id"], f["severity"]) for f in findings)
            blocking = [f for f in findings if f["severity"] in ("high", "critical")]
            results[target.name] = {
                "language": target.language,
                "note": target.note,
                "files": files,
                "clone_seconds": round(cloned, 1),
                "scan_seconds": round(elapsed, 1),
                "findings": len(findings),
                "blocking": len(blocking),
                "by_rule": {f"{rule}/{sev}": n for (rule, sev), n in sorted(by_rule.items())},
                # Every high or critical finding in full, because those are the
                # ones a user would have to act on and the ones worth triaging by
                # hand. The rest are counted.
                "blocking_detail": [
                    {
                        "rule": f["rule_id"],
                        "severity": f["severity"],
                        "path": (f.get("location") or {}).get("path"),
                        "line": (f.get("location") or {}).get("line"),
                        "kind": dict((f.get("evidence") or {}).get("metadata") or []).get("kind"),
                    }
                    for f in blocking
                ],
            }
            print(
                f"    {files:,} files, {len(findings)} findings, "
                f"{len(blocking)} blocking, {elapsed:.0f}s",
                flush=True,
            )

        # Written after every repository, not at the end. The checkout is deleted as
        # this block exits, so a result not persisted here is one that has to be
        # re-cloned to recover -- and fourteen hundred repositories is hours of
        # cloning. A measurement nobody can afford to repeat stops being taken.
        if checkpoint is not None:
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            checkpoint.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    return results


def summarise(results: dict) -> None:
    scanned = {k: v for k, v in results.items() if "error" not in v}
    failed = {k: v for k, v in results.items() if "error" in v}

    total_files = sum(v["files"] for v in scanned.values())
    total_findings = sum(v["findings"] for v in scanned.values())
    total_blocking = sum(v["blocking"] for v in scanned.values())

    print()
    print("=" * 78)
    print(
        f"{len(scanned)} repositories scanned, {total_files:,} files, "
        f"{total_findings:,} findings, {total_blocking:,} blocking"
    )
    if failed:
        print(f"{len(failed)} could not be measured: {', '.join(sorted(failed))}")
    print("=" * 78)

    # By rule, blocking first. A rule firing across many unrelated repositories is
    # the signal worth acting on: one project can always be the exception, and
    # forty cannot.
    spread: dict[str, set[str]] = collections.defaultdict(set)
    counts: collections.Counter[str] = collections.Counter()
    for name, data in scanned.items():
        for key, number in data["by_rule"].items():
            rule, _, severity = key.rpartition("/")
            counts[f"{severity:8} {rule}"] += number
            spread[f"{severity:8} {rule}"].add(name)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    print()
    print(f"{'count':>7} {'repos':>6}  rule")
    for key in sorted(
        counts, key=lambda k: (order.get(k.split()[0], 9), -len(spread[k]), -counts[k])
    ):
        print(f"{counts[key]:>7} {len(spread[key]):>6}  {key}")

    print()
    print("Blocking findings by repository:")
    for name, data in sorted(scanned.items(), key=lambda kv: -kv[1]["blocking"]):
        if data["blocking"]:
            print(f"  {data['blocking']:>4}  {name} ({data['language']}) {data['note']}")
    clean = sorted(n for n, d in scanned.items() if not d["blocking"])
    print(f"\n{len(clean)} of {len(scanned)} produced no blocking finding:")
    print("  " + ", ".join(clean) if clean else "  none")


CORPUS_FILE = ROOT / "scripts" / "data" / "measurement-corpus.json"


def generated_targets() -> list[Target]:
    """The corpus built by `scripts/discover_repos.py`, if it has been generated.

    Kept alongside `TARGETS` rather than replacing it, because the two are chosen on
    different grounds and each does something the other cannot.

    The hand-picked set is chosen for SHAPE: security tools whose own signature files
    are the canonical false positive for the obfuscation rules, offensive tooling that
    is supposed to look malicious, a repository that is nothing but an enormous
    Markdown table. A star ranking will not reliably produce any of those.

    The generated set is chosen for BREADTH, which is the half a hand-written list
    cannot do honestly. A thousand URLs typed from memory is a thousand chances to
    name a project that does not exist: of 302 offered by hand for this corpus, 53 did
    not resolve, and a run that silently fails to clone a fifth of its targets reports
    a rate measured over whatever happened to succeed.
    """
    if not CORPUS_FILE.exists():
        return []
    payload = json.loads(CORPUS_FILE.read_text(encoding="utf-8"))
    return [
        Target(
            name=entry["name"],
            url=entry["url"],
            language=entry.get("language") or "unknown",
            note=entry.get("note", ""),
        )
        for entry in payload.get("repositories", [])
    ]


def load_checkpoint(path: Path) -> dict:
    """Results already recorded, so a long run can be resumed.

    Fourteen hundred repositories is hours of cloning. Without this, one dropped
    connection throws the whole measurement away -- and a measurement nobody can
    afford to repeat is one that stops being taken.
    """
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", nargs="+", help="only these languages")
    parser.add_argument("--only", nargs="+", help="only these repository names")
    parser.add_argument("--limit", type=int, help="stop after this many")
    parser.add_argument("--report", type=Path, help="write the full result as JSON")
    parser.add_argument("--clone-timeout", type=int, default=600)
    parser.add_argument("--scan-timeout", type=int, default=1800)
    parser.add_argument("--list", action="store_true", help="list the corpus and exit")
    parser.add_argument(
        "--hand-picked-only",
        action="store_true",
        help="use only the shapes chosen by hand, skipping the generated corpus",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="skip repositories already recorded in --report, and append to it",
    )
    args = parser.parse_args()

    targets = list(TARGETS)
    if not args.hand_picked_only:
        # Hand-picked entries win a name collision, because their `note` records why
        # that particular repository is in the corpus at all.
        chosen = {target.name for target in targets}
        targets.extend(t for t in generated_targets() if t.name not in chosen)

    if args.language:
        wanted = {x.lower() for x in args.language}
        targets = [t for t in targets if t.language in wanted]
    if args.only:
        wanted = {x.lower() for x in args.only}
        targets = [t for t in targets if t.name.lower() in wanted]
    if args.limit:
        targets = targets[: args.limit]

    if args.list:
        by_language = collections.Counter(t.language for t in targets)
        for language, count in sorted(by_language.items()):
            print(f"  {language:14} {count:4}")
        print(f"  {'TOTAL':14} {len(targets):4}")
        return 0

    if not targets:
        print("no targets selected", file=sys.stderr)
        return 2
    if shutil.which("git") is None:
        print("git is not on PATH", file=sys.stderr)
        return 2

    done: dict = {}
    if args.resume and args.report:
        done = load_checkpoint(args.report)
        before = len(targets)
        targets = [target for target in targets if target.name not in done]
        print(f"resuming: {len(done)} already measured, {before - len(targets)} skipped")

    results = measure(
        targets,
        clone_timeout=args.clone_timeout,
        scan_timeout=args.scan_timeout,
        checkpoint=args.report,
        done=done,
    )
    summarise(results)

    if args.report:
        args.report.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nwrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
