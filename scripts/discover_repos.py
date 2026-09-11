#!/usr/bin/env python3
"""Build the measurement corpus from GitHub, ranked by stars.

A MAINTENANCE script, like `refresh_package_intel.py`, and for the same reason:
the list it writes is data that ships and gets reviewed, not something computed
during a scan.

    python3 scripts/discover_repos.py --per-language 80
    python3 scripts/discover_repos.py --token "$GITHUB_TOKEN"   # 30 req/min
    python3 scripts/discover_repos.py --check                   # write nothing

Generated rather than written by hand. A thousand repository URLs typed from
memory is a thousand chances to name a project that does not exist, or to name one
that does and get its owner wrong -- and a corpus that silently fails to clone a
third of its targets reports a false-positive rate measured over whatever
happened to succeed.

Ranked by stars because popularity is a proxy for the property that matters: code
that many people have read. A false positive in a repository with forty thousand
stars is a false positive thousands of engineers would recognise as wrong
immediately, which is exactly the signal wanted. It is NOT a proxy for code
quality, and that is fine -- the measurement is about what cordon says, not about
what the code deserves.

Search is capped at a thousand results per query, so the corpus is built per
language. That also guarantees the spread the measurement needs: the allowlist
changed for eleven ecosystems and had been measured against three.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "scripts" / "data" / "measurement-corpus.json"
API = "https://api.github.com/search/repositories"

#: Languages to sample, with the minimum star count worth including.
#:
#: The floors differ because the ecosystems differ in size. A thousand stars puts a
#: Go project in the top few hundred; the same number in Dart or Swift would return
#: almost nothing, and the point is coverage of the ecosystem rather than a uniform
#: threshold nobody can justify.
LANGUAGES: dict[str, int] = {
    "python": 2000,
    "javascript": 3000,
    "typescript": 2000,
    "go": 1500,
    "rust": 1000,
    "java": 1500,
    "kotlin": 500,
    "ruby": 500,
    "php": 500,
    "c#": 500,
    "swift": 500,
    "dart": 300,
    "c": 1000,
    "c++": 2000,
    "shell": 1000,
    "hcl": 200,
    "dockerfile": 200,
}

#: Repositories to skip, with the reason.
#:
#: Not "these produce findings we dislike" -- nothing is excluded for being noisy,
#: which would be measuring the corpus against itself. These are excluded because
#: cloning or scanning them tells us nothing: a repository with no code in it
#: measures nothing, and one that is forty gigabytes of game assets measures disk.
SKIP_REASONS: dict[str, str] = {
    "github/gitignore": "a collection of .gitignore files, no code",
    "jwasham/coding-interview-university": "a reading list",
    "sindresorhus/awesome": "a list of links",
    "EbookFoundation/free-programming-books": "a reading list",
    "public-apis/public-apis": "already in the hand-picked set, as a prose case",
    "torvalds/linux": "a full kernel clone measures bandwidth, not precision",
    "chromium/chromium": "the same, an order of magnitude worse",
}


def search(
    language: str, minimum_stars: int, *, pages: int, token: str | None, pause: float
) -> list[dict]:
    """One language's most-starred repositories.

    Paged to the API's hard thousand-result ceiling. A 403 here is the rate limit
    rather than a permission problem: unauthenticated search allows ten requests a
    minute, which is why `--token` exists and why the pause between pages is
    generous by default.
    """
    collected: list[dict] = []
    for page in range(1, pages + 1):
        query = urllib.parse.urlencode(
            {
                "q": f"language:{language} stars:>={minimum_stars} archived:false",
                "sort": "stars",
                "order": "desc",
                "per_page": 100,
                "page": page,
            }
        )
        headers = {
            "User-Agent": "cordon-scanner measurement corpus",
            "Accept": "application/vnd.github+json",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        # `API` is an https literal in this file; nothing about the scheme comes
        # from input, and the query is urlencoded.
        request = urllib.request.Request(f"{API}?{query}", headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=45) as response:  # noqa: S310
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                print(f"  rate limited on page {page}; waiting 70s", file=sys.stderr)
                time.sleep(70)
                continue
            print(f"  {language} page {page}: HTTP {exc.code}", file=sys.stderr)
            break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"  {language} page {page}: {type(exc).__name__}", file=sys.stderr)
            break

        items = payload.get("items") or []
        if not items:
            break
        collected.extend(items)
        if len(items) < 100:
            break
        time.sleep(pause)
    return collected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-language", type=int, default=70)
    parser.add_argument("--token", default=None, help="a GitHub token raises the rate limit")
    parser.add_argument("--pause", type=float, default=7.0, help="seconds between requests")
    parser.add_argument("--check", action="store_true", help="report and write nothing")
    parser.add_argument("--language", nargs="+", help="only these languages")
    args = parser.parse_args()

    wanted = (
        {lang: LANGUAGES[lang] for lang in args.language if lang in LANGUAGES}
        if args.language
        else LANGUAGES
    )

    corpus: list[dict] = []
    seen: set[str] = set()
    for language, minimum in wanted.items():
        pages = max(1, -(-args.per_language // 100))
        print(f"{language}: fetching up to {args.per_language}", flush=True)
        found = search(language, minimum, pages=pages, token=args.token, pause=args.pause)
        added = 0
        for item in found:
            full_name = item.get("full_name")
            if not full_name or full_name in seen:
                continue
            if full_name in SKIP_REASONS:
                continue
            # Size is in kilobytes. The cap keeps one pathological repository from
            # being most of the run; the harness measures precision, and a
            # four-gigabyte asset tree contributes disk and bandwidth rather than
            # evidence.
            if (item.get("size") or 0) > 2_000_000:
                continue
            seen.add(full_name)
            corpus.append(
                {
                    "name": full_name.replace("/", "__"),
                    "url": item["clone_url"],
                    "language": (item.get("language") or language).lower(),
                    "stars": item.get("stargazers_count") or 0,
                    "size_kb": item.get("size") or 0,
                    "note": "",
                }
            )
            added += 1
            if added >= args.per_language:
                break
        print(f"  kept {added}", flush=True)

    corpus.sort(key=lambda entry: (-entry["stars"], entry["name"]))
    print(f"\n{len(corpus)} repositories across {len(wanted)} languages")

    if args.check:
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(
            {
                "generated": time.strftime("%Y-%m-%d"),
                "source": API,
                "note": (
                    "Generated by scripts/discover_repos.py. Ranked by stars, which is "
                    "a proxy for how many engineers have read the code and would "
                    "recognise a false positive immediately - not a claim about "
                    "quality."
                ),
                "skipped": SKIP_REASONS,
                "repositories": corpus,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
