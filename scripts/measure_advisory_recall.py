"""Detection rate per ecosystem, for releases the bundled database names.

Reproduces the advisory rows of the README's detection table. A manifest is
written in the shape each ecosystem actually uses, pinning real versions the
database records, and the scan has to report them. This is the path that
reaches every ecosystem; content analysis needs real package contents, and
those exist publicly for npm and PyPI only.

Run it offline -- everything it needs ships in the wheel:

    python3 scripts/measure_advisory_recall.py
"""

import collections
import json
import pathlib
import subprocess
import sys
import tempfile

from cordon_scanner.intel.advisories import AdvisoryDatabase

SAMPLE = 120  # per ecosystem, capped so the run stays bounded


def manifest(eco: str, pins: list[tuple[str, str]]) -> tuple[str, str] | None:
    """The file to write, in the shape the ecosystem's parser reads."""
    if eco == "npm":
        return "package-lock.json", json.dumps(
            {
                "name": "m",
                "lockfileVersion": 2,
                "packages": {
                    f"node_modules/{n}": {
                        "version": v,
                        "resolved": f"https://registry.npmjs.org/{n}/-/{n}-{v}.tgz",
                    }
                    for n, v in pins
                },
            },
            indent=1,
        )
    if eco == "pypi":
        return "requirements.txt", "".join(f"{n}=={v}\n" for n, v in pins)
    if eco == "cargo":
        return "Cargo.lock", "".join(
            f'[[package]]\nname = "{n}"\nversion = "{v}"\n\n' for n, v in pins
        )
    if eco == "gomod":
        return "go.mod", "module m\n\ngo 1.21\n\nrequire (\n" + "".join(
            f"\t{n} v{v.lstrip('v')}\n" for n, v in pins
        ) + ")\n"
    if eco in {"maven", "gradle"}:
        body = "".join(
            f"  <dependency><groupId>{n.split(':')[0]}</groupId>"
            f"<artifactId>{n.split(':')[-1]}</artifactId>"
            f"<version>{v}</version></dependency>\n"
            for n, v in pins
            if ":" in n
        )
        return "pom.xml", (
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "<modelVersion>4.0.0</modelVersion>\n<groupId>x</groupId>\n"
            f"<artifactId>y</artifactId>\n<version>1</version>\n<dependencies>\n{body}"
            "</dependencies>\n</project>\n"
        )
    if eco == "nuget":
        body = "".join(f'  <package id="{n}" version="{v}" />\n' for n, v in pins)
        return (
            "packages.config",
            f'<?xml version="1.0" encoding="utf-8"?>\n<packages>\n{body}</packages>\n',
        )
    if eco == "rubygems":
        # Four spaces: `Gemfile.lock` indents a top-level gem under `specs:`
        # by exactly that, and the parser anchors on it.
        body = "".join(f"    {n} ({v})\n" for n, v in pins)
        return (
            "Gemfile.lock",
            f"GEM\n  remote: https://rubygems.org/\n  specs:\n{body}\nDEPENDENCIES\n",
        )
    if eco == "composer":
        return "composer.lock", json.dumps(
            {"packages": [{"name": n, "version": v} for n, v in pins]}, indent=1
        )
    if eco == "pub":
        body = "".join(
            f'  {n}:\n    dependency: "direct main"\n    source: hosted\n    version: "{v}"\n'
            for n, v in pins
        )
        return "pubspec.lock", f'packages:\n{body}sdks:\n  dart: ">=3.0.0 <4.0.0"\n'
    if eco == "hex":
        # The atom is quoted: a hex package name may contain a hyphen and a
        # bare Elixir atom may not, so this is the spelling mix writes.
        body = "".join(
            f'  "{n}": {{:hex, :"{n}", "{v}", "aa", [:mix], [], "hexpm", "bb"}},\n' for n, v in pins
        )
        return "mix.lock", f"%{{\n{body}}}\n"
    if eco == "swift":
        return "Package.resolved", json.dumps(
            {
                "version": 2,
                "pins": [
                    {"identity": n, "location": f"https://github.com/{n}", "state": {"version": v}}
                    for n, v in pins
                ],
            },
            indent=1,
        )
    return None


db = AdvisoryDatabase.bundled()
db._load_all()
by_eco: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
for (eco, _), advs in db._by_key.items():
    for a in advs:
        if not a.malicious:
            continue
        version = a.versions[0] if a.versions else None
        if not version or version in {"0", ""}:
            # A range-based malicious advisory names no single version. Go
            # publishes almost entirely this way -- `introduced: 0` with no
            # fixed release, meaning every version of the name is the incident
            # -- so a concrete pin inside the range is what a real manifest
            # would carry, and is what has to be matched.
            if a.is_range and not a.fixed:
                by_eco[eco].append((a.name, "1.0.0"))
            continue
        by_eco[eco].append((a.name, version))

print(f"{'ecosystem':11} {'pinned':>7} {'reported':>9} {'rate':>7}   manifest")
rows = {}
for eco in sorted(by_eco):
    # One version per NAME: a manifest keys packages by name, so pinning the
    # same package at three versions writes one entry and measures nothing.
    seen = set()
    pins = []
    for name, version in sorted(set(by_eco[eco])):
        if name in seen:
            continue
        seen.add(name)
        pins.append((name, version))
        if len(pins) >= SAMPLE:
            break
    shape = manifest(eco, pins)
    if not shape or not pins:
        rows[eco] = (len(pins), 0, None)
        print(f"{eco:11} {len(pins):7} {'-':>9} {'n/a':>7}   (no sample or no manifest shape)")
        continue
    name, body = shape
    d = pathlib.Path(tempfile.mkdtemp())
    (d / name).write_text(body, encoding="utf-8")
    out = d / "r.json"
    subprocess.run(  # noqa: S603 -- this interpreter, on a tree this script wrote
        [
            sys.executable,
            "-m",
            "cordon_scanner.cli",
            "scan",
            str(d),
            "--format",
            "json",
            "-o",
            str(out),
        ],
        capture_output=True,
    )
    try:
        findings = json.loads(out.read_text())["findings"]
    except Exception:
        findings = []
    # Distinct packages reported, not string matching on the purl: a name
    # written with homoglyphs is percent-encoded there and will not compare
    # equal to the name the advisory records.
    named = {
        (f.get("location") or {}).get("package", "")
        for f in findings
        if f["rule_id"] == "MALWARE.DEPENDENCY.KNOWN.001"
    }
    hits = min(len({p for p in named if p}), len(pins))
    rate = hits / len(pins) if pins else 0
    rows[eco] = (len(pins), hits, rate)
    print(f"{eco:11} {len(pins):7} {hits:9} {rate:6.1%}   {name}")

pathlib.Path("ecosystems.json").write_text(json.dumps(rows, indent=1))
