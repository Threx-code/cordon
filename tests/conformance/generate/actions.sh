#!/bin/sh
# Regenerates the real-world GitHub Actions conformance case: the workflows and action.yml files
# of a public repository at its current default branch, with GitHub's own dependency graph for the
# same commit (the dependency-graph SBOM API) as the authoritative inventory of the actions they
# use. Nothing in the workflows is run. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim sh /conformance/generate/actions.sh
set -eu
REPO=${REPO:-pypa/cibuildwheel}
OUT=/conformance/cases/actions/real-workflows
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq git >/dev/null 2>&1
rm -rf /tmp/r && git clone --quiet --depth 1 "https://github.com/$REPO" /tmp/r
python3 - "$REPO" "$OUT" <<'PY'
import json, shutil, sys, urllib.request
from pathlib import Path

repo, out = sys.argv[1], Path(sys.argv[2])
source = Path("/tmp/r")
if out.exists():
    shutil.rmtree(out)
out.mkdir(parents=True)
copied = []
for path in sorted(source.rglob("*")):
    relative = path.relative_to(source)
    if relative.parts[0] == ".git" or not path.is_file():
        continue
    workflow = relative.parts[:2] == (".github", "workflows") and path.suffix in (".yml", ".yaml")
    action = path.name in ("action.yml", "action.yaml")
    if workflow or action:
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        copied.append(str(relative))
request = urllib.request.Request(
    f"https://api.github.com/repos/{repo}/dependency-graph/sbom",
    headers={"Accept": "application/vnd.github+json", "User-Agent": "cordon-conformance"},
)
sbom = json.load(urllib.request.urlopen(request, timeout=60))["sbom"]
actions = {}
for package in sbom["packages"]:
    for ref in package.get("externalRefs") or []:
        locator = ref.get("referenceLocator", "")
        if locator.startswith("pkg:githubactions/"):
            name, _, version = locator.removeprefix("pkg:githubactions/").partition("@")
            actions[name] = version
import re, subprocess

def release(name: str, commit: str) -> str | None:
    """The most specific `vX.Y.Z` tag of the action's repository that names this commit, read
    from the repository itself -- not from the comment beside the pin."""
    listed = subprocess.run(
        ["git", "ls-remote", "--tags", f"https://github.com/{name}"], capture_output=True, text=True, timeout=120, check=False
    ).stdout
    found = []
    for line in listed.splitlines():
        sha, _, ref = line.partition("\t")
        tag = ref.removeprefix("refs/tags/").removesuffix("^{}")
        exact = re.fullmatch(r"v?(\d+\.\d+\.\d+)", tag)
        if sha == commit and exact:
            found.append(exact.group(1))
    return max(found, key=lambda v: tuple(int(p) for p in v.split("."))) if found else None

ignore = {}
packages = []
for name, version in sorted(actions.items()):
    if re.fullmatch(r"[0-9a-f]{40}", version or ""):
        tagged = release(name, version)
        if tagged is None:
            ignore[name] = "pinned to a commit no release tag names"
        packages.append(f"{name}@{tagged or version}")
        continue
    if not version or "*" in version:
        # GitHub reads a moving tag (`@v4`) as the range 4.*.*: the commit the tag names today
        # is not in the repository, and no exact version is.
        ignore[name] = f"a moving tag: GitHub's graph reports the range {version or 'unversioned'}, not a version"
    packages.append(f"{name}@{version or '0'}")
(out / "authoritative.json").write_text(
    json.dumps({"tool": "GitHub dependency graph (dependency-graph/sbom API)", "repository": repo, "packages": packages, "ignore": ignore}, indent=1) + "\n"
)
print(len(copied), "files;", len(actions), "actions;", "\n".join(f"{k}@{v}" for k, v in sorted(actions.items())))
PY
echo done
