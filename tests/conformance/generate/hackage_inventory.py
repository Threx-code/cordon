"""Second step of hackage.sh: the authoritative inventories from Cabal's install plan and Stack's
dependency listing. Run inside Docker only (see hackage.sh)."""

import json
import shutil
from pathlib import Path

CASES = Path("/conformance/cases/hackage")
RAW = CASES / ".raw"
# Packages that ship inside GHC and cannot come from Hackage: recorded as platform requirements.
GHC = {
    "base",
    "ghc",
    "ghc-bignum",
    "ghc-boot-th",
    "ghc-heap",
    "ghc-internal",
    "ghc-prim",
    "ghci",
    "integer-gmp",
    "integer-simple",
    "rts",
    "system-cxx-std-lib",
    "template-haskell",
}
GHC_REASON = "part of GHC itself, not installable from Hackage: recorded as a platform requirement the compiler meets"

plan = json.loads((RAW / "plan.json").read_text(encoding="utf-8"))
units = [u for u in plan["install-plan"] if u.get("pkg-name") != "conformance"]
listed = sorted({f"{u['pkg-name']}@{u['pkg-version']}" for u in units})
(CASES / "real-cabal" / "authoritative.json").write_text(
    json.dumps(
        {
            "tool": "cabal build all --dry-run (plan.json)",
            "packages": listed,
            "ignore": dict.fromkeys(sorted({u["pkg-name"] for u in units} & GHC), GHC_REASON),
            "compiler": plan.get("compiler-id"),
        },
        indent=1,
    )
    + "\n",
    encoding="utf-8",
)
print("cabal", len(listed))

deps = json.loads((RAW / "stack-deps.json").read_text(encoding="utf-8"))
found = sorted({f"{d['name']}@{d['version']}" for d in deps if d.get("name") != "stackapp"})
lock = (CASES / "real-stack" / "stack.yaml.lock").read_text(encoding="utf-8")
ignore = {}
for entry in found:
    name = entry.rsplit("@", 1)[0]
    if name in GHC:
        ignore[name] = GHC_REASON
    elif f"hackage: {name}-" not in lock and f"name: {name}\n" not in lock:
        # Not an extra-dep: Stack resolved it from the snapshot, whose package set stack.yaml.lock
        # pins by hash and does not list -- the repository does not hold the version.
        ignore[name] = "resolved from the snapshot, whose packages stack.yaml.lock does not list"
(CASES / "real-stack" / "authoritative.json").write_text(
    json.dumps(
        {"tool": "stack ls dependencies json", "packages": found, "ignore": ignore}, indent=1
    )
    + "\n",
    encoding="utf-8",
)
print("stack", len(found), "of which from the snapshot or GHC", len(ignore))
shutil.rmtree(RAW)
