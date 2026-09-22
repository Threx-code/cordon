"""Generates `docs/07-ECOSYSTEMS.md` from the ecosystems that actually ship.

"Which package managers do you read?" is the first question anyone asks a
supply-chain scanner, and this project answered it nowhere: the README never
named one, and the only enumeration was prose in `docs/01-ARCHITECTURE.md` that
stopped six ecosystems short of what the code registers.

Generated for the same reason `tests/matrix.py` is. A hand-kept support table is
a claim about coverage, and a claim about coverage that nothing checks is the
failure this scanner exists to report in other people's pipelines.
`tests/unit/test_ecosystem_matrix.py` fails when the file on disk disagrees.

Run it after adding an ecosystem, a manifest shape or an advisory feed:

    python tests/ecosystems.py > docs/07-ECOSYSTEMS.md
"""

from __future__ import annotations

from cordon_scanner.detect.provenance import SUPPORTED_ECOSYSTEMS as PROVENANCE_ECOSYSTEMS
from cordon_scanner.detect.registry import REGISTRY_ECOSYSTEMS
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.intel.advisories import AdvisoryDatabase
from cordon_scanner.intel.popular import PackageIntel
from cordon_scanner.intel.real import real_packages

HEADER = """# Ecosystems

Every package ecosystem Cordon reads, the files it reads for each, and which
checks that ecosystem gets. Generated from the shipped code -- the manifest and
lockfile patterns are the ones the walker actually matches, and the capability
columns are read from the data and detectors that actually ship.

Regenerate after adding an ecosystem or a feed:

```bash
python tests/ecosystems.py > docs/07-ECOSYSTEMS.md
```

## How to read the columns

```
  MANIFESTS      what a project declares: ranges, no resolved versions
  LOCKFILES      what a project resolved: exact versions, usually hashes
  ADVISORIES     known-malicious and known-vulnerable matching, offline
  TYPOSQUAT      name-similarity checks against that ecosystem's popular set
  REGISTRY       --online only: withdrawal, version distance, hash agreement
  PROVENANCE     --online only: attestation presence, and verification with [attest]
```

A dependency whose ecosystem has no advisory feed still gets everything else --
the graph, typosquat and confusion checks, lockfile integrity, licences, install
hooks. What it cannot get is a vulnerability match, and a scan that includes one
says so through `OPERATIONAL.ADVISORY.NO_FEED.001` rather than reporting a clean
result that was never checked.

"""

FOOTER = """
## What is not here

- **Operating-system packages** (`dpkg`, `rpm`, `apk`) and container image
  layers. Cordon reads a source tree; image scanning is a different product.
- **An ecosystem's own resolver.** Nothing here runs `npm install`, `pip
  download` or `conan install` to find out what a range resolves to -- see
  constraint C2 in `docs/01-ARCHITECTURE.md`. A range stays a range, and the
  checks that need an exact version skip it rather than guess.
"""


def _yes(value: bool) -> str:
    return "yes" if value else "--"


def rows() -> list[tuple[str, ...]]:
    """One row per registered ecosystem, in the order the registry holds them."""
    database = AdvisoryDatabase.bundled()
    collected: list[tuple[str, ...]] = []
    for ecosystem_id in sorted(EcosystemRegistry.BY_ID):
        ecosystem = EcosystemRegistry.get(ecosystem_id)
        if ecosystem is None:  # pragma: no cover - registry cannot hold a None
            continue
        manifests = ", ".join(f"`{_basename(g)}`" for g in ecosystem.manifest_globs) or "--"
        lockfiles = ", ".join(f"`{_basename(g)}`" for g in ecosystem.lockfile_globs) or "--"
        collected.append(
            (
                f"`{ecosystem_id}`",
                manifests,
                lockfiles,
                _yes(database.covers(ecosystem_id)),
                _yes(bool(PackageIntel.POPULAR_PACKAGES.get(ecosystem_id))),
                _yes(ecosystem_id in REGISTRY_ECOSYSTEMS),
                _yes(ecosystem_id in PROVENANCE_ECOSYSTEMS),
                f"{len(real_packages(ecosystem_id)):,}",
            )
        )
    return collected


def _basename(glob: str) -> str:
    """`**/package.json` reads as `package.json` in a table."""
    return glob.removeprefix("**/")


def render() -> str:
    header = (
        "| Ecosystem | Manifests | Lockfiles | Advisories | Typosquat | "
        "Registry | Provenance | Allowlist |"
    )
    divider = "|---|---|---|---|---|---|---|---|"
    body = "\n".join("| " + " | ".join(row) + " |" for row in rows())
    return f"{HEADER}{header}\n{divider}\n{body}\n{FOOTER}"


if __name__ == "__main__":
    print(render(), end="")
