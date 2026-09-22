"""Generates `docs/05-COVERAGE-MATRIX.md` from the rules that actually ship.

A hand-kept coverage matrix drifts, and a drifted one is worse than none: it
reports coverage that is not there, which is the same failure this project is
organised against in the scanner itself. So the document is generated, and
`tests/unit/test_coverage_matrix.py` fails when the file on disk disagrees with
what this produces.

Run it after adding a rule:

    python tests/matrix.py > docs/05-COVERAGE-MATRIX.md
"""

from __future__ import annotations

from collections import defaultdict

from cordon_scanner.core.registry import Registry
from cordon_scanner.core.taxonomy import ThreatDomain, category_of, domain_of
from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.rules.loader import RuleLoader

DOMAIN_ORDER: tuple[tuple[ThreatDomain, str, str], ...] = (
    (ThreatDomain.SOURCE, "1", "Source and VCS identity"),
    (ThreatDomain.DEPENDENCY, "2", "Dependencies"),
    (ThreatDomain.REGISTRY, "3", "Registries"),
    (ThreatDomain.BUILD, "4", "Build systems"),
    (ThreatDomain.CICD, "5", "CI/CD"),
    (ThreatDomain.MALWARE, "6", "Install and execution malware"),
    (ThreatDomain.OBFUSCATION, "7", "Obfuscation and evasion"),
    (ThreatDomain.CREDENTIAL, "8", "Credentials and secret stores"),
    (ThreatDomain.EXFILTRATION, "9", "Exfiltration channels"),
    (ThreatDomain.CONTAINER, "10", "Containers and orchestration"),
    (ThreatDomain.INFRASTRUCTURE, "11", "Infrastructure as code"),
    (ThreatDomain.BINARY, "12", "Binaries and artefacts"),
    (ThreatDomain.PROVENANCE, "13", "Provenance and integrity"),
    (ThreatDomain.SCANNER, "14", "The scanner itself"),
)

HEADER = """# Coverage matrix

What Cordon detects, by threat domain, with the rule that implements each check.

**Generated from the shipped rules, not written alongside them.** A hand-kept
matrix drifts, and a drifted matrix is worse than none: it reports coverage that
is not there, which is the same failure mode as a scan reporting clean on a file
it never read. `tests/unit/test_coverage_matrix.py` regenerates this content and
fails if it disagrees with what the tool actually ships, so a new rule that is
absent here fails the build.

Regenerate after adding a rule:

```bash
python tests/matrix.py > docs/05-COVERAGE-MATRIX.md
```

## How to read it

The fourteen domains are the taxonomy the threat model is organised around; see
`docs/02-THREAT-MODEL.md`. A rule's **attack category** says what is being
attempted rather than where -- typosquatting and dependency confusion share a
domain and are different attacks, and a vulnerability is a liability rather than
somebody attacking you.

Capability primitives (`CAP.*`) are not listed. They are labels that composite
rules reason over, not findings: a file that decodes something is not a finding,
and a file that decodes and executes is. The composites are what appear here.

## What is not covered

Stated because a coverage matrix that lists only what exists is an advertisement
rather than a document.

- **Runtime behaviour.** Cordon does not execute the code it scans, so behaviour
  that exists only at runtime -- a target decoded from a network response, logic
  gated on a fetched value -- is outside it by construction. What such code
  cannot avoid is looking like it is hiding something, which is what the
  obfuscation domain reports. Observing the behaviour itself requires an
  isolated sandbox, which is a separate opt-in component.
- **Cryptographic signature verification** (domain 13) is available as the
  opt-in `[attest]` extra. The base checks provenance against what the registry
  publishes -- npm's `dist.attestations`, PyPI's `provenance`, and the lockfile
  hash against the registry's -- and reconciles an SBOM against the resolved
  graph. With `[attest]` installed, the provenance detector verifies the
  sigstore bundle itself: the Fulcio certificate, the Rekor inclusion proof, the
  DSSE signature over the pinned digest, and the signing identity against the
  declared source repository. That verification needs a cryptographic library
  the core will not take, which is why it is an extra; without it, provenance
  stays at the presence check and the unverifiable case is reported, never
  passed.
- **Reachability** -- whether a vulnerable or malicious symbol is actually
  called -- is modelled at its import tier, behind `--reachability`: a vulnerable
  transitive dependency that first-party code does not import is lowered and
  tagged rather than dropped. The precise call-graph tier, whether the vulnerable
  symbol is on a path a caller reaches, is not yet built.
- **Operating-system and container-image packages.** Cordon reads source,
  manifests, lockfiles, CI and IaC. It does not scan `dpkg`/`rpm`/`apk`
  databases or image layers for base-image CVEs, which is a distinct product
  from supply-chain analysis of a source tree.
- **Languages without a capability pack** inherit no behavioural rules. Packs
  ship for Python, JavaScript and TypeScript, shell and PowerShell, Make, the
  JVM build languages, CMake, MSBuild, Rust, and the compiled-language set.
  A language outside those is read by the language-agnostic rules only --
  obfuscation, secrets, and anything matched on path or content shape.
- **Online checks** (withdrawal, version distance, registry hash verification,
  and provenance/attestation verification) require `--online` and do not run by
  default.

---
"""


def shipped_rules() -> dict[str, tuple[str, str]]:
    """Every reportable rule, mapped to the source that implements it.

    Capability primitives are excluded: they are inputs to composites rather
    than findings, and listing them would describe the machinery instead of the
    coverage.
    """
    rows: dict[str, tuple[str, str]] = {}
    for rule in RuleCatalogue.from_detectors(Registry().detectors()):
        rows[rule.id] = (rule.detector, str(rule.severity))
    for pack in RuleLoader.load_builtin():
        for compiled in pack:
            if compiled.rule.capability is None and not compiled.id.startswith("CAP."):
                rows[compiled.id] = (pack.id.replace("cordon.", ""), str(compiled.rule.severity))
    return rows


def render() -> str:
    by_domain: dict[ThreatDomain, list[tuple[str, str, str]]] = defaultdict(list)
    for rule_id, (source, severity) in sorted(shipped_rules().items()):
        by_domain[domain_of(rule_id)].append((rule_id, source, severity))

    lines = [HEADER]
    for domain, number, title in DOMAIN_ORDER:
        entries = by_domain.get(domain, [])
        lines.append(f"\n### Domain {number} — {title}\n")
        if not entries:
            lines.append("No rules ship for this domain yet.\n")
            continue
        lines.append("| Rule | Severity | Implemented by | Attack category |")
        lines.append("|---|---|---|---|")
        for rule_id, source, severity in entries:
            lines.append(
                f"| `{rule_id}` | {severity} | `{source}` | {category_of(rule_id).value} |"
            )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(render(), end="")
