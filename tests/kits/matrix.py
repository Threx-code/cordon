"""Generates `docs/05-COVERAGE-MATRIX.md` from the rules that actually ship.

A hand-kept coverage matrix drifts, and a drifted one is worse than none: it
reports coverage that is not there, which is the same failure this project is
organised against in the scanner itself. So the document is generated, and
`tests/unit/cli/test_coverage_matrix.py` fails when the file on disk disagrees with
what this produces.

Run it after adding a rule:

    python tests/kits/matrix.py > docs/05-COVERAGE-MATRIX.md
"""

from __future__ import annotations

from collections import defaultdict

from cordon_scanner.detect.catalogue import RuleCatalogue
from cordon_scanner.engine.registry import Registry
from cordon_scanner.foundation.taxonomy import Taxonomy, ThreatDomain
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
    (ThreatDomain.AGENT, "15", "The agent chain"),
)

HEADER = """# Coverage matrix

What Cordon detects, by threat domain, with the rule that implements each check.

**Generated from the shipped rules, not written alongside them.** A hand-kept
matrix drifts, and a drifted matrix is worse than none: it reports coverage that
is not there, which is the same failure mode as a scan reporting clean on a file
it never read. `tests/unit/cli/test_coverage_matrix.py` regenerates this content and
fails if it disagrees with what the tool actually ships, so a new rule that is
absent here fails the build.

Regenerate after adding a rule:

```bash
python tests/kits/matrix.py > docs/05-COVERAGE-MATRIX.md
```

## How to read it

The fifteen domains are the taxonomy the threat model is organised around; see
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
  tagged rather than dropped. For Go it goes one level further: the Go
  vulnerability database names the affected functions, and a finding whose
  functions first-party code never calls is lowered the same way. A full call
  graph, for every language, is not built.
- **Operating-system packages outside an image.** `cordon-scanner scan
  image.tar` reads a `docker save` or OCI tarball's dpkg, apk and RPM (SQLite)
  databases as the final layer leaves them, and matches them through OSV with
  `--online`. A running host's package database, and the legacy Berkeley DB
  rpmdb, are not read.
- **Languages without a capability pack** inherit no behavioural rules. Packs
  ship for Python, JavaScript and TypeScript, shell and PowerShell, Make, the
  JVM build languages, CMake, MSBuild, Rust, Ruby, PHP, Perl, Lua, Dart, Elixir,
  R, and the compiled-language set. Dart has no string evaluator and no native
  object deserialiser, so it has no rule for either. A language outside those
  (Haskell, Swift and the rest) is read by the language-agnostic rules only --
  obfuscation, secrets, and anything matched on path or content shape.
- **Online checks** (withdrawal, version distance, registry hash verification,
  and provenance/attestation verification) require `--online` and do not run by
  default. They ask npm, PyPI, crates.io, RubyGems, NuGet, the Go module proxy and
  sum.golang.org, Maven Central, Packagist, pub.dev and Hex. Provenance is
  verified for npm, PyPI, Maven, RubyGems, container images, Homebrew bottles,
  Bazel Central Registry modules, Helm charts (a chart's OpenPGP provenance file,
  against the keys given with `--keyring`, as `helm verify` checks it) and Ansible
  collections (their OpenPGP signatures over MANIFEST.json, recorded at install or
  served by galaxy.ansible.com, against the same keys, as `ansible-galaxy collection
  verify` checks them); the others publish none a scanner can read.
- **Advisories through the upstream.** OSV publishes no Bazel, vcpkg, Conan,
  Homebrew, CocoaPods, Terraform, Nix or conda ecosystem. With `--online`, each of
  those packages is matched through what its own ecosystem says it was built from
  -- a repository and tag or commit (OSV's GIT ecosystem), a Go module (Terraform
  providers) or a registry archive (a PyPI sdist a conda recipe builds) -- read
  from BCR's source.json, a Conan Center recipe export, a podspec, a Homebrew
  formula (from its bottle, for an older version; from homebrew-core's history,
  found by the bottle digest the lock records, for a deleted one), a vcpkg portfile
  at the baseline, the Terraform registry, a flake's locked commit, or the recipe
  inside a conda package (its .conda zstd member read by the core's own decoder
  where Python is older than 3.14). A binary pod is the release of the repository
  a sibling pod of the same lock resolved to only when that repository's podspec at
  the tag names the very download trunk gives (Firebase). A package that installs
  no code -- an empty vcpkg port, a conda metapackage -- has nothing to check; a
  vendor's prebuilt binary is reported as one. Where the ecosystem names a release
  archive but no tag, a tag
  spelled as the version in the repository it names is used only if the archive,
  checked against its pinned digest, holds the tag's files byte for byte
  (**proved**, as good as named); a host's known repository is used only when
  proved; otherwise the tag is used and labelled **inferred** (MEDIUM). A branch
  is never a fixed point.
- **Advisories from NVD.** What no repository route reaches -- a tarball from a
  project's own site, a closed binary, a macOS application -- is matched against
  NVD's own records (bundled, offline; complete after `advisories sync`), once
  the package is tied to one CPE product: by a curated mapping (HIGH), or by the
  guarded rule, reported as inferred (MEDIUM): the product's name is the
  package's (or the name its release file gives, or its `<vendor>_<product>`)
  AND one of the product's references -- in NVD's dictionary, or a CVE's patch and
  issue links for a product named alone -- is on the package's homepage or
  download site, and only one product passes; or, failing a name, the package's
  own repository or SourceForge project is listed by one product alone. NVD's own
  ranges then decide -- and, for a CVE NVD has not analysed, the ranges its record in
  the CVE List states: its CPEs and affected versions, from its CNA or CISA's
  Vulnrichment. A package tied to nothing is unchecked, and the report
  names it and why.

---
"""


class CoverageMatrix:
    """The rule coverage matrix, rendered from what ships."""

    @staticmethod
    def generated_ids() -> set[str]:
        """The infrastructure policies built from provider schemas.

        Listed as a summary rather than as rows. There are more of them than there
        are hand-written rules by a factor of five, and a table where the
        machine-generated entries outnumber the explained ones stops being a
        document somebody reads and becomes a file somebody greps -- while the count
        and the provenance, which are what a reader actually wants from them, fit in
        a paragraph.
        """
        from cordon_scanner.detect.infra.iac_policies import GeneratedPolicies

        return {policy.id for policy in GeneratedPolicies.generated_policies()}

    @staticmethod
    def shipped_rules() -> dict[str, tuple[str, str]]:
        """Every reportable rule written by hand, mapped to what implements it.

        Capability primitives are excluded: they are inputs to composites rather
        than findings, and listing them would describe the machinery instead of the
        coverage. Generated policies are excluded for the reason above, and counted
        in their own section.
        """
        rows: dict[str, tuple[str, str]] = {}
        generated = CoverageMatrix.generated_ids()
        for rule in RuleCatalogue.from_detectors(Registry().detectors()):
            if rule.id in generated:
                continue
            rows[rule.id] = (rule.detector, str(rule.severity))
        for pack in RuleLoader.load_builtin():
            for compiled in pack:
                if compiled.rule.capability is None and not compiled.id.startswith("CAP."):
                    rows[compiled.id] = (
                        pack.id.replace("cordon.", ""),
                        str(compiled.rule.severity),
                    )
        return rows

    @staticmethod
    def render() -> str:
        by_domain: dict[ThreatDomain, list[tuple[str, str, str]]] = defaultdict(list)
        for rule_id, (source, severity) in sorted(CoverageMatrix.shipped_rules().items()):
            by_domain[Taxonomy.domain_of(rule_id)].append((rule_id, source, severity))

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
                    f"| `{rule_id}` | {severity} | `{source}` | {Taxonomy.category_of(rule_id).value} |"
                )
        lines.append(CoverageMatrix.generated_section())
        return "\n".join(lines) + "\n"

    @staticmethod
    def generated_section() -> str:
        """The generated infrastructure policies, by family, with their provenance."""
        from collections import Counter

        from cordon_scanner.detect.infra.iac_policies import GeneratedPolicies

        policies = GeneratedPolicies.generated_policies()
        if not policies:
            return (
                "\n## Generated infrastructure policy\n\n"
                "None in this checkout. Run `scripts/build/build_iac_policies.py` against a "
                "provider schema to build them.\n"
            )

        meta = GeneratedPolicies.generated_meta()
        families = Counter(policy.id.split(".")[2] for policy in policies)
        severities = Counter(str(policy.severity) for policy in policies)

        lines = [
            "\n## Generated infrastructure policy\n",
            f"**{len(policies)} policies**, over the resources the providers say have the "
            "attribute each control is about. Which resources those are is a fact rather "
            "than a memory, so it is read from the schema rather than typed: a policy "
            "naming an attribute a provider does not have can never fire, and looks "
            "exactly like a clean scan.\n",
            "| Control family | Policies |",
            "|---|---|",
        ]
        lines.extend(f"| `{family}` | {count} |" for family, count in sorted(families.items()))
        lines.append("")
        lines.append(
            "Severity: "
            + ", ".join(f"{count} {name}" for name, count in severities.most_common())
            + "."
        )
        lines.append("")
        lines.append("Built from:\n")
        lines.append("```")
        for provider, version in sorted((meta.get("providers") or {}).items()):
            lines.append(f"  {provider:48} {version}")
        cloudformation = meta.get("cloudformation") or {}
        if cloudformation:
            lines.append(
                f"  {'AWS CloudFormation resource specification':48} "
                f"{cloudformation.get('specification_version', '')}"
            )
        lines.append("```")
        lines.append(
            "\nRegenerate after a provider release:\n\n"
            "```bash\n"
            "terraform providers schema -json > schema.json\n"
            "python scripts/build/build_iac_policies.py --schema schema.json \\\n"
            "    --cfn-spec CloudFormationResourceSpecification.json --versions versions.json\n"
            "```\n"
        )
        return "\n".join(lines)


if __name__ == "__main__":
    print(CoverageMatrix.render(), end="")
