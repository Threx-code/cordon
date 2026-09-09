# Coverage matrix

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
- **Package versus repository mismatch** (domain 3) needs a repository field on
  the dependency model that no ecosystem parser populates yet.
- **SBOM reconciliation and signature attestation** (domain 13) are not
  implemented; only registry hash verification is.
- **Languages without a capability pack** inherit no behavioural rules. Packs
  ship for Python, JavaScript and TypeScript, shell and PowerShell, Make, the
  JVM build languages, CMake, MSBuild, Rust, and the compiled-language set.
  A language outside those is read by the language-agnostic rules only --
  obfuscation, secrets, and anything matched on path or content shape.
- **Online checks** (withdrawal, version distance, registry hash verification)
  require `--online` and do not run by default.

---


### Domain 1 — Source and VCS identity

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.VCS.BINARY_ADDED.001` | low | `vcs` | policy |
| `SUSPECT.POLYGLOT.MISMATCH.001` | high | `binary` | obfuscation |
| `SUSPECT.SUBMODULE.UNTRUSTED.001` | medium | `config` | integrity |
| `SUSPECT.VCS.HOOKS_PATH.001` | medium | `config` | integrity |
| `SUSPECT.VCS.HOOK_ADDED.001` | medium | `vcs` | integrity |

### Domain 2 — Dependencies

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.DEPENDENCY.KNOWN.001` | critical | `advisory` | malicious_code |
| `POLICY.DEPENDENCY.DOWNGRADE.001` | low | `registry` | policy |
| `POLICY.DEPENDENCY.INTEGRITY.001` | medium | `dependency` | policy |
| `POLICY.DEPENDENCY.SOURCE.001` | low | `dependency` | policy |
| `POLICY.LOCKFILE.INTEGRITY.001` | medium | `lockfile` | integrity |
| `SUSPECT.DEPENDENCY.CONFUSION.001` | high | `dependency` | dependency_confusion |
| `SUSPECT.DEPENDENCY.SOURCE.001` | medium | `dependency` | policy |
| `SUSPECT.DEPENDENCY.TYPOSQUAT.001` | high | `dependency` | policy |
| `SUSPECT.DEPENDENCY.YANKED.001` | high | `registry` | policy |
| `SUSPECT.LOCKFILE.SOURCE.001` | medium | `lockfile` | integrity |
| `VULNERABLE.DEPENDENCY.KNOWN.001` | high | `advisory` | vulnerability |

### Domain 3 — Registries

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `SUSPECT.PACKAGE.PROVENANCE.001` | medium | `registry` | integrity |
| `SUSPECT.PACKAGE.REPOSITORY.001` | medium | `registry` | integrity |

### Domain 4 — Build systems

No rules ship for this domain yet.


### Domain 5 — CI/CD

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.CI.SECRET_EXFIL.001` | critical | `config` | exfiltration |
| `POLICY.CI.UNPINNED_ACTION.001` | medium | `config` | policy |
| `SUSPECT.CI.ARTIFACT_POISONING.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.EXPRESSION_INJECTION.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.FETCH_EXEC.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.PR_TARGET.001` | high | `config` | misconfiguration |
| `SUSPECT.CI.SECRET_EGRESS.001` | high | `config` | misconfiguration |

### Domain 6 — Install and execution malware

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.ANTI_ANALYSIS.001` | critical | `composites` | malicious_code |
| `MALWARE.CRYPTOMINER.001` | critical | `composites` | cryptomining |
| `MALWARE.DROPPER.001` | critical | `composites` | dropper |
| `MALWARE.INSTALL.FETCH_EXEC.001` | critical | `manifest` | install_hook |
| `SUSPECT.CRYPTOMINER.001` | high | `composites` | cryptomining |
| `SUSPECT.DECODE_CHAIN.001` | critical | `composites` | malicious_code |
| `SUSPECT.DROPPER.001` | high | `composites` | dropper |
| `SUSPECT.INSTALL.SCRIPT.001` | low | `manifest` | install_hook |
| `SUSPECT.PERSIST.001` | high | `composites` | persistence |

### Domain 7 — Obfuscation and evasion

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.DYNAMIC_DISPATCH.001` | critical | `composites` | obfuscation |
| `SUSPECT.ANTI_ANALYSIS.001` | high | `composites` | anti_analysis |
| `SUSPECT.DECODE_EXEC.001` | high | `composites` | obfuscation |
| `SUSPECT.DYNAMIC_DISPATCH.001` | high | `composites` | obfuscation |
| `SUSPECT.OBFUSCATION.BIDI.001` | high | `obfuscation` | obfuscation |
| `SUSPECT.OBFUSCATION.ENCODED.001` | medium | `obfuscation` | obfuscation |
| `SUSPECT.OBFUSCATION.LONGLINE.001` | low | `obfuscation` | obfuscation |
| `SUSPECT.OBFUSCATION.PACKED.001` | medium | `obfuscation` | obfuscation |

### Domain 8 — Credentials and secret stores

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `SECRET.AWS.ACCESS_KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.GENERIC.ASSIGNMENT.001` | high | `secrets` | secret_exposure |
| `SECRET.GITHUB.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.GOOGLE.API_KEY.001` | high | `secrets` | secret_exposure |
| `SECRET.JWT.001` | medium | `secrets` | secret_exposure |
| `SECRET.NPM.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.PRIVATE_KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.PYPI.TOKEN.001` | critical | `secrets` | secret_exposure |
| `SECRET.SLACK.TOKEN.001` | high | `secrets` | secret_exposure |
| `SECRET.SLACK.WEBHOOK.001` | medium | `secrets` | secret_exposure |
| `SECRET.STRIPE.KEY.001` | critical | `secrets` | secret_exposure |
| `SECRET.URL.CREDENTIAL.001` | high | `secrets` | secret_exposure |

### Domain 9 — Exfiltration channels

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `MALWARE.EXFIL.001` | critical | `composites` | exfiltration |
| `MALWARE.EXFIL.CREDENTIAL_STORE.001` | critical | `composites` | exfiltration |
| `MALWARE.EXFIL.DROP_POINT.001` | critical | `composites` | exfiltration |
| `SUSPECT.EXFIL.001` | high | `composites` | exfiltration |
| `SUSPECT.EXFIL.CREDENTIAL_STORE.001` | high | `composites` | exfiltration |
| `SUSPECT.EXFIL.DNS.001` | high | `composites` | exfiltration |
| `SUSPECT.EXFIL.DROP_POINT.001` | high | `composites` | exfiltration |

### Domain 10 — Containers and orchestration

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.CONTAINER.UNPINNED_BASE.001` | low | `config` | misconfiguration |
| `POLICY.K8S.SERVICE_ACCOUNT_TOKEN.001` | low | `config` | policy |
| `SUSPECT.CONTAINER.BUILD_SECRET.001` | high | `config` | misconfiguration |
| `SUSPECT.CONTAINER.FETCH_EXEC.001` | high | `config` | misconfiguration |
| `SUSPECT.HELM.UNTRUSTED_REPOSITORY.001` | medium | `config` | misconfiguration |
| `SUSPECT.K8S.CAPABILITIES.001` | high | `config` | misconfiguration |
| `SUSPECT.K8S.RBAC_WILDCARD.001` | high | `config` | misconfiguration |

### Domain 11 — Infrastructure as code

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `SUSPECT.IAC.ANSIBLE_FETCH_EXEC.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.HOST_MOUNT.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.IAM_WILDCARD.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.PRIVILEGED.001` | high | `config` | misconfiguration |
| `SUSPECT.IAC.PUBLIC_INGRESS.001` | high | `config` | misconfiguration |

### Domain 12 — Binaries and artefacts

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.BINARY.COMMITTED.001` | low | `binary` | policy |
| `SUSPECT.BINARY.EXECUTABLE_PATH.001` | high | `binary` | integrity |
| `SUSPECT.BINARY.PACKED.001` | medium | `binary` | integrity |
| `SUSPECT.BINARY.STRINGS.001` | medium | `binary` | integrity |

### Domain 13 — Provenance and integrity

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `POLICY.RELEASE.NO_PROVENANCE.001` | low | `attestation` | integrity |
| `SUSPECT.PROVENANCE.MISMATCH.001` | critical | `registry` | integrity |
| `SUSPECT.SBOM.DRIFT.001` | medium | `sbom` | integrity |

### Domain 14 — The scanner itself

| Rule | Severity | Implemented by | Attack category |
|---|---|---|---|
| `OPERATIONAL.REGISTRY.UNREACHABLE.001` | low | `registry` | coverage |
| `OPERATIONAL.SBOM.UNREADABLE.001` | low | `sbom` | coverage |
| `OPERATIONAL.VCS.UNREADABLE.001` | low | `vcs` | coverage |
