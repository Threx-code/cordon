"""Where a rule's claim is written down by somebody other than this project.

A finding asserts that something is a problem. A reference is what a reader
follows when they do not take that on trust -- to decide whether the rule
applies to them, to argue with it, or to quote it to somebody who has to
approve the change. Without one, the only authority behind a finding is the
tool that emitted it.

Defined here rather than beside each rule because the same handful of documents
covers hundreds of them: every credential rule rests on CWE-798, every
encryption-at-rest policy on CWE-311. A rule names the constant; the URL is
written once and corrected once.

Only stable, vendor- or standards-body-owned URLs belong here. A blog post that
explains an attack well is not a reference a build failure can rest on in three
years, and a link that rots is worse than no link -- it reads as authority and
delivers a 404.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------
# CWE, which is the common vocabulary between a scanner and a security team
# --------------------------------------------------------------------------
CWE: Final = "https://cwe.mitre.org/data/definitions/{}.html"

HARDCODED_CREDENTIALS: Final = CWE.format(798)
CLEARTEXT_STORAGE: Final = CWE.format(312)
MISSING_ENCRYPTION: Final = CWE.format(311)
CLEARTEXT_TRANSMISSION: Final = CWE.format(319)
IMPROPER_ACCESS_CONTROL: Final = CWE.format(284)
EXPOSED_RESOURCE: Final = CWE.format(668)
INSUFFICIENT_LOGGING: Final = CWE.format(778)
IMPROPER_PRIVILEGE_MANAGEMENT: Final = CWE.format(269)
PRIVILEGE_ESCALATION: Final = CWE.format(269)
EXECUTION_WITH_UNNECESSARY_PRIVILEGE: Final = CWE.format(250)
CODE_INJECTION: Final = CWE.format(94)
EVAL_INJECTION: Final = CWE.format(95)
DOWNLOAD_WITHOUT_INTEGRITY_CHECK: Final = CWE.format(494)
UNTRUSTED_SEARCH_PATH: Final = CWE.format(426)
OBSCURED_SECURITY_DATA: Final = CWE.format(1295)
INSUFFICIENT_VERIFICATION: Final = CWE.format(345)
MISSING_AUTHENTICATION: Final = CWE.format(306)
WEAK_CRYPTO: Final = CWE.format(326)
IMPROPER_CERT_VALIDATION: Final = CWE.format(295)
UNCONTROLLED_RESOURCE: Final = CWE.format(400)
INSECURE_DEFAULT: Final = CWE.format(1188)
MISSING_BACKUP: Final = CWE.format(1188)
HOMOGLYPH: Final = CWE.format(1007)
UNTRUSTED_INPUT_IN_BUILD: Final = CWE.format(1357)

# --------------------------------------------------------------------------
# Supply-chain specific, where CWE is too general to be useful
# --------------------------------------------------------------------------
SLSA: Final = "https://slsa.dev/spec/v1.0/levels"
SLSA_PROVENANCE: Final = "https://slsa.dev/spec/v1.0/provenance"
OSV: Final = "https://osv.dev/"
SIGSTORE: Final = "https://docs.sigstore.dev/"
DEPENDENCY_CONFUSION: Final = "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610"
"""The original write-up of the attack, kept because there is no standards-body
document for it and every later description cites this one."""

CYCLONEDX: Final = "https://cyclonedx.org/specification/overview/"
SPDX: Final = "https://spdx.dev/use/specifications/"
NPM_LIFECYCLE: Final = "https://docs.npmjs.com/cli/v10/using-npm/scripts"
PYPI_YANK: Final = "https://peps.python.org/pep-0592/"
TROJAN_SOURCE: Final = "https://trojansource.codes/"

# --------------------------------------------------------------------------
# CI and container guidance from the projects that own the surface
# --------------------------------------------------------------------------
GITHUB_ACTIONS_HARDENING: Final = (
    "https://docs.github.com/en/actions/security-for-github-actions/"
    "security-guides/security-hardening-for-github-actions"
)
OPENSSF_SCORECARD_PINNED: Final = (
    "https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies"
)
KUBERNETES_POD_SECURITY: Final = (
    "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
)
DOCKER_BUILD_BEST_PRACTICE: Final = "https://docs.docker.com/build/building/best-practices/"
OWASP_SECRETS_MANAGEMENT: Final = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_CheatSheet.html"
)

# --------------------------------------------------------------------------
# Cloud provider documentation, for the infrastructure policies
# --------------------------------------------------------------------------
AWS_KMS: Final = "https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#master_keys"
AWS_IMDSV2: Final = (
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"
)
AZURE_PRIVATE_LINK: Final = (
    "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview"
)
AZURE_SHARED_KEY: Final = (
    "https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent"
)
GOOGLE_CMEK: Final = "https://cloud.google.com/kms/docs/cmek"

__all__ = [n for n in dir() if n.isupper() and not n.startswith("_")]
