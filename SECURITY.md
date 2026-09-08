# Security policy

## Reporting a vulnerability

Report privately, not as a public issue.

- GitHub: open a [private security advisory](https://github.com/Threx-code/cordon/security/advisories/new).
- Email: security@threx.dev, with `cordon` in the subject.

Include the version, the platform, and the smallest input that reproduces it. If
the report involves a payload, describe its shape rather than attaching a
working sample.

You will get an acknowledgement within three working days and an assessment
within ten. If a fix is warranted, we will agree a disclosure date with you
before publishing.

## What counts as a vulnerability here

Cordon is pointed deliberately at code that may be hostile, so its threat model
is unusual. These are in scope:

- **A detection bypass.** Any input that suppresses a finding a working scan
  would produce, without the output saying coverage was reduced. A scan that
  examined nothing must never look like a scan that found nothing.
- **Code execution from a scan target.** Cordon must never execute what it
  scans. A crafted repository, archive, lockfile or configuration that causes
  execution is a vulnerability regardless of how it is reached.
- **Reading or writing outside the scan root.** Path traversal in an archive, a
  followed symlink, a configuration or manifest pointing elsewhere.
- **Credential disclosure.** Evidence redaction failing to mask a value, or a
  secret reaching a report, log or SARIF file that should not carry it.
- **Denial of service from a scan target.** Unbounded CPU or memory driven by
  attacker-controlled input, including catastrophic regex backtracking and
  archive expansion.
- **Configuration escalation.** A configuration file inside the scan target
  gaining a power it should not have, or defeating an organisation policy.

Out of scope: findings you disagree with, false positives and false negatives in
rule content. Open a normal issue for those — they matter, they are just not
handled under embargo.

## Supported versions

Cordon is pre-1.0. Security fixes land on the latest release; there is no
backport branch yet. That will change at 1.0 and this file will say so.

## The scanner's own supply chain

Cordon has no runtime dependencies, so its install-time surface is the Python
interpreter and the wheel itself. Development dependencies are pinned. The
scanner scans its own repository in CI, and rule packs ship inside the wheel
rather than being fetched at scan time.
