# 42 · From your own code: the Python API and the JSON result

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Level 3, wiring Cordon into systems of your own: a deployment gate, a package mirror that
checks what it admits, a dashboard. Two ways in, and both are stable: the Python API, and the
JSON result every scan can write.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  YOUR SERVICE                                                            │
│      │                                                                   │
│      ├── in-process ──► Scanner.for_target(path).scan(path) ──► ScanResult│
│      │                  PolicyGate.evaluate(result, policy) ──► Verdict  │
│      │                                                                   │
│      └── as a process ─► cordon-scanner scan … -f json:result.json       │
│                          the exit code is the verdict; the JSON is why   │
└──────────────────────────────────────────────────────────────────────────┘
```

## A gate in twenty lines

```python
"""A pre-merge gate: scan, decide with the configured policy, explain."""
import json
import sys

from cordon_scanner import Category, PolicyGate, Scanner

target = sys.argv[1] if len(sys.argv) > 1 else "."
scanner = Scanner.for_target(target)          # discovers cordon.yaml; applies the policy ceiling
result = scanner.scan(target)
verdict = PolicyGate.evaluate(result, scanner.config.policy)

for finding in result.findings:
    if finding.category is Category.MALICIOUS:
        print("MALICIOUS", finding.rule_id, finding.location, file=sys.stderr)

print(json.dumps({
    "passed": verdict.passed,
    "exit_code": int(verdict.exit_code),
    "reason": verdict.reason,
    "complete": result.complete,
    "findings": len(result.findings),
    "blocking": [f.rule_id for f in verdict.triggering],
}, indent=1))
sys.exit(int(verdict.exit_code))
```

Pointed at a project whose `requirements.txt` pins `urllib3==1.26.4`, it prints
`"passed": false`, `"exit_code": 1` and `"reason": "8 finding(s) met the failure policy
(highest: high)"`, with each blocking rule listed, and exits 1, the same verdict the command
line gives.

**Use `Scanner.for_target`.** It loads the repository's configuration the way the command line
does: the organisation policy as a ceiling, and the settings a scan target may not grant itself
withheld. `Scanner(Config.from_file(...))` skips both, so keep it for a `Config` you build
deliberately in code.

## What you get back

```
   ScanResult
     .findings          tuple of Finding, sorted by (path, rule_id, fingerprint)
     .dependencies      the resolved dependency graph
     .stats             files read, bytes, time
     .complete          False when anything was not read, or the intel is stale
     .content_complete  whether every file's content was read

   Finding  (frozen: a result cannot be edited and passed off as a scan's)
     .rule_id  .severity  .confidence  .category  .location  .message  .remediation

   Verdict = PolicyGate.evaluate(result, policy)
     .passed  .exit_code  .reason  .triggering   (the findings that met the policy)
```

`cordon_scanner.__all__` is the contract: anything not in it is internal and may change in a
minor release.

## Many scans in one process

A `Scanner` compiles its rules once and is reusable, so a long-running service builds one per
configuration and calls `scan()` for each target. Two scanners with different configurations
can live in one process; nothing is global.

```python
from cordon_scanner import Config, Scanner

scanner = Scanner(Config.default().with_overrides(use_cache=False))
for path in incoming_packages():          # your code: a mirror's upload queue, say
    result = scanner.scan(path)
    admit(path) if result.complete and not result.findings else hold(path, result)
```

## From any language: the JSON result

When the caller is not Python, run the command line and read the JSON it writes. The exit
code alone is enough to gate on (0 clean, 1 findings, 2 scanner error, 3 configuration
error, 4 incomplete), and the file says why:

```bash
cordon-scanner scan ./candidate --fail-on high --fail-on-incomplete -f json:result.json -f text
```

```
   result.json
     complete, content_complete,     whether everything was read, and what was not
       advisory_complete, content_gaps
     verdict                         the decision and the score behind it
     findings[]                      rule_id, severity, confidence, category, location,
                                     message, remediation, evidence, risk, fingerprint
     dependencies                    the resolved graph
     intel                           its source, age and whether it is stale
     schema_version, engine_version, rulepack_version, config_hash
```

The JSON follows the schema in `schemas/`, versioned with the release, so a consumer can
validate what it reads. For a dashboard, `-f sarif:` feeds any SARIF viewer and
`--upload` sends results to Cordon Cloud (tutorials 35 and 39).

That is the last implementation tutorial. Tutorials 25 to 28 are the reference: every
ecosystem, command, agent location and rule.
