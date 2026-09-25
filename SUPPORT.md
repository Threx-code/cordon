# Getting help

## Pick the right door

```
   ┌─────────────────────────────────────────────────────────────────────┐
   │  WHAT YOU HAVE                    WHERE IT GOES                     │
   ├─────────────────────────────────────────────────────────────────────┤
   │  A vulnerability in Cordon   ──►  SECURITY.md. Not an issue.        │
   │  itself                           Never a public issue.             │
   │                                                                     │
   │  A finding you think is      ──►  Issue: "false positive"           │
   │  wrong                            Include the file, redacted.       │
   │                                                                     │
   │  Something Cordon missed     ──►  Issue: "false negative"           │
   │                                   The more specific, the better.    │
   │                                                                     │
   │  A crash, a hang, a wrong    ──►  Issue: "bug"                      │
   │  exit code                        `--version` and the command.      │
   │                                                                     │
   │  "How do I ... ?"            ──►  tutorials/ first, then            │
   │                                   Discussions.                      │
   │                                                                     │
   │  "Will you support X?"       ──►  Discussions. Say what you would   │
   │                                   do with it.                       │
   └─────────────────────────────────────────────────────────────────────┘
```

## Before opening an issue

Run the scan again with `--verbose`, and include the output. Three quarters of
reports are answered by something already in it: the config that was loaded,
the detectors that ran, and whether the scan was complete.

```
   $ cordon-scanner --version
   $ cordon-scanner scan . --verbose 2>&1 | tail -40
```

If a finding is wrong, the single most useful thing you can send is the
**smallest file that still produces it**. A rule is fixed by narrowing it, and
narrowing it safely needs a case to test against.

## What a good false-positive report looks like

```
   Rule:     SUSPECT.DECODE_EXEC.001
   Version:  0.4.1
   File:     scripts/setup.sh (attached, 6 lines)
   Expected: nothing -- this decodes a licence key into a variable
   Actual:   high severity, "decoded and executed"
```

That is enough to write a test from. A screenshot of a terminal is not.

## Documentation

| If you want to | Read |
|---|---|
| Scan something for the first time | [tutorials/01-first-scan.md](tutorials/01-first-scan.md) |
| Understand what a finding means | [tutorials/02-how-detection-works.md](tutorials/02-how-detection-works.md) |
| See every rule that ships | `cordon-scanner rules list`, or [docs/05-COVERAGE-MATRIX.md](docs/05-COVERAGE-MATRIX.md) |
| Know why a rule fired | `cordon-scanner rules show <RULE.ID>` |
| Tune what fails a build | [tutorials/14-config-policy-baselines.md](tutorials/14-config-policy-baselines.md) |
| Run it offline or air-gapped | [tutorials/11-air-gapped.md](tutorials/11-air-gapped.md) |
| Understand the architecture | [docs/01-ARCHITECTURE.md](docs/01-ARCHITECTURE.md) |

## Response times

This is maintained by people with other jobs. A security report gets an
acknowledgement within 48 hours because that one is agreed in `SECURITY.md`.
Everything else is best effort, and "no reply yet" means no reply yet rather
than no.

## Commercial support

There is none. If that is a blocker for your organisation, say so in
Discussions -- knowing it is wanted is the first step to it existing.
