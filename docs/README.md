# Documentation

Two sets, and they are read differently.

```
   ┌────────────────────────────────────────────────────────────────────────┐
   │                                                                        │
   │   tutorials/          a READING ORDER. 01 to 17, each one building     │
   │        │              on the last. Start here if you have not run      │
   │        │              a scan yet.                                      │
   │        │                                                               │
   │        └──────────►   01 first scan                                    │
   │                       02 how detection works                           │
   │                       03 malware and vulnerabilities                   │
   │                       ...                                              │
   │                       17 source, build and binaries                    │
   │                                                                        │
   │   docs/               REFERENCE. Read the one you need, in any order.  │
   │        │                                                               │
   │        └──────────►   01 architecture      what runs, and when         │
   │                       02 threat model      what this defends against   │
   │                       03 interfaces        CLI, config, exit codes     │
   │                       04 operations        running it for real         │
   │                       05 coverage matrix   every rule that ships       │
   │                       06 sandbox           isolation and its limits    │
   │                       07 ecosystems        what is parsed, per         │
   │                                            language                    │
   └────────────────────────────────────────────────────────────────────────┘
```

## Reference

| | What it answers |
|---|---|
| [01-ARCHITECTURE.md](01-ARCHITECTURE.md) | How a scan is put together: detectors, rule packs, the engine, and the order things happen in |
| [02-THREAT-MODEL.md](02-THREAT-MODEL.md) | What this defends against, what it does not, and the constraints that follow from scanning untrusted code |
| [03-INTERFACES.md](03-INTERFACES.md) | Every command, every configuration key, every exit code |
| [04-OPERATIONS.md](04-OPERATIONS.md) | Running it in CI, tuning the gate, baselines, suppressions, air-gapped installs |
| [05-COVERAGE-MATRIX.md](05-COVERAGE-MATRIX.md) | Every rule the tool can emit, generated from the tool itself and asserted by the suite |
| [06-SANDBOX.md](06-SANDBOX.md) | What the sandbox isolates, and what it cannot |
| [07-ECOSYSTEMS.md](07-ECOSYSTEMS.md) | Per ecosystem: the manifests and lockfiles read, and which checks reach it |

## Tutorials

[tutorials/README.md](../tutorials/README.md) is the index. They are numbered
because they are a sequence: each one assumes the one before it, and the
numbering and the chain of `Next:` links are asserted by the test suite so the
order cannot rot.

## Generated, not written

Two of these are produced from the code and checked against it on every push:

- **docs/05-COVERAGE-MATRIX.md** comes from `tests/matrix.py`, which asks the
  installed engine what rules it has. A rule that ships and is missing from the
  matrix fails the suite.
- **docs/07-ECOSYSTEMS.md** comes from the ecosystem registry, for the same
  reason: the README once named no ecosystem at all, and a hand-written list
  drifts the moment somebody adds a parser.

Editing either by hand is a mistake the next CI run will correct.

## The claims in the README are measured

`scripts/measure_noise.py` runs the scanner over the repository list in
`scripts/data/measurement-corpus.json` and reports what it found. The numbers in
the README's accuracy table come from that script and from public corpora of
real malicious packages; the method for each is stated beside the number.
