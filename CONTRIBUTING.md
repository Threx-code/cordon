# Contributing

## Getting set up

```bash
git clone https://github.com/Threx-code/cordon
cd cordon
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r ci/dev-requirements.txt
pip install --no-deps -e .

pytest -q
ruff check src/ tests/
ruff format --check src/ tests/
cordon-scanner scan .            # the tool scans its own repository
```

Python 3.11 or newer. There are no runtime dependencies and there will not be
any: it is what makes the air-gapped story real, and every proposal to add one
should assume it will be refused.

## What a change needs

**A test that fails without it.** For a bug fix, the test should reproduce the
bug. For a detection change, add a sample to `corpus/` or an inline rule sample.

**A reason in the code.** Comments and docstrings here explain *why* a decision
was made, not what the line does. A change that alters a security property
should say what it prevents and what it costs.

**No new runtime dependency.**

**Coverage at or above 85 percent**, which CI enforces.

## Where code goes

```
  src/cordon_scanner/
    foundation/   shared types and utilities -- imports nothing above it
    analysis/     reading code, per language -- facts, never verdicts
    detect/       detectors, per area: code agents supply binary infra secrets source
    decide/       package-level decisions: verdict, intent, scoring, policy, vex
    engine/       running a scan
    intel/        knowledge from outside the content: advisories malware registries
                  provenance store
    ecosystems/ sources/ images/ rules/ report/ cli/ ...   one purpose each

  tests/unit/<place>/test_<module>.py     beside where the module lives
  tests/unit/repository/ bench/ sandbox/  tests of the repository, the bench, the sandbox
```

A layer imports only the layers inside it (`docs/01-ARCHITECTURE.md`). Every module and every
unit test has one line in `tests/unit/package_layout.json`; add yours in the same commit, and
`tests/unit/repository/test_package_layout.py` fails until you do. The same test, part of every
gate and of CI, holds the rest of the arrangement:

```
  rule                                        fails when
  ──────────────────────────────────────────  ─────────────────────────────────────────────────
  every file has its place                    a module or unit test is not where the table says
  every top-level package has a layer         a new package or module appears in src/ unplaced
  no loose files                              a file at the top of src/cordon_scanner, detect/,
                                              intel/, tests/, scripts/ or bench/ beyond the few
                                              that belong there
  at most 20 modules a directory              a directory in src/ or tests/unit/ grows past it
  at most 1,000 lines a module                a module passes it
  at most 1,000 lines a class                 a class passes it
  at most 90 lines a function                 a function passes it
  the engine reaches adapters through their   engine/ imports a concrete detector, reporter,
    ports only                                  ecosystem, source or intel module: an adapter
                                              layer's `base` (its protocols) and `registry`
                                              (what implements them) are the way in
  imports point inward                        a NEW outward import (today's are frozen; each
                                              one removed comes off the list)
  no paths counted from a file's position     a new `__file__`: data is found with PackagePaths
                                              (foundation/paths.py), the repository from
                                              support.ROOT in tests, the checkout from where a
                                              script runs
  the repository root holds what it declares  a tracked entry at the top of the repository
                                              that REPOSITORY_ROOT, in the test, does not name
                                              with its reason
```

What exceeds a limit today -- modules, classes, functions and directories past their size, the
outward imports -- is listed in
`package_layout.json` under `frozen` with its size, and may only shrink: nothing new may join a list
and nothing on one may grow. Shrinking one is a one-line edit there; the test also fails when an
entry no longer applies, so the lists stay exact. The lists are being emptied (reviews
`21-MAINTAINABILITY.md`); when they are, every rule above holds with no exceptions.

## Adding a detection rule

Rules live in `src/cordon_scanner/rules/builtin/` as YAML and are data, not code:

```bash
cordon-scanner rules list                  # what exists
cordon-scanner rules show RULE.ID          # one rule in full
cordon-scanner rules test                  # every rule's own samples
```

Every rule declares at least one positive and one negative sample, and the
loader refuses a pack without them. A rule that parses, compiles, loads and
matches nothing is the failure a detection tool cannot see from the inside, so
the samples are what make an inert rule impossible to ship.

`confidence: high` additionally requires a zero baseline over `corpus/benign`.

Patterns are validated at load time and refused if they can backtrack
catastrophically. If yours is rejected, rewrite it rather than working around
the check: Python's `re` cannot be interrupted mid-match, so nothing downstream
can bound a pathological pattern.

## Reporting a false positive

Open an issue with the smallest file that triggers it and the output of
`cordon-scanner rules show <RULE.ID>`. False positives are treated as seriously as
missed detections: a tool people mute is a tool that detects nothing.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under Apache-2.0, matching the project.
