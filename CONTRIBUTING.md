# Contributing

## Getting set up

```bash
git clone https://github.com/Threx-code/cordon
cd cordon
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

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
