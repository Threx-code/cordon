## What changes, and why

<!-- One paragraph. What was wrong or missing, and what this does about it. -->

## For a detection change

A rule change needs evidence on both sides, because a rule that fires on the
documented safe spelling is worse than no rule.

- [ ] It fires on the shape it is about
- [ ] It stays quiet on the careful spelling of the same thing
- [ ] Measured against real code, not only a sample -- say what, and how many

<!--
    Rule:      SUSPECT.EXAMPLE.001
    Measured:  247 repositories, 12 findings, all read by hand
    Before:    88 findings, 76 of them a lockfile comment
-->

## Checks

- [ ] `pytest -q` passes
- [ ] `ruff check src/ tests/` and `ruff format --check src/ tests/` pass
- [ ] `mypy src/cordon_scanner` passes
- [ ] `cordon-scanner rules test` passes, if a rule or sample changed
- [ ] `scripts/preflight.sh` if the change touches parsing, limits or output

`scripts/preflight.sh` runs the suite the way CI does, including the lint job,
in a clean export on three Python versions. It exists because a push that
passed locally still went red.

## Anything a reviewer should look at first

<!--
    A trade-off you made, a case you decided not to handle, a number you are
    unsure about. This section is the most useful one in the template.
-->
