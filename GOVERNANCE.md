# Governance

## What this project optimises for

A security scanner has one failure mode that matters more than the others: a
rule stops matching, the scan still succeeds, and the gate is green precisely
because the check is broken. Everything below follows from trying not to do
that.

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │  A CHANGE GETS IN WHEN                                               │
   │                                                                      │
   │    it is measured          not "this looks like a false positive"    │
   │       │                    but "247 repositories, 12 findings,       │
   │       │                     all read by hand"                        │
   │       ▼                                                              │
   │    it proves both sides    the shape is reported AND the careful     │
   │       │                    spelling of the same thing is not         │
   │       ▼                                                              │
   │    it says why in place    the comment outlives the reviewer, and    │
   │       │                    the next person needs the reasoning       │
   │       ▼                                                              │
   │    the suite agrees        every platform, every supported Python    │
   └──────────────────────────────────────────────────────────────────────┘
```

## Who decides

Maintainers are listed in the repository's contributor graph and on the commits.
Today that is a small group; decisions are made by whoever reviews, in public,
on the pull request.

Disagreements are resolved by evidence rather than by seniority. If two people
disagree about whether a rule is too noisy, the answer is a measurement over
real repositories, not a longer argument. The project ships
`scripts/measure_noise.py` and a corpus list so that anybody can produce one.

## What needs more than a review

| Change | What it needs |
|---|---|
| A new detection rule | Samples on both sides, and a noise measurement |
| Raising a rule's severity | Evidence that the higher severity is right in every case it fires |
| Anything that changes what fails a build | A `CHANGELOG` entry saying so plainly, because somebody's pipeline will change colour |
| A new ecosystem | Manifest and lockfile parsing, advisory coverage, and a row in `docs/07-ECOSYSTEMS.md` |
| Removing a rule | The measurement that says it was wrong, kept in the commit message |

## Releases

Versions follow semantic versioning. A release is cut from `main` when the
changelog has something worth shipping, not on a schedule.

Releases are signed and carry SLSA provenance. The bundled advisory database
and the generated infrastructure policy set ship inside the signed artefact,
with a digest manifest, so that editing one after the fact means editing a
signed archive.

## Bundled data

Two things ship as data rather than as code: the OSV advisory snapshot and the
infrastructure policy set generated from provider schemas. Both are refreshed
by scheduled workflows that open a pull request rather than committing, because
they decide what a scan reports and a human should see the diff.

A scan says how old its data is, and says so loudly once it passes the staleness
window. Data that nobody refreshes is the quiet version of a rule that stopped
matching.

## Forking

Apache 2.0. Fork it, ship it, sell it. The one thing worth asking: if you
change a detection rule, change the tests that prove it, and keep the reasoning
in the comment. The comments are the part that is expensive to rebuild.
