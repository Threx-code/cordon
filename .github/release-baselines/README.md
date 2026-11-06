# Release baselines

`release.yml` compares each release's wheel with the one before it (`--compare-with`) and blocks on a
high finding. A file here, named for one version, is the project's reviewed acceptance of findings
that comparison reports for that release only: each entry names its rule, its path and why.

They exist because the judgement that a file is rule material is never applied inside a published
package: it is read from text the file's author writes, so an attacker could use it to lower their
own findings (fail-open audit, 2 Nov). A rule pack's samples are therefore reported in Cordon's own
wheel like anyone else's, and the acceptance comes from here, which the scanned package cannot
supply.

- `0.7.0.json`: the first release whose rule packs hold obfuscation-shaped positive samples
  (`capabilities-javascript.yaml`) after 0.6.0 had none, so `SUSPECT.RELEASE.NEW_OBFUSCATION.001`.
  From 0.8.0 the previous release has them too and the finding does not arise.

`tests/unit/repository/release/test_release_artefacts.py` holds every file here to that shape: only
`SUSPECT.RELEASE.NEW_OBFUSCATION.001`, only on a bundled rule pack, each entry with a reason.
