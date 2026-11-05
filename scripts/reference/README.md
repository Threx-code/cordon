# Measuring against the reference

Cordon's rule engine (cordon-rule) is its own code. It claims to give the same answers as YARA, the
engine whose rule-file format it reads, and these tools are how that claim is measured. They need the
reference installed, yara-python 4.5.1, so they are not part of Cordon: nothing under `src/` or
`tests/` imports the reference, and a repository test fails if anything does
(`tests/unit/repository/test_reference_boundary.py`).

Each tool runs once, by a maintainer, inside Docker, when what it measures changes. What it records
is committed, and the tests replay those recordings without the reference.

| tool | measures | records |
|---|---|---|
| `rule_pack_evaluate.py` | the built-in rule pack on both engines, over the benign and malicious corpora | `MEASUREMENT.json` beside the pack |
| `rule_pack_select.py` | which upstream rules the pack keeps, from that measurement | `cordon-builtin.yar` and `MANIFEST.json` |
| `record_binary_modules.py` | the `pe`, `elf` and `dotnet` module values on the malformed set derived from the benign fixtures | `tests/unit/data/rule_reference/modules/malformed.json` |
| `function_args.py` | the per-file arguments that hit something in each benign fixture (a real import, export, section, address), found with Cordon's own reader | the arguments `function_differential.py` calls with |
| `function_differential.py` | the module functions on both engines, and keeps the reference's output only when it equals Cordon's | `tests/unit/data/rule_reference/modules/functions.json` |

The benign fixtures, their licences and the other recorded values are described in
`tests/unit/data/rule_reference/modules/README.md`.

A typical run, from the repository root:

    docker run --rm -v "$PWD:/pkg" -w /pkg python:3.12-slim sh -c \
      "pip install -q yara-python==4.5.1 && python scripts/reference/record_binary_modules.py \
       tests/unit/data/rule_reference/modules tests/unit/data/rule_reference/modules/malformed.json"
