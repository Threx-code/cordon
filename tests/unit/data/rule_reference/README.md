# The reference suite

`reference-suite-rules.json` holds the test cases of YARA 4.5.1 (`tests/test-rules.c` at tag
`v4.5.1`, https://github.com/VirusTotal/yara) whose rule and data are literals: each rule, its data
(base64) and the outcome the suite asserts -- that it matches, that it does not, or that it does
not compile. Extracted mechanically, unmodified; BSD 3-Clause (`LICENSE` here).

cordon-rule (`detect/binary/rule_lang`) is held to every one of them, with the external variables
the suite's harness defines (`var_zero`, `var_one`, `var_true`, `var_false`).

`type-checking.json` records, for each condition of the typed battery in
`tests/unit/detect/binary/test_rule_lang.py` (`TypeChecking.cases()`, 20,007 of them: every
operator over every pairing of value kinds, and each construct that takes a typed operand), whether
yara-python 4.5.1 compiles it -- one bit per case. cordon-rule must compile exactly the same ones.
