# YARA's own test cases

`yara-4.5.1-test-rules.json` holds the cases of YARA's test suite (`tests/test-rules.c` at tag
`v4.5.1`, https://github.com/VirusTotal/yara) whose rule and data are literals: each rule, its data
(base64) and what YARA asserts -- that it matches, that it does not, or that it does not compile.
Extracted mechanically, unmodified; BSD 3-Clause (`LICENSE` here).

Cordon's YARA engine (`detect/binary/yara_lang`) is held to every one of them, with the external
variables YARA's harness defines (`var_zero`, `var_one`, `var_true`, `var_false`).
