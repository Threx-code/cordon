# YARA's own test files and the values its test suite asserts on them

The reference engine's test programs (`tests/test-macho.c`, `tests/test-dex.c` in VirusTotal/yara at tag
v4.5.8, BSD-3-Clause) assert `macho` and `dex` module values on these files: two from `tests/data` and five
byte arrays from `tests/blob.h`, written out unchanged. `test_yara_assertions.py` replays every one of those
assertions through Cordon's readers, so the readers are held to values the reference itself is held to,
before the recorded-reference differential (which needs the reference image) runs.

| file | from | bytes | sha256 |
|---|---|---|---|
| `tiny-macho` | `tests/data/tiny-macho` | 4096 | e29e46cc91651a52fa2078e747890ea9ceb89ed9f2f024fb4b60e04f7454fd63 |
| `tiny-universal` | `tests/data/tiny-universal` | 24928 | 8917e8a4d33701d6c2f56f0acf62b9cad88abf48da394a5312fac0d0b93491bf |
| `macho_x86_file.bin` | `tests/blob.h` `MACHO_X86_FILE` | 1124 | f72b95cef1874d7c14228c1f3e0996eb75c6f7e3a3ec5e0659e7703818862e47 |
| `macho_ppc_file.bin` | `tests/blob.h` `MACHO_PPC_FILE` | 1780 | 858e110792cde08d12c7dfa8e12e44586224a3d445a0d3a4781cd817212279fb |
| `macho_x86_object_file.bin` | `tests/blob.h` `MACHO_X86_OBJECT_FILE` | 356 | 1e709abbdd3e0681166ea3611fc80a25f6fc184f0ed143b51d496a931a91e8cf |
| `macho_x86_64_dylib_file.bin` | `tests/blob.h` `MACHO_X86_64_DYLIB_FILE` | 812 | bf1907fec6d5ee364341b2bf3b7ddb0b5d37eaa9e102da5389b6afdcf816687c |
| `dex_file.bin` | `tests/blob.h` `DEX_FILE` | 656 | 94cfb4594a4b82fa29a1612f1c9260b728b58336bc797c48ccdd5e9d22fb93e7 |

Fetched 2026-10-31 from raw.githubusercontent.com at the tag; the byte arrays were decoded from their C
initialisers with no change.

`shared-100x100.dex` is Cordon's own crafted dex (100 class definitions pointing at one class data of
100 methods), the file the reference's quadratic class-data walk is measured on; it holds no third-party
bytes.

`reference-4.5.8.json` holds the reference's `macho` and `dex` module values for every file here, as
`yara -D` (YARA 4.5.8 built from source in the reference image) printed them, recorded once by
`scripts/reference/record_module_dumps.py` with each file's SHA-256; `test_yara_dumps.py` replays them
leaf by leaf without the reference. The crafted file is recorded as a digest of its 88,593 leaves, so the
one named divergence (the reference drops each class's last three methods) is pinned without storing
them.

`reference-x-1.21.0.json` holds YARA-X's `olecf`, `msi` and `vba` module values (`yr dump`, yara-x 1.21.0
in the reference image) for seven compound files the kit builds to the MS-CFB specification
(`FormatKit.cfb`: mini stream, mini FAT, cutoff 4,096) in `test_yarax_dumps.py`, which rebuilds them,
holds their hashes to the recorded ones and replays the values leaf by leaf. Those files are Cordon's
own bytes; a module YARA-X leaves out of a dump is the one whose flag is false here.

`reference-x-1.21.0-macho.json` holds YARA-X's `macho` values for the six Mach-O files above, replayed by `test_yarax_dumps.py`'s macho class against the superset the one `macho` name answers.
