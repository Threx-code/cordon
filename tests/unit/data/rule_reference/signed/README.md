# Two real signed files, recorded by both references

The certificate paths of `msi` and `macho` are held to real signed files: GitHub CLI v2.102.0's release
assets (MIT, Copyright 2019 GitHub Inc., https://github.com/cli/cli/releases/tag/v2.102.0). They are too
large to keep in the repository, so only their recorded dumps are here, each with the file's SHA-256; the
files live in the Docker volume `cordon-signed-fixtures` with the release's checksums file and a
PROVENANCE.tsv, and `test_signed_fixtures.py` reads them from the directory `CORDON_SIGNED_FIXTURES`
names (skipped, and saying why, without it).

| file | what | bytes | sha256 |
|---|---|---|---|
| `gh_2.102.0_windows_386.msi` | the release asset, a version 4 compound file with an Authenticode signature, signed metadata and a Microsoft timestamp | 15118336 | 9d7cd7f991622fdf98401e2bf41d3449e9471e8e75fa70812ca814174a852d07 |
| `gh-macos-arm64` | `bin/gh` from `gh_2.102.0_macOS_arm64.zip` (sha256 da922c20d1792e5b2cbf375593d7a658acf034c12c84e007e71c76ef959c337e), a notarised Mach-O with a code signature of three certificates | 39834784 | 8a4258433c81106343144857750316241759d06dcf16265cf3c4864a8f2f2ad6 |

The installer's SHA-256 is the one the release's checksums file publishes; the binary's archive's is too.

`reference-4.5.8.json` is `yara -D` (YARA 4.5.8 built from source in the reference image) over the binary
with a rule importing `macho`; `reference-x-1.21.0.json` is `yr dump --output-format=json` (YARA-X 1.21.0)
over both files, every module it names. Both were recorded once, on 2026-10-31, by
`scripts/reference/record_module_dumps.py`:

    yara -D macho.yar gh-macos-arm64 > yara/gh-macos-arm64.macho.yara.txt
    yr dump --output-format=json gh-macos-arm64 > yr/gh-macos-arm64.json
    yr dump --output-format=json gh_2.102.0_windows_386.msi > yr/gh_2.102.0_windows_386.msi.json
    python scripts/reference/record_module_dumps.py yara <files> tests/unit/data/rule_reference/signed/reference-4.5.8.json
    python scripts/reference/record_module_dumps.py yr <files> tests/unit/data/rule_reference/signed/reference-x-1.21.0.json

The binary carries no entitlements, so the entitlements path is not exercised here.
