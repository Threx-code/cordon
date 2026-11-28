# Homebrew captures (taken 2026-11-27)

Real brew output and one real bottle; `test_install_homebrew.py` serves them through the real planner.

| file | source | licence | how it was taken | sha256 |
|---|---|---|---|---|
| cowsay.bottle.tar.gz | https://ghcr.io/v2/homebrew/core/cowsay/blobs/sha256:345e99255a69e9cb188a5a8e6bd8e6f50c334830c8a72877fc6b504c95e5cbd1 | GPL-3.0-only (cowsay, per its formula) | the product's own RegistryImage client with a generic User-Agent; the blob, digest-checked | 345e99255a69e9cb188a5a8e6bd8e6f50c334830c8a72877fc6b504c95e5cbd1 |
| deps-jq.txt | `brew deps --formula --union jq` | BSD-2-Clause (Homebrew/homebrew-core formula metadata) | Homebrew 7.0.15 with HOMEBREW_NO_AUTO_UPDATE=1; as printed | 52e9eb43cbe7a0097980320700220d18e5a0e00e5ab2785b0b994b9268381bfb |
| info-cask-rectangle.json | `brew info --json=v2 rectangle` | BSD-2-Clause (Homebrew/homebrew-cask metadata) | Homebrew 7.0.15 with HOMEBREW_NO_AUTO_UPDATE=1; the fields naming what is installed on the machine were blanked, every other field is as printed | a00e673671dcfa51db1d7b590f274771eb9cf50fd4d4ef98482f6ebbbf5961ca |
| info-cowsay.json | `brew info --json=v2 cowsay` | BSD-2-Clause (Homebrew/homebrew-core formula metadata) | Homebrew 7.0.15 with HOMEBREW_NO_AUTO_UPDATE=1; the fields naming what is installed on the machine were blanked, every other field is as printed | 12dec71209cf07cf04c6167455ab35a9653db5dd58809da696a75ed2e4a419e1 |
| info-jq.json | `brew info --json=v2 jq oniguruma` | BSD-2-Clause (Homebrew/homebrew-core formula metadata) | Homebrew 7.0.15 with HOMEBREW_NO_AUTO_UPDATE=1; the fields naming what is installed on the machine were blanked, every other field is as printed | 7ddd9b98faa3afb25d1ea2271829daffc51ab7f6de27d2d5ebec54f0edfd0300 |
