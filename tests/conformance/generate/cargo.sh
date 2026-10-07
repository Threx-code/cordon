#!/bin/sh
# Regenerates the real-world Cargo conformance case: cargo resolves a workspace and writes
# Cargo.lock, and `cargo metadata` (cargo's own reading of the resolution, every platform) is kept
# as the authoritative inventory. Nothing is built: `generate-lockfile` and `metadata` only.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" rust:1-slim sh /conformance/generate/cargo.sh
#
# A current toolchain: crates on the index now require edition 2024.
set -eu
OUT=/conformance/cases/cargo/real-workspace
apt-get update -qq >/dev/null && apt-get install -y -qq git python3 >/dev/null 2>&1
rm -rf /tmp/ws && mkdir -p /tmp/ws/crates/app/src /tmp/ws/crates/util/src && cd /tmp/ws
cat > Cargo.toml <<'EOF'
[workspace]
members = ["crates/app", "crates/util"]
resolver = "2"

[workspace.package]
edition = "2021"
rust-version = "1.74"

[workspace.dependencies]
anyhow = "1.0.89"
EOF
cat > crates/util/Cargo.toml <<'EOF'
[package]
name = "conformance-util"
version = "0.1.0"
edition.workspace = true

[dependencies]
anyhow = { workspace = true }
EOF
echo 'pub fn util() {}' > crates/util/src/lib.rs
cat > crates/app/Cargo.toml <<'EOF'
[package]
name = "conformance-app"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[dependencies]
serde = { version = "1.0.210", features = ["derive"] }
rand_core_alias = { package = "rand_core", version = "0.6.4" }
log = { version = "0.4.22", optional = true }
itoa = { git = "https://github.com/dtolnay/itoa", tag = "1.0.11" }
conformance-util = { path = "../util" }
anyhow = { workspace = true }

[target.'cfg(windows)'.dependencies]
winapi-util = "0.1.9"

[build-dependencies]
cc = "1.1.30"

[dev-dependencies]
tempfile = "3.13.0"

[features]
default = []
logging = ["dep:log"]
EOF
echo 'fn main() {}' > crates/app/src/main.rs
cargo generate-lockfile -q
# --all-features: Cargo.lock resolves every optional dependency whatever the features enabled, so
# the lockfile's content is cargo's resolution with all features on.
cargo metadata -q --format-version 1 --locked --all-features > /tmp/metadata.json
mkdir -p "$OUT/crates/app" "$OUT/crates/util"
cp Cargo.toml Cargo.lock "$OUT/"
cp crates/app/Cargo.toml "$OUT/crates/app/"
cp crates/util/Cargo.toml "$OUT/crates/util/"
python3 - "$OUT/authoritative.json" <<'PY'
import json, sys
meta = json.load(open("/tmp/metadata.json"))
found = sorted({f"{p['name']}@{p['version']}" for p in meta["packages"] if p.get("source")})
json.dump({"tool": "cargo metadata --format-version 1 --locked --all-features", "packages": found}, open(sys.argv[1], "w"), indent=1)
PY
head -c 400 Cargo.lock
echo

# Lockfile version 4: Cargo's current default, written when no rust-version holds it back.
OUT4=/conformance/cases/cargo/real-lock-v4
rm -rf /tmp/v4 && mkdir -p /tmp/v4/src && cd /tmp/v4
cat > Cargo.toml <<'EOF'
[package]
name = "lock-v4"
version = "0.1.0"
edition = "2021"

[dependencies]
itoa = "1.0.11"
EOF
echo 'fn main() {}' > src/main.rs
cargo generate-lockfile -q
mkdir -p "$OUT4"
cp Cargo.toml Cargo.lock "$OUT4/"
grep -m1 '^version' Cargo.lock
echo done
