#!/bin/sh
# Regenerates the real-world Nix conformance case: a flake whose inputs are a nixpkgs branch from
# GitHub, flake-utils, home-manager made to follow nixpkgs, an indirect input resolved through the
# flake registry, a git repository that is not a flake, and a tarball -- locked by `nix flake lock`.
# Nix's own `nix flake metadata --json` is the authoritative inventory. Nothing in the flake is
# evaluated beyond its inputs, and nothing is built. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" nixos/nix:2.24.10 sh /conformance/generate/nix.sh
#   docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/nix_inventory.py
set -eu
OUT=/conformance/cases/nix/real-flake
export NIX_CONFIG="experimental-features = nix-command flakes"
rm -rf /tmp/f && mkdir -p /tmp/f && cd /tmp/f
cat > flake.nix <<'EOF'
{
  description = "A conformance fixture";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    home-manager = {
      url = "github:nix-community/home-manager/release-24.05";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Resolved through the flake registry when the lock was made.
    nixpkgs-unstable.url = "nixpkgs";
    hello-src = {
      url = "git+https://git.savannah.gnu.org/git/hello.git?ref=master";
      flake = false;
    };
    gitignore = {
      url = "https://github.com/hercules-ci/gitignore.nix/archive/637db329424fd7e46cf4185293b9cc8c88c95394.tar.gz";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, ... }: flake-utils.lib.eachDefaultSystem (system: {
    packages.default = nixpkgs.legacyPackages.${system}.hello;
  });
}
EOF
git init -q . && git add flake.nix
nix flake lock >/tmp/lock.log 2>&1 || { tail -20 /tmp/lock.log; exit 1; }
rm -rf "$OUT" && mkdir -p "$OUT"
cp flake.nix flake.lock "$OUT/"
nix flake metadata --json > /tmp/metadata.json 2>>/tmp/lock.log
cp /tmp/metadata.json "$OUT/authoritative.raw.json"
cat flake.lock | head -80
echo done
