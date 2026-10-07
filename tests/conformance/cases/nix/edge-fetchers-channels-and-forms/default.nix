{ pkgs ? import <nixpkgs> { } }:

let
  # Pinned: a revision and its hash.
  pinnedSrc = pkgs.fetchFromGitHub {
    owner = "BurntSushi";
    repo = "ripgrep";
    rev = "4649aa9700619f94cf9c66876e9549d83420e16c";
    hash = "sha256-HBuUu4WrYDXhLDIRV3NJcjVEiT5QDDOq9ZvhkDmEW4o=";
  };

  # A tarball of a branch: whatever the branch holds when it is fetched.
  rolling = builtins.fetchTarball "https://github.com/acme/nix-overlay/archive/main.tar.gz";

  # No revision at all.
  tools = builtins.fetchGit {
    url = "https://git.acme.example.internal/platform/tools.git";
    ref = "main";
  };
in
with pkgs;
assert lib.versionAtLeast lib.version "23.11";
stdenv.mkDerivation {
  pname = "edge";
  version = "1.0";
  src = pinnedSrc;
  shellHook = ''
    echo "${toString rolling} and ${tools}"
  '';
}
