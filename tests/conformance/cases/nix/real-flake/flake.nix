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
