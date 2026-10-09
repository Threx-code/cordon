{
  description = "payments service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    acme-tools.url = "github:acme/nix-tools/v1.4.0";
  };

  outputs = { self, nixpkgs, rust-overlay, acme-tools }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        overlays = [
          rust-overlay.overlays.default
          acme-tools.overlays.openssl-fips
          (import ./overlays/pinned-curl.nix)
          # (import ./overlays/disabled.nix)
        ];
      };
    in {
      packages.x86_64-linux.default = pkgs.hello;
    };
}
