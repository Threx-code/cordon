{
  description = "Inputs written every way a flake allows";

  # Dotted paths at the top level, and an unquoted URI (the old syntax, still accepted).
  inputs.nixpkgs.url = github:NixOS/nixpkgs/b134951a4c9f3c995fd7be05f3243f8ecd65d798;
  inputs.devenv = {
    url = "github:cachix/devenv/v1.3.1";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.shared.url = "path:../shared";
  inputs.dynamic.url = "github:acme/${"interpolated"}";

  outputs = { self, nixpkgs, devenv, ... }@inputs:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = with pkgs; mkShell { packages = [ hello ]; };
    };
}
