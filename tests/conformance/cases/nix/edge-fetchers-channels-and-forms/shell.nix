let
  nixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/b134951a4c9f3c995fd7be05f3243f8ecd65d798.tar.gz";
    sha256 = "1m9sf8ajc6s4a8yidp0bkyvqzv1fvmx5a6fd8bl9frmlbbh0a52m";
  };
  pkgs = import nixpkgs { };
in
pkgs.mkShell { packages = [ pkgs.jq ]; }
