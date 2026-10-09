{
  description = "Inputs from FlakeHub and from forge archives";

  inputs.nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # unstable Nixpkgs
  inputs.nix-select.url = "https://git.clan.lol/api/v1/repos/clan/nix-select/archive/3d1e3860bef36857a01a2ddecba7cdb0a14c35a9.tar.gz";
  inputs.tools.url = "https://gitlab.com/acme/platform/tools/-/archive/v2.1.0/tools-v2.1.0.tar.gz";

  outputs = { self, nixpkgs, ... }: { };
}
