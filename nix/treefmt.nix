{ pkgs, ... }:
{
  projectRootFile = "flake.nix";

  programs.rustfmt.enable = true;
  programs.nixfmt.enable = true;
  programs.ruff-format.enable = true;
  programs.ruff-check.enable = true;
  programs.actionlint.enable = true;
  programs.shellcheck.enable = true;

  settings.formatter.ast-grep = {
    command = "${pkgs.ast-grep}/bin/ast-grep";
    options = [ "scan" ];
    includes = [ "*.rs" ];
  };

  settings.global.excludes = [
    "*.lock"
    "*.patch"
    "target/*"
    "result/*"
  ];
}
