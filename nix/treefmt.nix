{
  projectRootFile = "flake.nix";

  programs.rustfmt.enable = true;
  programs.nixfmt.enable = true;
  programs.ruff-format.enable = true;
  programs.ruff-check.enable = true;
  programs.actionlint.enable = true;
  programs.shellcheck.enable = true;

  settings.global.excludes = [
    "*.lock"
    "*.patch"
    "target/*"
    "result/*"
  ];
}
