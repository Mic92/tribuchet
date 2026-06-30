# Fixed-output probes: curl must resolve a hostname and complete a TLS
# fetch from inside the sandbox (pasta's forwarder on Linux, seatbelt's
# network* on macOS). runId keeps the store path uncached so the build
# really runs on the worker; the output is constant for the fixed hash.
{
  runId,
  systems,
  nixpkgs ? <nixpkgs>,
}:
let
  one = system: {
    name = system;
    value =
      let
        pkgs = import nixpkgs { inherit system; };
      in
      derivation {
        name = "tribuchet-e2e-fod-${system}-${runId}";
        inherit system;
        builder = "${pkgs.bash}/bin/bash";
        PATH = "${pkgs.curl}/bin";
        args = [
          "-c"
          "curl -sSf https://example.com > /dev/null && echo fod-dns-ok > $out"
        ];
        outputHashAlgo = "sha256";
        outputHashMode = "flat";
        # sha256 of "fod-dns-ok\n"
        outputHash = "sha256-LB7J/GiffOgGvs4AiiLQLQAZmwnM5dBnExXUtjgF0IA=";
      };
  };
in
builtins.listToAttrs (map one systems)
