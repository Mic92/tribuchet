# systemd-nsresourced: leases UID/GID ranges to unprivileged processes.
#
# nixpkgs builds systemd without vmlinux.h, so nsresourced lacks its BPF-LSM
# part and refuses to delegate. Rebuild systemd with a vmlinux.h extracted
# from the configured kernel until nixpkgs#404864 lands.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.nsresourced;
  kernel = config.boot.kernelPackages.kernel;

  vmlinuxH =
    pkgs.runCommand "vmlinux.h"
      {
        # extract-vmlinux needs readelf and the kernel image's decompressor.
        nativeBuildInputs = with pkgs; [
          bpftools
          binutils
          zstd
          xz
          gzip
        ];
      }
      ''
        ${kernel.dev}/lib/modules/${kernel.modDirVersion}/source/scripts/extract-vmlinux \
          ${kernel}/${kernel.target} > vmlinux
        mkdir $out
        bpftool btf dump file vmlinux format c > $out/vmlinux.h
      '';
in
{
  options.services.nsresourced = {
    enable = lib.mkEnableOption "systemd-nsresourced user namespace delegation";
  };

  config = lib.mkIf cfg.enable {
    systemd.package = lib.mkDefault (
      pkgs.systemd.overrideAttrs (old: {
        mesonFlags = old.mesonFlags ++ [
          "-Dvmlinux-h=provided"
          "-Dvmlinux-h-path=${vmlinuxH}/vmlinux.h"
        ];
      })
    );

    systemd.additionalUpstreamSystemUnits = [
      "systemd-nsresourced.socket"
      "systemd-nsresourced.service"
    ];

    # Also needs the BPF LSM (in security.lsm by default).
    systemd.sockets.systemd-nsresourced.wantedBy = [ "sockets.target" ];
  };
}
