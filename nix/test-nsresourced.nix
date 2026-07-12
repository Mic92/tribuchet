# systemd-nsresourced delegates a UID range to a user namespace owned by an
# unprivileged user (what the rootless worker will rely on).
{ nsresourcedModule }:
{ pkgs, ... }:
{
  name = "tribuchet-nsresourced";
  nodes.machine = {
    imports = [ nsresourcedModule ];
    services.nsresourced.enable = true;
    users.users.alice.isNormalUser = true;
    environment.etc."alloc-range.sh" = {
      mode = "0755";
      text = ''
        #!${pkgs.runtimeShell}
        set -e
        exec 2>&1
        exec ${pkgs.util-linux}/bin/unshare --user ${pkgs.runtimeShell} -ec '
          exec 3< /proc/self/ns/user
          varlinkctl call --push-fd=3 /run/systemd/io.systemd.NamespaceResource \
            io.systemd.NamespaceResource.AllocateUserRange \
            "{\"name\": \"test\", \"size\": 65536, \"target\": 0, \"userNamespaceFileDescriptor\": 0}"
          cat /proc/self/uid_map
        '
      '';
    };
  };
  testScript = ''
    machine.wait_for_unit("systemd-nsresourced.socket")

    out = machine.succeed("su - alice -c /etc/alloc-range.sh")
    print(out)
    assert "65536" in out, f"expected a 64K range in uid_map: {out}"
  '';
}
