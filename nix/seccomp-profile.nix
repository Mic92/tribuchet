# Podman's default profile plus the namespace and mount syscalls the
# build sandbox needs. They are stripped from the existing rules first
# because the default carries explicit EPERM rules for some of them.
{
  runCommand,
  jq,
  podman,
}:
runCommand "tribuchet-seccomp.json" { nativeBuildInputs = [ jq ]; } ''
  jq '[
    "clone",
    "clone3",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "mount",
    "mount_setattr",
    "move_mount",
    "open_tree",
    "pivot_root",
    "setdomainname",
    "sethostname",
    "setns",
    "umount",
    "umount2",
    "unshare"
  ] as $sandbox
  | .syscalls |= [
      (.[] | .names -= $sandbox | select(.names != [])),
      { names: $sandbox, action: "SCMP_ACT_ALLOW" }
    ]' ${podman.src}/vendor/go.podman.io/common/pkg/seccomp/seccomp.json > $out
''
