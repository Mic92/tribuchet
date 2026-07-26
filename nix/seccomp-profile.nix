# Podman's default profile plus the sandbox rule from
# seccomp-additions.json. The syscalls are stripped from the existing
# rules first because the default carries explicit EPERM rules for
# some of them.
{
  runCommand,
  jq,
  podman,
}:
runCommand "tribuchet-seccomp.json" { nativeBuildInputs = [ jq ]; } ''
  jq --slurpfile add ${./seccomp-additions.json} '
    $add[0].names as $sandbox
    | .syscalls |= [
        (.[] | .names -= $sandbox | select(.names != [])),
        $add[0]
      ]' ${podman.src}/vendor/go.podman.io/common/pkg/seccomp/seccomp.json > $out
''
