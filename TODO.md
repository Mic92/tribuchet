# TODO

- Reaper status files are keyed by pid: a recycled pid can make the
  spawn path delete a finished build's not-yet-consumed exit status,
  which is then reported as a timeout. Key statuses by a per-spawn
  token instead.

- ResultAck and CancelBuild match the registry by build_id, which a
  concurrent resume rotates: a stale id means the ack is dropped (the
  build dir lingers until the TTL) or the cancel is lost. Match by
  dedupe key, or accept any build_id the entry has carried.

- With `reloadIfChanged`, changing worker command-line options (e.g.
  --max-jobs) only reloads the unit, and the reaper re-execs with its
  original argv, so the change silently never applies until a manual
  restart. Either restart on argv changes (reloadTriggers on the
  package only) or have the reaper pick up new argv on reload.

- Support launchd socket activation for the hub on macOS: adopt
  listeners via `launch_activate_socket()` (the launchd analogue of
  systemd's `LISTEN_FDS`) so hub restarts keep the attach socket and
  worker port accepting, with clients queueing in launchd instead of
  seeing ECONNREFUSED. Until then, macOS hubs self-bind and clients
  rely on reconnect-with-backoff to cover the restart gap.
