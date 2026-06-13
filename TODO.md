# TODO


- Support launchd socket activation for the hub on macOS: adopt
  listeners via `launch_activate_socket()` (the launchd analogue of
  systemd's `LISTEN_FDS`) so hub restarts keep the attach socket and
  worker port accepting, with clients queueing in launchd instead of
  seeing ECONNREFUSED. Until then, macOS hubs self-bind and clients
  rely on reconnect-with-backoff to cover the restart gap.
