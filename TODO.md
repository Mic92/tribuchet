# TODO

## Recursive-nix support

Goal: builds with `requiredSystemFeatures = ["recursive-nix"]` can realise
further derivations from inside the sandbox, with a smaller trust surface
than upstream Nix (no hole into a root daemon, no unverified store
registration, no build-driven setns).

Architecture: the in-sandbox `NIX_REMOTE` socket terminates in an
unprivileged per-build proxy; recursive build requests are re-submitted
through the hub as ordinary jobs; verified results are imported into the
worker store and exposed to the running sandbox; the outer output's upload
ships the closure delta.

### Phase 1: groundwork

- [ ] Feature routing: workers advertise `recursive-nix` in their hello,
      hub only assigns such derivations to advertising workers
      (extend the existing system/feature matching).
- [ ] Closure-delta upload: outputs may reference store paths the client
      does not have. Worker computes the references closure of each
      output, ships missing paths as additional signed NARs, hub verifies
      and registers them like outputs. (Useful on its own for builds that
      reference newly imported inputs.)
- [ ] Hub: cap and account per-client in-flight jobs so a recursing build
      cannot submit unbounded work; cancellation of a parent job cascades
      to its children; recursion depth limit.

### Phase 2: per-build proxy (worker side)

- [ ] Spawn an unprivileged proxy process per recursive-capable build:
      runs as the build's uid, Landlock/seccomp-restricted, listens on
      `$NIX_BUILD_TOP/.nix-socket`, holds only a channel scoped to its
      build id (no daemon connection, no ambient authority).
- [ ] Implement the minimal daemon-protocol subset recursive nix actually
      uses (addToStore, buildPaths/buildDerivation, queryPathInfo /
      isValidPath for paths the build introduced); reject every other
      opcode. Pin the protocol version.
- [ ] Alternative/stopgap to protocol compatibility: a `tribuchet
      recursive-build <drv>` CLI shim mounted into the sandbox for users
      who do not need `nix build` proper.

### Phase 3: dispatch and result injection

- [ ] Worker forwards proxy build requests to the hub over its existing
      session (new message pair), tagged with the parent build id and the
      submitting client's identity, deadline and quota.
- [ ] Results: hub-verified output paths are imported into the worker
      store via the existing import path; the build's allowed-path set is
      extended only with these verified paths.
- [ ] Linux sandbox visibility: the reaper bind-mounts the new store
      paths into the running build's mount namespace; it accepts only
      store paths from the worker (validated list keyed by build id),
      never paths named by the build itself. Investigate a per-build
      store view (overlay upper) so inner results stay out of the shared
      worker store until verified.
- [ ] macOS: store paths are already visible at their real locations;
      only the allowed-path bookkeeping applies.
- [ ] Scheduling: a parent blocked on children must not deadlock the
      cluster; release the parent's slot credit while it waits, or give
      child jobs scheduling priority.

### Phase 4: provenance and polish

- [ ] Hub logs the recursion chain (outer drv, inner drvs, signatures)
      and exposes it in the build log / attach output.
- [ ] e2e test: derivation that recursively builds another derivation and
      references its output; cancellation cascade test; depth-limit test.
- [ ] DESIGN.md: replace the "no recursive-nix" tradeoff with the new
      design and its trust boundary.

## Other

- [ ] fd-based NAR pack/unpack (currently path-based via
      harmonia-file-nar; see DESIGN.md known limitations). Needs an
      upstream change or a fork.
- [ ] Compile and test the macOS-only code paths on a real Mac
      (sandbox cleanup, seatbelt deny rules, launchd socket adoption);
      consider a darwin CI runner.
