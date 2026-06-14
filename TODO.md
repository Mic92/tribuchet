# TODO

## Recursive-nix support

Goal: builds with `requiredSystemFeatures = ["recursive-nix"]` can realise
further derivations from inside the sandbox, with a smaller trust surface
than upstream Nix: no full protocol server in a privileged process, no
unverified store registration, no build-driven setns.

### Background (upstream code, local prototype 2026-06-14)

* Upstream (`startDaemon()`, `restricted-store.cc`): the in-sandbox
  `.nix-socket` is served by the full worker-protocol server inside the
  privileged builder process, wrapping the local store in a
  `RestrictedStore`. A path/drv may be queried, dumped or built only if
  it is in the outer build's input closure or was added by an earlier
  recursive call; after an inner build, the closure of its outputs joins
  the allowed set. Inner .drvs and sources land in the real store via
  AddToStore; inner builds run as normal daemon goals (and may go to
  remote builders). New paths become visible in the chroot via a forked
  child that setns()es into the sandbox's user+mount namespace and
  bind-mounts (`addDependencyImpl`); without a chroot nothing is needed.
* Prototype build of a trivial recursive drv: the outer output references
  both the inner output and the inner .drv, so the closure delta to ship
  back includes AddToStore'd paths, not just inner outputs.
* Daemon ops a minimal inner `nix build --expr` issues: SetOptions(19),
  AddToStore(7), QueryPathInfo(26), QueryMissing(40),
  BuildPathsWithResults(46) plus the handshake. Out-links, fetchers and
  CA drvs add AddPermRoot/AddIndirectRoot, QueryValidPaths, AddTempRoot,
  NarFromPath, QueryDerivationOutputMap, QueryRealisation.
* harmonia (already a dependency) provides the server side:
  `harmonia-daemon` has the unix-socket connection loop and
  `harmonia_protocol::DaemonStore` defaults every op to `unimplemented`,
  so a deny-by-default proxy only implements the allowed methods.
* setns/bind-mount injection needs the sandbox's user+mount ns fds (today
  only the reaper-spawned setup process has them) and a forked child
  (setns(CLONE_NEWNS) fails in multithreaded processes). Not testable in
  this container (no CAP_SYS_ADMIN); verify in the e2e VM.

### Plan

MVP: worker-local recursion with the proxy outside the privileged
process. Cluster dispatch afterwards.

Phase 1: groundwork
- [ ] Feature routing: workers advertise `recursive-nix`, hub assigns such
      derivations only to advertising workers.
- [ ] Closure-delta upload: worker ships output references the client
      lacks (inner outputs, inner .drvs, added sources) as additional
      signed NARs; hub verifies and registers them like outputs.
- [ ] Keep the build's user+mount ns fds (or a pidfd) available to the
      worker/reaper for mount injection.

Phase 2: per-build proxy (MVP, worker-local)
- [ ] Per recursive build, spawn an unprivileged proxy (build's uid,
      Landlock/seccomp) on `$NIX_BUILD_TOP/.nix-socket` implementing
      `DaemonStore` for: SetOptions, QueryValidPaths/IsValidPath,
      QueryPathInfo (censored), AddToStore, AddTempRoot/AddIndirectRoot
      (no-ops), QueryMissing, BuildPaths(WithResults), NarFromPath,
      QueryDerivationOutputMap.
- [ ] Allowed-set bookkeeping as upstream: outer input closure + paths
      added by recursive calls; closure of inner outputs joins after a
      build.
- [ ] Forward allowed AddToStore/build requests to the worker host's
      nix-daemon; the proxy, not the build, is the only daemon client.
- [ ] Linux visibility: reaper (or a forked worker child) setns()es into
      the build's namespaces and bind-mounts newly allowed store paths,
      from a verified list keyed by build id. macOS: paths are already
      visible; only bookkeeping applies.
- [ ] e2e test: recursive derivation whose output references the inner
      output; client receives the full closure.

Phase 3: cluster dispatch (replaces forwarding to the host daemon)
- [ ] Proxy build requests travel worker -> hub as new session messages,
      tagged with parent build id, client identity, deadline.
- [ ] Hub schedules inner drvs like normal jobs; the originating worker
      (or the hub) serves their input closure, since inner drvs/sources
      exist nowhere else.
- [ ] Quotas: per-client in-flight caps, recursion depth limit,
      cancellation cascades parent -> children; release the parent's slot
      credit while it blocks on children.
- [ ] Decide where AddToStore'd paths live: worker store (simple) vs
      hub-side staging (cleaner trust, more transfer).

Phase 4: provenance and polish
- [ ] Hub logs the recursion chain (outer drv, inner drvs, signatures).
- [ ] e2e: cancellation cascade, depth limit, dedupe of identical inner
      builds across two outer builds.
- [ ] DESIGN.md: replace the "no recursive-nix" tradeoff with the new
      design and its trust boundary.

## Other

- [ ] fd-based NAR pack/unpack (currently path-based via
      harmonia-file-nar; see DESIGN.md known limitations). Needs an
      upstream change or a fork.
- [ ] Compile and test the macOS-only code paths on a real Mac
      (sandbox cleanup, seatbelt deny rules, launchd socket adoption);
      consider a darwin CI runner.
