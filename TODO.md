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
* `external-derivation-builder.cc` hard-rejects `recursive-nix` (line 38)
  and has no return channel: base-class `registerOutputs` scans outputs
  against `inputPaths ∪ scratchOutputs ∪ state_.addedPaths`, but
  `addedPaths` is populated only by the in-process recursive-nix
  machinery, so for external builders it is always empty and references
  to inner paths are silently dropped from the registered closure. A
  small Nix patch is required: drop the reject, read an optional
  `result.json` written by the external builder after exit, populate
  `addedPaths` from it.

### Plan

MVP: worker-local recursion with the proxy outside the privileged
process; cluster dispatch afterwards. Each commit compiles standalone
and is unit-tested where it has a seam.

Phase 0: Nix patch (prerequisite, opt-in)
- [ ] Maintain `nix/patches/recursive-nix-external-builders.patch`:
      drop the `recursive-nix` reject in
      `external-derivation-builder.cc`; after the child exits, if
      `topTmpDir/result.json` exists, parse its `addedPaths` array
      and insert each into `state_.addedPaths` before
      `registerOutputs` runs. The flake exposes
      `packages.${system}.nix-recursive` (stock nixpkgs Nix with the
      patch applied) and a NixOS/darwin module option
      `services.tribuchet.recursive-nix.enable` that swaps in that
      package; default deployments stay on stock Nix. Upstream
      proposal tracked separately.

Phase 1: routing and transport
- [ ] config: `recursive-nix` bool (default off); advertised in
      `local_features()` for native systems when set. (caps unit test)
- [ ] deps: `harmonia-store-ref-scan`, `harmonia-protocol`,
      `harmonia-daemon` at the pinned rev.
- [ ] proto: `BuildResult.extras: repeated ExtraPath { PathInfoMsg
      info; string signature }`. Hub verifies the worker signature
      against the recomputed NAR hash and registers each extra in the
      local store via its daemon pool (`AddToStoreNar`); `verify_set`
      stays strict on `outputs`. `FinishedBuild.extras` added (empty
      for now); `deliver()` sends it. (hub unit test)
- [ ] worker: tee output NARs through `RefScanSink` while packing
      (candidates: inputs ∪ scratch outputs); record refs on
      `PackedOutput`. (unit test)
- [ ] attach: after all outputs unpack, write `result.json` with
      `addedPaths = [extras]` next to `build.json` (received from the
      hub via a new `AttachEvent::AddedPath`). Phase 0 patch picks it
      up.

Phase 2: per-build proxy (worker-local)
- [ ] `worker/proxy.rs`: `DaemonStore` over a held host-daemon
      connection, gated by an allowed set (initially the outer input
      closure). Ops: SetOptions, IsValidPath/QueryValidPaths,
      QueryPathInfo, AddToStore, AddTempRoot/AddIndirectRoot (no-op),
      QueryMissing, BuildPaths(WithResults), NarFromPath,
      QueryDerivationOutputMap. AddToStore results and inner-build
      output closures join the allowed set. (unit test: gating)
- [ ] worker: for recursive builds, listen on `dir/top/.nix-socket`
      (visible at `/build/.nix-socket`), set `NIX_REMOTE` in the
      build env, spawn the proxy after the reaper returns the pid;
      tear it down with the build.
- [ ] Linux: bind-mount newly allowed paths into the sandbox via a
      forked child that setns()es into `/proc/<pid>/ns/{user,mnt}`
      (opened lazily on first injection: by then the build has
      connected, so unshare has happened). macOS: no-op.
- [ ] worker: after success, extras = closure(allowed-set additions
      referenced by any output) \ input closure; pack from
      `/nix/store`, query PathInfo, sign, fill `FinishedBuild.extras`.
- [ ] e2e `nix/tests/recursive.nix`: outer output references the
      inner output; client store ends up with the full closure and
      the registered output PathInfo lists the inner path.

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
