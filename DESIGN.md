# tribuchet — remote build execution for Nix

RBE-style remote builder service driven by Nix's experimental
`external-builders` feature. A shim on the client machine receives the
build environment from Nix as JSON, forwards it to a local hub, which
schedules the build on a remote worker that executes the builder inside
its own sandbox.

## Why not the build-hook / `--builders` protocol?

The classic remote build protocol requires SSH reachability, nix on every
worker, and copies the full closure each time without a scheduler. The
external-builders interface gives us the complete, already-rewritten build
environment (builder, args, env, input closure, scratch output paths) and
lets us own transfer, scheduling, and execution.

## Key insight: scratch paths are identical on both sides

Nix hands the external builder *scratch* output paths and expects them to
be populated on exit. The worker sandbox writes to the very same scratch
paths; the shim unpacks the returned NARs at those paths unchanged. Nix
then performs self-reference rewriting, hashing, and registration itself.
No store-path rewriting in tribuchet, no drvPath needed, and the worker
does not need a Nix installation at all.

## Components (single binary, subcommands)

```
nix-daemon (external-builders) ──exec──> tribuchet attach
                                              │ unix socket
                                              ▼
                                       tribuchet hub        (same machine as nix-daemon)
                                       - queue per system, in-flight dedupe
                                       - reads input paths directly from /nix/store
                                       - NAR transfer with zstd, per-worker have/missing
                                              ▲
                                              │ gRPC over mTLS, worker dials in (NAT-friendly)
                                       tribuchet worker     (2–10 machines, internet)
                                       - input cache keyed by store path
                                       - own sandbox (Linux namespaces / macOS sandbox_init)
                                       - signs output NARs with ed25519
tribuchet ca                           - init CA, issue worker/hub certificates
```

## Build flow

1. Nix invokes `tribuchet attach <build.json>`. The shim parses build.json
   (version 1: builder, args, env, inputPaths, outputs, system, topTmpDir,
   tmpDirInSandbox) and submits a build request to the hub over a unix
   socket. The request carries the `topTmpDir` *path*; the hub (which runs
   as root next to nix-daemon) tars its contents itself, because
   structured attrs / `passAsFile` place files there that env refers to
   via `tmpDirInSandbox` (`/build/.attrs.json` etc.). Since the hub reads
   that directory off local disk, it first verifies the directory is
   owned by the connecting peer (SO_PEERCRED) — a client cannot point the
   hub at someone else's files.
2. Hub validates the request (store dir pinned to `/nix/store`, store-path
   basenames restricted to Nix's name charset, absolute builder,
   `tmpDirInSandbox` pinned to `/build`, no duplicate or input-aliasing
   outputs) and dedupes by a hash of the full request: a second identical
   request attaches to the in-flight build's log and result, and a
   *different* request claiming an in-flight scratch path is rejected.
   Otherwise it queues the request for a worker matching `system` (and
   later: required features). A system no connected worker serves is
   rejected immediately; otherwise submitters block and Nix's max-jobs
   bounds parallelism.
3. Path negotiation: hub sends the input path list; worker answers with
   the missing subset; hub streams those as zstd-compressed NARs read
   straight from the local /nix/store (hub is colocated with the daemon,
   all inputs are valid locally).
4. Worker materializes inputs in its cache, constructs the sandbox, and
   executes `builder args…` with the env from build.json, cwd
   `/build`. Logs stream back live through hub to the shim's stdout/stderr
   (Nix shows them as ordinary build output).
5. On success the worker NAR-packs every scratch output path (bounded in
   size and by the build deadline), signs the NAR hashes with its
   ed25519 key, and streams them back. The *hub* verifies each signature
   against the worker's registered key (optionally pinned, see Security)
   while relaying the compressed chunks. The shim unpacks into a temp
   path next to each scratch path and renames into place only after the
   verified end-of-stream event, then exits 0. Builder failure ⇒ shim
   exits with the builder's status; Nix reports a normal build failure.

## Sandbox

We re-implement the sandbox rather than requiring Nix on workers.
Reference implementations: `nix/src/libstore/unix/build/` and
`nix/src/libstore/darwin/build/sandbox-defaults.sb`.

* Linux: `unshare(CLONE_NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS)` (plus NEWNET
  unless fixed-output), then a fork so the builder execs as PID 1 of the
  new PID namespace — its death kills every descendant, so daemonized
  builder children cannot outlive the build. Input paths are bind-mounted
  read-only (`MS_NOSUID|MS_NODEV`) at their store paths inside a private
  root, scratch outputs are created in a writable store dir, the shipped
  tmp dir is bind-mounted at `tmpDirInSandbox`, minimal `/dev` (nodes,
  `/dev/shm` tmpfs, devpts), fresh `/proc`, loopback brought up, stub
  `/etc/passwd`, then `pivot_root` + detach of the old root. The uid is
  remapped via the user namespace (no separate build uid yet). When the
  worker's cgroup is delegated (systemd `Delegate=yes`), each build runs
  in its own cgroup with `pids.max` (and optional `memory.max`), torn
  down via `cgroup.kill`. `--sandbox-bin-sh` binds a static shell at
  `/bin/sh` like Nix's busybox sandbox path. Builds requiring the
  `uid-range` system feature get a disjoint 65536-uid block (Nix's
  auto-allocate-uids scheme, root worker required), run as in-namespace
  root, and see their own delegated cgroup subtree at `/sys/fs/cgroup`
  — enough for systemd-nspawn inside the sandbox.
* macOS: no mount namespace, so inputs are materialized in the host
  /nix/store, `/build` is a symlink to the build dir, and the builder
  runs under `/usr/bin/sandbox-exec` with a deny-default write profile
  modeled on Nix's `sandbox-defaults.sb` (reads stay permissive except
  for the worker's key material; writes are scoped to the build dir,
  outputs, and specific device nodes; signals are limited to the
  sandbox).
* Fixed-output derivations are detected via the `outputHash` env var —
  or, under `__structuredAttrs`, inside the `__json` env blob — and get
  network access (no NEWNET on Linux, network allowance in the macOS
  profile).

Accepted tradeoffs: no recursive-nix, sandbox parity is ours to maintain,
trusted worker pool assumed (output authenticity still enforced via
signatures).

## Security

* Transport: mTLS; `tribuchet ca` issues the CA and per-worker certs
  (finite validity: 10y CA, 2y leaves; no revocation yet — rotate the CA
  if a worker key leaks).
* Output authenticity: workers sign output NARs (ed25519); the hub
  verifies while relaying. By default the key is the one the worker
  registers over its mTLS session; with a `trusted-signing-keys` file in
  the hub config dir (one hex public key per line) registration is
  restricted to pinned keys, so a stolen TLS cert alone cannot serve
  validly-signed outputs.
* The attach socket is group-restricted to `nixbld` (the hub refuses to
  start without that group). Request validation pins every client-chosen
  path; `topTmpDir` must be owned by the connecting peer.
* The worker validates everything the hub sends (build ids, store paths,
  builder, sandbox dir) before using it in filesystem operations — a
  compromised hub does not get filesystem primitives on workers.

## Scale & state

MVP targets 2–10 workers and a few clients: all scheduler state is in
memory (no database). The worker's input NAR cache is bounded
(`--cache-max-bytes`, LRU eviction, crash-safe completion markers); the
hub's replay buffer is capped at 256 MiB per build and slow dedupe
subscribers are dropped rather than buffered. The transfer protocol keeps a
`oneof` payload so a chunked CAS (FastCDC + blake3) can replace whole-NAR
streaming later without a protocol break.

## Known limitations (MVP)

* Dedupe is keyed on the scratch output set, which Nix randomizes per
  build attempt: it only catches concurrent duplicate submissions of the
  same goal, not the same derivation submitted twice. Proper dedupe
  needs a derivation identity in build.json (upstream patch).
* Workers run up to `--max-jobs` concurrent builds over one session;
  on macOS, builds sharing the daemon-pinned `/build` symlink are
  serialized per worker (no mount namespace to give each its own).
* A worker dying mid-build (detected via heartbeat silence and HTTP/2
  keepalive) fails the build instead of requeueing it.
* When a worker reconnects, the previous session's scheduler loop may
  still grab one job and fail it before noticing the closed channel.
* No build cancellation: Nix killing the attach process does not yet
  stop the remote build. A submission whose attach client is gone also
  stays queued until a matching worker picks it up.
* Dedupe attaches duplicates to the first attempt, so a transient
  failure propagates to all attached submitters (same as Buck2's RE
  dedupe behaviour).
* Inputs taken from the worker's host /nix/store are not protected by GC
  roots; a concurrent `nix-collect-garbage` on the worker can delete
  them mid-build.
* The Linux builder keeps the worker's kernel uid (remapped in the user
  namespace); there is no dedicated unprivileged build user yet.
* Input NARs are not verified against an expected content hash; the
  worker trusts the mTLS-authenticated hub for input content.

## Deployment (planned)

No NixOS modules or launchd plists ship yet; `nix/test.nix` contains
reference systemd units for hub and worker (the worker unit should set
`Delegate=yes` for per-build cgroup limits). macOS workers are a plain
binary (no nix required).
