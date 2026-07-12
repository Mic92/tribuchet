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
No store-path rewriting in tribuchet and no drvPath needed. Workers run a
nix-daemon of their own: inputs are imported through it (AddToStoreNar),
so they are registered in the worker's Nix database and protected from
GC by per-build temp roots. The worker must be a trusted daemon user
(imports skip signature checks; transport authenticity comes from mTLS).

## Components (single binary, subcommands)

![Architecture](docs/architecture.svg)

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
   outputs) and dedupes by a hash of the request minus the per-attempt
   `topTmpDir`. Nix derives the scratch outputs deterministically from
   the drvPath, so submissions of the same derivation hash identically:
   a matching request attaches to the in-flight build's log and result,
   while a *different* request claiming an in-flight scratch path is
   rejected.
   Otherwise it queues the request for a worker matching `system` (and
   later: required features). A system no connected worker serves is
   rejected immediately; otherwise submitters block and Nix's max-jobs
   bounds parallelism.
3. Path negotiation: hub sends the input path list; the worker asks its
   local nix-daemon (taking temp roots so GC cannot race the build) and
   answers with the missing subset; the hub streams those as
   zstd-compressed NARs plus their Nix db metadata (hash, size,
   references, via the daemon protocol) read from the local store (hub is
   colocated with the daemon, all inputs are valid locally).
4. Worker imports missing inputs through its nix-daemon (which verifies
   the NAR hash and registers the path), constructs the sandbox, and
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

We re-implement the sandbox rather than driving builds through the
worker's Nix (its daemon serves only as the input store).
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
  in its own cgroup with an optional `memory.max`, torn
  down via `cgroup.kill`. `--sandbox-bin-sh` binds a static shell at
  `/bin/sh` like Nix's busybox sandbox path. Builds requiring the
  `uid-range` system feature get a disjoint 65536-uid block (Nix's
  auto-allocate-uids scheme, root worker required), run as in-namespace
  root, and see their own delegated cgroup subtree at `/sys/fs/cgroup`
  — enough for systemd-nspawn inside the sandbox. `--emulate
  system=/path/to/static-qemu` advertises foreign systems; such builds
  get the emulator bound into the sandbox and registered in a per-userns
  binfmt_misc instance (kernel 6.7+); a nested user namespace drops the
  registration-time root back to uid 1000 for the build. On root
  workers with `/dev/net/tun`, fixed-output builds get a private
  network namespace with user-mode NAT (the embedded
  [presto-pasta](https://github.com/Mic92/presto-pasta) datapath, run
  by a helper process that drops to an unprivileged uid) instead of
  the host namespace: host abstract sockets and loopback services are
  unreachable. The worker's `[fod-network]` setting adds an ordered
  allow/deny rule list (destination CIDR or the `private` keyword,
  protocol, ports/port ranges; first match wins) evaluated for every
  outbound connection of such builds.
* macOS: no mount namespace, but inputs already live at their real
  /nix/store paths thanks to the daemon import; the worker's own
  per-build dir becomes the cwd and env values referencing the hub's
  `tmpDirInSandbox` (e.g. `/build` from a Linux hub) are rewritten to
  it, so no symlink is created at a hub-chosen path. The builder runs
  under `/usr/bin/sandbox-exec` with a deny-default write profile
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

* Transport: mTLS by default; `tribuchet ca` issues the CA and
  per-worker certs (finite validity: 10y CA, 2y leaves; no revocation
  yet — rotate the CA if a worker key leaks). With `auth =
  "tailscale"` the listener runs plaintext and the hub asks
  tailscaled's LocalAPI `whois` for the peer's node name and ACL tags
  on each session, so WireGuard provides confidentiality/integrity
  and the tailnet provides identity (optionally gated to
  `tailscale-allowed-tags`).
* Output authenticity: workers sign output NARs (ed25519); the hub
  verifies while relaying. By default the key is the one the worker
  registers over its authenticated session; with a `trusted-signing-keys` file in
  the hub config dir (one Nix-format `name:base64` public key per line,
  same syntax as nix.conf `trusted-public-keys`) registration is
  restricted to pinned keys, so a stolen transport credential alone
  cannot serve validly-signed outputs.
* The attach socket is group-restricted to `nixbld` (the hub refuses to
  start without that group). Request validation pins every client-chosen
  path; `topTmpDir` must be owned by the connecting peer.
* The worker validates everything the hub sends (build ids, store paths,
  builder, sandbox dir) before using it in filesystem operations — a
  compromised hub does not get filesystem primitives on workers.

## Scale & state

MVP targets 2–10 workers and a few clients: all scheduler state is in
memory (no database). The hub's replay buffer is capped at 256 MiB per
build and slow dedupe subscribers are dropped rather than buffered. The
transfer protocol keeps a `oneof` payload so a chunked CAS (FastCDC +
blake3) can replace whole-NAR streaming later without a protocol break.

Hub restarts cancel nothing, without any state handoff: on SIGTERM the
hub exits immediately and the replacement reconstructs its state from
the edges. Workers re-register and announce the dedupe keys of builds
they still hold (running, or finished but undelivered); attach clients
reconnect and resubmit the identical request, whose deterministic
dedupe key routes it back to the worker holding the build, which
resumes (or just re-delivers the finished result) instead of building
again.

Worker redeploys go through reload (SIGHUP to the unit): builds are
children of a small reaper process the worker is exec'd by, with
resume state and logs persisted in their build dirs, so the reaper
just execs a fresh worker that re-adopts them — running builds are
supervised to completion, finished ones redelivered. The hub covers
the session gap by requeueing instead of failing jobs whose worker
session died; the attached client sees a pause, not an error. A full
stop (SIGTERM) does not drain: the unit teardown takes the reaper and
the build processes with it, and the requeued jobs fail once no
capable worker is left (or get rebuilt by another one).

## Known limitations (MVP)

* Workers run up to `max-jobs` concurrent builds over one session.
* The hub's tmp-dir tar and the worker's unpack walk their trees
  through directory fds with O_NOFOLLOW, but NAR pack/unpack go through
  harmonia-file-nar, which resolves paths; output packing therefore
  trusts that nothing rewrites the finished build's output tree while
  it is being packed (builds run under disjoint uids, so only root or
  the same build could).
* Reload upgrades the worker but never the reaper itself; picking up
  a new reaper still needs a full restart (which kills running
  builds). The reaper is deliberately small so this rarely matters.
* Results are kept until the hub acknowledges them, but log replay
  offsets advance when a chunk is handed to the session, so a few log
  lines in flight when a session dies are skipped on resume.
* Cancellation is lazy: a dispatched build whose attach clients are
  all gone is killed only after a grace period, and an abandoned
  queued job is dropped when a worker would have picked it up, not
  immediately.
* Dedupe attaches duplicates to the first attempt, so a transient
  failure propagates to all attached submitters (same as Buck2's RE
  dedupe behaviour).
* The Linux builder keeps the worker's kernel uid (remapped in the user
  namespace); there is no dedicated unprivileged build user yet.
* Input NARs are not verified against an expected content hash; the
  worker trusts the mTLS-authenticated hub for input content.

## Deployment

Hub and worker read their settings from TOML config files
(`--config`, default `/etc/tribuchet/{hub,worker}.toml`); only the
one-shot `attach` and `ca` commands take their parameters on the
command line. `nixosModules.default` ships hub and worker services
(`services.tribuchet-hub`, `services.tribuchet-worker`): the hub is
socket-activated, the worker unit delegates its cgroup subtree for
per-build limits and execs the worker through a stable /run symlink
with `reloadIfChanged`, so package bumps and settings changes reload
instead of restarting (the fresh worker generation re-reads the
config file).
The e2e test consumes the same module. macOS hosts use the
`darwinModules.default` nix-darwin module, which ships both services:
the hub adopts its listeners from launchd (`launch_activate_socket`,
the analogue of the socket-activated NixOS unit), and the worker's
launchd daemon execs a stable symlink that activation flips and
SIGHUPs the reaper, again reloading on package bumps and settings
changes.
