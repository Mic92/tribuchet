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
   socket. The shim ships the contents of `topTmpDir` as well, because
   structured attrs / `passAsFile` place files there that env refers to
   via `tmpDirInSandbox` (`/build/.attrs.json` etc.).
2. Hub dedupes by scratch-output set: a second identical request attaches
   to the in-flight build's log and result. Otherwise it queues the
   request for a worker matching `system` (and later: required features).
   No worker available ⇒ block; Nix's max-jobs bounds parallelism.
3. Path negotiation: hub sends the input path list; worker answers with
   the missing subset; hub streams those as zstd-compressed NARs read
   straight from the local /nix/store (hub is colocated with the daemon,
   all inputs are valid locally).
4. Worker materializes inputs in its cache, constructs the sandbox, and
   executes `builder args…` with the env from build.json, cwd
   `/build`. Logs stream back live through hub to the shim's stdout/stderr
   (Nix shows them as ordinary build output).
5. On success the worker NAR-packs every scratch output path, signs the
   NAR hashes with its ed25519 key, and streams them back. The shim
   verifies the signature against the allowlist, unpacks at the scratch
   paths, and exits 0. Builder failure ⇒ shim exits with the builder's
   status; Nix reports a normal build failure.

## Sandbox

We re-implement the sandbox rather than requiring Nix on workers.
Reference implementations: `nix/src/libstore/unix/build/` and
`nix/src/libstore/darwin/build/sandbox-defaults.sb`.

* Linux: `unshare(CLONE_NEWNS|NEWUSER|NEWPID|NEWIPC|NEWUTS|NEWNET)`,
  bind-mount input paths read-only at their store paths, scratch outputs
  writable, tmpfs `/build`, minimal `/dev` and `/proc`, stub
  `/etc/passwd`, `pivot_root`, drop privileges to a build uid.
* macOS: `sandbox_init_with_parameters` with a profile modeled on Nix's
  `sandbox-defaults.sb`: deny default, allow read on inputs, write on
  scratch outputs and `/build`.
* Fixed-output derivations are detected via the `outputHash` env var
  (always present in FOD derivations) and get network access
  (no NEWNET on Linux, network allowance in the macOS profile).

Accepted tradeoffs: no recursive-nix, sandbox parity is ours to maintain,
trusted worker pool assumed (output authenticity still enforced via
signatures).

## Security

* Transport: mTLS; `tribuchet ca` issues the CA and per-worker certs.
* Output authenticity: workers sign output NARs (ed25519); the hub/shim
  verify against configured public keys before unpacking.

## Scale & state

MVP targets 2–10 workers and a few clients: in-memory scheduler state,
sqlite for worker identities and stats. The transfer protocol keeps a
`oneof` payload so a chunked CAS (FastCDC + blake3) can replace whole-NAR
streaming later without a protocol break.

## Known limitations (MVP)

* Dedupe is keyed on the scratch output set, which Nix randomizes per
  build attempt: it only catches concurrent duplicate submissions of the
  same goal, not the same derivation submitted twice. Proper dedupe
  needs a derivation identity in build.json (upstream patch).
* A worker dying mid-build fails the build instead of requeueing it.
* The replay buffer for deduped subscribers holds compressed output
  chunks in memory.
* When a worker reconnects, the previous session's scheduler loop may
  still grab one job and fail it before noticing the closed channel.
* No build cancellation: Nix killing the attach process does not yet
  stop the remote build.

## Deployment

* NixOS modules for hub and worker.
* macOS workers: plain binary + launchd plist (no nix required).
