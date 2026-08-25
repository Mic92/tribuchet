// Worker-side input staging.
//
// Several builds on one worker share the daemon store and a registry of
// claims: the first build to miss a path claims it and imports it, later
// builds wait on that claim instead of fetching the path twice. The hub
// delivers manifests and chunks in any order. The daemon rejects an
// import whose references are not valid yet.
//
// A claim behaves like a watch channel: waiters see Running while the
// owner still stages the path, Done once it is imported, Failed once the
// owner gave up. A waiter whose claim failed takes the path over.
//
// An import is dispatched only after every reference is valid here (an
// input or an own import that finished), so the import pool never waits.
//
//   quint run    spec/staging.qnt --invariant inv
//   quint verify spec/staging.qnt --invariant inv --inductive-invariant indInv

module staging {
  type Path = str
  type BuildId = int
  type Wait = { build: BuildId, path: Path, owner: BuildId }

  pure val PATHS: Set[Path] = Set("a", "b", "c")
  pure val REFS: Path -> Set[Path] = Map("a" -> Set(), "b" -> Set("a"), "c" -> Set("a", "b"))
  // input closures are closed under REFS
  pure val CLOSURES: Set[Set[Path]] = Set(Set("a"), Set("a", "b"), Set("a", "b", "c"))
  pure val BUILDS: Set[BuildId] = Set(1, 2)
  pure val NOBODY: BuildId = 0

  type ClaimState = Running | Done | Failed
  type Phase = Init | Staging | Ready | Rejected | Cancelled

  pure def refsOf(p: Path): Set[Path] = REFS.get(p).exclude(Set(p))

  // ---- state ----------------------------------------------------------

  // shared on the worker
  var valid: Set[Path]              // the daemon store
  var claim: Path -> BuildId        // live claim per path, or NOBODY
  var waits: Set[Wait]              // builds waiting on another build's claim

  // per build
  var closure: BuildId -> Set[Path]
  var phase: BuildId -> Phase
  var inputs: BuildId -> Set[Path]   // staged: valid in the store
  var pending: BuildId -> Set[Path]  // claimed, requested from the hub
  var complete: BuildId -> Set[Path] // manifest and all chunks arrived
  var running: BuildId -> Set[Path]  // handed to the import pool
  var done: BuildId -> Set[Path]     // imported by this build

  // ---- derived --------------------------------------------------------

  def owned(b: BuildId): Set[Path] = pending.get(b).union(running.get(b)).union(done.get(b))
  def staged(b: BuildId): Set[Path] = inputs.get(b).union(done.get(b))
  def waitingFor(b: BuildId): Set[Path] = waits.filter(w => w.build == b).map(w => w.path)

  def claimState(w: Wait): ClaimState =
    if (done.get(w.owner).contains(w.path)) Done
    else if (phase.get(w.owner) == Staging and owned(w.owner).contains(w.path)) Running
    else Failed

  def releaseClaims(b: BuildId): Path -> BuildId =
    PATHS.fold(claim, (c, p) => if (c.get(p) == b) c.set(p, NOBODY) else c)

  // ---- actions --------------------------------------------------------

  action init = {
    nondet c1 = CLOSURES.oneOf()
    nondet c2 = CLOSURES.oneOf()
    all {
      valid' = Set(),
      claim' = PATHS.mapBy(_ => NOBODY),
      waits' = Set(),
      closure' = Map(1 -> c1, 2 -> c2),
      phase' = BUILDS.mapBy(_ => Init),
      inputs' = BUILDS.mapBy(_ => Set()),
      pending' = BUILDS.mapBy(_ => Set()),
      complete' = BUILDS.mapBy(_ => Set()),
      running' = BUILDS.mapBy(_ => Set()),
      done' = BUILDS.mapBy(_ => Set()),
    }
  }

  // check_missing_inputs, one pass under the registry lock: valid paths
  // are inputs, claimed paths are waited for, the rest is claimed.
  action negotiate(b: BuildId): bool = {
    val missing = closure.get(b).exclude(valid)
    val theirs = missing.filter(p => claim.get(p) != NOBODY)
    val mine = missing.exclude(theirs)
    all {
      phase.get(b) == Init,
      phase' = phase.set(b, Staging),
      inputs' = inputs.set(b, closure.get(b).intersect(valid)),
      pending' = pending.set(b, mine),
      claim' = mine.fold(claim, (c, p) => c.set(p, b)),
      waits' = waits.union(theirs.map(p => { build: b, path: p, owner: claim.get(p) })),
      valid' = valid, closure' = closure, complete' = complete, running' = running, done' = done,
    }
  }

  // The hub delivered manifest and chunks of a requested path. Order
  // across paths is arbitrary.
  action deliver(b: BuildId, p: Path): bool = all {
    phase.get(b) == Staging,
    pending.get(b).contains(p),
    not(complete.get(b).contains(p)),
    complete' = complete.set(b, complete.get(b).union(Set(p))),
    valid' = valid, claim' = claim, waits' = waits, closure' = closure, phase' = phase,
    inputs' = inputs, pending' = pending, running' = running, done' = done,
  }

  // start_import: a complete path goes to the pool once each reference
  // is staged.
  action dispatch(b: BuildId, p: Path): bool = all {
    phase.get(b) == Staging,
    pending.get(b).contains(p),
    complete.get(b).contains(p),
    refsOf(p).subseteq(staged(b)),
    pending' = pending.set(b, pending.get(b).exclude(Set(p))),
    running' = running.set(b, running.get(b).union(Set(p))),
    valid' = valid, claim' = claim, waits' = waits, closure' = closure, phase' = phase,
    inputs' = inputs, complete' = complete, done' = done,
  }

  // run_import: AddToStoreNar.
  action daemonImport(b: BuildId, p: Path): bool = all {
    phase.get(b) == Staging,
    running.get(b).contains(p),
    if (refsOf(p).subseteq(valid)) all {
      valid' = valid.union(Set(p)),
      running' = running.set(b, running.get(b).exclude(Set(p))),
      done' = done.set(b, done.get(b).union(Set(p))),
      phase' = phase, pending' = pending, claim' = claim, waits' = waits,
    } else all {
      phase' = phase.set(b, Rejected),
      running' = running.set(b, Set()),
      pending' = pending.set(b, Set()),
      claim' = releaseClaims(b),
      waits' = waits.filter(w => w.build != b),
      valid' = valid, done' = done,
    },
    closure' = closure, inputs' = inputs, complete' = complete,
  }

  // The claim a build waits on settled. Done: the path is an input.
  // Failed: follow whoever re-claimed it, else claim it and ask the hub.
  action resolve(b: BuildId, p: Path): bool = {
    val mine = waits.filter(w => w.build == b and w.path == p)
    all {
      phase.get(b) == Staging,
      mine != Set(),
      mine.forall(w => claimState(w) != Running),
      waits' = if (mine.exists(w => claimState(w) == Done) or claim.get(p) == NOBODY) waits.exclude(mine)
               else waits.exclude(mine).union(Set({ build: b, path: p, owner: claim.get(p) })),
      if (mine.exists(w => claimState(w) == Done)) all {
        inputs' = inputs.set(b, inputs.get(b).union(Set(p))),
        pending' = pending, claim' = claim,
      } else if (claim.get(p) == NOBODY) all {
        claim' = claim.set(p, b),
        pending' = pending.set(b, pending.get(b).union(Set(p))),
        inputs' = inputs,
      } else all {
        inputs' = inputs, pending' = pending, claim' = claim,
      },
      valid' = valid, closure' = closure, phase' = phase, complete' = complete,
      running' = running, done' = done,
    }
  }

  // try_complete: nothing pending, in the pool, or waited on.
  action finish(b: BuildId): bool = all {
    phase.get(b) == Staging,
    pending.get(b) == Set(),
    running.get(b) == Set(),
    waitingFor(b) == Set(),
    phase' = phase.set(b, Ready),
    inputs' = inputs.set(b, staged(b)),
    claim' = releaseClaims(b),
    valid' = valid, waits' = waits, closure' = closure, pending' = pending,
    complete' = complete, running' = running, done' = done,
  }

  // Build torn down mid-staging. Limited to build 1 so random runs are
  // not dominated by early cancellation.
  action cancel(b: BuildId): bool = all {
    b == 1,
    phase.get(b) == Staging,
    phase' = phase.set(b, Cancelled),
    claim' = releaseClaims(b),
    waits' = waits.filter(w => w.build != b),
    running' = running.set(b, Set()),
    pending' = pending.set(b, Set()),
    valid' = valid, closure' = closure, inputs' = inputs, complete' = complete, done' = done,
  }

  action step = {
    nondet b = BUILDS.oneOf()
    nondet p = PATHS.oneOf()
    any { negotiate(b), deliver(b, p), dispatch(b, p), daemonImport(b, p), resolve(b, p), finish(b), cancel(b) }
  }

  // ---- properties ----------------------------------------------------

  val noDaemonReject = BUILDS.forall(b => phase.get(b) != Rejected)

  val readyMeansValid = BUILDS.forall(b => phase.get(b) == Ready implies closure.get(b).subseteq(valid))

  // Some staging build can take a step other than cancel: staging never
  // wedges on a claim nobody fulfils or an import that cannot dispatch.
  def canStep(b: BuildId): bool = or {
    PATHS.exists(p => or {
      pending.get(b).contains(p) and not(complete.get(b).contains(p)),
      pending.get(b).contains(p) and complete.get(b).contains(p)
        and refsOf(p).subseteq(staged(b)),
      running.get(b).contains(p),
      waitingFor(b).contains(p)
        and waits.filter(w => w.build == b and w.path == p).forall(w => claimState(w) != Running),
    }),
    pending.get(b) == Set() and running.get(b) == Set() and waitingFor(b) == Set(),
  }
  val noWedge = or {
    BUILDS.exists(b => phase.get(b) == Init),
    BUILDS.forall(b => phase.get(b) != Staging),
    BUILDS.exists(b => phase.get(b) == Staging and canStep(b)),
  }

  val inv = noDaemonReject and readyMeansValid and noWedge

  // ---- inductive strengthening ---------------------------------------

  pure val PHASES = Set(Init, Staging, Ready, Rejected, Cancelled)
  pure val PATHSETS = BUILDS.setOfMaps(PATHS.powerset())
  pure val WAITS = tuples(BUILDS, PATHS, BUILDS).map(t => { build: t._1, path: t._2, owner: t._3 })

  val typeOK = and {
    valid.in(PATHS.powerset()),
    claim.in(PATHS.setOfMaps(BUILDS.union(Set(NOBODY)))),
    waits.in(WAITS.powerset()),
    closure.in(BUILDS.setOfMaps(CLOSURES)),
    phase.in(BUILDS.setOfMaps(PHASES)),
    inputs.in(PATHSETS), pending.in(PATHSETS), complete.in(PATHSETS),
    running.in(PATHSETS), done.in(PATHSETS),
  }

  // The daemon only registers paths whose references are valid.
  val validClosed = valid.forall(p => REFS.get(p).subseteq(valid))

  val buildShape = BUILDS.forall(b => and {
    owned(b).union(inputs.get(b)).union(complete.get(b)).union(waitingFor(b)).subseteq(closure.get(b)),
    staged(b).subseteq(valid),
    pending.get(b).intersect(running.get(b)) == Set(),
    pending.get(b).intersect(done.get(b)) == Set(),
    running.get(b).intersect(done.get(b)) == Set(),
    waitingFor(b).intersect(owned(b).union(inputs.get(b))) == Set(),
    phase.get(b) == Init implies
      owned(b).union(inputs.get(b)).union(complete.get(b)).union(waitingFor(b)) == Set(),
    phase.get(b) == Staging implies and {
      closure.get(b).subseteq(inputs.get(b).union(owned(b)).union(waitingFor(b))),
      running.get(b).union(done.get(b)).subseteq(complete.get(b)),
      complete.get(b).subseteq(owned(b)),
      // why the daemon never rejects
      running.get(b).forall(p => refsOf(p).subseteq(staged(b))),
    },
    phase.get(b) != Staging implies and {
      pending.get(b) == Set(), running.get(b) == Set(), waitingFor(b) == Set(),
      PATHS.forall(p => claim.get(p) != b),
    },
    phase.get(b) == Ready implies closure.get(b).subseteq(valid),
  })

  // A live claim points at a staging build that owns the path.
  val claimShape = PATHS.forall(p =>
    claim.get(p) == NOBODY or (phase.get(claim.get(p)) == Staging and owned(claim.get(p)).contains(p)))

  val waitShape = waits.forall(w => BUILDS.contains(w.owner) and w.owner != w.build)

  val indInv = and { typeOK, validClosed, buildShape, claimShape, waitShape, inv }
}

// Witnesses: `quint run --main witnesses --invariant <name>` must FAIL,
// showing the state is reachable.
module witnesses {
  import staging.*
  val bothReady = not(BUILDS.forall(b => phase.get(b) == Ready) and valid == PATHS)
  val takeover = not(BUILDS.exists(b => phase.get(b) == Cancelled) and BUILDS.exists(b => phase.get(b) == Ready and closure.get(b) == PATHS))
}
