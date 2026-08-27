// Hub <-> worker input transfer for one build.
//
// The assignment offers the input closure, with manifests inline where
// the hub had the recipe cached. The worker answers with one Need naming
// the paths it lacks and the chunks it lacks for the inline manifests.
// The hub sends a Manifest per missing path as recipes finish computing
// and, per Need carrying hashes, those chunks followed by one Eof.
// Channels are bounded FIFOs with blocking send, like the gRPC streams.
// The hub -> worker channel is shared by all builds on the worker, so
// foreign messages (Other) may fill it at any time. The worker's chunk
// store may evict anything at any time. When the last Eof is in and a
// path still lacks chunks, the worker asks again, a bounded number of
// times.
//
// The chunks answering one Need travel as one message: the worker keys
// them by hash, so their order is immaterial.
//
// The hub relay is modelled at await granularity: a computed recipe
// first lands in `hubOutbox` (hubTake) and reaches the wire in a
// separate step (hubFlush). A Need's hashes are queued (hubRecv) and
// answered when the channel has room (hubServe). HUB selects what the
// relay may do while a manifest send is pending:
//   queue  everything else continues (send is a polled future)
//   block  nothing else until the send completes (send in a select! arm)
//   drop   like queue, but the pending send may be cancelled
//
//   quint run    spec/protocol.qnt --main protocol --invariant inv
//   quint verify spec/protocol.qnt --main protocol --invariant inv --inductive-invariant indInv
//   quint run    spec/protocol.qnt --main hubBlock --invariant inv   # expect violation
//   quint run    spec/protocol.qnt --main hubDrop  --invariant inv   # expect violation

module relay {
  type Path = str
  type Chunk = int
  const HUB: str

  pure val PATHS: Set[Path] = Set("a", "b", "c")
  pure val RECIPE: Path -> Set[Chunk] = Map("a" -> Set(1, 2), "b" -> Set(2, 3), "c" -> Set(3))
  pure val CHUNKS: Set[Chunk] = Set(1, 2, 3)
  pure val MAX_ROUNDS: int = 1
  pure val CAP_W: int = 3
  pure val CAP_H: int = 2
  // hash-Needs per build: negotiate + one per late manifest + resend rounds + the one that gives up
  pure val CAP_Q: int = 1 + 3 + MAX_ROUNDS + 1

  pure def chunksOf(ps: Set[Path]): Set[Chunk] = ps.map(p => RECIPE.get(p)).flatten()

  type Kind = Man | Chunks | Eof | Other | Nil
  type Phase = Init | Staging | Ready | GaveUp | ProtoErr

  pure val slotsW: Set[int] = 0.to(CAP_W - 1)
  pure val slotsH: Set[int] = 0.to(CAP_H - 1)
  pure val slotsQ: Set[int] = 0.to(CAP_Q - 1)

  // ---- state ----------------------------------------------------------

  // hub -> worker after the assignment: Man(wPath) | Chunks(wChunks) | Eof
  var wLen: int
  var wKind: int -> Kind
  var wPath: int -> Path
  var wChunks: int -> Set[Chunk]
  // worker -> hub: Need { paths, hashes }
  var hLen: int
  var hPaths: int -> Set[Path]
  var hHashes: int -> Set[Chunk]

  // hub
  var inline: Set[Path]
  var hubSent: Set[Path]
  var hubComputing: Set[Path]
  var hubOutbox: Set[Path]
  // hashes of Needs read but not yet answered
  var qLen: int
  var qHashes: int -> Set[Chunk]
  var hubFirstNeed: bool
  var hubErr: bool

  // worker
  var have: Set[Path]
  var phase: Phase
  var pending: Set[Path]
  var recipes: Set[Path]
  var store: Set[Chunk]
  var awaiting: Chunk -> Set[Path]
  var outstanding: int
  var rounds: int
  var imported: Set[Path]

  // ---- channels -------------------------------------------------------

  def manInFlight(p: Path): bool = slotsW.exists(i => i < wLen and wKind.get(i) == Man and wPath.get(i) == p)
  def eofsInFlight: int = slotsW.filter(i => i < wLen and wKind.get(i) == Eof).size()
  def hashNeedsInFlight: int = slotsH.filter(i => i < hLen and hHashes.get(i) != Set()).size()
  def pathNeedInFlight(p: Path): bool = slotsH.exists(i => i < hLen and hPaths.get(i).contains(p))

  action wKeep = all { wLen' = wLen, wKind' = wKind, wPath' = wPath, wChunks' = wChunks }
  action hKeep = all { hLen' = hLen, hPaths' = hPaths, hHashes' = hHashes }
  action qKeep = all { qLen' = qLen, qHashes' = qHashes }
  action qPush(cs: Set[Chunk]): bool = all {
    qLen < CAP_Q,
    qLen' = qLen + 1,
    qHashes' = qHashes.set(qLen, cs),
  }
  action qPop = all {
    qLen' = qLen - 1,
    qHashes' = slotsQ.mapBy(i => if (i < CAP_Q - 1) qHashes.get(i + 1) else Set()),
  }
  action wPop = all {
    wLen' = wLen - 1,
    wKind' = slotsW.mapBy(i => if (i < CAP_W - 1) wKind.get(i + 1) else Nil),
    wPath' = slotsW.mapBy(i => if (i < CAP_W - 1) wPath.get(i + 1) else "a"),
    wChunks' = slotsW.mapBy(i => if (i < CAP_W - 1) wChunks.get(i + 1) else Set()),
  }
  action wPushMan(p: Path): bool = all {
    wLen < CAP_W,
    wLen' = wLen + 1,
    wKind' = wKind.set(wLen, Man), wPath' = wPath.set(wLen, p), wChunks' = wChunks,
  }
  action wPushOther: bool = all {
    wLen < CAP_W,
    wLen' = wLen + 1,
    wKind' = wKind.set(wLen, Other), wPath' = wPath, wChunks' = wChunks,
  }
  action wPushAnswer(cs: Set[Chunk]): bool = all {
    wLen + 2 <= CAP_W,
    wLen' = wLen + 2,
    wKind' = wKind.set(wLen, Chunks).set(wLen + 1, Eof),
    wChunks' = wChunks.set(wLen, cs),
    wPath' = wPath,
  }
  action hPop = all {
    hLen' = hLen - 1,
    hPaths' = slotsH.mapBy(i => if (i < CAP_H - 1) hPaths.get(i + 1) else Set()),
    hHashes' = slotsH.mapBy(i => if (i < CAP_H - 1) hHashes.get(i + 1) else Set()),
  }
  action hPush(paths: Set[Path], hashes: Set[Chunk]): bool = all {
    hLen < CAP_H,
    hLen' = hLen + 1,
    hPaths' = hPaths.set(hLen, paths),
    hHashes' = hHashes.set(hLen, hashes),
  }

  // ---- worker steps ---------------------------------------------------

  pure val NO_WAITERS: Chunk -> Set[Path] = CHUNKS.mapBy(_ => Set())

  pure def waitsOn(aw: Chunk -> Set[Path], p: Path): bool = CHUNKS.exists(c => aw.get(c).contains(p))

  // Chunks of `ps` absent from `st`, as (chunk, path) pairs.
  pure def lacking(ps: Set[Path], st: Set[Chunk]): Set[(Chunk, Path)] =
    ps.map(p => RECIPE.get(p).exclude(st).map(c => (c, p))).flatten()

  pure def addWaiters(aw: Chunk -> Set[Path], l: Set[(Chunk, Path)]): Chunk -> Set[Path] =
    CHUNKS.mapBy(c => aw.get(c).union(l.filter(cp => cp._1 == c).map(cp => cp._2)))

  // chunks in `l` nobody awaited yet get requested
  pure def fresh(aw: Chunk -> Set[Path], l: Set[(Chunk, Path)]): Set[Chunk] =
    l.map(cp => cp._1).filter(c => aw.get(c) == Set())

  // Outcome of handling one message: paths `cand` that wait on nothing
  // are imported when their chunks are in `st`, else await them again.
  action settle(cand: Set[Path], pend: Set[Path], rec: Set[Path], st: Set[Chunk],
                aw: Chunk -> Set[Path], needPaths: Set[Path], needHashes0: Set[Chunk],
                answered: int, countRound: bool, err: bool): bool = {
    val ready = cand.intersect(pend).filter(p => not(waitsOn(aw, p)))
    val ok = ready.filter(p => RECIPE.get(p).subseteq(st))
    val retry = lacking(ready.exclude(ok), st)
    val needHashes = needHashes0.union(fresh(aw, retry))
    val pend2 = pend.exclude(ok)
    val sends = needPaths != Set() or needHashes != Set()
    val bump = countRound and needHashes != Set()
    all {
      pending' = pend2,
      recipes' = rec,
      store' = st,
      awaiting' = addWaiters(aw, retry),
      imported' = imported.union(ok),
      if (sends) hPush(needPaths, needHashes) else hKeep,
      outstanding' = outstanding - answered + (if (needHashes != Set()) 1 else 0),
      rounds' = if (bump) rounds + 1 else rounds,
      phase' = if (err) ProtoErr
               else if (bump and rounds + 1 > MAX_ROUNDS) GaveUp
               else if (pend2 == Set()) Ready
               else Staging,
      have' = have,
    }
  }

  action negotiate = {
    val missing = PATHS.exclude(have)
    val rec = inline.intersect(missing)
    val l = lacking(rec, store)
    all {
      phase == Init,
      settle(rec, missing, rec, store, addWaiters(awaiting, l), missing, fresh(awaiting, l), 0, false, false),
      wKeep, hubKeep,
    }
  }

  action onManifest(p: Path): bool =
    if (pending.contains(p) and not(recipes.contains(p))) {
      val l = lacking(Set(p), store)
      settle(Set(p), pending, recipes.union(Set(p)), store, addWaiters(awaiting, l), Set(), fresh(awaiting, l), 0, false, false)
    } else
      settle(Set(), pending, recipes, store, awaiting, Set(), Set(), 0, false,
             not(have.contains(p) or imported.contains(p)))

  action onChunks(cs: Set[Chunk]): bool = {
    val woken = cs.map(c => awaiting.get(c)).flatten()
    val aw = CHUNKS.mapBy(c => if (cs.contains(c)) Set() else awaiting.get(c))
    settle(woken, pending, recipes, store.union(cs), aw, Set(), Set(), 0, true, false)
  }

  // Every Need answered, yet paths still wait: chunks were evicted.
  action onLastEof: bool = {
    val stuck = pending.filter(p => waitsOn(awaiting, p))
    val l = lacking(stuck, store)
    settle(stuck, pending, recipes, store, addWaiters(NO_WAITERS, l), Set(), fresh(NO_WAITERS, l), 1, true, false)
  }

  action workerRecv = all {
    wLen > 0,
    phase == Staging or phase == Ready,
    wPop, hubKeep,
    if (wKind.get(0) == Man) onManifest(wPath.get(0))
    else if (wKind.get(0) == Chunks) onChunks(wChunks.get(0))
    else if (wKind.get(0) == Eof and outstanding == 1) onLastEof
    else if (wKind.get(0) == Eof and outstanding > 1)
      settle(Set(), pending, recipes, store, awaiting, Set(), Set(), 1, false, false)
    else if (wKind.get(0) == Other)
      settle(Set(), pending, recipes, store, awaiting, Set(), Set(), 0, false, false)
    else
      settle(Set(), pending, recipes, store, awaiting, Set(), Set(), 0, false, true),
  }

  // another build's traffic on the shared session channel
  action otherTraffic = all {
    phase != Init,
    wPushOther, hKeep, hubKeep, workerKeep,
  }

  action evict = {
    nondet c = CHUNKS.oneOf()
    all {
      store.contains(c),
      store' = store.exclude(Set(c)),
      wKeep, hKeep, hubKeep,
      phase' = phase, pending' = pending, recipes' = recipes, awaiting' = awaiting,
      outstanding' = outstanding, rounds' = rounds, imported' = imported, have' = have,
    }
  }

  action hubKeep = all {
    inline' = inline, hubSent' = hubSent, hubComputing' = hubComputing,
    hubOutbox' = hubOutbox, hubFirstNeed' = hubFirstNeed, hubErr' = hubErr, qKeep,
  }

  // block: the relay sits in send(manifest).await and polls nothing else
  val hubFree = HUB != "block" or hubOutbox == Set()
  action workerKeep = all {
    phase' = phase, pending' = pending, recipes' = recipes, store' = store, awaiting' = awaiting,
    outstanding' = outstanding, rounds' = rounds, imported' = imported, have' = have,
  }

  // ---- hub steps ------------------------------------------------------

  action hubRecv = {
    val paths = hPaths.get(0)
    val hashes = hHashes.get(0)
    val bogus = not(paths.subseteq(PATHS)) or not(hashes.subseteq(chunksOf(hubSent)))
    all {
      hLen > 0,
      not(hubErr),
      hubFree,
      hPop,
      hubErr' = bogus,
      hubFirstNeed' = false,
      hubComputing' = hubComputing.union(paths.exclude(hubSent).exclude(hubOutbox)),
      hubSent' = hubSent, hubOutbox' = hubOutbox, inline' = inline,
      if (bogus or hashes == Set()) qKeep else qPush(hashes),
      wKeep, workerKeep,
    }
  }

  action hubServe = all {
    qLen > 0,
    not(hubErr),
    hubFree,
    wPushAnswer(qHashes.get(0)),
    qPop,
    inline' = inline, hubSent' = hubSent, hubComputing' = hubComputing,
    hubOutbox' = hubOutbox, hubFirstNeed' = hubFirstNeed, hubErr' = hubErr,
    hKeep, workerKeep,
  }

  action hubTake = {
    nondet p = PATHS.oneOf()
    all {
      hubComputing.contains(p),
      not(hubErr),
      hubFree,
      hubComputing' = hubComputing.exclude(Set(p)),
      hubOutbox' = hubOutbox.union(Set(p)),
      hubSent' = hubSent, hubFirstNeed' = hubFirstNeed, hubErr' = hubErr, inline' = inline,
      qKeep, wKeep, hKeep, workerKeep,
    }
  }

  action hubFlush = {
    nondet p = PATHS.oneOf()
    all {
      hubOutbox.contains(p),
      not(hubErr),
      wPushMan(p),
      hubOutbox' = hubOutbox.exclude(Set(p)),
      hubSent' = hubSent.union(Set(p)),
      hubComputing' = hubComputing, hubFirstNeed' = hubFirstNeed, hubErr' = hubErr, inline' = inline,
      qKeep, hKeep, workerKeep,
    }
  }

  // select! picked another branch while the send was pending
  action hubDropped = {
    nondet p = PATHS.oneOf()
    all {
      HUB == "drop",
      hubOutbox.contains(p),
      wLen == CAP_W,
      not(hubErr),
      hubOutbox' = hubOutbox.exclude(Set(p)),
      hubSent' = hubSent.union(Set(p)),
      hubComputing' = hubComputing, hubFirstNeed' = hubFirstNeed, hubErr' = hubErr, inline' = inline,
      qKeep, wKeep, hKeep, workerKeep,
    }
  }

  // ---- init -----------------------------------------------------------

  action init = {
    nondet have0 = PATHS.powerset().oneOf()
    nondet inline0 = PATHS.powerset().oneOf()
    all {
      wLen' = 0, wKind' = slotsW.mapBy(_ => Nil), wPath' = slotsW.mapBy(_ => "a"),
      wChunks' = slotsW.mapBy(_ => Set()),
      hLen' = 0, hPaths' = slotsH.mapBy(_ => Set()), hHashes' = slotsH.mapBy(_ => Set()),
      inline' = inline0, hubSent' = inline0, hubComputing' = Set(), hubOutbox' = Set(),
      qLen' = 0, qHashes' = slotsQ.mapBy(_ => Set()),
      hubFirstNeed' = true, hubErr' = false,
      have' = have0, phase' = Init,
      pending' = Set(), recipes' = Set(), store' = Set(), awaiting' = NO_WAITERS,
      outstanding' = 0, rounds' = 0, imported' = Set(),
    }
  }

  action step = any {
    negotiate, workerRecv, evict, otherTraffic,
    hubRecv, hubServe, hubTake, hubFlush, hubDropped,
  }

  // ---- properties -----------------------------------------------------

  val noProtoErr = phase != ProtoErr and not(hubErr)

  val readyMeansStaged = (phase == Ready) implies PATHS.subseteq(have.union(imported))

  // Until the worker has decided, a handler other than evict can run.
  val decided = phase == Ready or phase == GaveUp
  val canWorkerRecv = wLen > 0 and hLen < CAP_H
  val canHubRecv = hLen > 0 and hubFree and (hHashes.get(0) == Set() or qLen < CAP_Q)
  val canHubServe = qLen > 0 and hubFree and wLen + 2 <= CAP_W
  val canHubTake = hubComputing != Set() and hubFree
  val canHubFlush = hubOutbox != Set() and wLen < CAP_W
  val noDeadlock = decided or phase == Init or canWorkerRecv
    or canHubRecv or canHubServe or canHubTake or canHubFlush

  // Each outstanding Need is en route, queued, or its Eof is en route.
  val eofAccounting = outstanding == hashNeedsInFlight + qLen + eofsInFlight

  val inv = noProtoErr and readyMeansStaged and noDeadlock and eofAccounting

  // ---- inductive strengthening ---------------------------------------

  val typeOK = all {
    wLen.in(0.to(CAP_W)),
    wKind.in(setOfMaps(slotsW, Set(Man, Chunks, Eof, Other, Nil))),
    wPath.in(setOfMaps(slotsW, PATHS)),
    wChunks.in(setOfMaps(slotsW, CHUNKS.powerset())),
    hLen.in(0.to(CAP_H)),
    hPaths.in(setOfMaps(slotsH, PATHS.powerset())),
    hHashes.in(setOfMaps(slotsH, CHUNKS.powerset())),
    inline.in(PATHS.powerset()), hubSent.in(PATHS.powerset()), hubComputing.in(PATHS.powerset()),
    hubOutbox.in(PATHS.powerset()),
    qLen.in(0.to(CAP_Q)), qHashes.in(setOfMaps(slotsQ, CHUNKS.powerset())),
    slotsQ.forall(i => (i >= qLen) == (qHashes.get(i) == Set())),
    hubFirstNeed.in(Set(true, false)), hubErr.in(Set(true, false)),
    have.in(PATHS.powerset()), phase.in(Set(Init, Staging, Ready, GaveUp, ProtoErr)),
    pending.in(PATHS.powerset()), recipes.in(PATHS.powerset()), store.in(CHUNKS.powerset()),
    awaiting.in(setOfMaps(CHUNKS, PATHS.powerset())),
    outstanding.in(0.to(CAP_H + CAP_Q + CAP_W)), rounds.in(0.to(MAX_ROUNDS + 1)),
    imported.in(PATHS.powerset()),
    // canonical empty slots
    slotsW.forall(i => (i >= wLen) implies wKind.get(i) == Nil),
    slotsW.forall(i => (i < wLen) implies wKind.get(i) != Nil),
    slotsW.forall(i => wKind.get(i) != Man implies wPath.get(i) == "a"),
    slotsW.forall(i => wKind.get(i) != Chunks implies wChunks.get(i) == Set()),
    slotsH.forall(i => (i >= hLen) == (hPaths.get(i) == Set() and hHashes.get(i) == Set())),
  }

  val missing = PATHS.exclude(have)

  val initShape = (phase == Init) implies all {
    wLen == 0, hLen == 0, qLen == 0, hubFirstNeed, hubComputing == Set(), hubOutbox == Set(), hubSent == inline,
    outstanding == 0, rounds == 0, pending == Set(), recipes == Set(), imported == Set(),
    store == Set(), awaiting == NO_WAITERS,
  }

  val workerShape = (phase != Init) implies all {
    pending.intersect(imported) == Set(),
    pending.union(imported) == missing,
    imported.subseteq(recipes),
    recipes.subseteq(missing),
    recipes.subseteq(hubSent),
    (phase == Ready) implies pending == Set(),
    (phase == Staging) implies pending != Set() and rounds <= MAX_ROUNDS,
    CHUNKS.forall(c => awaiting.get(c).forall(p =>
      pending.contains(p) and recipes.contains(p) and RECIPE.get(p).contains(c) and not(store.contains(c)))),
    (phase == Staging) implies pending.forall(p => recipes.contains(p) implies waitsOn(awaiting, p)),
    CHUNKS.exists(c => awaiting.get(c) != Set()) implies outstanding > 0,
    pending.forall(p => recipes.contains(p) or hubComputing.contains(p) or hubOutbox.contains(p)
      or manInFlight(p) or pathNeedInFlight(p)),
    hLen + qLen + eofsInFlight <= 1 + recipes.exclude(inline).size() + rounds,
  }

  val hubShape = (phase != Init) implies all {
    hubComputing.intersect(hubSent) == Set(),
    hubComputing.subseteq(missing),
    hubOutbox.intersect(hubSent) == Set(),
    hubOutbox.intersect(hubComputing) == Set(),
    hubOutbox.subseteq(missing),
    (HUB == "block") implies hubOutbox.size() <= 1,
    inline.subseteq(hubSent),
    hubSent.subseteq(inline.union(missing)),
    store.subseteq(chunksOf(hubSent)),
    hubSent.intersect(missing).forall(p => recipes.contains(p) or manInFlight(p)),
    slotsQ.forall(i => i < qLen implies qHashes.get(i).subseteq(chunksOf(hubSent))),
    if (hubFirstNeed) all {
      slotsW.forall(i => i < wLen implies wKind.get(i) == Other),
      hLen <= 1, qLen == 0, hubComputing == Set(), hubOutbox == Set(), hubSent == inline,
      recipes == inline.intersect(missing), store == Set(), rounds == 0,
      (hLen > 0 and hPaths.get(0) == missing) or missing == Set(),
    } else
      slotsH.forall(i => i < hLen implies hPaths.get(i) == Set()),
    slotsH.forall(i => (0 < i and i < hLen) implies hPaths.get(i) == Set()),
  }

  val channelShape = (phase != Init) implies all {
    slotsW.forall(i => (i < wLen and wKind.get(i) == Man) implies all {
      hubSent.contains(wPath.get(i)), not(inline.contains(wPath.get(i))),
      pending.contains(wPath.get(i)), not(recipes.contains(wPath.get(i))),
      slotsW.forall(j => (j < wLen and j != i and wKind.get(j) == Man) implies wPath.get(j) != wPath.get(i)),
    }),
    slotsW.forall(i => (i < wLen and wKind.get(i) == Chunks) implies
      wChunks.get(i) != Set() and wChunks.get(i).subseteq(chunksOf(hubSent))
      and i + 1 < wLen and wKind.get(i + 1) == Eof),
    slotsW.forall(i => (i < wLen and wKind.get(i) == Eof and i > 0) implies wKind.get(i - 1) != Eof),
    slotsH.forall(i => i < hLen implies
      hPaths.get(i).subseteq(missing) and hHashes.get(i).subseteq(chunksOf(recipes))),
  }

  val indInv = typeOK and inv and initShape and workerShape and hubShape and channelShape
}

module protocol {
  import relay(HUB = "queue").*
}

module hubBlock {
  import relay(HUB = "block").*
}

module hubDrop {
  import relay(HUB = "drop").*
}

module witnesses {
  import relay(HUB = "queue").*
  // each should FAIL under quint run: the state is reachable
  val noResend = rounds == 0
  val neverReady = phase != Ready
  val neverGivesUp = phase != GaveUp
}
