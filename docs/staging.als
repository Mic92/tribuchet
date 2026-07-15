// Alloy model of tribuchet input staging.
//
// The hub streams a missing input during the earliest staging phase
// (staging-permit order) of any build that needs it; later builds skip
// it. Within one phase paths are streamed references-before-referrers,
// and the worker imports NARs in stream order. This model checks the
// resulting invariant: when a referrer is imported, its references are
// already valid on the worker.
//
// Run: alloy6 exec -c '*' docs/staging.als
//   check ReferencesValidBeforeReferrers  -- expect UNSAT (holds)
//   run   Scenario                        -- expect SAT (not vacuous)

open util/ordering[Phase]

sig Path {
  refs: set Path
}

fact AcyclicRefs { no p: Path | p in p.^refs }

sig Build {
  needs: set Path,      // offered input closure
  phase: disj one Phase // when this build's inputs are streamed
}
sig Phase {}
fact PhasesAreBuilds { Phase = Build.phase }

// The offered set is a closure: a build needing a referrer needs its
// references too.
fact NeedsClosed { all b: Build | b.needs.refs in b.needs }

// A path is streamed during the earliest phase of any build needing it.
fun streamedIn[p: Path]: lone Build {
  { b: Build | p in b.needs and
      no b2: Build | p in b2.needs and lt[b2.phase, b.phase] }
}

// A reference streamed in the same phase is ordered by the per-build
// topological sort; one streamed by another build must come from an
// earlier phase, whose imports committed first (stream order).
check ReferencesValidBeforeReferrers {
  all p: Path, r: p.refs | some streamedIn[p] implies {
    streamedIn[r] = streamedIn[p] or lt[streamedIn[r].phase, streamedIn[p].phase]
  }
} for 8 Path, exactly 4 Build, exactly 4 Phase

// A cross-build reference edge (the production failure shape) is
// expressible, so the check above is not vacuous.
run Scenario {
  some p: Path, r: p.refs, disj a, b: Build |
    r in a.needs and p in b.needs and p not in a.needs
} for 4 Path, exactly 2 Build, exactly 2 Phase
