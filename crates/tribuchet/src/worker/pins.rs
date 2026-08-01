//! Choose which offered input paths need their own GC temp root.
//!
//! A temp root on a valid path protects its whole reference closure,
//! so instead of one AddTempRoot round trip per offered path the
//! worker reads the reference graph from the Nix SQLite database and
//! roots only the paths no other offered path references. The read is
//! advisory: the daemon still decides validity, and any failure here
//! falls back to rooting everything. The database is opened read-only
//! through the WAL (never `immutable=1`, which would race the writing
//! nix-daemon), so no write access to /nix/var/nix/db is needed.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::errors::Result;
pub(super) use harmonia_store_db::StoreDb;
use rusqlite::OptionalExtension;

pub(super) struct PinPlan {
    /// Paths that need their own temp root because no other offered
    /// path references them.
    pub pins: HashSet<String>,
    /// Paths the database considered valid. If the daemon later calls
    /// one of these invalid, a GC raced our snapshot and the coverage
    /// argument no longer holds.
    pub db_valid: HashSet<String>,
}

/// Location of the Nix store database, honouring `NIX_STATE_DIR`.
pub(super) fn nix_db_path() -> PathBuf {
    let state = std::env::var("NIX_STATE_DIR").unwrap_or_else(|_| "/nix/var/nix".into());
    PathBuf::from(state).join("db/db.sqlite")
}

pub(super) fn plan_pins(db: &StoreDb, offered: &[String]) -> Result<PinPlan> {
    // One read transaction so validity and references come from the
    // same snapshot.
    let tx = db.connection().unchecked_transaction()?;
    let mut id_to_path = HashMap::new();
    let mut db_valid = HashSet::new();
    {
        let mut stmt = tx.prepare_cached("SELECT id FROM ValidPaths WHERE path = ?1")?;
        for p in offered {
            if let Some(id) = stmt.query_row([p], |r| r.get::<_, i64>(0)).optional()? {
                db_valid.insert(p.clone());
                id_to_path.insert(id, p.clone());
            }
        }
    }
    // Collect paths that some other offered path references.
    // Self-references must not unpin a path.
    let mut referenced = HashSet::new();
    {
        let mut stmt = tx
            .prepare_cached("SELECT reference FROM Refs WHERE referrer = ?1 AND reference != ?1")?;
        for id in id_to_path.keys() {
            let mut rows = stmt.query([id])?;
            while let Some(row) = rows.next()? {
                let r: i64 = row.get(0)?;
                if let Some(p) = id_to_path.get(&r) {
                    referenced.insert(p.clone());
                }
            }
        }
    }
    let pins = offered
        .iter()
        .filter(|p| !referenced.contains(*p))
        .cloned()
        .collect();
    Ok(PinPlan { pins, db_valid })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use harmonia_store_path::{StoreDir, StorePath};
    use harmonia_store_path_info::{NarHash, UnkeyedValidPathInfo};

    use super::*;

    fn path(store_dir: &StoreDir, n: u8, name: &str) -> (String, StorePath) {
        let p = format!("/nix/store/{n:032}-{name}");
        (p.clone(), store_dir.parse(&p).unwrap())
    }

    fn register(db: &mut StoreDb, store_dir: &StoreDir, sp: &StorePath, refs: &[&StorePath]) {
        let info = UnkeyedValidPathInfo {
            deriver: None,
            nar_hash: NarHash::from_slice(&[0u8; 32]).unwrap(),
            references: refs.iter().map(|r| (*r).clone()).collect::<BTreeSet<_>>(),
            registration_time: None,
            nar_size: 1,
            ultimate: false,
            signatures: BTreeSet::new(),
            ca: None,
            store_dir: store_dir.clone(),
        };
        db.register_valid_path(store_dir, sp, &info).unwrap();
    }

    /// Only closure roots, unknown paths and self-referencing paths
    /// get pinned. A valid chain is covered by its top path.
    #[test]
    fn pins_roots_missing_and_self_referencing_paths() -> Result<()> {
        let store_dir = StoreDir::default();
        let mut db = StoreDb::open_memory()?;
        // a -> b -> c are valid, d is missing, e is valid with a self-reference.
        let (ap, sp_a) = path(&store_dir, 1, "a");
        let (bp, sp_b) = path(&store_dir, 2, "b");
        let (cp, sp_c) = path(&store_dir, 3, "c");
        let (dp, _) = path(&store_dir, 4, "d");
        let (ep, sp_e) = path(&store_dir, 5, "self");
        register(&mut db, &store_dir, &sp_c, &[]);
        register(&mut db, &store_dir, &sp_b, &[&sp_c]);
        register(&mut db, &store_dir, &sp_a, &[&sp_b]);
        register(&mut db, &store_dir, &sp_e, &[&sp_e]);

        let offered = vec![ap.clone(), bp.clone(), cp.clone(), dp.clone(), ep.clone()];
        let plan = plan_pins(&db, &offered)?;
        assert_eq!(plan.pins, HashSet::from([ap.clone(), dp, ep.clone()]));
        assert_eq!(plan.db_valid, HashSet::from([ap, bp, cp, ep]));
        Ok(())
    }

    /// Edges to paths outside the offer neither pin nor cover anything.
    #[test]
    fn references_outside_the_offer_are_ignored() -> Result<()> {
        let store_dir = StoreDir::default();
        let mut db = StoreDb::open_memory()?;
        let (_, sp_x) = path(&store_dir, 6, "outside");
        let (ap, sp_a) = path(&store_dir, 7, "a");
        let (bp, sp_b) = path(&store_dir, 8, "b");
        register(&mut db, &store_dir, &sp_x, &[]);
        register(&mut db, &store_dir, &sp_b, &[&sp_x]);
        register(&mut db, &store_dir, &sp_a, &[&sp_b, &sp_x]);

        let offered = vec![ap.clone(), bp.clone()];
        let plan = plan_pins(&db, &offered)?;
        assert_eq!(plan.pins, HashSet::from([ap.clone()]));
        assert_eq!(plan.db_valid, HashSet::from([ap, bp]));
        Ok(())
    }
}
