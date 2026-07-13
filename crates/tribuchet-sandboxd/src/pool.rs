//! Uid pool: disjoint 65536-uid blocks for concurrent leases. Every
//! lease gets a whole block even when it maps only one uid.

pub const BLOCK: u32 = 65536;

#[derive(Debug)]
pub struct UidPool {
    start: u32,
    in_use: Vec<bool>,
}

impl UidPool {
    /// Pool covering `blocks` blocks of 65536 uids starting at `start`.
    pub fn new(start: u32, blocks: u32) -> Self {
        Self {
            start,
            in_use: vec![false; blocks as usize],
        }
    }

    /// Reserve a block; returns its base uid.
    pub fn allocate(&mut self) -> Option<u32> {
        let free = self.in_use.iter().position(|used| !used)?;
        self.in_use[free] = true;
        Some(self.start + u32::try_from(free).ok()? * BLOCK)
    }

    /// Return a block to the pool.
    pub fn release(&mut self, base: u32) {
        let index = (base - self.start) / BLOCK;
        if let Some(used) = self.in_use.get_mut(index as usize) {
            *used = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_disjoint_and_reusable() {
        let mut pool = UidPool::new(3_000_000, 2);
        let a = pool.allocate().unwrap();
        let b = pool.allocate().unwrap();
        assert_eq!(a, 3_000_000);
        assert_eq!(b, 3_000_000 + BLOCK);
        assert_eq!(pool.allocate(), None);
        pool.release(a);
        assert_eq!(pool.allocate(), Some(a));
    }
}
