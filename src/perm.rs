//! Permissions as bits, and sets of them.

use core::fmt;

/// The most permissions one [`Schema`](crate::Schema) can declare.
pub const MAX_PERMISSIONS: usize = 256;

/// One permission: a bit number assigned by a [`Schema`](crate::Schema) at
/// boot. Look one up with [`Schema::perm`](crate::Schema::perm).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Perm(u8);

impl Perm {
    /// The permission with bit number `index`.
    #[must_use]
    pub const fn from_index(index: u8) -> Self {
        Self(index)
    }

    /// The bit number, 0 to 255.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }

    const fn word(self) -> usize {
        (self.0 >> 6) as usize
    }

    const fn bit(self) -> u64 {
        1u64 << (self.0 & 63)
    }
}

/// A set of up to 256 permissions, one bit each.
///
/// Checking that a subject holds everything a rule needs is four AND
/// operations ([`covers`](Self::covers)).
///
/// ```
/// use access_gate::{Perm, PermSet};
///
/// let read = Perm::from_index(0);
/// let write = Perm::from_index(1);
/// let have = PermSet::new().with(read).with(write);
/// let need = PermSet::new().with(write);
/// assert!(have.covers(&need));
/// assert!(!need.covers(&have));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PermSet([u64; 4]);

impl PermSet {
    /// The empty set.
    pub const EMPTY: Self = Self([0; 4]);

    /// The empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self::EMPTY
    }

    /// This set with `perm` added.
    #[must_use]
    pub const fn with(mut self, perm: Perm) -> Self {
        self.0[perm.word()] |= perm.bit();
        self
    }

    /// Add `perm`.
    pub fn insert(&mut self, perm: Perm) {
        self.0[perm.word()] |= perm.bit();
    }

    /// Remove `perm`.
    pub fn remove(&mut self, perm: Perm) {
        self.0[perm.word()] &= !perm.bit();
    }

    /// Whether `perm` is in the set.
    #[must_use]
    pub const fn contains(&self, perm: Perm) -> bool {
        self.0[perm.word()] & perm.bit() != 0
    }

    /// Whether this set holds every permission in `need`.
    #[inline]
    #[must_use]
    pub const fn covers(&self, need: &Self) -> bool {
        (self.0[0] & need.0[0]) == need.0[0]
            && (self.0[1] & need.0[1]) == need.0[1]
            && (self.0[2] & need.0[2]) == need.0[2]
            && (self.0[3] & need.0[3]) == need.0[3]
    }

    /// Every permission in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self([
            self.0[0] | other.0[0],
            self.0[1] | other.0[1],
            self.0[2] | other.0[2],
            self.0[3] | other.0[3],
        ])
    }

    /// The permissions in both sets.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self([
            self.0[0] & other.0[0],
            self.0[1] & other.0[1],
            self.0[2] & other.0[2],
            self.0[3] & other.0[3],
        ])
    }

    /// The permissions in this set that are not in `other`.
    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self([
            self.0[0] & !other.0[0],
            self.0[1] & !other.0[1],
            self.0[2] & !other.0[2],
            self.0[3] & !other.0[3],
        ])
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// How many permissions the set holds.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.0[0].count_ones()
            + self.0[1].count_ones()
            + self.0[2].count_ones()
            + self.0[3].count_ones()
    }

    /// The permissions in the set, lowest bit first.
    pub fn iter(&self) -> impl Iterator<Item = Perm> + '_ {
        (0..=255u8)
            .map(Perm::from_index)
            .filter(move |p| self.contains(*p))
    }

    /// The set as 32 little-endian bytes, for a session record.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, word) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// The set from [`to_bytes`](Self::to_bytes).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut words = [0u64; 4];
        for (i, word) in words.iter_mut().enumerate() {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(chunk);
        }
        Self(words)
    }
}

impl FromIterator<Perm> for PermSet {
    fn from_iter<I: IntoIterator<Item = Perm>>(iter: I) -> Self {
        let mut set = Self::new();
        for p in iter {
            set.insert(p);
        }
        set
    }
}

impl fmt::Debug for PermSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter().map(Perm::index)).finish()
    }
}
