//! Who is asking, and what they are asking about.

use core::fmt;

use crate::perm::PermSet;

/// The most attributes a subject or resource can carry.
pub const MAX_ATTRIBUTES: usize = 16;

/// An attribute, by its position in the [`Schema`](crate::Schema).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AttrId(u8);

impl AttrId {
    /// The attribute at `index`, or `None` past 15. An index out of range
    /// never aliases another attribute.
    #[must_use]
    pub const fn from_index(index: u8) -> Option<Self> {
        if index < MAX_ATTRIBUTES as u8 {
            Some(Self(index))
        } else {
            None
        }
    }

    /// For indexes the crate has already bounded (0 to 15).
    pub(crate) const fn new_bounded(index: u8) -> Self {
        Self(index & 15)
    }

    /// The position, 0 to 15.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }
}

/// Up to 16 attribute values (`org_id`, `department`, ...), each a `u64`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Attrs {
    present: u16,
    values: [u64; MAX_ATTRIBUTES],
}

impl Attrs {
    /// No attributes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            present: 0,
            values: [0; MAX_ATTRIBUTES],
        }
    }

    /// These attributes with `id` set to `value`.
    #[must_use]
    pub const fn with(mut self, id: AttrId, value: u64) -> Self {
        self.present |= 1 << id.0;
        self.values[id.0 as usize] = value;
        self
    }

    /// Set `id` to `value`.
    pub fn set(&mut self, id: AttrId, value: u64) {
        *self = self.with(id, value);
    }

    /// Remove `id`.
    pub fn remove(&mut self, id: AttrId) {
        self.present &= !(1 << id.0);
        self.values[usize::from(id.0)] = 0;
    }

    /// The value of `id`, if set.
    #[must_use]
    pub const fn get(&self, id: AttrId) -> Option<u64> {
        if self.present & (1 << id.0) != 0 {
            Some(self.values[id.0 as usize])
        } else {
            None
        }
    }

    /// Whether no attribute is set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.present == 0
    }

    /// The set attributes, lowest id first.
    pub fn iter(&self) -> impl Iterator<Item = (AttrId, u64)> + '_ {
        (0..16u8)
            .map(AttrId::new_bounded)
            .filter_map(move |id| self.get(id).map(|v| (id, v)))
    }
}

impl fmt::Debug for Attrs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.iter().map(|(id, v)| (id.0, v)))
            .finish()
    }
}

/// What a subject's account standing allows a request to reach.
///
/// Banned and locked accounts never reach authorization: authentication
/// refuses them or turns them into guests. These are the standings a
/// signed-in request can still carry.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Status {
    /// In good standing.
    #[default]
    Active,
    /// Signed up, not verified yet. Rules refuse it unless they
    /// [`allow_pending`](crate::Rule::allow_pending).
    PendingVerification,
    /// Suspended until a time (Unix milliseconds), or with no end. Rules
    /// refuse it unless they [`allow_suspended`](crate::Rule::allow_suspended).
    Suspended {
        /// When the suspension lifts by itself.
        until: Option<u64>,
    },
}

/// The signed-in party a decision is about: who, which tenant, what they
/// hold, and their standing. Built from the server-side session record,
/// never from anything the client sent.
///
/// ```
/// use access_gate::{PermSet, Subject};
///
/// let subject = Subject::new(42).with_perms(PermSet::new()).with_tenant(7);
/// assert_eq!(subject.id(), 42);
/// assert_eq!(subject.tenant(), Some(7));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Subject {
    id: u128,
    tenant: Option<u64>,
    perms: PermSet,
    status: Status,
    attrs: Attrs,
    factor_at: Option<u64>,
}

impl Subject {
    /// A subject with id `id`, active, holding nothing.
    #[must_use]
    pub const fn new(id: u128) -> Self {
        Self {
            id,
            tenant: None,
            perms: PermSet::EMPTY,
            status: Status::Active,
            attrs: Attrs::new(),
            factor_at: None,
        }
    }

    /// With these permissions.
    #[must_use]
    pub const fn with_perms(mut self, perms: PermSet) -> Self {
        self.perms = perms;
        self
    }

    /// In this tenant.
    #[must_use]
    pub const fn with_tenant(mut self, tenant: u64) -> Self {
        self.tenant = Some(tenant);
        self
    }

    /// With this status.
    #[must_use]
    pub const fn with_status(mut self, status: Status) -> Self {
        self.status = status;
        self
    }

    /// With these attributes.
    #[must_use]
    pub const fn with_attrs(mut self, attrs: Attrs) -> Self {
        self.attrs = attrs;
        self
    }

    /// Second factor last proven at `at` (Unix milliseconds).
    #[must_use]
    pub const fn with_factor_at(mut self, at: u64) -> Self {
        self.factor_at = Some(at);
        self
    }

    /// The subject id (the account's 128-bit id).
    #[must_use]
    pub const fn id(&self) -> u128 {
        self.id
    }

    /// The tenant, in a multi-tenant service.
    #[must_use]
    pub const fn tenant(&self) -> Option<u64> {
        self.tenant
    }

    /// What the subject holds.
    #[must_use]
    pub const fn perms(&self) -> &PermSet {
        &self.perms
    }

    /// The subject's standing as rules see it.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    /// The subject's attributes.
    #[must_use]
    pub const fn attrs(&self) -> &Attrs {
        &self.attrs
    }

    /// When the second factor was last proven (Unix milliseconds).
    #[must_use]
    pub const fn factor_at(&self) -> Option<u64> {
        self.factor_at
    }
}

/// The thing a request acts on, for object-level checks: its owner, its
/// tenant, and the attributes rules compare. Loaded by the caller (the
/// handler), passed in; access-gate never loads anything.
///
/// ```
/// use access_gate::Resource;
///
/// let post = Resource::new().owner(42).tenant(7);
/// assert_eq!(post.owner_id(), Some(42));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Resource {
    owner: Option<u128>,
    tenant: Option<u64>,
    attrs: Attrs,
}

impl Resource {
    /// A resource with no owner, tenant, or attributes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: None,
            tenant: None,
            attrs: Attrs::new(),
        }
    }

    /// Owned by subject `id`.
    #[must_use]
    pub const fn owner(mut self, id: u128) -> Self {
        self.owner = Some(id);
        self
    }

    /// In tenant `tenant`.
    #[must_use]
    pub const fn tenant(mut self, tenant: u64) -> Self {
        self.tenant = Some(tenant);
        self
    }

    /// With attribute `id` set to `value`.
    #[must_use]
    pub const fn attr(mut self, id: AttrId, value: u64) -> Self {
        self.attrs = self.attrs.with(id, value);
        self
    }

    /// The owner.
    #[must_use]
    pub const fn owner_id(&self) -> Option<u128> {
        self.owner
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<u64> {
        self.tenant
    }

    /// The attributes.
    #[must_use]
    pub const fn attrs(&self) -> &Attrs {
        &self.attrs
    }
}
