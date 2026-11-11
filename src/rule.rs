//! Route and object rules, compiled once at boot.

use core::time::Duration;

use crate::{error::SchemaError, perm::PermSet, schema::Schema, subject::AttrId};

/// The most conditions one rule can hold.
pub const MAX_CONDITIONS: usize = 8;

/// Who a rule is for.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Audience {
    /// Everyone, guests included (a public page).
    Anyone,
    /// Guests only (a login or sign-up form).
    GuestsOnly,
    /// Signed-in subjects only.
    SignedIn,
}

/// A check on the resource or on the session, beyond permissions.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum Condition {
    /// The subject owns the resource.
    Owner,
    /// The subject owns the resource, or holds every permission in the set
    /// (an editor may change anyone's post).
    OwnerOr(PermSet),
    /// The resource is in the subject's tenant.
    SameTenant,
    /// The subject's attribute equals the resource's attribute of the same
    /// id (`resource.org_id == subject.org_id`).
    AttrMatch(AttrId),
    /// The second factor was proven within this many milliseconds (step-up
    /// for sensitive actions).
    FreshFactor(u64),
}

/// What a route or action requires. Deny by default: a rule that is never
/// built allows nothing, and every rule names its audience.
///
/// ```
/// use access_gate::{Rule, Schema};
///
/// let schema = Schema::builder("web")
///     .permissions(&["post.write", "post.edit.any"])
///     .build()?;
///
/// let public = Rule::guest();
/// let login_form = Rule::guest_only();
/// let edit = Rule::signed_in()
///     .needs(&schema, &["post.write"])?
///     .owner_or(&schema, &["post.edit.any"])?;
/// # let _ = (public, login_form, edit);
/// # Ok::<(), access_gate::SchemaError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Rule {
    audience: Audience,
    need: PermSet,
    allow_pending: bool,
    allow_suspended: bool,
    conditions: [Option<Condition>; MAX_CONDITIONS],
}

impl Rule {
    const fn with_audience(audience: Audience) -> Self {
        Self {
            audience,
            need: PermSet::EMPTY,
            allow_pending: false,
            allow_suspended: false,
            conditions: [None; MAX_CONDITIONS],
        }
    }

    /// Open to everyone, guests included.
    #[must_use]
    pub const fn guest() -> Self {
        Self::with_audience(Audience::Anyone)
    }

    /// For guests only: a signed-in subject is refused with
    /// [`DenialKind::GuestOnly`](crate::DenialKind::GuestOnly).
    #[must_use]
    pub const fn guest_only() -> Self {
        Self::with_audience(Audience::GuestsOnly)
    }

    /// For signed-in subjects in good standing.
    #[must_use]
    pub const fn signed_in() -> Self {
        Self::with_audience(Audience::SignedIn)
    }

    /// Also require the named permissions.
    ///
    /// # Errors
    ///
    /// [`SchemaError::UnknownPermission`] for a name the schema does not
    /// declare.
    pub fn needs(self, schema: &Schema, perms: &[&str]) -> Result<Self, SchemaError> {
        Ok(self.needs_set(schema.perms(perms)?))
    }

    /// Also require every permission in `perms`.
    #[must_use]
    pub const fn needs_set(mut self, perms: PermSet) -> Self {
        self.need = self.need.union(perms);
        self
    }

    /// Let a subject whose account is pending verification through.
    #[must_use]
    pub const fn allow_pending(mut self) -> Self {
        self.allow_pending = true;
        self
    }

    /// Let a suspended subject through (for example, to read but not write).
    #[must_use]
    pub const fn allow_suspended(mut self) -> Self {
        self.allow_suspended = true;
        self
    }

    /// Add a condition.
    ///
    /// # Errors
    ///
    /// [`SchemaError::TooManyConditions`] past eight;
    /// [`SchemaError::EmptyOverride`] for an `OwnerOr` with no permissions.
    pub fn when(mut self, condition: Condition) -> Result<Self, SchemaError> {
        if let Condition::OwnerOr(perms) = condition {
            if perms.is_empty() {
                return Err(SchemaError::EmptyOverride);
            }
        }
        let slot = self
            .conditions
            .iter_mut()
            .find(|c| c.is_none())
            .ok_or(SchemaError::TooManyConditions)?;
        *slot = Some(condition);
        Ok(self)
    }

    /// Require that the subject owns the resource.
    ///
    /// # Errors
    ///
    /// As [`when`](Self::when).
    pub fn owner(self) -> Result<Self, SchemaError> {
        self.when(Condition::Owner)
    }

    /// Require that the subject owns the resource or holds the named
    /// permissions.
    ///
    /// # Errors
    ///
    /// As [`needs`](Self::needs) and [`when`](Self::when).
    pub fn owner_or(self, schema: &Schema, perms: &[&str]) -> Result<Self, SchemaError> {
        let set = schema.perms(perms)?;
        self.when(Condition::OwnerOr(set))
    }

    /// Require that the resource is in the subject's tenant.
    ///
    /// # Errors
    ///
    /// As [`when`](Self::when).
    pub fn same_tenant(self) -> Result<Self, SchemaError> {
        self.when(Condition::SameTenant)
    }

    /// Require that the subject's attribute `name` equals the resource's.
    ///
    /// # Errors
    ///
    /// [`SchemaError::UnknownAttribute`], or as [`when`](Self::when).
    pub fn attr_match(self, schema: &Schema, name: &str) -> Result<Self, SchemaError> {
        let id = schema
            .attribute(name)
            .ok_or_else(|| SchemaError::UnknownAttribute { name: name.into() })?;
        self.when(Condition::AttrMatch(id))
    }

    /// Require a second factor proven within `within`.
    ///
    /// # Errors
    ///
    /// As [`when`](Self::when).
    pub fn fresh_factor(self, within: Duration) -> Result<Self, SchemaError> {
        let ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX);
        self.when(Condition::FreshFactor(ms))
    }

    /// Who the rule is for.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        self.audience
    }

    /// The permissions it needs.
    #[must_use]
    pub const fn need(&self) -> &PermSet {
        &self.need
    }

    /// Whether a subject pending verification may pass.
    #[must_use]
    pub const fn allows_pending(&self) -> bool {
        self.allow_pending
    }

    /// Whether a suspended subject may pass.
    #[must_use]
    pub const fn allows_suspended(&self) -> bool {
        self.allow_suspended
    }

    /// Its conditions, in the order added.
    pub fn conditions(&self) -> impl Iterator<Item = &Condition> + '_ {
        self.conditions.iter().flatten()
    }

    /// Whether any condition needs the resource to decide.
    #[must_use]
    pub fn needs_resource(&self) -> bool {
        self.conditions()
            .any(|c| !matches!(c, Condition::FreshFactor(_)))
    }

    /// Whether the rule is open to guests with no further check.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.audience == Audience::Anyone && self.need.is_empty() && self.conditions[0].is_none()
    }
}
