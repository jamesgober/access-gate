//! Boot-time errors and request-time denials.

use alloc::boxed::Box;
use core::fmt;

use crate::perm::PermSet;

/// A schema or rule that cannot be compiled. A service refuses to boot on
/// any of these, so a mistake never becomes an open door at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaError {
    /// A name is empty, longer than 64 bytes, or uses a character other than
    /// `a-z`, `0-9`, `.`, `_`, `-`, `:`.
    InvalidName {
        /// The name as given.
        name: Box<str>,
    },
    /// The same name was declared twice.
    Duplicate {
        /// The name.
        name: Box<str>,
    },
    /// More than 256 permissions.
    TooManyPermissions,
    /// More than 1024 roles.
    TooManyRoles,
    /// More than 16 attributes.
    TooManyAttributes,
    /// A role or rule names a permission the schema does not declare.
    UnknownPermission {
        /// The name.
        name: Box<str>,
    },
    /// A role inherits from a role the schema does not declare.
    UnknownRole {
        /// The name.
        name: Box<str>,
    },
    /// A rule names an attribute the schema does not declare.
    UnknownAttribute {
        /// The name.
        name: Box<str>,
    },
    /// Roles inherit from each other in a loop.
    RoleCycle {
        /// A role on the loop.
        role: Box<str>,
    },
    /// `inherits` was called before any `role`.
    InheritsWithoutRole,
    /// A rule holds more conditions than it can (8).
    TooManyConditions,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName { name } => {
                write!(f, "invalid name {name:?}: use 1 to 64 of a-z 0-9 . _ - :")
            }
            Self::Duplicate { name } => write!(f, "{name:?} is declared twice"),
            Self::TooManyPermissions => f.write_str("more than 256 permissions"),
            Self::TooManyRoles => f.write_str("more than 1024 roles"),
            Self::TooManyAttributes => f.write_str("more than 16 attributes"),
            Self::UnknownPermission { name } => {
                write!(f, "permission {name:?} is not declared in the schema")
            }
            Self::UnknownRole { name } => write!(f, "role {name:?} is not declared in the schema"),
            Self::UnknownAttribute { name } => {
                write!(f, "attribute {name:?} is not declared in the schema")
            }
            Self::RoleCycle { role } => write!(f, "role {role:?} inherits from itself"),
            Self::InheritsWithoutRole => f.write_str("`inherits` called before any `role`"),
            Self::TooManyConditions => f.write_str("a rule holds at most 8 conditions"),
        }
    }
}

impl core::error::Error for SchemaError {}

/// Why a request was refused. For logs, audit, and choosing the status;
/// never shown to the client beyond the status itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenialKind {
    /// The rule needs a signed-in subject and the request is a guest's.
    NeedsSignIn,
    /// The rule is for guests only (a login form) and the subject is signed
    /// in. A web layer usually redirects to the account page.
    GuestOnly,
    /// The subject lacks a permission the rule needs.
    MissingPermission,
    /// The subject's status (pending verification, suspended) is not
    /// allowed by this rule.
    Status,
    /// A condition on the resource failed (owner, tenant, attribute), or the
    /// rule needs a resource and none was given.
    Condition,
    /// The rule needs a second factor proven more recently.
    StaleFactor,
}

/// A refusal from [`authorize`](crate::authorize).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial {
    kind: DenialKind,
    missing: PermSet,
}

impl Denial {
    pub(crate) const fn new(kind: DenialKind) -> Self {
        Self {
            kind,
            missing: PermSet::EMPTY,
        }
    }

    pub(crate) const fn missing(missing: PermSet) -> Self {
        Self {
            kind: DenialKind::MissingPermission,
            missing,
        }
    }

    /// Why.
    #[must_use]
    pub const fn kind(&self) -> DenialKind {
        self.kind
    }

    /// The permissions the subject lacked, for audit (empty unless the
    /// kind is [`DenialKind::MissingPermission`]).
    #[must_use]
    pub const fn missing_perms(&self) -> PermSet {
        self.missing
    }

    /// The HTTP status to answer with: 401 when signing in would help, 403
    /// otherwise.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self.kind {
            DenialKind::NeedsSignIn | DenialKind::StaleFactor => 401,
            _ => 403,
        }
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self.kind {
            DenialKind::NeedsSignIn => "sign-in required",
            DenialKind::GuestOnly => "for guests only",
            DenialKind::MissingPermission => "missing permission",
            DenialKind::Status => "account status does not allow this",
            DenialKind::Condition => "condition on the resource failed",
            DenialKind::StaleFactor => "second factor required again",
        };
        f.write_str(text)
    }
}

impl core::error::Error for Denial {}
