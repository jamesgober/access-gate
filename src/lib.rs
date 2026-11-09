//! # access_gate
//!
//! Authorization for Rust services: **may this subject do this, to this
//! thing, right now?** Roles compile to permission bit sets once at boot;
//! a decision is an array of rules, four AND operations, and a few
//! comparisons. Deny by default, storage-free, protocol-free, no runtime
//! dependencies, `no_std` with `alloc`.
//!
//! ## Tier 1
//!
//! ```
//! use access_gate::{authorize, Resource, Rule, Schema, Subject};
//!
//! // Boot: the service declares its vocabulary; mistakes refuse the boot.
//! let schema = Schema::builder("web")
//!     .permissions(&["post.read", "post.write", "post.edit.any"])
//!     .role("member", &["post.read"])
//!     .role("author", &["post.write"]).inherits("member")
//!     .role("editor", &["post.edit.any"]).inherits("author")
//!     .build()?;
//! let edit_post = Rule::signed_in()
//!     .needs(&schema, &["post.write"])?
//!     .owner_or(&schema, &["post.edit.any"])?;
//!
//! // Login: the session stores what the account's roles grant.
//! let alice = Subject::new(1).with_perms(schema.grants(["author"]));
//! let eve = Subject::new(2).with_perms(schema.grants(["member"]));
//!
//! // Request: the handler loaded the post; the gate decides.
//! let post = Resource::new().owner(1);
//! assert!(authorize(Some(&alice), &edit_post, Some(&post), 0).is_ok());
//! assert_eq!(authorize(Some(&eve), &edit_post, Some(&post), 0).unwrap_err().status(), 403);
//! assert_eq!(authorize(None, &edit_post, Some(&post), 0).unwrap_err().status(), 401);
//! # Ok::<(), access_gate::SchemaError>(())
//! ```
//!
//! ## The model
//!
//! - A [`Schema`] names permissions (each becomes one bit of a
//!   [`PermSet`]), roles (with inheritance, resolved at boot; cycles are an
//!   error), and attributes.
//! - A [`Rule`] names its [`Audience`] (anyone, guests only, signed in),
//!   the permissions it needs, which standings it lets through, and up to
//!   eight [`Condition`]s: ownership, tenancy, attribute equality, and
//!   second-factor freshness.
//! - A [`Subject`] is a snapshot from the server-side session: id, tenant,
//!   permissions, [`Status`], attributes. A [`Resource`] is what the
//!   handler loaded.
//! - [`authorize`] returns `Ok(())` or a [`Denial`] whose
//!   [`status`](Denial::status) is 401 or 403. The reason is for audit,
//!   never for the client.
//!
//! ## What it does not do
//!
//! It never loads anything: no database, no session lookup. The caller
//! hands it the subject (from authentication) and the resource (from the
//! handler). Authentication is a separate crate.
//!
//! ## Cost
//!
//! A role-only decision is a branch on the audience and a 256-bit subset
//! test; with conditions, a few integer compares more. Numbers are in
//! `docs/PERFORMANCE.md`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod decide;
mod error;
mod perm;
mod rule;
mod schema;
mod subject;

pub use crate::{
    decide::{authorize, authorize_with},
    error::{Denial, DenialKind, SchemaError},
    perm::{MAX_PERMISSIONS, Perm, PermSet},
    rule::{Audience, Condition, MAX_CONDITIONS, Rule},
    schema::{MAX_NAME_LEN, MAX_ROLES, RoleId, Schema, SchemaBuilder},
    subject::{AttrId, Attrs, MAX_ATTRIBUTES, Resource, Status, Subject},
};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests;
