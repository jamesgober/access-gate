//! The decision.

use crate::{
    error::{Denial, DenialKind},
    perm::PermSet,
    rule::{Audience, Condition, Rule},
    subject::{Resource, Status, Subject},
};

/// Decide whether `subject` (or a guest, when `None`) may pass `rule`, on
/// `resource` when the rule has object conditions. `now_ms` is Unix
/// milliseconds (for suspensions that have run out and second-factor
/// freshness).
///
/// The rules, in order:
///
/// 1. A public rule ([`Rule::guest`] with nothing added) lets everyone in.
/// 2. A guest passes only a guests-only rule; anything else that needs a
///    subject is [`DenialKind::NeedsSignIn`] (401).
/// 3. A signed-in subject fails a guests-only rule
///    ([`DenialKind::GuestOnly`]).
/// 4. Pending and suspended subjects fail unless the rule allows them.
/// 5. The subject must hold every permission the rule needs.
/// 6. Every condition must hold. A condition that needs the resource fails
///    when none is given: the check fails closed.
///
/// ```
/// use access_gate::{authorize, DenialKind, Resource, Rule, Schema, Subject};
///
/// let schema = Schema::builder("web").permissions(&["post.write"]).build()?;
/// let edit = Rule::signed_in().needs(&schema, &["post.write"])?.owner()?;
///
/// let author = Subject::new(1).with_perms(schema.perms(&["post.write"])?);
/// let own = Resource::new().owner(1);
/// let other = Resource::new().owner(2);
///
/// assert!(authorize(Some(&author), &edit, Some(&own), 0).is_ok());
/// assert_eq!(authorize(Some(&author), &edit, Some(&other), 0).unwrap_err().kind(), DenialKind::Condition);
/// assert_eq!(authorize(None, &edit, Some(&own), 0).unwrap_err().status(), 401);
/// # Ok::<(), access_gate::SchemaError>(())
/// ```
///
/// # Errors
///
/// A [`Denial`] saying why; send the client only
/// [`Denial::status`].
#[inline]
pub fn authorize(
    subject: Option<&Subject>,
    rule: &Rule,
    resource: Option<&Resource>,
    now_ms: u64,
) -> Result<(), Denial> {
    authorize_with(&PermSet::EMPTY, subject, rule, resource, now_ms)
}

/// [`authorize`], where every visitor also holds `guests` (the schema's
/// [`guests`](crate::Schema::guests)): a guest passes an open rule whose
/// permissions `guests` covers, and a signed-in subject holds `guests` on
/// top of its own.
///
/// ```
/// use access_gate::{authorize_with, Rule, Schema};
///
/// let schema = Schema::builder("web")
///     .permissions(&["post.read", "post.write"])
///     .guest_grants(&["post.read"])
///     .build()?;
/// let read = Rule::guest().needs(&schema, &["post.read"])?;
/// let write = Rule::guest().needs(&schema, &["post.write"])?;
/// assert!(authorize_with(schema.guests(), None, &read, None, 0).is_ok());
/// assert_eq!(authorize_with(schema.guests(), None, &write, None, 0).unwrap_err().status(), 401);
/// # Ok::<(), access_gate::SchemaError>(())
/// ```
///
/// # Errors
///
/// As [`authorize`].
#[inline]
pub fn authorize_with(
    guests: &PermSet,
    subject: Option<&Subject>,
    rule: &Rule,
    resource: Option<&Resource>,
    now_ms: u64,
) -> Result<(), Denial> {
    if rule.is_public() {
        return Ok(());
    }
    let Some(subject) = subject else {
        if rule.audience() == Audience::Anyone
            && rule.conditions().next().is_none()
            && guests.covers(rule.need())
        {
            return Ok(());
        }
        return if rule.audience() == Audience::GuestsOnly {
            // A guests-only rule that also needs permissions or conditions
            // cannot be met by anyone: refuse rather than guess.
            if rule.need().is_empty() && rule.conditions().next().is_none() {
                Ok(())
            } else {
                Err(Denial::new(DenialKind::Condition))
            }
        } else {
            Err(Denial::new(DenialKind::NeedsSignIn))
        };
    };
    if rule.audience() == Audience::GuestsOnly {
        return Err(Denial::new(DenialKind::GuestOnly));
    }
    // What a guest may do, any signed-in subject may do, whatever its
    // standing: the status check guards only what membership adds.
    if rule.audience() == Audience::Anyone
        && rule.conditions().next().is_none()
        && guests.covers(rule.need())
    {
        return Ok(());
    }
    match subject.status() {
        Status::Active => {}
        Status::PendingVerification => {
            if !rule.allows_pending() {
                return Err(Denial::new(DenialKind::Status));
            }
        }
        Status::Suspended { until } => {
            let lapsed = until.is_some_and(|t| now_ms >= t);
            if !lapsed && !rule.allows_suspended() {
                return Err(Denial::new(DenialKind::Status));
            }
        }
    }
    let held = subject.perms().union(*guests);
    if !held.covers(rule.need()) {
        return Err(Denial::missing(rule.need().difference(held)));
    }
    for condition in rule.conditions() {
        check(subject, condition, resource, now_ms)?;
    }
    Ok(())
}

fn check(
    subject: &Subject,
    condition: &Condition,
    resource: Option<&Resource>,
    now_ms: u64,
) -> Result<(), Denial> {
    let fail = Err(Denial::new(DenialKind::Condition));
    if let Condition::FreshFactor(within) = condition {
        return match subject.factor_at() {
            Some(at) if now_ms.saturating_sub(at) <= *within && at <= now_ms => Ok(()),
            _ => Err(Denial::new(DenialKind::StaleFactor)),
        };
    }
    let Some(resource) = resource else {
        return fail;
    };
    let ok = match condition {
        Condition::Owner => resource.owner_id() == Some(subject.id()),
        Condition::OwnerOr(perms) => {
            resource.owner_id() == Some(subject.id()) || subject.perms().covers(perms)
        }
        Condition::SameTenant => {
            subject.tenant().is_some() && resource.tenant_id() == subject.tenant()
        }
        Condition::AttrMatch(id) => match (subject.attrs().get(*id), resource.attrs().get(*id)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
        Condition::FreshFactor(_) => true,
    };
    if ok { Ok(()) } else { fail }
}
