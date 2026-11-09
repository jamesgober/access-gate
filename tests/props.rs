//! Invariants that must hold for any schema, subject, rule, and resource.

use access_gate::{
    AttrId, Attrs, Audience, Condition, DenialKind, Perm, PermSet, Resource, Rule, Schema, Status,
    Subject, authorize,
};
use proptest::prelude::*;

fn permset() -> impl Strategy<Value = PermSet> {
    prop::collection::vec(any::<u8>(), 0..12)
        .prop_map(|bits| bits.into_iter().map(Perm::from_index).collect())
}

fn status() -> impl Strategy<Value = Status> {
    prop_oneof![
        Just(Status::Active),
        Just(Status::PendingVerification),
        proptest::option::of(any::<u64>()).prop_map(|until| Status::Suspended { until }),
    ]
}

fn subject() -> impl Strategy<Value = Subject> {
    (
        any::<u128>(),
        permset(),
        proptest::option::of(any::<u64>()),
        status(),
        proptest::option::of(any::<u64>()),
        prop::collection::vec((0u8..16, any::<u64>()), 0..4),
    )
        .prop_map(|(id, perms, tenant, status, factor, attrs)| {
            let mut s = Subject::new(id).with_perms(perms).with_status(status);
            if let Some(t) = tenant {
                s = s.with_tenant(t);
            }
            if let Some(f) = factor {
                s = s.with_factor_at(f);
            }
            let mut a = Attrs::new();
            for (k, v) in attrs {
                a.set(AttrId::from_index(k), v);
            }
            s.with_attrs(a)
        })
}

fn condition() -> impl Strategy<Value = Condition> {
    prop_oneof![
        Just(Condition::Owner),
        permset().prop_map(Condition::OwnerOr),
        Just(Condition::SameTenant),
        (0u8..16).prop_map(|i| Condition::AttrMatch(AttrId::from_index(i))),
        any::<u64>().prop_map(Condition::FreshFactor),
    ]
}

fn rule() -> impl Strategy<Value = Rule> {
    (
        prop_oneof![
            Just(Rule::guest()),
            Just(Rule::guest_only()),
            Just(Rule::signed_in())
        ],
        permset(),
        any::<bool>(),
        any::<bool>(),
        prop::collection::vec(condition(), 0..4),
    )
        .prop_map(|(base, need, pending, suspended, conds)| {
            let mut r = base.needs_set(need);
            if pending {
                r = r.allow_pending();
            }
            if suspended {
                r = r.allow_suspended();
            }
            for c in conds {
                r = r.when(c).unwrap_or(r);
            }
            r
        })
}

fn resource() -> impl Strategy<Value = Option<Resource>> {
    proptest::option::of(
        (
            proptest::option::of(any::<u128>()),
            proptest::option::of(any::<u64>()),
        )
            .prop_map(|(owner, tenant)| {
                let mut r = Resource::new();
                if let Some(o) = owner {
                    r = r.owner(o);
                }
                if let Some(t) = tenant {
                    r = r.tenant(t);
                }
                r
            }),
    )
}

proptest! {
    /// Whatever is allowed, the subject holds everything the rule needs.
    #[test]
    fn allowed_implies_covers(s in subject(), r in rule(), res in resource(), now in any::<u64>()) {
        if authorize(Some(&s), &r, res.as_ref(), now).is_ok() && !r.is_public() {
            prop_assert!(s.perms().covers(r.need()));
            prop_assert!(r.audience() != Audience::GuestsOnly);
        }
    }

    /// A guest never passes a rule that needs permissions.
    #[test]
    fn guests_hold_nothing(r in rule(), res in resource(), now in any::<u64>()) {
        if !r.need().is_empty() {
            prop_assert!(authorize(None, &r, res.as_ref(), now).is_err());
        }
    }

    /// Adding a permission to the rule never turns a denial into an allow.
    #[test]
    fn stricter_rule_never_allows_more(
        s in subject(), r in rule(), extra in permset(), res in resource(), now in any::<u64>()
    ) {
        let stricter = r.needs_set(extra);
        if authorize(Some(&s), &r, res.as_ref(), now).is_err() {
            prop_assert!(authorize(Some(&s), &stricter, res.as_ref(), now).is_err());
        }
    }

    /// Without a resource, a rule with an object condition always refuses.
    #[test]
    fn object_rules_fail_closed(s in subject(), r in rule(), now in any::<u64>()) {
        if r.needs_resource() {
            prop_assert!(authorize(Some(&s), &r, None, now).is_err());
        }
    }

    /// Owner checks never pass for somebody else's resource unless the
    /// override permissions are held.
    #[test]
    fn owner_means_owner(s in subject(), owner in any::<u128>(), now in any::<u64>()) {
        let r = Rule::signed_in().allow_pending().allow_suspended().owner().unwrap();
        let res = Resource::new().owner(owner);
        let out = authorize(Some(&s), &r, Some(&res), now);
        prop_assert_eq!(out.is_ok(), owner == s.id());
    }

    /// 401 only for guests and stale factors; signed-in denials are 403.
    #[test]
    fn statuses(s in subject(), r in rule(), res in resource(), now in any::<u64>()) {
        if let Err(d) = authorize(Some(&s), &r, res.as_ref(), now) {
            prop_assert!(d.kind() != DenialKind::NeedsSignIn);
            prop_assert_eq!(d.status() == 401, d.kind() == DenialKind::StaleFactor);
        }
    }

    /// Set algebra.
    #[test]
    fn permset_laws(a in permset(), b in permset()) {
        prop_assert!(a.union(b).covers(&a));
        prop_assert!(a.covers(&a.intersection(b)));
        prop_assert!(a.difference(b).intersection(b).is_empty());
        prop_assert_eq!(a.covers(&b), b.difference(a).is_empty());
        prop_assert_eq!(PermSet::from_bytes(&a.to_bytes()), a);
    }

    /// A child role always holds at least what its parent holds, whatever
    /// the declaration order.
    #[test]
    fn inheritance_is_monotone(grants in prop::collection::vec(prop::collection::vec(0usize..8, 0..4), 2..8)) {
        let perms: Vec<String> = (0..8).map(|i| format!("p{i}")).collect();
        let perm_refs: Vec<&str> = perms.iter().map(String::as_str).collect();
        let names: Vec<String> = (0..grants.len()).map(|i| format!("r{i}")).collect();
        let mut b = Schema::builder("svc").permissions(&perm_refs);
        for (i, g) in grants.iter().enumerate() {
            let gs: Vec<&str> = g.iter().map(|&p| perm_refs[p]).collect();
            b = b.role(&names[i], &gs);
            if i > 0 {
                b = b.inherits(&names[i - 1]);
            }
        }
        let s = b.build().unwrap();
        for i in 1..names.len() {
            prop_assert!(s.grants([&names[i]]).covers(&s.grants([&names[i - 1]])));
        }
    }
}
