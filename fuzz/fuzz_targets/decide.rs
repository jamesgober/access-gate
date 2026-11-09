//! Schemas, rules, subjects, and resources built from arbitrary bytes: never
//! a panic, and every allow respects the invariants.
#![no_main]

use access_gate::{
    AttrId, Attrs, Audience, Condition, Perm, PermSet, Resource, Rule, Schema, Status, Subject,
    authorize,
};
use libfuzzer_sys::fuzz_target;

struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u8(&mut self) -> u8 {
        let (b, rest) = self.0.split_first().map_or((0, &[][..]), |(b, r)| (*b, r));
        self.0 = rest;
        b
    }
    fn u64(&mut self) -> u64 {
        (0..8).fold(0, |acc, _| (acc << 8) | u64::from(self.u8()))
    }
    fn perms(&mut self) -> PermSet {
        let n = self.u8() % 8;
        (0..n).map(|_| Perm::from_index(self.u8())).collect()
    }
}

fuzz_target!(|data: &[u8]| {
    let mut b = Bytes(data);

    // A schema with random names and inheritance; errors are fine, panics are not.
    let names: Vec<String> = (0..b.u8() % 6).map(|i| format!("r{}", i)).collect();
    let mut sb = Schema::builder("svc").permissions(&["p0", "p1", "p2", "p3"]);
    for n in &names {
        sb = sb.role(n, &["p1"]);
        let parent = b.u8() as usize % (names.len() + 1);
        if parent < names.len() {
            sb = sb.inherits(&names[parent]);
        }
    }
    if let Ok(schema) = sb.build() {
        for n in &names {
            let set = schema.grants([n.as_str()]);
            assert!(set.covers(&schema.perms(&["p1"]).unwrap()));
        }
    }

    let mut rule = match b.u8() % 3 {
        0 => Rule::guest(),
        1 => Rule::guest_only(),
        _ => Rule::signed_in(),
    }
    .needs_set(b.perms());
    for _ in 0..(b.u8() % 4) {
        let c = match b.u8() % 5 {
            0 => Condition::Owner,
            1 => Condition::OwnerOr(b.perms()),
            2 => Condition::SameTenant,
            3 => Condition::AttrMatch(AttrId::from_index(b.u8())),
            _ => Condition::FreshFactor(b.u64()),
        };
        rule = rule.when(c).unwrap_or(rule);
    }
    let status = match b.u8() % 3 {
        0 => Status::Active,
        1 => Status::PendingVerification,
        _ => Status::Suspended {
            until: Some(b.u64()),
        },
    };
    let subject = Subject::new(u128::from(b.u64()))
        .with_perms(b.perms())
        .with_tenant(b.u64() % 3)
        .with_status(status)
        .with_attrs(Attrs::new().with(AttrId::from_index(b.u8()), b.u64() % 3))
        .with_factor_at(b.u64());
    let resource = Resource::new()
        .owner(u128::from(b.u64() % 3))
        .tenant(b.u64() % 3)
        .attr(AttrId::from_index(b.u8()), b.u64() % 3);
    let now = b.u64();
    for (s, r) in [
        (Some(&subject), Some(&resource)),
        (Some(&subject), None),
        (None, Some(&resource)),
    ] {
        if authorize(s, &rule, r, now).is_ok() && !rule.is_public() {
            match s {
                Some(s) => {
                    assert!(s.perms().covers(rule.need()));
                    assert_ne!(rule.audience(), Audience::GuestsOnly);
                }
                None => assert!(rule.need().is_empty()),
            }
        }
    }
});
