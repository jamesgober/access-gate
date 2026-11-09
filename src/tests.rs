use alloc::{format, string::String, vec::Vec};
use core::time::Duration;

use crate::*;

fn blog() -> Schema {
    Schema::builder("web")
        .permissions(&["post.read", "post.write", "post.publish", "user.manage"])
        .attribute("org_id")
        .role("member", &["post.read"])
        .role("author", &["post.write"])
        .inherits("member")
        .role("editor", &["post.publish"])
        .inherits("author")
        .role("admin", &["user.manage"])
        .inherits("editor")
        .build()
        .unwrap()
}

#[test]
fn inheritance_is_resolved() {
    let s = blog();
    let admin = s.grants(["admin"]);
    assert_eq!(admin.len(), 4);
    let member = s.grants(["member"]);
    assert_eq!(member, s.perms(&["post.read"]).unwrap());
    assert!(admin.covers(&s.grants(["editor"])));
}

#[test]
fn parent_declared_after_child() {
    let s = Schema::builder("web")
        .permissions(&["a", "b"])
        .role("child", &["a"])
        .inherits("parent")
        .role("parent", &["b"])
        .build()
        .unwrap();
    assert_eq!(s.grants(["child"]).len(), 2);
}

#[test]
fn cycles_refuse_the_boot() {
    let err = Schema::builder("web")
        .permissions(&["a"])
        .role("x", &["a"])
        .inherits("y")
        .role("y", &[])
        .inherits("z")
        .role("z", &[])
        .inherits("x")
        .build()
        .unwrap_err();
    assert!(matches!(err, SchemaError::RoleCycle { .. }));
    let selfish = Schema::builder("web").role("x", &[]).inherits("x").build();
    assert!(matches!(selfish, Err(SchemaError::RoleCycle { .. })));
}

#[test]
fn unknown_names_refuse_the_boot() {
    let e = Schema::builder("web")
        .role("x", &["nope"])
        .build()
        .unwrap_err();
    assert!(matches!(e, SchemaError::UnknownPermission { .. }));
    let e = Schema::builder("web")
        .role("x", &[])
        .inherits("nope")
        .build()
        .unwrap_err();
    assert!(matches!(e, SchemaError::UnknownRole { .. }));
    let e = Schema::builder("web").inherits("x").build().unwrap_err();
    assert_eq!(e, SchemaError::InheritsWithoutRole);
    let s = blog();
    assert!(Rule::signed_in().needs(&s, &["post.nope"]).is_err());
    assert!(Rule::signed_in().attr_match(&s, "nope").is_err());
}

#[test]
fn names_are_checked() {
    for bad in ["", "Post.read", "post read", "p\u{e9}", &"x".repeat(65)] {
        let e = Schema::builder("web").permission(bad).build().unwrap_err();
        assert!(matches!(e, SchemaError::InvalidName { .. }), "{bad:?}");
    }
    let e = Schema::builder("web")
        .permissions(&["a", "a"])
        .build()
        .unwrap_err();
    assert!(matches!(e, SchemaError::Duplicate { .. }));
    let e = Schema::builder("web")
        .role("r", &[])
        .role("r", &[])
        .build()
        .unwrap_err();
    assert!(matches!(e, SchemaError::Duplicate { .. }));
}

#[test]
fn limits() {
    let names: Vec<String> = (0..257).map(|i| format!("p{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(
        Schema::builder("web")
            .permissions(&refs)
            .build()
            .unwrap_err(),
        SchemaError::TooManyPermissions
    );
    let ok = Schema::builder("web")
        .permissions(&refs[..256])
        .build()
        .unwrap();
    let last = ok.perm("p255").unwrap();
    assert_eq!(last.index(), 255);
    let mut b = Schema::builder("web");
    for i in 0..17 {
        b = b.attribute(&format!("a{i}"));
    }
    assert_eq!(b.build().unwrap_err(), SchemaError::TooManyAttributes);
}

#[test]
fn deep_inheritance_does_not_overflow() {
    let names: Vec<String> = (0..1000).map(|i| format!("r{i}")).collect();
    let mut b = Schema::builder("web").permission("p");
    b = b.role("r0", &["p"]);
    for i in 1..1000 {
        b = b.role(&names[i], &[]).inherits(&names[i - 1]);
    }
    let s = b.build().unwrap();
    assert_eq!(s.grants(["r999"]).len(), 1);
}

#[test]
fn unknown_role_grants_nothing() {
    let s = blog();
    assert!(s.grants(["ghost"]).is_empty());
    assert_eq!(s.grants(["ghost", "member"]).len(), 1);
}

#[test]
fn guests() {
    let s = blog();
    assert!(authorize(None, &Rule::guest(), None, 0).is_ok());
    assert!(authorize(None, &Rule::guest_only(), None, 0).is_ok());
    let e = authorize(None, &Rule::signed_in(), None, 0).unwrap_err();
    assert_eq!((e.kind(), e.status()), (DenialKind::NeedsSignIn, 401));
    let read = Rule::guest().needs(&s, &["post.read"]).unwrap();
    assert_eq!(authorize(None, &read, None, 0).unwrap_err().status(), 401);
}

#[test]
fn signed_in_subjects() {
    let s = blog();
    let alice = Subject::new(1).with_perms(s.grants(["author"]));
    assert!(authorize(Some(&alice), &Rule::guest(), None, 0).is_ok());
    let e = authorize(Some(&alice), &Rule::guest_only(), None, 0).unwrap_err();
    assert_eq!(e.kind(), DenialKind::GuestOnly);
    let publish = Rule::signed_in().needs(&s, &["post.publish"]).unwrap();
    let e = authorize(Some(&alice), &publish, None, 0).unwrap_err();
    assert_eq!(e.kind(), DenialKind::MissingPermission);
    assert_eq!(e.missing_perms(), s.perms(&["post.publish"]).unwrap());
    assert_eq!(e.status(), 403);
}

#[test]
fn standing() {
    let s = blog();
    let write = Rule::signed_in().needs(&s, &["post.write"]).unwrap();
    let read = Rule::signed_in()
        .needs(&s, &["post.read"])
        .unwrap()
        .allow_suspended();
    let base = Subject::new(1).with_perms(s.grants(["author"]));
    let suspended = base.with_status(Status::Suspended { until: Some(1_000) });
    assert_eq!(
        authorize(Some(&suspended), &write, None, 999)
            .unwrap_err()
            .kind(),
        DenialKind::Status
    );
    assert!(authorize(Some(&suspended), &read, None, 999).is_ok());
    assert!(
        authorize(Some(&suspended), &write, None, 1_000).is_ok(),
        "lapsed"
    );
    let forever = base.with_status(Status::Suspended { until: None });
    assert!(authorize(Some(&forever), &write, None, u64::MAX).is_err());
    let pending = base.with_status(Status::PendingVerification);
    assert!(authorize(Some(&pending), &write, None, 0).is_err());
    assert!(authorize(Some(&pending), &write.allow_pending(), None, 0).is_ok());
    assert!(authorize(Some(&forever), &Rule::guest(), None, 0).is_ok());
}

#[test]
fn ownership_and_tenancy() {
    let s = blog();
    let edit = Rule::signed_in()
        .needs(&s, &["post.write"])
        .unwrap()
        .owner_or(&s, &["post.publish"])
        .unwrap();
    let author = Subject::new(1)
        .with_perms(s.grants(["author"]))
        .with_tenant(9);
    let editor = Subject::new(2)
        .with_perms(s.grants(["editor"]))
        .with_tenant(9);
    let mine = Resource::new().owner(1).tenant(9);
    let theirs = Resource::new().owner(3).tenant(9);
    assert!(authorize(Some(&author), &edit, Some(&mine), 0).is_ok());
    assert!(authorize(Some(&author), &edit, Some(&theirs), 0).is_err());
    assert!(authorize(Some(&editor), &edit, Some(&theirs), 0).is_ok());
    assert!(
        authorize(Some(&author), &edit, None, 0).is_err(),
        "fails closed"
    );

    let tenant = Rule::signed_in().same_tenant().unwrap();
    assert!(authorize(Some(&author), &tenant, Some(&mine), 0).is_ok());
    let other = Resource::new().tenant(8);
    assert!(authorize(Some(&author), &tenant, Some(&other), 0).is_err());
    let no_tenant = Subject::new(4);
    assert!(authorize(Some(&no_tenant), &tenant, Some(&Resource::new()), 0).is_err());
}

#[test]
fn attributes_and_freshness() {
    let s = blog();
    let org = s.attribute("org_id").unwrap();
    let rule = Rule::signed_in().attr_match(&s, "org_id").unwrap();
    let a = Subject::new(1).with_attrs(Attrs::new().with(org, 5));
    assert!(authorize(Some(&a), &rule, Some(&Resource::new().attr(org, 5)), 0).is_ok());
    assert!(authorize(Some(&a), &rule, Some(&Resource::new().attr(org, 6)), 0).is_err());
    assert!(authorize(Some(&a), &rule, Some(&Resource::new()), 0).is_err());

    let step_up = Rule::signed_in()
        .fresh_factor(Duration::from_secs(300))
        .unwrap();
    let fresh = Subject::new(1).with_factor_at(1_000_000);
    assert!(authorize(Some(&fresh), &step_up, None, 1_000_000 + 300_000).is_ok());
    let e = authorize(Some(&fresh), &step_up, None, 1_000_000 + 300_001).unwrap_err();
    assert_eq!((e.kind(), e.status()), (DenialKind::StaleFactor, 401));
    assert!(authorize(Some(&Subject::new(1)), &step_up, None, 0).is_err());
    assert!(
        authorize(Some(&fresh), &step_up, None, 999_999).is_err(),
        "future factor time"
    );
}

#[test]
fn condition_limit() {
    let mut rule = Rule::signed_in();
    for _ in 0..MAX_CONDITIONS {
        rule = rule.owner().unwrap();
    }
    assert_eq!(rule.owner().unwrap_err(), SchemaError::TooManyConditions);
}

#[test]
fn permset_bytes_round_trip() {
    let set: PermSet = [0u8, 63, 64, 200, 255]
        .into_iter()
        .map(Perm::from_index)
        .collect();
    assert_eq!(PermSet::from_bytes(&set.to_bytes()), set);
    assert_eq!(set.iter().count(), 5);
    assert_eq!(format!("{set:?}"), "{0, 63, 64, 200, 255}");
}

#[test]
fn guest_grants() {
    let s = Schema::builder("web")
        .permissions(&["post.read", "post.write"])
        .guest_grants(&["post.read"])
        .role("author", &["post.write"])
        .build()
        .unwrap();
    let read = Rule::guest().needs(&s, &["post.read"]).unwrap();
    let both = Rule::signed_in()
        .needs(&s, &["post.read", "post.write"])
        .unwrap();
    assert!(authorize_with(s.guests(), None, &read, None, 0).is_ok());
    assert!(
        authorize(None, &read, None, 0).is_err(),
        "without the guest set"
    );
    let author = Subject::new(1).with_perms(s.grants(["author"]));
    assert!(authorize_with(s.guests(), Some(&author), &both, None, 0).is_ok());
    assert!(authorize(Some(&author), &both, None, 0).is_err());
    let owned = read.owner().unwrap();
    assert!(
        authorize_with(s.guests(), None, &owned, None, 0).is_err(),
        "conditions need a subject"
    );
    let e = Schema::builder("web")
        .guest_grants(&["nope"])
        .build()
        .unwrap_err();
    assert!(matches!(e, SchemaError::UnknownPermission { .. }));
}
