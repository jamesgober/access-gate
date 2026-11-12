//! Regression tests for the 2026-11-11 hardening pass. Each failed
//! before its fix.

use access_gate::*;

/// a pending or suspended member reads what a guest reads.
#[test]
fn test_status_member_with_guest_grant_is_allowed() {
    let schema = Schema::builder("web")
        .permissions(&["post.read", "post.write"])
        .guest_grants(&["post.read"])
        .build()
        .unwrap();
    let read = Rule::guest().needs(&schema, &["post.read"]).unwrap();
    let write = Rule::signed_in().needs(&schema, &["post.write"]).unwrap();
    let pending = Subject::new(1)
        .with_status(Status::PendingVerification)
        .with_perms(schema.perms(&["post.write"]).unwrap());
    let suspended = Subject::new(2).with_status(Status::Suspended { until: None });
    for s in [pending, suspended] {
        assert!(authorize_with(schema.guests(), Some(&s), &read, None, 0).is_ok());
    }
    // What membership adds is still guarded by the status.
    let d = authorize_with(schema.guests(), Some(&pending), &write, None, 0).unwrap_err();
    assert_eq!(d.kind(), DenialKind::Status);
}

/// an attribute index past 15 never aliases attribute 0.
#[test]
fn test_attr_id_out_of_range_is_none() {
    assert_eq!(AttrId::from_index(16), None);
    assert_eq!(AttrId::from_index(255), None);
    assert_eq!(AttrId::from_index(15).map(AttrId::index), Some(15));
}

/// an override with no permissions refuses the boot.
#[test]
fn test_owner_or_empty_override_is_refused() {
    let schema = Schema::builder("web")
        .permissions(&["post.write"])
        .build()
        .unwrap();
    let configured: Vec<&str> = Vec::new();
    assert_eq!(
        Rule::signed_in()
            .owner_or(&schema, &configured)
            .unwrap_err(),
        SchemaError::EmptyOverride
    );
    assert_eq!(
        Rule::signed_in()
            .when(Condition::OwnerOr(PermSet::EMPTY))
            .unwrap_err(),
        SchemaError::EmptyOverride
    );
}

/// reordering, inserting, or renaming a permission or an
/// attribute changes the fingerprint; roles do not affect bit positions.
#[test]
fn test_fingerprint_tracks_bit_positions() {
    let base = || {
        Schema::builder("web")
            .permissions(&["post.read", "admin.delete"])
            .attribute("org_id")
    };
    let a = base().build().unwrap();
    assert_eq!(
        a.fingerprint(),
        base().build().unwrap().fingerprint(),
        "stable"
    );
    let with_role = base().role("member", &["post.read"]).build().unwrap();
    assert_ne!(
        a.fingerprint(),
        with_role.fingerprint(),
        "roles are part of it"
    );
    let reordered = Schema::builder("web")
        .permissions(&["admin.delete", "post.read"])
        .attribute("org_id");
    let inserted = base().permission("post.write");
    let attr = Schema::builder("web")
        .permissions(&["post.read", "admin.delete"])
        .attribute("team_id");
    let service = Schema::builder("api")
        .permissions(&["post.read", "admin.delete"])
        .attribute("org_id");
    for other in [reordered, inserted, attr, service] {
        assert_ne!(a.fingerprint(), other.build().unwrap().fingerprint());
    }
}

/// A permission or attribute named like a section cannot shift the
/// sections: these two schemas once gave the same fingerprint.
#[test]
fn test_fingerprint_section_names_do_not_collide() {
    let a = Schema::builder("web")
        .permissions(&["post.read", "attrs", "org"])
        .attribute("tenant")
        .build()
        .unwrap();
    let b = Schema::builder("web")
        .permissions(&["post.read"])
        .attribute("org")
        .attribute("attrs")
        .attribute("tenant")
        .build()
        .unwrap();
    assert_ne!(a.fingerprint(), b.fingerprint());
}

/// A role that loses a permission changes the fingerprint, so sessions
/// that carry the old grant end.
#[test]
fn test_fingerprint_changes_when_a_role_loses_a_grant() {
    let before = Schema::builder("web")
        .permissions(&["post.read", "admin.delete"])
        .role("member", &["post.read", "admin.delete"])
        .build()
        .unwrap();
    let after = Schema::builder("web")
        .permissions(&["post.read", "admin.delete"])
        .role("member", &["post.read"])
        .build()
        .unwrap();
    assert_ne!(before.fingerprint(), after.fingerprint());
    // An inherited grant counts too.
    let inherit = |grant: &[&str]| {
        Schema::builder("web")
            .permissions(&["a", "b"])
            .role("base", grant)
            .role("child", &[])
            .inherits("base")
            .build()
            .unwrap()
            .fingerprint()
    };
    assert_ne!(inherit(&["a", "b"]), inherit(&["a"]));
    // Guest grants too.
    let guests = |grant: &[&str]| {
        Schema::builder("web")
            .permissions(&["a"])
            .guest_grants(grant)
            .build()
            .unwrap()
            .fingerprint()
    };
    assert_ne!(guests(&["a"]), guests(&[]));
}
