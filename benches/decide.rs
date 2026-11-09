//! Decision cost: role-only, with conditions, and the schema compile.

use std::hint::black_box;

use access_gate::{Resource, Rule, Schema, Subject, authorize};
use criterion::{Criterion, criterion_group, criterion_main};

fn schema() -> Schema {
    let mut b = Schema::builder("web");
    let names: Vec<String> = (0..200).map(|i| format!("perm.{i}")).collect();
    for n in &names {
        b = b.permission(n);
    }
    b.role("member", &["perm.1", "perm.2"])
        .role("author", &["perm.3", "perm.150"])
        .inherits("member")
        .role("editor", &["perm.199"])
        .inherits("author")
        .build()
        .expect("schema")
}

fn bench(c: &mut Criterion) {
    let s = schema();
    let subject = Subject::new(7)
        .with_perms(s.grants(["editor"]))
        .with_tenant(3);
    let role_only = Rule::signed_in()
        .needs(&s, &["perm.150", "perm.199"])
        .expect("rule");
    let with_conditions = role_only
        .owner_or(&s, &["perm.199"])
        .expect("rule")
        .same_tenant()
        .expect("rule");
    let post = Resource::new().owner(9).tenant(3);

    c.bench_function("authorize/public", |b| {
        b.iter(|| {
            authorize(
                black_box(Some(&subject)),
                black_box(&Rule::guest()),
                None,
                0,
            )
        })
    });
    c.bench_function("authorize/role_only", |b| {
        b.iter(|| authorize(black_box(Some(&subject)), black_box(&role_only), None, 0))
    });
    c.bench_function("authorize/owner_tenant", |b| {
        b.iter(|| {
            authorize(
                black_box(Some(&subject)),
                black_box(&with_conditions),
                black_box(Some(&post)),
                0,
            )
        })
    });
    c.bench_function("authorize/guest_refused", |b| {
        b.iter(|| authorize(black_box(None), black_box(&role_only), None, 0))
    });
    c.bench_function("schema/grants_3_roles", |b| {
        b.iter(|| black_box(&s).grants(black_box(["member", "author", "editor"])))
    });
    c.bench_function("schema/build_200_perms", |b| b.iter(schema));
}

criterion_group!(benches, bench);
criterion_main!(benches);
