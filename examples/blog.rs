//! A blog's rules, decided for a few subjects.
//!
//! Run with `cargo run --example blog`.

use access_gate::{Resource, Rule, Schema, Subject, authorize_with};

fn main() -> Result<(), access_gate::SchemaError> {
    let schema = Schema::builder("blog")
        .permissions(&["post.read", "post.write", "post.edit.any"])
        .guest_grants(&["post.read"])
        .role("member", &["post.read"])
        .role("author", &["post.write"])
        .inherits("member")
        .role("editor", &["post.edit.any"])
        .inherits("author")
        .build()?;
    let rules = [
        ("read", Rule::guest().needs(&schema, &["post.read"])?),
        (
            "edit",
            Rule::signed_in()
                .needs(&schema, &["post.write"])?
                .owner_or(&schema, &["post.edit.any"])?,
        ),
    ];
    let post = Resource::new().owner(1);
    let people = [
        ("guest", None),
        (
            "alice (author, owner)",
            Some(Subject::new(1).with_perms(schema.grants(["author"]))),
        ),
        (
            "bob (author)",
            Some(Subject::new(2).with_perms(schema.grants(["author"]))),
        ),
        (
            "eve (editor)",
            Some(Subject::new(3).with_perms(schema.grants(["editor"]))),
        ),
    ];
    for (who, subject) in &people {
        for (what, rule) in &rules {
            let answer =
                match authorize_with(schema.guests(), subject.as_ref(), rule, Some(&post), 0) {
                    Ok(()) => "allowed".to_owned(),
                    Err(d) => format!("{} ({d})", d.status()),
                };
            println!("{who:24} {what:5} {answer}");
        }
    }
    Ok(())
}
