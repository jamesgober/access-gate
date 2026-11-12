<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>access-gate</b>
    <br>
    <sub><sup>AUTHORIZATION</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/access-gate"><img alt="Crates.io" src="https://img.shields.io/crates/v/access-gate"></a>
    <a href="https://docs.rs/access-gate"><img alt="docs.rs" src="https://img.shields.io/docsrs/access-gate"></a>
    <a href="https://github.com/jamesgober/access-gate/actions"><img alt="CI" src="https://github.com/jamesgober/access-gate/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>access-gate</strong> answers one question for every request a service routes: <strong>may this subject do this, to this thing, right now?</strong> A service declares its permissions, roles, and attributes once at boot; roles compile to permission bit sets with inheritance resolved, and every mistake (an unknown name, a role cycle) refuses the boot. A decision is then a branch on the rule's audience, a 256-bit subset test, and a few comparisons for ownership, tenancy, attributes, and second-factor freshness.
    </p>
    <p>
        Deny by default, storage-free, and protocol-free: the caller hands it the subject (from the server-side session) and the resource (from the handler). No runtime dependencies; <code>no_std</code> with <code>alloc</code>.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: <code>0.5.0</code>, pre-release.</strong> Published on crates.io. The API may still change before 1.0.
    </blockquote>
</div>

<hr>
<br>

## Installation

```toml
[dependencies]
access-gate = "0.5"
```

## Usage

```rust
use access_gate::{authorize, Resource, Rule, Schema, Subject};

// Boot: the vocabulary, compiled once. Mistakes refuse the boot.
let schema = Schema::builder("web")
    .permissions(&["post.read", "post.write", "post.edit.any"])
    .role("member", &["post.read"])
    .role("author", &["post.write"]).inherits("member")
    .role("editor", &["post.edit.any"]).inherits("author")
    .build()?;
let edit_post = Rule::signed_in()
    .needs(&schema, &["post.write"])?
    .owner_or(&schema, &["post.edit.any"])?;

// Sign-in stores what the roles grant; a request decides from memory.
let alice = Subject::new(1).with_perms(schema.grants(["author"]));
let post = Resource::new().owner(1);
assert!(authorize(Some(&alice), &edit_post, Some(&post), 0).is_ok());
assert_eq!(authorize(None, &edit_post, Some(&post), 0).unwrap_err().status(), 401);
```

## What a rule can say

| Part | Example |
|---|---|
| audience | `Rule::guest()` (public), `Rule::guest_only()` (login form), `Rule::signed_in()` |
| permissions | `.needs(&schema, &["post.write"])?` |
| standing | refused when pending or suspended, unless `.allow_pending()` / `.allow_suspended()` |
| ownership | `.owner()?`, `.owner_or(&schema, &["post.edit.any"])?` |
| tenancy | `.same_tenant()?` |
| attributes | `.attr_match(&schema, "org_id")?` |
| step-up | `.fresh_factor(Duration::from_secs(300))?` |

A denial says why (`DenialKind`, for audit) and which status to send: 401 when signing in would help, 403 otherwise. The reason never goes to the client.

## Documentation

- [`docs/API.md`](./docs/API.md): every public item.
- [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md): measured costs.
- [`dev/PLAN.md`](./dev/PLAN.md): design and decisions.
- [`CHANGELOG.md`](./CHANGELOG.md).

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, and `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
