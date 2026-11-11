<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>access-gate</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.4.0] - 2026-11-11

Hardening fixes.

### Changed

- `AttrId::from_index` returns `Option<AttrId>`: an index past 15 no longer
  wraps onto another attribute (breaking).
- `owner_or` with no permissions, or `Condition::OwnerOr` with an empty set,
  refuses with `SchemaError::EmptyOverride` instead of admitting every
  signed-in subject.
- A pending or suspended subject passes an open rule that the guest grants
  cover: what a guest may read, a member of any standing may read.

### Added

- `Schema::fingerprint`: a 64-bit version of the permission and attribute
  positions, for checking a permission set stored outside the process.

### Migrating from 0.3

- `AttrId::from_index(i)` returns `Option<AttrId>`: write
  `AttrId::from_index(i).ok_or(..)?`, or get ids from
  `Schema::attribute(name)`, which never needs an index.
- An `owner_or` rule built from an empty list now refuses the boot
  (`SchemaError::EmptyOverride`): give it the override permissions, or use
  `owner()`.
- If you store a `PermSet` outside the process, store
  `Schema::fingerprint()` next to it and refuse the set when it differs.

See [`docs/release/v0.4.0.md`](./docs/release/v0.4.0.md).

---

## [0.3.0] - 2026-11-08

Hardening: property tests for every invariant, fuzz targets for every parser, and benchmarks with measured numbers.

See [`docs/release/v0.3.0.md`](./docs/release/v0.3.0.md).

---

## [0.2.0] - 2026-11-08

Design lock: the public API settled with the neighbouring server and router crates, documented item by item, with examples.

See [`docs/release/v0.2.0.md`](./docs/release/v0.2.0.md).

---

## [0.1.0] - 2026-11-08

First working core: the types, the main path, and the in-memory stores, with unit and integration tests. For gatekeeper-io this includes the end-to-end sign-in scenario: sign in and out, forged and expired tokens refused, CSRF on login and logout.

See [`docs/release/v0.1.0.md`](./docs/release/v0.1.0.md).

