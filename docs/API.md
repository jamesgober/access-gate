# access-gate API

Everything is re-exported at the crate root.

## Schema (boot)

| Item | Purpose |
|---|---|
| `Schema::builder(service) -> SchemaBuilder` | start declaring |
| `SchemaBuilder::permissions(&[..])`, `permission(name)` | each becomes one bit (at most 256) |
| `SchemaBuilder::role(name, &[grants])`, `inherits(parent)` | roles with inheritance (at most 1024) |
| `SchemaBuilder::attribute(name)` | attributes rules may compare (at most 16) |
| `SchemaBuilder::guest_grants(&[..])` | permissions every visitor holds; read back with `Schema::guests` |
| `SchemaBuilder::build() -> Result<Schema, SchemaError>` | compile; inheritance resolved, cycles refused |
| `Schema::fingerprint` | a version of the bit positions, to check stored permission sets against |
| `Schema::perm`, `perms`, `perm_name`, `role`, `role_perms`, `grants`, `attribute`, `attribute_name`, `attributes`, `permission_count`, `role_count`, `service` | lookups |

Names: 1 to 64 bytes of `a-z 0-9 . _ - :`.

## Rules (boot)

| Item | Purpose |
|---|---|
| `Rule::guest()`, `guest_only()`, `signed_in()` | the audience |
| `needs(&schema, &[..])?`, `needs_set(PermSet)` | required permissions |
| `allow_pending()`, `allow_suspended()` | standings let through |
| `owner()?`, `owner_or(&schema, &[..])?`, `same_tenant()?`, `attr_match(&schema, name)?`, `fresh_factor(Duration)?`, `when(Condition)?` | conditions (at most 8) |
| `audience`, `need`, `conditions`, `needs_resource`, `is_public`, `allows_pending`, `allows_suspended` | inspection |

## Request

| Item | Purpose |
|---|---|
| `authorize(Option<&Subject>, &Rule, Option<&Resource>, now_ms) -> Result<(), Denial>` | the decision |
| `authorize_with(&guests, ...)` | the same, with the schema's guest grants |
| `Subject::new(id)`, `with_perms`, `with_tenant`, `with_status`, `with_attrs`, `with_factor_at` | the signed-in party |
| `Resource::new()`, `owner`, `tenant`, `attr` | what the handler loaded |
| `Denial::kind`, `status`, `missing_perms` | why, and the status to send |

## Types

`Perm`, `PermSet` (256-bit set: `covers`, `union`, `intersection`, `difference`, `to_bytes`, `from_bytes`), `AttrId`, `Attrs`, `Status` (`Active`, `PendingVerification`, `Suspended { until }`), `Audience`, `Condition`, `RoleId`, `DenialKind`, `SchemaError`.
