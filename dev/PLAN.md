# access-gate: Plan

> Design and decision record. Read order: [`../REPS.md`](../REPS.md), [`DIRECTIVES.md`](./DIRECTIVES.md), this file, [`ROADMAP.md`](./ROADMAP.md).

## 1. Purpose

access-gate is authorization: deny-by-default permission sets compiled from roles, rules with audience, standing, ownership, tenancy, attribute, and step-up conditions. Storage-free and protocol-free. Authentication is auth-gate.

## 2. Decisions

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-11-08 | Authorization only; authentication is auth-gate; both meet in gatekeeper-io | single-purpose crates; the router needs only this one |
| D-002 | 2026-11-08 | Roles compile to `PermSet` (256 bits) at boot with inheritance resolved; cycles and unknown names refuse the boot | a decision is four AND operations; a mistake never becomes an open door |
| D-003 | 2026-11-08 | Deny by default; every rule names its audience | nothing is reachable by omission |
| D-004 | 2026-11-08 | Storage-free: the caller passes the subject and the resource | no database on the request path; testable alone |
| D-005 | 2026-11-08 | Object conditions without a resource refuse | the check fails closed if a handler forgets to load the resource |
| D-006 | 2026-11-08 | A guests-only rule that also needs permissions or conditions refuses everyone | found by a property test: such a rule cannot be met, so guessing would open it |
| D-007 | 2026-11-08 | An unknown role name at sign-in grants nothing | a role removed from the schema but still stored fails closed |
| D-008 | 2026-11-08 | Rules are `Copy` with at most 8 inline conditions | no allocation or pointer chase per decision |
| D-009 | 2026-11-08 | Guest grants: a schema names permissions every visitor holds (`guest_grants`); `authorize_with` applies them to guests and members | public pages that still name a permission; a guest is not a signed-in subject |
| D-010 | 2026-11-11 | `Schema::fingerprint` (FNV-1a over the service and the ordered permission and attribute names) | a stored permission set is positional; a consumer must refuse one written under another schema (hardening) |
| D-011 | 2026-11-11 | `AttrId::from_index` returns `Option`; `owner_or` with no permissions refuses the boot; guest-covered open rules pass every standing | hardening |
