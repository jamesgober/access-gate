# access-gate: Roadmap

| Version | Status | Scope |
|---|---|---|
| 0.1.0 | done | core types, the main path, in-memory stores, unit and integration tests |
| 0.2.0 | done | design lock: API settled with the server and router crates, docs, examples |
| 0.3.0 | done | property tests, fuzz targets, benchmarks, the end-to-end sign-in scenario |
| 0.4.0 | done | hardening: schema fingerprint, no attribute aliasing, no empty overrides, guest grants for every standing |
| 0.5.0 | done | fingerprint covers role and guest grants, unambiguous sections |
| 0.6.0 | next | `explain(subject, rule, resource)` for administrators and tests; a route coverage report (who can reach what, through which role); explicit denies that override grants; scoped API keys that can only narrow their owner's permissions |
| 0.7.0 | | policy loaded from configuration (roles and grants as data, same compile step); versioned policy snapshots swapped whole |
| 0.9.x | | polish and freeze: every gap revisited, measured against the targets |
| 1.0.0 | maintainer's call | after real use by the router end to end and an adversarial review |
