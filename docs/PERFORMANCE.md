# access-gate performance

Measured 2026-11-08 with criterion (`cargo bench`), Rust 1.99, release
profile, Windows 11 x86-64 on a shared development machine (other builds
were running). Median, with criterion's 95% interval. Treat them as
build-to-build comparisons, not reference-box numbers.

| Benchmark | Time | What it measures |
|---|---|---|
| `authorize/public` | 11.6 ns (10.8 to 12.5) | a public rule |
| `authorize/role_only` | 12.6 ns (11.3 to 14.1) | audience, standing, a 256-bit subset test |
| `authorize/owner_tenant` | 18.1 ns (16.7 to 19.7) | plus an owner-or-permission and a tenant condition |
| `authorize/guest_refused` | 9.8 ns (8.2 to 11.8) | a guest at a signed-in rule |
| `schema/grants_3_roles` | 46.8 ns (42.5 to 51.9) | role names to a permission set (once per sign-in) |
| `schema/build_200_perms` | 118 us (97 to 147) | compiling a 200-permission schema (once per boot) |

No allocation on a decision. Run with `cargo bench --bench decide`.
