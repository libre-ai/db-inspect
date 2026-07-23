# ADR-0001 — Scope and upstream policy

- Status: Accepted
- Date: 2026-06-29
- Upstream: [Scythe](https://github.com/Goldziher/scythe)

## Context

`db-inspect` is a companion repository in the Presto-Matic / Agent-O-Matic ecosystem. Its role is **SQL and database inspection**. It is intentionally separate from the Presto-Matic product repo so heavy dependencies, operational lifecycle, and upstream tracking stay isolated.

This repository replaces the former `vault-inspector` name, which was ambiguous because it suggested a user-facing vault, a secrets manager, or a vault product. Architecturally, the project belongs to the tooling layer and is the database-specialized counterpart to the more general structural-inspection scope.

## Decision

Build `db-inspect` as an upstream-first, sovereign Rust project:

- track upstream releases/tags/commits explicitly;
- keep local patches small and temporary;
- expose stable contracts rather than leaking upstream internals to consumers;
- enforce permissive OSS licensing and vulnerability gates in CI;
- default to self-hosted/EU-resident operation and avoid US hyperscaler requirements.

## Integration contract

- input: SQL files, migrations, or live DATABASE_URL in CI
- output: human, JSON, and SARIF-style reports
- policy: fail only on configured high-confidence security findings

## Naming policy

- keep `db-inspect` as the repository/crate identifier;
- describe it externally as a database security inspector, not as a vault product;
- do not rename back to vault-oriented terminology;
- do not merge it into a general-purpose inspector unless the database rule set remains shallow enough to be generic inspection.

## Non-goals

- no ORM replacement
- no migration framework replacement
- no production DB mutation during inspection

## Consequences

- The companion can iterate independently from Presto-Matic.
- Presto-Matic avoids accidental dependency bloat and can roll back integration by switching contracts off.
- Upstream changes are absorbed deliberately through version bumps, changelog review, and contract tests.
