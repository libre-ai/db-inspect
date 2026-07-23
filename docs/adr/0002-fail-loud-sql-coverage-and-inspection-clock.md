# ADR-0002 — Fail-loud SQL coverage and explicit inspection clock

- Status: Accepted for implementation, staged rollout
- Date: 2026-07-11
- Extends: ADR-0001 (scope and upstream policy)

## Context

`db-inspect` performs structural inspection over PostgreSQL schema and migration artifacts. Its previous lenient parser retried a failed whole-file parse by splitting on every semicolon and silently discarded fragments that `sqlparser` could not parse. Reports nevertheless emitted `parser_error_count: 0`.

That behavior could produce a false PASS over a partially inspected schema. Waiver validity had a similar integrity defect: expiry was compared against the fixed timestamp `2026-06-30T00:00:00Z`, so a waiver could remain accepted after its real expiry.

A first fail-loud implementation exposed every dropped semicolon fragment. This correctly blocked incomplete inspection but produced 955 findings on the generated install SQL from `microsoft/pg_durable`, because semicolons inside dollar-quoted PL/pgSQL bodies were mistaken for independent statements. The gate therefore requires a PostgreSQL-aware lexical splitter before rollout.

## Decision

1. Every PostgreSQL statement that cannot be structurally parsed produces `SQL_STATEMENT_UNPARSED` in the `inspection_integrity` category.
2. `parser_error_count` is derived from these findings and is never hardcoded.
3. Protected-branch and release profiles fail closed on `inspection_integrity`; local profiles may keep the finding as a warning.
4. Raw SQL and parser error strings are excluded from findings. Reports expose only one-based statement positions, preventing schema comments, literals or secrets from leaking.
5. Fallback statement splitting recognizes:
   - single-quoted strings, including doubled quotes and backslash escapes;
   - double-quoted identifiers;
   - `$tag$...$tag$` and `$$...$$` bodies;
   - line comments;
   - nested block comments.
6. Semicolons inside these lexical regions never create extra statements.
7. Reports carry an RFC3339 `scope.inspected_at` timestamp. Production defaults to current UTC; deterministic fixtures and CI inject `--inspection-at`.
8. Waiver timestamps are parsed as RFC3339 and compared to the injected clock. Missing, malformed or expired waivers fail according to gate policy; an invalid clock is a blocking `INSPECTION_CLOCK_INVALID` finding.
9. The report remains `db_inspect.report.v0.1`: added fields are additive under the current schema. The gate-semantics change is documented as a tool behavior change and must be rolled out in stages.

## Corpus evidence

After the PostgreSQL-aware splitter:

| Corpus | Parser errors | Explicit blocking review |
| --- | ---: | ---: |
| `rumble-feed-mind/migrations` | 0 | 0 |
| `rumble-ai-practices/crates/store/migrations` | 0 | 0 |
| `pg_durable--0.1.1.sql` | 0 | 7 |

The `pg_durable` result first decreased from 955 to 10 complete unsupported statements. Token-aware normalization of `@extschema@` in ordinary SQL lexical state covered the extension-template `SET LOCAL search_path` statement without touching quoted strings, comments or dollar-quoted bodies. Unknown template tokens remain fail-closed.

The two `CREATE OPERATOR` declarations are now structurally extracted; unqualified implementation functions block inspection and unsupported declaration options remain parser errors. The seven `DO $$...$$` blocks are no longer generic parser failures: they produce focused, redacted `inspection_integrity` findings. Five containing `EXECUTE` are marked as dynamic SQL and two as opaque procedural review. All seven remain blocking—`parser_error_count: 0` does not turn uninspected PL/pgSQL into a PASS.

## Rollout

1. Keep protected-branch adoption staged while product corpora and central fixtures are synchronized.
2. Run product migrations under the local profile and create product DB manifests.
3. Enable protected-branch blocking only for products whose corpus has zero unexplained parser errors.
4. Keep release fail-closed.
5. Treat known unsupported constructs explicitly in a future policy only after a rule can inspect their security-relevant semantics; never silently allowlist them.

No global CI or Bolt gate is activated by this ADR.

## Compatibility

- CLI: additive `--inspection-at <RFC3339>` option.
- JSON: additive `scope.inspected_at`, waiver `expiry_valid`/`expired`, and real parser metrics.
- Behavior: artifacts with unsupported or malformed SQL may move from `passed` to `failed`.
- Dependency: `time` (MIT OR Apache-2.0 ecosystem-compatible) provides RFC3339 parsing and current UTC formatting.

## Verification

Tests cover:

- one malformed statement does not hide valid surrounding statements;
- dollar-quoted PL/pgSQL bodies remain one statement despite internal semicolons;
- quotes and nested comments do not split statements;
- parser errors block protected branches and increment the metric;
- waiver expiry follows an injected clock;
- invalid clocks produce integrity findings;
- report redaction remains effective.

The release gate requires format, strict Clippy, full tests, dependency license/advisory checks and corpus measurements.

## Consequences

- Positive: no schema can pass while inspection silently drops SQL.
- Positive: waiver decisions are reproducible and time-correct.
- Positive: generated extension SQL produces bounded, statement-level coverage findings.
- Cost: unsupported PostgreSQL syntax can block rollout until the inspector gains coverage.
- Cost: CI fixtures must inject a clock for reproducibility.
- Residual limitation: lexical statement splitting is not a full PostgreSQL parser; corpus tests remain mandatory.

## Non-goals

- Executing SQL or connecting to a live database.
- Automatically waiving unsupported extension statements.
- Automatic remediation.
- Replacing Bolt gate policy or Gear evidence storage.
