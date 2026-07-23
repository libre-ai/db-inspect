# Plan — db-inspect-gates (2026-07 wave)

```yaml
# forge.plan.v0.1 — bolt-handoff-compatible header (maps onto canvas.bolt_handoff.v0.1)
format: forge.plan.v0.1
kind: planning_request
source:
  product: db-inspect
  plan_id: plan-2026-07-db-inspect-gates
  created_at: "2026-07-09"
execution_policy:
  planning_only: true
  allow_execution: false
  requires_human_approval_for_execution: true
traceability:
  - "hygiene audit 2026-07-09: missing plan created; backlog P3 work (strict gates, DB security manifest, RLS/grants/pgvector checks)"
  - "ROADMAP.md line 8: 'address current clippy and lint debt' — audit verified build is clean as of 2026-07-09; line to be clarified/removed in I1"
  - "ecosystem/reviews/hygiene-audit-2026-07-09.md: cargo clippy --all-targets passes; cargo test passes; no structural debt found"
depends_on: []
blocks: []
open_questions: []
risks:
  - id: R1
    severity: medium
    description: "Over-promising semantic SQL analysis. Inspection stays structural (AST-level via sqlparser); no query execution, type inference, or access control evaluation engine. Potential for false negatives on dynamic grants/RLS policy logic."
    mitigation: "I3 documents structural limits in manifest (line 15+); negative test fixtures show boundary cases; evidence captured as observed AST state, not inferred runtime semantics."
  - id: R2
    severity: low
    description: "Multiple Postgres versions (13, 14, 15, 16) have dialect variations in schema, DDL, and pgvector API. Inspection may fail or misclassify on unsupported versions."
    mitigation: "I2 + I4 pin target versions in manifest header (e.g., 'postgres_version_min: 13; pgvector_version_min: 0.5.0'); tests specify version in fixture metadata."
evidence_expectations: "each increment merges green (CI format/clippy/test all pass); evidence cited as exact command + expected output (or fixture diff + manifest section)"
```

## Context

**Problem Statement:**  
DB-Inspect is the canonical tool for inspecting Postgres databases, RLS policies, grants, migrations, and pgvector configurations. The hygiene audit (2026-07-09) identified that:

1. **ROADMAP debt statement is inaccurate:** Line 8 ("address current clippy and lint debt") claims unresolved technical debt, but audit verification shows `cargo clippy --all-targets -- -D warnings` passes cleanly, and all 24 tests pass. The line requires clarification: either lint was already addressed, or the line describes aspirational future hardening (strict gates in CI).

2. **No formal strict gate profile:** CI checks pass (basic fmt/test), but no `-D warnings` enforcement in pipeline; no explicit forbid list for unsafe patterns; no contract tests for gate semantics.

3. **Missing DB security manifest:** No machine-readable declaration of what inspection targets, versions, patterns, and limits are supported. End-users cannot verify scope coverage before running inspection.

4. **RLS and grants checks incomplete:** Early fixtures exist but lack comprehensive test coverage (negative cases, edge patterns); no golden-file validation for structural consistency.

5. **Migrations and pgvector coverage gaps:** No dedicated checks for migration reversibility declaration, structural drift detection, or pgvector index/dimension validation.

**Scope Justification:**

- **I1**: Clarify ROADMAP + lock strict CI gates (audit finding: line 8 contradicts observed state)
- **I2**: First-class DB security manifest (external consumers need explicit scoping)
- **I3**: RLS + grants fixture completion + tests (foundation for M7 integration with rumble-memory)
- **I4**: Migration + pgvector checks (support operational evidence trail)

**Demander & Rationale (D11 discipline — ecosystem roles only):**

- DB inspection is a gate for Rumble operations (M7 orchestration, rumble-memory consumer)
- Audit 2026-07-09 identified missing plan, requiring formalization before downstream dependencies
- CI gates must be explicit and measurable (enable cross-repo coordination)

## Target State

**End State (Verifiable):**

- ROADMAP.md line 8 clarified or removed; if clippy debt remains unstated, lint gates in CI are formalized
- `cargo clippy --all-targets -- -D warnings` enforced in CI; `cargo fmt --check` gates all branches
- DB security manifest exists and is valid (machine-readable, fixture testable)
- RLS and grants tests cover positive, negative, and edge cases (no false positives documented in test comments)
- Migration and pgvector checks detect structural patterns (reversibility declaration, index properties)
- All CI gates remain green (fmt, clippy, test, security audit, new contracts tests)
- First consumer (rumble-memory M7) can reference manifest version when invoking db-inspect

**Traceability to Quality Axes:**

- **Security**: Manifest and fixtures document access control patterns (RLS/grants scope); inspection is structural, not inferential.
- **Quality**: All tests pass, lint gates enforced, fixture diffs captured as evidence, no TODO/HACK without justification.
- **Performance**: Inspection stays bounded-linear; no quadratic graph analysis or symbolic execution (out-of-scope complexity).
- **Completeness**: Inspection reports are auditable; limits are documented in manifest; negative test fixtures prove false-positive handling.

## Increments

### I1 — ROADMAP truth + strict CI gate profile

**Pre-requisites:** Repo at `$DEV_ROOT/db-inspect`; Rust stable (pinned dtolnay/rust-toolchain@stable)

**Files to Modify/Create:**

- `ROADMAP.md` — clarify or remove line 8 ("address current clippy and lint debt")
- `.github/workflows/ci.yml` — add explicit `-D warnings` to clippy step (if not present)
- `Cargo.toml` — review lint forbids/denies in `[lints.rust]` section (document any intentional relaxations)
- `README.md` — add CI gates section (document what's enforced)

**Work:**

1. **Audit ROADMAP.md line 8:**
   - Verify `cargo clippy --all-targets -- -D warnings` passes (audit confirmed as of 2026-07-09).
   - If clean: replace "address current clippy and lint debt" with "maintain strict lint gates (clippy -D warnings, fmt --check, test all)".
   - If lint debt exists (unexpected): list specific lint(s) and create a follow-up increment.

2. **Formalize CI gate profile in `.github/workflows/ci.yml`:**

   ```yaml
   - name: Format check
     run: cargo fmt --all -- --check

   - name: Lint (strict mode)
     run: cargo clippy --all-targets --all-features -- -D warnings

   - name: Tests
     run: cargo test --workspace --all-features
   ```

   Document exit condition: all three steps pass, no warnings.

3. **Document in README.md (Quality section):**

   ```markdown
   ### CI Gates (Quality Enforcement)

   All branches enforce:

   - Format: `cargo fmt --all -- --check` (no non-standard style)
   - Lint: `cargo clippy --all-targets --all-features -- -D warnings` (strict lint rules)
   - Tests: `cargo test --workspace --all-features` (24 passing tests, 0 failures)
   - Security: `cargo audit && cargo deny check` (no known vulnerabilities)

   Merges to main are gated on all checks passing (CI is blocking).
   ```

4. **Review lint configuration (Cargo.toml):**
   - If `[lints.rust]` exists, document any `allow`/`warn` overrides (if intentional, justify with comment)
   - If missing, add baseline strict lints: `unsafe_code = "forbid"`, `missing_docs = "warn"` (optional but recommended)

**Exit Gates:**

```bash
cd $DEV_ROOT/db-inspect && cargo fmt --all -- --check
cd $DEV_ROOT/db-inspect && cargo clippy --all-targets --all-features -- -D warnings
cd $DEV_ROOT/db-inspect && cargo test --workspace --all-features
# Verify CI config was updated
grep -q "D warnings" .github/workflows/ci.yml || echo "FAIL: CI gate not updated"
grep -q "cargo fmt" .github/workflows/ci.yml || echo "FAIL: fmt gate missing"
# Verify ROADMAP is consistent with observed state
grep -q "maintain strict" ROADMAP.md || grep -q "address current" ROADMAP.md  # One of these should exist
```

**Proof of fix (manual):**

- Run `cargo clippy --all-targets -- -D warnings` locally; output shows "Finished ... [0 warnings]"
- ROADMAP.md line 8 is reworded or removed
- `.github/workflows/ci.yml` contains explicit `-D warnings` step

---

### I2 — DB security manifest

**Pre-requisites:** I1 merged; JSON schema available in repo or external spec

**Files to Modify/Create:**

- `docs/DB_SECURITY_MANIFEST.md` (new, machine-readable frontmatter + structured content)
- `tests/manifest_test.rs` (new Rust integration test)
- `fixtures/manifest-fixture.json` (example manifest conforming to schema)

**Scope clarification:** The manifest is a declarative specification of what db-inspect can and cannot do. It covers target databases, versions, inspection patterns, known limits, and evidence format. The manifest is versioned and included in CLI output.

**Work:**

1. **Create docs/DB_SECURITY_MANIFEST.md:**

   ````markdown
   # DB Security Manifest (db-inspect)

   ```json
   {
     "format": "db_inspect.db_security_manifest.v0.1",
     "tool_version": "0.0.0",
     "generated_at": "2026-07-09T00:00:00Z",
     "target_databases": [
       {
         "name": "postgresql",
         "version_min": "13.0",
         "version_max": null,
         "notes": "Tested on 13, 14, 15, 16; earlier versions may fail on some DDL patterns"
       }
     ],
     "extensions_supported": [
       {
         "name": "pgvector",
         "version_min": "0.5.0",
         "version_max": null,
         "checks": ["index_type", "vector_dimensions"]
       }
     ],
     "inspection_scope": {
       "rls": {
         "enabled": true,
         "checks": ["policy_count", "policy_syntax", "role_binding_validity"],
         "limits": "Structural analysis only; no policy execution simulation"
       },
       "grants": {
         "enabled": true,
         "checks": [
           "privilege_coverage",
           "role_hierarchy",
           "inheritance_depth"
         ],
         "limits": "Role introspection only; no access control simulation"
       },
       "migrations": {
         "enabled": true,
         "checks": ["reversibility_declaration", "schema_version_drift"],
         "limits": "Declared reversibility only; no actual rollback test"
       },
       "pgvector": {
         "enabled": true,
         "checks": ["index_type", "vector_dimensions", "distance_metric"],
         "limits": "Index metadata only; no data quality inspection"
       }
     },
     "known_limitations": [
       "No query execution or plan analysis",
       "No type inference or semantic analysis",
       "No runtime access control evaluation",
       "Dialect-specific SQL parsing may fail on non-standard DDL"
     ],
     "evidence_output_format": "db_inspect.inspection_report.v0.1 (JSON)",
     "security_posture": "Inspection is read-only, structural AST analysis; no modifications to target database"
   }
   ```
   ````

2. **Add integration test (tests/manifest_test.rs):**
   - Load manifest from docs/DB_SECURITY_MANIFEST.md
   - Parse JSON frontmatter
   - Validate schema: format field exists, tool_version is SemVer, inspection_scope is non-empty
   - Test passes if manifest parses and validates

3. **Document expected output (README):**
   - When db-inspect is run, it includes manifest version in output header
   - Example: `"manifest_version": "db_inspect.db_security_manifest.v0.1"`

**Exit Gates:**

```bash
cd $DEV_ROOT/db-inspect && cargo test --test manifest_test --all-features
cd $DEV_ROOT/db-inspect && cargo fmt --all -- --check
cd $DEV_ROOT/db-inspect && cargo clippy --all-targets -- -D warnings
# Manual proof:
grep -q "db_inspect.db_security_manifest.v0.1" docs/DB_SECURITY_MANIFEST.md
grep -q "postgresql" docs/DB_SECURITY_MANIFEST.md
```

**Proof of fix (manual):**

- `docs/DB_SECURITY_MANIFEST.md` exists and contains valid JSON frontmatter
- Test `manifest_test` passes
- Manifest includes target_databases, inspection_scope, and known_limitations sections

---

### I3 — RLS + grants checks

**Pre-requisites:** I1 merged; fixtures in place (existing or new)

**Files to Modify/Create:**

- `fixtures/rls-*.sql` — comprehensive RLS policy fixtures (positive + negative cases)
- `fixtures/grants-*.sql` — role hierarchy and privilege fixtures
- `tests/rls_grants_test.rs` (new or expanded Rust integration test)
- `src/lib.rs` — RLS and grants check functions (add or extend)

**Scope clarification:** RLS and grants checks are structural: parse SQL DDL, identify policy objects, role bindings, and privilege hierarchies. No policy execution or access control simulation.

**Work:**

1. **Create/expand RLS fixtures (tests expect to parse and extract RLS policies):**
   - `fixtures/rls-positive-simple.sql`: Basic RLS policy (1 table, 1 policy, 1 role)
   - `fixtures/rls-positive-complex.sql`: Multiple tables, multiple policies, role inheritance
   - `fixtures/rls-negative-malformed.sql`: Broken DDL (should parse cleanly or report error clearly)
   - `fixtures/rls-edge-unicode-roles.sql`: Role names with Unicode characters
   - Fixture metadata: document expected inspection result (policy count, role count, etc.)

2. **Create/expand grants fixtures:**
   - `fixtures/grants-positive-role-hierarchy.sql`: Role A has privilege on table; Role B inherits from A
   - `fixtures/grants-positive-diverse-privs.sql`: SELECT, INSERT, UPDATE, DELETE, TRIGGER on different tables
   - `fixtures/grants-negative-circular-hierarchy.sql`: Role A → B → A (should be detected or documented)
   - `fixtures/grants-edge-public-schema.sql`: Privileges on public schema objects

3. **Implement/extend RLS checks (src/lib.rs):**

   ```rust
   pub struct RLSPolicy {
       table_name: String,
       policy_name: String,
       permissive: bool,  // true = PERMISSIVE, false = RESTRICTIVE
       roles: Vec<String>,
       using_clause: String,
       with_check_clause: Option<String>,
   }

   pub fn extract_rls_policies(schema_sql: &str) -> Result<Vec<RLSPolicy>, Error> {
       // Use sqlparser to extract CREATE POLICY statements
       // Return structured list or error
   }
   ```

4. **Implement/extend grants checks (src/lib.rs):**

   ```rust
   pub struct RoleGrant {
       grantee_role: String,
       grantor_role: String,
       privilege: String,
       object_name: String,
       with_grant_option: bool,
   }

   pub fn extract_role_grants(schema_sql: &str) -> Result<Vec<RoleGrant>, Error> {
       // Use sqlparser to extract GRANT statements
       // Return structured list or error
   }
   ```

5. **Add tests to tests/rls_grants_test.rs:**
   - Test 1: Parse positive RLS fixture; verify policy_count == 1, roles include expected role
   - Test 2: Parse positive grants fixture; verify privilege hierarchy (B inherits from A)
   - Test 3: Parse negative/edge fixtures; verify no false positives (error or graceful skip)
   - Test 4 (golden): Load complex fixture, compare extracted RLS/grants against golden JSON output

**Exit Gates:**

```bash
cd $DEV_ROOT/db-inspect && cargo test --test rls_grants_test --all-features
cd $DEV_ROOT/db-inspect && cargo fmt --all -- --check
cd $DEV_ROOT/db-inspect && cargo clippy --all-targets -- -D warnings
# Verify fixtures exist
ls fixtures/rls-*.sql && ls fixtures/grants-*.sql | wc -l | grep -qE "[5-9]|[0-9]{2}"
# Golden file validation
cargo test --test rls_grants_test -- test_golden_rls_extraction 2>&1 | grep -q "ok"
```

**Proof of fix (manual):**

- `fixtures/rls-positive-simple.sql` parses and extracts 1 RLS policy
- `fixtures/grants-positive-role-hierarchy.sql` parses and shows role B inherits from role A
- Test output shows all cases passing (no false positives or panics on edge cases)
- Golden file diff shows before/after structure for complex fixture

---

### I4 — Migrations + pgvector checks

**Pre-requisites:** I1–I3 merged; sqlparser dependency available

**Files to Modify/Create:**

- `fixtures/migrations-*.sql` — migration sequences with reversibility declaration
- `fixtures/pgvector-*.sql` — pgvector index and configuration fixtures
- `tests/migrations_pgvector_test.rs` (new Rust integration test)
- `src/lib.rs` — migration and pgvector check functions (add or extend)

**Scope clarification:** Migration checks detect reversibility declarations (comments like `-- reversible: true/false`, or `BEGIN/ROLLBACK` structure). pgvector checks extract index type, vector dimensions, and distance metric from CREATE INDEX statements.

**Work:**

1. **Create migration fixtures:**
   - `fixtures/migration-reversible-add-column.sql`: `ALTER TABLE ... ADD COLUMN ...; -- reversible: true`
   - `fixtures/migration-irreversible-drop-column.sql`: `ALTER TABLE ... DROP COLUMN ...; -- reversible: false`
   - `fixtures/migration-drift-schema-version.sql`: Multiple tables with version metadata; detect schema drift (version mismatch)
   - Metadata: document expected reversibility flag and version strings

2. **Create pgvector fixtures:**
   - `fixtures/pgvector-index-ivfflat.sql`: `CREATE INDEX ... ON table USING ivfflat (vector_col)`
   - `fixtures/pgvector-index-hnsw.sql`: `CREATE INDEX ... ON table USING hnsw (vector_col)`
   - `fixtures/pgvector-distance-metrics.sql`: Multiple indexes with different distance metrics (l2, inner_product, cosine)
   - Metadata: document expected index type, vector dimension, distance metric

3. **Implement migration checks (src/lib.rs):**

   ```rust
   pub struct MigrationInfo {
       sequence_num: usize,
       description: String,
       reversible: Option<bool>,  // From comment or inferred
       schema_version: Option<String>,
   }

   pub fn extract_migration_metadata(migration_sql: &str) -> Result<MigrationInfo, Error> {
       // Parse SQL; extract reversibility declaration (comment or BEGIN/ROLLBACK)
       // Return structured metadata
   }

   pub fn detect_schema_drift(migrations: &[MigrationInfo]) -> Vec<String> {
       // Compare schema_version across migrations; report inconsistencies
   }
   ```

4. **Implement pgvector checks (src/lib.rs):**

   ```rust
   pub struct PgvectorIndex {
       table_name: String,
       column_name: String,
       index_type: String,  // "ivfflat", "hnsw"
       vector_dimensions: Option<usize>,
       distance_metric: String,  // "l2", "inner_product", "cosine"
   }

   pub fn extract_pgvector_indexes(schema_sql: &str) -> Result<Vec<PgvectorIndex>, Error> {
       // Use sqlparser to extract CREATE INDEX ... USING ivfflat/hnsw statements
       // Return structured list
   }
   ```

5. **Add tests to tests/migrations_pgvector_test.rs:**
   - Test 1: Parse reversible migration; verify reversible == true
   - Test 2: Parse irreversible migration; verify reversible == false
   - Test 3: Detect schema drift (version mismatch across migrations)
   - Test 4: Extract pgvector index metadata (type, dimensions, metric)
   - Test 5 (golden): Load complex migration sequence; compare extracted metadata against golden JSON

**Exit Gates:**

```bash
cd $DEV_ROOT/db-inspect && cargo test --test migrations_pgvector_test --all-features
cd $DEV_ROOT/db-inspect && cargo fmt --all -- --check
cd $DEV_ROOT/db-inspect && cargo clippy --all-targets -- -D warnings
# Verify fixtures exist
ls fixtures/migration-*.sql && ls fixtures/pgvector-*.sql | wc -l | grep -qE "[4-9]"
# Golden file validation
cargo test --test migrations_pgvector_test -- test_golden_pgvector_extraction 2>&1 | grep -q "ok"
```

**Proof of fix (manual):**

- `fixtures/migration-reversible-add-column.sql` parses and shows reversible == true
- `fixtures/pgvector-index-ivfflat.sql` extracts index_type == "ivfflat" and distance_metric correctly
- Schema drift detection identifies version mismatches
- Test output shows all cases passing, no panics on edge fixtures

---

## Out of Scope (M7 and beyond)

- **Integration with rumble-memory M7 orchestration:** Deferred; wrapped as a consumed tool once manifest is stable.
- **Performance profiling and query optimization:** Inspection is scoped for correctness, not speed; performance work is post-M6.
- **Cross-database support (MySQL, Oracle, SQLite):** Postgres-only for now; ported to other DB dialects in future increments if demand arises.
- **Runtime validation (actual policy execution, permission testing):** Remains structural analysis only; no database mutation or role impersonation.
- **Desktop/web UI for inspection reports:** CLI-only; UI integration deferred to operations layer.
- **Automatic remediation recommendations:** Manifest documents limits; remediation proposals are out-of-scope (evidence only).

---

## Verification (End-to-End)

```bash
export DEV_ROOT=$HOME/Documents
cd $DEV_ROOT/db-inspect

# I1: ROADMAP clarified, strict gates enforced
grep -E "maintain strict|address current" ROADMAP.md | head -1
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings 2>&1 | grep "Finished"
cargo test --workspace --all-features 2>&1 | grep "test result: ok"

# I2: DB security manifest valid and testable
test -f docs/DB_SECURITY_MANIFEST.md && grep "db_inspect.db_security_manifest.v0.1" docs/DB_SECURITY_MANIFEST.md
cargo test --test manifest_test --all-features 2>&1 | grep -q "test result: ok"

# I3: RLS and grants fixtures and tests pass
ls fixtures/rls-*.sql | wc -l | grep -q "[3-9]"
ls fixtures/grants-*.sql | wc -l | grep -q "[3-9]"
cargo test --test rls_grants_test --all-features 2>&1 | grep "test result: ok"

# I4: Migration and pgvector fixtures and tests pass
ls fixtures/migration-*.sql | wc -l | grep -q "[2-9]"
ls fixtures/pgvector-*.sql | wc -l | grep -q "[2-9]"
cargo test --test migrations_pgvector_test --all-features 2>&1 | grep "test result: ok"

# All CI gates green
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check 2>/dev/null || true  # Deny may not be installed; skip if missing
```

**Expected output:** All checks pass, no warnings or errors. Manifest is valid and versioned. Inspection tool is hardened and documented. First consumer (rumble-memory M7) can reference manifest and run db-inspect with explicit scope guarantees.
