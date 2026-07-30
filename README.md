# db-inspect

**Outil** : `db-inspect`
**Rôle** : inspection SQL/Postgres/RLS/grants/migrations/pgvector
**deployment_class** : factory-only
**Maturité** : dojo — CLI migré avec fixtures ; première adoption statique sur les jobs Sessions, preuve PostgreSQL live encore requise
**Place dans la chaîne DoD** : transforme schémas et migrations SQL en évidence DB consommable par CI, revues et Agent Factory.
**Doctrine** : evidence-only, jamais vérité durable ; spécialisé DB sans devenir vault ni ORM.
**Souveraineté** : licences MIT/Apache/MPL compatibles ; pas d’AGPL/SSPL dans la chaîne versionnée.

## Ce que ça fait

Audite les surfaces Postgres sensibles : RLS, grants, migrations, pgvector et redaction de rapports. L’outil est une preuve spécialisée ; le prochain palier est l’adoption comme gate sur un produit SQL-backed.

## Où ça se branche

- Amont : migrations et schémas des produits Libre IA utilisant Postgres.
- Aval : CI, [Agent Factory Engine](https://github.com/libre-ai/agent-factory/tree/main/engine), [Artifact Supply Depot](https://github.com/libre-ai/artifact-supply/tree/main/depot) si les rapports deviennent artefacts.
- Contrats/preuves : fixtures SQL, rapports JSON, release SBOM/provenance.

[![Release](https://github.com/libre-ai/db-inspect/actions/workflows/release.yml/badge.svg)](https://github.com/libre-ai/db-inspect/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Dogfooding

This repository is part of the **Libre IA** tool family — one tool, one job, stacked.

Current visible evidence:

- CI, release, and security workflows exercise the inspection CLI surface;
- README maturity notes keep CI-gate readiness and integration limits explicit;
- fixtures and contracts frame RLS, grants, migration, and pgvector inspection behavior.

Current Phase 2 evidence:

- tenant tables with RLS but no policy are blocked;
- policies require both `USING` and `WITH CHECK`;
- direct and composite tenant columns must reference their declared `current_setting` names;
- strict no-argument SQL resolvers may wrap a declared setting, but `SECURITY DEFINER`, multi-statement, non-SQL, and non-derived resolvers fail closed;
- the Sessions jobs migration passes the protected-branch profile with zero findings.

Expected next evidence:

- run the same contract against a non-superuser target PostgreSQL role;
- publish a deterministic report without local absolute paths.

Dogfooding claims should stay backed by visible commands, fixtures, CI workflows, generated reports, or linked docs.

## Contributing

See:

- [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines;
- [ROADMAP.md](ROADMAP.md) for current contribution priorities;
- [issue templates](.github/ISSUE_TEMPLATE/) for bugs, docs issues, fixture/example requests, and design discussions.

## Tool role

`db-inspect` is a standalone inspection capability. It gives products and Agent Factory workflows concrete database-security evidence instead of letting product code silently own RLS, grants, migration, or pgvector audit logic.

## Boundary

It must not become a vault, a secrets manager, a product UX, or the generic inspection brain. Orchestration stays in Agent Factory; context and durable memory stay in Context Kit; artifact storage stays in Artifact Supply; product workflows stay in their owning products.

## Purpose

`db-inspect` is the specialized database inspector of the ecosystem. It audits Postgres-oriented systems and produces actionable evidence for CI, reviews, and compliance.

It exists because database security is deep enough to deserve its own tool instead of being hidden inside a generic inspector. It is separate from the ecosystem's general-purpose inspector by scope, not by layer: general structural inspection stays there, while `db-inspect` owns deep database-security rules.

## Owns

- SQL, migration, RLS, grants, and schema inspection.
- Postgres/pgvector-oriented security checks.
- CI-friendly reports and audit evidence.
- Database-specific policy validation.

## Does Not Own

- Generic structural inspection outside database/security scope: belongs to the general-purpose inspector.
- Product UX: belongs to the owning products; this repo is not a vault or secrets manager.
- Long-term context and memory substrate: belongs to Context Kit.
- Artifact retention and distribution: belongs to Artifact Supply.
- Orchestration or remediation decisions: belong to Agent Factory.

## Allowed Dependencies

- Can be called by Agent Factory Engine as a gate; `bolt-cos-matic` remains a compatibility identifier.
- Can emit reports into Artifact Supply or ordinary CI artifacts.
- Can complement the general-purpose inspector without replacing it.

## Inspection integrity

The protected-branch and release profiles fail closed when any PostgreSQL-aware statement cannot be parsed or requires explicit procedural review. Reports expose the real `parser_error_count`; recognized `DO` blocks produce separate blocking review findings instead of disappearing behind a false zero. Raw failing SQL, procedural bodies and parser messages are omitted from findings to avoid leaking schema comments or secrets.

The splitter understands quotes, comments and dollar-quoted PL/pgSQL bodies. Extension-template `@extschema@` identifiers are normalized only in ordinary SQL lexical state; quoted/commented lookalikes and unknown tokens remain untouched and fail closed when unsupported. Rollout remains staged: no global CI/Agent Factory gate should be activated until the target product corpus has zero unexplained parser errors. Rationale, corpus measurements and compatibility are recorded in [`ADR-0002`](docs/adr/0002-fail-loud-sql-coverage-and-inspection-clock.md).

Waiver expiry is evaluated against the report's RFC3339 inspection clock. Production runs use the current UTC time; deterministic CI or fixture runs can inject it explicitly:

```bash
db-inspect run \
  --manifest db-security-manifest.json \
  --schema-dump schema.sql \
  --inspection-at 2026-07-11T00:00:00Z \
  --profile protected_branch
```

An invalid inspection clock is itself a blocking `INSPECTION_CLOCK_INVALID` finding.

## Product Vision Challenge

`db-inspect` must not be confused with a vault application. Its product is database trust evidence, not user-facing secure storage.

The former `vault-inspector` name is retired; avoid reintroducing vault/secrets terminology for this tool.

## État du projet

<!-- libre-ai:project-status:begin -->
<!-- Section générée depuis project.v1.yaml — ne pas éditer à la main. -->

- Situation actuelle : Outil autonome antérieur à l'activation générale, actif et versionné par releases.
- Maturité : usable
- Exposition : usable-verifiable
- Confiance : medium
- Preuves vérifiées le : 2026-07-30
- Avancement : 50 % du périmètre actuellement déclaré

<!-- libre-ai:project-status:end -->

La fiche [`project.v1.yaml`](./project.v1.yaml) est l'autorité de l'état du projet ; cette section en est générée et le gate de flotte échoue si elles divergent.
