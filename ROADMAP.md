# Roadmap

This is a contribution map, not a startup roadmap or a delivery promise. It shows where help is useful while keeping scope explicit.

## Now

- make dogfooding evidence visible through commands, fixtures, CI checks, generated reports, or linked docs;
- maintain strict format/clippy/test gates;
- qualify the fail-loud parser against real product and extension SQL corpora before global gate activation;
- improve RLS/grants/migration fixtures;
- document known inspection limits and unsupported PostgreSQL constructs;
- keep CI, release, and security checks green.

## Next

- synchronize central report schemas, expected fixtures and parser metrics in `constantin-jais`;
- add example inspection reports;
- improve fail-closed diagnostic messages;
- add contract tests around CI-gate semantics;
- prepare the first alpha-quality inspection CLI.

## Done in parser-integrity increment (2026-07-11)

- PostgreSQL-aware statement splitting for quotes, comments and dollar-quoted bodies;
- explicit parser coverage findings and real `parser_error_count`;
- injectable RFC3339 inspection clock and time-correct waiver expiry;
- token-aware `@extschema@` normalization with unknown templates kept fail-closed;
- structural `CREATE OPERATOR` coverage and focused blocking review for `DO` blocks;
- staged-rollout and compatibility decision recorded in ADR-0002.

## Later

- broader database and migration integrations;
- release provenance for inspection reports;
- hosted inspection only when redaction and tenant boundaries are explicit.
