# Db Inspect Canonical Agent Rules

## Authority

Fail-closed PostgreSQL schema inspection gate for the Libre AI constellation
— a standalone CI tool on the transverse layer, consumed pinned by release so
schema inspections stay replayable without any third-party service or
unverified copy.
Doctrine lives upstream: https://raw.githubusercontent.com/libre-ai/governance/main/docs/README.md

## Boundaries

- Project state is owned by `project.v1.yaml`; the README status section is
  generated from it — never edit that section by hand.
- No second durable implementation of this domain elsewhere in the
  constellation; generic structural inspection lives outside this repository.
- Not a vault, a secrets manager, an ORM, or a product UX.

## Quality gates

Run `cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D warnings`
and `cargo test --locked --all-features` before pushing; `cargo-deny check
bans licenses sources` enforces the committed dependency policy. Never hide a
red test.

## Agents

- Check real state (`git status`, the test suite) before editing.
- Consumers pin releases by sha256: fail-closed verdicts and release
  reproducibility are load-bearing — never weaken them for convenience.
- English for code, commits and this file.
- Never commit a machine-local absolute filesystem path; use repo-relative
  paths or `~` instead.
- Security > quality > performance > completeness.
