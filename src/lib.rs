//! db-inspect — SQL and database security inspection for Postgres, pgvector, RLS, grants, and migrations.
//!
//! Naming note: `db-inspect` is the crate/repository name for the database
//! inspector formerly called `vault-inspector`. It is not a user-facing
//! vault, a secrets manager, or a vault product.
//!
//! This crate is intentionally a minimal skeleton. The first implementation
//! increments must keep the upstream boundary explicit and preserve the
//! sovereign constraints documented in `docs/adr/0001-scope-and-upstream-policy.md`.

/// Static project metadata used by the CLI and smoke tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectCard {
    pub name: &'static str,
    pub role: &'static str,
    pub upstream: &'static str,
    pub relationship: &'static str,
}

/// The repository's initial scope card.
pub const PROJECT: ProjectCard = ProjectCard {
    name: "db-inspect",
    role: "SQL and database inspection",
    upstream: "Scythe",
    relationship: "Tooling-layer DB security tool consuming SQL/schema artifacts; does not replace a general-purpose inspector or sqlx.",
};

/// Human-readable summary for CLI smoke runs.
pub fn summary() -> String {
    format!(
        "{} — {} (upstream: {})",
        PROJECT.name, PROJECT.role, PROJECT.upstream
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_card_names_the_repo_and_upstream() {
        assert_eq!(PROJECT.name, "db-inspect");
        assert_eq!(PROJECT.upstream, "Scythe");
        assert!(summary().contains(PROJECT.role));
    }
}
