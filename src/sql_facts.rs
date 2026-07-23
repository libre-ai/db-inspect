use crate::finding::Finding;
use regex::Regex;
use sqlparser::{
    ast::{
        AlterColumnOperation, AlterTableOperation, ColumnOption, Expr, GrantObjects, Privileges,
        Statement, TableConstraint,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};
use std::{borrow::Cow, collections::BTreeSet, sync::OnceLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignKeyFact {
    pub table: String,
    pub column: String,
    pub referenced_table: String,
    pub referenced_column: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFact {
    pub table: String,
    pub name: String,
    pub using_expr: Option<Expr>,
    pub with_check_expr: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomOperatorFact {
    pub statement_index: usize,
    pub name: String,
    pub implementation_function: String,
    pub left_argument: String,
    pub right_argument: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoBlockFact {
    pub statement_index: usize,
    pub contains_dynamic_sql: bool,
}

#[derive(Debug, Default)]
pub struct SchemaFacts {
    pub tables: BTreeSet<String>,
    pub rls_enabled: BTreeSet<String>,
    pub force_rls: BTreeSet<String>,
    pub grant_all: BTreeSet<(String, String)>,
    pub grant_roles: BTreeSet<String>,
    pub foreign_keys: Vec<ForeignKeyFact>,
    pub policies: Vec<PolicyFact>,
    pub policy_tables: BTreeSet<String>,
    pub policy_using: BTreeSet<String>,
    pub policy_with_check: BTreeSet<String>,
    pub custom_operators: Vec<CustomOperatorFact>,
    pub do_blocks: Vec<DoBlockFact>,
    pub dangerous: Vec<Finding>,
    /// One-based indexes of PostgreSQL-aware statements that could not be parsed.
    /// Raw SQL and parser messages are deliberately omitted from reports.
    pub parser_error_statements: Vec<usize>,
}

pub fn collect_schema_facts(schema: &str) -> SchemaFacts {
    let dialect = PostgreSqlDialect {};
    let mut facts = SchemaFacts::default();

    let parse_outcome = parse_sql_lenient(schema, &dialect);
    facts.parser_error_statements = parse_outcome.failed_statements;
    facts.custom_operators = parse_outcome.custom_operators;
    facts.do_blocks = parse_outcome.do_blocks;

    for stmt in parse_outcome.statements {
        match stmt {
            Statement::CreateTable(create) => {
                let table_name = create.name.to_string();
                facts.tables.insert(table_name.clone());
                for column in &create.columns {
                    for opt in &column.options {
                        if let ColumnOption::ForeignKey(fk) = &opt.option {
                            facts.foreign_keys.push(ForeignKeyFact {
                                table: table_name.clone(),
                                column: column.name.to_string(),
                                referenced_table: fk.foreign_table.to_string(),
                                referenced_column: fk
                                    .referred_columns
                                    .first()
                                    .map(ToString::to_string)
                                    .unwrap_or_else(|| "id".to_string()),
                            });
                        }
                    }
                }
                for constraint in &create.constraints {
                    if let TableConstraint::ForeignKey(fk) = constraint {
                        for (idx, column) in fk.columns.iter().enumerate() {
                            facts.foreign_keys.push(ForeignKeyFact {
                                table: table_name.clone(),
                                column: column.to_string(),
                                referenced_table: fk.foreign_table.to_string(),
                                referenced_column: fk
                                    .referred_columns
                                    .get(idx)
                                    .or_else(|| fk.referred_columns.first())
                                    .map(ToString::to_string)
                                    .unwrap_or_else(|| "id".to_string()),
                            });
                        }
                    }
                }
            }
            Statement::CreatePolicy(policy) => {
                let table = policy.table_name.to_string();
                facts.policy_tables.insert(table.clone());
                if policy.using.is_some() {
                    facts.policy_using.insert(table.clone());
                }
                if policy.with_check.is_some() {
                    facts.policy_with_check.insert(table.clone());
                }
                facts.policies.push(PolicyFact {
                    table,
                    name: policy.name.to_string(),
                    using_expr: policy.using.clone(),
                    with_check_expr: policy.with_check.clone(),
                });
            }
            Statement::AlterTable(alter) => {
                if alter
                    .operations
                    .iter()
                    .any(|op| matches!(op, AlterTableOperation::EnableRowLevelSecurity))
                {
                    facts.rls_enabled.insert(alter.name.to_string());
                }
                if alter
                    .operations
                    .iter()
                    .any(|op| matches!(op, AlterTableOperation::ForceRowLevelSecurity))
                {
                    facts.force_rls.insert(alter.name.to_string());
                }
                for op in &alter.operations {
                    match op {
                        AlterTableOperation::DisableRowLevelSecurity => {
                            facts.dangerous.push(Finding::new(
                                "DISABLE_RLS_FORBIDDEN",
                                "migration_safety",
                                "critical",
                                "table",
                                &alter.name.to_string(),
                            ))
                        }
                        AlterTableOperation::DropColumn { .. } => {
                            facts.dangerous.push(Finding::new(
                                "DROP_COLUMN_DANGEROUS",
                                "migration_safety",
                                "high",
                                "table",
                                &alter.name.to_string(),
                            ))
                        }
                        AlterTableOperation::DropConstraint { .. } => {
                            facts.dangerous.push(Finding::new(
                                "DROP_CONSTRAINT_DANGEROUS",
                                "migration_safety",
                                "high",
                                "table",
                                &alter.name.to_string(),
                            ))
                        }
                        AlterTableOperation::DropForeignKey { .. } => {
                            facts.dangerous.push(Finding::new(
                                "DROP_FOREIGN_KEY_DANGEROUS",
                                "migration_safety",
                                "high",
                                "table",
                                &alter.name.to_string(),
                            ))
                        }
                        AlterTableOperation::NoForceRowLevelSecurity => {
                            facts.dangerous.push(Finding::new(
                                "NO_FORCE_RLS_FORBIDDEN",
                                "migration_safety",
                                "critical",
                                "table",
                                &alter.name.to_string(),
                            ))
                        }
                        AlterTableOperation::AlterColumn {
                            column_name,
                            op: AlterColumnOperation::DropNotNull,
                        } => facts.dangerous.push(Finding::new(
                            "ALTER_COLUMN_DROP_NOT_NULL_DANGEROUS",
                            "migration_safety",
                            "high",
                            "column",
                            &format!("{}.{}", alter.name, column_name),
                        )),
                        _ => {}
                    }
                }
            }
            Statement::Grant(grant) => {
                for grantee in &grant.grantees {
                    facts.grant_roles.insert(grantee.to_string());
                }
                if matches!(grant.privileges, Privileges::All { .. }) {
                    if grant
                        .grantees
                        .iter()
                        .any(|g| g.to_string().eq_ignore_ascii_case("PUBLIC"))
                    {
                        facts.dangerous.push(Finding::new(
                            "GRANT_ALL_TO_PUBLIC_DANGEROUS",
                            "grant_privilege",
                            "critical",
                            "grant",
                            "PUBLIC",
                        ));
                    }
                    if let Some(objects) = grant.objects {
                        match objects {
                            GrantObjects::Tables(tables) => {
                                for table in tables {
                                    for grantee in &grant.grantees {
                                        facts
                                            .grant_all
                                            .insert((table.to_string(), grantee.to_string()));
                                    }
                                }
                            }
                            GrantObjects::Schemas(schemas) => {
                                for schema in schemas {
                                    facts.dangerous.push(Finding::new(
                                        "GRANT_ALL_ON_SCHEMA_DANGEROUS",
                                        "grant_privilege",
                                        "high",
                                        "schema",
                                        &schema.to_string(),
                                    ));
                                }
                            }
                            GrantObjects::AllTablesInSchema { schemas } => {
                                for schema in schemas {
                                    facts.dangerous.push(Finding::new(
                                        "GRANT_ALL_TABLES_IN_SCHEMA_DANGEROUS",
                                        "grant_privilege",
                                        "high",
                                        "schema",
                                        &schema.to_string(),
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Statement::DropPolicy(policy) => {
                facts.dangerous.push(Finding::new(
                    "DROP_POLICY_DANGEROUS",
                    "migration_safety",
                    "critical",
                    "table",
                    &policy.table_name.to_string(),
                ));
            }
            Statement::Drop { names, .. } => {
                for name in names {
                    facts.dangerous.push(Finding::new(
                        "DROP_TABLE_DANGEROUS",
                        "migration_safety",
                        "critical",
                        "table",
                        &name.to_string(),
                    ));
                }
            }
            Statement::Truncate(truncate) => {
                facts.dangerous.push(Finding::new(
                    "TRUNCATE_DANGEROUS",
                    "migration_safety",
                    "critical",
                    "table",
                    &truncate
                        .table_names
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "unknown".to_string()),
                ));
            }
            Statement::Delete(delete) if delete.selection.is_none() => {
                facts.dangerous.push(Finding::new(
                    "UNQUALIFIED_DELETE_DANGEROUS",
                    "migration_safety",
                    "critical",
                    "table",
                    &delete.from.to_string(),
                ));
            }
            Statement::Update(update) if update.selection.is_none() => {
                facts.dangerous.push(Finding::new(
                    "UNQUALIFIED_UPDATE_DANGEROUS",
                    "migration_safety",
                    "critical",
                    "table",
                    &update.table.to_string(),
                ));
            }
            _ => {}
        }
    }

    add_text_fallback_facts(schema, &mut facts);

    facts
}

fn add_text_fallback_facts(schema: &str, facts: &mut SchemaFacts) {
    let schema_lc = schema.to_lowercase();
    let policy_sql = sanitize_policy_sql(schema).to_lowercase();
    add_policy_fallback_facts(&policy_sql, facts);
    // Some PostgreSQL GRANT forms involving PUBLIC may be rejected by the parser depending on
    // exact grammar support. Keep this fallback narrow: any GRANT ALL to PUBLIC is unsafe enough
    // to block, and reports contain only the synthetic subject `PUBLIC`, not SQL text.
    if schema_lc.contains("grant all")
        && schema_lc.contains(" to public")
        && !facts
            .dangerous
            .iter()
            .any(|f| f.rule_id == "GRANT_ALL_TO_PUBLIC_DANGEROUS")
    {
        facts.dangerous.push(Finding::new(
            "GRANT_ALL_TO_PUBLIC_DANGEROUS",
            "grant_privilege",
            "critical",
            "grant",
            "PUBLIC",
        ));
    }

    if schema_lc.contains("set row_security = off") || schema_lc.contains("set row_security to off")
    {
        facts.dangerous.push(Finding::new(
            "SET_ROW_SECURITY_OFF_FORBIDDEN",
            "migration_safety",
            "critical",
            "session_setting",
            "row_security",
        ));
    }

    if schema_lc.contains("alter default privileges") && schema_lc.contains("grant all") {
        facts.dangerous.push(Finding::new(
            "DEFAULT_PRIVILEGES_GRANT_ALL_DANGEROUS",
            "grant_privilege",
            "high",
            "default_privileges",
            "future_objects",
        ));
    }
}

pub fn sanitize_policy_sql(schema: &str) -> String {
    let bytes = schema.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"--") {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(b' ');
                index += 1;
            }
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            let mut depth = 1_u32;
            output.extend_from_slice(b"  ");
            index += 2;
            while index < bytes.len() && depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth = depth.saturating_add(1);
                    output.extend_from_slice(b"  ");
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth = depth.saturating_sub(1);
                    output.extend_from_slice(b"  ");
                    index += 2;
                } else {
                    output.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
            continue;
        }
        if bytes[index] == b'\'' {
            let preserve = output
                .iter()
                .rev()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .take(32)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .ends_with(b"current_setting(");
            output.push(if preserve { b'\'' } else { b' ' });
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        output.extend_from_slice(if preserve { b"''" } else { b"  " });
                        index += 2;
                        continue;
                    }
                    output.push(if preserve { b'\'' } else { b' ' });
                    index += 1;
                    break;
                }
                output.push(if preserve || bytes[index] == b'\n' {
                    bytes[index]
                } else {
                    b' '
                });
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'$' {
            let mut end = index + 1;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            if bytes.get(end) == Some(&b'$') {
                let delimiter = &bytes[index..=end];
                let body_start = end + 1;
                if let Some(relative_end) = find_bytes(&bytes[body_start..], delimiter) {
                    let body_end = body_start + relative_end;
                    let previous_token = output
                        .split(|byte| byte.is_ascii_whitespace())
                        .rfind(|token| !token.is_empty())
                        .unwrap_or_default();
                    let preserve_do_body = previous_token.eq_ignore_ascii_case(b"do");
                    output.resize(output.len() + delimiter.len(), b' ');
                    if preserve_do_body {
                        let body = std::str::from_utf8(&bytes[body_start..body_end])
                            .expect("body is sliced from valid UTF-8 SQL");
                        output.extend_from_slice(sanitize_policy_sql(body).as_bytes());
                    } else {
                        for byte in &bytes[body_start..body_end] {
                            output.push(if *byte == b'\n' { b'\n' } else { b' ' });
                        }
                    }
                    output.resize(output.len() + delimiter.len(), b' ');
                    index = body_end + delimiter.len();
                    continue;
                }
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(output).expect("sanitizing UTF-8 SQL preserves valid bytes")
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn add_policy_fallback_facts(schema_lc: &str, facts: &mut SchemaFacts) {
    let policy = Regex::new(r#"(?is)create\s+policy\s+[^\s]+\s+on\s+([a-z0-9_."]+)"#)
        .expect("static policy regex");
    let matches = policy.captures_iter(schema_lc).collect::<Vec<_>>();
    for (index, captures) in matches.iter().enumerate() {
        let Some(table_match) = captures.get(1) else {
            continue;
        };
        let table = table_match.as_str().trim_matches('"').to_string();
        let body_start = captures.get(0).map_or(0, |matched| matched.end());
        let body_end = matches
            .get(index + 1)
            .and_then(|next| next.get(0))
            .map_or(schema_lc.len(), |matched| matched.start());
        let body = &schema_lc[body_start..body_end];
        facts.policy_tables.insert(table.clone());
        if body.contains("using") {
            facts.policy_using.insert(table.clone());
        }
        if body.contains("with check") {
            facts.policy_with_check.insert(table);
        }
    }
}

struct ParseOutcome {
    statements: Vec<Statement>,
    custom_operators: Vec<CustomOperatorFact>,
    do_blocks: Vec<DoBlockFact>,
    failed_statements: Vec<usize>,
}

fn parse_sql_lenient(schema: &str, dialect: &PostgreSqlDialect) -> ParseOutcome {
    // PostgreSQL extensions/functions can be ahead of parser support. Inspect each complete
    // statement independently so one unsupported construct does not hide all other facts.
    // Dedicated coverage classifiers run before the generic parser: a future parser upgrade
    // must not silently accept a DO body whose security-relevant semantics are still opaque.
    let mut statements = Vec::new();
    let mut custom_operators = Vec::new();
    let mut do_blocks = Vec::new();
    let mut failed_statements = Vec::new();
    for (index, sql) in split_postgres_statements(schema).into_iter().enumerate() {
        let statement_index = index + 1;
        if let Some(operator) = parse_custom_operator_declaration(&sql, statement_index) {
            custom_operators.push(operator);
        } else if let Some(do_block) = classify_do_block(&sql, statement_index) {
            do_blocks.push(do_block);
        } else {
            match parse_postgres_statement(&sql, dialect) {
                Ok(parsed) => statements.extend(parsed),
                Err(_) => failed_statements.push(statement_index),
            }
        }
    }

    ParseOutcome {
        statements,
        custom_operators,
        do_blocks,
        failed_statements,
    }
}

fn parse_postgres_statement(
    sql: &str,
    dialect: &PostgreSqlDialect,
) -> Result<Vec<Statement>, sqlparser::parser::ParserError> {
    match Parser::parse_sql(dialect, sql) {
        Ok(statements) => Ok(statements),
        Err(original_error) => {
            let normalized = normalize_extension_template_identifiers(sql);
            if matches!(normalized, Cow::Borrowed(_)) {
                Err(original_error)
            } else {
                Parser::parse_sql(dialect, normalized.as_ref())
            }
        }
    }
}

fn parse_custom_operator_declaration(
    sql: &str,
    statement_index: usize,
) -> Option<CustomOperatorFact> {
    static DECLARATION: OnceLock<Regex> = OnceLock::new();
    let regex = DECLARATION.get_or_init(|| {
        Regex::new(
            r#"(?is)^CREATE\s+OPERATOR\s+(?P<name>[^\s(]+)\s*\(\s*(?:FUNCTION|PROCEDURE)\s*=\s*(?P<function>(?:[A-Z_][A-Z0-9_$]*|\"(?:[^\"]|\"\")+\")(?:\.(?:[A-Z_][A-Z0-9_$]*|\"(?:[^\"]|\"\")+\"))?)\s*,\s*LEFTARG\s*=\s*(?P<left>[A-Z_][A-Z0-9_.$]*(?:\[\])?)\s*,\s*RIGHTARG\s*=\s*(?P<right>[A-Z_][A-Z0-9_.$]*(?:\[\])?)\s*\)\s*;\s*$"#,
        )
        .expect("custom operator declaration regex must compile")
    });
    let statement = strip_leading_sql_trivia(sql)?;
    let captures = regex.captures(statement)?;
    Some(CustomOperatorFact {
        statement_index,
        name: captures.name("name")?.as_str().to_string(),
        implementation_function: captures.name("function")?.as_str().to_string(),
        left_argument: captures.name("left")?.as_str().to_string(),
        right_argument: captures.name("right")?.as_str().to_string(),
    })
}

fn classify_do_block(sql: &str, statement_index: usize) -> Option<DoBlockFact> {
    let statement = strip_leading_sql_trivia(sql)?;
    let rest = strip_ascii_keyword(statement, "DO")?.trim_start();
    let tag = dollar_quote_tag(rest, 0)?;
    let body_and_suffix = &rest[tag.len()..];
    let closing_offset = body_and_suffix.find(&tag)?;
    let body = &body_and_suffix[..closing_offset];
    let suffix = body_and_suffix[closing_offset + tag.len()..].trim();
    if suffix != ";" {
        return None;
    }

    Some(DoBlockFact {
        statement_index,
        // Conservative by design: a false positive requires review, while a false negative could
        // hide dynamic DDL. Detailed PL/pgSQL parsing remains outside this bounded classifier.
        contains_dynamic_sql: body.to_ascii_lowercase().contains("execute"),
    })
}

fn strip_ascii_keyword<'a>(input: &'a str, keyword: &str) -> Option<&'a str> {
    let prefix = input.get(..keyword.len())?;
    if !prefix.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &input[keyword.len()..];
    if rest
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return None;
    }
    Some(rest)
}

fn strip_leading_sql_trivia(sql: &str) -> Option<&str> {
    let bytes = sql.as_bytes();
    let mut index = 0usize;
    loop {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if bytes.get(index) == Some(&b'-') && bytes.get(index + 1) == Some(&b'-') {
            index += 2;
            while bytes.get(index).is_some_and(|byte| *byte != b'\n') {
                index += 1;
            }
        } else if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            let mut depth = 1usize;
            while index < bytes.len() && depth > 0 {
                if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
                    depth += 1;
                    index += 2;
                } else if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            if depth != 0 {
                return None;
            }
        } else {
            return sql.get(index..).filter(|rest| !rest.is_empty());
        }
    }
}

/// Normalize pgrx/PostgreSQL extension template identifiers only in ordinary SQL lexical state.
/// Quoted strings, identifiers, comments and function bodies must remain byte-for-byte unchanged.
fn normalize_extension_template_identifiers(sql: &str) -> Cow<'_, str> {
    const PLACEHOLDER: &str = "@extschema@";
    const SENTINEL_IDENT: &str = "\"__dbinspect_extschema__\"";

    let bytes = sql.as_bytes();
    let mut state = SqlLexicalState::Normal;
    let mut output: Option<String> = None;
    let mut copied_until = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        match &mut state {
            SqlLexicalState::Normal => {
                if bytes[index..].starts_with(PLACEHOLDER.as_bytes())
                    && extension_template_token_is_bounded(bytes, index, PLACEHOLDER.len())
                {
                    let normalized = output.get_or_insert_with(|| String::with_capacity(sql.len()));
                    normalized.push_str(&sql[copied_until..index]);
                    normalized.push_str(SENTINEL_IDENT);
                    index += PLACEHOLDER.len();
                    copied_until = index;
                } else {
                    match bytes[index] {
                        b'\'' => {
                            state = SqlLexicalState::SingleQuoted;
                            index += 1;
                        }
                        b'"' => {
                            state = SqlLexicalState::DoubleQuoted;
                            index += 1;
                        }
                        b'-' if bytes.get(index + 1) == Some(&b'-') => {
                            state = SqlLexicalState::LineComment;
                            index += 2;
                        }
                        b'/' if bytes.get(index + 1) == Some(&b'*') => {
                            state = SqlLexicalState::BlockComment(1);
                            index += 2;
                        }
                        b'$' => {
                            if let Some(tag) = dollar_quote_tag(sql, index) {
                                index += tag.len();
                                state = SqlLexicalState::DollarQuoted(tag);
                            } else {
                                index += 1;
                            }
                        }
                        _ => index += 1,
                    }
                }
            }
            SqlLexicalState::SingleQuoted => {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    index += 2;
                } else if bytes[index] == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                    } else {
                        state = SqlLexicalState::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            SqlLexicalState::DoubleQuoted => {
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        index += 2;
                    } else {
                        state = SqlLexicalState::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            SqlLexicalState::DollarQuoted(tag) => {
                if sql[index..].starts_with(tag.as_str()) {
                    index += tag.len();
                    state = SqlLexicalState::Normal;
                } else {
                    index += sql[index..].chars().next().map(char::len_utf8).unwrap_or(1);
                }
            }
            SqlLexicalState::LineComment => {
                if bytes[index] == b'\n' {
                    state = SqlLexicalState::Normal;
                }
                index += 1;
            }
            SqlLexicalState::BlockComment(depth) => {
                if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    *depth += 1;
                    index += 2;
                } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    *depth -= 1;
                    index += 2;
                    if *depth == 0 {
                        state = SqlLexicalState::Normal;
                    }
                } else {
                    index += 1;
                }
            }
        }
    }

    match output {
        Some(mut normalized) => {
            normalized.push_str(&sql[copied_until..]);
            Cow::Owned(normalized)
        }
        None => Cow::Borrowed(sql),
    }
}

fn extension_template_token_is_bounded(bytes: &[u8], start: usize, len: usize) -> bool {
    let is_identifier_part =
        |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'@';
    let starts_at_boundary = start == 0 || !is_identifier_part(bytes[start - 1]);
    let end = start + len;
    let ends_at_boundary = end == bytes.len() || !is_identifier_part(bytes[end]);
    starts_at_boundary && ends_at_boundary
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SqlLexicalState {
    Normal,
    SingleQuoted,
    DoubleQuoted,
    DollarQuoted(String),
    LineComment,
    BlockComment(usize),
}

fn split_postgres_statements(schema: &str) -> Vec<String> {
    let bytes = schema.as_bytes();
    let mut statements = Vec::new();
    let mut state = SqlLexicalState::Normal;
    let mut start = 0usize;
    let mut index = 0usize;

    while index < bytes.len() {
        match &mut state {
            SqlLexicalState::Normal => match bytes[index] {
                b'\'' => {
                    state = SqlLexicalState::SingleQuoted;
                    index += 1;
                }
                b'"' => {
                    state = SqlLexicalState::DoubleQuoted;
                    index += 1;
                }
                b'-' if bytes.get(index + 1) == Some(&b'-') => {
                    state = SqlLexicalState::LineComment;
                    index += 2;
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    state = SqlLexicalState::BlockComment(1);
                    index += 2;
                }
                b'$' => {
                    if let Some(tag) = dollar_quote_tag(schema, index) {
                        index += tag.len();
                        state = SqlLexicalState::DollarQuoted(tag);
                    } else {
                        index += 1;
                    }
                }
                b';' => {
                    let statement = schema[start..=index].trim();
                    if !statement.is_empty() {
                        statements.push(statement.to_string());
                    }
                    start = index + 1;
                    index += 1;
                }
                _ => index += 1,
            },
            SqlLexicalState::SingleQuoted => {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    index += 2;
                } else if bytes[index] == b'\'' {
                    if bytes.get(index + 1) == Some(&b'\'') {
                        index += 2;
                    } else {
                        state = SqlLexicalState::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            SqlLexicalState::DoubleQuoted => {
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        index += 2;
                    } else {
                        state = SqlLexicalState::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            SqlLexicalState::DollarQuoted(tag) => {
                if schema[index..].starts_with(tag.as_str()) {
                    index += tag.len();
                    state = SqlLexicalState::Normal;
                } else {
                    index += schema[index..]
                        .chars()
                        .next()
                        .map(char::len_utf8)
                        .unwrap_or(1);
                }
            }
            SqlLexicalState::LineComment => {
                if bytes[index] == b'\n' {
                    state = SqlLexicalState::Normal;
                }
                index += 1;
            }
            SqlLexicalState::BlockComment(depth) => {
                if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    *depth += 1;
                    index += 2;
                } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    *depth -= 1;
                    index += 2;
                    if *depth == 0 {
                        state = SqlLexicalState::Normal;
                    }
                } else {
                    index += 1;
                }
            }
        }
    }

    let trailing = schema[start..].trim();
    if !trailing.is_empty() {
        statements.push(trailing.to_string());
    }
    statements
}

fn dollar_quote_tag(schema: &str, start: usize) -> Option<String> {
    let bytes = schema.as_bytes();
    if bytes.get(start) != Some(&b'$') {
        return None;
    }
    let mut end = start + 1;
    while let Some(byte) = bytes.get(end) {
        if *byte == b'$' {
            let body = &schema[start + 1..end];
            if body.is_empty()
                || (body
                    .bytes()
                    .next()
                    .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
                    && body
                        .bytes()
                        .all(|part| part.is_ascii_alphanumeric() || part == b'_'))
            {
                return Some(schema[start..=end].to_string());
            }
            return None;
        }
        if !byte.is_ascii_alphanumeric() && *byte != b'_' {
            return None;
        }
        end += 1;
    }
    None
}

#[cfg(test)]
mod parser_tests {
    use super::{
        normalize_extension_template_identifiers, parse_sql_lenient, split_postgres_statements,
    };
    use sqlparser::ast::Statement;
    use sqlparser::dialect::PostgreSqlDialect;

    #[test]
    fn splitter_keeps_dollar_quoted_function_body_together() {
        let sql = r#"
            CREATE FUNCTION demo() RETURNS void AS $body$
            BEGIN
                PERFORM 1;
                PERFORM 'semi;colon';
            END;
            $body$ LANGUAGE plpgsql;
            CREATE TABLE demo_table (id bigint);
        "#;

        let statements = split_postgres_statements(sql);
        assert_eq!(statements.len(), 2);
        assert!(statements[0].contains("PERFORM 1;"));
        assert!(statements[1].contains("CREATE TABLE demo_table"));
    }

    #[test]
    fn do_block_is_explicit_review_fact_without_hiding_following_table() {
        let sql = r#"
            DO $$
            BEGIN
                EXECUTE format('CREATE TABLE %I (id bigint)', 'dynamic_table');
            END;
            $$;
            CREATE TABLE visible_after_do (id bigint);
        "#;

        let outcome = parse_sql_lenient(sql, &PostgreSqlDialect {});
        assert!(outcome.failed_statements.is_empty());
        assert_eq!(outcome.do_blocks.len(), 1);
        assert_eq!(outcome.do_blocks[0].statement_index, 1);
        assert!(outcome.do_blocks[0].contains_dynamic_sql);
        assert!(outcome.statements.iter().any(|statement| {
            matches!(statement, Statement::CreateTable(create) if create.name.to_string() == "visible_after_do")
        }));
    }

    #[test]
    fn custom_operator_declaration_is_structured_without_generic_parser_error() {
        let sql = r#"
            /* outer /* nested */ comment */
            CREATE OPERATOR ?> (
                FUNCTION = df.if_then_op,
                LEFTARG = text,
                RIGHTARG = text
            );
        "#;

        let outcome = parse_sql_lenient(sql, &PostgreSqlDialect {});
        assert!(outcome.failed_statements.is_empty());
        assert_eq!(outcome.custom_operators.len(), 1);
        let operator = &outcome.custom_operators[0];
        assert_eq!(operator.statement_index, 1);
        assert_eq!(operator.name, "?>");
        assert_eq!(operator.implementation_function, "df.if_then_op");
        assert_eq!(operator.left_argument, "text");
        assert_eq!(operator.right_argument, "text");
    }

    #[test]
    fn unsupported_custom_operator_options_remain_fail_closed() {
        let sql = r#"
            CREATE OPERATOR ?> (
                FUNCTION = df.if_then_op,
                LEFTARG = text,
                RIGHTARG = text,
                COMMUTATOR = !>
            );
        "#;

        let outcome = parse_sql_lenient(sql, &PostgreSqlDialect {});
        assert_eq!(outcome.failed_statements, vec![1]);
        assert!(outcome.custom_operators.is_empty());
    }

    #[test]
    fn extension_schema_template_identifier_is_parsed_without_hiding_following_sql() {
        let sql = r#"
            SET LOCAL search_path TO @extschema@;
            CREATE TABLE visible_after_template (id bigint);
        "#;

        let outcome = parse_sql_lenient(sql, &PostgreSqlDialect {});
        assert!(outcome.failed_statements.is_empty());
        assert!(outcome.statements.iter().any(|statement| {
            matches!(statement, Statement::CreateTable(create) if create.name.to_string() == "visible_after_template")
        }));
    }

    #[test]
    fn extension_schema_lookalikes_in_lexical_regions_are_not_normalized() {
        let sql = r#"
            SELECT '@extschema@', "@extschema@", $$@extschema@$$;
            -- @extschema@
            /* outer @extschema@ /* nested @extschema@ */ */
            SELECT prefix@extschema@suffix;
        "#;

        let normalized = normalize_extension_template_identifiers(sql);
        assert!(matches!(normalized, std::borrow::Cow::Borrowed(_)));
        assert_eq!(normalized, sql);
    }

    #[test]
    fn extension_schema_normalization_handles_unicode_sql() {
        let sql = "SELECT café FROM résumé; SET search_path TO @extschema@;";

        let normalized = normalize_extension_template_identifiers(sql);

        assert!(normalized.contains("café"));
        assert!(normalized.contains("résumé"));
        assert!(normalized.contains("\"__dbinspect_extschema__\""));
    }

    #[test]
    fn unknown_extension_template_identifier_remains_fail_closed() {
        let sql = r#"
            SET LOCAL search_path TO @unknown_schema@;
            CREATE TABLE visible_after_unknown_template (id bigint);
        "#;

        let outcome = parse_sql_lenient(sql, &PostgreSqlDialect {});
        assert_eq!(outcome.failed_statements, vec![1]);
        assert!(outcome.statements.iter().any(|statement| {
            matches!(statement, Statement::CreateTable(create) if create.name.to_string() == "visible_after_unknown_template")
        }));
    }

    #[test]
    fn splitter_ignores_semicolons_in_quotes_and_nested_comments() {
        let sql = r#"
            /* outer ; /* nested ; */ done */
            INSERT INTO demo VALUES ('a;''b');
            -- line ; comment
            SELECT "semi;colon" FROM demo;
        "#;

        let statements = split_postgres_statements(sql);
        assert_eq!(statements.len(), 2);
        assert!(statements[0].contains("INSERT INTO demo"));
        assert!(statements[1].contains("SELECT \"semi;colon\""));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_policy_text_in_comments_and_plain_strings() {
        let facts = collect_schema_facts(
            r#"
            -- CREATE POLICY fake ON presto_jobs USING (tenant = current_setting('app.tenant')) WITH CHECK (true);
            SELECT 'CREATE POLICY fake ON presto_jobs USING (true) WITH CHECK (true)';
            SELECT $fake$CREATE POLICY fake ON presto_jobs USING (true) WITH CHECK (true)$fake$;
            "#,
        );
        assert!(!facts.policy_tables.contains("presto_jobs"));
    }

    #[test]
    fn extracts_policy_clauses_from_postgres_do_blocks() {
        let facts = collect_schema_facts(
            r#"
            DO $policy$
            BEGIN
                IF true THEN
                    CREATE POLICY tenant_scope ON presto_jobs
                    USING (organization_id = current_setting('presto.organization_id', true))
                    WITH CHECK (organization_id = current_setting('presto.organization_id', true));
                END IF;
            END
            $policy$;
            "#,
        );
        assert!(facts.policy_tables.contains("presto_jobs"));
        assert!(facts.policy_using.contains("presto_jobs"));
        assert!(facts.policy_with_check.contains("presto_jobs"));
    }
}
