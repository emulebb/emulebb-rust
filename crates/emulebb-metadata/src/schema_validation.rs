//! Lightweight structural validation of a database claiming the current version.
//!
//! SQLite descriptors cover columns, keys, indexes, foreign keys, and table
//! options without reading library rows or depending on DDL whitespace.

use std::{collections::BTreeMap, sync::LazyLock};

use anyhow::{Result, anyhow, ensure};
use rusqlite::{Connection, OptionalExtension, Params, types::Value};

type Shape = BTreeMap<String, Vec<Vec<Value>>>;

static EXPECTED: LazyLock<Result<Shape, String>> = LazyLock::new(|| {
    let build = || -> Result<Shape> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(crate::SCHEMA_SQL)?;
        describe(&conn)
    };
    build().map_err(|error| error.to_string())
});

pub(crate) fn validate(conn: &Connection) -> Result<()> {
    let expected = EXPECTED
        .as_ref()
        .map_err(|error| anyhow!("invalid built-in schema: {error}"))?;
    let actual = describe(conn)?;
    for key in expected.keys().chain(actual.keys()) {
        ensure!(
            expected.get(key) == actual.get(key),
            "metadata schema structure differs at {key}; create an entirely fresh profile for this build"
        );
    }
    let profile: Option<String> = conn
        .query_row("SELECT uuid FROM profile WHERE id = 1", [], |row| {
            row.get(0)
        })
        .optional()?;
    ensure!(
        profile.is_some_and(|id| uuid::Uuid::parse_str(&id).is_ok()),
        "metadata profile identity is missing or invalid"
    );
    Ok(())
}

fn describe(conn: &Connection) -> Result<Shape> {
    let mut shape = Shape::new();
    shape.insert(
        "objects".into(),
        rows(
            conn,
            "SELECT type, name, tbl_name FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' AND name NOT LIKE 'file_name_fts_%'
         ORDER BY type, name",
            [],
        )?,
    );
    shape.insert(
        "tables".into(),
        rows(
            conn,
            "SELECT name, type, ncol, wr, strict FROM pragma_table_list
         WHERE schema = 'main' AND type != 'shadow' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            [],
        )?,
    );
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_list WHERE schema = 'main' AND type != 'shadow' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let tables = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for table in tables {
        shape.insert(format!("{table}:columns"), rows(conn,
            "SELECT name, type, \"notnull\", dflt_value, pk, hidden FROM pragma_table_xinfo(?1) ORDER BY cid", [&table])?);
        shape.insert(format!("{table}:foreign_keys"), rows(conn,
            "SELECT \"table\", \"from\", \"to\", on_update, on_delete, seq FROM pragma_foreign_key_list(?1) ORDER BY \"table\", \"from\", seq", [&table])?);
        shape.insert(
            format!("{table}:indexes"),
            rows(
                conn,
                "SELECT name, \"unique\", origin, partial FROM pragma_index_list(?1) ORDER BY name",
                [&table],
            )?,
        );
        let mut indexes = conn.prepare("SELECT name FROM pragma_index_list(?1) ORDER BY name")?;
        let indexes = indexes
            .query_map([&table], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for index in indexes {
            shape.insert(
                format!("{table}:index:{index}"),
                rows(
                    conn,
                    "SELECT name, \"desc\", coll, key FROM pragma_index_xinfo(?1) ORDER BY seqno",
                    [&index],
                )?,
            );
        }
    }
    Ok(shape)
}

fn rows(conn: &Connection, sql: &str, params: impl Params) -> Result<Vec<Vec<Value>>> {
    let mut stmt = conn.prepare(sql)?;
    let count = stmt.column_count();
    let rows = stmt.query_map(params, |row| {
        (0..count)
            .map(|column| row.get(column))
            .collect::<rusqlite::Result<Vec<Value>>>()
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
