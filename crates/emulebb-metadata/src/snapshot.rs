//! Transaction-local snapshot reconciliation without rewriting unchanged rows.

use anyhow::{Result, ensure};
use rusqlite::Transaction;

pub(crate) struct SnapshotTable {
    table: &'static str,
    keys: &'static [&'static str],
    columns: Vec<String>,
}

impl SnapshotTable {
    /// Stage one complete collection. Identifiers come exclusively from store code.
    pub(crate) fn begin(
        tx: &Transaction<'_>,
        table: &'static str,
        keys: &'static [&'static str],
    ) -> Result<Self> {
        ensure!(
            table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "invalid snapshot table"
        );
        let mut stmt =
            tx.prepare("SELECT name, type, dflt_value FROM pragma_table_info(?1) ORDER BY cid")?;
        let definitions = stmt
            .query_map([table], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|(column, _, _)| column != "id" || keys.contains(&"id"))
            .collect::<Vec<_>>();
        let columns = definitions
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect::<Vec<_>>();
        ensure!(
            !columns.is_empty() && keys.iter().all(|key| columns.iter().any(|c| c == key)),
            "invalid snapshot keys"
        );
        let fields = definitions
            .iter()
            .map(|(name, kind, default)| {
                let default = default
                    .as_ref()
                    .map(|value| format!(" DEFAULT {value}"))
                    .unwrap_or_default();
                format!("{name} {kind}{default}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let key_fields = keys.join(", ");
        tx.execute_batch(&format!(
            "CREATE TEMP TABLE IF NOT EXISTS incoming_{table}({fields}) STRICT;
             CREATE UNIQUE INDEX IF NOT EXISTS temp.incoming_{table}_key ON incoming_{table}({key_fields});
             DELETE FROM temp.incoming_{table};"))?;
        Ok(Self {
            table,
            keys,
            columns,
        })
    }

    /// Merge changed values, preserve original first-seen/creation times, and
    /// delete rows absent from the supplied collection in this ownership scope.
    pub(crate) fn finish(self, tx: &Transaction<'_>, scope: Option<(&str, i64)>) -> Result<()> {
        let table = self.table;
        let fields = self.columns.join(", ");
        let mutable = self
            .columns
            .iter()
            .filter(|column| {
                !self.keys.contains(&column.as_str())
                    && !matches!(column.as_str(), "first_seen_at_ms" | "created_at_ms")
            })
            .collect::<Vec<_>>();
        let changed = mutable
            .iter()
            .filter(|column| column.as_str() != "updated_at_ms")
            .map(|column| format!("{table}.{column} IS NOT excluded.{column}"))
            .collect::<Vec<_>>();
        let conflict = if changed.is_empty() {
            "DO NOTHING".to_string()
        } else {
            let updates = mutable
                .iter()
                .map(|column| format!("{column} = excluded.{column}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("DO UPDATE SET {updates} WHERE {}", changed.join(" OR "))
        };
        tx.execute_batch(&format!("INSERT INTO main.{table}({fields}) SELECT {fields} FROM temp.incoming_{table} WHERE 1 ON CONFLICT {conflict};"))?;
        let matches = self
            .keys
            .iter()
            .map(|key| format!("incoming.{key} IS {table}.{key}"))
            .collect::<Vec<_>>()
            .join(" AND ");
        let ownership = if let Some((column, _)) = scope {
            ensure!(
                self.columns.iter().any(|c| c == column),
                "invalid snapshot scope"
            );
            format!("{column} = ?1 AND ")
        } else {
            String::new()
        };
        let sql = format!(
            "DELETE FROM main.{table} WHERE {ownership}NOT EXISTS (SELECT 1 FROM temp.incoming_{table} incoming WHERE {matches})"
        );
        if let Some((_, id)) = scope {
            tx.execute(&sql, [id])?;
        } else {
            tx.execute(&sql, [])?;
        }
        tx.execute_batch(&format!("DELETE FROM temp.incoming_{table};"))?;
        Ok(())
    }
}
