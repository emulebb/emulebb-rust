//! Bounded server-resource reads; protocol endpoints remain separate from IDs.
use anyhow::Result;
use rusqlite::{Row, params};

use crate::{MetadataServer, MetadataStore};

/// Retained rows and bounded text/port conversion workspace for one read.
pub const SERVER_READ_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MetadataServerRecord {
    pub id: i64,
    pub server: MetadataServer,
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataServerQuery {
    /// Immutable positive ID boundary, independent of the anchor's existence.
    pub after_id: Option<i64>,
    pub limit: usize,
    pub count_total: bool,
}
impl Default for MetadataServerQuery {
    fn default() -> Self {
        Self {
            after_id: None,
            limit: 100,
            count_total: false,
        }
    }
}

#[derive(Debug)]
pub struct MetadataServerPage {
    pub servers: Vec<MetadataServerRecord>,
    pub next_after_id: Option<i64>,
    pub has_more: bool,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataServerReadError {
    InvalidQuery,
    RowTooLarge,
}
impl std::fmt::Display for MetadataServerReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidQuery => "invalid server read query",
            Self::RowTooLarge => "server row exceeds read allowance",
        })
    }
}
impl std::error::Error for MetadataServerReadError {}

pub(super) const SERVER_COLUMNS: &str = "address,port,name,description,dynamic_host,auxiliary_ports,
    server_priority,static_server,enabled,failed_count,ping_ms,users,files,max_users,low_id_users,
    soft_files,hard_files,version,obfuscation_tcp_port,obfuscation_udp_port,udp_flags,udp_key,udp_key_ip";
const TEXT_BYTES: &str = "length(CAST(address AS BLOB))+length(CAST(name AS BLOB))+
    length(CAST(description AS BLOB))+length(CAST(dynamic_host AS BLOB))+
    length(CAST(auxiliary_ports AS BLOB))+length(CAST(server_priority AS BLOB))+length(CAST(version AS BLOB))";

fn page_sql() -> String {
    // WHY: tombstones can dominate the catalog. Seek the live partial index so
    // a sparse/empty page does not walk historical rows after the boundary.
    format!(
        "SELECT id,{TEXT_BYTES},{SERVER_COLUMNS} FROM servers INDEXED BY servers_live_id_idx
        WHERE deleted_at_ms IS NULL AND id>?1 ORDER BY id LIMIT ?2"
    )
}

fn row_bytes(row: &Row<'_>) -> Result<usize> {
    let text = usize::try_from(row.get::<_, i64>(1)?)?;
    // WHY: check before cloning text or decoding CSV ports. Fourfold headroom
    // covers CSV backing, port deduplication/Vec workspace and owned strings.
    Ok(text
        .saturating_mul(4)
        .saturating_add(std::mem::size_of::<MetadataServerRecord>()))
}

impl MetadataStore {
    /// Ascending immutable-ID traversal. Disabled servers remain visible;
    /// deleted boundaries need no lookup and never invalidate continuation.
    pub fn server_page(&self, query: MetadataServerQuery) -> Result<MetadataServerPage> {
        anyhow::ensure!(
            (1..=200).contains(&query.limit) && query.after_id.is_none_or(|id| id > 0),
            MetadataServerReadError::InvalidQuery
        );
        let conn = self.connection()?;
        let mut statement = conn.prepare_cached(&page_sql())?;
        let mut rows = statement.query(params![
            query.after_id.unwrap_or(0),
            i64::try_from(query.limit + 1)?
        ])?;
        let mut servers = Vec::with_capacity(query.limit);
        let mut bytes =
            16 * 1024 + servers.capacity() * std::mem::size_of::<MetadataServerRecord>();
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            if servers.len() == query.limit {
                has_more = true;
                break;
            }
            let needed = row_bytes(row)?;
            if bytes.saturating_add(needed) > SERVER_READ_MAX_BYTES {
                anyhow::ensure!(!servers.is_empty(), MetadataServerReadError::RowTooLarge);
                has_more = true;
                break;
            }
            bytes += needed;
            servers.push(MetadataServerRecord {
                id: row.get(0)?,
                server: server_from_row(row, 2)?,
            });
        }
        drop(rows);
        drop(statement);
        let total = if query.count_total {
            Some(u64::try_from(conn.query_row(
                "SELECT count(*) FROM servers WHERE deleted_at_ms IS NULL",
                [],
                |r| r.get::<_, i64>(0),
            )?)?)
        } else {
            None
        };
        let next_after_id = if has_more {
            servers.last().map(|r| r.id)
        } else {
            None
        };
        Ok(MetadataServerPage {
            servers,
            next_after_id,
            has_more,
            total,
        })
    }

    /// Read one resource without enumerating the catalog or probing a network.
    pub fn server_by_id(&self, id: i64) -> Result<Option<MetadataServerRecord>> {
        anyhow::ensure!(id > 0, MetadataServerReadError::InvalidQuery);
        let conn = self.connection()?;
        let sql = format!(
            "SELECT id,{TEXT_BYTES},{SERVER_COLUMNS} FROM servers
            WHERE id=?1 AND deleted_at_ms IS NULL"
        );
        let mut statement = conn.prepare_cached(&sql)?;
        let mut rows = statement.query([id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        anyhow::ensure!(
            row_bytes(row)?.saturating_add(16 * 1024) <= SERVER_READ_MAX_BYTES,
            MetadataServerReadError::RowTooLarge
        );
        Ok(Some(MetadataServerRecord {
            id: row.get(0)?,
            server: server_from_row(row, 2)?,
        }))
    }
}

pub(super) fn server_from_row(row: &Row<'_>, offset: usize) -> rusqlite::Result<MetadataServer> {
    Ok(MetadataServer {
        address: row.get(offset)?,
        port: row.get(offset + 1)?,
        name: row.get(offset + 2)?,
        description: row.get(offset + 3)?,
        dynamic_host: row.get(offset + 4)?,
        auxiliary_ports: crate::profile_store::decode_auxiliary_ports(
            &row.get::<_, String>(offset + 5)?,
        ),
        server_priority: row.get(offset + 6)?,
        static_server: row.get::<_, i64>(offset + 7)? != 0,
        enabled: row.get::<_, i64>(offset + 8)? != 0,
        failed_count: row.get(offset + 9)?,
        ping_ms: row.get(offset + 10)?,
        users: crate::sql_value::optional_unsigned::<u64>(row, offset + 11)?.unwrap_or_default(),
        files: crate::sql_value::optional_unsigned::<u64>(row, offset + 12)?.unwrap_or_default(),
        max_users: crate::sql_value::optional_unsigned::<u64>(row, offset + 13)?
            .unwrap_or_default(),
        low_id_users: crate::sql_value::optional_unsigned::<u64>(row, offset + 14)?
            .unwrap_or_default(),
        soft_files: crate::sql_value::optional_unsigned::<u64>(row, offset + 15)?
            .unwrap_or_default(),
        hard_files: crate::sql_value::optional_unsigned::<u64>(row, offset + 16)?
            .unwrap_or_default(),
        version: row.get(offset + 17)?,
        obfuscation_tcp_port: row.get(offset + 18)?,
        obfuscation_udp_port: row.get(offset + 19)?,
        udp_flags: row.get(offset + 20)?,
        udp_key: row.get(offset + 21)?,
        udp_key_ip: row.get(offset + 22)?,
    })
}

#[cfg(test)]
mod tests;
