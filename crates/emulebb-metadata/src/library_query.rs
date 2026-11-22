//! Bounded hash-level library pages over indexed, process-local read projections.

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Row, params_from_iter, types::Value};

use crate::{MetadataFileUploadStatistics, MetadataFileUploadTotals, MetadataStore};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LibraryFileView {
    #[default]
    Present,
    Shared,
    Unavailable,
    AllKnown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LibraryFileSort {
    #[default]
    DisplayName,
    SizeBytes,
    SessionUploadedBytes,
    SessionUploadRequests,
    SessionAcceptedUploads,
    LifetimeUploadedBytes,
    LifetimeUploadRequests,
    LifetimeAcceptedUploads,
    LastRequestedAt,
    LastUploadedAt,
}

impl LibraryFileSort {
    fn index(self) -> &'static str {
        match self {
            Self::DisplayName => "library_file_present_name_idx",
            Self::SizeBytes => "library_file_present_size_idx",
            Self::SessionUploadedBytes => "session_upload_bytes_idx",
            Self::SessionUploadRequests => "session_upload_requests_idx",
            Self::SessionAcceptedUploads => "session_upload_accepts_idx",
            Self::LifetimeUploadedBytes => "lifetime_upload_bytes_idx",
            Self::LifetimeUploadRequests => "lifetime_upload_requests_idx",
            Self::LifetimeAcceptedUploads => "lifetime_upload_accepts_idx",
            Self::LastRequestedAt => "last_upload_requested_idx",
            Self::LastUploadedAt => "last_uploaded_idx",
        }
    }

    fn is_summary(self) -> bool {
        matches!(self, Self::DisplayName | Self::SizeBytes)
    }

    fn key(self, alias: &str) -> String {
        // WHY: SQLite expression-index row tuples can order correctly yet walk
        // the entire presence cohort at a late cursor. Generated non-null key
        // columns permit actual indexed tuple seeks and distinguish null from 0.
        let column = match self {
            Self::DisplayName => "name_key",
            Self::SizeBytes => "size_key",
            Self::SessionUploadedBytes => "uploaded_bytes",
            Self::SessionUploadRequests => "upload_requests",
            Self::SessionAcceptedUploads => "accepted_sessions",
            Self::LifetimeUploadedBytes => "lifetime_bytes",
            Self::LifetimeUploadRequests => "lifetime_requests",
            Self::LifetimeAcceptedUploads => "lifetime_accepts",
            Self::LastRequestedAt => "last_requested_key",
            Self::LastUploadedAt => "last_uploaded_key",
        };
        format!("{alias}.{column}")
    }
}

#[derive(Debug, Clone)]
pub struct LibraryFileQuery {
    pub view: LibraryFileView,
    pub sort: LibraryFileSort,
    pub descending: bool,
    pub search: Option<String>,
    /// Immutable root resource identity; paths are not filter identities.
    pub root_id: Option<i64>,
    /// Public immutable tag name. SQLite resolves its internal key once.
    pub tag: Option<String>,
    pub sharing_enabled: Option<bool>,
    /// Anchor hash remains addressable independently of the selected filters.
    pub after: Option<[u8; 16]>,
    pub limit: usize,
    pub count_total: bool,
}

impl Default for LibraryFileQuery {
    fn default() -> Self {
        Self {
            view: LibraryFileView::Present,
            sort: LibraryFileSort::DisplayName,
            descending: false,
            search: None,
            root_id: None,
            tag: None,
            sharing_enabled: None,
            after: None,
            limit: 100,
            count_total: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLibraryFile {
    pub file_hash: String,
    pub display_name: String,
    /// Accepted content size only. A download's provisional claim is not identity.
    pub size_bytes: Option<u64>,
    pub present: bool,
    pub sharing_enabled: bool,
    pub statistics: MetadataFileUploadStatistics,
}

/// Point-read metadata is separate from thin collection rows.
#[derive(Debug, PartialEq, Eq)]
pub struct MetadataLibraryFileDetail {
    pub file: MetadataLibraryFile,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub comment: String,
    pub rating: u8,
    pub aich_root: Option<[u8; 20]>,
}

#[derive(Debug)]
pub struct MetadataLibraryFilePage {
    pub files: Vec<MetadataLibraryFile>,
    pub next_after: Option<[u8; 16]>,
    pub total: Option<u64>,
}

#[derive(Debug)]
pub struct MetadataLibraryCursorExpired;

impl std::fmt::Display for MetadataLibraryCursorExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("library cursor anchor is unavailable")
    }
}
impl std::error::Error for MetadataLibraryCursorExpired {}

/// SQL identifiers are selected exclusively from the closed sort/view enums.
/// Bound request values never become SQL text.
fn source_and_filters(query: &LibraryFileQuery, search: Option<&str>) -> (String, Vec<Value>) {
    let index = query.sort.index();
    let mut source = if query.sort.is_summary() {
        format!(
            "FROM temp.session_library_files f INDEXED BY {index}
            CROSS JOIN temp.session_file_upload_statistics s ON s.known_file_id=f.known_file_id"
        )
    } else {
        format!(
            "FROM temp.session_file_upload_statistics s INDEXED BY {index}
            CROSS JOIN temp.session_library_files f ON f.known_file_id=s.known_file_id"
        )
    };
    source.push_str(" CROSS JOIN known_files k ON k.id=f.known_file_id WHERE 1=1");
    match query.view {
        LibraryFileView::Present => source.push_str(" AND f.present=1"),
        LibraryFileView::Shared => source.push_str(" AND f.present=1 AND f.sharing_enabled=1"),
        LibraryFileView::Unavailable => source.push_str(" AND f.present=0"),
        LibraryFileView::AllKnown => {}
    }
    let mut values = Vec::new();
    for (value, predicate) in [
        (
            search.map(|value| Value::Text(value.into())),
            "instr(f.name_key,?)>0",
        ),
        (
            query
                .sharing_enabled
                .map(|value| Value::Integer(i64::from(value))),
            "f.sharing_enabled=?",
        ),
        (
            query.root_id.map(Value::Integer),
            "EXISTS(SELECT 1 FROM shared_file_memberships m
            CROSS JOIN shared_directory_roots r ON r.id=m.root_id
            WHERE m.root_id=? AND m.known_file_id=f.known_file_id AND m.removed_at_s IS NULL
                AND r.enabled=1 AND r.deleted_at_s IS NULL)",
        ),
        (
            query.tag.as_ref().map(|name|Value::Text(name.clone())),
            "EXISTS(SELECT 1 FROM known_file_tags t WHERE t.tag_id=(SELECT id FROM library_tags WHERE name=?)
                AND t.known_file_id=f.known_file_id)",
        ),
    ] {
        if let Some(value) = value {
            values.push(value);
            source.push_str(" AND ");
            source.push_str(&predicate.replace('?', &format!("?{}", values.len())));
        }
    }
    (source, values)
}

const COLUMNS: &str = "length(CAST(k.display_name AS BLOB)),
    CASE WHEN length(CAST(k.display_name AS BLOB))<=65536 THEN k.display_name END,
    f.size_bytes,f.present,f.sharing_enabled,
    s.uploaded_bytes,s.upload_requests,s.accepted_sessions,
    s.lifetime_bytes,s.lifetime_requests,s.lifetime_accepts,
    s.last_requested_at_s,s.last_uploaded_at_s";

fn decode(row: &Row<'_>) -> rusqlite::Result<MetadataLibraryFile> {
    Ok(MetadataLibraryFile {
        file_hash: hex::encode(row.get_ref(0)?.as_blob()?),
        display_name: row.get(2)?,
        size_bytes: crate::sql_value::optional_unsigned(row, 3)?,
        present: row.get(4)?,
        sharing_enabled: row.get(5)?,
        statistics: MetadataFileUploadStatistics {
            session_uploaded_bytes: crate::sql_value::unsigned(row, 6)?,
            session_upload_requests: crate::sql_value::unsigned(row, 7)?,
            session_accepted_uploads: crate::sql_value::unsigned(row, 8)?,
            lifetime: MetadataFileUploadTotals {
                uploaded_bytes: crate::sql_value::unsigned(row, 9)?,
                upload_requests: crate::sql_value::unsigned(row, 10)?,
                accepted_sessions: crate::sql_value::unsigned(row, 11)?,
                last_requested_at_s: row.get(12)?,
                last_uploaded_at_s: row.get(13)?,
            },
        },
    })
}

fn page_sql(query: &LibraryFileQuery, source: &str, values: &mut Vec<Value>) -> String {
    let alias = if query.sort.is_summary() { "f" } else { "s" };
    let key = query.sort.key(alias);
    let direction = if query.descending { "DESC" } else { "ASC" };
    let comparison = if query.descending { "<" } else { ">" };
    let mut source = source.to_owned();
    if let Some(hash) = query.after {
        let table = if query.sort.is_summary() {
            "session_library_files"
        } else {
            "session_file_upload_statistics"
        };
        let anchor = query.sort.key("a");
        values.push(Value::Blob(hash.into()));
        // The scalar subquery is a single hash-index lookup, independent of
        // filter membership. SQLite keeps even long name anchors out of Rust.
        source.push_str(&format!(
            " AND ({key},{alias}.ed2k_hash){comparison}
            (SELECT {anchor},a.ed2k_hash FROM temp.{table} a WHERE a.ed2k_hash=?{})",
            values.len()
        ));
    }
    values.push(Value::Integer((query.limit + 1) as i64));
    let branch = |present| {
        format!("SELECT {alias}.ed2k_hash,{COLUMNS},{key} {source} AND {alias}.present={present}")
    };
    let select = match query.view {
        // WHY: merge two indexed presence cohorts instead of scanning retained
        // unavailable jobs for a Present view or duplicating every sort index.
        LibraryFileView::AllKnown => format!("{} UNION ALL {}", branch(0), branch(1)),
        LibraryFileView::Unavailable => branch(0),
        LibraryFileView::Present | LibraryFileView::Shared => branch(1),
    };
    format!(
        "{select} ORDER BY 15 {direction},1 {direction} LIMIT ?{}",
        values.len()
    )
}

impl MetadataStore {
    /// Read one client hash, including unavailable/copyless content. This uses
    /// the same cached facts as pages and never warms unrelated filename keys.
    pub fn library_file(&self, hash: &[u8; 16]) -> Result<Option<MetadataLibraryFile>> {
        self.library_file_read(hash, "", decode)
    }

    /// One transaction supplies the same summary facts and explicit local
    /// metadata, without reading any job, copy list, hashset or filesystem.
    pub fn library_file_detail(
        &self,
        hash: &[u8; 16],
    ) -> Result<Option<MetadataLibraryFileDetail>> {
        self.library_file_read(
            hash,
            ",length(CAST(k.comment AS BLOB)),
            CASE WHEN length(CAST(k.comment AS BLOB))<=65536 THEN k.comment END,
            length(CAST(k.upload_priority AS BLOB)),
            CASE WHEN length(CAST(k.upload_priority AS BLOB))<=64 THEN k.upload_priority END,
            k.auto_upload_priority,k.rating,k.aich_root",
            |row| {
                crate::download_job_store::bounded_row_bytes(row, &[(14, 65_536, 8), (16, 64, 8)])?;
                let aich_root = match row.get_ref(20)? {
                    rusqlite::types::ValueRef::Null => None,
                    value => Some(
                        value
                            .as_blob()?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ),
                };
                Ok(MetadataLibraryFileDetail {
                    file: decode(row)?,
                    upload_priority: row.get(17)?,
                    auto_upload_priority: row.get(18)?,
                    comment: row.get(15)?,
                    rating: row.get(19)?,
                    aich_root,
                })
            },
        )
    }

    fn library_file_read<T>(
        &self,
        hash: &[u8; 16],
        extra: &str,
        decode: impl FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Option<T>> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.session_library_files WHERE ed2k_hash=?1)",
            [hash.as_slice()],
            |row| row.get::<_, bool>(0),
        )? {
            return Ok(None);
        }
        crate::library_projection::refresh(&tx)?;
        let file=tx.query_row(&format!("SELECT f.ed2k_hash,{COLUMNS}{extra}
            FROM temp.session_library_files f CROSS JOIN temp.session_file_upload_statistics s ON s.known_file_id=f.known_file_id
            CROSS JOIN known_files k ON k.id=f.known_file_id WHERE f.ed2k_hash=?1"),[hash.as_slice()],|row| {
                crate::download_job_store::bounded_row_bytes(row,&[(1,65_536,8)])?;
                decode(row)
            }).optional()?;
        tx.commit()?;
        Ok(file)
    }

    /// A byte-bounded live page. The admitted caller publishes captured counters
    /// first and reserves work for one folded label plus this result. No paths,
    /// hashsets, jobs or per-file tag arrays are materialized by this read.
    pub fn library_file_page(
        &self,
        query: &LibraryFileQuery,
        max_bytes: usize,
    ) -> Result<MetadataLibraryFilePage> {
        ensure!(
            (1..=200).contains(&query.limit),
            "invalid library page size"
        );
        ensure!(
            (1..=crate::LIBRARY_READ_MAX_BYTES).contains(&max_bytes),
            "invalid library read budget"
        );
        ensure!(
            query.root_id.is_none_or(|id| id > 0)
                && query
                    .tag
                    .as_ref()
                    .is_none_or(|name| crate::valid_category_name(name)),
            "invalid library filter identity"
        );
        ensure!(
            query
                .search
                .as_ref()
                .is_none_or(|value| value.len() <= 65_536),
            "library query exceeds allowance"
        );
        let search = crate::normalize_library_search(query.search.as_deref())?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        // WHY: reject a missing anchor before cold projection work; rolling
        // back a fully warmed index would repeat that work on the next request.
        if let Some(hash) = query.after {
            ensure!(
                tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM temp.session_library_files WHERE ed2k_hash=?1)",
                    [hash.as_slice()],
                    |row| row.get::<_, bool>(0)
                )?,
                MetadataLibraryCursorExpired
            );
        }
        crate::library_projection::refresh(&tx)?;
        crate::library_projection::refresh_names(&tx)?;
        let (source, mut values) = source_and_filters(query, search.as_deref());
        let total = if query.count_total {
            Some(tx.query_row(
                &format!("SELECT count(*) {source}"),
                params_from_iter(values.iter()),
                |row| crate::sql_value::unsigned(row, 0),
            )?)
        } else {
            None
        };
        let sql = page_sql(query, &source, &mut values);
        let mut statement = tx.prepare_cached(&sql)?;
        let mut rows = statement.query(params_from_iter(values.iter()))?;
        let mut files = Vec::new();
        let mut bytes = 0usize;
        let mut has_more = false;
        let mut last = None;
        while let Some(row) = rows.next()? {
            if files.len() == query.limit {
                has_more = true;
                break;
            }
            let charge = crate::download_job_store::bounded_row_bytes(row, &[(1, 65_536, 8)])?;
            if bytes
                .checked_add(charge)
                .is_none_or(|value| value > max_bytes)
            {
                ensure!(!files.is_empty(), "library row exceeds result allowance");
                has_more = true;
                break;
            }
            let hash: [u8; 16] = row.get_ref(0)?.as_blob()?.try_into()?;
            files.push(decode(row)?);
            last = Some(hash);
            bytes += charge;
        }
        drop(rows);
        drop(statement);
        tx.commit()?;
        Ok(MetadataLibraryFilePage {
            files,
            next_after: if has_more { last } else { None },
            total,
        })
    }
}

#[cfg(test)]
mod tests;
