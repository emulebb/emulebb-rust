//! Small peer/name deltas and byte-bounded diagnostic pages, independent of geometry.
use crate::{JobToken, MetadataStore, MetadataTransferFileNameObservation, MetadataTransferSource};
use anyhow::{Result, ensure};
use rusqlite::{Connection, TransactionBehavior, params};

#[derive(Debug, Clone)]
pub enum MetadataDownloadPeerDelta {
    Source {
        source: MetadataTransferSource,
        description_only: bool,
    },
    ObserveName {
        observation: MetadataTransferFileNameObservation,
        source: Option<MetadataTransferSource>,
    },
    RemoveSource {
        endpoint: Option<(std::net::Ipv4Addr, u16)>,
        user_hash: Option<[u8; 16]>,
    },
    Rename(String),
}
#[derive(Debug)]
pub struct MetadataDownloadPeerChange {
    pub changed: bool,
    pub display_name: Option<String>,
}
#[derive(Debug)]
pub struct MetadataDownloadSourceEntry {
    pub id: i64,
    pub source: MetadataTransferSource,
    pub reported_file_names: Vec<MetadataTransferFileNameObservation>,
    pub reported_file_names_has_more: bool,
}

/// Comment evidence without source-name windows or execution geometry.
#[derive(Debug)]
pub struct MetadataDownloadCommentEntry {
    pub id: i64,
    pub ip: String,
    pub tcp_port: u16,
    pub user_hash: Option<String>,
    pub comment: String,
    pub rating: u8,
}

#[derive(Debug)]
pub struct MetadataDownloadCommentPage {
    pub comments: Vec<MetadataDownloadCommentEntry>,
    pub has_more: bool,
}

const COMMENTS_SQL: &str = "SELECT s.id,s.ip,s.tcp_port,s.user_hash,s.file_comment,s.file_rating
    FROM download_job_sources s INDEXED BY download_job_sources_comments_idx
    JOIN download_jobs j ON j.id=s.job_id
    WHERE s.job_id=?1 AND s.id>?2 AND j.execution_generation=?3 AND j.removed_at_s IS NULL
    AND (s.file_comment<>'' OR s.file_rating>0) ORDER BY s.id LIMIT ?4";
#[derive(Debug, Clone, Copy)]
pub enum MetadataDownloadSourceSelector {
    UserHash([u8; 16]),
    Endpoint(std::net::Ipv4Addr, u16),
}
#[derive(Debug)]
pub struct MetadataDownloadSourceEndpoint {
    pub id: i64,
    pub ip: std::net::Ipv4Addr,
    pub tcp_port: u16,
    pub user_hash: Option<[u8; 16]>,
    pub connect_options: Option<u8>,
}
#[derive(Debug)]
pub struct MetadataDownloadNameEntry {
    pub id: i64,
    pub observation: MetadataTransferFileNameObservation,
}
const PAGE_BYTES: usize = 1024 * 1024;
const SOURCE_NAME_WINDOW: usize = 16;
// Leave room for the consumer's live scalars and sixfold JSON escaping under
// the existing eight-MiB work budget. This is a projection cap, not retention.
const SOURCE_NAMES_PAGE_BYTES: usize = 512 * 1024;
const SOURCE_HASH_NAMES_SQL: &str = "SELECT id,source_ip,source_tcp_port,user_hash,
    client_software,origin,reporter_endpoint,raw_name,normalized_name,observed_at_s
    FROM download_job_file_name_observations INDEXED BY download_job_names_hash_window_idx
    WHERE job_id=?1 AND user_hash=?2 AND user_hash IS NOT NULL
    ORDER BY observed_at_s DESC,id DESC LIMIT 17";
const SOURCE_ENDPOINT_NAMES_SQL: &str = "SELECT id,source_ip,source_tcp_port,user_hash,
    client_software,origin,reporter_endpoint,raw_name,normalized_name,observed_at_s
    FROM download_job_file_name_observations INDEXED BY download_job_names_endpoint_window_idx
    WHERE job_id=?1 AND source_ip=?2 AND source_tcp_port=?3 AND user_hash IS NULL
    ORDER BY observed_at_s DESC,id DESC LIMIT 17";

/// Charge text before copying it. Oversized observations are omitted from the
/// source window, with an explicit flag, rather than rewritten or truncated.
fn source_name_charge(row: &rusqlite::Row<'_>) -> Result<Option<usize>> {
    let mut bytes = 32;
    for (column, cap) in [
        (1, 45),
        (4, 65_536),
        (5, 64),
        (6, 256),
        (7, 65_536),
        (8, 65_536),
    ] {
        let value = row.get_ref(column)?;
        if !matches!(value, rusqlite::types::ValueRef::Null) {
            let text = value.as_str()?;
            if text.len() > cap {
                return Ok(None);
            }
            bytes += text.len();
        }
    }
    if row.get_ref(8)?.as_str()?.chars().count() > 4096 {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn source_name_from_row(row: &rusqlite::Row<'_>) -> Result<MetadataTransferFileNameObservation> {
    Ok(MetadataTransferFileNameObservation {
        source_ip: row.get(1)?,
        source_tcp_port: row.get(2)?,
        user_hash: row.get::<_, Option<Vec<u8>>>(3)?.map(hex::encode),
        client_software: row.get(4)?,
        origin: row.get(5)?,
        reporter_endpoint: row.get(6)?,
        raw_name: row.get(7)?,
        normalized_name: row.get(8)?,
        observed_at_s: row.get(9)?,
    })
}

fn source_name_window(
    conn: &Connection,
    token: JobToken,
    source: &MetadataTransferSource,
    bytes: &mut usize,
    name_bytes: &mut usize,
) -> Result<(Vec<MetadataTransferFileNameObservation>, bool)> {
    let hash = source
        .user_hash
        .as_deref()
        .map(|value| crate::store::decode_fixed_hex(value, 16, "source user hash"))
        .transpose()?;
    let mut stmt = conn.prepare_cached(if hash.is_some() {
        SOURCE_HASH_NAMES_SQL
    } else {
        SOURCE_ENDPOINT_NAMES_SQL
    })?;
    let mut rows = if let Some(hash) = &hash {
        stmt.query(params![token.job_id, hash])?
    } else {
        stmt.query(params![token.job_id, source.ip, source.tcp_port])?
    };
    let mut names = Vec::new();
    let mut has_more = false;
    let backing = SOURCE_NAME_WINDOW * std::mem::size_of::<MetadataTransferFileNameObservation>();
    let mut visited = 0;
    while let Some(row) = rows.next()? {
        visited += 1;
        if visited > SOURCE_NAME_WINDOW {
            has_more = true;
            break;
        }
        let Some(charge) = source_name_charge(row)? else {
            has_more = true;
            continue;
        };
        let required = charge + if names.capacity() == 0 { backing } else { 0 };
        if *bytes + required > PAGE_BYTES || *name_bytes + required > SOURCE_NAMES_PAGE_BYTES {
            has_more = true;
            continue;
        }
        if names.capacity() == 0 {
            names.reserve_exact(SOURCE_NAME_WINDOW);
            ensure!(
                names.capacity() == SOURCE_NAME_WINDOW,
                "source name allocation exceeds allowance"
            );
            *bytes += backing;
            *name_bytes += backing;
        }
        *bytes += charge;
        *name_bytes += charge;
        names.push(source_name_from_row(row)?);
    }
    Ok((names, has_more))
}

fn validate_source(source: &MetadataTransferSource) -> Result<()> {
    source.ip.parse::<std::net::Ipv4Addr>()?;
    ensure!(
        source.tcp_port != 0 && source.file_comment.len() <= 65_536,
        "invalid source description"
    );
    if let Some(hash) = source.user_hash.as_deref() {
        crate::store::decode_fixed_hex(hash, 16, "source user hash")?;
    }
    Ok(())
}
fn source_bytes(source: &MetadataTransferSource) -> Result<usize> {
    validate_source(source)?;
    Ok(std::mem::size_of::<MetadataTransferSource>()
        + source.ip.capacity()
        + source.file_comment.capacity()
        + source.user_hash.as_ref().map_or(0, String::capacity))
}

fn observation_bytes(value: &MetadataTransferFileNameObservation) -> Result<usize> {
    ensure!(
        !value.raw_name.trim().is_empty()
            && !value.normalized_name.trim().is_empty()
            && value.raw_name.len() <= 65_536
            && value.normalized_name.len() <= 65_536
            && value.client_software.len() <= 65_536
            && value.origin.len() <= 64
            && value
                .reporter_endpoint
                .as_ref()
                .is_none_or(|v| v.len() <= 256)
            && value.observed_at_s >= 0
            && value.source_ip.is_some() == value.source_tcp_port.is_some(),
        "filename observation exceeds bounded diagnostic fields"
    );
    if let Some(ip) = &value.source_ip {
        ip.parse::<std::net::Ipv4Addr>()?;
    }
    if let Some(hash) = &value.user_hash {
        crate::store::decode_fixed_hex(hash, 16, "source user hash")?;
    }
    Ok(std::mem::size_of::<MetadataTransferFileNameObservation>()
        + value.raw_name.capacity()
        + value.normalized_name.capacity()
        + value.client_software.capacity()
        + value.origin.capacity()
        + value.source_ip.as_ref().map_or(0, String::capacity)
        + value.user_hash.as_ref().map_or(0, String::capacity)
        + value.reporter_endpoint.as_ref().map_or(0, String::capacity))
}

/// Source hints and diagnostic names committed with a newly admitted job.
/// Duplicate admission never modifies the existing job's peer state.
#[derive(Debug, Clone, Default)]
pub struct MetadataDownloadInitialPeers {
    pub sources: Vec<MetadataTransferSource>,
    pub observations: Vec<MetadataTransferFileNameObservation>,
}
impl MetadataDownloadInitialPeers {
    /// Validate caller backing before the native owner clones the command.
    pub fn payload_bytes(&self) -> Result<usize> {
        let mut bytes = std::mem::size_of::<Self>()
            + self.sources.capacity() * std::mem::size_of::<MetadataTransferSource>()
            + self.observations.capacity()
                * std::mem::size_of::<MetadataTransferFileNameObservation>();
        for source in &self.sources {
            bytes = bytes
                .checked_add(source_bytes(source)?)
                .ok_or_else(|| anyhow::anyhow!("initial peer size overflow"))?;
        }
        for observation in &self.observations {
            bytes = bytes
                .checked_add(observation_bytes(observation)?)
                .ok_or_else(|| anyhow::anyhow!("initial peer size overflow"))?;
        }
        ensure!(
            bytes <= 512 * 1024,
            "initial peers exceed command allowance"
        );
        Ok(bytes)
    }
    pub(crate) fn insert(&self, conn: &Connection, token: JobToken) -> Result<()> {
        for source in &self.sources {
            upsert_source(conn, token, source, false)?;
        }
        for observation in &self.observations {
            insert_observation(conn, token, observation)?;
        }
        Ok(())
    }
}

impl MetadataDownloadPeerDelta {
    /// Validate before command cloning/admission. This is the owned text size,
    /// not a claim about SQLite's separate connection/page cache.
    pub fn payload_bytes(&self) -> Result<usize> {
        Ok(match self {
            Self::Source { source, .. } => source_bytes(source)?,
            Self::ObserveName {
                observation: value,
                source,
            } => {
                observation_bytes(value)?
                    + source.as_ref().map(source_bytes).transpose()?.unwrap_or(0)
            }
            Self::RemoveSource { .. } => 128,
            Self::Rename(name) => {
                ensure!(
                    !name.is_empty() && name.len() <= 65_536,
                    "invalid chosen download name"
                );
                name.capacity()
            }
        })
    }
}

fn upsert_source(
    conn: &Connection,
    token: JobToken,
    source: &MetadataTransferSource,
    description: bool,
) -> Result<bool> {
    let hash = source
        .user_hash
        .as_deref()
        .map(|hash| crate::store::decode_fixed_hex(hash, 16, "source user hash"))
        .transpose()?;
    let now = crate::download_job_store::unix_s();
    if description {
        if source.file_comment.is_empty() && source.file_rating == 0 {
            return Ok(false);
        }
        let existing: Option<i64> = conn.query_row(
            "SELECT min(id) FROM (
                SELECT id FROM (SELECT id FROM download_job_sources WHERE job_id=?1 AND ip=?2 AND tcp_port=?3 LIMIT 1)
                UNION ALL SELECT id FROM (SELECT id FROM download_job_sources WHERE job_id=?1 AND user_hash=?4 ORDER BY id LIMIT 1))",
            params![token.job_id, source.ip, source.tcp_port, hash], |row| row.get(0),
        )?;
        if let Some(id) = existing {
            return Ok(conn.execute("UPDATE download_job_sources SET file_comment=?2,file_rating=?3,
                user_hash=coalesce(user_hash,?4),connect_options=coalesce(connect_options,?5),last_seen_at_s=?6 WHERE id=?1",
                params![id, source.file_comment, source.file_rating, hash, source.connect_options, now])? != 0);
        }
    }
    Ok(conn.execute("INSERT INTO download_job_sources(job_id,ip,tcp_port,user_hash,connect_options,file_comment,file_rating,first_seen_at_s,last_seen_at_s)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)
        ON CONFLICT(job_id,ip,tcp_port) DO UPDATE SET
            user_hash=coalesce(excluded.user_hash,download_job_sources.user_hash),
            connect_options=coalesce(excluded.connect_options,download_job_sources.connect_options),
            file_comment=CASE WHEN excluded.file_comment<>'' OR excluded.file_rating<>0 THEN excluded.file_comment ELSE download_job_sources.file_comment END,
            file_rating=CASE WHEN excluded.file_comment<>'' OR excluded.file_rating<>0 THEN excluded.file_rating ELSE download_job_sources.file_rating END,
            last_seen_at_s=excluded.last_seen_at_s",
        params![token.job_id, source.ip, source.tcp_port, hash, source.connect_options, source.file_comment, source.file_rating, now])? != 0)
}

fn insert_observation(
    conn: &Connection,
    token: JobToken,
    value: &MetadataTransferFileNameObservation,
) -> Result<()> {
    let hash = value
        .user_hash
        .as_deref()
        .map(|hash| crate::store::decode_fixed_hex(hash, 16, "source user hash"))
        .transpose()?;
    conn.execute("INSERT INTO download_job_file_name_observations(job_id,position,source_ip,source_tcp_port,user_hash,
                    client_software,origin,reporter_endpoint,raw_name,normalized_name,observed_at_s)
                    VALUES(?1,(SELECT coalesce(max(position)+1,0) FROM download_job_file_name_observations WHERE job_id=?1),?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![token.job_id,value.source_ip,value.source_tcp_port,hash,value.client_software,value.origin,
                        value.reporter_endpoint,value.raw_name,value.normalized_name,value.observed_at_s])?;
    // Diagnostic history keeps the existing latest 512-observation
    // window in SQL; it is never an automatic name-selection policy.
    conn.execute("DELETE FROM download_job_file_name_observations WHERE job_id=?1 AND id<(
                    SELECT id FROM download_job_file_name_observations WHERE job_id=?1 ORDER BY id DESC LIMIT 1 OFFSET 511)", [token.job_id])?;
    Ok(())
}

impl MetadataStore {
    pub fn apply_download_peer_delta(
        &self,
        token: JobToken,
        delta: &MetadataDownloadPeerDelta,
    ) -> Result<MetadataDownloadPeerChange> {
        ensure!(
            delta.payload_bytes()? <= 512 * 1024,
            "peer delta exceeds command allowance"
        );
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rename = matches!(delta, MetadataDownloadPeerDelta::Rename(_));
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_jobs
            WHERE id=?1 AND execution_generation=?2 AND removed_at_s IS NULL
              AND terminal_completed_at_s IS NULL AND delete_requested_at_s IS NULL
              AND (?3 OR intent='started'))",
            params![token.job_id, i64::try_from(token.generation)?, rename],
            |row| row.get(0),
        )?;
        ensure!(current, "stale download peer callback");
        let mut name = None;
        let changed = match delta {
            MetadataDownloadPeerDelta::Source {
                source,
                description_only,
            } => upsert_source(&tx, token, source, *description_only)?,
            MetadataDownloadPeerDelta::ObserveName {
                observation: value,
                source,
            } => {
                if let Some(source) = source {
                    upsert_source(&tx, token, source, false)?;
                }
                insert_observation(&tx, token, value)?;
                true
            }
            MetadataDownloadPeerDelta::RemoveSource {
                endpoint,
                user_hash,
            } => {
                let endpoint = endpoint.map(|(ip, port)| (ip.to_string(), port));
                tx.execute(
                    "DELETE FROM download_job_sources WHERE job_id=?1 AND
                    ((ip=?2 AND tcp_port=?3) OR user_hash=?4)",
                    params![
                        token.job_id,
                        endpoint.as_ref().map(|v| &v.0),
                        endpoint.as_ref().map(|v| v.1),
                        user_hash.as_ref().map(|v| v.as_slice())
                    ],
                )? != 0
            }
            MetadataDownloadPeerDelta::Rename(value) => {
                ensure!(tx.execute("UPDATE download_jobs SET display_name=?3,updated_at_s=?4
                    WHERE id=?1 AND execution_generation=?2 AND terminal_completed_at_s IS NULL AND removed_at_s IS NULL
                      AND delete_requested_at_s IS NULL AND delivery_state='pending'
                      AND NOT EXISTS(SELECT 1 FROM download_delivery_attempts WHERE job_id=?1)",
                    params![token.job_id,i64::try_from(token.generation)?,value,crate::download_job_store::unix_s()])? == 1,
                    "only unfinished jobs without a delivery attempt may be renamed");
                name = Some(value.clone());
                true
            }
        };
        tx.commit()?;
        Ok(MetadataDownloadPeerChange {
            changed,
            display_name: name,
        })
    }

    /// Fixed-size wire/scheduler source candidates; descriptions stay in the
    /// diagnostic page and cannot truncate a rarity-count or protocol batch.
    pub fn download_job_source_endpoints_after(
        &self,
        token: JobToken,
        after: i64,
        limit: usize,
    ) -> Result<Vec<MetadataDownloadSourceEndpoint>> {
        ensure!(
            after >= 0 && (1..=256).contains(&limit),
            "invalid source endpoint page"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(
            "SELECT s.id,s.ip,s.tcp_port,s.user_hash,s.connect_options
            FROM download_job_sources s JOIN download_jobs j ON j.id=s.job_id
            WHERE s.job_id=?1 AND s.id>?2 AND j.execution_generation=?3 AND j.removed_at_s IS NULL
            ORDER BY s.id LIMIT ?4",
        )?;
        let mut rows = stmt.query(params![
            token.job_id,
            after,
            i64::try_from(token.generation)?,
            i64::try_from(limit)?
        ])?;
        let mut result = Vec::with_capacity(limit);
        while let Some(row) = rows.next()? {
            let ip = row.get_ref(1)?.as_str()?;
            ensure!(ip.len() <= 45, "source address exceeds field allowance");
            let hash = row.get_ref(3)?;
            let hash = if matches!(hash, rusqlite::types::ValueRef::Null) {
                None
            } else {
                Some(hash.as_blob()?.try_into()?)
            };
            result.push(MetadataDownloadSourceEndpoint {
                id: row.get(0)?,
                ip: ip.parse()?,
                tcp_port: row.get(2)?,
                user_hash: hash,
                connect_options: row.get(4)?,
            });
        }
        Ok(result)
    }

    /// Seek only comment/rating rows. The extra row establishes continuation
    /// without copying another page or fetching reported filenames.
    pub fn download_job_comments_after(
        &self,
        token: JobToken,
        after: i64,
        limit: usize,
    ) -> Result<MetadataDownloadCommentPage> {
        ensure!(
            after >= 0 && (1..=256).contains(&limit),
            "invalid comment page"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(COMMENTS_SQL)?;
        let mut rows = stmt.query(params![
            token.job_id,
            after,
            i64::try_from(token.generation)?,
            i64::try_from(limit + 1)?
        ])?;
        let mut comments = Vec::with_capacity(limit);
        let mut bytes = comments.capacity() * std::mem::size_of::<MetadataDownloadCommentEntry>();
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            if comments.len() == limit {
                has_more = true;
                break;
            }
            let ip = row.get_ref(1)?.as_str()?;
            let comment = row.get_ref(4)?.as_str()?;
            ensure!(
                ip.len() <= 45 && comment.len() <= 65_536,
                "comment row exceeds field allowance"
            );
            let charge = ip.len() + comment.len() + 32;
            if bytes + charge > PAGE_BYTES {
                ensure!(!comments.is_empty(), "comment exceeds page allowance");
                has_more = true;
                break;
            }
            bytes += charge;
            comments.push(MetadataDownloadCommentEntry {
                id: row.get(0)?,
                ip: ip.to_owned(),
                tcp_port: row.get(2)?,
                user_hash: row.get::<_, Option<Vec<u8>>>(3)?.map(hex::encode),
                comment: comment.to_owned(),
                rating: row.get(5)?,
            });
        }
        Ok(MetadataDownloadCommentPage { comments, has_more })
    }

    /// Byte-capped keyset source page. The last returned row is the next cursor.
    pub fn download_job_sources_after(
        &self,
        token: JobToken,
        after: i64,
        limit: usize,
    ) -> Result<Vec<MetadataDownloadSourceEntry>> {
        self.download_source_rows(token, after, limit, None)
    }

    /// The same bounded projection as the source collection, selected through
    /// its identity index rather than searching or hydrating the collection.
    pub fn download_job_source(
        &self,
        token: JobToken,
        selector: MetadataDownloadSourceSelector,
    ) -> Result<Option<MetadataDownloadSourceEntry>> {
        Ok(self
            .download_source_rows(token, 0, 1, Some(selector))?
            .into_iter()
            .next())
    }

    fn download_source_rows(
        &self,
        token: JobToken,
        after: i64,
        limit: usize,
        selector: Option<MetadataDownloadSourceSelector>,
    ) -> Result<Vec<MetadataDownloadSourceEntry>> {
        ensure!(
            after >= 0 && (1..=256).contains(&limit),
            "invalid source page"
        );
        let conn = self.connection()?;
        let (index, predicate, key, port) = match selector {
            None => (
                "download_job_sources_page_idx",
                "AND ?5 IS NULL AND ?6 IS NULL",
                rusqlite::types::Value::Null,
                rusqlite::types::Value::Null,
            ),
            Some(MetadataDownloadSourceSelector::UserHash(hash)) => (
                "download_job_sources_user_idx",
                "AND s.user_hash=?5 AND ?6 IS NULL",
                rusqlite::types::Value::Blob(hash.to_vec()),
                rusqlite::types::Value::Null,
            ),
            Some(MetadataDownloadSourceSelector::Endpoint(ip, port)) => (
                "download_job_sources_identity_idx",
                "AND s.ip=?5 AND s.tcp_port=?6",
                rusqlite::types::Value::Text(ip.to_string()),
                rusqlite::types::Value::Integer(port.into()),
            ),
        };
        let sql = format!(
            "SELECT s.id,s.ip,s.tcp_port,s.user_hash,s.connect_options,s.file_comment,s.file_rating
            FROM download_job_sources s INDEXED BY {index} JOIN download_jobs j ON j.id=s.job_id
            WHERE s.job_id=?1 AND s.id>?2 AND j.execution_generation=?3 AND j.removed_at_s IS NULL
            {predicate} ORDER BY s.id LIMIT ?4"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let mut rows = stmt.query(params![
            token.job_id,
            after,
            i64::try_from(token.generation)?,
            i64::try_from(limit)?,
            key,
            port
        ])?;
        let mut result = Vec::with_capacity(limit);
        let mut bytes = result.capacity() * std::mem::size_of::<MetadataDownloadSourceEntry>();
        let mut name_bytes = 0;
        while let Some(row) = rows.next()? {
            let ip = row.get_ref(1)?.as_str()?;
            let comment = row.get_ref(5)?.as_str()?;
            ensure!(
                ip.len() <= 45 && comment.len() <= 65_536,
                "source row exceeds field allowance"
            );
            let charge = ip.len() + comment.len() + 32;
            if bytes + charge > PAGE_BYTES {
                ensure!(!result.is_empty(), "source exceeds page allowance");
                break;
            }
            bytes += charge;
            let source = MetadataTransferSource {
                ip: ip.to_owned(),
                tcp_port: row.get(2)?,
                user_hash: row.get::<_, Option<Vec<u8>>>(3)?.map(hex::encode),
                connect_options: row.get(4)?,
                file_comment: comment.to_owned(),
                file_rating: row.get(6)?,
            };
            // The outer source cursor keeps this connection's read snapshot
            // alive while the two indexed identity windows are queried.
            let (reported_file_names, reported_file_names_has_more) =
                source_name_window(&conn, token, &source, &mut bytes, &mut name_bytes)?;
            result.push(MetadataDownloadSourceEntry {
                id: row.get(0)?,
                source,
                reported_file_names,
                reported_file_names_has_more,
            });
        }
        Ok(result)
    }

    /// Latest-window diagnostic observations, with a stable row-ID cursor.
    pub fn download_job_names_after(
        &self,
        token: JobToken,
        after: i64,
        limit: usize,
    ) -> Result<Vec<MetadataDownloadNameEntry>> {
        ensure!(
            after >= 0 && (1..=256).contains(&limit),
            "invalid observation page"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached("SELECT n.id,n.source_ip,n.source_tcp_port,n.user_hash,n.client_software,
            n.origin,n.reporter_endpoint,n.raw_name,n.normalized_name,n.observed_at_s
            FROM download_job_file_name_observations n JOIN download_jobs j ON j.id=n.job_id
            WHERE n.job_id=?1 AND n.id>?2 AND j.execution_generation=?3 AND j.removed_at_s IS NULL ORDER BY n.id LIMIT ?4")?;
        let mut rows = stmt.query(params![
            token.job_id,
            after,
            i64::try_from(token.generation)?,
            i64::try_from(limit)?
        ])?;
        let mut result = Vec::with_capacity(limit);
        let mut bytes = result.capacity() * std::mem::size_of::<MetadataDownloadNameEntry>();
        while let Some(row) = rows.next()? {
            let mut charge = 32;
            for (column, cap) in [
                (1, 45),
                (4, 65536),
                (5, 64),
                (6, 256),
                (7, 65536),
                (8, 65536),
            ] {
                let value = row.get_ref(column)?;
                if !matches!(value, rusqlite::types::ValueRef::Null) {
                    let text = value.as_str()?;
                    ensure!(text.len() <= cap, "observation field exceeds allowance");
                    charge += text.len();
                }
            }
            if bytes + charge > PAGE_BYTES {
                ensure!(!result.is_empty(), "observation exceeds page allowance");
                break;
            }
            bytes += charge;
            result.push(MetadataDownloadNameEntry {
                id: row.get(0)?,
                observation: MetadataTransferFileNameObservation {
                    source_ip: row.get(1)?,
                    source_tcp_port: row.get(2)?,
                    user_hash: row.get::<_, Option<Vec<u8>>>(3)?.map(hex::encode),
                    client_software: row.get(4)?,
                    origin: row.get(5)?,
                    reporter_endpoint: row.get(6)?,
                    raw_name: row.get(7)?,
                    normalized_name: row.get(8)?,
                    observed_at_s: row.get(9)?,
                },
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
