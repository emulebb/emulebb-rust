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
impl MetadataDownloadPeerDelta {
    /// Validate before command cloning/admission. This is the owned text size,
    /// not a claim about SQLite's separate connection/page cache.
    pub fn payload_bytes(&self) -> Result<usize> {
        let source_bytes = |source: &MetadataTransferSource| -> Result<usize> {
            validate_source(source)?;
            Ok(std::mem::size_of::<MetadataTransferSource>()
                + source.ip.capacity()
                + source.file_comment.capacity()
                + source.user_hash.as_ref().map_or(0, String::capacity))
        };
        Ok(match self {
            Self::Source { source, .. } => source_bytes(source)?,
            Self::ObserveName {
                observation: value,
                source,
            } => {
                ensure!(
                    !value.raw_name.trim().is_empty()
                        && !value.normalized_name.trim().is_empty()
                        && value.raw_name.len() <= 65_536
                        && value.normalized_name.len() <= 65_536
                        && value.client_software.len() <= 65_536
                        && value.origin.len() <= 64
                        && value
                            .server_endpoint
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
                std::mem::size_of::<MetadataTransferFileNameObservation>()
                    + value.raw_name.capacity()
                    + value.normalized_name.capacity()
                    + value.client_software.capacity()
                    + value.origin.capacity()
                    + value.source_ip.as_ref().map_or(0, String::capacity)
                    + value.user_hash.as_ref().map_or(0, String::capacity)
                    + value.server_endpoint.as_ref().map_or(0, String::capacity)
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
                let hash = value
                    .user_hash
                    .as_deref()
                    .map(|hash| crate::store::decode_fixed_hex(hash, 16, "source user hash"))
                    .transpose()?;
                tx.execute("INSERT INTO download_job_file_name_observations(job_id,position,source_ip,source_tcp_port,user_hash,
                    client_software,origin,server_endpoint,raw_name,normalized_name,observed_at_s)
                    VALUES(?1,(SELECT coalesce(max(position)+1,0) FROM download_job_file_name_observations WHERE job_id=?1),?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![token.job_id,value.source_ip,value.source_tcp_port,hash,value.client_software,value.origin,
                        value.server_endpoint,value.raw_name,value.normalized_name,value.observed_at_s])?;
                // Diagnostic history keeps the existing latest 512-observation
                // window in SQL; it is never an automatic name-selection policy.
                tx.execute("DELETE FROM download_job_file_name_observations WHERE job_id=?1 AND id<(
                    SELECT id FROM download_job_file_name_observations WHERE job_id=?1 ORDER BY id DESC LIMIT 1 OFFSET 511)", [token.job_id])?;
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
                    WHERE id=?1 AND execution_generation=?2 AND completed=0 AND delivery_state='pending'
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

    /// Byte-capped keyset source page. The last returned row is the next cursor.
    pub fn download_job_sources_after(
        &self,
        token: JobToken,
        after: i64,
        limit: usize,
    ) -> Result<Vec<MetadataDownloadSourceEntry>> {
        ensure!(
            after >= 0 && (1..=256).contains(&limit),
            "invalid source page"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(
            "SELECT s.id,s.ip,s.tcp_port,s.user_hash,s.connect_options,s.file_comment,s.file_rating
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
        let mut bytes = result.capacity() * std::mem::size_of::<MetadataDownloadSourceEntry>();
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
            result.push(MetadataDownloadSourceEntry {
                id: row.get(0)?,
                source: MetadataTransferSource {
                    ip: ip.to_owned(),
                    tcp_port: row.get(2)?,
                    user_hash: row.get::<_, Option<Vec<u8>>>(3)?.map(hex::encode),
                    connect_options: row.get(4)?,
                    file_comment: comment.to_owned(),
                    file_rating: row.get(6)?,
                },
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
            n.origin,n.server_endpoint,n.raw_name,n.normalized_name,n.observed_at_s
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
                    server_endpoint: row.get(6)?,
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
