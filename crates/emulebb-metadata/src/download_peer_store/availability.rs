//! Current-session availability pages never load execution geometry or hints.
use super::*;
use rusqlite::OptionalExtension;
use std::net::{Ipv4Addr, SocketAddrV4};

const PAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct MetadataDownloadAvailabilityQuery {
    pub token: JobToken,
    pub session_id: [u8; 16],
    pub observed_since_s: i64,
    pub observed_until_s: i64,
    pub after_source_id: i64,
    pub limit: usize,
}

/// A selected reporter's current opportunity, not a persistent priority score.
#[derive(Debug, Clone, Copy)]
pub struct MetadataDownloadScarcityQuery {
    pub token: JobToken,
    pub session_id: [u8; 16],
    pub observed_since_s: i64,
    pub observed_until_s: i64,
    pub user_hash: [u8; 16],
}

#[derive(Debug)]
pub struct MetadataDownloadSourceAvailability {
    pub source_id: i64,
    pub endpoint: SocketAddrV4,
    pub user_hash: [u8; 16],
    pub file_size_bytes: u64,
    pub part_count: u32,
    /// LSB-first data-part bits, without a protocol EOF slice.
    pub part_status: Vec<u8>,
    pub observed_at_s: i64,
}
impl MetadataDownloadSourceAvailability {
    pub fn has_part(&self, index: u32) -> bool {
        index < self.part_count
            && self
                .part_status
                .get(index as usize / 8)
                .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
    }
}

pub(super) fn store(
    tx: &Connection,
    token: JobToken,
    source: &MetadataTransferSource,
    session: [u8; 16],
    size: u64,
    parts: &[bool],
    observed: i64,
) -> Result<bool> {
    let geometry: Option<(i64, i64)> = tx
        .query_row(
            "SELECT expected_size_bytes,CASE WHEN expected_size_bytes>0
            THEN 1+(expected_size_bytes-1)/part_size_bytes ELSE 0 END FROM download_jobs
        WHERE id=?1 AND execution_generation=?2 AND storage_failure_code IS NULL",
            params![token.job_id, i64::try_from(token.generation)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    ensure!(
        geometry == Some((i64::try_from(size)?, i64::try_from(parts.len())?)),
        "peer availability contradicts job geometry"
    );
    upsert_source(tx, token, source, false, None)?;
    let source_id: i64 = tx.query_row(
        "SELECT id FROM download_job_sources WHERE job_id=?1 AND ip=?2 AND tcp_port=?3
         AND low_client_id IS NULL",
        params![token.job_id, source.ip, source.tcp_port],
        |row| row.get(0),
    )?;
    let mut packed = vec![0u8; parts.len().div_ceil(8)];
    for (index, present) in parts.iter().enumerate() {
        if *present {
            packed[index / 8] |= 1 << (index % 8);
        }
    }
    let user = crate::store::decode_fixed_hex(
        source
            .user_hash
            .as_deref()
            .expect("validated observed identity"),
        16,
        "observed user hash",
    )?;
    Ok(tx.execute("INSERT INTO download_job_source_availability(job_id,source_id,execution_generation,session_id,
        observed_user_hash,file_size_bytes,part_count,part_status,observed_at_s)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
        ON CONFLICT(job_id,source_id) DO UPDATE SET execution_generation=excluded.execution_generation,
        session_id=excluded.session_id,observed_user_hash=excluded.observed_user_hash,file_size_bytes=excluded.file_size_bytes,
        part_count=excluded.part_count,part_status=excluded.part_status,observed_at_s=excluded.observed_at_s",
        params![token.job_id, source_id, i64::try_from(token.generation)?, session.as_slice(), user,
            i64::try_from(size)?, i64::try_from(parts.len())?, packed, observed])? != 0)
}

const PAGE_SQL: &str = "SELECT a.source_id,s.ip,s.tcp_port,a.observed_user_hash,a.file_size_bytes,
    a.part_count,a.part_status,a.observed_at_s FROM download_job_source_availability a
    JOIN download_job_sources s ON s.job_id=a.job_id AND s.id=a.source_id
    JOIN download_jobs j ON j.id=a.job_id
    WHERE a.job_id=?1 AND a.source_id>?2 AND a.execution_generation=?3 AND a.session_id=?4
    AND a.observed_at_s BETWEEN ?5 AND ?6 AND s.user_hash=a.observed_user_hash
    AND j.execution_generation=?3 AND j.intent='started' AND j.removed_at_s IS NULL
    AND j.terminal_completed_at_s IS NULL AND j.delete_requested_at_s IS NULL AND j.storage_failure_code IS NULL
    AND j.expected_size_bytes=a.file_size_bytes
    AND 1+(j.expected_size_bytes-1)/j.part_size_bytes=a.part_count
    ORDER BY a.source_id LIMIT ?7";

impl MetadataStore {
    /// Does this reporter offer a missing part no other freshly observed
    /// identity offers? Stream all observations in one SQLite snapshot with
    /// two protocol-bounded bitsets; repeated endpoints never add votes.
    pub fn download_job_has_rare_source_part(
        &self,
        query: MetadataDownloadScarcityQuery,
    ) -> Result<bool> {
        self.source_scarcity(query, None)
    }

    /// A listener-owned callback supplies fresh status without creating a
    /// dialable endpoint. Other reporter claims and verified parts use the
    /// same database snapshot and identity rules as persisted observations.
    pub fn download_job_live_source_has_rare_part(
        &self,
        query: MetadataDownloadScarcityQuery,
        file_size: u64,
        parts: &[bool],
    ) -> Result<bool> {
        self.source_scarcity(query, Some((file_size, parts)))
    }

    fn source_scarcity(
        &self,
        query: MetadataDownloadScarcityQuery,
        live: Option<(u64, &[bool])>,
    ) -> Result<bool> {
        ensure!(
            query.observed_since_s >= 0 && query.observed_until_s >= query.observed_since_s,
            "invalid scarcity observation interval"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let geometry = tx
            .query_row(
                "SELECT expected_size_bytes,
            1+(expected_size_bytes-1)/part_size_bytes FROM download_jobs
            WHERE id=?1 AND execution_generation=?2 AND intent='started'
            AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL
            AND delete_requested_at_s IS NULL AND storage_failure_code IS NULL
            AND internal_storage_retired=0 AND expected_size_bytes>0",
                params![query.token.job_id, i64::try_from(query.token.generation)?],
                |row| {
                    Ok((
                        crate::sql_value::unsigned::<u64>(row, 0)?,
                        crate::sql_value::unsigned::<usize>(row, 1)?,
                    ))
                },
            )
            .optional()?;
        let Some((size, part_count)) = geometry else {
            return Ok(false);
        };
        ensure!(
            (1..=65534).contains(&part_count),
            "unsupported scarcity geometry"
        );
        let mut offered = vec![0u8; part_count.div_ceil(8)];
        let mut others = vec![0u8; offered.len()];
        if let Some((live_size, parts)) = live {
            ensure!(
                live_size == size && parts.len() == part_count,
                "live source differs from job geometry"
            );
            for (index, present) in parts.iter().enumerate() {
                if *present {
                    offered[index / 8] |= 1 << (index % 8);
                }
            }
        }
        {
            let mut stmt = tx.prepare_cached(PAGE_SQL)?;
            let mut rows = stmt.query(params![
                query.token.job_id,
                0,
                i64::try_from(query.token.generation)?,
                query.session_id.as_slice(),
                query.observed_since_s,
                query.observed_until_s,
                -1
            ])?;
            while let Some(row) = rows.next()? {
                let count = crate::sql_value::unsigned::<usize>(row, 5)?;
                let bits = row.get_ref(6)?.as_blob()?;
                ensure!(
                    (1..=65534).contains(&count) && bits.len() == count.div_ceil(8),
                    "invalid observed part status"
                );
                ensure!(count == part_count, "inconsistent observed geometry");
                let identity = row.get_ref(3)?.as_blob()?;
                ensure!(identity.len() == 16, "invalid observed identity");
                // A live reply supersedes older status from the same identity;
                // it must not regain unavailable parts through another endpoint.
                if live.is_some() && identity == query.user_hash {
                    continue;
                }
                let target = if identity == query.user_hash {
                    &mut offered
                } else {
                    &mut others
                };
                for (target, bits) in target.iter_mut().zip(bits) {
                    *target |= bits;
                }
            }
        }
        for (offered, others) in offered.iter_mut().zip(others) {
            *offered &= !others;
        }
        {
            let mut stmt = tx.prepare_cached(
                "SELECT piece_index FROM download_job_pieces
                WHERE job_id=?1 AND state='Verified' ORDER BY piece_index",
            )?;
            let mut rows = stmt.query([query.token.job_id])?;
            while let Some(row) = rows.next()? {
                let index = crate::sql_value::unsigned::<usize>(row, 0)?;
                ensure!(index < part_count, "verified part outside job geometry");
                offered[index / 8] &= !(1 << (index % 8));
            }
        }
        // WHY: status padding is not a data part and cannot establish rarity.
        if !part_count.is_multiple_of(8) {
            *offered.last_mut().expect("nonempty part geometry") &= (1 << (part_count % 8)) - 1;
        }
        let rare = offered.iter().any(|byte| *byte != 0);
        tx.commit()?;
        Ok(rare)
    }

    /// Byte-bounded keyset page over observed peers, independent of hint count.
    pub fn download_job_source_availability(
        &self,
        query: MetadataDownloadAvailabilityQuery,
    ) -> Result<Vec<MetadataDownloadSourceAvailability>> {
        ensure!(
            query.after_source_id >= 0
                && (1..=256).contains(&query.limit)
                && query.observed_since_s >= 0
                && query.observed_until_s >= query.observed_since_s,
            "invalid availability page"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(PAGE_SQL)?;
        let mut rows = stmt.query(params![
            query.token.job_id,
            query.after_source_id,
            i64::try_from(query.token.generation)?,
            query.session_id.as_slice(),
            query.observed_since_s,
            query.observed_until_s,
            i64::try_from(query.limit)?
        ])?;
        let mut result = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let ip = row.get_ref(1)?.as_str()?;
            ensure!(ip.len() <= 15, "invalid observed endpoint length");
            let blob = row.get_ref(6)?.as_blob()?;
            let count = crate::sql_value::unsigned::<u32>(row, 5)?;
            ensure!(
                (1..=65534).contains(&count) && blob.len() == (count as usize).div_ceil(8),
                "invalid observed part status"
            );
            let charge = std::mem::size_of::<MetadataDownloadSourceAvailability>() * 2 + blob.len();
            if bytes + charge > PAGE_BYTES {
                break;
            }
            bytes += charge;
            result.push(MetadataDownloadSourceAvailability {
                source_id: row.get(0)?,
                endpoint: SocketAddrV4::new(ip.parse::<Ipv4Addr>()?, row.get(2)?),
                user_hash: row
                    .get::<_, Vec<u8>>(3)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid observed identity"))?,
                file_size_bytes: crate::sql_value::unsigned::<u64>(row, 4)?,
                part_count: count,
                part_status: blob.to_vec(),
                observed_at_s: row.get(7)?,
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
