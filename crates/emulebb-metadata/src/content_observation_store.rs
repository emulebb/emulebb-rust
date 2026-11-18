//! Bounded ingestion of raw occurrences, with no session-owned lifetime.

use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::{
    CONTENT_OBSERVATION_BATCH_BYTES, CONTENT_OBSERVATION_BATCH_ITEMS, MetadataContentClaim,
    MetadataContentMetadata, MetadataContentObservation, MetadataContentObservationEvent,
    MetadataContentObservationPage, MetadataContentObservationReceipt, MetadataObservationOrigin,
    MetadataStore, content_observation_model::OBSERVATION_BYTES,
};

const PAGE_ITEMS: usize = 100;
pub(crate) const COLUMNS: &str =
    "o.id,o.claim_id,o.first_seen_at_s,o.last_seen_at_s,o.observation_count,
    o.origin,o.reporter_endpoint,c.ed2k_hash,c.size_bytes,o.name,o.source_count,
    o.complete_source_count,o.source_client_id,o.source_client_port,o.file_type,
    o.media_artist,o.media_album,o.media_title,o.media_length_seconds,
    o.media_bitrate_kbps,o.media_codec,o.rating,o.aich_root,o.complete,o.directory";

impl MetadataStore {
    /// Commit an ordered batch of newly decoded occurrences atomically.
    /// The caller must not replay a committed batch or submit projections.
    /// Receipts follow input order, including repeated observations in the batch.
    pub fn ingest_content_observations(
        &self,
        events: &[MetadataContentObservationEvent],
    ) -> Result<Vec<MetadataContentObservationReceipt>> {
        self.write_content_observations(events, None)
            .map(|(receipts, _)| receipts)
    }

    /// Ingest raw facts and collecting-session membership in the same transaction.
    /// A missing/terminal session still retains every valid corpus occurrence.
    pub fn ingest_search_observations(
        &self,
        events: &[MetadataContentObservationEvent],
        projection: &crate::MetadataSearchProjection,
    ) -> Result<Option<crate::MetadataSearchPublication>> {
        ensure!(projection.session_id > 0, "invalid search identity");
        ensure!(
            !events.is_empty(),
            "search projection requires observations"
        );
        ensure!(
            !projection.name_votes.is_empty()
                && projection.name_votes.len() <= CONTENT_OBSERVATION_BATCH_ITEMS,
            "search projection requires bounded filename votes"
        );
        let mut bytes = 0usize;
        for vote in &projection.name_votes {
            ensure!(
                !vote.normalized_name.is_empty() && vote.quality.rating <= 5,
                "invalid filename vote"
            );
            let charge = vote
                .payload_bytes()
                .context("filename vote size overflow")?;
            ensure!(charge <= OBSERVATION_BYTES, "filename vote is too large");
            bytes = bytes
                .checked_add(charge)
                .context("filename vote size overflow")?;
        }
        ensure!(
            bytes <= CONTENT_OBSERVATION_BATCH_BYTES,
            "filename votes exceed batch bound"
        );
        self.write_content_observations(events, Some(projection))
            .map(|(receipts, name)| {
                name.map(|name| crate::MetadataSearchPublication {
                    claim_id: receipts[0].claim_id,
                    name,
                })
            })
    }

    fn write_content_observations(
        &self,
        events: &[MetadataContentObservationEvent],
        projection: Option<&crate::MetadataSearchProjection>,
    ) -> Result<(Vec<MetadataContentObservationReceipt>, Option<String>)> {
        ensure!(
            events.len() <= CONTENT_OBSERVATION_BATCH_ITEMS,
            "too many content observations"
        );
        let mut bytes = 0usize;
        for event in events {
            ensure!(event.observed_at_s >= 0, "negative observation timestamp");
            let charge = event
                .payload_bytes()
                .context("content observation size overflow")?;
            ensure!(
                charge <= OBSERVATION_BYTES,
                "content observation is too large"
            );
            bytes = bytes
                .checked_add(charge)
                .context("content observation batch size overflow")?;
            ensure!(
                bytes <= CONTENT_OBSERVATION_BATCH_BYTES,
                "content observation batch is too large"
            );
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut receipts = Vec::with_capacity(events.len());
        for event in events {
            let hash = event.claim.hash.as_slice();
            let size = event.claim.size_bytes.map(u64::to_be_bytes);
            // WHY: SQLite UNIQUE treats nulls as distinct. Separate partial
            // indexes keep one unresolved claim without equating null with zero.
            let claim_id: i64 = tx.query_row(
                "INSERT INTO content_claims(ed2k_hash,size_bytes,first_seen_at_s,last_seen_at_s)
                 VALUES(?1,?2,?3,?3) ON CONFLICT DO UPDATE SET
                 first_seen_at_s=min(first_seen_at_s,excluded.first_seen_at_s),
                 last_seen_at_s=max(last_seen_at_s,excluded.last_seen_at_s) RETURNING id",
                params![
                    hash,
                    size.as_ref().map(|value| value.as_slice()),
                    event.observed_at_s
                ],
                |row| row.get(0),
            )?;
            // The typed tuple has a fixed field order and omits absent metadata;
            // time/count are deliberately outside semantic variant identity.
            let fingerprint = Sha256::digest(serde_json::to_vec(&(
                event.origin,
                event.reporter_endpoint,
                &event.metadata,
            ))?);
            let m = &event.metadata;
            let receipt = tx.query_row(
                "INSERT INTO content_claim_observations(
                    claim_id,fingerprint,origin,reporter_endpoint,name,source_count,
                    complete_source_count,source_client_id,source_client_port,file_type,
                    media_artist,media_album,media_title,media_length_seconds,media_bitrate_kbps,
                    media_codec,rating,aich_root,complete,directory,first_seen_at_s,last_seen_at_s,
                    observation_count)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                    ?17,?18,?19,?20,?21,?21,1)
                 ON CONFLICT(claim_id,fingerprint) DO UPDATE SET
                    first_seen_at_s=min(first_seen_at_s,excluded.first_seen_at_s),
                    last_seen_at_s=max(last_seen_at_s,excluded.last_seen_at_s),
                    observation_count=CASE WHEN observation_count < 9223372036854775807
                        THEN observation_count+1 ELSE observation_count END
                 RETURNING id,first_seen_at_s,last_seen_at_s,observation_count",
                params![
                    claim_id,
                    fingerprint.as_slice(),
                    event.origin.as_str(),
                    event.reporter_endpoint.map(|endpoint| endpoint.to_string()),
                    m.name,
                    m.source_count.map(i64::from),
                    m.complete_source_count.map(i64::from),
                    m.source_client_id.map(i64::from),
                    m.source_client_port.map(i64::from),
                    m.file_type,
                    m.media_artist,
                    m.media_album,
                    m.media_title,
                    m.media_length_seconds.map(i64::from),
                    m.media_bitrate_kbps.map(i64::from),
                    m.media_codec,
                    m.rating.map(i64::from),
                    m.aich_root.as_ref().map(|root| root.as_slice()),
                    m.complete,
                    m.directory,
                    event.observed_at_s,
                ],
                |row| {
                    Ok(MetadataContentObservationReceipt {
                        claim_id,
                        observation_id: row.get(0)?,
                        first_seen_at_s: row.get(1)?,
                        last_seen_at_s: row.get(2)?,
                        observation_count: row.get(3)?,
                    })
                },
            )?;
            receipts.push(receipt);
        }
        let projected = match projection {
            Some(projection) => crate::search_store::persist_projection(
                &tx,
                projection,
                &receipts,
                &events.iter().map(|e| e.observed_at_s).collect::<Vec<_>>(),
            )?,
            None => None,
        };
        tx.commit().map_err(|error| {
            anyhow::Error::new(error).context(crate::MetadataObservationCommitUncertain)
        })?;
        Ok((receipts, projected))
    }

    /// Keyset page of permanent provenance. Returns no more than 256 KiB of
    /// conservatively charged data and never loads a claim's whole history.
    pub fn content_observations_page(
        &self,
        claim_id: i64,
        after_id: i64,
        limit: usize,
    ) -> Result<MetadataContentObservationPage> {
        ensure!(
            claim_id > 0 && after_id >= 0,
            "invalid content observation cursor"
        );
        ensure!(
            (1..=PAGE_ITEMS).contains(&limit),
            "invalid content observation page limit"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM content_claim_observations o
             JOIN content_claims c ON c.id=o.claim_id
             WHERE o.claim_id=?1 AND o.id>?2 ORDER BY o.id LIMIT ?3"
        ))?;
        let mut rows = stmt.query(params![claim_id, after_id, i64::try_from(limit)? + 1])?;
        let mut items = Vec::with_capacity(limit);
        let mut bytes = 0usize;
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            if items.len() == limit {
                has_more = true;
                break;
            }
            // Charge SQLite's borrowed text before allocating owned strings.
            let mut charge = 2048usize;
            for column in [9, 14, 15, 16, 17, 20, 24] {
                let value = row.get_ref(column)?;
                if !matches!(value, rusqlite::types::ValueRef::Null) {
                    charge = charge
                        .checked_add(
                            value
                                .as_str()?
                                .len()
                                .checked_mul(6)
                                .context("content observation size overflow")?,
                        )
                        .context("content observation size overflow")?;
                }
            }
            ensure!(
                charge <= OBSERVATION_BYTES,
                "stored content observation is too large"
            );
            if bytes + charge > CONTENT_OBSERVATION_BATCH_BYTES {
                has_more = true;
                break;
            }
            bytes += charge;
            items.push(observation_from_row(row)?);
        }
        Ok(MetadataContentObservationPage { items, has_more })
    }

    pub fn content_claim(&self, id: i64) -> Result<Option<MetadataContentClaim>> {
        ensure!(id > 0, "invalid content claim identity");
        let conn = self.connection()?;
        let encoded: Option<(Vec<u8>, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT ed2k_hash,size_bytes FROM content_claims WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        encoded
            .map(|(hash, size)| decode_claim(hash, size))
            .transpose()
    }
}

fn decode_claim(hash: Vec<u8>, size: Option<Vec<u8>>) -> Result<MetadataContentClaim> {
    Ok(MetadataContentClaim {
        hash: hash.try_into().ok().context("invalid content claim hash")?,
        size_bytes: size
            .map(|size| {
                Ok::<_, anyhow::Error>(u64::from_be_bytes(
                    size.try_into().ok().context("invalid content claim size")?,
                ))
            })
            .transpose()?,
    })
}

pub(crate) fn observation_from_row(row: &rusqlite::Row<'_>) -> Result<MetadataContentObservation> {
    let origin: String = row.get(5)?;
    let origin = match origin.as_str() {
        "server" => MetadataObservationOrigin::Server,
        "global" => MetadataObservationOrigin::Global,
        "kad" => MetadataObservationOrigin::Kad,
        _ => anyhow::bail!("invalid observation origin"),
    };
    let reporter: Option<String> = row.get(6)?;
    let aich: Option<Vec<u8>> = row.get(22)?;
    let last_seen_at_s = row.get(3)?;
    Ok(MetadataContentObservation {
        receipt: MetadataContentObservationReceipt {
            observation_id: row.get(0)?,
            claim_id: row.get(1)?,
            first_seen_at_s: row.get(2)?,
            last_seen_at_s,
            observation_count: row.get(4)?,
        },
        event: MetadataContentObservationEvent {
            claim: decode_claim(row.get(7)?, row.get(8)?)?,
            origin,
            reporter_endpoint: reporter.map(|value| value.parse()).transpose()?,
            observed_at_s: last_seen_at_s,
            metadata: MetadataContentMetadata {
                name: row.get(9)?,
                source_count: row.get(10)?,
                complete_source_count: row.get(11)?,
                source_client_id: row.get(12)?,
                source_client_port: row.get(13)?,
                file_type: row.get(14)?,
                media_artist: row.get(15)?,
                media_album: row.get(16)?,
                media_title: row.get(17)?,
                media_length_seconds: row.get(18)?,
                media_bitrate_kbps: row.get(19)?,
                media_codec: row.get(20)?,
                rating: row.get(21)?,
                aich_root: aich
                    .map(|root| {
                        root.try_into()
                            .ok()
                            .context("invalid observation AICH root")
                    })
                    .transpose()?,
                complete: row.get(23)?,
                directory: row.get(24)?,
            },
        },
    })
}

#[cfg(test)]
mod tests;
