//! Independent field winners, bounded by admitted presentation observations.
use crate::{MetadataSearchNameQuality, MetadataSearchResultFields};
use anyhow::Result;
use rusqlite::{ToSql, Transaction, params};

fn consider(
    tx: &Transaction<'_>,
    session: i64,
    claim: i64,
    columns: &[&str],
    quality: MetadataSearchNameQuality,
    values: &[&dyn ToSql],
) -> Result<()> {
    // Identifiers are fixed call-site literals. Values always remain bound parameters.
    let field = columns[0];
    let names = columns.join(",");
    let placeholders = (8..8 + values.len())
        .map(|n| format!("?{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let useful = i64::from(quality.useful);
    let mut bindings: Vec<&dyn ToSql> = vec![
        &session,
        &claim,
        &field,
        &useful,
        &quality.sources,
        &quality.complete_sources,
        &quality.rating,
    ];
    bindings.extend_from_slice(values);
    let changed=tx.execute(&format!("INSERT INTO search_field_quality(session_id,claim_id,field,
        quality_useful,quality_sources,quality_complete_sources,quality_rating) VALUES(?1,?2,?3,?4,?5,?6,?7)
        ON CONFLICT(session_id,claim_id,field) DO UPDATE SET quality_useful=excluded.quality_useful,
            quality_sources=excluded.quality_sources,quality_complete_sources=excluded.quality_complete_sources,
            quality_rating=excluded.quality_rating
        WHERE (quality_useful,quality_sources,quality_complete_sources,quality_rating)<(?4,?5,?6,?7)
        OR ((quality_useful,quality_sources,quality_complete_sources,quality_rating)=(?4,?5,?6,?7)
            AND ({placeholders})<(SELECT {names} FROM search_results WHERE session_id=?1 AND claim_id=?2))"),
        bindings.as_slice())?;
    if changed != 0 {
        // WHY: quality and selected value must advance in the same transaction;
        // equal-quality values use binary/numeric order, independent of arrival.
        tx.execute(&format!("UPDATE search_results SET ({names})=({placeholders}) WHERE session_id=?1 AND claim_id=?2"),
            bindings.as_slice())?;
    }
    Ok(())
}

pub(super) fn apply(
    tx: &Transaction<'_>,
    session: i64,
    claim: i64,
    observations: &[MetadataSearchResultFields],
) -> Result<()> {
    for value in observations {
        let q = value.quality;
        if let Some((id, port)) = value.source_client_id.zip(value.source_client_port) {
            consider(
                tx,
                session,
                claim,
                &["source_client_id", "source_client_port"],
                q,
                &[&id, &port],
            )?;
        }
        for (field, text) in [
            ("file_type", &value.file_type),
            ("media_artist", &value.media_artist),
            ("media_album", &value.media_album),
            ("media_title", &value.media_title),
            ("media_codec", &value.media_codec),
            ("directory", &value.directory),
        ] {
            if !text.is_empty() && (field != "file_type" || !text.eq_ignore_ascii_case("unknown")) {
                consider(tx, session, claim, &[field], q, &[text])?;
            }
        }
        for (field, number) in [
            ("media_length_seconds", value.media_length_seconds),
            ("media_bitrate_kbps", value.media_bitrate_kbps),
        ] {
            if number != 0 {
                consider(tx, session, claim, &[field], q, &[&number])?;
            }
        }
        if let Some(root) = super::encode_aich_root(&value.aich_hash)? {
            consider(tx, session, claim, &["aich_root"], q, &[&root])?;
        }
        tx.execute("UPDATE search_results SET rating=max(rating,?3),complete=max(complete,?4) WHERE session_id=?1 AND claim_id=?2",
            params![session,claim,value.rating,i64::from(value.complete)])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
