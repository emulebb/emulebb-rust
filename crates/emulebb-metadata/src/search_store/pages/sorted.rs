//! Indexed ordering for the fixed twelve public result sorts.
use super::*;
use crate::{
    MetadataSearchResultSort as Sort, MetadataSearchResultsQuery, MetadataSearchSortOrder as Order,
};
fn column(sort: Sort) -> &'static str {
    match sort {
        Sort::Name => "name",
        Sort::SizeBytes => "size_sort_key",
        Sort::Sources => "source_count",
        Sort::CompleteSources => "complete_source_count",
        Sort::Rating => "rating",
        Sort::FileType => "file_type",
        Sort::Artist => "media_artist",
        Sort::Album => "media_album",
        Sort::Title => "media_title",
        Sort::LengthSeconds => "media_length_seconds",
        Sort::BitrateKbps => "media_bitrate_kbps",
        Sort::Codec => "media_codec",
    }
}
fn sql(query: &MetadataSearchResultsQuery) -> String {
    let column = column(query.sort);
    let (direction, comparison) = match query.order {
        Order::Asc => ("ASC", ">"),
        Order::Desc => ("DESC", "<"),
    };
    let boundary = if query.after_claim_id.is_some() {
        format!("AND (r.{column},r.claim_id){comparison}(?2,?3)")
    } else {
        String::new()
    };
    format!(
        "SELECT {RESULT_COLUMNS} FROM search_results r INDEXED BY search_results_sort_{column}_idx
        JOIN content_claims c ON c.id=r.claim_id WHERE r.session_id=?1 {boundary}
        ORDER BY r.{column} {direction},r.claim_id {direction} LIMIT ?4"
    )
}
fn anchor_sql(query: &MetadataSearchResultsQuery) -> String {
    format!(
        "SELECT {} FROM search_results WHERE session_id=?1 AND claim_id=?2",
        column(query.sort)
    )
}
fn anchor(
    conn: &rusqlite::Connection,
    query: &MetadataSearchResultsQuery,
) -> Result<Option<rusqlite::types::Value>> {
    let Some(claim) = query.after_claim_id else {
        return Ok(Some(rusqlite::types::Value::Null));
    };
    let mut statement = conn.prepare(&anchor_sql(query))?;
    let mut rows = statement.query(params![query.session_id, claim])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let bytes = match row.get_ref(0)? {
        rusqlite::types::ValueRef::Text(value) | rusqlite::types::ValueRef::Blob(value) => {
            value.len()
        }
        _ => 0,
    };
    ensure!(
        bytes.saturating_mul(6).saturating_add(256) <= 128 * 1024,
        "search cursor key exceeds its byte bound"
    );
    Ok(Some(row.get(0)?))
}
impl crate::MetadataStore {
    /// Global indexed ordering, with weak live traversal under summary mutations.
    /// An absent anchor in an existing session yields an empty page.
    pub fn search_results_page(
        &self,
        query: &MetadataSearchResultsQuery,
    ) -> Result<Option<MetadataSearchPage<MetadataSearchResultHeader>>> {
        let count = limit_value(query.limit)?;
        ensure!(
            query.session_id > 0 && query.after_claim_id.is_none_or(|id| id > 0),
            "invalid search result cursor identity"
        );
        let conn = self.connection()?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM search_sessions WHERE id=?1)",
            [query.session_id],
            |r| r.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        // WHY: a scalar subquery inside a tuple boundary may scan every tie.
        // Resolve one bounded anchor first so SQLite seeks the complete tuple.
        let Some(anchor) = anchor(&conn, query)? else {
            return Ok(Some(MetadataSearchPage {
                items: Vec::new(),
                has_more: false,
            }));
        };
        let mut statement = conn.prepare(&sql(query))?;
        let mut rows = statement.query(params![
            query.session_id,
            anchor,
            query.after_claim_id,
            count
        ])?;
        Ok(Some(collect_page(
            &mut rows,
            query.limit,
            &[3, 8, 9, 10, 11, 14, 18],
            SUMMARY_BOUNDS,
            result_from_row,
        )?))
    }
}
#[cfg(test)]
mod tests;
