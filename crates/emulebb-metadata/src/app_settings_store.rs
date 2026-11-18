//! One complete typed settings document and checked saved-revision CAS.
use anyhow::{Context, Result};
use emulebb_settings::product::{SavedSettings, SettingsEdit, SettingsRevision};
use rusqlite::{Connection, TransactionBehavior, params};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataAppSettings {
    pub revision: SettingsRevision,
    pub saved: SavedSettings,
}

#[derive(Debug)]
pub enum MetadataSettingsWriteError {
    Conflict { actual: SettingsRevision },
    CommitUncertain(rusqlite::Error),
}
impl fmt::Display for MetadataSettingsWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict {..}=>f.write_str("Saved settings changed; read the latest revision."),
            Self::CommitUncertain(_)=>f.write_str("Settings commit outcome is uncertain; reload authoritative state before another write."),
        }
    }
}
impl std::error::Error for MetadataSettingsWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CommitUncertain(error) => Some(error),
            _ => None,
        }
    }
}

pub(crate) fn seed(conn: &Connection, saved: &SavedSettings) -> Result<()> {
    let document = String::from_utf8(saved.resolved()?.to_json_bytes()?)?;
    conn.execute(
        "INSERT INTO app_settings(id,revision,document_json) VALUES(1,?1,?2)",
        params![SettingsRevision::INITIAL.get(), document],
    )?;
    Ok(())
}

fn read(conn: &Connection) -> Result<MetadataAppSettings> {
    let (revision, document) = conn.query_row(
        "SELECT revision,document_json FROM app_settings WHERE id=1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )?;
    Ok(MetadataAppSettings {
        revision: SettingsRevision::from_i64(revision)?,
        saved: SavedSettings::from_json_bytes(document.as_bytes())
            .context("invalid saved settings document")?,
    })
}

impl crate::MetadataStore {
    /// Capture document and revision in one statement. Default resolution is
    /// read-only: it neither rewrites the document nor advances its revision.
    /// Missing or invalid documents are errors, never defaults or repaired rows.
    pub fn load_app_settings(&self) -> Result<MetadataAppSettings> {
        read(&*self.connection()?)
    }

    /// Runtime callers use the shared persistence owner and a captured CAS
    /// token. Ok means the candidate and its next revision committed together.
    pub fn compare_and_set_app_settings(
        &self,
        expected: SettingsRevision,
        edit: &SettingsEdit,
    ) -> Result<MetadataAppSettings> {
        self.write_app_settings(Some(expected), edit)
    }

    /// Offline callers must already own the stopped profile's exclusive lease.
    /// The caller supplies no CAS token; concurrent external changes still fail
    /// explicitly rather than triggering a hidden read/modify/write retry.
    pub fn edit_app_settings(&self, edit: &SettingsEdit) -> Result<MetadataAppSettings> {
        self.write_app_settings(None, edit)
    }

    fn write_app_settings(
        &self,
        expected: Option<SettingsRevision>,
        edit: &SettingsEdit,
    ) -> Result<MetadataAppSettings> {
        let mut conn = self.connection()?;
        let current = read(&conn)?;
        if expected.is_some_and(|expected| expected != current.revision) {
            return Err(MetadataSettingsWriteError::Conflict {
                actual: current.revision,
            }
            .into());
        }
        // WHY: validation and exact serialization finish before acquiring the
        // write transaction. A second connection can advance meanwhile, so the
        // UPDATE must still CAS the captured revision inside that transaction.
        let saved = current.saved.edited(edit)?;
        let document = String::from_utf8(saved.to_json_bytes()?)?;
        let revision = current.revision.checked_next()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE app_settings SET revision=?2,document_json=?3 WHERE id=1 AND revision=?1",
            params![current.revision.get(), revision.get(), document],
        )?;
        if changed == 0 {
            let actual = SettingsRevision::from_i64(tx.query_row(
                "SELECT revision FROM app_settings WHERE id=1",
                [],
                |row| row.get(0),
            )?)?;
            return Err(MetadataSettingsWriteError::Conflict { actual }.into());
        }
        // A COMMIT error must not become a promise that no durable write took
        // place. The runtime owner will handle this typed uncertainty explicitly.
        tx.commit()
            .map_err(MetadataSettingsWriteError::CommitUncertain)?;
        Ok(MetadataAppSettings { revision, saved })
    }
}

#[cfg(test)]
mod tests;
