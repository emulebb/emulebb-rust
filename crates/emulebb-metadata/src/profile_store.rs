use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

use crate::{
    profile_model::{MetadataCategory, MetadataFriend, MetadataServer},
    store::{bool_to_i64, decode_fixed_hex, unix_ms},
};

impl super::MetadataStore {
    pub fn load_preference_json(&self, key: &str) -> Result<Option<String>> {
        self.connection()?
            .query_row(
                "SELECT value_json FROM preferences WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn put_preference_json(&self, key: &str, value_json: &str) -> Result<()> {
        ensure!(!key.trim().is_empty(), "preference key must not be empty");
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO preferences(key, value_json, updated_at_ms)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![key, value_json, now],
        )?;
        Ok(())
    }

    pub fn load_categories(&self) -> Result<Vec<MetadataCategory>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, name, path, comment, priority, color
            FROM categories
            WHERE deleted_at_ms IS NULL
            ORDER BY id
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataCategory {
                id: row.get::<_, i64>(0)? as u32,
                name: row.get(1)?,
                path: row.get(2)?,
                comment: row.get(3)?,
                priority: row.get::<_, i64>(4)? as u32,
                color: row.get::<_, Option<i64>>(5)?.map(|value| value as u32),
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn upsert_category(&self, category: &MetadataCategory) -> Result<()> {
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO categories(id, name, path, comment, priority, color, created_at_ms, updated_at_ms, deleted_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, NULL)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                path = excluded.path,
                comment = excluded.comment,
                priority = excluded.priority,
                color = excluded.color,
                updated_at_ms = excluded.updated_at_ms,
                deleted_at_ms = NULL
            "#,
            params![
                i64::from(category.id),
                category.name,
                category.path,
                category.comment,
                i64::from(category.priority),
                category.color.map(i64::from),
                now,
            ],
        )?;
        Ok(())
    }

    pub fn delete_category(&self, category_id: u32) -> Result<()> {
        self.connection()?.execute(
            "UPDATE categories SET deleted_at_ms = ?1, updated_at_ms = ?1 WHERE id = ?2",
            params![unix_ms(), i64::from(category_id)],
        )?;
        Ok(())
    }

    pub fn load_friends(&self) -> Result<Vec<MetadataFriend>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(user_hash)), name, last_address, last_port, first_seen_ms, last_seen_ms
            FROM friends
            WHERE deleted_at_ms IS NULL
            ORDER BY name, user_hash
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataFriend {
                user_hash: row.get(0)?,
                name: row.get(1)?,
                last_address: row.get(2)?,
                last_port: row.get::<_, i64>(3)? as u16,
                first_seen_ms: row.get(4)?,
                last_seen_ms: row.get(5)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn upsert_friend(&self, friend: &MetadataFriend) -> Result<()> {
        let now = unix_ms();
        let user_hash = decode_fixed_hex(&friend.user_hash, 16, "friend user hash")?;
        self.connection()?.execute(
            r#"
            INSERT INTO friends(user_hash, name, last_address, last_port, first_seen_ms, last_seen_ms, deleted_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
            ON CONFLICT(user_hash) DO UPDATE SET
                name = excluded.name,
                last_address = excluded.last_address,
                last_port = excluded.last_port,
                last_seen_ms = excluded.last_seen_ms,
                deleted_at_ms = NULL
            "#,
            params![
                user_hash,
                friend.name,
                friend.last_address,
                i64::from(friend.last_port),
                if friend.first_seen_ms > 0 {
                    friend.first_seen_ms
                } else {
                    now
                },
                friend.last_seen_ms,
            ],
        )?;
        Ok(())
    }

    pub fn delete_friend(&self, user_hash: &str) -> Result<()> {
        let user_hash = decode_fixed_hex(user_hash, 16, "friend user hash")?;
        self.connection()?.execute(
            "UPDATE friends SET deleted_at_ms = ?1 WHERE user_hash = ?2",
            params![unix_ms(), user_hash],
        )?;
        Ok(())
    }

    pub fn load_servers(&self) -> Result<Vec<MetadataServer>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT endpoint, address, port, name, description, priority, static_server,
                   enabled, failed_count, ping_ms, users, files, soft_files, hard_files, version
            FROM servers
            WHERE deleted_at_ms IS NULL
            ORDER BY endpoint
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataServer {
                endpoint: row.get(0)?,
                address: row.get(1)?,
                port: row.get::<_, i64>(2)? as u16,
                name: row.get(3)?,
                description: row.get(4)?,
                priority: row.get(5)?,
                static_server: row.get::<_, i64>(6)? != 0,
                enabled: row.get::<_, i64>(7)? != 0,
                failed_count: row.get::<_, i64>(8)? as u32,
                ping_ms: row.get::<_, Option<i64>>(9)?.map(|value| value as u32),
                users: row.get::<_, Option<i64>>(10)?.unwrap_or_default() as u64,
                files: row.get::<_, Option<i64>>(11)?.unwrap_or_default() as u64,
                soft_files: row.get::<_, Option<i64>>(12)?.unwrap_or_default() as u64,
                hard_files: row.get::<_, Option<i64>>(13)?.unwrap_or_default() as u64,
                version: row.get(14)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn upsert_server(&self, server: &MetadataServer) -> Result<()> {
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO servers(
                endpoint, address, port, name, description, priority, static_server,
                enabled, failed_count, ping_ms, users, files, soft_files, hard_files,
                version, first_seen_ms, last_seen_ms, deleted_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16, NULL)
            ON CONFLICT(endpoint) DO UPDATE SET
                address = excluded.address,
                port = excluded.port,
                name = excluded.name,
                description = excluded.description,
                priority = excluded.priority,
                static_server = excluded.static_server,
                enabled = excluded.enabled,
                failed_count = excluded.failed_count,
                ping_ms = excluded.ping_ms,
                users = excluded.users,
                files = excluded.files,
                soft_files = excluded.soft_files,
                hard_files = excluded.hard_files,
                version = excluded.version,
                last_seen_ms = excluded.last_seen_ms,
                deleted_at_ms = NULL
            "#,
            params![
                server.endpoint,
                server.address,
                i64::from(server.port),
                server.name,
                server.description,
                server.priority,
                bool_to_i64(server.static_server),
                bool_to_i64(server.enabled),
                i64::from(server.failed_count),
                server.ping_ms.map(i64::from),
                server.users as i64,
                server.files as i64,
                server.soft_files as i64,
                server.hard_files as i64,
                server.version,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn set_server_enabled(&self, endpoint: &str, enabled: bool) -> Result<()> {
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO servers(endpoint, address, port, enabled, first_seen_ms, last_seen_ms)
            VALUES (?1, '', 0, ?2, ?3, ?3)
            ON CONFLICT(endpoint) DO UPDATE SET
                enabled = excluded.enabled,
                last_seen_ms = excluded.last_seen_ms,
                deleted_at_ms = NULL
            "#,
            params![endpoint, bool_to_i64(enabled), now],
        )?;
        Ok(())
    }

    pub fn load_unshared_file_hashes(&self) -> Result<Vec<String>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(known_files.ed2k_hash))
            FROM unshared_files
            JOIN known_files ON known_files.id = unshared_files.known_file_id
            ORDER BY unshared_files.id
            "#,
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn mark_unshared_file(&self, ed2k_hash: &str, reason: &str) -> Result<bool> {
        let hash = decode_fixed_hex(ed2k_hash, 16, "ED2K hash")?;
        let known_file_id = self
            .connection()?
            .query_row(
                "SELECT id FROM known_files WHERE ed2k_hash = ?1",
                params![hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(known_file_id) = known_file_id else {
            return Ok(false);
        };
        self.connection()?.execute(
            r#"
            INSERT INTO unshared_files(known_file_id, reason, created_at_ms)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(known_file_id) DO UPDATE SET
                reason = excluded.reason
            "#,
            params![known_file_id, reason, unix_ms()],
        )?;
        Ok(true)
    }

    pub fn unmark_unshared_file(&self, ed2k_hash: &str) -> Result<()> {
        let hash = decode_fixed_hex(ed2k_hash, 16, "ED2K hash")?;
        self.connection()?.execute(
            r#"
            DELETE FROM unshared_files
            WHERE known_file_id IN (SELECT id FROM known_files WHERE ed2k_hash = ?1)
            "#,
            params![hash],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_state_roundtrips() {
        let store = super::super::MetadataStore::in_memory().unwrap();

        store
            .put_preference_json("core.preferences", r#"{"networkEd2k":true}"#)
            .unwrap();
        assert_eq!(
            store.load_preference_json("core.preferences").unwrap(),
            Some(r#"{"networkEd2k":true}"#.to_string())
        );

        store
            .upsert_category(&MetadataCategory {
                id: 7,
                name: "Samples".to_string(),
                path: None,
                comment: "Synthetic".to_string(),
                priority: 2,
                color: Some(0x00aa11),
            })
            .unwrap();
        assert_eq!(store.load_categories().unwrap()[0].id, 7);
        store.delete_category(7).unwrap();
        assert!(store.load_categories().unwrap().is_empty());

        store
            .upsert_friend(&MetadataFriend {
                user_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Peer".to_string(),
                last_address: Some("192.0.2.44".to_string()),
                last_port: 4662,
                first_seen_ms: 1,
                last_seen_ms: Some(2),
            })
            .unwrap();
        assert_eq!(store.load_friends().unwrap()[0].last_port, 4662);
        store
            .delete_friend("00112233445566778899aabbccddeeff")
            .unwrap();
        assert!(store.load_friends().unwrap().is_empty());
    }

    #[test]
    fn server_and_unshared_state_roundtrip() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        store
            .upsert_server(&MetadataServer {
                endpoint: "192.0.2.10:4661".to_string(),
                address: "192.0.2.10".to_string(),
                port: 4661,
                name: "Test Server".to_string(),
                description: "Synthetic".to_string(),
                priority: "high".to_string(),
                static_server: true,
                enabled: true,
                failed_count: 2,
                ping_ms: Some(50),
                users: 10,
                files: 20,
                soft_files: 30,
                hard_files: 40,
                version: "17.15".to_string(),
            })
            .unwrap();
        store.set_server_enabled("192.0.2.10:4661", false).unwrap();
        let servers = store.load_servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert!(!servers[0].enabled);
        assert_eq!(servers[0].name, "Test Server");

        store
            .upsert_transfer_manifest(&crate::MetadataTransferManifest {
                file_hash: "00112233445566778899aabbccddeeff".to_string(),
                canonical_name: "Sample.bin".to_string(),
                file_size: 10,
                piece_size: 10,
                completed: true,
                md4_hashset_acquired: false,
                md4_hashset: Vec::new(),
                aich_hashset_acquired: false,
                aich_root: None,
                aich_hashset: Vec::new(),
                verified_ranges: Vec::new(),
                upload_priority: "normal".to_string(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
                control_state: None,
                transfer_row_removed: false,
                pieces: Vec::new(),
                sources: Vec::new(),
            })
            .unwrap();
        assert!(
            store
                .mark_unshared_file("00112233445566778899aabbccddeeff", "manual")
                .unwrap()
        );
        assert_eq!(
            store.load_unshared_file_hashes().unwrap(),
            vec!["00112233445566778899aabbccddeeff".to_string()]
        );
        store
            .unmark_unshared_file("00112233445566778899aabbccddeeff")
            .unwrap();
        assert!(store.load_unshared_file_hashes().unwrap().is_empty());
    }
}
