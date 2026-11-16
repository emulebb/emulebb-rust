use std::{collections::BTreeMap, path::Path};

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{
    profile_model::{MetadataCategory, MetadataFriend, MetadataServer},
    store::{
        bool_to_i64, decode_fixed_hex, refresh_shared_root_eligibility, unix_ms, upsert_local_path,
    },
};

// A root path and its root row are each unique. Scalar lookups keep the
// membership scan constrained to one root and ordered by the covering index.
pub(crate) const CATEGORY_ROOT_HASH_PAGE_SQL: &str = "SELECT m.known_file_id,(SELECT k.ed2k_hash FROM known_files k WHERE k.id=m.known_file_id) FROM shared_file_memberships m INDEXED BY shared_file_memberships_root_content_idx WHERE m.root_id=(SELECT r.id FROM shared_directory_roots r JOIN local_paths p ON p.id=r.path_id WHERE p.platform=?1 AND p.native_path=?2) AND m.known_file_id>?3 GROUP BY m.known_file_id ORDER BY m.known_file_id LIMIT ?4";

/// Time spent acquiring the shared connection and executing a friend write.
#[derive(Debug, Clone, Copy)]
pub struct FriendWriteTiming {
    pub connection_wait: std::time::Duration,
    pub execution: std::time::Duration,
}

pub(crate) fn seed_host_storage_defaults(
    tx: &rusqlite::Transaction<'_>,
    storage: &crate::InitialProfileStorage,
) -> Result<()> {
    ensure!(
        storage.incoming_dir.is_absolute() && storage.shared_dir.is_absolute(),
        "host folders must be absolute"
    );
    let incoming = storage
        .incoming_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("host incoming path must be valid Unicode"))?;
    let now = unix_ms();
    tx.execute(
            "INSERT INTO settings(section, key, value_json, updated_at_ms) VALUES ('daemon', 'incomingDir', json_quote(?1), ?2)",
            params![incoming, now],
        )?;
    let path_id = upsert_local_path(tx, &storage.shared_dir)?;
    tx.execute(
            "INSERT INTO shared_directory_roots(path_id, monitor_owned, shareable, accessible, enabled, created_at_ms, deleted_at_ms)
             VALUES (?1, 0, 1, 1, 1, ?2, NULL)",
            params![path_id, now],
        )?;
    tx.execute(
            "INSERT INTO shared_directory_root_origins(root_id, origin, monitor_owned, shareable, accessible)
             VALUES ((SELECT id FROM shared_directory_roots WHERE path_id = ?1), 'explicit', 0, 1, 1)",
            params![path_id],
        )?;
    Ok(())
}

impl super::MetadataStore {
    pub fn load_setting_json(&self, section: &str, key: &str) -> Result<Option<String>> {
        ensure!(
            !section.trim().is_empty(),
            "settings section must not be empty"
        );
        ensure!(!key.trim().is_empty(), "settings key must not be empty");
        self.connection()?
            .query_row(
                "SELECT value_json FROM settings WHERE section = ?1 AND key = ?2",
                params![section, key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn load_settings_section(&self, section: &str) -> Result<Vec<(String, String)>> {
        ensure!(
            !section.trim().is_empty(),
            "settings section must not be empty"
        );
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT key, value_json
            FROM settings
            WHERE section = ?1
            ORDER BY key
            "#,
        )?;
        let rows = stmt.query_map(params![section], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn has_settings_section(&self, section: &str) -> Result<bool> {
        ensure!(
            !section.trim().is_empty(),
            "settings section must not be empty"
        );
        let count: i64 = self.connection()?.query_row(
            "SELECT count(*) FROM settings WHERE section = ?1",
            params![section],
            |row| row.get(0),
        )?;
        Ok(count != 0)
    }

    pub fn put_setting_json(&self, section: &str, key: &str, value_json: &str) -> Result<()> {
        ensure!(
            !section.trim().is_empty(),
            "settings section must not be empty"
        );
        ensure!(!key.trim().is_empty(), "settings key must not be empty");
        let now = unix_ms();
        self.connection()?.execute(
            r#"
            INSERT INTO settings(section, key, value_json, updated_at_ms)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(section, key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![section, key, value_json, now],
        )?;
        Ok(())
    }

    pub fn replace_settings_section<'a>(
        &self,
        section: &str,
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<()> {
        ensure!(
            !section.trim().is_empty(),
            "settings section must not be empty"
        );
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM settings WHERE section = ?1", params![section])?;
        for (key, value_json) in entries {
            ensure!(!key.trim().is_empty(), "settings key must not be empty");
            tx.execute(
                r#"
                INSERT INTO settings(section, key, value_json, updated_at_ms)
                VALUES (?1, ?2, ?3, ?4)
                "#,
                params![section, key, value_json, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Validate and replace selected settings sections in one serialized transaction.
    ///
    /// The callback receives a coherent snapshot and must perform only synchronous
    /// candidate computation, without calling back into this store. Unselected
    /// and unchanged sections are preserved. A callback or write failure rolls
    /// back every section; success is returned only after durable commit.
    pub fn update_settings_sections<T>(
        &self,
        sections: &[&str],
        update: impl FnOnce(&mut BTreeMap<String, Vec<(String, String)>>) -> Result<T>,
    ) -> Result<T> {
        ensure!(!sections.is_empty(), "settings sections must not be empty");
        let mut conn = self.connection()?;
        // WHY: read/modify/write must serialize across independent connections,
        // not only clones sharing this store's connection mutex.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut rows = BTreeMap::new();
        {
            let mut select =
                tx.prepare("SELECT key, value_json FROM settings WHERE section = ?1 ORDER BY key")?;
            for section in sections {
                ensure!(
                    !section.trim().is_empty(),
                    "settings section must not be empty"
                );
                let entries = select
                    .query_map([section], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<(String, String)>>>()?;
                ensure!(
                    rows.insert((*section).to_owned(), entries).is_none(),
                    "duplicate settings section"
                );
            }
        }
        let previous = rows.clone();
        let result = update(&mut rows)?;
        ensure!(
            rows.keys().eq(previous.keys()),
            "settings update changed selected section names"
        );
        let now = unix_ms();
        for (section, entries) in &rows {
            if previous.get(section) == Some(entries) {
                continue;
            }
            tx.execute("DELETE FROM settings WHERE section = ?1", [section])?;
            for (key, value_json) in entries {
                ensure!(!key.trim().is_empty(), "settings key must not be empty");
                tx.execute(
                    "INSERT INTO settings(section, key, value_json, updated_at_ms) VALUES (?1, ?2, ?3, ?4)",
                    params![section, key, value_json, now],
                )?;
            }
        }
        tx.commit()?;
        Ok(result)
    }

    pub fn load_kad_bootstrap_endpoints(&self) -> Result<Vec<String>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT endpoint
            FROM kad_bootstrap_endpoints
            ORDER BY position
            "#,
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn replace_kad_bootstrap_endpoints(&self, endpoints: &[String]) -> Result<()> {
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM kad_bootstrap_endpoints", [])?;
        for (position, endpoint) in endpoints.iter().enumerate() {
            ensure!(
                !endpoint.trim().is_empty(),
                "Kad bootstrap endpoint must not be empty"
            );
            tx.execute(
                r#"
                INSERT INTO kad_bootstrap_endpoints(position, endpoint, updated_at_ms)
                VALUES (?1, ?2, ?3)
                "#,
                params![i64::try_from(position)?, endpoint, now],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_categories(&self) -> Result<Vec<MetadataCategory>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT c.id,c.name,t.display_path,d.display_path,c.comment FROM categories c \
             LEFT JOIN local_paths t ON t.id=c.temp_path_id \
             LEFT JOIN local_paths d ON d.id=c.destination_path_id ORDER BY c.id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataCategory {
                id: row.get(0)?,
                name: row.get(1)?,
                temp_dir: row.get(2)?,
                destination_dir: row.get(3)?,
                comment: row.get(4)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Allocate an immutable ID and persist the category in one transaction.
    pub fn create_category(
        &self,
        name: &str,
        temp_dir: Option<&str>,
        destination_dir: Option<&str>,
        comment: &str,
        incoming: &Path,
    ) -> Result<MetadataCategory> {
        ensure!(valid_category_name(name), "invalid category name");
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let temp_id = temp_dir
            .map(|path| upsert_local_path(&tx, Path::new(path)))
            .transpose()?;
        let destination_id = destination_dir
            .map(|path| upsert_local_path(&tx, Path::new(path)))
            .transpose()?;
        tx.execute("INSERT INTO categories(name,temp_path_id,destination_path_id,comment) VALUES (?1,?2,?3,?4)", params![name, temp_id, destination_id, comment])?;
        let id = tx.last_insert_rowid();
        ensure!(id > 0, "category ID exhausted");
        if destination_id.is_some() {
            sync_category_roots(&tx, incoming)?;
        }
        tx.commit()?;
        Ok(MetadataCategory {
            id,
            name: name.to_owned(),
            temp_dir: temp_dir.map(str::to_owned),
            destination_dir: destination_dir.map(str::to_owned),
            comment: comment.to_owned(),
        })
    }

    pub fn update_category(&self, category: &MetadataCategory, incoming: &Path) -> Result<bool> {
        ensure!(
            category.id > 0 && valid_category_name(&category.name),
            "invalid category"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<Option<i64>> = tx
            .query_row(
                "SELECT destination_path_id FROM categories WHERE id=?1",
                [category.id],
                |row| row.get(0),
            )
            .optional()?;
        let temp_id = category
            .temp_dir
            .as_deref()
            .map(|path| upsert_local_path(&tx, Path::new(path)))
            .transpose()?;
        let destination_id = category
            .destination_dir
            .as_deref()
            .map(|path| upsert_local_path(&tx, Path::new(path)))
            .transpose()?;
        let changed = tx.execute(
            "UPDATE categories SET temp_path_id=?1,destination_path_id=?2,comment=?3 WHERE id=?4",
            params![temp_id, destination_id, category.comment, category.id],
        )?;
        if changed != 0 && previous.flatten() != destination_id {
            sync_category_roots(&tx, incoming)?;
        }
        tx.commit()?;
        Ok(changed != 0)
    }

    /// Clear only assignments to this category and delete it atomically.
    pub fn delete_category(&self, id: i64, incoming: &Path) -> Result<bool> {
        ensure!(id > 0, "invalid category ID");
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<Option<i64>> = tx
            .query_row(
                "SELECT destination_path_id FROM categories WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        tx.execute(
            "UPDATE download_jobs SET category_id=NULL WHERE category_id=?1",
            [id],
        )?;
        let changed = tx.execute("DELETE FROM categories WHERE id=?1", [id])?;
        if changed != 0 && previous.flatten().is_some() {
            sync_category_roots(&tx, incoming)?;
        }
        tx.commit()?;
        Ok(changed != 0)
    }

    /// Traverse one root's membership keys without collecting the affected library.
    pub fn category_root_hash_page(
        &self,
        root: &Path,
        after_known_file_id: i64,
        limit: usize,
    ) -> Result<Vec<(i64, [u8; 16])>> {
        ensure!(
            (1..=128).contains(&limit) && after_known_file_id >= 0,
            "invalid category root page"
        );
        let native = crate::NativePath::from(root);
        let conn = self.connection()?;
        let mut stmt = conn.prepare_cached(CATEGORY_ROOT_HASH_PAGE_SQL)?;
        let mut rows = stmt.query(params![
            crate::NativePath::platform(),
            native.storage_bytes(),
            after_known_file_id,
            i64::try_from(limit)?
        ])?;
        let mut page = Vec::with_capacity(limit);
        while let Some(row) = rows.next()? {
            let hash: Vec<u8> = row.get(1)?;
            let hash: [u8; 16] = hash
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid content hash"))?;
            page.push((row.get(0)?, hash));
        }
        Ok(page)
    }

    pub fn load_friends(&self) -> Result<Vec<MetadataFriend>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT lower(hex(user_hash)), name, last_address, last_port, first_seen_at_ms, last_seen_at_ms
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
                last_port: row.get::<_, u16>(3)?,
                first_seen_ms: row.get(4)?,
                last_seen_ms: row.get(5)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn upsert_friend(&self, friend: &MetadataFriend) -> Result<()> {
        self.upsert_friend_timed(friend).map(|_| ())
    }

    /// Write a friend and report connection wait and statement/commit time.
    pub fn upsert_friend_timed(&self, friend: &MetadataFriend) -> Result<FriendWriteTiming> {
        let now = unix_ms();
        let user_hash = decode_fixed_hex(&friend.user_hash, 16, "friend user hash")?;
        let waiting = std::time::Instant::now();
        let conn = self.connection()?;
        let connection_wait = waiting.elapsed();
        let execution = std::time::Instant::now();
        conn.execute(
            r#"
            INSERT INTO friends(user_hash, name, last_address, last_port, first_seen_at_ms, last_seen_at_ms, deleted_at_ms)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
            ON CONFLICT(user_hash) DO UPDATE SET
                name = excluded.name,
                last_address = excluded.last_address,
                last_port = excluded.last_port,
                last_seen_at_ms = excluded.last_seen_at_ms,
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
        Ok(FriendWriteTiming {
            connection_wait,
            execution: execution.elapsed(),
        })
    }

    /// Check one friend without materializing an unbounded collection.
    pub fn has_friend(&self, user_hash: &str) -> Result<bool> {
        let user_hash = decode_fixed_hex(user_hash, 16, "friend user hash")?;
        self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM friends WHERE user_hash = ?1 AND deleted_at_ms IS NULL)",
            [user_hash],
            |row| row.get(0),
        ).map_err(Into::into)
    }

    /// Compare one durable friend against a candidate without loading its strings.
    pub fn friend_matches(
        &self,
        user_hash: &str,
        name: &str,
        address: Option<&str>,
        port: u16,
        last_seen_ms: Option<i64>,
    ) -> Result<bool> {
        let user_hash = decode_fixed_hex(user_hash, 16, "friend user hash")?;
        self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM friends WHERE user_hash = ?1 AND deleted_at_ms IS NULL AND name = ?2 AND last_address IS ?3 AND last_port = ?4 AND last_seen_at_ms IS ?5)",
            params![user_hash, name, address, i64::from(port), last_seen_ms],
            |row| row.get(0),
        ).map_err(Into::into)
    }

    pub fn delete_friend(&self, user_hash: &str) -> Result<()> {
        self.delete_friend_timed(user_hash).map(|_| ())
    }

    /// Delete a friend and report connection wait and statement/commit time.
    pub fn delete_friend_timed(&self, user_hash: &str) -> Result<FriendWriteTiming> {
        let user_hash = decode_fixed_hex(user_hash, 16, "friend user hash")?;
        let waiting = std::time::Instant::now();
        let conn = self.connection()?;
        let connection_wait = waiting.elapsed();
        let execution = std::time::Instant::now();
        conn.execute(
            "UPDATE friends SET deleted_at_ms = ?1 WHERE user_hash = ?2",
            params![unix_ms(), user_hash],
        )?;
        Ok(FriendWriteTiming {
            connection_wait,
            execution: execution.elapsed(),
        })
    }

    pub fn load_servers(&self) -> Result<Vec<MetadataServer>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT address, port, name, description, dynamic_host, auxiliary_ports,
                   server_priority, static_server,
                   enabled, failed_count, ping_ms, users, files, max_users, low_id_users,
                   soft_files, hard_files, version,
                   obfuscation_tcp_port, obfuscation_udp_port, udp_flags, udp_key, udp_key_ip
            FROM servers
            WHERE deleted_at_ms IS NULL
            ORDER BY address, port
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MetadataServer {
                address: row.get(0)?,
                port: row.get::<_, u16>(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                dynamic_host: row.get(4)?,
                auxiliary_ports: decode_auxiliary_ports(&row.get::<_, String>(5)?),
                server_priority: row.get(6)?,
                static_server: row.get::<_, i64>(7)? != 0,
                enabled: row.get::<_, i64>(8)? != 0,
                failed_count: row.get::<_, u32>(9)?,
                ping_ms: row.get::<_, Option<u32>>(10)?,
                users: crate::sql_value::optional_unsigned::<u64>(row, 11)?.unwrap_or_default(),
                files: crate::sql_value::optional_unsigned::<u64>(row, 12)?.unwrap_or_default(),
                max_users: crate::sql_value::optional_unsigned::<u64>(row, 13)?.unwrap_or_default(),
                low_id_users: crate::sql_value::optional_unsigned::<u64>(row, 14)?
                    .unwrap_or_default(),
                soft_files: crate::sql_value::optional_unsigned::<u64>(row, 15)?
                    .unwrap_or_default(),
                hard_files: crate::sql_value::optional_unsigned::<u64>(row, 16)?
                    .unwrap_or_default(),
                version: row.get(17)?,
                obfuscation_tcp_port: row.get::<_, Option<u16>>(18)?,
                obfuscation_udp_port: row.get::<_, Option<u16>>(19)?,
                udp_flags: row.get::<_, Option<u32>>(20)?,
                udp_key: row.get::<_, Option<u32>>(21)?,
                udp_key_ip: row.get::<_, Option<u32>>(22)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn upsert_server(&self, server: &MetadataServer) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        upsert_server_in_transaction(&tx, server)?;
        Self::mark_discovery_initialized(&tx, crate::DiscoveryDomain::Servers)?;
        tx.commit()?;
        Ok(())
    }

    /// Initialize servers only if no other operation has claimed the list.
    /// Returns false when an operator or another initializer won the race.
    pub fn initialize_servers_if_pending(&self, servers: &[MetadataServer]) -> Result<bool> {
        ensure!(
            !servers.is_empty(),
            "server bootstrap list must not be empty"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status: String = tx.query_row(
            "SELECT status FROM discovery_initialization WHERE domain = 'servers'",
            [],
            |row| row.get(0),
        )?;
        match status.as_str() {
            "initialized" => return Ok(false),
            "pending" => {}
            _ => anyhow::bail!("invalid server initialization status"),
        }
        for server in servers {
            upsert_server_in_transaction(&tx, server)?;
        }
        Self::mark_discovery_initialized(&tx, crate::DiscoveryDomain::Servers)?;
        tx.commit()?;
        Ok(true)
    }
}

fn upsert_server_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    server: &MetadataServer,
) -> Result<()> {
    let now = unix_ms();
    tx.execute(
            r#"
            INSERT INTO servers(
                address, port, name, description, dynamic_host, auxiliary_ports,
                server_priority, static_server,
                enabled, failed_count, ping_ms, users, files, max_users, low_id_users,
                soft_files, hard_files,
                version, obfuscation_tcp_port, obfuscation_udp_port, udp_flags, udp_key,
                udp_key_ip, first_seen_at_ms, last_seen_at_ms, deleted_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?24, NULL)
            ON CONFLICT(address, port) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                dynamic_host = excluded.dynamic_host,
                auxiliary_ports = excluded.auxiliary_ports,
                server_priority = excluded.server_priority,
                static_server = excluded.static_server,
                enabled = excluded.enabled,
                failed_count = excluded.failed_count,
                ping_ms = excluded.ping_ms,
                users = excluded.users,
                files = excluded.files,
                max_users = excluded.max_users,
                low_id_users = excluded.low_id_users,
                soft_files = excluded.soft_files,
                hard_files = excluded.hard_files,
                version = excluded.version,
                obfuscation_tcp_port = excluded.obfuscation_tcp_port,
                obfuscation_udp_port = excluded.obfuscation_udp_port,
                udp_flags = excluded.udp_flags,
                udp_key = excluded.udp_key,
                udp_key_ip = excluded.udp_key_ip,
                last_seen_at_ms = excluded.last_seen_at_ms,
                deleted_at_ms = NULL
            "#,
            params![
                server.address,
                i64::from(server.port),
                server.name,
                server.description,
                server.dynamic_host,
                encode_auxiliary_ports(&server.auxiliary_ports),
                server.server_priority,
                bool_to_i64(server.static_server),
                bool_to_i64(server.enabled),
                i64::from(server.failed_count),
                server.ping_ms.map(i64::from),
                i64::try_from(server.users)?,
                i64::try_from(server.files)?,
                i64::try_from(server.max_users)?,
                i64::try_from(server.low_id_users)?,
                i64::try_from(server.soft_files)?,
                i64::try_from(server.hard_files)?,
                server.version,
                server.obfuscation_tcp_port.map(i64::from),
                server.obfuscation_udp_port.map(i64::from),
                server.udp_flags.map(i64::from),
                server.udp_key.map(i64::from),
                server.udp_key_ip.map(i64::from),
                now,
            ],
        )?;
    Ok(())
}

/// Rebuild implicit root origins within the category transaction, using only SQL
/// rows. A new root remains unavailable until the existing health owner verifies it.
fn sync_category_roots(tx: &rusqlite::Transaction<'_>, incoming: &Path) -> Result<()> {
    let incoming_id = upsert_local_path(tx, incoming)?;
    let now = unix_ms();
    tx.execute(
        "DELETE FROM shared_directory_root_origins WHERE origin='implicit'",
        [],
    )?;
    tx.execute("INSERT INTO shared_directory_roots(path_id,monitor_owned,shareable,accessible,enabled,created_at_ms,deleted_at_ms) SELECT path_id,0,1,0,1,?2,NULL FROM (SELECT ?1 AS path_id UNION SELECT destination_path_id FROM categories WHERE destination_path_id IS NOT NULL) WHERE true ON CONFLICT(path_id) DO NOTHING", params![incoming_id, now])?;
    tx.execute("INSERT INTO shared_directory_root_origins(root_id,origin,monitor_owned,shareable,accessible) SELECT r.id,'implicit',0,1,r.accessible FROM shared_directory_roots r WHERE r.path_id=?1 OR r.path_id IN (SELECT destination_path_id FROM categories WHERE destination_path_id IS NOT NULL)", [incoming_id])?;
    refresh_shared_root_eligibility(tx, now)?;
    Ok(())
}

impl super::MetadataStore {
    /// Refresh mandatory roots from the category rows in this same transaction.
    pub fn sync_profile_category_roots(&self, incoming: &Path) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        sync_category_roots(&tx, incoming)?;
        tx.commit()?;
        Ok(())
    }
}

/// Category and tag names share this ASCII grammar.
#[must_use]
pub fn valid_category_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

#[cfg(test)]
mod category_name_tests {
    use super::valid_category_name;

    #[test]
    fn accepts_only_the_current_ascii_category_grammar() {
        for name in ["A", "9", "Media-2026", &"a".repeat(64)] {
            assert!(valid_category_name(name), "{name:?}");
        }
        for name in [
            "",
            "-A",
            "A B",
            " A",
            "A ",
            "A_B",
            "A.B",
            "ä",
            &"a".repeat(65),
        ] {
            assert!(!valid_category_name(name), "{name:?}");
        }
    }

    #[test]
    fn schema_rejects_embedded_nul_in_category_name() {
        let store = crate::MetadataStore::in_memory().unwrap();
        let result = store.connection().unwrap().execute(
            "INSERT INTO categories(name,comment) VALUES ('Alpha' || char(0) || 'invalid','')",
            [],
        );
        assert!(result.is_err());
    }
}

fn encode_auxiliary_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn decode_auxiliary_ports(value: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for value in value.split(',') {
        if let Ok(port) = value.parse::<u16>()
            && port != 0
            && !ports.contains(&port)
        {
            ports.push(port);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_transaction_rolls_back_an_earlier_section_after_later_write_failure() {
        for fault in ["invalid-json", "empty-key", "duplicate-key"] {
            let store = super::super::MetadataStore::in_memory().unwrap();
            store.put_setting_json("alpha", "value", "1").unwrap();
            store.put_setting_json("omega", "value", "2").unwrap();
            let result = store.update_settings_sections(&["alpha", "omega"], |sections| {
                sections.insert("alpha".into(), vec![("value".into(), "3".into())]);
                let invalid = match fault {
                    "invalid-json" => vec![("value".into(), "invalid-json".into())],
                    "empty-key" => vec![(String::new(), "4".into())],
                    _ => vec![("value".into(), "4".into()), ("value".into(), "5".into())],
                };
                sections.insert("omega".into(), invalid);
                Ok(())
            });
            assert!(result.is_err(), "accepted injected {fault} failure");
            assert_eq!(
                store
                    .load_setting_json("alpha", "value")
                    .unwrap()
                    .as_deref(),
                Some("1")
            );
            assert_eq!(
                store
                    .load_setting_json("omega", "value")
                    .unwrap()
                    .as_deref(),
                Some("2")
            );
        }
    }

    #[test]
    fn candidate_rejection_and_section_escape_leave_all_rows_unchanged() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        store.put_setting_json("selected", "value", "1").unwrap();
        let rejected: Result<()> = store.update_settings_sections(&["selected"], |sections| {
            sections.insert("selected".into(), vec![("value".into(), "2".into())]);
            anyhow::bail!("candidate rejected before writes")
        });
        assert!(rejected.is_err());
        let escaped = store.update_settings_sections(&["selected"], |sections| {
            sections.insert("unselected".into(), vec![("value".into(), "3".into())]);
            Ok(())
        });
        assert!(escaped.is_err());
        assert_eq!(
            store
                .load_setting_json("selected", "value")
                .unwrap()
                .as_deref(),
            Some("1")
        );
        assert!(
            store
                .load_settings_section("unselected")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn independent_connections_serialize_settings_read_modify_write() {
        let path = unique_metadata_path("atomic-settings-connections");
        let store = super::super::MetadataStore::open(&path).unwrap();
        store.put_setting_json("counter", "value", "0").unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(5));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let store = super::super::MetadataStore::open(&path).unwrap();
            let start = std::sync::Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                start.wait();
                store
                    .update_settings_sections(&["counter"], |sections| {
                        let entries = sections.get_mut("counter").unwrap();
                        let value = entries[0].1.parse::<u32>().unwrap();
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        entries[0].1 = (value + 1).to_string();
                        Ok(())
                    })
                    .unwrap();
            }));
        }
        start.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            store
                .load_setting_json("counter", "value")
                .unwrap()
                .as_deref(),
            Some("4")
        );
    }

    #[test]
    fn profile_state_roundtrips() {
        let store = super::super::MetadataStore::in_memory().unwrap();

        store
            .put_setting_json("core", "networkEd2k", "true")
            .unwrap();
        assert_eq!(
            store.load_setting_json("core", "networkEd2k").unwrap(),
            Some("true".to_string())
        );
        assert!(store.has_settings_section("core").unwrap());
        store
            .replace_settings_section(
                "core",
                [("networkEd2k", "false"), ("downloadLimitKiBps", "2048")],
            )
            .unwrap();
        assert_eq!(
            store.load_settings_section("core").unwrap(),
            vec![
                ("downloadLimitKiBps".to_string(), "2048".to_string()),
                ("networkEd2k".to_string(), "false".to_string())
            ]
        );
        store
            .replace_kad_bootstrap_endpoints(&[
                "192.0.2.10:4672".to_string(),
                "192.0.2.11:4672".to_string(),
            ])
            .unwrap();
        assert_eq!(
            store.load_kad_bootstrap_endpoints().unwrap(),
            vec!["192.0.2.10:4672".to_string(), "192.0.2.11:4672".to_string()]
        );

        let category = store
            .create_category("Samples", None, None, "Synthetic", Path::new("incoming"))
            .unwrap();
        assert_eq!(store.load_categories().unwrap()[0], category);
        assert!(
            store
                .delete_category(category.id, Path::new("incoming"))
                .unwrap()
        );
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
    fn server_state_roundtrip() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        store
            .upsert_server(&MetadataServer {
                address: "192.0.2.10".to_string(),
                port: 4661,
                name: "Test Server".to_string(),
                description: "Synthetic".to_string(),
                dynamic_host: "server.example".to_string(),
                auxiliary_ports: vec![4662, 4663],
                server_priority: "high".to_string(),
                static_server: true,
                enabled: true,
                failed_count: 2,
                ping_ms: Some(50),
                users: 10,
                files: 20,
                max_users: 25,
                low_id_users: 5,
                soft_files: 30,
                hard_files: 40,
                version: "17.15".to_string(),
                obfuscation_tcp_port: Some(4665),
                obfuscation_udp_port: Some(4675),
                udp_flags: Some(0x331),
                udp_key: Some(0x1122_3344),
                udp_key_ip: Some(u32::from_le_bytes([198, 51, 100, 9])),
            })
            .unwrap();
        store
            .upsert_server(&MetadataServer {
                address: "192.0.2.10".to_string(),
                port: 4661,
                name: "Test Server".to_string(),
                description: "Synthetic".to_string(),
                dynamic_host: "server.example".to_string(),
                auxiliary_ports: vec![4662, 4663],
                server_priority: "high".to_string(),
                static_server: true,
                enabled: false,
                failed_count: 2,
                ping_ms: Some(50),
                users: 10,
                files: 20,
                max_users: 25,
                low_id_users: 5,
                soft_files: 30,
                hard_files: 40,
                version: "17.15".to_string(),
                obfuscation_tcp_port: Some(4665),
                obfuscation_udp_port: Some(4675),
                udp_flags: Some(0x331),
                udp_key: Some(0x1122_3344),
                udp_key_ip: Some(u32::from_le_bytes([198, 51, 100, 9])),
            })
            .unwrap();
        let servers = store.load_servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert!(!servers[0].enabled);
        assert_eq!(servers[0].name, "Test Server");
        assert_eq!(servers[0].dynamic_host, "server.example");
        assert_eq!(servers[0].auxiliary_ports, vec![4662, 4663]);
        assert_eq!(servers[0].endpoint(), "192.0.2.10:4661");
        assert_eq!(servers[0].max_users, 25);
        assert_eq!(servers[0].low_id_users, 5);
        assert_eq!(servers[0].obfuscation_tcp_port, Some(4665));
        assert_eq!(servers[0].obfuscation_udp_port, Some(4675));
        assert_eq!(servers[0].udp_flags, Some(0x331));
        assert_eq!(servers[0].udp_key, Some(0x1122_3344));
        assert_eq!(
            servers[0].udp_key_ip,
            Some(u32::from_le_bytes([198, 51, 100, 9]))
        );
    }

    #[test]
    fn server_bootstrap_rolls_back_and_respects_initialized_empty_list() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let server = MetadataServer {
            address: "192.0.2.10".into(),
            port: 4661,
            name: "Sample".into(),
            description: String::new(),
            dynamic_host: String::new(),
            auxiliary_ports: vec![],
            server_priority: "normal".into(),
            static_server: false,
            enabled: true,
            failed_count: 0,
            ping_ms: None,
            users: 0,
            files: 0,
            max_users: 0,
            low_id_users: 0,
            soft_files: 0,
            hard_files: 0,
            version: String::new(),
            obfuscation_tcp_port: None,
            obfuscation_udp_port: None,
            udp_flags: None,
            udp_key: None,
            udp_key_ip: None,
        };
        {
            let conn = store.connection().unwrap();
            conn.execute_batch("CREATE TEMP TRIGGER fail_server_status BEFORE UPDATE ON discovery_initialization BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
        }
        assert!(
            store
                .initialize_servers_if_pending(std::slice::from_ref(&server))
                .is_err()
        );
        assert!(store.load_servers().unwrap().is_empty());
        assert_eq!(
            store
                .discovery_initialization_status(crate::DiscoveryDomain::Servers)
                .unwrap(),
            crate::DiscoveryInitializationStatus::Pending
        );
        let store = super::super::MetadataStore::in_memory().unwrap();
        {
            let mut conn = store.connection().unwrap();
            let tx = conn.transaction().unwrap();
            super::super::MetadataStore::mark_discovery_initialized(
                &tx,
                crate::DiscoveryDomain::Servers,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        assert!(!store.initialize_servers_if_pending(&[server]).unwrap());
        assert!(store.load_servers().unwrap().is_empty());
    }

    #[test]
    fn categories_keep_ids_and_clear_only_deleted_assignments() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let first = store
            .create_category("First", None, None, "", Path::new("incoming"))
            .unwrap();
        let second = store
            .create_category("Media", None, None, "", Path::new("incoming"))
            .unwrap();
        let third = store
            .create_category("Third", None, None, "", Path::new("incoming"))
            .unwrap();
        assert!(
            store
                .create_category("MEDIA", None, None, "", Path::new("incoming"))
                .is_err()
        );
        store
            .upsert_transfer_manifest(&test_transfer_manifest(&store, 1, Some(second.id)))
            .unwrap();
        store
            .upsert_transfer_manifest(&test_transfer_manifest(&store, 2, Some(third.id)))
            .unwrap();
        assert!(
            store
                .delete_category(second.id, Path::new("incoming"))
                .unwrap()
        );
        assert_eq!(
            store
                .download_job_manifest(
                    store
                        .latest_download_job(&"01".repeat(16))
                        .unwrap()
                        .unwrap()
                        .token
                        .job_id
                )
                .unwrap()
                .unwrap()
                .category_id,
            None
        );
        assert_eq!(
            store
                .download_job_manifest(
                    store
                        .latest_download_job(&"02".repeat(16))
                        .unwrap()
                        .unwrap()
                        .token
                        .job_id
                )
                .unwrap()
                .unwrap()
                .category_id,
            Some(third.id)
        );
        let next = store
            .create_category("Next", None, None, "", Path::new("incoming"))
            .unwrap();
        assert!(next.id > third.id);
        assert_eq!(
            store
                .load_categories()
                .unwrap()
                .iter()
                .map(|c| c.id)
                .collect::<Vec<_>>(),
            vec![first.id, third.id, next.id]
        );
    }

    #[test]
    fn delayed_root_sync_uses_committed_category_rows() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let incoming = std::path::PathBuf::from("incoming");
        let mut category = store
            .create_category("Media", None, Some("old-root"), "", &incoming)
            .unwrap();
        let (ready, ready_rx) = std::sync::mpsc::channel();
        let (resume, resume_rx) = std::sync::mpsc::channel();
        let worker = {
            let store = store.clone();
            let incoming = incoming.clone();
            std::thread::spawn(move || {
                ready.send(()).unwrap();
                resume_rx.recv().unwrap();
                store.sync_profile_category_roots(&incoming).unwrap();
            })
        };
        ready_rx.recv().unwrap();
        category.destination_dir = Some("new-root".into());
        store.update_category(&category, &incoming).unwrap();
        resume.send(()).unwrap();
        worker.join().unwrap();
        let roots = store.implicit_shared_directory_roots().unwrap();
        assert!(roots.iter().any(|root| root.path == "new-root"));
        assert!(!roots.iter().any(|root| root.path == "old-root"));
        assert!(
            roots
                .iter()
                .find(|root| root.path == "new-root")
                .is_some_and(|root| !root.accessible)
        );
    }

    #[test]
    fn explicit_root_commit_rejects_stale_implicit_roots() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let incoming = Path::new("incoming");
        let mut category = store
            .create_category("Media", None, Some("old-root"), "", incoming)
            .unwrap();
        let expected = store.implicit_shared_directory_roots().unwrap();
        category.destination_dir = Some("new-root".into());
        store.update_category(&category, incoming).unwrap();
        let explicit = crate::MetadataSharedDirectoryRoot {
            path: "explicit".into(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        };
        assert!(
            !store
                .replace_explicit_roots_if_implicit_matches(
                    &expected,
                    std::slice::from_ref(&explicit)
                )
                .unwrap()
        );
        assert!(store.shared_directory_roots().unwrap().is_empty());
        let current = store.implicit_shared_directory_roots().unwrap();
        assert!(
            store
                .replace_explicit_roots_if_implicit_matches(
                    &current,
                    std::slice::from_ref(&explicit)
                )
                .unwrap()
        );
        assert_eq!(store.shared_directory_roots().unwrap(), vec![explicit]);
    }

    #[test]
    fn category_allocator_does_not_reuse_deleted_committed_ids_after_reopen() {
        let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
            .join("tmp/category-metadata-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("metadata.sqlite");
        let store = super::super::MetadataStore::open(&path).unwrap();
        let first = store.create_category("One", None, None, "", &root).unwrap();
        let second = store.create_category("Two", None, None, "", &root).unwrap();
        assert!(store.delete_category(second.id, &root).unwrap());
        drop(store);
        let store = super::super::MetadataStore::open(&path).unwrap();
        let third = store
            .create_category("Three", None, None, "", &root)
            .unwrap();
        assert!(third.id > second.id && second.id > first.id);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_transfer_progress_cannot_restore_deleted_category() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let category = store
            .create_category("Retired", None, None, "", Path::new("incoming"))
            .unwrap();
        let stale = test_transfer_manifest(&store, 4, Some(category.id));
        store.upsert_transfer_manifest(&stale).unwrap();
        assert!(
            store
                .delete_category(category.id, Path::new("incoming"))
                .unwrap()
        );
        let stored = store.upsert_transfer_manifest_reconciled(&stale).unwrap();
        assert_eq!(stored.category_id, None);
        assert_eq!(
            store
                .download_job_manifest(stale.token.job_id)
                .unwrap()
                .unwrap()
                .category_id,
            None
        );
    }

    #[test]
    fn category_delete_rolls_back_assignment_when_delete_fails() {
        let store = super::super::MetadataStore::in_memory().unwrap();
        let category = store
            .create_category("Keep", None, None, "", Path::new("incoming"))
            .unwrap();
        store
            .upsert_transfer_manifest(&test_transfer_manifest(&store, 3, Some(category.id)))
            .unwrap();
        {
            let conn = store.connection().unwrap();
            conn.execute_batch("CREATE TEMP TRIGGER fail_category_delete BEFORE DELETE ON categories BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        }
        assert!(
            store
                .delete_category(category.id, Path::new("incoming"))
                .is_err()
        );
        assert_eq!(store.load_categories().unwrap()[0].id, category.id);
        assert_eq!(
            store
                .download_job_manifest(
                    store
                        .latest_download_job(&"03".repeat(16))
                        .unwrap()
                        .unwrap()
                        .token
                        .job_id
                )
                .unwrap()
                .unwrap()
                .category_id,
            Some(category.id)
        );
    }

    fn test_transfer_manifest(
        store: &crate::MetadataStore,
        byte: u8,
        category_id: Option<i64>,
    ) -> crate::MetadataTransferManifest {
        crate::MetadataTransferManifest {
            token: store
                .admit_download_job(&crate::DownloadJobRequest {
                    file_hash: format!("{byte:02x}").repeat(16),
                    display_name: format!("{byte:02x}.bin"),
                    expected_size_bytes: Some(10),
                    category_id,
                    intent: crate::DownloadIntent::Stopped,
                    piece_size: 10,
                })
                .unwrap()
                .job
                .token,
            file_hash: format!("{byte:02x}").repeat(16),
            display_name: format!("{byte:02x}.bin"),
            display_name_pinned: false,
            follow_majority_filename: false,
            file_name_observations: Vec::new(),
            expected_size_bytes: Some(10),
            piece_size: 10,
            completed: false,
            final_rehash_pending: false,
            md4_hashset_acquired: false,
            md4_hashset: Vec::new(),
            aich_hashset_acquired: false,
            aich_root: None,
            aich_root_origin: None,
            aich_trust_generation: 0,
            aich_hashset: Vec::new(),
            verified_ranges: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
            category_id,
            intent: crate::DownloadIntent::Stopped,
            transfer_row_removed: false,
            delivery_state: crate::MetadataTransferDeliveryState::Pending,
            delivery_ownership: crate::MetadataTransferDeliveryOwnership::None,
            delivered_path: None,
            source_fingerprint: None,
            payload_fingerprint: None,
            pieces: Vec::new(),
            sources: Vec::new(),
        }
    }

    fn unique_metadata_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "emulebb-metadata-{name}-{}.sqlite",
            uuid::Uuid::new_v4()
        ))
    }
}
