CREATE TABLE metadata_schema (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    schema_id TEXT NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
) STRICT;

CREATE TABLE profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    uuid TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
) STRICT;

CREATE TABLE local_identities (
    id INTEGER PRIMARY KEY,
    identity_kind TEXT NOT NULL UNIQUE CHECK(identity_kind IN ('ed2k-user-hash', 'ed2k-secure-ident')),
    public_identity BLOB,
    private_secret BLOB,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK (
        (identity_kind = 'ed2k-user-hash' AND public_identity IS NOT NULL AND length(public_identity) = 16 AND private_secret IS NULL)
        OR (identity_kind = 'ed2k-secure-ident' AND public_identity IS NULL AND private_secret IS NOT NULL AND length(private_secret) > 0)
    )
) STRICT;

CREATE TABLE settings (
    section TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    PRIMARY KEY(section, key),
    CHECK(length(trim(section)) > 0),
    CHECK(length(trim(key)) > 0),
    CHECK(json_valid(value_json))
) STRICT, WITHOUT ROWID;

CREATE TABLE categories (
    id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 4294967295),
    name TEXT NOT NULL,
    path_id INTEGER REFERENCES local_paths(id),
    comment TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0 CHECK(sort_order BETWEEN 0 AND 4294967295),
    color INTEGER CHECK(color IS NULL OR color BETWEEN 0 AND 4294967295),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0)
) STRICT;

CREATE TABLE friends (
    id INTEGER PRIMARY KEY,
    user_hash BLOB NOT NULL UNIQUE CHECK(length(user_hash) = 16),
    name TEXT NOT NULL,
    last_address TEXT,
    last_port INTEGER NOT NULL DEFAULT 0 CHECK(last_port BETWEEN 0 AND 65535),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER CHECK(last_seen_at_ms IS NULL OR last_seen_at_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0)
) STRICT;

CREATE TABLE known_files (
    id INTEGER PRIMARY KEY,
    ed2k_hash BLOB NOT NULL UNIQUE CHECK(length(ed2k_hash) = 16),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    display_name TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    media_artist TEXT NOT NULL DEFAULT '',
    media_album TEXT NOT NULL DEFAULT '',
    media_title TEXT NOT NULL DEFAULT '',
    media_length_seconds INTEGER NOT NULL DEFAULT 0 CHECK(media_length_seconds BETWEEN 0 AND 4294967295),
    media_bitrate_kbps INTEGER NOT NULL DEFAULT 0 CHECK(media_bitrate_kbps BETWEEN 0 AND 4294967295),
    media_codec TEXT NOT NULL DEFAULT '',
    media_extractor_version INTEGER NOT NULL DEFAULT 0 CHECK(media_extractor_version BETWEEN 0 AND 4294967295),
    availability_score INTEGER NOT NULL DEFAULT 0 CHECK(availability_score >= 0),
    -- Lifetime bytes we have uploaded to other peers for this file (eMule
    -- CStatisticFile all-time transferred), used to derive the all-time upload
    -- ratio that feeds the upload-queue low-ratio score bonus.
    all_time_uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(all_time_uploaded_bytes >= 0),
    all_time_upload_requests INTEGER NOT NULL DEFAULT 0 CHECK(all_time_upload_requests >= 0),
    all_time_upload_accepts INTEGER NOT NULL DEFAULT 0 CHECK(all_time_upload_accepts >= 0),
    last_upload_requested_at_ms INTEGER NOT NULL DEFAULT 0 CHECK(last_upload_requested_at_ms >= 0),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
) STRICT;

CREATE TABLE known_file_origins (
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    origin TEXT NOT NULL CHECK(origin IN ('local_share', 'transfer', 'passive_cache')),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    content_type TEXT NOT NULL DEFAULT '',
    availability_score INTEGER NOT NULL DEFAULT 0 CHECK(availability_score >= 0),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    PRIMARY KEY(known_file_id, origin)
) STRICT, WITHOUT ROWID;

CREATE INDEX known_file_origins_origin_idx
    ON known_file_origins(origin, availability_score DESC, last_seen_at_ms DESC);

-- Durable content identity for successful downloads. This intentionally has
-- no foreign key to current known-file, transfer, share, or path rows: cleanup,
-- moving, or deleting a payload must not erase the fact it completed, and a
-- historical record must never imply that an obsolete path is still live.
CREATE TABLE download_history (
    ed2k_hash BLOB NOT NULL PRIMARY KEY CHECK(length(ed2k_hash) = 16),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    display_name TEXT NOT NULL,
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    first_completed_at_ms INTEGER NOT NULL CHECK(first_completed_at_ms >= 0),
    last_completed_at_ms INTEGER NOT NULL CHECK(last_completed_at_ms >= first_completed_at_ms)
) STRICT;

CREATE TABLE file_names (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1 CHECK(seen_count >= 1),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    UNIQUE(known_file_id, normalized_name)
) STRICT;

CREATE TABLE file_name_origins (
    file_name_id INTEGER NOT NULL REFERENCES file_names(id) ON DELETE CASCADE,
    origin TEXT NOT NULL CHECK(origin IN ('local_share', 'transfer', 'passive_cache')),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    PRIMARY KEY(file_name_id, origin)
) STRICT, WITHOUT ROWID;

CREATE INDEX file_name_origins_origin_idx
    ON file_name_origins(origin, last_seen_at_ms DESC);

CREATE VIRTUAL TABLE file_name_fts USING fts5(
    name,
    normalized_name,
    content='file_names',
    content_rowid='id',
    tokenize = 'unicode61 remove_diacritics 2 tokenchars ''.-_'''
);

CREATE TRIGGER file_names_ai AFTER INSERT ON file_names BEGIN
    INSERT INTO file_name_fts(rowid, name, normalized_name)
    VALUES (new.id, new.name, new.normalized_name);
END;

CREATE TRIGGER file_names_ad AFTER DELETE ON file_names BEGIN
    INSERT INTO file_name_fts(file_name_fts, rowid, name, normalized_name)
    VALUES('delete', old.id, old.name, old.normalized_name);
END;

CREATE TRIGGER file_names_au AFTER UPDATE OF name, normalized_name ON file_names
WHEN old.name IS NOT new.name OR old.normalized_name IS NOT new.normalized_name BEGIN
    INSERT INTO file_name_fts(file_name_fts, rowid, name, normalized_name)
    VALUES('delete', old.id, old.name, old.normalized_name);
    INSERT INTO file_name_fts(rowid, name, normalized_name)
    VALUES (new.id, new.name, new.normalized_name);
END;

CREATE TABLE transfer_md4_part_hashes (
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 4294967295),
    md4_hash BLOB NOT NULL CHECK(length(md4_hash) = 16),
    PRIMARY KEY(transfer_id, part_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE transfer_aich_part_hashes (
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 4294967295),
    aich_hash BLOB NOT NULL CHECK(length(aich_hash) = 20),
    PRIMARY KEY(transfer_id, part_index)
) STRICT, WITHOUT ROWID;

-- Verified complete content is independent of a download for the same hash.
-- A new download must not erase the local file's hashsets or presentation.
CREATE TABLE verified_local_content (
    known_file_id INTEGER PRIMARY KEY REFERENCES known_files(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    part_size_bytes INTEGER NOT NULL CHECK(part_size_bytes > 0),
    part_count INTEGER NOT NULL CHECK(part_count BETWEEN 0 AND 4294967295),
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    upload_priority TEXT NOT NULL DEFAULT 'normal'
        CHECK(upload_priority IN ('auto', 'not-published', 'verylow', 'low', 'normal', 'high', 'release')),
    auto_upload_priority INTEGER NOT NULL DEFAULT 0 CHECK(auto_upload_priority IN (0, 1)),
    comment TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5)
) STRICT;

CREATE TABLE verified_local_md4_hashes (
    known_file_id INTEGER NOT NULL REFERENCES verified_local_content(known_file_id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 4294967295),
    md4_hash BLOB NOT NULL CHECK(length(md4_hash) = 16),
    PRIMARY KEY(known_file_id, part_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE aich_recovery_sets (
    root BLOB NOT NULL CHECK(length(root) = 20),
    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0 AND size_bytes <= 274877906944),
    PRIMARY KEY(root, size_bytes)
) STRICT, WITHOUT ROWID;

CREATE INDEX verified_local_aich_root_idx ON verified_local_content(aich_root);

CREATE TABLE aich_recovery_parts (
    root BLOB NOT NULL,
    size_bytes INTEGER NOT NULL,
    part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 4294967295),
    part_root BLOB NOT NULL CHECK(length(part_root) = 20),
    leaves BLOB NOT NULL CHECK(length(leaves) > 0 AND length(leaves) <= 1060 AND length(leaves) % 20 = 0),
    PRIMARY KEY(root, size_bytes, part_index),
    FOREIGN KEY(root, size_bytes) REFERENCES aich_recovery_sets(root, size_bytes) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE TABLE verified_local_aich_hashes (
    known_file_id INTEGER NOT NULL REFERENCES verified_local_content(known_file_id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 4294967295),
    aich_hash BLOB NOT NULL CHECK(length(aich_hash) = 20),
    PRIMARY KEY(known_file_id, part_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE verified_ranges (
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    start_offset INTEGER NOT NULL CHECK(start_offset >= 0),
    end_offset INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    CHECK(end_offset >= start_offset),
    PRIMARY KEY(transfer_id, start_offset, end_offset)
) STRICT, WITHOUT ROWID;

CREATE TABLE local_paths (
    id INTEGER PRIMARY KEY,
    display_path TEXT NOT NULL,
    native_path BLOB NOT NULL,
    search_key TEXT NOT NULL,
    sort_key TEXT NOT NULL,
    file_name_search_key TEXT NOT NULL,
    platform TEXT NOT NULL CHECK(platform IN ('windows', 'unix', 'macos')),
    CHECK(length(native_path) > 0 AND (platform != 'windows' OR length(native_path) % 2 = 0)),
    UNIQUE(platform, native_path)
) STRICT;

CREATE INDEX local_paths_search_idx ON local_paths(platform, search_key);

-- Durable, verified path-to-content cache. Presence in this table does not
-- authorize serving: current root membership and a live fingerprint match do.
CREATE TABLE local_file_instances (
    path_id INTEGER PRIMARY KEY REFERENCES local_paths(id),
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    native_identity BLOB NOT NULL CHECK(length(native_identity) > 0),
    verified_fingerprint BLOB NOT NULL CHECK(length(verified_fingerprint) > 0),
    verified_at_ms INTEGER NOT NULL CHECK(verified_at_ms >= 0)
) STRICT;

CREATE INDEX local_file_instances_content_idx
    ON local_file_instances(known_file_id);

CREATE INDEX local_file_instances_identity_idx
    ON local_file_instances(native_identity, size_bytes);

CREATE TABLE shared_directory_roots (
    id INTEGER PRIMARY KEY,
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    monitor_owned INTEGER NOT NULL DEFAULT 0 CHECK(monitor_owned IN (0, 1)),
    shareable INTEGER NOT NULL DEFAULT 1 CHECK(shareable IN (0, 1)),
    accessible INTEGER NOT NULL DEFAULT 1 CHECK(accessible IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_scanned_at_ms INTEGER CHECK(last_scanned_at_ms IS NULL OR last_scanned_at_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0),
    UNIQUE(path_id)
) STRICT;

-- A physical directory can be both user-selected and a mandatory Incoming or
-- category root. Replacing explicit roots must not withdraw implicit membership.
CREATE TABLE shared_directory_root_origins (
    root_id INTEGER NOT NULL REFERENCES shared_directory_roots(id) ON DELETE CASCADE,
    origin TEXT NOT NULL CHECK(origin IN ('explicit', 'implicit')),
    monitor_owned INTEGER NOT NULL CHECK(monitor_owned IN (0, 1)),
    shareable INTEGER NOT NULL CHECK(shareable IN (0, 1)),
    accessible INTEGER NOT NULL CHECK(accessible IN (0, 1)),
    PRIMARY KEY(root_id, origin)
) STRICT, WITHOUT ROWID;

CREATE TABLE shared_file_ignore_patterns (
    pattern TEXT NOT NULL PRIMARY KEY CHECK(length(pattern) BETWEEN 1 AND 255),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
) STRICT;

CREATE TABLE shared_default_ignore_overrides (
    rule_key TEXT NOT NULL PRIMARY KEY,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK(length(trim(rule_key)) > 0)
) STRICT;

CREATE TABLE shared_file_memberships (
    root_id INTEGER NOT NULL REFERENCES shared_directory_roots(id),
    path_id INTEGER NOT NULL REFERENCES local_file_instances(path_id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    removed_at_ms INTEGER CHECK(removed_at_ms IS NULL OR removed_at_ms >= 0),
    PRIMARY KEY(root_id, path_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE transfers (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    part_size_bytes INTEGER NOT NULL CHECK(part_size_bytes > 0),
    part_count INTEGER NOT NULL CHECK(part_count BETWEEN 0 AND 4294967295),
    upload_priority TEXT NOT NULL DEFAULT 'normal'
        CHECK(upload_priority IN ('auto', 'not-published', 'verylow', 'low', 'normal', 'high', 'release')),
    auto_upload_priority INTEGER NOT NULL DEFAULT 0 CHECK(auto_upload_priority IN (0, 1)),
    comment TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5),
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
    md4_hashset_acquired INTEGER NOT NULL DEFAULT 0 CHECK(md4_hashset_acquired IN (0, 1)),
    aich_hashset_acquired INTEGER NOT NULL DEFAULT 0 CHECK(aich_hashset_acquired IN (0, 1)),
    visible_state TEXT NOT NULL CHECK(visible_state IN ('completed', 'completing', 'downloading', 'queued')),
    -- Set after all parts verify and cleared only after the authoritative
    -- whole-file ED2K MD4 completion rehash succeeds or demotes bad parts.
    final_rehash_pending INTEGER NOT NULL DEFAULT 0
        CHECK(final_rehash_pending IN (0, 1)),
    control_state TEXT CHECK(control_state IS NULL OR control_state IN ('paused', 'stopped')),
    category_id INTEGER REFERENCES categories(id),
    -- Downloads remain pending until a verified output path is committed.
    delivery_state TEXT NOT NULL
        CHECK(delivery_state IN ('pending', 'delivered')),
    delivery_ownership TEXT NOT NULL DEFAULT 'none'
        CHECK(delivery_ownership IN ('none', 'owned', 'unowned')),
    -- Absolute path identity for the completed payload materialized under a
    -- category path or the global incoming dir. NULL until delivery completes.
    delivered_path_id INTEGER REFERENCES local_paths(id),
    -- Versioned identity of the delivered file. NULL until delivery.
    source_fingerprint BLOB,
    -- Versioned identity baseline for the canonical internal pieces.bin after
    -- successful whole-file verification. NULL forces a startup ED2K rehash.
    payload_fingerprint BLOB,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    completed_at_ms INTEGER CHECK(completed_at_ms IS NULL OR completed_at_ms >= 0),
    removed_at_ms INTEGER CHECK(removed_at_ms IS NULL OR removed_at_ms >= 0),
    -- Terminal destructive-delete intent. Once set, active selectors suppress
    -- the transfer until cleanup removes the row; ordinary manifest upserts
    -- deliberately preserve the marker.
    delete_requested_at_ms INTEGER
        CHECK(delete_requested_at_ms IS NULL OR delete_requested_at_ms >= 0),
    -- Stable identity of the owned transfer directory captured before it is
    -- renamed to the deletion tombstone. Recovery must never recursively
    -- delete a path whose identity differs from this durable authority.
    transfer_directory_tombstone_identity BLOB,
    -- Random marker created inside the owned directory before deletion intent
    -- commits. Native identities can be reused after deletion, so recovery
    -- requires both this marker and the native identity.
    transfer_directory_tombstone_marker_id TEXT,
    CHECK(
        (transfer_directory_tombstone_identity IS NULL AND transfer_directory_tombstone_marker_id IS NULL)
        OR (
            transfer_directory_tombstone_identity IS NOT NULL
            AND transfer_directory_tombstone_marker_id IS NOT NULL
            AND length(trim(transfer_directory_tombstone_marker_id)) > 0
            AND delete_requested_at_ms IS NOT NULL
        )
    ),
    CHECK(
        (delivery_state = 'pending' AND delivery_ownership = 'none' AND delivered_path_id IS NULL)
        OR (delivery_state = 'delivered' AND delivery_ownership = 'owned' AND delivered_path_id IS NOT NULL AND source_fingerprint IS NOT NULL)
        OR (delivery_state = 'delivered' AND delivery_ownership = 'unowned' AND delivered_path_id IS NOT NULL)
    ),
    CHECK((completed = 1) = (visible_state = 'completed')),
    CHECK(payload_fingerprint IS NULL OR (completed = 1 AND final_rehash_pending = 0)),
    UNIQUE(known_file_id)
) STRICT;

-- A delivered download is hidden while its owned piece directory is safely
-- reclaimed. The output has already become independent verified local content.
CREATE TABLE transfer_retirements (
    transfer_id INTEGER PRIMARY KEY REFERENCES transfers(id) ON DELETE CASCADE,
    directory_identity BLOB,
    directory_marker_id TEXT,
    CHECK (
        (directory_identity IS NULL AND directory_marker_id IS NULL)
        OR (directory_identity IS NOT NULL AND directory_marker_id IS NOT NULL
            AND length(trim(directory_marker_id)) > 0)
    )
) STRICT;

CREATE TABLE delivery_attempts (
    transfer_id INTEGER PRIMARY KEY REFERENCES transfers(id) ON DELETE CASCADE,
    attempt_id TEXT NOT NULL UNIQUE CHECK(length(trim(attempt_id)) > 0),
    phase TEXT NOT NULL CHECK(phase IN ('prepared', 'staged', 'published')),
    target_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    staging_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    staging_fingerprint BLOB,
    published_fingerprint BLOB,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK(target_path_id != staging_path_id),
    CHECK(
        (phase = 'prepared' AND staging_fingerprint IS NULL AND published_fingerprint IS NULL)
        OR (phase = 'staged' AND staging_fingerprint IS NOT NULL AND published_fingerprint IS NULL)
        OR (phase = 'published' AND staging_fingerprint IS NOT NULL AND published_fingerprint IS NOT NULL)
    )
) STRICT;

CREATE INDEX delivery_attempts_phase_idx ON delivery_attempts(phase, transfer_id);

CREATE TABLE delivery_output_tombstones (
    transfer_id INTEGER PRIMARY KEY REFERENCES transfers(id) ON DELETE CASCADE,
    tombstone_id TEXT NOT NULL UNIQUE CHECK(length(trim(tombstone_id)) > 0),
    phase TEXT NOT NULL CHECK(phase IN ('prepared', 'moved')),
    original_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    tombstone_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    source_fingerprint BLOB NOT NULL,
    moved_fingerprint BLOB,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK(original_path_id != tombstone_path_id),
    CHECK(
        (phase = 'prepared' AND moved_fingerprint IS NULL)
        OR (phase = 'moved' AND moved_fingerprint IS NOT NULL)
    )
) STRICT;

CREATE INDEX delivery_output_tombstones_phase_idx
ON delivery_output_tombstones(phase, transfer_id);

CREATE TRIGGER clear_delivery_attempt_after_delivered
AFTER UPDATE OF delivery_state ON transfers
WHEN NEW.delivery_state = 'delivered'
BEGIN
    DELETE FROM delivery_attempts WHERE transfer_id = NEW.id;
END;

CREATE TABLE shared_file_scan_failures (
    id INTEGER PRIMARY KEY,
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    source_fingerprint BLOB,
    reason TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    UNIQUE(path_id)
) STRICT;

CREATE TABLE transfer_pieces (
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    piece_index INTEGER NOT NULL CHECK(piece_index BETWEEN 0 AND 4294967295),
    state TEXT NOT NULL CHECK(state IN ('Missing', 'Verified')),
    bytes_written INTEGER NOT NULL DEFAULT 0 CHECK(bytes_written >= 0),
    block_bitmap TEXT,
    ich_corrupted INTEGER NOT NULL DEFAULT 0 CHECK(ich_corrupted IN (0, 1)),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    PRIMARY KEY(transfer_id, piece_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE servers (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL CHECK(length(trim(address)) > 0),
    port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    dynamic_host TEXT NOT NULL DEFAULT '',
    auxiliary_ports TEXT NOT NULL DEFAULT '',
    server_priority TEXT NOT NULL DEFAULT 'normal' CHECK(server_priority IN ('low', 'normal', 'high')),
    static_server INTEGER NOT NULL DEFAULT 0 CHECK(static_server IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    failed_count INTEGER NOT NULL DEFAULT 0 CHECK(failed_count BETWEEN 0 AND 4294967295),
    ping_ms INTEGER CHECK(ping_ms IS NULL OR ping_ms BETWEEN 0 AND 4294967295),
    users INTEGER CHECK(users IS NULL OR users >= 0),
    files INTEGER CHECK(files IS NULL OR files >= 0),
    max_users INTEGER CHECK(max_users IS NULL OR max_users >= 0),
    low_id_users INTEGER CHECK(low_id_users IS NULL OR low_id_users >= 0),
    soft_files INTEGER CHECK(soft_files IS NULL OR soft_files >= 0),
    hard_files INTEGER CHECK(hard_files IS NULL OR hard_files >= 0),
    version TEXT NOT NULL DEFAULT '',
    obfuscation_tcp_port INTEGER CHECK(obfuscation_tcp_port IS NULL OR obfuscation_tcp_port BETWEEN 1 AND 65535),
    obfuscation_udp_port INTEGER CHECK(obfuscation_udp_port IS NULL OR obfuscation_udp_port BETWEEN 1 AND 65535),
    udp_flags INTEGER CHECK(udp_flags IS NULL OR udp_flags >= 0),
    udp_key INTEGER CHECK(udp_key IS NULL OR udp_key BETWEEN 1 AND 4294967295),
    udp_key_ip INTEGER CHECK(udp_key_ip IS NULL OR udp_key_ip BETWEEN 1 AND 4294967295),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0),
    UNIQUE(address, port)
) STRICT;

CREATE TABLE peers (
    id INTEGER PRIMARY KEY,
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    client_id TEXT,
    user_name TEXT NOT NULL DEFAULT '',
    client_software TEXT NOT NULL DEFAULT '',
    client_mod TEXT NOT NULL DEFAULT '',
    last_address TEXT,
    last_tcp_port INTEGER CHECK(last_tcp_port IS NULL OR last_tcp_port BETWEEN 1 AND 65535),
    last_udp_port INTEGER CHECK(last_udp_port IS NULL OR last_udp_port BETWEEN 1 AND 65535),
    low_id INTEGER NOT NULL DEFAULT 0 CHECK(low_id IN (0, 1)),
    secure_ident_state TEXT NOT NULL DEFAULT '',
    -- Verified secure-identification public key bound to this peer on the first
    -- successful secure-ident verify (eMule CClientCredits abySecureIdent[80] +
    -- nKeySize, persisted in clients.met). A later verify with a DIFFERENT key
    -- for the same user hash wipes this peer's credits (anti-takeover,
    -- ClientCredits.cpp:338-356 CClientCredits::Verified).
    secure_ident_pubkey BLOB,
    secure_ident_pubkey_len INTEGER NOT NULL DEFAULT 0 CHECK(secure_ident_pubkey_len BETWEEN 0 AND 80),
    friend INTEGER NOT NULL DEFAULT 0 CHECK(friend IN (0, 1)),
    banned INTEGER NOT NULL DEFAULT 0 CHECK(banned IN (0, 1)),
    uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(uploaded_bytes >= 0),
    downloaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(downloaded_bytes >= 0),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    CHECK((secure_ident_pubkey IS NULL AND secure_ident_pubkey_len = 0)
          OR (secure_ident_pubkey IS NOT NULL AND length(secure_ident_pubkey) = secure_ident_pubkey_len
              AND secure_ident_pubkey_len BETWEEN 1 AND 80)),
    UNIQUE(user_hash)
) STRICT;

CREATE TABLE transfer_sources (
    id INTEGER PRIMARY KEY,
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    tcp_port INTEGER NOT NULL CHECK(tcp_port BETWEEN 1 AND 65535),
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    connect_options INTEGER CHECK(connect_options IS NULL OR connect_options BETWEEN 0 AND 255),
    file_comment TEXT NOT NULL DEFAULT '',
    file_rating INTEGER NOT NULL DEFAULT 0 CHECK(file_rating BETWEEN 0 AND 255),
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    last_outcome TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE UNIQUE INDEX transfer_sources_identity_idx
ON transfer_sources(transfer_id, ip, tcp_port);

CREATE TABLE transfer_name_state (
    transfer_id INTEGER PRIMARY KEY REFERENCES transfers(id) ON DELETE CASCADE,
    display_name_pinned INTEGER NOT NULL DEFAULT 0
        CHECK(display_name_pinned IN (0, 1)),
    follow_majority_filename INTEGER NOT NULL DEFAULT 0
        CHECK(follow_majority_filename IN (0, 1))
) STRICT;

CREATE TABLE transfer_file_name_observations (
    id INTEGER PRIMARY KEY,
    position INTEGER NOT NULL CHECK(position >= 0),
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    source_ip TEXT,
    source_tcp_port INTEGER CHECK(source_tcp_port IS NULL OR source_tcp_port BETWEEN 1 AND 65535),
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    client_software TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL,
    server_endpoint TEXT,
    raw_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    CHECK((source_ip IS NULL) = (source_tcp_port IS NULL)),
    CHECK(length(trim(raw_name)) > 0),
    CHECK(length(trim(normalized_name)) > 0),
    UNIQUE(transfer_id, position)
) STRICT;

CREATE INDEX transfer_file_name_observations_transfer_idx
ON transfer_file_name_observations(transfer_id, observed_at_ms, id);

CREATE TABLE kad_bootstrap_endpoints (
    position INTEGER PRIMARY KEY,
    endpoint TEXT NOT NULL UNIQUE,
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK(position >= 0),
    CHECK(length(trim(endpoint)) > 0)
) STRICT;

CREATE TABLE kad_keyword_publishes (
    id INTEGER PRIMARY KEY,
    size_bytes BLOB NOT NULL CHECK(length(size_bytes) = 8),
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    ed2k_hash BLOB NOT NULL CHECK(length(ed2k_hash) = 16),
    known_file_id INTEGER REFERENCES known_files(id) ON DELETE SET NULL,
    raw_tags BLOB NOT NULL,
    load INTEGER CHECK(load IS NULL OR load BETWEEN 0 AND 255),
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    UNIQUE(target_node_id, ed2k_hash, size_bytes)
) STRICT;

CREATE TABLE kad_source_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 16),
    ed2k_hash BLOB NOT NULL CHECK(length(ed2k_hash) = 16),
    source_ip TEXT NOT NULL,
    source_tcp_port INTEGER NOT NULL CHECK(source_tcp_port BETWEEN 0 AND 65535),
    source_udp_port INTEGER NOT NULL CHECK(source_udp_port BETWEEN 0 AND 65535),
    raw_tags BLOB NOT NULL,
    load INTEGER CHECK(load IS NULL OR load BETWEEN 0 AND 255),
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    UNIQUE(target_node_id, source_ip, source_tcp_port, source_udp_port)
) STRICT;

CREATE TABLE kad_note_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 16),
    publisher_ip TEXT NOT NULL,
    ed2k_hash BLOB CHECK(ed2k_hash IS NULL OR length(ed2k_hash) = 16),
    raw_tags BLOB NOT NULL,
    load INTEGER CHECK(load IS NULL OR load BETWEEN 0 AND 255),
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    UNIQUE(target_node_id, publisher_id, publisher_ip)
) STRICT;

CREATE TABLE kad_outbound_publish_schedule (
    ed2k_hash BLOB NOT NULL CHECK(length(ed2k_hash) = 16),
    publish_kind TEXT NOT NULL CHECK(publish_kind IN ('keyword', 'source', 'notes')),
    keyword TEXT NOT NULL DEFAULT '',
    published_at_ms INTEGER NOT NULL CHECK(published_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    PRIMARY KEY(ed2k_hash, publish_kind, keyword)
) STRICT, WITHOUT ROWID;

CREATE TABLE search_sessions (
    id INTEGER PRIMARY KEY,
    public_id TEXT NOT NULL UNIQUE,
    query TEXT NOT NULL,
    normalized_query TEXT NOT NULL,
    requested_method TEXT NOT NULL CHECK(requested_method IN ('automatic', 'server', 'global', 'kad')),
    resolved_method TEXT CHECK(resolved_method IS NULL OR resolved_method IN ('server', 'global', 'kad')),
    file_type_filter TEXT NOT NULL DEFAULT '',
    extension_filter TEXT NOT NULL DEFAULT '',
    min_size_bytes BLOB CHECK(min_size_bytes IS NULL OR length(min_size_bytes) = 8),
    max_size_bytes BLOB CHECK(max_size_bytes IS NULL OR length(max_size_bytes) = 8),
    min_availability INTEGER CHECK(min_availability IS NULL OR min_availability BETWEEN 0 AND 4294967295),
    min_complete_sources INTEGER CHECK(min_complete_sources IS NULL OR min_complete_sources BETWEEN 0 AND 4294967295),
    min_bitrate_kbps INTEGER CHECK(min_bitrate_kbps IS NULL OR min_bitrate_kbps BETWEEN 0 AND 4294967295),
    min_length_seconds INTEGER CHECK(min_length_seconds IS NULL OR min_length_seconds BETWEEN 0 AND 4294967295),
    codec_filter TEXT NOT NULL DEFAULT '',
    title_filter TEXT NOT NULL DEFAULT '',
    album_filter TEXT NOT NULL DEFAULT '',
    artist_filter TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'completed', 'error')),
    status_reason TEXT CHECK(status_reason IS NULL OR length(status_reason) > 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    completed_at_ms INTEGER CHECK(completed_at_ms IS NULL OR completed_at_ms >= 0),
    CHECK(min_size_bytes IS NULL OR max_size_bytes IS NULL OR min_size_bytes <= max_size_bytes)
) STRICT;

CREATE TABLE search_results (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES search_sessions(id) ON DELETE CASCADE,
    known_file_id INTEGER REFERENCES known_files(id) ON DELETE SET NULL,
    ed2k_hash BLOB NOT NULL CHECK(length(ed2k_hash) = 16),
    name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    source_count INTEGER NOT NULL DEFAULT 0 CHECK(source_count BETWEEN 0 AND 4294967295),
    complete_source_count INTEGER NOT NULL DEFAULT 0 CHECK(complete_source_count BETWEEN 0 AND 4294967295),
    file_type TEXT NOT NULL DEFAULT '',
    media_artist TEXT NOT NULL DEFAULT '',
    media_album TEXT NOT NULL DEFAULT '',
    media_title TEXT NOT NULL DEFAULT '',
    media_length_seconds INTEGER NOT NULL DEFAULT 0 CHECK(media_length_seconds BETWEEN 0 AND 4294967295),
    media_bitrate_kbps INTEGER NOT NULL DEFAULT 0 CHECK(media_bitrate_kbps BETWEEN 0 AND 4294967295),
    media_codec TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5),
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
    directory TEXT NOT NULL DEFAULT '',
    UNIQUE(session_id, ed2k_hash)
) STRICT;

CREATE TABLE search_result_observations (
    id INTEGER PRIMARY KEY,
    result_id INTEGER NOT NULL REFERENCES search_results(id) ON DELETE CASCADE,
    origin TEXT NOT NULL,
    server_endpoint TEXT,
    name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    source_count INTEGER NOT NULL DEFAULT 0 CHECK(source_count BETWEEN 0 AND 4294967295),
    complete_source_count INTEGER NOT NULL DEFAULT 0 CHECK(complete_source_count BETWEEN 0 AND 4294967295),
    source_client_id INTEGER CHECK(source_client_id IS NULL OR source_client_id BETWEEN 0 AND 4294967295),
    source_client_port INTEGER CHECK(source_client_port IS NULL OR source_client_port BETWEEN 1 AND 65535),
    file_type TEXT NOT NULL DEFAULT '',
    media_artist TEXT NOT NULL DEFAULT '',
    media_album TEXT NOT NULL DEFAULT '',
    media_title TEXT NOT NULL DEFAULT '',
    media_length_seconds INTEGER NOT NULL DEFAULT 0 CHECK(media_length_seconds BETWEEN 0 AND 4294967295),
    media_bitrate_kbps INTEGER NOT NULL DEFAULT 0 CHECK(media_bitrate_kbps BETWEEN 0 AND 4294967295),
    media_codec TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5),
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
    directory TEXT NOT NULL DEFAULT '',
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    CHECK((source_client_id IS NULL) = (source_client_port IS NULL))
) STRICT;

CREATE INDEX file_names_normalized_idx ON file_names(normalized_name);
CREATE INDEX shared_file_memberships_path_idx ON shared_file_memberships(path_id);
CREATE INDEX transfers_pending_delete_idx
ON transfers(delete_requested_at_ms)
WHERE delete_requested_at_ms IS NOT NULL;
CREATE INDEX kad_keyword_target_idx ON kad_keyword_publishes(target_node_id, observed_at_ms);
CREATE INDEX kad_source_file_idx ON kad_source_publishes(ed2k_hash, observed_at_ms);
CREATE INDEX kad_note_file_idx ON kad_note_publishes(ed2k_hash, observed_at_ms);
CREATE INDEX search_results_session_idx ON search_results(session_id, id);
CREATE INDEX search_result_observations_result_idx
ON search_result_observations(result_id, observed_at_ms, id);
CREATE INDEX categories_path_id_idx ON categories(path_id);
CREATE INDEX transfers_category_id_idx ON transfers(category_id);
CREATE INDEX transfers_delivered_path_id_idx ON transfers(delivered_path_id);
CREATE INDEX delivery_attempts_target_path_id_idx ON delivery_attempts(target_path_id);
CREATE INDEX delivery_attempts_staging_path_id_idx ON delivery_attempts(staging_path_id);
CREATE INDEX delivery_output_tombstones_original_path_id_idx ON delivery_output_tombstones(original_path_id);
CREATE INDEX delivery_output_tombstones_tombstone_path_id_idx ON delivery_output_tombstones(tombstone_path_id);
CREATE INDEX kad_keyword_publishes_known_file_id_idx ON kad_keyword_publishes(known_file_id);
CREATE INDEX search_results_known_file_id_idx ON search_results(known_file_id);

-- A cheap durable invalidation clock shared by every connection. It contains no
-- parallel client state: session catalog projections are disposable derivatives.
CREATE TABLE library_catalog_revision (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    revision INTEGER NOT NULL CHECK(revision >= 0)
) STRICT;
INSERT INTO library_catalog_revision VALUES(1, 0);

CREATE TRIGGER library_catalog_local_file_instances_insert
AFTER INSERT ON local_file_instances
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_local_file_instances_delete
AFTER DELETE ON local_file_instances
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_local_file_instances_update
AFTER UPDATE OF known_file_id, verified_fingerprint ON local_file_instances
WHEN old.known_file_id IS NOT new.known_file_id OR old.verified_fingerprint IS NOT new.verified_fingerprint
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_shared_file_memberships_insert
AFTER INSERT ON shared_file_memberships
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_shared_file_memberships_delete
AFTER DELETE ON shared_file_memberships
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_shared_file_memberships_update
AFTER UPDATE OF root_id, path_id, removed_at_ms ON shared_file_memberships
WHEN old.root_id IS NOT new.root_id OR old.path_id IS NOT new.path_id OR old.removed_at_ms IS NOT new.removed_at_ms
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_shared_directory_roots_update
AFTER UPDATE OF enabled, accessible, shareable, deleted_at_ms ON shared_directory_roots
WHEN old.enabled IS NOT new.enabled OR old.accessible IS NOT new.accessible OR old.shareable IS NOT new.shareable OR old.deleted_at_ms IS NOT new.deleted_at_ms
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_local_paths_update
AFTER UPDATE OF sort_key, file_name_search_key, platform, native_path ON local_paths
WHEN old.sort_key IS NOT new.sort_key OR old.file_name_search_key IS NOT new.file_name_search_key OR old.platform IS NOT new.platform OR old.native_path IS NOT new.native_path
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_known_files_update
AFTER UPDATE OF ed2k_hash ON known_files
WHEN old.ed2k_hash IS NOT new.ed2k_hash
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_verified_local_content_insert
AFTER INSERT ON verified_local_content
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_verified_local_content_delete
AFTER DELETE ON verified_local_content
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_verified_local_content_update
AFTER UPDATE OF known_file_id ON verified_local_content
WHEN old.known_file_id IS NOT new.known_file_id
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;
