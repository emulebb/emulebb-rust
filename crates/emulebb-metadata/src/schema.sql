CREATE TABLE metadata_schema (
    schema_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
);

CREATE TABLE profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    uuid TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
);

CREATE TABLE local_identities (
    id INTEGER PRIMARY KEY,
    identity_kind TEXT NOT NULL UNIQUE CHECK(identity_kind IN ('ed2k-user-hash', 'ed2k-secure-ident')),
    public_identity BLOB,
    private_secret BLOB,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK (public_identity IS NULL OR length(public_identity) IN (16, 20))
);

CREATE TABLE settings (
    section TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    PRIMARY KEY(section, key),
    CHECK(length(trim(section)) > 0),
    CHECK(length(trim(key)) > 0),
    CHECK(json_valid(value_json))
);

CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    path_id INTEGER REFERENCES local_paths(id),
    comment TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    color INTEGER,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0)
);

CREATE TABLE friends (
    id INTEGER PRIMARY KEY,
    user_hash BLOB NOT NULL UNIQUE CHECK(length(user_hash) = 16),
    name TEXT NOT NULL,
    last_address TEXT,
    last_port INTEGER NOT NULL DEFAULT 0 CHECK(last_port BETWEEN 0 AND 65535),
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    last_seen_ms INTEGER CHECK(last_seen_ms IS NULL OR last_seen_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0)
);

CREATE TABLE known_files (
    id INTEGER PRIMARY KEY,
    ed2k_hash BLOB NOT NULL UNIQUE CHECK(length(ed2k_hash) = 16),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    display_name TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    part_size INTEGER CHECK(part_size IS NULL OR part_size > 0),
    part_count INTEGER CHECK(part_count IS NULL OR part_count >= 0),
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)),
    md4_hashset_acquired INTEGER NOT NULL DEFAULT 0 CHECK(md4_hashset_acquired IN (0, 1)),
    aich_hashset_acquired INTEGER NOT NULL DEFAULT 0 CHECK(aich_hashset_acquired IN (0, 1)),
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    upload_priority TEXT NOT NULL DEFAULT 'normal'
        CHECK(upload_priority IN ('auto', 'not-published', 'verylow', 'low', 'normal', 'high', 'release')),
    auto_upload_priority INTEGER NOT NULL DEFAULT 0 CHECK(auto_upload_priority IN (0, 1)),
    comment TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5),
    media_artist TEXT NOT NULL DEFAULT '',
    media_album TEXT NOT NULL DEFAULT '',
    media_title TEXT NOT NULL DEFAULT '',
    media_length_seconds INTEGER NOT NULL DEFAULT 0 CHECK(media_length_seconds >= 0),
    media_bitrate_kbps INTEGER NOT NULL DEFAULT 0 CHECK(media_bitrate_kbps >= 0),
    media_codec TEXT NOT NULL DEFAULT '',
    media_extractor_version INTEGER NOT NULL DEFAULT 0 CHECK(media_extractor_version >= 0),
    availability_score INTEGER NOT NULL DEFAULT 0 CHECK(availability_score >= 0),
    -- Lifetime bytes we have uploaded to other peers for this file (eMule
    -- CStatisticFile all-time transferred), used to derive the all-time upload
    -- ratio that feeds the upload-queue low-ratio score bonus.
    all_time_uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(all_time_uploaded_bytes >= 0),
    all_time_upload_requests INTEGER NOT NULL DEFAULT 0 CHECK(all_time_upload_requests >= 0),
    all_time_upload_accepts INTEGER NOT NULL DEFAULT 0 CHECK(all_time_upload_accepts >= 0),
    last_upload_request_ms INTEGER NOT NULL DEFAULT 0 CHECK(last_upload_request_ms >= 0),
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
);

-- Durable content identity for successful downloads. This intentionally has
-- no foreign key to current known-file, transfer, share, or path rows: cleanup,
-- moving, or deleting a payload must not erase the fact it completed, and a
-- historical record must never imply that an obsolete path is still live.
CREATE TABLE download_history (
    ed2k_hash BLOB PRIMARY KEY CHECK(length(ed2k_hash) = 16),
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    display_name TEXT NOT NULL,
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    first_completed_at_ms INTEGER NOT NULL CHECK(first_completed_at_ms >= 0),
    last_completed_at_ms INTEGER NOT NULL CHECK(last_completed_at_ms >= first_completed_at_ms)
);

CREATE TABLE file_names (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1 CHECK(seen_count >= 1),
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= 0),
    UNIQUE(known_file_id, normalized_name)
);

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

CREATE TRIGGER file_names_au AFTER UPDATE ON file_names BEGIN
    INSERT INTO file_name_fts(file_name_fts, rowid, name, normalized_name)
    VALUES('delete', old.id, old.name, old.normalized_name);
    INSERT INTO file_name_fts(rowid, name, normalized_name)
    VALUES (new.id, new.name, new.normalized_name);
END;

CREATE TABLE ed2k_part_hashes (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index >= 0),
    md4_hash BLOB NOT NULL CHECK(length(md4_hash) = 16),
    UNIQUE(known_file_id, part_index)
);

CREATE TABLE aich_part_hashes (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index >= 0),
    aich_hash BLOB NOT NULL CHECK(length(aich_hash) = 20),
    UNIQUE(known_file_id, part_index)
);

CREATE TABLE imported_known_files (
    id INTEGER PRIMARY KEY,
    ed2k_hash BLOB NOT NULL CHECK(length(ed2k_hash) = 16),
    display_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
    modified_s INTEGER NOT NULL CHECK(modified_s > 0),
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    upload_priority TEXT NOT NULL DEFAULT 'normal'
        CHECK(upload_priority IN ('auto', 'not-published', 'verylow', 'low', 'normal', 'high', 'release')),
    auto_upload_priority INTEGER NOT NULL DEFAULT 0 CHECK(auto_upload_priority IN (0, 1)),
    all_time_uploaded_bytes INTEGER NOT NULL DEFAULT 0 CHECK(all_time_uploaded_bytes >= 0),
    all_time_upload_requests INTEGER NOT NULL DEFAULT 0 CHECK(all_time_upload_requests >= 0),
    all_time_upload_accepts INTEGER NOT NULL DEFAULT 0 CHECK(all_time_upload_accepts >= 0),
    last_upload_request_ms INTEGER NOT NULL DEFAULT 0 CHECK(last_upload_request_ms >= 0),
    imported_at_ms INTEGER NOT NULL CHECK(imported_at_ms >= 0)
);

CREATE INDEX imported_known_files_identity_idx
    ON imported_known_files(display_name, size_bytes, modified_s);

CREATE TABLE imported_known_file_md4_hashes (
    id INTEGER PRIMARY KEY,
    imported_known_file_id INTEGER NOT NULL REFERENCES imported_known_files(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index >= 0),
    md4_hash BLOB NOT NULL CHECK(length(md4_hash) = 16),
    UNIQUE(imported_known_file_id, part_index)
);

CREATE TABLE imported_known_file_aich_hashes (
    id INTEGER PRIMARY KEY,
    imported_known_file_id INTEGER NOT NULL REFERENCES imported_known_files(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index >= 0),
    aich_hash BLOB NOT NULL CHECK(length(aich_hash) = 20),
    UNIQUE(imported_known_file_id, part_index)
);

CREATE TABLE verified_ranges (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    start_offset INTEGER NOT NULL CHECK(start_offset >= 0),
    end_offset INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    CHECK(end_offset >= start_offset)
);

CREATE TABLE local_paths (
    id INTEGER PRIMARY KEY,
    display_path TEXT NOT NULL,
    native_path BLOB NOT NULL,
    search_key TEXT NOT NULL,
    platform TEXT NOT NULL,
    UNIQUE(platform, native_path)
);

CREATE INDEX idx_local_paths_search ON local_paths(platform, search_key);

CREATE TABLE shared_directory_roots (
    id INTEGER PRIMARY KEY,
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    monitor_owned INTEGER NOT NULL DEFAULT 0 CHECK(monitor_owned IN (0, 1)),
    shareable INTEGER NOT NULL DEFAULT 1 CHECK(shareable IN (0, 1)),
    accessible INTEGER NOT NULL DEFAULT 1 CHECK(accessible IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_scan_ms INTEGER CHECK(last_scan_ms IS NULL OR last_scan_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0),
    UNIQUE(path_id)
);

CREATE TABLE shared_file_exclusions (
    path_id INTEGER PRIMARY KEY REFERENCES local_paths(id) ON DELETE CASCADE,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
);

CREATE TABLE shared_default_ignore_overrides (
    rule_key TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK(length(trim(rule_key)) > 0)
);

CREATE TABLE shared_file_memberships (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    root_id INTEGER NOT NULL REFERENCES shared_directory_roots(id),
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    relative_path TEXT NOT NULL,
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= 0),
    removed_at_ms INTEGER CHECK(removed_at_ms IS NULL OR removed_at_ms >= 0),
    UNIQUE(known_file_id, root_id, path_id)
);

CREATE TABLE unshared_files (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    reason TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    UNIQUE(known_file_id)
);

CREATE TABLE transfers (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    visible_state TEXT NOT NULL CHECK(visible_state IN ('completed', 'completing', 'downloading', 'queued')),
    -- Set after all parts verify and cleared only after the authoritative
    -- whole-file ED2K MD4 completion rehash succeeds or demotes bad parts.
    final_rehash_pending INTEGER NOT NULL DEFAULT 0
        CHECK(final_rehash_pending IN (0, 1)),
    control_state TEXT CHECK(control_state IS NULL OR control_state IN ('paused', 'stopped')),
    category_id INTEGER REFERENCES categories(id),
    download_priority TEXT NOT NULL DEFAULT 'normal'
        CHECK(download_priority IN ('auto', 'verylow', 'low', 'normal', 'high', 'veryhigh')),
    target_path_id INTEGER REFERENCES local_paths(id),
    payload_directory TEXT NOT NULL DEFAULT '',
    -- Materialization lifecycle for downloads. Share-in-place files never need
    -- an external delivered copy; downloads remain pending until a verified
    -- output path is committed.
    delivery_state TEXT NOT NULL
        CHECK(delivery_state IN ('not_applicable', 'pending', 'delivered')),
    delivery_ownership TEXT NOT NULL DEFAULT 'none'
        CHECK(delivery_ownership IN ('none', 'owned', 'unowned')),
    -- Absolute path identity for the completed payload materialized under a
    -- category path or the global incoming dir. NULL until delivery completes.
    delivered_path_id INTEGER REFERENCES local_paths(id),
    -- Original path identity of a shared, already-complete file seeded in
    -- place. NON-NULL marks the transfer as share-in-place; NULL is a download.
    source_path_id INTEGER REFERENCES local_paths(id),
    -- Versioned native file identity + size + nanosecond timestamps captured at
    -- ingest or delivery. NULL forces a conservative re-hash on reload.
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
            AND source_path_id IS NULL
        )
    ),
    CHECK(
        (delivery_state = 'not_applicable' AND delivery_ownership = 'none' AND source_path_id IS NOT NULL AND delivered_path_id IS NULL)
        OR (delivery_state = 'pending' AND delivery_ownership = 'none' AND source_path_id IS NULL AND delivered_path_id IS NULL)
        OR (delivery_state = 'delivered' AND delivery_ownership = 'owned' AND source_path_id IS NULL AND delivered_path_id IS NOT NULL AND source_fingerprint IS NOT NULL)
        OR (delivery_state = 'delivered' AND delivery_ownership = 'unowned' AND source_path_id IS NULL AND delivered_path_id IS NOT NULL)
    ),
    UNIQUE(known_file_id)
);

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
);

CREATE INDEX idx_delivery_attempts_phase ON delivery_attempts(phase, transfer_id);

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
);

CREATE INDEX idx_delivery_output_tombstones_phase
ON delivery_output_tombstones(phase, transfer_id);

CREATE TRIGGER clear_delivery_attempt_after_delivered
AFTER UPDATE OF delivery_state ON transfers
WHEN NEW.delivery_state = 'delivered'
BEGIN
    DELETE FROM delivery_attempts WHERE transfer_id = NEW.id;
END;

CREATE TABLE shared_file_sources (
    id INTEGER PRIMARY KEY,
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    file_size INTEGER NOT NULL CHECK(file_size >= 0),
    source_fingerprint BLOB,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    UNIQUE(path_id)
);

CREATE TABLE shared_file_scan_failures (
    id INTEGER PRIMARY KEY,
    path_id INTEGER NOT NULL REFERENCES local_paths(id),
    file_size INTEGER NOT NULL CHECK(file_size >= 0),
    source_fingerprint BLOB,
    reason TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    UNIQUE(path_id)
);

CREATE TABLE transfer_pieces (
    id INTEGER PRIMARY KEY,
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    piece_index INTEGER NOT NULL CHECK(piece_index >= 0),
    state TEXT NOT NULL CHECK(state IN ('Missing', 'Requested', 'Written', 'Verified')),
    bytes_written INTEGER NOT NULL DEFAULT 0 CHECK(bytes_written >= 0),
    block_bitmap TEXT,
    ich_corrupted INTEGER NOT NULL DEFAULT 0 CHECK(ich_corrupted IN (0, 1)),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    UNIQUE(transfer_id, piece_index)
);

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
    failed_count INTEGER NOT NULL DEFAULT 0 CHECK(failed_count >= 0),
    ping_ms INTEGER CHECK(ping_ms IS NULL OR ping_ms >= 0),
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
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= 0),
    deleted_at_ms INTEGER CHECK(deleted_at_ms IS NULL OR deleted_at_ms >= 0),
    UNIQUE(address, port)
);

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
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= 0),
    UNIQUE(user_hash)
);

CREATE TABLE transfer_sources (
    id INTEGER PRIMARY KEY,
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    peer_id INTEGER REFERENCES peers(id),
    ip TEXT NOT NULL,
    tcp_port INTEGER NOT NULL CHECK(tcp_port BETWEEN 1 AND 65535),
    udp_port INTEGER CHECK(udp_port IS NULL OR udp_port BETWEEN 1 AND 65535),
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    connect_options INTEGER CHECK(connect_options IS NULL OR connect_options BETWEEN 0 AND 255),
    file_comment TEXT NOT NULL DEFAULT '',
    file_rating INTEGER NOT NULL DEFAULT 0 CHECK(file_rating BETWEEN 0 AND 255),
    first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
    last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= 0),
    last_outcome TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX transfer_sources_identity_idx
ON transfer_sources(transfer_id, ip, tcp_port, coalesce(udp_port, 0));

CREATE TABLE transfer_name_state (
    transfer_id INTEGER PRIMARY KEY REFERENCES transfers(id) ON DELETE CASCADE,
    display_name_pinned INTEGER NOT NULL DEFAULT 0
        CHECK(display_name_pinned IN (0, 1)),
    follow_majority_filename INTEGER NOT NULL DEFAULT 0
        CHECK(follow_majority_filename IN (0, 1))
);

CREATE TABLE transfer_file_name_observations (
    id INTEGER PRIMARY KEY,
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
    CHECK(length(trim(normalized_name)) > 0)
);

CREATE INDEX transfer_file_name_observations_transfer_idx
ON transfer_file_name_observations(transfer_id, observed_at_ms, id);

CREATE TABLE kad_bootstrap_endpoints (
    position INTEGER PRIMARY KEY,
    endpoint TEXT NOT NULL UNIQUE,
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK(position >= 0),
    CHECK(length(trim(endpoint)) > 0)
);

CREATE TABLE kad_keyword_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    file_hash BLOB NOT NULL CHECK(length(file_hash) = 16),
    known_file_id INTEGER REFERENCES known_files(id) ON DELETE SET NULL,
    raw_tags BLOB NOT NULL,
    load INTEGER CHECK(load IS NULL OR load BETWEEN 0 AND 255),
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0)
);

CREATE TABLE kad_source_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 16),
    file_hash BLOB NOT NULL CHECK(length(file_hash) = 16),
    source_ip TEXT NOT NULL,
    source_tcp_port INTEGER NOT NULL CHECK(source_tcp_port BETWEEN 0 AND 65535),
    source_udp_port INTEGER NOT NULL CHECK(source_udp_port BETWEEN 0 AND 65535),
    raw_tags BLOB NOT NULL,
    load INTEGER CHECK(load IS NULL OR load BETWEEN 0 AND 255),
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0)
);

CREATE TABLE kad_note_publishes (
    id INTEGER PRIMARY KEY,
    target_node_id BLOB NOT NULL CHECK(length(target_node_id) = 16),
    publisher_id BLOB NOT NULL CHECK(length(publisher_id) = 16),
    publisher_ip TEXT NOT NULL,
    file_hash BLOB CHECK(file_hash IS NULL OR length(file_hash) = 16),
    raw_tags BLOB NOT NULL,
    load INTEGER CHECK(load IS NULL OR load BETWEEN 0 AND 255),
    valid INTEGER NOT NULL DEFAULT 1 CHECK(valid IN (0, 1)),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0)
);

CREATE TABLE kad_outbound_publish_schedule (
    id INTEGER PRIMARY KEY,
    file_hash BLOB NOT NULL CHECK(length(file_hash) = 16),
    publish_kind TEXT NOT NULL CHECK(publish_kind IN ('keyword', 'source', 'notes')),
    keyword TEXT NOT NULL DEFAULT '',
    published_at_ms INTEGER NOT NULL CHECK(published_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    UNIQUE(file_hash, publish_kind, keyword)
);

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
    completed_at_ms INTEGER CHECK(completed_at_ms IS NULL OR completed_at_ms >= 0)
);

CREATE TABLE search_results (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES search_sessions(id) ON DELETE CASCADE,
    known_file_id INTEGER REFERENCES known_files(id) ON DELETE SET NULL,
    file_hash BLOB NOT NULL CHECK(length(file_hash) = 16),
    name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    source_count INTEGER NOT NULL DEFAULT 0 CHECK(source_count >= 0),
    complete_source_count INTEGER NOT NULL DEFAULT 0 CHECK(complete_source_count >= 0),
    file_type TEXT NOT NULL DEFAULT '',
    media_artist TEXT NOT NULL DEFAULT '',
    media_album TEXT NOT NULL DEFAULT '',
    media_title TEXT NOT NULL DEFAULT '',
    media_length_seconds INTEGER NOT NULL DEFAULT 0 CHECK(media_length_seconds BETWEEN 0 AND 4294967295),
    media_bitrate_kbps INTEGER NOT NULL DEFAULT 0 CHECK(media_bitrate_kbps BETWEEN 0 AND 4294967295),
    media_codec TEXT NOT NULL DEFAULT '',
    rating INTEGER NOT NULL DEFAULT 0 CHECK(rating BETWEEN 0 AND 5),
    aich_hash TEXT NOT NULL DEFAULT '',
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
    directory TEXT NOT NULL DEFAULT '',
    UNIQUE(session_id, file_hash)
);

CREATE TABLE search_result_observations (
    id INTEGER PRIMARY KEY,
    result_id INTEGER NOT NULL REFERENCES search_results(id) ON DELETE CASCADE,
    origin TEXT NOT NULL,
    server_endpoint TEXT,
    name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    source_count INTEGER NOT NULL DEFAULT 0 CHECK(source_count >= 0),
    complete_source_count INTEGER NOT NULL DEFAULT 0 CHECK(complete_source_count >= 0),
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
    aich_hash TEXT NOT NULL DEFAULT '',
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0, 1)),
    directory TEXT NOT NULL DEFAULT '',
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    CHECK((source_client_id IS NULL) = (source_client_port IS NULL))
);

CREATE INDEX known_files_hash_idx ON known_files(ed2k_hash);
CREATE INDEX file_names_normalized_idx ON file_names(normalized_name);
CREATE INDEX shared_file_memberships_file_idx ON shared_file_memberships(known_file_id);
CREATE INDEX transfer_sources_transfer_idx ON transfer_sources(transfer_id);
CREATE INDEX transfers_pending_delete_idx
ON transfers(delete_requested_at_ms)
WHERE delete_requested_at_ms IS NOT NULL;
CREATE INDEX kad_keyword_target_idx ON kad_keyword_publishes(target_node_id, observed_at_ms);
CREATE INDEX kad_source_file_idx ON kad_source_publishes(file_hash, observed_at_ms);
CREATE INDEX kad_note_file_idx ON kad_note_publishes(file_hash, observed_at_ms);
CREATE INDEX kad_outbound_publish_file_idx
ON kad_outbound_publish_schedule(file_hash, publish_kind);
CREATE INDEX search_results_session_idx ON search_results(session_id, id);
CREATE INDEX search_result_observations_result_idx
ON search_result_observations(result_id, observed_at_ms, id);
