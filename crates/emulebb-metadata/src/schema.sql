CREATE TABLE metadata_schema (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    schema_id TEXT NOT NULL UNIQUE,
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
) STRICT;

CREATE TABLE discovery_initialization (
    domain TEXT PRIMARY KEY CHECK(domain IN ('servers', 'kad')),
    status TEXT NOT NULL CHECK(status IN ('pending', 'initialized'))
) STRICT, WITHOUT ROWID;

INSERT INTO discovery_initialization(domain, status) VALUES
    ('servers', 'pending'), ('kad', 'pending');

CREATE TABLE profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    uuid TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
) STRICT;

CREATE TABLE local_identities (
    id INTEGER PRIMARY KEY,
    identity_kind TEXT NOT NULL UNIQUE CHECK(identity_kind IN ('ed2k-user-hash', 'ed2k-secure-ident', 'kad-node-id')),
    public_identity BLOB,
    private_secret BLOB,
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK (
        (identity_kind = 'ed2k-user-hash' AND public_identity IS NOT NULL AND length(public_identity) = 16 AND private_secret IS NULL)
        OR (identity_kind = 'ed2k-secure-ident' AND public_identity IS NULL AND private_secret IS NOT NULL AND length(private_secret) > 0)
        OR (identity_kind = 'kad-node-id' AND public_identity IS NOT NULL AND length(public_identity) = 16 AND public_identity != zeroblob(16) AND private_secret IS NULL)
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
    id INTEGER PRIMARY KEY AUTOINCREMENT CHECK(id > 0),
    name TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK(instr(name, char(0)) = 0 AND length(name) BETWEEN 1 AND 64 AND substr(name, 1, 1) GLOB '[A-Za-z0-9]' AND name NOT GLOB '*[^A-Za-z0-9-]*'),
    temp_path_id INTEGER REFERENCES local_paths(id),
    destination_path_id INTEGER REFERENCES local_paths(id),
    comment TEXT NOT NULL DEFAULT ''
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
    size_bytes INTEGER CHECK(size_bytes IS NULL OR size_bytes >= 0),
    latest_download_job_id INTEGER REFERENCES download_jobs(id) ON DELETE SET NULL,
    display_name TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    aich_root_origin TEXT CHECK(aich_root_origin IN
        ('local_computed', 'operator_link', 'stock_import')),
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
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK((aich_root IS NULL) = (aich_root_origin IS NULL))
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
    first_completed_at_s INTEGER NOT NULL CHECK(first_completed_at_s >= 0),
    last_completed_at_s INTEGER NOT NULL CHECK(last_completed_at_s >= first_completed_at_s)
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

CREATE TABLE download_job_md4_part_hashes (
    job_id INTEGER NOT NULL REFERENCES download_jobs(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 4294967295),
    md4_hash BLOB NOT NULL CHECK(length(md4_hash) = 16),
    PRIMARY KEY(job_id, part_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE download_job_aich_part_hashes (
    job_id INTEGER NOT NULL REFERENCES download_jobs(id) ON DELETE CASCADE,
    part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 4294967295),
    aich_hash BLOB NOT NULL CHECK(length(aich_hash) = 20),
    PRIMARY KEY(job_id, part_index)
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

CREATE TABLE download_job_verified_ranges (
    job_id INTEGER NOT NULL REFERENCES download_jobs(id) ON DELETE CASCADE,
    start_offset INTEGER NOT NULL CHECK(start_offset >= 0),
    end_offset INTEGER NOT NULL,
    created_at_s INTEGER NOT NULL CHECK(created_at_s >= 0),
    CHECK(end_offset >= start_offset),
    PRIMARY KEY(job_id, start_offset, end_offset)
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
CREATE INDEX local_paths_delivery_leaf_idx ON local_paths(platform, file_name_search_key, id);

-- Durable, verified path-to-content cache. Presence in this table does not
-- authorize serving: current root membership and a live fingerprint match do.
CREATE TABLE local_file_instances (
    path_id INTEGER PRIMARY KEY REFERENCES local_paths(id),
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE CASCADE,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    native_identity BLOB NOT NULL CHECK(length(native_identity) > 0),
    secondary_identity BLOB CHECK(secondary_identity IS NULL OR length(secondary_identity)<=64),
    verified_fingerprint BLOB NOT NULL CHECK(length(verified_fingerprint) > 0),
    verified_at_ms INTEGER NOT NULL CHECK(verified_at_ms >= 0)
) STRICT;

CREATE INDEX local_file_instances_content_idx
    ON local_file_instances(known_file_id);
CREATE UNIQUE INDEX local_file_instances_path_content_idx
    ON local_file_instances(path_id, known_file_id);

CREATE INDEX local_file_instances_identity_idx
    ON local_file_instances(native_identity, size_bytes);
CREATE INDEX local_file_instances_secondary_identity_idx
    ON local_file_instances(secondary_identity, size_bytes) WHERE secondary_identity IS NOT NULL;

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
    path_id INTEGER NOT NULL,
    known_file_id INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    first_seen_at_ms INTEGER NOT NULL CHECK(first_seen_at_ms >= 0),
    last_seen_at_ms INTEGER NOT NULL CHECK(last_seen_at_ms >= 0),
    removed_at_ms INTEGER CHECK(removed_at_ms IS NULL OR removed_at_ms >= 0),
    PRIMARY KEY(root_id, path_id),
    FOREIGN KEY(path_id, known_file_id) REFERENCES local_file_instances(path_id, known_file_id)
        ON UPDATE CASCADE ON DELETE CASCADE
) STRICT, WITHOUT ROWID;
CREATE INDEX shared_file_memberships_root_content_idx
    ON shared_file_memberships(root_id, known_file_id, path_id);

CREATE TABLE download_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT CHECK(id > 0),
    known_file_id INTEGER NOT NULL REFERENCES known_files(id) ON DELETE RESTRICT,
    expected_size_bytes INTEGER CHECK(expected_size_bytes IS NULL OR expected_size_bytes >= 0),
    execution_generation INTEGER NOT NULL DEFAULT 0 CHECK(execution_generation >= 0),
    selected_temp_path_id INTEGER REFERENCES local_paths(id),
    storage_path_id INTEGER UNIQUE REFERENCES local_paths(id),
    terminal_completed_at_s INTEGER CHECK(terminal_completed_at_s IS NULL OR terminal_completed_at_s >= 0),
    internal_storage_retired INTEGER NOT NULL DEFAULT 0 CHECK(internal_storage_retired IN (0, 1)),
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
    -- A live consensus belongs to the transfer, never accepted known/local
    -- content. Persist the decision and origin separately from mere acquisition.
    aich_root BLOB CHECK(aich_root IS NULL OR length(aich_root) = 20),
    aich_root_origin TEXT CHECK(aich_root_origin IN
        ('local_computed', 'operator_link', 'stock_import', 'network_consensus')),
    aich_trust_generation INTEGER NOT NULL DEFAULT 0 CHECK(aich_trust_generation >= 0),
    visible_state TEXT NOT NULL CHECK(visible_state IN ('completed', 'completing', 'downloading', 'queued')),
    -- Set after all parts verify and cleared only after the authoritative
    -- whole-file ED2K MD4 completion rehash succeeds or demotes bad parts.
    final_rehash_pending INTEGER NOT NULL DEFAULT 0
        CHECK(final_rehash_pending IN (0, 1)),
    intent TEXT NOT NULL DEFAULT 'started' CHECK(intent IN ('started', 'stopped')),
    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
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
    created_at_s INTEGER NOT NULL CHECK(created_at_s >= 0),
    updated_at_s INTEGER NOT NULL CHECK(updated_at_s >= 0),
    completed_at_s INTEGER CHECK(completed_at_s IS NULL OR completed_at_s >= 0),
    removed_at_s INTEGER CHECK(removed_at_s IS NULL OR removed_at_s >= 0),
    -- Terminal destructive-delete intent. Once set, active selectors suppress
    -- the transfer until cleanup removes the row; ordinary manifest upserts
    -- deliberately preserve the marker.
    delete_requested_at_s INTEGER
        CHECK(delete_requested_at_s IS NULL OR delete_requested_at_s >= 0),
    -- Allocation intent is persisted before exclusive directory creation. Only
    -- an established identity plus the marker authorizes payload writes/cleanup.
    storage_directory_identity BLOB CHECK(storage_directory_identity IS NULL OR length(storage_directory_identity)<=64),
    storage_directory_marker_id TEXT UNIQUE CHECK(storage_directory_marker_id IS NULL OR length(storage_directory_marker_id)=36),
    CHECK((selected_temp_path_id IS NULL) = (storage_path_id IS NULL)),
    CHECK((storage_path_id IS NULL) = (storage_directory_marker_id IS NULL)),
    CHECK(storage_directory_identity IS NULL OR storage_path_id IS NOT NULL),
    CHECK(
        (delivery_state = 'pending' AND delivery_ownership = 'none' AND delivered_path_id IS NULL)
        OR (delivery_state = 'delivered' AND delivery_ownership = 'owned' AND delivered_path_id IS NOT NULL AND source_fingerprint IS NOT NULL)
        OR (delivery_state = 'delivered' AND delivery_ownership = 'unowned' AND delivered_path_id IS NOT NULL)
    ),
    CHECK((aich_root IS NULL) = (aich_root_origin IS NULL)),
    CHECK(aich_hashset_acquired = 0 OR aich_root IS NOT NULL),
    CHECK((completed = 1) = (visible_state = 'completed')),
    CHECK(payload_fingerprint IS NULL OR (completed = 1 AND final_rehash_pending = 0)),
    CHECK(terminal_completed_at_s IS NULL OR (completed = 1 AND final_rehash_pending = 0 AND delivery_state = 'delivered')),
    CHECK(internal_storage_retired = 0 OR terminal_completed_at_s IS NOT NULL OR removed_at_s IS NOT NULL)
) STRICT;

-- A logically removed job with pending cleanup does not own future admission.
CREATE UNIQUE INDEX download_jobs_unremoved_unfinished_content_idx
ON download_jobs(known_file_id)
WHERE removed_at_s IS NULL AND terminal_completed_at_s IS NULL;
CREATE INDEX download_jobs_visible_page_idx ON download_jobs(id) WHERE removed_at_s IS NULL;
CREATE INDEX download_jobs_work_page_idx ON download_jobs(intent, id)
WHERE removed_at_s IS NULL AND terminal_completed_at_s IS NULL;
CREATE INDEX download_jobs_removed_page_idx ON download_jobs(id) WHERE removed_at_s IS NOT NULL;
CREATE INDEX download_jobs_content_history_idx ON download_jobs(known_file_id, id);
CREATE TRIGGER download_jobs_fixed_physical_storage BEFORE UPDATE OF storage_path_id, storage_directory_identity, storage_directory_marker_id ON download_jobs
WHEN (old.storage_path_id IS NOT NULL AND new.storage_path_id IS NOT old.storage_path_id)
  OR (old.storage_directory_marker_id IS NOT NULL AND new.storage_directory_marker_id IS NOT old.storage_directory_marker_id)
  OR (old.storage_directory_identity IS NOT NULL AND new.storage_directory_identity IS NOT old.storage_directory_identity)
BEGIN SELECT RAISE(ABORT, 'download job physical storage authority is immutable'); END;

CREATE TRIGGER download_jobs_fixed_storage BEFORE UPDATE OF selected_temp_path_id ON download_jobs
WHEN old.selected_temp_path_id IS NOT NULL AND new.selected_temp_path_id IS NOT old.selected_temp_path_id
BEGIN SELECT RAISE(ABORT, 'download job storage is immutable once selected'); END;

-- Durable materialization is a fact even before internal retirement commits.
CREATE TRIGGER download_jobs_delivered_history BEFORE UPDATE ON download_jobs
WHEN old.delivery_state = 'delivered' AND (
    new.delivery_state != 'delivered' OR new.delivered_path_id IS NOT old.delivered_path_id
    OR new.completed != 1 OR new.final_rehash_pending != 0)
BEGIN SELECT RAISE(ABORT, 'durable download delivery is immutable'); END;

CREATE TRIGGER download_jobs_terminal_history BEFORE UPDATE ON download_jobs
WHEN old.terminal_completed_at_s IS NOT NULL AND (
    new.terminal_completed_at_s IS NOT old.terminal_completed_at_s OR new.completed != 1
    OR new.final_rehash_pending != 0 OR new.delivery_state != 'delivered')
BEGIN SELECT RAISE(ABORT, 'terminal download completion is immutable'); END;

CREATE TRIGGER known_files_accepted_size_immutable BEFORE UPDATE OF size_bytes ON known_files
WHEN old.size_bytes IS NOT NULL AND new.size_bytes IS NOT old.size_bytes
BEGIN SELECT RAISE(ABORT, 'accepted content size is immutable'); END;

CREATE INDEX known_files_latest_job_idx ON known_files(latest_download_job_id);

CREATE TRIGGER download_jobs_identity_immutable
BEFORE UPDATE OF id, known_file_id ON download_jobs
WHEN new.id != old.id OR new.known_file_id != old.known_file_id
BEGIN SELECT RAISE(ABORT, 'download job identity is immutable'); END;

CREATE TRIGGER known_files_latest_job_same_content_insert
BEFORE INSERT ON known_files
WHEN new.latest_download_job_id IS NOT NULL
AND NOT EXISTS(SELECT 1 FROM download_jobs WHERE id=new.latest_download_job_id AND known_file_id=new.id)
BEGIN SELECT RAISE(ABORT, 'latest download job belongs to another content'); END;

CREATE TRIGGER known_files_latest_job_same_content_update
BEFORE UPDATE OF latest_download_job_id ON known_files
WHEN new.latest_download_job_id IS NOT NULL
AND NOT EXISTS(SELECT 1 FROM download_jobs WHERE id=new.latest_download_job_id AND known_file_id=new.id)
BEGIN SELECT RAISE(ABORT, 'latest download job belongs to another content'); END;

-- Completion and explicit removal share this internal-storage authority.
-- Output deletion has its own journal and never follows from this row.
CREATE TABLE download_retirements (
    job_id INTEGER PRIMARY KEY REFERENCES download_jobs(id) ON DELETE RESTRICT,
    target_path_id INTEGER REFERENCES local_paths(id),
    directory_identity BLOB,
    directory_marker_id TEXT,
    CHECK (
        (directory_identity IS NULL AND directory_marker_id IS NULL)
        OR (directory_identity IS NOT NULL AND directory_marker_id IS NOT NULL
            AND length(trim(directory_marker_id)) > 0)
    )
) STRICT;
CREATE INDEX download_retirements_target_path_id_idx ON download_retirements(target_path_id);
CREATE TRIGGER download_retirements_authority_immutable
BEFORE UPDATE OF job_id,target_path_id,directory_identity,directory_marker_id ON download_retirements
WHEN new.job_id IS NOT old.job_id OR new.target_path_id IS NOT old.target_path_id
  OR new.directory_identity IS NOT old.directory_identity OR new.directory_marker_id IS NOT old.directory_marker_id
BEGIN SELECT RAISE(ABORT, 'internal retirement authority is immutable'); END;

-- WHY: A crash can leave an exclusively created but incomplete final name.
-- Its sharing exclusion must outlive both the attempt and transfer deletion.
CREATE TABLE download_delivery_exclusions (
    platform TEXT NOT NULL,
    native_path BLOB NOT NULL,
    reservation_id TEXT NOT NULL UNIQUE CHECK(length(reservation_id)=36),
    originating_job_id INTEGER NOT NULL CHECK(originating_job_id > 0),
    output_identity BLOB CHECK(output_identity IS NULL OR length(output_identity)<=64),
    secondary_identity BLOB CHECK(secondary_identity IS NULL OR length(secondary_identity)<=64),
    CHECK(secondary_identity IS NULL OR output_identity IS NOT NULL),
    PRIMARY KEY(platform, native_path)
) STRICT;

CREATE INDEX download_delivery_exclusion_origin_idx ON download_delivery_exclusions(originating_job_id);
CREATE INDEX download_delivery_exclusion_identity_idx ON download_delivery_exclusions(output_identity)
WHERE output_identity IS NOT NULL;
CREATE INDEX download_delivery_exclusion_secondary_identity_idx ON download_delivery_exclusions(secondary_identity)
WHERE secondary_identity IS NOT NULL;
CREATE TRIGGER download_delivery_exclusion_identity_immutable BEFORE UPDATE OF output_identity,secondary_identity ON download_delivery_exclusions
WHEN old.output_identity IS NOT NULL AND (new.output_identity IS NOT old.output_identity OR new.secondary_identity IS NOT old.secondary_identity)
BEGIN SELECT RAISE(ABORT, 'delivery exclusion identity is immutable'); END;

CREATE TRIGGER download_delivery_exclusion_origin_immutable
BEFORE UPDATE OF originating_job_id,reservation_id,platform,native_path ON download_delivery_exclusions
BEGIN SELECT RAISE(ABORT, 'delivery exclusion authority is immutable'); END;

CREATE TABLE download_delivery_attempts (
    job_id INTEGER PRIMARY KEY REFERENCES download_jobs(id) ON DELETE RESTRICT,
    attempt_id TEXT NOT NULL UNIQUE CHECK(length(attempt_id) = 36),
    phase TEXT NOT NULL CHECK(phase IN ('prepared', 'staged', 'published')),
    target_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    staging_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    staging_fingerprint BLOB,
    published_fingerprint BLOB,
    created_at_s INTEGER NOT NULL CHECK(created_at_s >= 0),
    updated_at_s INTEGER NOT NULL CHECK(updated_at_s >= 0),
    CHECK(target_path_id != staging_path_id),
    CHECK(
        (phase = 'prepared' AND staging_fingerprint IS NULL AND published_fingerprint IS NULL)
        OR (phase = 'staged' AND staging_fingerprint IS NOT NULL AND published_fingerprint IS NULL)
        OR (phase = 'published' AND staging_fingerprint IS NOT NULL AND published_fingerprint IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER download_delivery_attempt_authority_immutable
BEFORE UPDATE OF job_id,attempt_id,target_path_id,staging_path_id ON download_delivery_attempts
BEGIN SELECT RAISE(ABORT, 'delivery attempt authority is immutable'); END;

CREATE INDEX download_delivery_attempts_phase_idx ON download_delivery_attempts(phase, job_id);

CREATE TABLE download_delivery_tombstones (
    job_id INTEGER PRIMARY KEY REFERENCES download_jobs(id) ON DELETE RESTRICT,
    tombstone_id TEXT NOT NULL UNIQUE CHECK(length(tombstone_id) = 36),
    phase TEXT NOT NULL CHECK(phase IN ('prepared', 'moved')),
    original_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    tombstone_path_id INTEGER NOT NULL REFERENCES local_paths(id),
    source_fingerprint BLOB NOT NULL,
    moved_fingerprint BLOB,
    created_at_s INTEGER NOT NULL CHECK(created_at_s >= 0),
    updated_at_s INTEGER NOT NULL CHECK(updated_at_s >= 0),
    CHECK(original_path_id != tombstone_path_id),
    CHECK(
        (phase = 'prepared' AND moved_fingerprint IS NULL)
        OR (phase = 'moved' AND moved_fingerprint IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER download_delivery_tombstone_authority_immutable
BEFORE UPDATE OF job_id,tombstone_id,original_path_id,tombstone_path_id,source_fingerprint ON download_delivery_tombstones
BEGIN SELECT RAISE(ABORT, 'delivery tombstone authority is immutable'); END;

CREATE INDEX download_delivery_tombstones_phase_idx
ON download_delivery_tombstones(phase, job_id);

CREATE TRIGGER clear_delivery_attempt_after_delivered
AFTER UPDATE OF delivery_state ON download_jobs
WHEN NEW.delivery_state = 'delivered'
BEGIN
    DELETE FROM download_delivery_attempts WHERE job_id = NEW.id;
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

CREATE TABLE download_job_pieces (
    job_id INTEGER NOT NULL REFERENCES download_jobs(id) ON DELETE CASCADE,
    piece_index INTEGER NOT NULL CHECK(piece_index BETWEEN 0 AND 4294967295),
    state TEXT NOT NULL CHECK(state IN ('Missing', 'Verified')),
    bytes_written INTEGER NOT NULL DEFAULT 0 CHECK(bytes_written >= 0),
    block_bitmap TEXT,
    ich_corrupted INTEGER NOT NULL DEFAULT 0 CHECK(ich_corrupted IN (0, 1)),
    updated_at_s INTEGER NOT NULL CHECK(updated_at_s >= 0),
    PRIMARY KEY(job_id, piece_index)
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

CREATE TABLE download_job_sources (
    id INTEGER PRIMARY KEY,
    job_id INTEGER NOT NULL REFERENCES download_jobs(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    tcp_port INTEGER NOT NULL CHECK(tcp_port BETWEEN 1 AND 65535),
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    connect_options INTEGER CHECK(connect_options IS NULL OR connect_options BETWEEN 0 AND 255),
    file_comment TEXT NOT NULL DEFAULT '',
    file_rating INTEGER NOT NULL DEFAULT 0 CHECK(file_rating BETWEEN 0 AND 255),
    first_seen_at_s INTEGER NOT NULL CHECK(first_seen_at_s >= 0),
    last_seen_at_s INTEGER NOT NULL CHECK(last_seen_at_s >= 0),
    last_outcome TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE UNIQUE INDEX download_job_sources_identity_idx
ON download_job_sources(job_id, ip, tcp_port);

CREATE INDEX download_job_sources_page_idx ON download_job_sources(job_id, id);
CREATE INDEX download_job_sources_user_idx ON download_job_sources(job_id, user_hash, id);

CREATE TABLE download_job_file_name_observations (
    id INTEGER PRIMARY KEY,
    position INTEGER NOT NULL CHECK(position >= 0),
    job_id INTEGER NOT NULL REFERENCES download_jobs(id) ON DELETE CASCADE,
    source_ip TEXT,
    source_tcp_port INTEGER CHECK(source_tcp_port IS NULL OR source_tcp_port BETWEEN 1 AND 65535),
    user_hash BLOB CHECK(user_hash IS NULL OR length(user_hash) = 16),
    client_software TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL,
    server_endpoint TEXT,
    raw_name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    observed_at_s INTEGER NOT NULL CHECK(observed_at_s >= 0),
    CHECK((source_ip IS NULL) = (source_tcp_port IS NULL)),
    CHECK(length(trim(raw_name)) > 0),
    CHECK(length(trim(normalized_name)) > 0),
    UNIQUE(job_id, position)
) STRICT;

CREATE INDEX download_job_file_name_observations_page_idx ON download_job_file_name_observations(job_id, id);

CREATE INDEX download_job_file_name_observations_job_idx
ON download_job_file_name_observations(job_id, observed_at_s, id);

CREATE TABLE kad_bootstrap_endpoints (
    position INTEGER PRIMARY KEY,
    endpoint TEXT NOT NULL UNIQUE,
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    CHECK(position >= 0),
    CHECK(length(trim(endpoint)) > 0)
) STRICT;

CREATE TABLE kad_routing_revision (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    revision INTEGER NOT NULL CHECK(revision >= 0)
) STRICT;
INSERT INTO kad_routing_revision(id, revision) VALUES (1, 0);

CREATE TABLE kad_routing_contacts (
    node_id BLOB PRIMARY KEY CHECK(length(node_id) = 16),
    ip INTEGER NOT NULL UNIQUE CHECK(ip BETWEEN 1 AND 4294967295),
    udp_port INTEGER NOT NULL CHECK(udp_port BETWEEN 1 AND 65535),
    tcp_port INTEGER NOT NULL CHECK(tcp_port BETWEEN 0 AND 65535),
    version INTEGER NOT NULL CHECK(version BETWEEN 0 AND 255),
    udp_key INTEGER NOT NULL CHECK(udp_key BETWEEN 0 AND 4294967295),
    udp_key_ip INTEGER CHECK(udp_key_ip BETWEEN 1 AND 4294967295),
    hello_source_udp_port INTEGER CHECK(hello_source_udp_port BETWEEN 1 AND 65535),
    udp_firewalled INTEGER NOT NULL CHECK(udp_firewalled IN (0, 1)),
    tcp_firewalled INTEGER NOT NULL CHECK(tcp_firewalled IN (0, 1)),
    requests_hello_res_ack INTEGER NOT NULL CHECK(requests_hello_res_ack IN (0, 1)),
    received_hello_packet INTEGER NOT NULL CHECK(received_hello_packet IN (0, 1)),
    verified INTEGER NOT NULL CHECK(verified IN (0, 1)),
    contact_type TEXT NOT NULL CHECK(contact_type IN ('active', 'inactive', 'dead')),
    probe_type INTEGER NOT NULL CHECK(probe_type BETWEEN 0 AND 4),
    bootstrap INTEGER NOT NULL CHECK(bootstrap IN (0, 1)),
    expires_at_seconds INTEGER CHECK(expires_at_seconds >= 0),
    last_type_set_at_seconds INTEGER CHECK(last_type_set_at_seconds >= 0),
    last_seen_at_seconds INTEGER NOT NULL CHECK(last_seen_at_seconds >= 0),
    created_at_seconds INTEGER NOT NULL CHECK(created_at_seconds >= 0)
) STRICT, WITHOUT ROWID;

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
CREATE INDEX shared_file_memberships_path_content_idx ON shared_file_memberships(path_id, known_file_id);
CREATE INDEX download_jobs_pending_delete_idx
ON download_jobs(delete_requested_at_s)
WHERE delete_requested_at_s IS NOT NULL;
CREATE INDEX kad_keyword_target_idx ON kad_keyword_publishes(target_node_id, observed_at_ms);
CREATE INDEX kad_source_file_idx ON kad_source_publishes(ed2k_hash, observed_at_ms);
CREATE INDEX kad_note_file_idx ON kad_note_publishes(ed2k_hash, observed_at_ms);
CREATE INDEX search_results_session_idx ON search_results(session_id, id);
CREATE INDEX search_result_observations_result_idx
ON search_result_observations(result_id, observed_at_ms, id);
CREATE INDEX categories_temp_path_id_idx ON categories(temp_path_id);
CREATE INDEX categories_destination_path_id_idx ON categories(destination_path_id);
CREATE INDEX download_jobs_temp_path_idx ON download_jobs(selected_temp_path_id);
CREATE INDEX download_jobs_category_id_idx ON download_jobs(category_id);
CREATE INDEX download_jobs_delivered_path_id_idx ON download_jobs(delivered_path_id);
CREATE INDEX download_delivery_attempts_target_path_id_idx ON download_delivery_attempts(target_path_id);
CREATE INDEX download_delivery_attempts_staging_path_id_idx ON download_delivery_attempts(staging_path_id);
CREATE INDEX download_delivery_tombstones_original_path_id_idx ON download_delivery_tombstones(original_path_id);
CREATE INDEX download_delivery_tombstones_tombstone_path_id_idx ON download_delivery_tombstones(tombstone_path_id);
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
AFTER UPDATE OF known_file_id, verified_fingerprint, native_identity, secondary_identity ON local_file_instances
WHEN old.known_file_id IS NOT new.known_file_id OR old.verified_fingerprint IS NOT new.verified_fingerprint
  OR old.native_identity IS NOT new.native_identity OR old.secondary_identity IS NOT new.secondary_identity
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

-- Reservation identity changes affect eligibility before membership withdrawal.
CREATE TRIGGER library_catalog_delivery_exclusions_insert
AFTER INSERT ON download_delivery_exclusions
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_delivery_exclusions_delete
AFTER DELETE ON download_delivery_exclusions
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;

CREATE TRIGGER library_catalog_delivery_exclusions_update
AFTER UPDATE OF platform, native_path, output_identity, secondary_identity ON download_delivery_exclusions
WHEN old.platform IS NOT new.platform OR old.native_path IS NOT new.native_path
  OR old.output_identity IS NOT new.output_identity OR old.secondary_identity IS NOT new.secondary_identity
BEGIN
    UPDATE library_catalog_revision SET revision = CASE WHEN revision = 9223372036854775807 THEN 0 ELSE revision + 1 END WHERE id = 1;
END;
