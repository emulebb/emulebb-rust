use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use chrono::{DateTime, Utc};
use emulebb_metadata::{MetadataCategory, MetadataFriend, MetadataServer, MetadataStore};
use emulebb_settings::{
    AppSettings, AppSettingsUpdate, SECTION_CORE, SECTION_DAEMON, SECTION_ED2K, SECTION_IP_FILTER,
    SECTION_KAD, SECTION_NAT, SECTION_VPN_GUARD, app_settings_update_is_empty,
    core_settings_from_values, core_settings_to_values, section_settings_from_values,
    section_settings_to_values,
};

use crate::{
    Category, CoreSettings, CoreState, Friend, ServerInfo, SharedDirectoryRoot, default_categories,
};

pub(crate) fn load_core_state(
    metadata: &MetadataStore,
    shared_directories: Vec<SharedDirectoryRoot>,
) -> Result<CoreState> {
    let core_setting_rows = metadata.load_settings_section(SECTION_CORE)?;
    let core_settings = core_settings_from_values(
        core_setting_rows
            .iter()
            .map(|(key, value_json)| (key.as_str(), value_json.as_str())),
    )?;
    let mut categories = default_categories();
    for category in metadata.load_categories()? {
        categories.insert(category.id, category_from_metadata(category));
    }
    let next_category_id = categories
        .keys()
        .copied()
        .max()
        .unwrap_or_default()
        .saturating_add(1)
        .max(1);

    let friends = metadata
        .load_friends()?
        .into_iter()
        .map(|friend| {
            let friend = friend_from_metadata(friend);
            (friend.user_hash.clone(), friend)
        })
        .collect::<BTreeMap<_, _>>();

    let mut servers = HashMap::new();
    let mut disabled_servers = HashSet::new();
    for server in metadata.load_servers()? {
        let endpoint = server.endpoint();
        if !server.enabled {
            disabled_servers.insert(endpoint.clone());
        }
        servers.insert(endpoint, server_from_metadata(server));
    }

    let searches = crate::search_state::load_searches(metadata)?;
    let next_search_id = crate::search_state::next_numeric_search_id(&searches);

    Ok(CoreState {
        searches,
        next_search_id,
        transfers: HashMap::new(),
        core_settings,
        categories,
        next_category_id,
        friends,
        servers,
        server_overrides: HashMap::new(),
        disabled_servers,
        server_fail_counts: HashMap::new(),
        banned_source_clients: HashSet::new(),
        active_download_attempts: HashSet::new(),
        download_cancels: HashMap::new(),
        next_download_cancel_id: 0,
        active_download_peer_endpoints: HashSet::new(),
        download_source_registry: crate::download_source_registry::DownloadSourceRegistry::default(
        ),
        ed2k_dead_sources: crate::ed2k_dead_source_list::DeadSourceList::default(),
        ed2k_server_source_last_queried: HashMap::new(),
        ed2k_server_source_last_frame_at: None,
        ed2k_udp_source_batch_last_queried: HashMap::new(),
        ed2k_kad_source_last_queried: HashMap::new(),
        ed2k_kad_callback_last_sent: HashMap::new(),
        ed2k_server_callback_last_sent: HashMap::new(),
        ed2k_direct_callback_last_sent: HashMap::new(),
        shared_directories,
        unshared_hashes: metadata.load_unshared_file_hashes()?.into_iter().collect(),
        monitor_shared_hashes: HashMap::new(),
        kad_running: false,
        last_source_count_emit_at: None,
    })
}

pub(crate) fn has_persisted_core_settings(metadata: &MetadataStore) -> Result<bool> {
    metadata.has_settings_section(SECTION_CORE)
}

pub(crate) fn persist_core_settings(
    metadata: &MetadataStore,
    core_settings: &CoreSettings,
) -> Result<()> {
    let entries = core_settings_to_values(core_settings)?;
    metadata.replace_settings_section(
        SECTION_CORE,
        entries
            .iter()
            .map(|(key, value_json)| (*key, value_json.as_str())),
    )?;
    Ok(())
}

pub(crate) fn load_app_settings(metadata: &MetadataStore) -> Result<AppSettings> {
    Ok(AppSettings {
        core: load_core_settings(metadata)?,
        daemon: load_settings_section(metadata, SECTION_DAEMON)?,
        ed2k: load_settings_section(metadata, SECTION_ED2K)?,
        kad: load_settings_section(metadata, SECTION_KAD)?,
        nat: load_settings_section(metadata, SECTION_NAT)?,
        vpn_guard: load_settings_section(metadata, SECTION_VPN_GUARD)?,
        ip_filter: load_settings_section(metadata, SECTION_IP_FILTER)?,
    })
}

pub(crate) fn persist_app_settings_update(
    metadata: &MetadataStore,
    update: AppSettingsUpdate,
) -> Result<AppSettings> {
    anyhow::ensure!(
        !app_settings_update_is_empty(&update),
        "settings PATCH requires at least one settings section"
    );
    if let Some(settings) = update.daemon {
        persist_settings_section(metadata, SECTION_DAEMON, &settings)?;
    }
    if let Some(settings) = update.ed2k {
        persist_settings_section(metadata, SECTION_ED2K, &settings)?;
    }
    if let Some(settings) = update.kad {
        persist_settings_section(metadata, SECTION_KAD, &settings)?;
    }
    if let Some(settings) = update.nat {
        persist_settings_section(metadata, SECTION_NAT, &settings)?;
    }
    if let Some(settings) = update.vpn_guard {
        persist_settings_section(metadata, SECTION_VPN_GUARD, &settings)?;
    }
    if let Some(settings) = update.ip_filter {
        persist_settings_section(metadata, SECTION_IP_FILTER, &settings)?;
    }
    load_app_settings(metadata)
}

pub(crate) fn load_core_settings(metadata: &MetadataStore) -> Result<CoreSettings> {
    let rows = metadata.load_settings_section(SECTION_CORE)?;
    Ok(core_settings_from_values(rows.iter().map(
        |(key, value_json)| (key.as_str(), value_json.as_str()),
    ))?)
}

fn load_settings_section<T>(metadata: &MetadataStore, section: &str) -> Result<T>
where
    T: Default + serde::de::DeserializeOwned,
{
    let rows = metadata.load_settings_section(section)?;
    Ok(section_settings_from_values(
        section,
        rows.iter()
            .map(|(key, value_json)| (key.as_str(), value_json.as_str())),
    )?)
}

fn persist_settings_section<T>(metadata: &MetadataStore, section: &str, settings: &T) -> Result<()>
where
    T: serde::Serialize,
{
    let entries = section_settings_to_values(settings)?;
    metadata.replace_settings_section(
        section,
        entries
            .iter()
            .map(|(key, value_json)| (key.as_str(), value_json.as_str())),
    )?;
    Ok(())
}

pub(crate) fn persist_category(metadata: &MetadataStore, category: &Category) -> Result<()> {
    metadata.upsert_category(&MetadataCategory {
        id: category.id,
        name: category.name.clone(),
        path: category.path.clone(),
        comment: category.comment.clone(),
        sort_order: category.priority,
        color: category.color,
    })
}

pub(crate) fn persist_friend(metadata: &MetadataStore, friend: &Friend) -> Result<()> {
    metadata.upsert_friend(&MetadataFriend {
        user_hash: friend.user_hash.clone(),
        name: friend.name.clone(),
        last_address: friend.address.clone(),
        last_port: friend.port,
        first_seen_ms: friend
            .last_seen
            .map(|last_seen| last_seen.timestamp_millis())
            .unwrap_or_default(),
        last_seen_ms: friend
            .last_seen
            .map(|last_seen| last_seen.timestamp_millis()),
    })
}

pub(crate) fn persist_server(
    metadata: &MetadataStore,
    server: &ServerInfo,
    enabled: bool,
) -> Result<()> {
    metadata.upsert_server(&MetadataServer {
        address: server.address.clone(),
        port: server.port,
        name: server.name.clone(),
        description: server.description.clone(),
        server_priority: server.priority.clone(),
        static_server: server.static_server,
        enabled,
        failed_count: server.failed_count,
        ping_ms: (server.ping != 0).then_some(server.ping),
        users: server.users,
        files: server.files,
        soft_files: server.soft_files,
        hard_files: server.hard_files,
        version: server.version.clone(),
        obfuscation_tcp_port: server.obfuscation_tcp_port,
        udp_flags: server.udp_flags,
    })
}

fn category_from_metadata(category: MetadataCategory) -> Category {
    Category {
        id: category.id,
        name: category.name,
        path: category.path,
        comment: category.comment,
        priority: category.sort_order,
        color: category.color,
    }
}

fn friend_from_metadata(friend: MetadataFriend) -> Friend {
    Friend {
        user_hash: friend.user_hash,
        name: friend.name,
        last_seen: friend
            .last_seen_ms
            .and_then(DateTime::<Utc>::from_timestamp_millis),
        address: friend.last_address,
        port: friend.last_port,
    }
}

fn server_from_metadata(server: MetadataServer) -> ServerInfo {
    let endpoint = server.endpoint();
    ServerInfo {
        address: server.address,
        port: server.port,
        endpoint,
        name: server.name,
        priority: server.server_priority,
        static_server: server.static_server,
        enabled: server.enabled,
        connected: false,
        connecting: false,
        current: false,
        description: server.description,
        dyn_ip: String::new(),
        failed_count: server.failed_count,
        hard_files: server.hard_files,
        ip: String::new(),
        ping: server.ping_ms.unwrap_or_default(),
        soft_files: server.soft_files,
        version: server.version,
        obfuscation_tcp_port: server.obfuscation_tcp_port,
        udp_flags: server.udp_flags,
        users: server.users,
        files: server.files,
        host_name: None,
        host_name_status: None,
        host_name_resolved_at: None,
        host_name_error: None,
    }
}
