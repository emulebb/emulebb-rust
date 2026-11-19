use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{Category, CoreState, Friend, ServerInfo, SharedDirectoryRoot};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use emulebb_ed2k::long_path::normal_path_display;
use emulebb_metadata::{MetadataCategory, MetadataFriend, MetadataServer, MetadataStore};

pub(crate) fn load_core_state(
    metadata: &MetadataStore,
    shared_directories: Vec<SharedDirectoryRoot>,
) -> Result<CoreState> {
    let settings = crate::settings::RuntimeSettings::startup(metadata.load_app_settings()?);
    let categories = metadata
        .load_categories()?
        .into_iter()
        .map(|category| (category.id, category_from_metadata(category)))
        .collect();

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

    metadata.interrupt_collecting_searches(chrono::Utc::now().timestamp())?;

    Ok(CoreState {
        searches: HashMap::new(),
        // Startup durably ends interrupted collection; no cancellation handles survive.
        search_cancels: HashMap::new(),
        // Network trust votes apply only to evidence received in this process.
        kad_aich_search_votes: Default::default(),
        transfers: HashMap::new(),
        settings,
        categories,
        friends,
        servers,
        server_overrides: HashMap::new(),
        disabled_servers,
        server_fail_counts: HashMap::new(),

        active_download_peer_endpoints: std::collections::HashMap::new(),
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
        monitor_shared_hashes: HashMap::new(),
        kad_running: false,
        last_source_count_emit_at: None,
    })
}

pub(crate) fn persist_friend(
    metadata: &MetadataStore,
    friend: &Friend,
) -> Result<emulebb_metadata::FriendWriteTiming> {
    metadata.upsert_friend_timed(&MetadataFriend {
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
        dynamic_host: server.dyn_ip.clone(),
        auxiliary_ports: server.auxiliary_ports.clone(),
        server_priority: server.priority.clone(),
        static_server: server.static_server,
        enabled,
        failed_count: server.failed_count,
        ping_ms: (server.ping != 0).then_some(server.ping),
        users: server.users,
        files: server.files,
        max_users: server.max_users,
        low_id_users: server.low_id_users,
        soft_files: server.soft_files,
        hard_files: server.hard_files,
        version: server.version.clone(),
        obfuscation_tcp_port: server.obfuscation_tcp_port,
        obfuscation_udp_port: server.obfuscation_udp_port,
        udp_flags: server.udp_flags,
        udp_key: server.udp_key,
        udp_key_ip: server.udp_key_ip,
    })
}

pub(crate) fn category_from_metadata(category: MetadataCategory) -> Category {
    Category {
        id: category.id,
        name: category.name,
        temp_dir: category.temp_dir,
        destination_dir: category.destination_dir,
        comment: category.comment,
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
        dyn_ip: server.dynamic_host,
        auxiliary_ports: server.auxiliary_ports,
        failed_count: server.failed_count,
        hard_files: server.hard_files,
        ip: String::new(),
        ping: server.ping_ms.unwrap_or_default(),
        soft_files: server.soft_files,
        offer_files_mode: None,
        offer_files_batch_max: None,
        offer_files_min_interval_ms: None,
        offer_files_fallback_reason: None,
        offer_files_published_entries: 0,
        offer_files_pending_entries: 0,
        version: server.version,
        obfuscation_tcp_port: server.obfuscation_tcp_port,
        obfuscation_udp_port: server.obfuscation_udp_port,
        udp_flags: server.udp_flags,
        udp_key: server.udp_key,
        udp_key_ip: server.udp_key_ip,
        max_users: server.max_users,
        low_id_users: server.low_id_users,
        users: server.users,
        files: server.files,
        host_name: None,
        host_name_status: None,
        host_name_resolved_at: None,
        host_name_error: None,
    }
}
