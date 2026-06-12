use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use chrono::{DateTime, Utc};
use emulebb_metadata::{MetadataCategory, MetadataFriend, MetadataServer, MetadataStore};

use crate::{
    Category, CoreState, Friend, Preferences, ServerInfo, SharedDirectoryRoot, default_categories,
    default_preferences,
};

const CORE_PREFERENCES_KEY: &str = "core.preferences";

pub(crate) fn load_core_state(
    metadata: &MetadataStore,
    shared_directories: Vec<SharedDirectoryRoot>,
) -> Result<CoreState> {
    let preferences = match metadata.load_preference_json(CORE_PREFERENCES_KEY)? {
        Some(value) => serde_json::from_str(&value)?,
        None => default_preferences(),
    };
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
        if !server.enabled {
            disabled_servers.insert(server.endpoint);
            continue;
        }
        if server.port != 0 && !server.address.is_empty() {
            servers.insert(server.endpoint.clone(), server_from_metadata(server));
        }
    }

    Ok(CoreState {
        searches: crate::search_state::load_searches(metadata)?,
        transfers: HashMap::new(),
        preferences,
        categories,
        next_category_id,
        friends,
        servers,
        server_overrides: HashMap::new(),
        disabled_servers,
        banned_source_clients: HashSet::new(),
        active_download_attempts: HashSet::new(),
        shared_directories,
        unshared_hashes: metadata.load_unshared_file_hashes()?.into_iter().collect(),
        kad_running: false,
    })
}

pub(crate) fn persist_preferences(
    metadata: &MetadataStore,
    preferences: &Preferences,
) -> Result<()> {
    metadata.put_preference_json(CORE_PREFERENCES_KEY, &serde_json::to_string(preferences)?)?;
    Ok(())
}

pub(crate) fn persist_category(metadata: &MetadataStore, category: &Category) -> Result<()> {
    metadata.upsert_category(&MetadataCategory {
        id: category.id,
        name: category.name.clone(),
        path: category.path.clone(),
        comment: category.comment.clone(),
        priority: category.priority,
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
        endpoint: server.endpoint.clone(),
        address: server.address.clone(),
        port: server.port,
        name: server.name.clone(),
        description: server.description.clone(),
        priority: server.priority.clone(),
        static_server: server.static_server,
        enabled,
        failed_count: server.failed_count,
        ping_ms: (server.ping != 0).then_some(server.ping),
        users: server.users,
        files: server.files,
        soft_files: server.soft_files,
        hard_files: server.hard_files,
        version: server.version.clone(),
    })
}

fn category_from_metadata(category: MetadataCategory) -> Category {
    Category {
        id: category.id,
        name: category.name,
        path: category.path,
        comment: category.comment,
        priority: category.priority,
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
    ServerInfo {
        address: server.address,
        port: server.port,
        endpoint: server.endpoint,
        name: server.name,
        priority: server.priority,
        static_server: server.static_server,
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
        users: server.users,
        files: server.files,
    }
}
