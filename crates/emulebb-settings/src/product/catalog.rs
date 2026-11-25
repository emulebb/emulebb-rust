//! Canonical product settings with their types, defaults, and metadata.
use super::*;

setting_group!(SecurityTcpErrorFloodDetectionValues,SavedSecurityTcpErrorFloodDetection,SecurityTcpErrorFloodDetectionPartial,"security.tcpErrorFloodDetection", { leaves {
    enabled:bool = true => ("enabled",Rule::Boolean,Restart,"none"),
    interval_seconds:u32 = 3600 => ("intervalSeconds",Rule::Integer {min:60,max:86400,step:60},Restart,"seconds"),
    threshold:u32 = 10 => ("threshold",Rule::Integer {min:1,max:1000,step:1},Restart,"failures per interval"),
} branches {
}});

setting_group!(NetworkHostnameLookupValues,SavedNetworkHostnameLookup,NetworkHostnameLookupPartial,"network.hostnameLookup", { leaves {
    enabled:bool = false => ("enabled",Rule::Boolean,Live,"none"),
    dns_servers:Vec<SocketAddrV4> = Vec::new() => ("dnsServers",Rule::DnsServers,Live,"endpoints"),
} branches {
}});

setting_group!(NetworkConnectionsValues,SavedNetworkConnections,NetworkConnectionsPartial,"network.connections", { leaves {
    max_connections:u32 = 500 => ("maxConnections",Rule::Integer {min:1,max:2147483647,step:1},Live,"connections"),
    max_new_connections_per_five_seconds:u32 = 50 => ("maxNewConnectionsPerFiveSeconds",Rule::Integer {min:1,max:2147483647,step:1},Live,"connections per five seconds"),
    max_half_open_connections:u32 = 50 => ("maxHalfOpenConnections",Rule::Integer {min:1,max:2147483647,step:1},Restart,"connections"),
    connect_timeout_seconds:u64 = 30 => ("connectTimeoutSeconds",Rule::Integer {min:1,max:86400,step:1},Restart,"seconds"),
    callback_timeout_seconds:u64 = 45 => ("callbackTimeoutSeconds",Rule::Integer {min:1,max:86400,step:1},Restart,"seconds"),
} branches {
}});

setting_group!(SecurityIpFilterValues,SavedSecurityIpFilter,SecurityIpFilterPartial,"security.ipFilter", { leaves {
    enabled:bool = false => ("enabled",Rule::Boolean,Restart,"none"),
    file_path:Option<PathBuf> = None => ("filePath",Rule::Path,Restart,"none"),
    level:u32 = 127 => ("level",Rule::Integer {min:0,max:4294967295,step:1},Restart,"filter level"),
} branches {
}});

setting_group!(SecurityVpnGuardValues,SavedSecurityVpnGuard,SecurityVpnGuardPartial,"security.vpnGuard", { leaves {
    mode:VpnMode = VpnMode::Off => ("mode",Rule::VpnMode,Restart,"none"),
    allowed_public_ip_cidrs:Vec<Ipv4Net> = Vec::new() => ("allowedPublicIpCidrs",Rule::Ipv4Cidrs,Restart,"networks"),
} branches {
}});

setting_group!(TransfersUploadValues,SavedTransfersUpload,TransfersUploadPartial,"transfers.upload", { leaves {
    target_client_rate_bytes_per_second:u64 = 32768 => ("targetClientRateBytesPerSecond",Rule::Integer {min:1,max:4398046510080,step:1},Live,"bytes per second"),
    base_slots:u32 = 12 => ("baseSlots",Rule::Integer {min:1,max:64,step:1},Live,"slots"),
    elastic_percent:u32 = 80 => ("elasticPercent",Rule::Integer {min:0,max:100,step:1},Live,"percent"),
    queue_capacity:u32 = 10000 => ("queueCapacity",Rule::Integer {min:2000,max:10000,step:1},Live,"waiting peers"),
    session_transfer_percent:u32 = 90 => ("sessionTransferPercent",Rule::Integer {min:0,max:100,step:1},Restart,"percent of requested file"),
    session_time_limit_seconds:u64 = 7200 => ("sessionTimeLimitSeconds",Rule::Integer {min:0,max:86400,step:1},Restart,"seconds"),
    credit_system_enabled:bool = true => ("creditSystemEnabled",Rule::Boolean,Live,"none"),
    shared_files_visibility:SharedFilesVisibility = SharedFilesVisibility::Everyone => ("sharedFilesVisibility",Rule::SharedFilesVisibility,Live,"none"),
} branches {
}});

setting_group!(NetworkServersValues,SavedNetworkServers,NetworkServersPartial,"network.servers", { leaves {
    auto_reconnect:bool = true => ("autoReconnect",Rule::Boolean,Restart,"none"),
    safe_connect:bool = false => ("safeConnect",Rule::Boolean,Restart,"none"),
    use_priorities:bool = true => ("usePriorities",Rule::Boolean,Restart,"none"),
    static_only:bool = false => ("staticOnly",Rule::Boolean,Restart,"none"),
    accept_server_list_updates:bool = false => ("acceptServerListUpdates",Rule::Boolean,Restart,"none"),
    connect_timeout_seconds:u64 = 25 => ("connectTimeoutSeconds",Rule::Integer {min:1,max:86400,step:1},Restart,"seconds"),
    reconnect_interval_seconds:u64 = 30 => ("reconnectIntervalSeconds",Rule::Integer {min:1,max:86400,step:1},Restart,"seconds"),
    keepalive_minutes:u64 = 0 => ("keepaliveMinutes",Rule::Integer {min:0,max:1440,step:1},Restart,"whole minutes"),
    session_rotation_seconds:u64 = 0 => ("sessionRotationSeconds",Rule::Integer {min:0,max:86400,step:1},Restart,"seconds"),
    dead_server_retries:u64 = 1 => ("deadServerRetries",Rule::Integer {min:1,max:10,step:1},Restart,"failed attempts"),
} branches {
}});

setting_group!(NetworkNatValues,SavedNetworkNat,NetworkNatPartial,"network.nat", { leaves {
    enabled:bool = true => ("enabled",Rule::Boolean,Restart,"none"),
    require_initial_mapping:bool = false => ("requireInitialMapping",Rule::Boolean,Restart,"none"),
    backend_order:Vec<NatBackend> = vec![NatBackend::PcpNatpmp,NatBackend::Upnp] => ("backendOrder",Rule::NatBackends,Restart,"ordered backends"),
    pcp_server_ip:Option<Ipv4Addr> = None => ("pcpServerIp",Rule::Ipv4,Restart,"none"),
    igd_ip:Option<Ipv4Addr> = None => ("igdIp",Rule::Ipv4,Restart,"none"),
    external_ip_override:Option<Ipv4Addr> = None => ("externalIpOverride",Rule::Ipv4,Restart,"none"),
} branches {
}});

setting_group!(NetworkP2pValues,SavedNetworkP2p,NetworkP2pPartial,"network.p2p", { leaves {
    bind_ip:Option<Ipv4Addr> = None => ("bindIp",Rule::Ipv4,Restart,"none"),
    bind_interface:Option<String> = None => ("bindInterface",Rule::Text {min_bytes:1,max_bytes:256,forbid_controls:false},Restart,"none"),
    tcp_port:u16 = 20019 => ("tcpPort",Rule::Integer {min:1,max:65535,step:1},Restart,"port"),
    udp_port:u16 = 20020 => ("udpPort",Rule::Integer {min:1,max:65535,step:1},Restart,"port"),
} branches {
}});

setting_group!(TransfersValues,SavedTransfers,TransfersPartial,"transfers", { leaves {
    upload_limit_bytes_per_second:u64 = 6348800 => ("uploadLimitBytesPerSecond",Rule::Integer {min:1,max:4398046509056,step:1},Live,"bytes per second"),
    download_limit_bytes_per_second:u64 = 12499968 => ("downloadLimitBytesPerSecond",Rule::Integer {min:1,max:4398046509056,step:1},Live,"bytes per second"),
    max_concurrent_downloads:Option<u32> = None => ("maxConcurrentDownloads",Rule::Integer {min:1,max:2147483647,step:1},Live,"ordinary active-download ceiling; fixed 25% rare-opportunity burst allowed"),
    max_sources_per_file:u32 = 600 => ("maxSourcesPerFile",Rule::Integer {min:1,max:2147483647,step:1},Live,"sources per file"),
    max_parallel_download_peers:u32 = 2 => ("maxParallelDownloadPeers",Rule::Integer {min:1,max:2147483647,step:1},Restart,"peers per file"),
} branches {
    upload:(TransfersUploadValues,SavedTransfersUpload,TransfersUploadPartial) => "upload",
}});

setting_group!(SecurityValues,SavedSecurity,SecurityPartial,"security", { leaves {
    obfuscation_enabled:bool = true => ("obfuscationEnabled",Rule::Boolean,Restart,"none"),
} branches {
    vpn_guard:(SecurityVpnGuardValues,SavedSecurityVpnGuard,SecurityVpnGuardPartial) => "vpnGuard",
    ip_filter:(SecurityIpFilterValues,SavedSecurityIpFilter,SecurityIpFilterPartial) => "ipFilter",
    tcp_error_flood_detection:(SecurityTcpErrorFloodDetectionValues,SavedSecurityTcpErrorFloodDetection,SecurityTcpErrorFloodDetectionPartial) => "tcpErrorFloodDetection",
}});

setting_group!(NetworkValues,SavedNetwork,NetworkPartial,"network", { leaves {
    ed2k_enabled:bool = true => ("ed2kEnabled",Rule::Boolean,Restart,"none"),
    kad_enabled:bool = true => ("kadEnabled",Rule::Boolean,Restart,"none"),
    auto_connect:bool = true => ("autoConnect",Rule::Boolean,Restart,"none"),
    nickname:String = "eMule".into() => ("nickname",Rule::Text {min_bytes:1,max_bytes:128,forbid_controls:true},Restart,"none"),
} branches {
    p2p:(NetworkP2pValues,SavedNetworkP2p,NetworkP2pPartial) => "p2p",
    connections:(NetworkConnectionsValues,SavedNetworkConnections,NetworkConnectionsPartial) => "connections",
    servers:(NetworkServersValues,SavedNetworkServers,NetworkServersPartial) => "servers",
    hostname_lookup:(NetworkHostnameLookupValues,SavedNetworkHostnameLookup,NetworkHostnameLookupPartial) => "hostnameLookup",
    nat:(NetworkNatValues,SavedNetworkNat,NetworkNatPartial) => "nat",
}});

setting_group!(SharingValues,SavedSharing,SharingPartial,"sharing", { leaves {
    scan_on_startup:bool = true => ("scanOnStartup",Rule::Boolean,Restart,"none"),
    kad_publishing_enabled:bool = true => ("kadPublishingEnabled",Rule::Boolean,Restart,"none"),
} branches {
}});

setting_group!(StorageValues,SavedStorage,StoragePartial,"storage", { leaves {
    incoming_directory:PathBuf = PathBuf::from("incoming") => ("incomingDirectory",Rule::Path,Restart,"none"),
    temp_directory:PathBuf = PathBuf::from("temp") => ("tempDirectory",Rule::Path,Restart,"none"),
    min_free_profile_bytes:u64 = 1073741824 => ("minFreeProfileBytes",Rule::Integer {min:1073741824,max:5497558138880,step:1},Live,"bytes"),
    min_free_temp_bytes:u64 = 5368709120 => ("minFreeTempBytes",Rule::Integer {min:5368709120,max:5497558138880,step:1},Live,"bytes"),
    min_free_incoming_bytes:u64 = 5368709120 => ("minFreeIncomingBytes",Rule::Integer {min:5368709120,max:5497558138880,step:1},Live,"bytes"),
} branches {
}});

setting_group!(SettingsValues,SavedSettings,SettingsPartial,"", { leaves {
} branches {
    network:(NetworkValues,SavedNetwork,NetworkPartial) => "network",
    transfers:(TransfersValues,SavedTransfers,TransfersPartial) => "transfers",
    storage:(StorageValues,SavedStorage,StoragePartial) => "storage",
    sharing:(SharingValues,SavedSharing,SharingPartial) => "sharing",
    security:(SecurityValues,SavedSecurity,SecurityPartial) => "security",
}});
