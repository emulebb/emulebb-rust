use serde::Serialize;

use crate::{CORE_SETTING_SPECS, CoreSettingGroup};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SettingSurfaceClass {
    NormalControl,
    AdvancedControl,
    ExistingSectionResource,
    BootstrapOnly,
    NotUserFacing,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingSurfaceSpec {
    pub path: &'static str,
    pub class: SettingSurfaceClass,
    pub restart_required: bool,
    pub ui_section: &'static str,
    pub route: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsSectionResourceSpec {
    pub name: &'static str,
    pub class: SettingSurfaceClass,
    pub route: &'static str,
    pub ui_section: &'static str,
    pub description: &'static str,
}

const fn app_setting(
    path: &'static str,
    class: SettingSurfaceClass,
    restart_required: bool,
    ui_section: &'static str,
    description: &'static str,
) -> SettingSurfaceSpec {
    SettingSurfaceSpec {
        path,
        class,
        restart_required,
        ui_section,
        route: "/api/v1/app/settings",
        description,
    }
}

const APP_SETTINGS_SECTION_SURFACE: &[SettingSurfaceSpec] = &[
    app_setting(
        "daemon.incomingDir",
        SettingSurfaceClass::NormalControl,
        false,
        "Storage",
        "Finished-file delivery directory.",
    ),
    app_setting(
        "daemon.p2pBindIp",
        SettingSurfaceClass::NormalControl,
        true,
        "Network",
        "P2P bind IPv4 address.",
    ),
    app_setting(
        "daemon.p2pBindInterface",
        SettingSurfaceClass::NormalControl,
        true,
        "Network",
        "Preferred P2P bind interface.",
    ),
    app_setting(
        "daemon.ed2kUserHash",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Identity",
        "Persisted local eD2K identity override.",
    ),
    app_setting(
        "daemon.hostnameLookup.enabled",
        SettingSurfaceClass::AdvancedControl,
        false,
        "Network",
        "Reverse hostname lookup worker.",
    ),
    app_setting(
        "daemon.hostnameLookup.dnsServers",
        SettingSurfaceClass::AdvancedControl,
        false,
        "Network",
        "Optional DNS server list for hostname lookup.",
    ),
    app_setting(
        "daemon.hostnameLookup.cacheTtlSecs",
        SettingSurfaceClass::AdvancedControl,
        false,
        "Network",
        "Hostname lookup cache TTL.",
    ),
    app_setting(
        "daemon.hostnameLookup.maxLookupsPerTick",
        SettingSurfaceClass::AdvancedControl,
        false,
        "Network",
        "Hostname lookup batch size.",
    ),
    app_setting(
        "daemon.hostnameLookup.tickIntervalSecs",
        SettingSurfaceClass::AdvancedControl,
        false,
        "Network",
        "Hostname lookup worker interval.",
    ),
    app_setting(
        "ed2k.listenPort",
        SettingSurfaceClass::NormalControl,
        true,
        "Network",
        "eD2K TCP listen port.",
    ),
    app_setting(
        "ed2k.obfuscationEnabled",
        SettingSurfaceClass::NormalControl,
        true,
        "Network",
        "Enable eD2K protocol obfuscation.",
    ),
    app_setting(
        "ed2k.probeSearchTerm",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Diagnostics",
        "Synthetic startup probe term.",
    ),
    app_setting(
        "ed2k.connectTimeoutSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Network",
        "Peer connection timeout.",
    ),
    app_setting(
        "ed2k.serverConnectTimeoutSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Servers",
        "Server connection timeout.",
    ),
    app_setting(
        "ed2k.callbackTimeoutSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Servers",
        "Server callback timeout.",
    ),
    app_setting(
        "ed2k.reconnectIntervalSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Servers",
        "Server reconnect interval.",
    ),
    app_setting(
        "ed2k.reconnectEnabled",
        SettingSurfaceClass::NormalControl,
        true,
        "Servers",
        "Reconnect after server disconnect.",
    ),
    app_setting(
        "ed2k.safeServerConnect",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Servers",
        "Shadowed by core safe server connection settings.",
    ),
    app_setting(
        "ed2k.keepaliveSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Network",
        "eD2K keepalive interval.",
    ),
    app_setting(
        "ed2k.sessionRotationSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Transfers",
        "Upload session rotation interval.",
    ),
    app_setting(
        "ed2k.maxConcurrentDownloads",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Transfers",
        "Concurrent download runtime cap.",
    ),
    app_setting(
        "ed2k.maxNewConnectionsPerFiveSeconds",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Network",
        "New outgoing connection budget.",
    ),
    app_setting(
        "ed2k.maxHalfOpenConnections",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Network",
        "Half-open outgoing connection budget.",
    ),
    app_setting(
        "ed2k.maxSourcesPerFile",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Transfers",
        "Per-transfer source cap.",
    ),
    app_setting(
        "ed2k.maxParallelDownloadPeers",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Transfers",
        "Per-transfer parallel peer cap.",
    ),
    app_setting(
        "ed2k.keywordServerAttemptBudget",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Search",
        "Server keyword search attempt budget.",
    ),
    app_setting(
        "ed2k.exactHashKeywordServerAttemptBudget",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Search",
        "Server exact-hash keyword search attempt budget.",
    ),
    app_setting(
        "ed2k.sourceServerAttemptBudget",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Search",
        "Server source lookup attempt budget.",
    ),
    app_setting(
        "ed2k.uploadQueue.activeSlots",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Startup upload slot count before live core settings apply.",
    ),
    app_setting(
        "ed2k.uploadQueue.elasticPercent",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Startup upload elasticity before live core settings apply.",
    ),
    app_setting(
        "ed2k.uploadQueue.uploadLimitBytesPerSec",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Startup upload byte budget before live core settings apply.",
    ),
    app_setting(
        "ed2k.uploadQueue.elasticUnderfillBytesPerSec",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Upload slot underfill threshold.",
    ),
    app_setting(
        "ed2k.uploadQueue.elasticUnderfillSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Upload slot underfill duration.",
    ),
    app_setting(
        "ed2k.uploadQueue.waitingCapacity",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Startup queue capacity before live core settings apply.",
    ),
    app_setting(
        "ed2k.uploadQueue.waitingTimeoutSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Waiting upload timeout.",
    ),
    app_setting(
        "ed2k.uploadQueue.grantedTimeoutSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Granted slot idle timeout.",
    ),
    app_setting(
        "ed2k.uploadQueue.uploadTimeoutSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Active upload timeout.",
    ),
    app_setting(
        "ed2k.uploadQueue.sessionTransferPercent",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Per-session upload completion target.",
    ),
    app_setting(
        "ed2k.uploadQueue.sessionTimeLimitSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Uploads",
        "Per-session upload time cap.",
    ),
    app_setting(
        "ed2k.downloadLimitBytesPerSec",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Transfers",
        "Startup download byte budget before live core settings apply.",
    ),
    app_setting(
        "ed2k.enableUdpReask",
        SettingSurfaceClass::NormalControl,
        true,
        "Transfers",
        "Enable UDP source reask.",
    ),
    app_setting(
        "ed2k.publishEmuleRustIdentity",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Network",
        "Advertise the Rust client identity string.",
    ),
    app_setting(
        "ed2k.addServersFromServer",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Servers",
        "Shadowed by core advertised-server import settings.",
    ),
    app_setting(
        "ed2k.deadServerRetries",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Servers",
        "Retries before marking a server dead.",
    ),
    app_setting(
        "kad.listenPort",
        SettingSurfaceClass::NormalControl,
        true,
        "Network",
        "Kad UDP listen port.",
    ),
    app_setting(
        "kad.bootstrapMinRoutingContacts",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Kad",
        "Minimum contacts before considering Kad bootstrapped.",
    ),
    app_setting(
        "kad.localStoreEnabled",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Kad",
        "Enable local Kad indexing.",
    ),
    app_setting(
        "kad.localStoreKeywordTtlSecs",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad keyword index TTL.",
    ),
    app_setting(
        "kad.localStoreSourceTtlSecs",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad source index TTL.",
    ),
    app_setting(
        "kad.localStoreNotesTtlSecs",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad notes index TTL.",
    ),
    app_setting(
        "kad.localStoreKeywordCapacity",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad keyword index capacity.",
    ),
    app_setting(
        "kad.localStoreSourceCapacity",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad source index capacity.",
    ),
    app_setting(
        "kad.localStoreNotesCapacity",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad notes index capacity.",
    ),
    app_setting(
        "kad.localStoreSourcePerFileCapacity",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Per-file Kad source index capacity.",
    ),
    app_setting(
        "kad.localStoreNotesPerFileCapacity",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Per-file Kad notes index capacity.",
    ),
    app_setting(
        "kad.publishSharedFilesEnabled",
        SettingSurfaceClass::NormalControl,
        true,
        "Kad",
        "Publish shared files into Kad.",
    ),
    app_setting(
        "kad.republishIntervalSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Kad",
        "Kad shared-file republish interval.",
    ),
    app_setting(
        "kad.publishContactFanout",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Kad",
        "Kad publish fanout.",
    ),
    app_setting(
        "kad.udpFirewallCheckEnabled",
        SettingSurfaceClass::NormalControl,
        true,
        "Kad",
        "Enable Kad UDP firewall checks.",
    ),
    app_setting(
        "kad.udpFirewallCheckIntervalSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Kad",
        "Kad UDP firewall check interval.",
    ),
    app_setting(
        "kad.tcpFirewallCheckEnabled",
        SettingSurfaceClass::NormalControl,
        true,
        "Kad",
        "Enable Kad TCP firewall checks.",
    ),
    app_setting(
        "kad.tcpFirewallCheckIntervalSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "Kad",
        "Kad TCP firewall check interval.",
    ),
    app_setting(
        "kad.buddyEnabled",
        SettingSurfaceClass::NormalControl,
        true,
        "Kad",
        "Enable Kad buddy behavior.",
    ),
    app_setting(
        "kad.routingMaintenanceEnabled",
        SettingSurfaceClass::NormalControl,
        true,
        "Kad",
        "Enable Kad routing maintenance.",
    ),
    app_setting(
        "kad.snoopQueueDedupWindowSecs",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad snoop queue deduplication window.",
    ),
    app_setting(
        "kad.snoopQueueGeneralMaxQueriesPer600s",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad general query budget.",
    ),
    app_setting(
        "kad.snoopQueueGeneralDrainCooldownSecs",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad general query drain cooldown.",
    ),
    app_setting(
        "kad.snoopQueueSourceMaxQueriesPer600s",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad source query budget.",
    ),
    app_setting(
        "kad.snoopQueueSourceDrainCooldownSecs",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad source query drain cooldown.",
    ),
    app_setting(
        "kad.snoopQueueSourceStopAfterResults",
        SettingSurfaceClass::NotUserFacing,
        true,
        "Kad",
        "Kad source query result stop threshold.",
    ),
    app_setting(
        "nat.enabled",
        SettingSurfaceClass::NormalControl,
        true,
        "NAT",
        "Enable NAT port mapping.",
    ),
    app_setting(
        "nat.requireInitialMapping",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "Require startup NAT mapping success.",
    ),
    app_setting(
        "nat.backendOrder",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "NAT backend preference order.",
    ),
    app_setting(
        "nat.bindIp",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "Local IP used for NAT discovery.",
    ),
    app_setting(
        "nat.igdIp",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "Pinned IGD address.",
    ),
    app_setting(
        "nat.minissdpdSocket",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "miniSSDPd socket path.",
    ),
    app_setting(
        "nat.ssdpLocalPort",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "Pinned SSDP local port.",
    ),
    app_setting(
        "nat.discoveryTimeoutSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "NAT discovery timeout.",
    ),
    app_setting(
        "nat.leaseDurationSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "Requested NAT lease duration.",
    ),
    app_setting(
        "nat.renewMarginSecs",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "NAT lease renewal margin.",
    ),
    app_setting(
        "nat.externalIpOverride",
        SettingSurfaceClass::AdvancedControl,
        true,
        "NAT",
        "Manual external IP override.",
    ),
    app_setting(
        "vpnGuard.enabled",
        SettingSurfaceClass::NormalControl,
        true,
        "VPN Guard",
        "Enable VPN public-IP guard.",
    ),
    app_setting(
        "vpnGuard.mode",
        SettingSurfaceClass::NormalControl,
        true,
        "VPN Guard",
        "VPN guard enforcement mode.",
    ),
    app_setting(
        "vpnGuard.allowedPublicIpCidrs",
        SettingSurfaceClass::NormalControl,
        true,
        "VPN Guard",
        "Allowed public IP CIDR list.",
    ),
    app_setting(
        "ipFilter.enabled",
        SettingSurfaceClass::NormalControl,
        true,
        "IP Filter",
        "Enable ipfilter.dat loading.",
    ),
    app_setting(
        "ipFilter.path",
        SettingSurfaceClass::NormalControl,
        true,
        "IP Filter",
        "ipfilter.dat path.",
    ),
    app_setting(
        "ipFilter.level",
        SettingSurfaceClass::NormalControl,
        true,
        "IP Filter",
        "IP filter level threshold.",
    ),
];

const SETTINGS_SECTION_RESOURCES: &[SettingsSectionResourceSpec] = &[
    SettingsSectionResourceSpec {
        name: "sharedDirectories",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/shared-directories",
        ui_section: "Sharing",
        description: "Shared root ownership and reload operations.",
    },
    SettingsSectionResourceSpec {
        name: "categories",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/categories",
        ui_section: "Categories",
        description: "Transfer category paths and priorities.",
    },
    SettingsSectionResourceSpec {
        name: "servers",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/servers",
        ui_section: "Servers",
        description: "eD2K server repository, import, and connect operations.",
    },
    SettingsSectionResourceSpec {
        name: "kad",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/kad",
        ui_section: "Kad",
        description: "Kad status, bootstrap, import, and control operations.",
    },
    SettingsSectionResourceSpec {
        name: "diagnostics",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/diagnostics",
        ui_section: "Diagnostics",
        description: "Runtime diagnostics and diagnostic operations.",
    },
];

pub fn app_settings_surface_inventory() -> Vec<SettingSurfaceSpec> {
    let mut inventory =
        Vec::with_capacity(CORE_SETTING_SPECS.len() + APP_SETTINGS_SECTION_SURFACE.len());
    inventory.extend(CORE_SETTING_SPECS.iter().map(|field| {
        app_setting(
            core_setting_path(field.key),
            core_setting_class(field.advanced),
            field.restart_required,
            core_setting_ui_section(field.group),
            field.description,
        )
    }));
    inventory.extend(APP_SETTINGS_SECTION_SURFACE.iter().copied());
    inventory.sort_by(|left, right| left.path.cmp(right.path));
    inventory
}

pub fn settings_section_resource_inventory() -> &'static [SettingsSectionResourceSpec] {
    SETTINGS_SECTION_RESOURCES
}

fn core_setting_class(advanced: bool) -> SettingSurfaceClass {
    if advanced {
        SettingSurfaceClass::AdvancedControl
    } else {
        SettingSurfaceClass::NormalControl
    }
}

fn core_setting_ui_section(group: CoreSettingGroup) -> &'static str {
    match group {
        CoreSettingGroup::Network => "Network",
        CoreSettingGroup::Transfers => "Transfers",
        CoreSettingGroup::Server => "Servers",
        CoreSettingGroup::Kad => "Kad",
        CoreSettingGroup::Safety => "Safety",
    }
}

fn core_setting_path(key: &'static str) -> &'static str {
    match key {
        "uploadLimitKiBps" => "core.uploadLimitKiBps",
        "downloadLimitKiBps" => "core.downloadLimitKiBps",
        "maxConnections" => "core.maxConnections",
        "maxConnectionsPerFiveSeconds" => "core.maxConnectionsPerFiveSeconds",
        "maxSourcesPerFile" => "core.maxSourcesPerFile",
        "uploadClientDataRate" => "core.uploadClientDataRate",
        "maxUploadSlots" => "core.maxUploadSlots",
        "uploadSlotElasticPercent" => "core.uploadSlotElasticPercent",
        "queueSize" => "core.queueSize",
        "autoConnect" => "core.autoConnect",
        "reconnect" => "core.reconnect",
        "creditSystem" => "core.creditSystem",
        "safeServerConnect" => "core.safeServerConnect",
        "addServersFromServer" => "core.addServersFromServer",
        "networkKademlia" => "core.networkKademlia",
        "networkEd2k" => "core.networkEd2k",
        _ => panic!("missing settings surface path for core setting"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use crate::{
        AppSettings, SettingSurfaceClass, app_settings_surface_inventory,
        settings_section_resource_inventory,
    };

    #[test]
    fn app_settings_surface_inventory_covers_serialized_fields() {
        let mut expected = BTreeSet::new();
        collect_leaf_paths(
            "",
            &serde_json::to_value(AppSettings::default()).unwrap(),
            &mut expected,
        );
        let actual = app_settings_surface_inventory()
            .into_iter()
            .map(|entry| entry.path.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn app_settings_surface_inventory_has_no_duplicate_paths() {
        let inventory = app_settings_surface_inventory();
        let unique = inventory
            .iter()
            .map(|entry| entry.path)
            .collect::<BTreeSet<_>>();

        assert_eq!(unique.len(), inventory.len());
    }

    #[test]
    fn shadowed_ed2k_server_toggles_are_not_user_facing() {
        let inventory = app_settings_surface_inventory();
        let class_for = |path: &str| {
            inventory
                .iter()
                .find(|entry| entry.path == path)
                .map(|entry| entry.class)
                .unwrap()
        };

        assert_eq!(
            class_for("ed2k.safeServerConnect"),
            SettingSurfaceClass::NotUserFacing
        );
        assert_eq!(
            class_for("ed2k.addServersFromServer"),
            SettingSurfaceClass::NotUserFacing
        );
    }

    #[test]
    fn settings_section_resources_are_classified_as_existing_resources() {
        let resources = settings_section_resource_inventory();

        assert!(
            resources
                .iter()
                .any(|entry| entry.route == "/api/v1/diagnostics")
        );
        assert!(
            resources
                .iter()
                .all(|entry| entry.class == SettingSurfaceClass::ExistingSectionResource)
        );
    }

    fn collect_leaf_paths(prefix: &str, value: &Value, output: &mut BTreeSet<String>) {
        match value {
            Value::Object(object) if !object.is_empty() => {
                for (key, nested) in object {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    collect_leaf_paths(&path, nested, output);
                }
            }
            _ => {
                output.insert(prefix.to_string());
            }
        }
    }
}
