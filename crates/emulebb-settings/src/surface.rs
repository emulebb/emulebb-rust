use serde::Serialize;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SettingSurfaceClass {
    ExistingSectionResource,
    BootstrapOnly,
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

pub const BOOTSTRAP_SETTINGS_SURFACE: &[SettingSurfaceSpec] = &[
    bootstrap_setting(
        "rest.bind_addr",
        "REST bind socket address. This remains bootstrap-only so the daemon can start safely.",
    ),
    bootstrap_setting(
        "rest.api_key",
        "REST API key. This remains bootstrap-only and is not exposed through REST.",
    ),
    bootstrap_setting(
        "rest.web_root_dir",
        "Optional WebUI root override used before the REST server starts.",
    ),
];

const fn bootstrap_setting(path: &'static str, description: &'static str) -> SettingSurfaceSpec {
    SettingSurfaceSpec {
        path,
        class: SettingSurfaceClass::BootstrapOnly,
        restart_required: true,
        ui_section: "Bootstrap REST",
        route: "emulebb-rust-settings.toml",
        description,
    }
}

const SETTINGS_SECTION_RESOURCES: &[SettingsSectionResourceSpec] = &[
    SettingsSectionResourceSpec {
        name: "libraryRoots",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/library/roots",
        ui_section: "Sharing",
        description: "Library root ownership and watch policy.",
    },
    SettingsSectionResourceSpec {
        name: "categories",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/categories",
        ui_section: "Categories",
        description: "Category paths and download assignment.",
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
        name: "network",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/network",
        ui_section: "Network",
        description: "Live P2P port, binding, interface, and VPN Guard status.",
    },
    SettingsSectionResourceSpec {
        name: "nat",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/nat",
        ui_section: "NAT",
        description: "Live NAT gateway, mapping, external address, error status, and refresh operation.",
    },
    SettingsSectionResourceSpec {
        name: "ipFilter",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/ip-filter",
        ui_section: "IP Filter",
        description: "IP filter status and live reload operation.",
    },
    SettingsSectionResourceSpec {
        name: "vpnGuard",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/vpn-guard",
        ui_section: "VPN Guard",
        description: "VPN Guard startup, binding, egress verdict, and probe operation.",
    },
    SettingsSectionResourceSpec {
        name: "diagnostics",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/diagnostics",
        ui_section: "Diagnostics",
        description: "Runtime diagnostics and diagnostic operations.",
    },
    SettingsSectionResourceSpec {
        name: "logs",
        class: SettingSurfaceClass::ExistingSectionResource,
        route: "/api/v1/logs",
        ui_section: "Logs",
        description: "Recent daemon log lines and retained-log clear operation.",
    },
];

/// Native metadata and schemas share the canonical declaration and are immutable.
#[derive(Serialize)]
pub struct SettingsSurfaceData {
    pub fields: &'static [crate::product::SettingSpec],
    pub schemas: &'static serde_json::Value,
    pub bootstrap: &'static [SettingSurfaceSpec],
    pub resources: &'static [SettingsSectionResourceSpec],
}

pub fn settings_surface() -> SettingsSurfaceData {
    static SCHEMAS: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    SettingsSurfaceData {
        fields: crate::product::setting_specs(),
        schemas: SCHEMAS.get_or_init(crate::product::settings_schemas),
        bootstrap: BOOTSTRAP_SETTINGS_SURFACE,
        resources: SETTINGS_SECTION_RESOURCES,
    }
}

pub fn settings_section_resource_inventory() -> &'static [SettingsSectionResourceSpec] {
    SETTINGS_SECTION_RESOURCES
}
pub fn bootstrap_settings_surface_inventory() -> &'static [SettingSurfaceSpec] {
    BOOTSTRAP_SETTINGS_SURFACE
}
