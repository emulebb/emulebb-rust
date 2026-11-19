//! Canonical product settings and declaration-derived public metadata.

pub mod product;
mod surface;
pub use surface::{
    BOOTSTRAP_SETTINGS_SURFACE, SettingSurfaceClass, SettingSurfaceSpec,
    SettingsSectionResourceSpec, SettingsSurfaceData, bootstrap_settings_surface_inventory,
    settings_section_resource_inventory, settings_surface,
};
