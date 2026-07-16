use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiState {
    pub window: Option<WindowState>,
    pub selected_tab: Option<i32>,
    #[serde(default)]
    pub backend_base_url: Option<String>,
    #[serde(default)]
    pub tables: BTreeMap<String, TableState>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowState {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    #[serde(default)]
    pub maximized: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TableState {
    pub sort_column: Option<i32>,
    #[serde(default)]
    pub sort_descending: bool,
    #[serde(default)]
    pub column_widths: Vec<f32>,
}

pub fn load() -> UiState {
    let Ok(path) = state_path() else {
        return UiState::default();
    };
    let Ok(bytes) = fs::read(path) else {
        return UiState::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(state: &UiState) -> Result<PathBuf> {
    let path = state_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create UI state directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(state).context("failed to encode UI state")?;
    fs::write(&path, bytes)
        .with_context(|| format!("failed to write UI state {}", path.display()))?;
    Ok(path)
}

pub fn reset() -> Result<PathBuf> {
    let path = state_path()?;
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to remove UI state {}", path.display()));
        }
    }
    Ok(path)
}

pub fn state_path() -> Result<PathBuf> {
    let mut base = config_base_dir().context("failed to resolve UI config directory")?;
    base.push("eMuleBB");
    base.push("emulebb-rust-ui");
    base.push("ui-state.json");
    Ok(base)
}

fn config_base_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        env::var_os("HOME").map(|home| {
            let mut path = PathBuf::from(home);
            path.push("Library");
            path.push("Application Support");
            path
        })
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|home| {
                    let mut path = PathBuf::from(home);
                    path.push(".config");
                    path
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_state_persists_backend_url_without_secret_fields() {
        let state = UiState {
            backend_base_url: Some("http://192.0.2.10:4711/api/v1".to_string()),
            ..UiState::default()
        };

        let json = serde_json::to_string(&state).expect("serialize UI state");

        assert!(json.contains("backendBaseUrl"));
        assert!(json.contains("192.0.2.10"));
        assert!(!json.contains("apiKey"));
        assert!(!json.contains("api-key"));
    }

    #[test]
    fn ui_state_accepts_older_layout_only_state() {
        let state: UiState =
            serde_json::from_str(r#"{"selectedTab":2,"tables":{}}"#).expect("parse UI state");

        assert_eq!(state.selected_tab, Some(2));
        assert_eq!(state.backend_base_url, None);
    }
}
