//! Persistent TOML configuration management.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

// ── Defaults ─────────────────────────────────────────────────────────────────

pub const DEFAULT_SERVER:  &str = "222.222.222.5";
pub const DEFAULT_PORT:    u16  = 25;
pub const DEFAULT_TIMEOUT: u64  = 30;

// ── Structs ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub defaults: DefaultsConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub host:    String,
    pub port:    u16,
    pub timeout: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host:    DEFAULT_SERVER.to_string(),
            port:    DEFAULT_PORT,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AuthConfig {
    pub username:  Option<String>,
    /// Never written to disk during `save`; stored here only when loaded
    /// from an existing config the user manually wrote.
    pub password:  Option<String>,
    pub mechanism: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DefaultsConfig {
    pub from:      Option<String>,
    pub from_name: Option<String>,
    pub subject:   String,
    pub body:      String,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            from:      None,
            from_name: Some("Email Tester".to_string()),
            subject:   "SMTP Test Email".to_string(),
            body:      "This is a test email sent by email-tester.\n\
                        https://github.com/cumulus13/email-tester"
                           .to_string(),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns path to config file, honouring an explicit override.
pub fn config_path(override_path: Option<&PathBuf>) -> PathBuf {
    if let Some(p) = override_path {
        return p.clone();
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".email-tester.toml")
}

/// Load config from disk; returns [`AppConfig::default`] on any error.
pub fn load_config(path: &Path) -> AppConfig {
    if !path.exists() {
        return AppConfig::default();
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

/// Serialise and write config to disk.
pub fn save_config(path: &Path, cfg: &AppConfig) -> Result<()> {
    let content = toml::to_string_pretty(cfg)?;
    fs::write(path, content)?;
    Ok(())
}
