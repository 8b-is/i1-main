//! Configuration management.

use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::output::OutputFormat;

/// CLI configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Shodan API key.
    pub api_key: Option<String>,

    /// Default output format.
    pub output_format: Option<OutputFormat>,

    /// Show helpful tips after commands.
    #[serde(default = "default_true")]
    pub show_tips: bool,

    /// Always show explanations (as if --explain was passed).
    #[serde(default)]
    pub explain_by_default: bool,
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Get the config file path.
    pub fn path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("is", "i1", "showdi1")
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;

        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Load configuration from file.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content)?;

        Ok(config)
    }

    /// Save configuration to file.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        std::fs::write(&path, content)?;

        Ok(())
    }
}
