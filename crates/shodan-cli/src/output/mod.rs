//! Output formatting for different formats.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Available output formats.
#[derive(Debug, Clone, Copy, Default, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Pretty-printed tables with colors
    #[default]
    Pretty,
    /// JSON output
    Json,
    /// CSV output
    Csv,
    /// YAML output
    Yaml,
}

impl FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" | "table" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            "yaml" | "yml" => Ok(Self::Yaml),
            _ => anyhow::bail!(
                "Unknown output format: {}\n\
                 Valid formats: pretty, json, csv, yaml",
                s
            ),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pretty => write!(f, "pretty"),
            Self::Json => write!(f, "json"),
            Self::Csv => write!(f, "csv"),
            Self::Yaml => write!(f, "yaml"),
        }
    }
}
