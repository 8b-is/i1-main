//! Signal records: near-zero TTL version-check records.
//!
//! Solves the high-TTL vulnerability window. Clients check the 30s-TTL
//! signal record to see if their cached blocklist is stale. If the serial
//! changed, they re-query specific IPs they care about.
//!
//! Record: `_v.bl.i1.is  30  IN  TXT  "serial=2026021701;entries=4523;updated=2026-02-17T14:30Z"`

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Signal record data for zone version tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalData {
    /// Monotonically increasing serial number (`YYYYMMDDnn` format).
    pub serial: u64,

    /// Total number of entries in the zone.
    pub entries: u32,

    /// Last update timestamp.
    pub updated: DateTime<Utc>,
}

impl SignalData {
    /// Create a new signal with the current timestamp.
    #[must_use]
    pub fn new(serial: u64, entries: u32) -> Self {
        Self {
            serial,
            entries,
            updated: Utc::now(),
        }
    }

    /// Increment the serial and update timestamp.
    pub fn bump(&mut self, new_entry_count: u32) {
        self.serial += 1;
        self.entries = new_entry_count;
        self.updated = Utc::now();
    }

    /// Encode as a TXT record value string.
    #[must_use]
    pub fn to_txt(&self) -> String {
        format!(
            "serial={};entries={};updated={}",
            self.serial,
            self.entries,
            self.updated.format("%Y-%m-%dT%H:%MZ")
        )
    }

    /// Parse from a TXT record value string.
    pub fn from_txt(txt: &str) -> crate::Result<Self> {
        let mut serial = None;
        let mut entries = None;
        let mut updated = None;

        for part in txt.split(';') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "serial" => {
                        serial = Some(value.parse::<u64>().map_err(|e| {
                            crate::SrvError::Encoding(format!("invalid serial: {e}"))
                        })?);
                    }
                    "entries" => {
                        entries = Some(value.parse::<u32>().map_err(|e| {
                            crate::SrvError::Encoding(format!("invalid entries: {e}"))
                        })?);
                    }
                    "updated" => {
                        updated = Some(value.to_string());
                    }
                    _ => {} // Ignore unknown fields for forward compat.
                }
            }
        }

        let serial =
            serial.ok_or_else(|| crate::SrvError::Encoding("missing serial field".into()))?;
        let entries =
            entries.ok_or_else(|| crate::SrvError::Encoding("missing entries field".into()))?;
        let updated_str =
            updated.ok_or_else(|| crate::SrvError::Encoding("missing updated field".into()))?;

        // Parse the timestamp. Our format ends with literal 'Z' (UTC),
        // so we parse with NaiveDateTime and assume UTC.
        let updated = chrono::NaiveDateTime::parse_from_str(&updated_str, "%Y-%m-%dT%H:%MZ")
            .map(|naive| naive.and_utc())
            .or_else(|_| {
                DateTime::parse_from_rfc3339(&updated_str).map(|dt| dt.with_timezone(&Utc))
            })
            .map_err(|e| crate::SrvError::Encoding(format!("invalid timestamp: {e}")))?;

        Ok(Self {
            serial,
            entries,
            updated,
        })
    }

    /// Generate the DNS query name for a zone's signal record.
    #[must_use]
    pub fn query_name(zone: &str) -> String {
        format!("_v.{zone}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_roundtrip() {
        let signal = SignalData::new(2_026_021_701, 4523);
        let txt = signal.to_txt();

        assert!(txt.contains("serial=2026021701"));
        assert!(txt.contains("entries=4523"));
        assert!(txt.contains("updated="));

        let parsed = SignalData::from_txt(&txt).unwrap();
        assert_eq!(parsed.serial, signal.serial);
        assert_eq!(parsed.entries, signal.entries);
    }

    #[test]
    fn test_signal_bump() {
        let mut signal = SignalData::new(1, 100);
        signal.bump(150);
        assert_eq!(signal.serial, 2);
        assert_eq!(signal.entries, 150);
    }

    #[test]
    fn test_query_name() {
        assert_eq!(SignalData::query_name("bl.i1.is."), "_v.bl.i1.is.");
    }
}
