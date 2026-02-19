//! DNS record encoding for threat intelligence data.
//!
//! Two encoding strategies:
//! - **DNSBL**: Reversed IP -> A record (127.0.0.X return codes)
//! - **TXT Intel**: Hybrid k=v pipe format + CBOR overflow for complex data

pub mod dnsbl;
pub mod signal;
pub mod txt_intel;
