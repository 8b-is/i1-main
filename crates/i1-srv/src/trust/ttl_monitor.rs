//! TTL manipulation detection.
//!
//! If observed TTL from a resolver is consistently < 3600 when i1-srv
//! set it to 86400, warn that the user's DNS resolver may be tampering.
//!
//! ```text
//! WARNING: Your DNS resolver (8.8.8.8) is reducing TTLs.
//!   Expected: 86400s, Observed: 600s (consistently over 5 queries)
//!   Your provider may be manipulating DNS responses.
//! ```

// TODO: Phase 2 - implement TTL monitor
// - Track observed TTLs over multiple queries
// - Warn when consistently below expected values
// - Expose via `i1 srv ttl-check` CLI command
