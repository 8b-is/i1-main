//! Node identity management.
//!
//! Each i1-srv node has a certificate signed by an i1-ca intermediate.
//! The certificate's SHA-256 hash is published as a TLSA record for
//! DANE-based trust verification.

// TODO: Phase 2 - implement NodeIdentity
// - Load or generate node certificate via i1-ca
// - Compute SHA-256 hash for TLSA record
// - Store identity in config directory
