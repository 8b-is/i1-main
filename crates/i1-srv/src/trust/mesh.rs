//! Trust mesh: cross-node DANE verification.
//!
//! Verification flow:
//! 1. Client gets referral: bl.i1.is NS -> node1.srv.i1.is
//! 2. Client queries a DIFFERENT server (ns2.i1.is) for the TLSA record
//! 3. Client connects to node1, gets its TLS cert
//! 4. Computes SHA-256 of cert, compares to TLSA record
//! 5. Match = trusted. Mismatch = MITM alert.

// TODO: Phase 2 - implement DANE cross-verification
