//! Node registration with i1-dns.
//!
//! Registers this node's A/AAAA and TLSA records with the authoritative
//! i1-dns servers via TSIG-authenticated DNS UPDATE.

// TODO: Phase 2 - implement node registration
// - Send DNS UPDATE to ns1/ns2.i1.is with TSIG authentication
// - Register A/AAAA record under srv.i1.is
// - Register TLSA record under _tlsa._tcp.node.srv.i1.is
// - Support DDNS nodes with short TTLs
