//! SWIM gossip protocol for inter-node state synchronization.
//!
//! Nodes sync attack state via lightweight gossip (not heavy AXFR):
//! - Each node maintains a local threat database
//! - SWIM protocol disseminates changes: "IP X was blocked by node Y at time Z"
//! - Nodes independently update their zone records from gossip state
//! - No single master - all nodes are peers

// TODO: Phase 3 - implement SWIM gossip
// This is deferred to a later phase. Phase 1 runs as a single node.
