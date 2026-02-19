//! Sync modules for inter-node state synchronization.
//!
//! - **Collector**: Reads defense state and patrol data, converts to DNS records.
//! - **Gossip**: SWIM protocol for lightweight inter-node state dissemination.

pub mod collector;
pub mod gossip;
