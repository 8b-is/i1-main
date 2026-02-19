//! Trust verification modules.
//!
//! - **Mesh**: Cross-node DANE/TLSA verification ("ask another server").
//! - **TTL Monitor**: Detects TTL manipulation by DNS resolvers.

pub mod mesh;
pub mod ttl_monitor;
