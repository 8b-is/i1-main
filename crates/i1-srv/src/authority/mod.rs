//! DNS authority modules for serving threat intelligence zones.
//!
//! Each zone (bl.i1.is, rep.i1.is, etc.) has its own authority backed by
//! an in-memory record store that gets rebuilt from defense state.

pub mod threat_authority;
pub mod ttl_policy;
pub mod zone_builder;
