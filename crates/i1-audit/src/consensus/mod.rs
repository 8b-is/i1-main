//! Network consensus — query and compare against community data.

pub mod compare;
pub mod query;

pub use compare::{compare_binaries, compare_certs, Anomaly, AnomalyKind, Severity};
pub use query::{
    create_resolver, query_binary_consensus, query_cert_consensus, ConsensusResult,
};
