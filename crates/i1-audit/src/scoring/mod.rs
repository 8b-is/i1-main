//! Trust scoring for binaries and certificates.

pub mod binary_trust;
pub mod cert_trust;
pub mod weights;

pub use binary_trust::score_binary;
pub use cert_trust::score_cert;
pub use weights::{offline_weights, paranoid_weights};
