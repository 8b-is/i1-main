//! Trust weight presets.

use crate::types::TrustWeights;

/// Offline-only weights: no network consensus available, redistribute its weight.
///
/// Used when running without i1-srv connectivity.
#[must_use]
pub const fn offline_weights() -> TrustWeights {
    TrustWeights {
        hash_consensus: 0.0,
        age_factor: 0.30,
        identity_stability: 0.25,
        usage_normality: 0.25,
        provenance_score: 0.20,
    }
}

/// Paranoid weights: consensus matters most, age matters least.
#[must_use]
pub const fn paranoid_weights() -> TrustWeights {
    TrustWeights {
        hash_consensus: 0.50,
        age_factor: 0.10,
        identity_stability: 0.15,
        usage_normality: 0.10,
        provenance_score: 0.15,
    }
}
