//! Trust scoring types and weight configuration.

use serde::{Deserialize, Serialize};

/// Multi-factor trust score for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Weighted total: 0.0 = untrusted, 1.0 = fully trusted
    pub total: f64,
    /// How many nodes report the same hash (0.0..1.0)
    pub hash_consensus: f64,
    /// Age factor: sigmoid curve (0d=0.0, 30d~0.5, 365d~1.0)
    pub age_factor: f64,
    /// Same inode/device over time (stable = 1.0)
    pub identity_stability: f64,
    /// Usage pattern matches normal behavior
    pub usage_normality: f64,
    /// Installed via package manager (dpkg/rpm/pacman)
    pub provenance_score: f64,
}

impl TrustScore {
    /// Compute weighted total from individual factors.
    #[allow(clippy::suboptimal_flops)]
    pub fn compute(
        hash_consensus: f64,
        age_factor: f64,
        identity_stability: f64,
        usage_normality: f64,
        provenance_score: f64,
        weights: &TrustWeights,
    ) -> Self {
        let total = hash_consensus * weights.hash_consensus
            + age_factor * weights.age_factor
            + identity_stability * weights.identity_stability
            + usage_normality * weights.usage_normality
            + provenance_score * weights.provenance_score;

        Self {
            total: total.clamp(0.0, 1.0),
            hash_consensus,
            age_factor,
            identity_stability,
            usage_normality,
            provenance_score,
        }
    }
}

/// Configurable weights for trust score factors.
///
/// All weights should sum to 1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustWeights {
    /// Consensus is king -- how many nodes agree on this hash
    pub hash_consensus: f64,
    /// How old the file is (older = more trusted)
    pub age_factor: f64,
    /// Inode/device stability over time
    pub identity_stability: f64,
    /// Whether usage patterns are normal
    pub usage_normality: f64,
    /// Package manager provenance
    pub provenance_score: f64,
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            hash_consensus: 0.40,
            age_factor: 0.15,
            identity_stability: 0.15,
            usage_normality: 0.15,
            provenance_score: 0.15,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_sum_to_one() {
        let w = TrustWeights::default();
        let sum =
            w.hash_consensus + w.age_factor + w.identity_stability + w.usage_normality + w.provenance_score;
        assert!((sum - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_clamps_to_range() {
        let w = TrustWeights::default();
        let s = TrustScore::compute(1.0, 1.0, 1.0, 1.0, 1.0, &w);
        assert!(s.total <= 1.0);
        assert!(s.total >= 0.0);

        let s = TrustScore::compute(0.0, 0.0, 0.0, 0.0, 0.0, &w);
        assert!((s.total).abs() < f64::EPSILON);
    }
}
