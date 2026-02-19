//! Certificate trust scoring.

use crate::types::{CertTrust, RootCertInfo};

/// Score a root certificate's trustworthiness.
///
/// Local factors only -- network consensus filled in later.
pub fn score_cert(cert: &RootCertInfo) -> CertTrust {
    let validity_ok = !cert.expired;

    // Known issuer heuristic: well-known CA issuers get a boost
    let known_issuer = is_known_issuer(&cert.issuer);

    // Base score from local factors
    let mut score: f64 = 0.0;
    if validity_ok {
        score += 0.3;
    }
    if known_issuer {
        score += 0.3;
    }
    // Network consensus adds up to 0.4 (filled in Phase 3)
    let network_consensus: f64 = 0.0;

    CertTrust {
        score: (score + network_consensus).clamp(0.0, 1.0),
        network_consensus,
        validity_ok,
        known_issuer,
    }
}

/// Check if issuer is a well-known Certificate Authority.
///
/// This is a best-effort heuristic; the real validation comes
/// from network consensus.
fn is_known_issuer(issuer: &str) -> bool {
    const KNOWN_CAS: &[&str] = &[
        "digicert",
        "let's encrypt",
        "isrg",
        "comodo",
        "sectigo",
        "globalsign",
        "entrust",
        "godaddy",
        "verisign",
        "thawte",
        "geotrust",
        "rapidssl",
        "amazon",
        "google trust",
        "microsoft",
        "apple",
        "mozilla",
        "baltimore",
        "usertrust",
        "starfield",
        "certum",
        "buypass",
        "actalis",
        "t-telesec",
        "d-trust",
        "quovadis",
        "ssl.com",
        "trustwave",
    ];
    let issuer_lower = issuer.to_lowercase();
    KNOWN_CAS.iter().any(|ca| issuer_lower.contains(ca))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_cert(issuer: &str, expired: bool) -> RootCertInfo {
        let now = Utc::now();
        RootCertInfo {
            path: "/etc/ssl/certs/test.pem".into(),
            fingerprint: "aabbccdd".into(),
            issuer: issuer.into(),
            subject: "Test CA".into(),
            serial: "01".into(),
            not_before: now - chrono::Duration::days(365),
            not_after: if expired {
                now - chrono::Duration::days(1)
            } else {
                now + chrono::Duration::days(365)
            },
            expired,
            in_consensus: None,
            trust_score: None,
        }
    }

    #[test]
    fn known_issuer_scores_higher() {
        let known = score_cert(&make_cert("CN=DigiCert Global Root G2", false));
        let unknown = score_cert(&make_cert("CN=Totally Legit Root CA", false));

        assert!(known.score > unknown.score);
        assert!(known.known_issuer);
        assert!(!unknown.known_issuer);
    }

    #[test]
    fn expired_cert_scores_lower() {
        let valid = score_cert(&make_cert("CN=DigiCert", false));
        let expired = score_cert(&make_cert("CN=DigiCert", true));

        assert!(valid.score > expired.score);
        assert!(valid.validity_ok);
        assert!(!expired.validity_ok);
    }
}
