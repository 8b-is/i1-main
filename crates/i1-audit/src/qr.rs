//! QR code generation for trust verification.
//!
//! Generates a QR code containing a verification URL. When scanned with
//! a phone (on cell network -- independent of your local network), it
//! opens a page that resolves the signal DNS record and compares:
//!
//! - **Value**: Does the TXT record match the expected trust digest?
//! - **TTL**: Is the TTL close to expected? Large drift = cache poisoning.
//!
//! The phone's cell network is the independent trust anchor. If your local
//! DNS is poisoned, the phone will see different results.

use image::Luma;
use qrcode::QrCode;
use std::path::Path;

use crate::error::{AuditError, Result};
use crate::verify::VerifyToken;

/// Generate a QR code PNG file from a verification token.
///
/// The QR encodes the verification URL. Scan it with any phone camera.
///
/// # Errors
///
/// Returns `AuditError::Encoding` if QR generation fails,
/// or `AuditError::Io` if the file cannot be written.
pub fn generate_qr_png(token: &VerifyToken, output_path: &Path) -> Result<()> {
    let url = token.verification_url();

    let code = QrCode::new(url.as_bytes()).map_err(|e| AuditError::Encoding(e.to_string()))?;

    let image = code.render::<Luma<u8>>().quiet_zone(true).build();

    image
        .save(output_path)
        .map_err(|e| AuditError::io(output_path.display().to_string(), std::io::Error::other(e)))?;

    Ok(())
}

/// Render a QR code as a terminal-friendly Unicode string.
///
/// Uses block characters so it displays in any terminal.
#[must_use]
pub fn render_qr_terminal(token: &VerifyToken) -> String {
    let url = token.verification_url();

    let Ok(code) = QrCode::new(url.as_bytes()) else {
        return "Error: failed to generate QR code".to_string();
    };

    code.render()
        .dark_color('\u{2588}') // Full block
        .light_color(' ')
        .quiet_zone(true)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditSnapshot, AuditSummary};
    use crate::verify::generate_verify_token;
    use chrono::Utc;
    use tempfile::TempDir;

    fn make_token() -> VerifyToken {
        let snap = AuditSnapshot {
            node_id: "test-node".into(),
            collected_at: Utc::now(),
            system_uptime_secs: 3600,
            cpu_count: 4,
            binaries: vec![],
            processes: vec![],
            root_certs: vec![],
            summary: AuditSummary {
                total_binaries: 0,
                total_processes: 0,
                total_root_certs: 0,
                running_binaries: 0,
                expired_certs: 0,
                low_trust_binaries: 0,
                unknown_certs: 0,
            },
        };
        generate_verify_token(&snap)
    }

    #[test]
    fn generate_png_creates_file() {
        let token = make_token();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("verify.png");

        generate_qr_png(&token, &path).unwrap();

        assert!(path.exists());
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.len() > 100, "PNG should be more than 100 bytes");
    }

    #[test]
    fn terminal_render_non_empty() {
        let token = make_token();
        let rendered = render_qr_terminal(&token);
        assert!(!rendered.is_empty());
        // Should contain block characters
        assert!(rendered.contains('\u{2588}'));
    }
}
