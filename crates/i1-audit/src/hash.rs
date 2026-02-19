//! Streaming SHA-256 hashing via `ring::digest`.

use ring::digest::{Context, SHA256};
use std::path::Path;
use tokio::io::AsyncReadExt;

use crate::error::{AuditError, Result};

/// Buffer size for streaming file reads (64 KiB).
const BUF_SIZE: usize = 64 * 1024;

/// Compute SHA-256 of a file, streaming to avoid loading it all into memory.
///
/// Returns lowercase hex-encoded digest.
///
/// # Errors
///
/// Returns `AuditError::Io` if the file cannot be opened or read.
pub async fn sha256_file(path: &Path) -> Result<String> {
    let path_str = path.display().to_string();
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AuditError::io(&path_str, e))?;

    let mut context = Context::new(&SHA256);
    let mut buf = vec![0u8; BUF_SIZE];

    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| AuditError::io(&path_str, e))?;
        if n == 0 {
            break;
        }
        context.update(&buf[..n]);
    }

    let digest = context.finish();
    Ok(hex::encode(digest.as_ref()))
}

/// Compute SHA-256 of raw bytes (for certificate DER data).
#[must_use]
pub fn sha256_bytes(data: &[u8]) -> String {
    let digest = ring::digest::digest(&SHA256, data);
    hex::encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_sha256_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "hello world").unwrap();
        tmp.flush().unwrap();

        let hash = sha256_file(tmp.path()).await.unwrap();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_bytes() {
        let hash = sha256_bytes(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn test_sha256_empty_file() {
        let tmp = NamedTempFile::new().unwrap();
        let hash = sha256_file(tmp.path()).await.unwrap();
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
