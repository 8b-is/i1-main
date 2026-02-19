//! DNS record encoding for audit data.

pub mod dns_names;
pub mod txt_audit;

pub use dns_names::{binary_dns_name, cert_dns_name, BIN_ZONE, CA_ZONE};
pub use txt_audit::{encode_binary_txt, encode_cert_txt};
