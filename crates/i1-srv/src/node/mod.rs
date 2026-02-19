//! Node identity and registration.
//!
//! - **Identity**: Node certificate from i1-ca, TLSA hash generation.
//! - **Registration**: Register with i1-dns via TSIG-authenticated DNS UPDATE.

pub mod identity;
pub mod registration;
