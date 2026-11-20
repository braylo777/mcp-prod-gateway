//! Rust port of `mcpgw` (PyCrust: the Python package stays; this crate mirrors it module by module).
//!
//! | Python            | Rust              |
//! |-------------------|-------------------|
//! | `mcpgw/scanner.py`  | [`scanner`]   |
//! | `mcpgw/versions.py` | [`versions`]  |
//! | `mcpgw/oauth.py`    | [`oauth`]     |
//! | `mcpgw/gateway.py`  | [`gateway`]   |
//! | `mocks/servers.py`  | [`mocks`]     |
//!
//! `canon` reproduces Python's `json.dumps` byte for byte, so fingerprints and JWTs match.

pub mod canon;
pub mod gateway;
pub mod mocks;
pub mod oauth;
pub mod scanner;
pub mod versions;
