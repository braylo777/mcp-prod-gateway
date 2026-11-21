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
//!
//! Rust-only modules: [`policy`] (deep rules on normalized text), [`http`] (HTTP/1.1 binding,
//! replaces `mcpgw/http.py`), [`corpus`] / [`eval`] (generated attack and benign corpora),
//! [`bench`] (per-check latency) and [`parity`] (counts used by the `metrics` bin).

pub mod bench;
pub mod canon;
pub mod corpus;
pub mod eval;
pub mod gateway;
pub mod http;
pub mod mocks;
pub mod oauth;
pub mod parity;
pub mod policy;
pub mod scanner;
pub mod versions;
