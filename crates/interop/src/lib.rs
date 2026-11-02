//! Interoperability tests against Postfix, in `tests/`. They need Docker
//! and are `#[ignore]`d in a plain `cargo test`; run them with
//! `scripts/interop-test`. This crate has no code of its own and is never
//! linked into `idly`.

#![forbid(unsafe_code)]
