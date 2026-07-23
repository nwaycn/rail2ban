//! rail2ban — Rust reimplementation of fail2ban.
//!
//! This crate exposes the building blocks used by the `rail2ban-server`,
//! `rail2ban-client`, and `rail2ban-regex` binaries.
//!
//! The module layout mirrors the architecture described in `docs/SPEC.md`:
//!
//! - [`error`] — error types used across the crate.
//! - [`time`] — time abbreviation parsing (`1y`, `30d`, `5m`, ...).
//! - [`ip`] — IP / CIDR utilities and ignore lists.
//! - [`config`] — fail2ban-compatible configuration parsing & interpolation.
//! - [`filter`] — failregex / ignoreregex / datepattern compilation & matching.
//! - [`backend`] — log acquisition backends (file inotify, polling, journal).
//! - [`action`] — action lifecycle execution.
//! - [`server`] — daemon: FailManager / BanManager / Jail / Database / IPC.
//! - [`protocol`] — client/server wire protocol.
//! - [`web`] — embedded web management interface.

#![deny(rust_2021_compatibility)]
#![warn(missing_docs)]
#![allow(clippy::needless_doctest_main)]

pub mod action;
pub mod backend;
pub mod config;
pub mod error;
pub mod filter;
pub mod ip;
pub mod protocol;
pub mod server;
pub mod time;
pub mod web;

pub use error::{Error, Result};
