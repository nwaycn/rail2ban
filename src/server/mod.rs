//! Server-side: FailManager, BanManager, Jail, Database, IPC.
//!
//! The server is a long-running tokio task that owns the configuration,
//! spawns one task per jail, and serves client requests over a Unix socket.

pub mod database;
pub mod failmanager;
pub mod banmanager;
pub mod jail;
#[allow(clippy::module_inception)]
pub mod server;
pub mod commands;

pub use banmanager::BanManager;
pub use database::Database;
pub use failmanager::FailManager;
pub use jail::{Jail, JailHandle};
pub use server::Server;
