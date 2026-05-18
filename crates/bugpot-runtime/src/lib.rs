//! Container lifecycle for bugpot, backed by youki/libcontainer + oci-client.
//!
//! Scope:
//!   - Pull OCI images via `oci-client`.
//!   - Unpack image layers into a per-image rootfs cache under the bugpot
//!     state dir.
//!   - Generate an OCI runtime spec (`config.json`) from `AppSpec` + image
//!     config.
//!   - Run the container via `libcontainer` and supervise it.
//!   - Stop, remove, list containers.
//!
//! Out of scope (handled by `bugpot-egress`):
//!   - Bridge / veth setup, IP allocation, DNS resolver, nftables.
//!   - Runtime accepts an externally-prepared network namespace path.
//!
//! State directory defaults to `/var/lib/bugpot` (override via
//! `BUGPOT_STATE_DIR`).
//!
//! Note: `pub(crate)` is used for cross-module items inside this crate;
//! the `clippy::redundant_pub_crate` warning conflicts with the workspace's
//! `unreachable_pub` rule, so the former is allowed crate-wide.

#![allow(clippy::redundant_pub_crate)]

mod auth;
pub mod caps;
mod cgroup_stats;
mod error;
mod image;
mod logs;
mod runtime;
mod seccomp;
mod spec;
mod volumes;

pub use auth::Auth;
pub use error::RuntimeError;
pub use image::ImageId;
pub use runtime::{ResourceUsage, RunningApp, Runtime, RuntimeOps};
