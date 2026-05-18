//! `impl AppHost` blocks grouped by responsibility.
//!
//! `AppHost` itself stays a single type so the in-memory state
//! (`registry`, `store`) and the kernel-side adapters (`runtime`,
//! `egress`) live in one place, but the methods it carries — CRUD,
//! lifecycle, rollout, background loops, boot recovery, HTTP
//! resolution — are independent concerns. Splitting the methods
//! across this module's submodules surfaces those concerns at the
//! file-tree level without paying the plumbing cost a per-concern
//! type split would impose (= the option we considered and rejected
//! during the rename design).
//!
//! Cross-module method calls (e.g. `crud::remove_app` calling
//! `lifecycle::stop`) are why a few methods on `AppHost` are marked
//! `pub(crate)` rather than private — the compiler can't see them
//! across module boundaries otherwise.

mod boot;
mod crud;
pub(crate) mod lifecycle;
mod loops;
mod resolver;
mod rollout;
