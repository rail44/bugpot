//! Sandbox for experimenting with the Rust OCI ecosystem.
//!
//! Current scope:
//!   1. `oci-client` — pull an image manifest from a registry.
//!
//! Next steps (TODO, intentionally not yet wired):
//!   - Pull and unpack layers (`oci-client` blobs + `tar` + `nix::mount` for overlayfs).
//!   - Build an OCI bundle on disk.
//!   - Run the bundle via `libcontainer` (youki) and capture stdout.
//!   - Tear down via the container lifecycle API.

use anyhow::{Context, Result};
use oci_client::{Client, Reference, secrets::RegistryAuth};
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_IMAGE: &str = "docker.io/library/hello-world:latest";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let image_ref = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_IMAGE.to_owned());
    let reference: Reference = image_ref.parse().with_context(|| format!("parse {image_ref}"))?;
    info!(image = %reference, "pulling manifest");

    let client = Client::default();
    let auth = RegistryAuth::Anonymous;
    let (manifest, digest) = client.pull_manifest(&reference, &auth).await?;
    info!(%digest, "manifest digest");
    println!("{manifest:#?}");
    Ok(())
}
