//! Image pull and on-disk layout.
//!
//! Layout under `<state_dir>/images/`:
//!
//! ```text
//! images/
//!   <digest>/
//!     manifest.json
//!     config.json
//!     rootfs/           # all layers extracted, top-down
//! ```
//!
//! `digest` is the manifest digest (e.g. `sha256:abc...`) with the `:`
//! replaced by `_` so it is a valid path component.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use oci_client::{
    Client, Reference,
    client::{ClientConfig, ImageData},
    config::ConfigFile,
    manifest::{
        IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE, IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
        IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE,
    },
    secrets::RegistryAuth,
};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::auth::Auth;
use crate::error::{Result, RuntimeError};

/// Stable identifier for a pulled image. Wraps the manifest digest
/// (`sha256:...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageId(String);

impl ImageId {
    /// Construct from a digest string.
    pub fn new(digest: impl Into<String>) -> Self {
        Self(digest.into())
    }

    /// The raw digest (`sha256:<hex>` or similar).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Path-safe form of the digest (`:` replaced with `_`).
    pub(crate) fn fs_component(&self) -> String {
        self.0.replace(':', "_")
    }
}

impl fmt::Display for ImageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// On-disk handle to a pulled image.
#[derive(Debug, Clone)]
pub(crate) struct PulledImage {
    pub id: ImageId,
    pub dir: PathBuf,
    pub config: ConfigFile,
}

impl PulledImage {
    pub(crate) fn rootfs(&self) -> PathBuf {
        self.dir.join("rootfs")
    }
}

/// Image puller.
pub(crate) struct Puller {
    client: Client,
    images_root: PathBuf,
}

impl Puller {
    pub(crate) fn new(images_root: PathBuf) -> Self {
        Self {
            client: Client::new(ClientConfig::default()),
            images_root,
        }
    }

    /// Pull and unpack an image. Idempotent: if the same digest already
    /// exists on disk it is reused.
    pub(crate) async fn pull(&self, image_ref: &str, auth: Auth) -> Result<PulledImage> {
        let reference: Reference = image_ref
            .parse()
            .map_err(|e: oci_client::ParseError| RuntimeError::InvalidImageRef(image_ref.to_owned(), e.to_string()))?;

        let registry_auth: RegistryAuth = auth.into_registry_auth();
        let accepted = accepted_media_types();
        info!(image = %reference, "pulling image");

        let data: ImageData = self
            .client
            .pull(&reference, &registry_auth, accepted)
            .await?;

        let digest = data
            .digest
            .clone()
            .ok_or_else(|| RuntimeError::Other("pulled image has no manifest digest".into()))?;
        let id = ImageId::new(digest);
        let image_dir = self.images_root.join(id.fs_component());

        // Idempotency: if `done` marker exists, reuse.
        let done_marker = image_dir.join(".done");
        if done_marker.exists() {
            debug!(%id, dir = %image_dir.display(), "image already on disk");
            let config: ConfigFile = serde_json::from_slice(&data.config.data)
                .map_err(RuntimeError::DeserializeConfig)?;
            return Ok(PulledImage {
                id,
                dir: image_dir,
                config,
            });
        }

        // Fresh extract. Use a tmp dir then atomic rename to avoid leaving
        // partials on crash.
        let tmp_dir = self
            .images_root
            .join(format!("{}.tmp.{}", id.fs_component(), std::process::id()));
        if tmp_dir.exists() {
            fs::remove_dir_all(&tmp_dir).map_err(|e| RuntimeError::io(&tmp_dir, e))?;
        }
        let rootfs = tmp_dir.join("rootfs");
        fs::create_dir_all(&rootfs).map_err(|e| RuntimeError::io(&rootfs, e))?;

        // Write manifest + config alongside.
        if let Some(manifest) = &data.manifest {
            let manifest_path = tmp_dir.join("manifest.json");
            let body = serde_json::to_vec_pretty(manifest).map_err(RuntimeError::SerializeSpec)?;
            fs::write(&manifest_path, body).map_err(|e| RuntimeError::io(&manifest_path, e))?;
        }
        let config_path = tmp_dir.join("config.json");
        fs::write(&config_path, data.config.data.as_ref())
            .map_err(|e| RuntimeError::io(&config_path, e))?;

        // Unpack layers in order.
        for (idx, layer) in data.layers.iter().enumerate() {
            debug!(idx, media_type = %layer.media_type, "unpacking layer");
            // Optional: verify each layer's sha256 against its annotation
            // when present. The manifest's layer digests are checked by
            // oci-client during pull, so we don't repeat that here.
            extract_layer(&rootfs, &layer.data, &layer.media_type)?;
        }

        let config: ConfigFile = serde_json::from_slice(&data.config.data)
            .map_err(RuntimeError::DeserializeConfig)?;

        // Mark done, then atomically swap into place.
        fs::write(tmp_dir.join(".done"), b"").map_err(|e| RuntimeError::io(&tmp_dir, e))?;

        if image_dir.exists() {
            // Another concurrent pull won the race; discard ours.
            fs::remove_dir_all(&tmp_dir).map_err(|e| RuntimeError::io(&tmp_dir, e))?;
        } else {
            fs::rename(&tmp_dir, &image_dir).map_err(|e| RuntimeError::io(&image_dir, e))?;
        }

        info!(%id, dir = %image_dir.display(), "image ready");
        Ok(PulledImage {
            id,
            dir: image_dir,
            config,
        })
    }
}

fn accepted_media_types() -> Vec<&'static str> {
    vec![
        IMAGE_LAYER_MEDIA_TYPE,
        IMAGE_LAYER_GZIP_MEDIA_TYPE,
        IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
        IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    ]
}

/// Hash the layer data, used for verification when caller provides an
/// expected digest. Currently exposed for future use; kept private.
#[allow(dead_code)]
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn extract_layer(rootfs: &Path, data: &[u8], media_type: &str) -> Result<()> {
    match media_type {
        IMAGE_LAYER_MEDIA_TYPE | IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => {
            unpack_tar(rootfs, data)
        }
        IMAGE_LAYER_GZIP_MEDIA_TYPE | IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => {
            let mut decoder = GzDecoder::new(data);
            let mut buf = Vec::with_capacity(data.len() * 4);
            decoder
                .read_to_end(&mut buf)
                .map_err(|e| RuntimeError::io(rootfs, e))?;
            unpack_tar(rootfs, &buf)
        }
        other => Err(RuntimeError::UnsupportedMediaType(other.to_owned())),
    }
}

fn unpack_tar(rootfs: &Path, data: &[u8]) -> Result<()> {
    let mut archive = tar::Archive::new(data);
    archive.set_preserve_permissions(true);
    // Preserving ownerships requires `CAP_CHOWN` and only makes sense for
    // a rootful container runtime. When bugpot is run as non-root (e.g. in
    // unit tests on a dev box) we skip it so layer extraction still works
    // — file owners will default to the running uid, which is correct for
    // the dev workflow.
    archive.set_preserve_ownerships(is_root());
    // OCI whiteouts are encoded with `.wh.` prefixed filenames. We do not
    // yet implement the overlay-style deletion semantics; for the typical
    // single-layer or strictly additive multi-layer images this is fine.
    // Track as a known limitation.
    archive
        .unpack(rootfs)
        .map_err(|e| RuntimeError::io(rootfs, e))?;
    Ok(())
}

fn is_root() -> bool {
    // SAFETY: `getuid` has no preconditions and is always-safe.
    nix::unistd::Uid::effective().is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_id_fs_component_replaces_colon() {
        let id = ImageId::new("sha256:abc123");
        assert_eq!(id.fs_component(), "sha256_abc123");
        assert_eq!(id.as_str(), "sha256:abc123");
    }

    #[test]
    fn sha256_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn unsupported_media_type_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_layer(tmp.path(), b"", "application/octet-stream").unwrap_err();
        match err {
            RuntimeError::UnsupportedMediaType(m) => assert_eq!(m, "application/octet-stream"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Builds a small tar in-memory and confirms it extracts.
    #[test]
    fn extracts_plain_tar_layer() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            let payload = b"hello\n";
            header.set_path("greeting.txt").unwrap();
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append(&header, payload.as_slice()).unwrap();
            builder.finish().unwrap();
        }
        let tmp = tempfile::tempdir().unwrap();
        extract_layer(tmp.path(), &buf, IMAGE_LAYER_MEDIA_TYPE).unwrap();
        let body = std::fs::read_to_string(tmp.path().join("greeting.txt")).unwrap();
        assert_eq!(body, "hello\n");
    }
}
