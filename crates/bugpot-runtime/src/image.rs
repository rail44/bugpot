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

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use flate2::read::GzDecoder;
use metrics::histogram;
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
    ///
    /// Cache-hit fast paths:
    /// - **sha-pinned ref** (`...@sha256:...`): no upstream round-trip;
    ///   look up the cache directly by the supplied digest.
    /// - **tag ref**: a HEAD-style manifest digest probe
    ///   (`fetch_manifest_digest`) decides whether the local cache
    ///   covers the request before any layer blob is transferred.
    ///
    /// Only a cache miss falls back to the monolithic `Client::pull`
    /// (manifest + config + all layers).
    pub(crate) async fn pull(&self, image_ref: &str, auth: Auth) -> Result<PulledImage> {
        let reference: Reference = image_ref
            .parse()
            .map_err(|e: oci_client::ParseError| RuntimeError::InvalidImageRef(image_ref.to_owned(), e.to_string()))?;

        let registry_auth: RegistryAuth = auth.into_registry_auth();
        debug!(image = %reference, "resolving image");

        // Determine the expected digest. For sha-pinned refs the
        // upstream call is unnecessary — the ref is content-addressed.
        let probed_id = if let Some(digest) = reference.digest() {
            histogram!("bugpot_image_pull_seconds", "step" => "manifest_probe").record(0.0);
            ImageId::new(digest.to_owned())
        } else {
            let probe_start = Instant::now();
            let probed_digest = self
                .client
                .fetch_manifest_digest(&reference, &registry_auth)
                .await?;
            histogram!("bugpot_image_pull_seconds", "step" => "manifest_probe")
                .record(probe_start.elapsed().as_secs_f64());
            ImageId::new(probed_digest)
        };

        if let Some(cached) = load_cached_image(&self.images_root, &probed_id)? {
            info!(id = %probed_id, "image cache hit");
            histogram!("bugpot_image_pull_seconds", "step" => "registry").record(0.0);
            histogram!("bugpot_image_pull_seconds", "step" => "extract").record(0.0);
            return Ok(cached);
        }

        // Cache miss: fall back to the full pull. For tag refs this
        // re-fetches the manifest one more time inside oci-client,
        // costing a duplicate round-trip; not worth optimising on the
        // miss path.
        let accepted = accepted_media_types();
        info!(image = %reference, "cache miss, pulling layers from registry");
        let registry_start = Instant::now();
        let data: ImageData = self
            .client
            .pull(&reference, &registry_auth, accepted)
            .await?;
        histogram!("bugpot_image_pull_seconds", "step" => "registry")
            .record(registry_start.elapsed().as_secs_f64());

        let digest = data
            .digest
            .clone()
            .ok_or_else(|| RuntimeError::Other("pulled image has no manifest digest".into()))?;
        let id = ImageId::new(digest);
        let image_dir = self.images_root.join(id.fs_component());

        // Re-check after the full pull: a concurrent pull may have
        // finished while we were downloading layers.
        if let Some(cached) = load_cached_image(&self.images_root, &id)? {
            info!(%id, "image cache hit");
            histogram!("bugpot_image_pull_seconds", "step" => "extract").record(0.0);
            return Ok(cached);
        }

        // Fresh extract. Use a tmp dir then atomic rename to avoid
        // leaving partials on crash. Tar extraction is CPU + sync I/O
        // heavy (multi-second for typical images), so run it on a
        // blocking thread to keep the tokio worker free for router /
        // controller traffic. Caller still awaits the same future.
        let extract_start = Instant::now();
        let tmp_dir = self
            .images_root
            .join(format!("{}.tmp.{}", id.fs_component(), std::process::id()));
        let image_dir_for_blocking = image_dir.clone();
        let config = tokio::task::spawn_blocking(move || -> Result<ConfigFile> {
            extract_to_image_dir(tmp_dir, image_dir_for_blocking, data)
        })
        .await
        .map_err(|e| RuntimeError::Other(format!("image extract task panicked: {e}")))??;
        histogram!("bugpot_image_pull_seconds", "step" => "extract")
            .record(extract_start.elapsed().as_secs_f64());

        info!(%id, dir = %image_dir.display(), "image ready");
        Ok(PulledImage {
            id,
            dir: image_dir,
            config,
        })
    }
}

/// Reconstruct a [`PulledImage`] from the on-disk cache for `id`,
/// Synchronous extract worker. Runs the tar unpack + small writes
/// inside `spawn_blocking`. Returns the parsed image config so the
/// async caller doesn't have to re-read the file off disk.
///
/// Args are by value because the caller hands ownership to
/// `spawn_blocking`'s `FnOnce`; clippy's by-value warning here is
/// not actionable.
#[allow(clippy::needless_pass_by_value)]
fn extract_to_image_dir(
    tmp_dir: PathBuf,
    image_dir: PathBuf,
    data: ImageData,
) -> Result<ConfigFile> {
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir).map_err(|e| RuntimeError::io(&tmp_dir, e))?;
    }
    let rootfs = tmp_dir.join("rootfs");
    fs::create_dir_all(&rootfs).map_err(|e| RuntimeError::io(&rootfs, e))?;

    if let Some(manifest) = &data.manifest {
        let manifest_path = tmp_dir.join("manifest.json");
        let body = serde_json::to_vec_pretty(manifest).map_err(RuntimeError::SerializeSpec)?;
        fs::write(&manifest_path, body).map_err(|e| RuntimeError::io(&manifest_path, e))?;
    }
    let config_path = tmp_dir.join("config.json");
    fs::write(&config_path, data.config.data.as_ref())
        .map_err(|e| RuntimeError::io(&config_path, e))?;

    for (idx, layer) in data.layers.iter().enumerate() {
        debug!(idx, media_type = %layer.media_type, "unpacking layer");
        // Optional: verify each layer's sha256 against its annotation
        // when present. The manifest's layer digests are checked by
        // oci-client during pull, so we don't repeat that here.
        extract_layer(&rootfs, &layer.data, &layer.media_type)?;
    }

    let config: ConfigFile =
        serde_json::from_slice(&data.config.data).map_err(RuntimeError::DeserializeConfig)?;

    fs::write(tmp_dir.join(".done"), b"").map_err(|e| RuntimeError::io(&tmp_dir, e))?;

    if image_dir.exists() {
        // Another concurrent pull won the race; discard ours.
        fs::remove_dir_all(&tmp_dir).map_err(|e| RuntimeError::io(&tmp_dir, e))?;
    } else {
        fs::rename(&tmp_dir, &image_dir).map_err(|e| RuntimeError::io(&image_dir, e))?;
    }
    Ok(config)
}

/// or return `Ok(None)` if no `.done` marker exists for that digest.
///
/// Shared between [`Puller::pull`]'s cache-hit short-circuit and
/// `Runtime::start_app` so callers that already pulled the image do
/// not have to round-trip the registry again.
pub(crate) fn load_cached_image(images_root: &Path, id: &ImageId) -> Result<Option<PulledImage>> {
    let image_dir = images_root.join(id.fs_component());
    if !image_dir.join(".done").exists() {
        return Ok(None);
    }
    let config_path = image_dir.join("config.json");
    let config_body = fs::read(&config_path).map_err(|e| RuntimeError::io(&config_path, e))?;
    let config: ConfigFile =
        serde_json::from_slice(&config_body).map_err(RuntimeError::DeserializeConfig)?;
    Ok(Some(PulledImage {
        id: id.clone(),
        dir: image_dir,
        config,
    }))
}

/// Drop image cache dirs whose digest is not in `live`, plus any dir
/// missing `.done` (incomplete pulls / orphaned `.tmp.*` leftovers
/// from a previous crash).
///
/// `live` is the set of digests currently referenced by something we
/// care to keep — for the current "flat extract per image" cache
/// layout that's the bundles' rootfs symlink targets (see
/// `Runtime::live_image_digests`). The signature stays the same shape
/// once we move to layer-keyed storage with overlayfs: the caller
/// will pass a `live_layers` set instead and the body will iterate
/// `layers/<digest>/`.
///
/// Designed to run at startup, before any pull can race with it.
/// Errors on individual entries are logged + skipped so a single bad
/// dir doesn't abort the sweep.
pub(crate) fn gc_unused_images(images_root: &Path, live: &HashSet<ImageId>) -> Result<usize> {
    if !images_root.exists() {
        return Ok(0);
    }
    let live_fs: HashSet<String> = live.iter().map(ImageId::fs_component).collect();
    let mut removed = 0usize;
    let entries = fs::read_dir(images_root).map_err(|e| RuntimeError::io(images_root, e))?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skip unreadable image cache entry");
                continue;
            }
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_owned(),
            None => continue,
        };
        let has_done = path.join(".done").exists();
        let should_remove = !has_done || !live_fs.contains(&name);
        if should_remove {
            match fs::remove_dir_all(&path) {
                Ok(()) => {
                    info!(dir = %path.display(), "image cache GC removed");
                    removed += 1;
                }
                Err(e) => {
                    tracing::warn!(dir = %path.display(), error = %e, "image cache GC remove failed");
                }
            }
        }
    }
    Ok(removed)
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

    /// Create a fake image cache dir with a `.done` marker.
    fn make_cache_dir(root: &Path, digest: &str, with_done: bool) -> PathBuf {
        let dir = root.join(digest);
        fs::create_dir_all(&dir).unwrap();
        if with_done {
            fs::write(dir.join(".done"), b"").unwrap();
        }
        dir
    }

    #[test]
    fn gc_keeps_referenced_drops_others() {
        let tmp = tempfile::tempdir().unwrap();
        let live_dir = make_cache_dir(tmp.path(), "sha256_alive", true);
        let dead_dir = make_cache_dir(tmp.path(), "sha256_dead", true);
        let mut live = HashSet::new();
        live.insert(ImageId::new("sha256:alive"));

        let removed = gc_unused_images(tmp.path(), &live).unwrap();
        assert_eq!(removed, 1);
        assert!(live_dir.exists(), "referenced image must survive");
        assert!(!dead_dir.exists(), "unreferenced image must be removed");
    }

    #[test]
    fn gc_removes_dirs_without_done_marker() {
        let tmp = tempfile::tempdir().unwrap();
        // Orphaned .tmp.* dir from a crashed pull.
        let orphan = tmp.path().join("sha256_foo.tmp.12345");
        fs::create_dir_all(&orphan).unwrap();
        // Half-extracted final dir with no .done.
        let half = make_cache_dir(tmp.path(), "sha256_half", false);
        // Even if the live set names it, missing .done means we treat
        // it as not-fully-extracted and reap it.
        let mut live = HashSet::new();
        live.insert(ImageId::new("sha256:half"));

        let removed = gc_unused_images(tmp.path(), &live).unwrap();
        assert_eq!(removed, 2);
        assert!(!orphan.exists());
        assert!(!half.exists());
    }

    #[test]
    fn gc_no_op_on_missing_root() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let removed = gc_unused_images(&missing, &HashSet::new()).unwrap();
        assert_eq!(removed, 0);
    }
}
