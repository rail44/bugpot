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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use flate2::read::GzDecoder;
use metrics::{counter, histogram};
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
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info};

use crate::auth::Auth;
use crate::error::{Result, RuntimeError};

/// Per-pull sequence counter; combined with the pid into the tmp dir
/// name to distinguish concurrent in-process pulls of the same digest.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

/// Per-image-ref coordination point used by [`Puller`] to dedupe
/// concurrent pulls. The leader holds `barrier` for the lifetime
/// of `Client::pull` + extract, and writes the resolved manifest
/// digest into `resolved` on success. Waiters block on `barrier`,
/// then read `resolved` to learn what digest was stored on disk
/// (the leader's resolved digest can differ from any probe digest
/// the waiter computed itself — see comment on [`Puller::pull`]).
struct InflightSlot {
    barrier: Arc<AsyncMutex<()>>,
    resolved: std::sync::Mutex<Option<ImageId>>,
}

impl InflightSlot {
    fn new() -> Self {
        Self {
            barrier: Arc::new(AsyncMutex::new(())),
            resolved: std::sync::Mutex::new(None),
        }
    }
}

/// Image puller.
///
/// One instance per [`crate::Runtime`]; the inflight map needs to be
/// shared across every concurrent `pull` call so eager-started apps
/// that point at the same image can coalesce.
pub(crate) struct Puller {
    client: Client,
    images_root: PathBuf,
    /// Per-image-reference singleflight slots used to dedupe
    /// concurrent pulls of the same image. Keyed on the raw image
    /// reference string (not the probed digest) because multi-arch
    /// references have a manifest-index digest that the probe sees
    /// but `Client::pull` follows the index to the platform manifest
    /// and stores under a *different* digest — a probe-digest key
    /// would have waiters look up the wrong cache entry. See
    /// [`Puller::pull`] for the full protocol.
    inflight: std::sync::Mutex<HashMap<String, Arc<InflightSlot>>>,
}

impl std::fmt::Debug for Puller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Puller")
            .field("images_root", &self.images_root)
            .finish_non_exhaustive()
    }
}

impl Puller {
    pub(crate) fn new(images_root: PathBuf) -> Self {
        Self {
            client: Client::new(ClientConfig::default()),
            images_root,
            inflight: std::sync::Mutex::new(HashMap::new()),
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
    /// Cache misses for the same digest from concurrent callers are
    /// deduped via the per-digest `inflight` barrier — only one
    /// `Client::pull` + extract runs, and the rest re-read from the
    /// on-disk cache after the leader publishes the `.done` marker.
    pub(crate) async fn pull(&self, image_ref: &str, auth: Auth) -> Result<PulledImage> {
        let reference: Reference = image_ref.parse().map_err(|e: oci_client::ParseError| {
            RuntimeError::InvalidImageRef(image_ref.to_owned(), e.to_string())
        })?;

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

        // Cache miss. Coalesce with any concurrent pull of the same
        // image reference. The leader runs the full pull + extract
        // and publishes the resolved manifest digest into its slot;
        // waiters block on the slot's barrier and use the published
        // digest to read the on-disk cache once the leader releases.
        //
        // We key on the image reference string (not on `probed_id`)
        // because for multi-arch images `manifest_probe` returns the
        // image-index digest while `Client::pull` follows the index
        // and stores under a different platform manifest digest. The
        // waiter therefore must not assume "the leader stored under
        // my probed digest" — it has to learn the storage digest
        // from the leader directly.
        loop {
            let role = self.claim_inflight(image_ref);
            match role {
                InflightRole::Leader {
                    slot,
                    guard: _guard,
                } => {
                    let result = self.do_full_pull(&reference, &registry_auth).await;
                    if let Ok(ref pulled) = result {
                        *slot.resolved.lock().expect("resolved slot poisoned") =
                            Some(pulled.id.clone());
                    }
                    self.release_inflight(image_ref);
                    return result;
                }
                InflightRole::Waiter(slot) => {
                    counter!("bugpot_image_pull_coalesced_total").increment(1);
                    info!(ref_str = %image_ref, "awaiting in-flight pull");
                    drop(slot.barrier.lock().await);
                    let resolved = slot
                        .resolved
                        .lock()
                        .expect("resolved slot poisoned")
                        .clone();
                    if let Some(id) = resolved {
                        if let Some(cached) = load_cached_image(&self.images_root, &id)? {
                            // Same accounting as the cache-hit fast
                            // path above: the waiter paid neither
                            // cost.
                            histogram!("bugpot_image_pull_seconds", "step" => "registry")
                                .record(0.0);
                            histogram!("bugpot_image_pull_seconds", "step" => "extract")
                                .record(0.0);
                            info!(%id, "in-flight pull completed; using cache");
                            return Ok(cached);
                        }
                        // Leader reported a digest but cache lookup
                        // failed — should be impossible (leader
                        // writes `.done` before publishing the
                        // digest). Treat as a leader failure and
                        // retry to keep this path safe.
                        debug!(%id, "in-flight pull's reported digest is not on disk; retrying");
                    } else {
                        // Leader returned an error and never
                        // published a digest. Loop and claim
                        // leadership ourselves.
                        debug!(ref_str = %image_ref, "in-flight pull failed; retrying");
                    }
                }
            }
        }
    }

    /// Try to become leader for `image_ref`. If another task already
    /// inserted a slot, return [`InflightRole::Waiter`] holding a
    /// clone of it. Otherwise insert a fresh slot, lock its barrier,
    /// and return [`InflightRole::Leader`].
    fn claim_inflight(&self, image_ref: &str) -> InflightRole {
        use std::collections::hash_map::Entry;
        let mut map = self.inflight.lock().expect("inflight map mutex poisoned");
        match map.entry(image_ref.to_owned()) {
            Entry::Occupied(e) => InflightRole::Waiter(e.get().clone()),
            Entry::Vacant(v) => {
                let slot = Arc::new(InflightSlot::new());
                // Fresh mutex, never handed out — `try_lock_owned`
                // cannot fail. Holding this guard while the leader
                // works is what blocks waiters on their
                // `slot.barrier.lock().await`.
                let guard = Arc::clone(&slot.barrier)
                    .try_lock_owned()
                    .expect("fresh barrier mutex");
                v.insert(Arc::clone(&slot));
                InflightRole::Leader { slot, guard }
            }
        }
    }

    /// Remove the slot for `image_ref`. The leader's guard drop after
    /// this call unblocks every queued waiter. Removing the entry
    /// first means a brand-new caller arriving after the removal
    /// won't try to wait on a slot whose leader has already finished.
    fn release_inflight(&self, image_ref: &str) {
        let mut map = self.inflight.lock().expect("inflight map mutex poisoned");
        map.remove(image_ref);
    }

    /// Full registry pull + extract. Called only by the singleflight
    /// leader. Re-checks the on-disk cache after the network round-trip
    /// because a different bugpot process (e.g. a parallel test run
    /// against the same state dir) may have populated it.
    async fn do_full_pull(
        &self,
        reference: &Reference,
        registry_auth: &RegistryAuth,
    ) -> Result<PulledImage> {
        let accepted = accepted_media_types();
        info!(image = %reference, "cache miss, pulling layers from registry");
        let registry_start = Instant::now();
        let data: ImageData = self.client.pull(reference, registry_auth, accepted).await?;
        histogram!("bugpot_image_pull_seconds", "step" => "registry")
            .record(registry_start.elapsed().as_secs_f64());

        let digest = data
            .digest
            .clone()
            .ok_or_else(|| RuntimeError::Other("pulled image has no manifest digest".into()))?;
        let id = ImageId::new(digest);
        let image_dir = self.images_root.join(id.fs_component());

        // Re-check after the full pull: a *different process* (not a
        // task in this Puller's singleflight; that's already ruled
        // out by the inflight map) may have finished an extract while
        // we were downloading layers.
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
        // Per-pull-call suffix so concurrent in-process pulls of the
        // same digest (e.g. the cross-process re-extract race above)
        // don't collide on the tmp dir.
        let extract_start = Instant::now();
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_dir = self.images_root.join(format!(
            "{}.tmp.{}.{}",
            id.fs_component(),
            std::process::id(),
            seq
        ));
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

/// Outcome of [`Puller::claim_inflight`]: either we own the slot
/// (and must drive the pull, then publish the resolved digest) or
/// we hold a clone of someone else's slot (and must wait for them
/// to finish, then read their published digest).
enum InflightRole {
    Leader {
        slot: Arc<InflightSlot>,
        guard: tokio::sync::OwnedMutexGuard<()>,
    },
    Waiter(Arc<InflightSlot>),
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

/// Hard cap on the **decompressed** bytes of a single image layer. A
/// malicious or compromised registry can serve a gzip layer that is
/// tiny on the wire but expands to terabytes — bug-class "tar bomb".
/// 2 GiB is well above any sane base image (debian-slim ~80 MB,
/// node:20 ~1.1 GB, full python:3.12 ~1.2 GB) while still being
/// orders of magnitude smaller than a successful exhaustion attack.
const MAX_LAYER_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

fn extract_layer(rootfs: &Path, data: &[u8], media_type: &str) -> Result<()> {
    extract_layer_inner(rootfs, data, media_type, MAX_LAYER_DECOMPRESSED_BYTES)
}

fn extract_layer_inner(
    rootfs: &Path,
    data: &[u8],
    media_type: &str,
    max_decompressed: u64,
) -> Result<()> {
    match media_type {
        IMAGE_LAYER_MEDIA_TYPE | IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE => {
            if data.len() as u64 > max_decompressed {
                return Err(RuntimeError::Other(format!(
                    "image layer exceeds decompressed size cap ({} bytes > {} bytes)",
                    data.len(),
                    max_decompressed
                )));
            }
            unpack_tar(rootfs, data)
        }
        IMAGE_LAYER_GZIP_MEDIA_TYPE | IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE => {
            let mut decoder = GzDecoder::new(data).take(max_decompressed + 1);
            // Cap the up-front capacity hint at the decompressed
            // ceiling so a malicious blob padded to a large size
            // can't trick us into reserving multi-GiB before the
            // `.take()` even has a chance to fire. `read_to_end`
            // will grow the buffer geometrically as needed.
            let initial_cap = data
                .len()
                .saturating_mul(4)
                .min(usize::try_from(max_decompressed).unwrap_or(usize::MAX));
            let mut buf = Vec::with_capacity(initial_cap);
            decoder
                .read_to_end(&mut buf)
                .map_err(|e| RuntimeError::io(rootfs, e))?;
            if buf.len() as u64 > max_decompressed {
                return Err(RuntimeError::Other(format!(
                    "gzipped image layer decompressed past size cap (> {max_decompressed} bytes)"
                )));
            }
            unpack_tar(rootfs, &buf)
        }
        other => Err(RuntimeError::UnsupportedMediaType(other.to_owned())),
    }
}

fn unpack_tar(rootfs: &Path, data: &[u8]) -> Result<()> {
    let mut archive = tar::Archive::new(data);
    archive.set_preserve_permissions(true);
    // Preserving ownerships calls `chown(2)` on every extracted entry —
    // which needs `CAP_CHOWN`. Both the rootful path (uid=0) and the
    // shipped systemd unit's unprivileged path (ambient `CAP_CHOWN`)
    // satisfy this; everything else (e.g. a dev test run as a regular
    // user) falls back to "files owned by the running uid", which is
    // still correct for the dev workflow.
    archive.set_preserve_ownerships(can_chown());
    // OCI whiteouts are encoded with `.wh.` prefixed filenames. We do not
    // yet implement the overlay-style deletion semantics; for the typical
    // single-layer or strictly additive multi-layer images this is fine.
    // Track as a known limitation.
    archive
        .unpack(rootfs)
        .map_err(|e| RuntimeError::io(rootfs, e))?;
    Ok(())
}

/// Returns `true` iff the current process can `chown(2)` arbitrary
/// uids/gids — either because it runs as root or because it holds
/// `CAP_CHOWN` (the shipped systemd unit grants it via
/// `AmbientCapabilities`).
///
/// Reads the effective capability mask from `/proc/self/status`;
/// returns `false` on any failure to read or parse so the caller
/// safely skips ownership preservation rather than tripping a
/// surprising `EPERM` mid-extraction.
fn can_chown() -> bool {
    // include/uapi/linux/capability.h: CAP_CHOWN = 0
    const CAP_CHOWN_BIT: u64 = 1 << 0;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:").map(str::trim))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .is_some_and(|bits| bits & CAP_CHOWN_BIT != 0)
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

    /// A small uncompressed layer that exceeds the cap is rejected
    /// before extraction, so the bytes never reach the filesystem.
    #[test]
    fn extract_layer_rejects_oversize_tar() {
        let data = vec![0u8; 200];
        let tmp = tempfile::tempdir().unwrap();
        let err = extract_layer_inner(tmp.path(), &data, IMAGE_LAYER_MEDIA_TYPE, 100).unwrap_err();
        match err {
            RuntimeError::Other(msg) => assert!(msg.contains("decompressed size cap"), "{msg}"),
            other => panic!("unexpected: {other:?}"),
        }
        // Nothing was extracted.
        assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());
    }

    /// A gzip stream whose expansion exceeds the cap is rejected
    /// before the inner tar is even parsed.
    #[test]
    fn extract_layer_rejects_oversize_gzip() {
        // Highly compressible: 1 KiB of zeros compresses to ~30 bytes.
        let payload = vec![0u8; 1024];
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::best());
            enc.write_all(&payload).unwrap();
            enc.finish().unwrap();
        }
        // Cap at 200 bytes — well under the 1 KiB the gzip would
        // produce — and confirm we surface the size error rather than
        // an opaque tar parse error.
        let tmp = tempfile::tempdir().unwrap();
        let err =
            extract_layer_inner(tmp.path(), &gz, IMAGE_LAYER_GZIP_MEDIA_TYPE, 200).unwrap_err();
        match err {
            RuntimeError::Other(msg) => assert!(msg.contains("size cap"), "{msg}"),
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

    /// First claim becomes leader; second claim for the same ref while
    /// the leader still holds its guard becomes a waiter. After
    /// release, a new claim becomes leader again.
    #[tokio::test]
    async fn inflight_roles_leader_then_waiter_then_leader_again() {
        let puller = Puller::new(tempfile::tempdir().unwrap().keep());
        let key = "registry.example/img:tag";

        let (leader_slot, leader_guard) = match puller.claim_inflight(key) {
            InflightRole::Leader { slot, guard } => (slot, guard),
            InflightRole::Waiter(_) => panic!("first claim must be leader"),
        };
        let waiter_slot = match puller.claim_inflight(key) {
            InflightRole::Leader { .. } => panic!("second claim must be waiter"),
            InflightRole::Waiter(s) => s,
        };
        assert!(
            Arc::ptr_eq(&leader_slot, &waiter_slot),
            "waiter must observe the leader's slot, not a fresh one"
        );

        // While the leader holds its guard, the waiter's barrier is
        // locked from the same Arc<Mutex>, so a non-blocking try_lock
        // must fail.
        assert!(
            waiter_slot.barrier.try_lock().is_err(),
            "waiter must be blocked while leader holds the guard"
        );

        drop(leader_guard);
        puller.release_inflight(key);

        // After release, the waiter's barrier is free.
        assert!(
            waiter_slot.barrier.try_lock().is_ok(),
            "waiter must unblock once leader releases"
        );

        // And a brand-new claim becomes leader again — the entry has
        // been removed from the inflight map.
        let _next = match puller.claim_inflight(key) {
            InflightRole::Leader { guard, .. } => guard,
            InflightRole::Waiter(_) => panic!("post-release claim must be leader"),
        };
    }

    /// Two concurrent waiters on the same ref both unblock once the
    /// leader releases. Verifies that the per-ref barrier is shared
    /// (not held exclusively by the first waiter to wake).
    #[tokio::test]
    async fn inflight_two_waiters_both_unblock() {
        let puller = Arc::new(Puller::new(tempfile::tempdir().unwrap().keep()));
        let key = "registry.example/img:tag";

        let leader_guard = match puller.claim_inflight(key) {
            InflightRole::Leader { guard, .. } => guard,
            InflightRole::Waiter(_) => panic!("first claim must be leader"),
        };

        // Two waiters whose .lock().await must complete after release.
        let mut waiters = Vec::new();
        for _ in 0..2 {
            let slot = match puller.claim_inflight(key) {
                InflightRole::Leader { .. } => panic!("must be waiter"),
                InflightRole::Waiter(s) => s,
            };
            waiters.push(tokio::spawn(async move {
                drop(slot.barrier.lock().await);
            }));
        }

        // Briefly yield so the waiter tasks have a chance to park on
        // the barrier. They must still be unfinished — leader hasn't
        // released yet.
        tokio::task::yield_now().await;
        for w in &waiters {
            assert!(!w.is_finished(), "waiter must not finish before release");
        }

        drop(leader_guard);
        puller.release_inflight(key);

        for w in waiters {
            w.await.expect("waiter task panicked");
        }
    }

    /// A leader-published digest (set on `slot.resolved`) is visible
    /// to a waiter that wakes on the same slot. This is the bit that
    /// stops the multi-arch cascade described in the doc comment on
    /// `Puller::inflight`: waiters must read the leader's *stored*
    /// digest, not their own probe digest.
    #[tokio::test]
    async fn inflight_leader_publishes_digest_for_waiter() {
        let puller = Arc::new(Puller::new(tempfile::tempdir().unwrap().keep()));
        let key = "registry.example/multiarch:tag";

        let (leader_slot, leader_guard) = match puller.claim_inflight(key) {
            InflightRole::Leader { slot, guard } => (slot, guard),
            InflightRole::Waiter(_) => panic!("first claim must be leader"),
        };
        let waiter_slot = match puller.claim_inflight(key) {
            InflightRole::Leader { .. } => panic!("second claim must be waiter"),
            InflightRole::Waiter(s) => s,
        };

        // Leader resolves the platform manifest digest (different
        // from any probe digest the waiter might compute on its
        // own) and publishes it before releasing the barrier.
        let platform_digest = ImageId::new("sha256:c2c89736deadbeef");
        *leader_slot.resolved.lock().expect("resolved slot poisoned") =
            Some(platform_digest.clone());
        drop(leader_guard);
        puller.release_inflight(key);

        // Waiter reads the published digest from the same slot.
        drop(waiter_slot.barrier.lock().await);
        let observed = waiter_slot
            .resolved
            .lock()
            .expect("resolved slot poisoned")
            .clone();
        assert_eq!(observed, Some(platform_digest));
    }
}
