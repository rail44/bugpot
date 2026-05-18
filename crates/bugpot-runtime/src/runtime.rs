//! Public `Runtime` API: container lifecycle on top of `oci-client` and
//! `libcontainer`.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::Instant;

use bugpot_config::AppSpec;
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::container::{Container, ContainerStatus};
use libcontainer::signal::Signal;
use libcontainer::syscall::syscall::SyscallType;
use metrics::histogram;
use nix::sys::signal::Signal as NixSignal;
use tracing::{debug, info, warn};

use crate::auth::Auth;
use crate::cgroup_stats::{cgroup_path_for_pid, read_cpu_usec, read_memory_bytes};
use crate::error::{Result, RuntimeError};
use crate::image::{ImageId, Puller, gc_unused_images, load_cached_image};
use crate::logs::spawn_log_tails;
use crate::spec::{SpecInputs, build_spec};
use crate::volumes::{ensure_volume_host_dirs, remove_volume_dirs};

/// A bugpot-managed container that has been started.
#[derive(Debug, Clone)]
pub struct RunningApp {
    pub name: String,
    pub pid: u32,
    pub image: ImageId,
}

/// A cgroup-v2 sample of a container's memory + CPU consumption.
///
/// `cpu_usec` is the cumulative on-CPU time of all processes in the
/// container's cgroup since the cgroup was created. `memory_bytes` is
/// the instantaneous resident memory.
#[derive(Debug, Clone, Copy)]
pub struct ResourceUsage {
    pub memory_bytes: u64,
    pub cpu_usec: u64,
}

// ---- Trait surface ----------------------------------------------------------
//
// The controller binds `<R: RuntimeOps>` and every caller (production
// + mocks) uses the full surface. Async methods use native AFIT
// (Rust 1.75+), so each call avoids the `Pin<Box<dyn Future>>`
// allocation `#[async_trait]` would introduce. The explicit `+ Send`
// bound is required because callers `tokio::spawn` work that holds
// these futures across awaits. Static dispatch only — no `dyn`.

/// Everything the controller needs from the container runtime.
///
/// Covers image pulls, per-container lifecycle / observation, and
/// log-tail spawning. Internal grouping is documented by section
/// comments below rather than at the type level — no narrow caller
/// (an image-only consumer, a log-only consumer) exists, so
/// segregating the surface buys nothing for the cost of three
/// separate impl blocks per implementor.
pub trait RuntimeOps: Send + Sync + std::fmt::Debug + 'static {
    // ----- image pulls -------------------------------------------------------

    /// Pull an OCI image into the bugpot image cache.
    fn pull_image(
        &self,
        image_ref: &str,
        auth: Auth,
    ) -> impl Future<Output = Result<ImageId>> + Send;

    // ----- container lifecycle + observation ---------------------------------

    fn start_app<'a>(
        &'a self,
        spec: &'a AppSpec,
        image_id: &'a ImageId,
        netns_path: Option<&'a Path>,
    ) -> impl Future<Output = Result<RunningApp>> + Send + 'a;
    fn stop_app(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    /// Suspend the container via cgroup v2 freezer. Memory stays
    /// resident; CPU usage falls to zero. `unfreeze_app` restores the
    /// process. Used by the controller's scale-to-zero path to keep
    /// recently-active apps warm without consuming CPU.
    fn freeze_app(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    /// Restore a frozen container.
    fn unfreeze_app(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    fn is_container_running(&self, name: &str) -> bool;
    /// Did libcontainer save status `Paused` for this container? Used
    /// at startup by `reattach_running` to recover the post-freeze
    /// state across a bugpot restart (cgroup freezer state survives the
    /// daemon process).
    fn is_container_paused(&self, name: &str) -> bool;
    fn resource_usage(&self, name: &str) -> Option<ResourceUsage>;
    /// Reap a leftover container whose `AppSpec` is no longer registered
    /// (TOML deleted while bugpot was down). Stops and removes
    /// libcontainer state if it exists, deletes the bundle dir. The
    /// per-app log directory is intentionally left alone — operators
    /// may want to read it post-mortem.
    ///
    /// Idempotent: returns Ok when nothing exists for `name`.
    fn cleanup_orphan_container(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

    // ----- log forwarding ----------------------------------------------------

    /// (Re)spawn log-tail tasks for `name`. Used by the controller after
    /// a successful reattach so the new bugpot's tracing pipeline picks
    /// up the surviving container's stdout/stderr from EOF.
    fn ensure_log_tails(&self, name: &str);
}

/// Container lifecycle runtime.
/// Container lifecycle handle.
///
/// **No in-memory app map.** libcontainer's on-disk state under
/// `<state>/containers/<name>/` is the single source of truth for
/// "what's running": `is_container_running`, `resource_usage`,
/// `stop_app`, and the duplicate-start check in `start_app` all read
/// from there. Bug audit follow-up: keeping a parallel in-memory mirror
/// invited subtle drift on crash / cleanup paths.
#[derive(Debug)]
#[allow(clippy::struct_field_names)] // every field IS a directory; the `_dir` suffix is the point.
pub struct Runtime {
    state_dir: PathBuf,
    images_dir: PathBuf,
    bundles_dir: PathBuf,
    containers_dir: PathBuf,
    logs_dir: PathBuf,
    volumes_dir: PathBuf,
    /// One puller shared across every `pull_image` call: its
    /// per-digest inflight map is what makes concurrent pulls of the
    /// same image coalesce on a single registry round-trip + extract.
    puller: Puller,
}

impl Runtime {
    /// Create a runtime rooted at `state_dir`. Creates `images/`,
    /// `bundles/`, and `containers/` subdirectories if they do not exist.
    pub fn new(state_dir: PathBuf) -> Result<Self> {
        let images_dir = state_dir.join("images");
        let bundles_dir = state_dir.join("bundles");
        let containers_dir = state_dir.join("containers");
        let logs_dir = state_dir.join("logs");
        let volumes_dir = state_dir.join("volumes");
        for p in [
            &state_dir,
            &images_dir,
            &bundles_dir,
            &containers_dir,
            &logs_dir,
            &volumes_dir,
        ] {
            fs::create_dir_all(p).map_err(|e| RuntimeError::io(p, e))?;
        }

        let puller = Puller::new(images_dir.clone());
        Ok(Self {
            state_dir,
            images_dir,
            bundles_dir,
            containers_dir,
            logs_dir,
            volumes_dir,
            puller,
        })
    }

    /// Resolve the runtime state directory, falling back to the
    /// `BUGPOT_STATE_DIR` env var, then `/var/lib/bugpot`.
    #[must_use]
    pub fn default_state_dir() -> PathBuf {
        std::env::var_os("BUGPOT_STATE_DIR")
            .map_or_else(|| PathBuf::from("/var/lib/bugpot"), PathBuf::from)
    }

    /// Root of the runtime state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Load libcontainer's state for `name`. Returns
    /// [`RuntimeError::AppNotFound`] when the per-container state
    /// directory doesn't exist; otherwise propagates any
    /// libcontainer load error.
    ///
    /// Centralises the `containers_dir.join(name)` + `exists()` +
    /// `Container::load` triple that every lifecycle method (start /
    /// stop / freeze / unfreeze / status / cgroup-stats / orphan
    /// reclaim) used to write inline.
    fn try_load_container(&self, name: &str) -> Result<Container> {
        let root = self.containers_dir.join(name);
        if !root.exists() {
            return Err(RuntimeError::AppNotFound(name.to_owned()));
        }
        Container::load(root).map_err(Into::into)
    }
}

impl RuntimeOps for Runtime {
    /// Pull `image_ref` from its registry and extract its layers into
    /// `<state>/images/<digest>/rootfs`.
    async fn pull_image(&self, image_ref: &str, auth: Auth) -> Result<ImageId> {
        let image = self.puller.pull(image_ref, auth).await?;
        Ok(image.id)
    }

    /// Prepare a bundle and start a container for `spec`.
    ///
    /// The image identified by `image_id` must already be on disk —
    /// callers obtain it from a prior [`Self::pull_image`] call.
    ///
    /// Steps:
    ///   1. Load the cached image (no registry round-trip).
    ///   2. Build `<state>/bundles/<app>/rootfs` by symlinking or copying
    ///      from the image cache.
    ///   3. Generate `config.json` from `AppSpec` + image config.
    ///   4. Hand off to `libcontainer::ContainerBuilder` to create/start.
    #[allow(clippy::unused_async)] // pre-pull moved to caller; kept async for API symmetry
    async fn start_app(
        &self,
        spec: &AppSpec,
        image_id: &ImageId,
        netns_path: Option<&Path>,
    ) -> Result<RunningApp> {
        let name = spec.name().to_owned();

        // Reject duplicates. Source of truth = libcontainer on-disk
        // state, not an in-memory map: callers can crash and restart;
        // the controller's reattach path will skip do_start in that
        // case, but a defensive check here means a buggy caller can't
        // wipe a live container's state below (the "stale state" cleanup
        // assumes the dir is from a *dead* container).
        let per_container_dir = self.containers_dir.join(&name);
        if per_container_dir.exists()
            && Container::load(per_container_dir.clone())
                .is_ok_and(|c| c.status() == ContainerStatus::Running)
        {
            return Err(RuntimeError::AppAlreadyRunning(name));
        }

        // 1. Image: must already be in the on-disk cache. Callers do
        // `pull_image` first; passing the result here avoids a second
        // registry round-trip on the warm path.
        let image = load_cached_image(&self.images_dir, image_id)?.ok_or_else(|| {
            RuntimeError::Other(format!(
                "image {image_id} not in cache; caller must pull it first"
            ))
        })?;

        // 2. Bundle.
        let step = Instant::now();
        let bundle_dir = self.bundles_dir.join(&name);
        prepare_bundle_dir(&bundle_dir, &image.rootfs())?;
        histogram!("bugpot_container_start_seconds", "step" => "bundle")
            .record(step.elapsed().as_secs_f64());

        // 3. Volumes.
        //
        // Materialise the per-app, per-volume host dirs *before* the
        // spec build needs their paths. Idempotent — re-running this
        // for an existing volume is a no-op aside from re-asserting
        // ownership (so a TOML `user` change does the right thing on
        // next start). Data survives across container restarts and
        // rollouts; only `cleanup_orphan_container` removes the dir.
        let volume_host_paths = ensure_volume_host_dirs(&self.volumes_dir, &name, &spec.volumes)?;

        // 4. Spec.
        //
        // Pass the absolute path `<bundle_dir>/rootfs` (a symlink set up by
        // `prepare_bundle_dir` that points at the image cache). libcontainer
        // accepts an absolute `root.path`; we also need an absolute path so
        // `build_spec`'s named-user resolver can read
        // `<rootfs>/etc/{passwd,group}` at spec-build time.
        let step = Instant::now();
        let bundle_rootfs = bundle_dir.join("rootfs");
        let runtime_spec = build_spec(&SpecInputs {
            spec,
            image_config: &image.config,
            rootfs: &bundle_rootfs,
            netns_path,
            volume_host_paths: &volume_host_paths,
        })?;
        let config_path = bundle_dir.join("config.json");
        runtime_spec
            .save(&config_path)
            .map_err(RuntimeError::from)?;
        histogram!("bugpot_container_start_seconds", "step" => "spec")
            .record(step.elapsed().as_secs_f64());

        // 4. Build container.
        //
        // libcontainer's `with_root_path` is the *parent* directory under
        // which it writes `<container_id>/state.json` (see libcontainer
        // `init_builder.rs::create_container_dir`). So we pass
        // `self.containers_dir` (parent), not `containers_dir/<name>`. The
        // per-container dir is created by libcontainer itself; we only
        // ensure stale state from a prior crash is gone first. The
        // running-check above has already refused this start if the
        // container were live, so anything we see now is genuinely
        // stale.
        if per_container_dir.exists() {
            warn!(?per_container_dir, "removing stale container state");
            fs::remove_dir_all(&per_container_dir)
                .map_err(|e| RuntimeError::io(&per_container_dir, e))?;
        }
        // `containers_dir` itself must exist (created by `Runtime::new`).

        info!(app = %name, bundle = %bundle_dir.display(), "creating container");

        // Container stdout/stderr go to append-mode files on the host
        // (`<state>/logs/<app>/{stdout,stderr}.log`) rather than pipes
        // owned by bugpot. Reasons:
        //   - Files survive bugpot's death; a SIGKILL/crash no longer
        //     leaves the container writing to a closed pipe (SIGPIPE
        //     would kill the app on its next write — see #38).
        //   - On `reattach_running`, the new bugpot just tails the
        //     existing files; the container's fd 1/2 keep working
        //     through the restart.
        // Volume bounding (rotation, rate limit) is deferred to #21.
        let log_dir = self.log_dir_for(&name);
        fs::create_dir_all(&log_dir).map_err(|e| RuntimeError::io(&log_dir, e))?;
        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");
        let stdout_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stdout_path)
            .map_err(|e| RuntimeError::io(&stdout_path, e))?;
        let stderr_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stderr_path)
            .map_err(|e| RuntimeError::io(&stderr_path, e))?;
        let stdout_fd: OwnedFd = stdout_file.into();
        let stderr_fd: OwnedFd = stderr_file.into();

        // `with_stdout`/`with_stderr` live on `ContainerBuilder`, so they
        // must be called *before* `.as_init(...)` flips us into the
        // init-builder type.
        let step = Instant::now();
        let mut container: Container = ContainerBuilder::new(name.clone(), SyscallType::Linux)
            .with_root_path(&self.containers_dir)?
            .with_stdout(stdout_fd)
            .with_stderr(stderr_fd)
            .as_init(&bundle_dir)
            .with_systemd(false)
            .with_detach(true)
            .build()?;
        histogram!("bugpot_container_start_seconds", "step" => "libcontainer_build")
            .record(step.elapsed().as_secs_f64());

        // libcontainer `as_init().build()` runs the init process up to the
        // "created" state. We then transition it to "running".
        let step = Instant::now();
        container.start()?;
        histogram!("bugpot_container_start_seconds", "step" => "libcontainer_start")
            .record(step.elapsed().as_secs_f64());

        // Tail tasks read from the same files (read-only) and emit each
        // new line via tracing so `just logs` still works. Seek to EOF
        // so a fresh start doesn't replay historical lines; on reattach,
        // the controller calls `ensure_log_tails` for the same effect.
        spawn_log_tails(&log_dir, &name);

        let raw_pid = container
            .pid()
            .ok_or_else(|| RuntimeError::Other("container has no pid after start".into()))?
            .as_raw();
        // `as_raw()` is i32; pids are always non-negative when running.
        let pid = u32::try_from(raw_pid).map_err(|_| {
            RuntimeError::Other(format!(
                "unexpected negative pid from libcontainer: {raw_pid}"
            ))
        })?;

        Ok(RunningApp {
            name,
            pid,
            image: image.id,
        })
    }

    /// Quick liveness check: does libcontainer believe the container for
    /// `id` is still `Running`?
    ///
    /// `Container::load` invokes `refresh_status()`, which reads
    /// `/proc/<pid>` to detect zombie / dead processes — so a container
    /// whose init has crashed, OOM'd, or been `kill -9`'d shows up as
    /// `Stopped` here, not (stale) `Running`. PID reuse is theoretically
    /// possible but rare on a single-host setup; we accept the limit.
    fn is_container_running(&self, name: &str) -> bool {
        self.try_load_container(name)
            .is_ok_and(|c| c.status() == ContainerStatus::Running)
    }

    /// Read the live cgroup v2 memory + CPU stats for the container
    /// named `name`. Returns `None` when the container is not running,
    /// or when its cgroup path / files cannot be resolved (e.g. cgroup
    /// v1 host, transient `/proc` races).
    fn resource_usage(&self, name: &str) -> Option<ResourceUsage> {
        let container = self.try_load_container(name).ok()?;
        if container.status() != ContainerStatus::Running {
            return None;
        }
        let pid = u32::try_from(container.pid()?.as_raw()).ok()?;
        let cgroup = cgroup_path_for_pid(pid)?;
        Some(ResourceUsage {
            memory_bytes: read_memory_bytes(&cgroup)?,
            cpu_usec: read_cpu_usec(&cgroup)?,
        })
    }

    /// Freeze the container's cgroup. Memory pages stay resident; CPU
    /// drops to zero. libcontainer writes the cgroup `freeze` file and
    /// records `ContainerStatus::Paused` so a bugpot restart can
    /// recover the state.
    #[allow(clippy::unused_async)]
    async fn freeze_app(&self, name: &str) -> Result<()> {
        let mut container = self.try_load_container(name)?;
        container.pause()?;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn unfreeze_app(&self, name: &str) -> Result<()> {
        let mut container = self.try_load_container(name)?;
        container.resume()?;
        Ok(())
    }

    fn is_container_paused(&self, name: &str) -> bool {
        self.try_load_container(name)
            .is_ok_and(|c| c.status() == ContainerStatus::Paused)
    }

    /// Stop and clean up a running container.
    ///
    /// `async` for API symmetry with `start_app` and to leave room for
    /// future use of `tokio` primitives (e.g. waiting on process exit via
    /// a child process abstraction).
    #[allow(clippy::unused_async)]
    async fn stop_app(&self, name: &str) -> Result<()> {
        let mut container = self.try_load_container(name)?;
        if container.status() == ContainerStatus::Running {
            // Best-effort graceful SIGTERM. We always force-delete after,
            // which matches `runc rm -f` semantics.
            if let Err(e) = container.kill(Signal::from(NixSignal::SIGTERM), true) {
                debug!(?e, "SIGTERM failed, escalating");
            }
        }
        container.delete(true)?;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn cleanup_orphan_container(&self, name: &str) -> Result<()> {
        let container_root = self.containers_dir.join(name);
        if container_root.exists() {
            match Container::load(container_root.clone()) {
                Ok(mut container) => {
                    if container.status() == ContainerStatus::Running {
                        let _ = container.kill(Signal::from(NixSignal::SIGKILL), true);
                    }
                    if let Err(e) = container.delete(true) {
                        warn!(app = %name, error = ?e, "libcontainer delete failed; removing state dir manually");
                        let _ = fs::remove_dir_all(&container_root);
                    }
                }
                Err(e) => {
                    warn!(app = %name, error = ?e, "libcontainer load failed; removing state dir manually");
                    let _ = fs::remove_dir_all(&container_root);
                }
            }
        }
        let bundle_dir = self.bundles_dir.join(name);
        if bundle_dir.exists() {
            fs::remove_dir_all(&bundle_dir).map_err(|e| RuntimeError::io(&bundle_dir, e))?;
        }
        // Volume dirs are part of the "explicit remove" path: their
        // whole purpose is surviving freezes / rollouts, so only an
        // operator-initiated remove (or an orphan whose TOML has
        // disappeared) should wipe them. The log dir is intentionally
        // left alone — operators may want post-mortem access.
        remove_volume_dirs(&self.volumes_dir, name)?;
        Ok(())
    }

    fn ensure_log_tails(&self, name: &str) {
        spawn_log_tails(&self.log_dir_for(name), name);
    }
}

impl Runtime {
    fn log_dir_for(&self, app: &str) -> PathBuf {
        self.logs_dir.join(app)
    }

    /// Materialise the host-side directories for an app's
    /// [`VolumeSpec`]s and (when a UID is declared) chown them so the
    /// container user can read & write them.
    ///
    /// Returns the resolved host paths in the same order as `volumes`
    /// — `build_spec` consumes them to emit bind mounts.
    ///
    /// Idempotent: re-running for an existing app is a no-op for the
    /// directories that already exist, but **re-asserts ownership**
    /// every call. That's deliberate — if an operator updates `user`
    /// in the TOML and redeploys, the next start picks up the new
    /// ownership without any manual `chown` on the host.
    /// Reference set for image-cache GC: every digest currently bound
    /// to a bundle's `rootfs` symlink. Apps that have at least started
    /// once have their image protected; apps registered but never
    /// started fall outside this set and will re-pull on first start.
    ///
    /// The set is keyed by [`ImageId`] (= manifest digest) on purpose:
    /// when overlayfs / layer-keyed storage lands, the same caller
    /// pattern works — the inner expansion to live layers is internal
    /// to `gc_unused_images`.
    pub fn live_image_digests(&self) -> Result<HashSet<ImageId>> {
        let mut out = HashSet::new();
        if !self.bundles_dir.exists() {
            return Ok(out);
        }
        let entries =
            fs::read_dir(&self.bundles_dir).map_err(|e| RuntimeError::io(&self.bundles_dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| RuntimeError::io(&self.bundles_dir, e))?;
            let bundle = entry.path();
            if !bundle.is_dir() {
                continue;
            }
            let rootfs = bundle.join("rootfs");
            let Ok(target) = fs::read_link(&rootfs) else {
                continue;
            };
            // target = <state>/images/<digest>/rootfs → take the
            // parent's file name as the fs_component, then turn it
            // back into an ImageId (digest form).
            let Some(image_dir) = target.parent() else {
                continue;
            };
            let Some(name) = image_dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // `ImageId::fs_component` replaces the first `:` with `_`,
            // so undo just the first one.
            out.insert(ImageId::new(name.replacen('_', ":", 1)));
        }
        Ok(out)
    }

    /// Reclaim image cache dirs whose digest is not currently
    /// referenced by a bundle, plus any orphan `.tmp.*` / incomplete-
    /// pull dirs without `.done`. Returns the count of dirs removed.
    /// Safe to run at startup before any pull can race.
    pub fn gc_unused_images(&self) -> Result<usize> {
        let live = self.live_image_digests()?;
        gc_unused_images(&self.images_dir, &live)
    }
}

/// Prepare `<bundle_dir>/rootfs` so libcontainer can use it.
///
/// Strategy: create `bundle_dir/rootfs` as an empty directory and
/// recursively bind-mount the image's rootfs into it at container start
/// (delegated to libcontainer's mount handling via the `Spec`). For now we
/// simply create a symlink to the image rootfs, which works for read-only
/// scenarios; once we want a writable upper layer (overlayfs), this is the
/// hook to replace.
fn prepare_bundle_dir(bundle_dir: &Path, image_rootfs: &Path) -> Result<()> {
    if bundle_dir.exists() {
        fs::remove_dir_all(bundle_dir).map_err(|e| RuntimeError::io(bundle_dir, e))?;
    }
    fs::create_dir_all(bundle_dir).map_err(|e| RuntimeError::io(bundle_dir, e))?;

    let rootfs_link = bundle_dir.join("rootfs");
    // Symlink the image rootfs in. Read-only is fine for the v1 milestone:
    // libcontainer will create an explicit mount namespace and the container
    // process gets its own view.
    #[cfg(unix)]
    std::os::unix::fs::symlink(image_rootfs, &rootfs_link)
        .map_err(|e| RuntimeError::io(&rootfs_link, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_subdirectories() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = Runtime::new(tmp.path().to_path_buf()).unwrap();
        assert!(rt.images_dir.is_dir());
        assert!(rt.bundles_dir.is_dir());
        assert!(rt.containers_dir.is_dir());
        assert_eq!(rt.state_dir(), tmp.path());
    }

    #[test]
    fn default_state_dir_falls_back_to_var_lib() {
        // Only check the no-env fallback; mutating the process env from a
        // test would require `unsafe`, which the crate denies.
        if std::env::var_os("BUGPOT_STATE_DIR").is_none() {
            assert_eq!(
                Runtime::default_state_dir(),
                PathBuf::from("/var/lib/bugpot")
            );
        }
    }

    #[test]
    fn prepare_bundle_dir_creates_rootfs_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let image_rootfs = tmp.path().join("image/rootfs");
        fs::create_dir_all(&image_rootfs).unwrap();
        fs::write(image_rootfs.join("marker"), b"hi").unwrap();
        let bundle = tmp.path().join("bundle");
        prepare_bundle_dir(&bundle, &image_rootfs).unwrap();
        let link = bundle.join("rootfs");
        assert!(link.exists());
        // Follow the symlink — should see the marker file.
        let marker = link.join("marker");
        let body = fs::read_to_string(&marker).unwrap();
        assert_eq!(body, "hi");
    }

    /// Confirms `stop_app` returns `AppNotFound` for an unknown id without
    /// touching libcontainer.
    #[tokio::test]
    async fn stop_app_unknown_returns_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = Runtime::new(tmp.path().to_path_buf()).unwrap();
        let err = rt.stop_app("ghost").await.unwrap_err();
        match err {
            RuntimeError::AppNotFound(name) => assert_eq!(name, "ghost"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Smoke test for real libcontainer start. Requires root + a Linux
    /// kernel with namespace support and network egress to pull the image,
    /// so it's ignored by default.
    #[tokio::test]
    #[ignore = "needs root + network to pull a real image"]
    async fn start_app_with_libcontainer_requires_root() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = Runtime::new(tmp.path().to_path_buf()).unwrap();
        let toml_src = r#"
repo = "docker.io/library/hello-world"
port = 8080
name = "hello"
"#;
        let app: AppSpec = toml::from_str(toml_src).unwrap();
        let image_ref = format!("{}:latest", app.repo);
        let image_id = rt
            .pull_image(&image_ref, Auth::Anonymous)
            .await
            .expect("pull_image");
        let running = rt
            .start_app(&app, &image_id, None)
            .await
            .expect("start_app");
        assert!(running.pid > 1);
        rt.stop_app("hello").await.expect("stop_app");
    }

    #[test]
    fn live_image_digests_follows_bundle_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = Runtime::new(tmp.path().to_path_buf()).unwrap();

        // Set up two cached images + two bundles pointing at them.
        let image_a = rt.images_dir.join("sha256_aaa");
        let image_b = rt.images_dir.join("sha256_bbb");
        let image_unref = rt.images_dir.join("sha256_orphan");
        for d in [&image_a, &image_b, &image_unref] {
            fs::create_dir_all(d.join("rootfs")).unwrap();
        }

        for (app, image) in [("alpha", &image_a), ("beta", &image_b)] {
            let bundle = rt.bundles_dir.join(app);
            fs::create_dir_all(&bundle).unwrap();
            std::os::unix::fs::symlink(image.join("rootfs"), bundle.join("rootfs")).unwrap();
        }

        let live = rt.live_image_digests().unwrap();
        assert!(live.contains(&ImageId::new("sha256:aaa")));
        assert!(live.contains(&ImageId::new("sha256:bbb")));
        assert!(
            !live.contains(&ImageId::new("sha256:orphan")),
            "orphan image must NOT appear in live set"
        );
    }
}
