//! Public `Runtime` API: container lifecycle on top of `oci-client` and
//! `libcontainer`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use bugpot_config::AppSpec;
use libcontainer::container::{Container, ContainerStatus};
use libcontainer::container::builder::ContainerBuilder;
use libcontainer::signal::Signal;
use libcontainer::syscall::syscall::SyscallType;
use nix::sys::signal::Signal as NixSignal;
use tracing::{debug, info, warn};

use crate::auth::Auth;
use crate::error::{Result, RuntimeError};
use crate::image::{ImageId, Puller};
use crate::spec::{SpecInputs, build_spec};

/// A bugpot-managed container that has been started.
#[derive(Debug, Clone)]
pub struct RunningApp {
    pub id: String,
    pub pid: u32,
    pub image: ImageId,
}

/// Container lifecycle runtime.
#[derive(Debug)]
pub struct Runtime {
    state_dir: PathBuf,
    images_dir: PathBuf,
    bundles_dir: PathBuf,
    containers_dir: PathBuf,
    apps: Mutex<HashMap<String, RunningApp>>,
}

impl Runtime {
    /// Create a runtime rooted at `state_dir`. Creates `images/`,
    /// `bundles/`, and `containers/` subdirectories if they do not exist.
    pub fn new(state_dir: PathBuf) -> Result<Self> {
        let images_dir = state_dir.join("images");
        let bundles_dir = state_dir.join("bundles");
        let containers_dir = state_dir.join("containers");
        for p in [&state_dir, &images_dir, &bundles_dir, &containers_dir] {
            fs::create_dir_all(p).map_err(|e| RuntimeError::io(p, e))?;
        }

        Ok(Self {
            state_dir,
            images_dir,
            bundles_dir,
            containers_dir,
            apps: Mutex::new(HashMap::new()),
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

    /// Pull `image_ref` from its registry and extract its layers into
    /// `<state>/images/<digest>/rootfs`.
    pub async fn pull_image(&self, image_ref: &str, auth: Auth) -> Result<ImageId> {
        let puller = Puller::new(self.images_dir.clone());
        let image = puller.pull(image_ref, auth).await?;
        Ok(image.id)
    }

    /// Prepare a bundle and start a container for `spec`.
    ///
    /// Steps:
    ///   1. Pull the image (idempotent: skips if already on disk).
    ///   2. Build `<state>/bundles/<app>/rootfs` by symlinking or copying
    ///      from the image cache.
    ///   3. Generate `config.json` from `AppSpec` + image config.
    ///   4. Hand off to `libcontainer::ContainerBuilder` to create/start.
    pub async fn start_app(
        &self,
        spec: &AppSpec,
        netns_path: Option<&Path>,
    ) -> Result<RunningApp> {
        let name = spec.name().to_owned();

        // Reject duplicates.
        if self
            .apps
            .lock()
            .expect("apps mutex poisoned")
            .contains_key(&name)
        {
            return Err(RuntimeError::AppAlreadyRunning(name));
        }

        // 1. Image.
        let puller = Puller::new(self.images_dir.clone());
        let image = puller.pull(&spec.image, Auth::Anonymous).await?;

        // 2. Bundle.
        let bundle_dir = self.bundles_dir.join(&name);
        prepare_bundle_dir(&bundle_dir, &image.rootfs())?;

        // 3. Spec.
        //
        // Pass the absolute path `<bundle_dir>/rootfs` (a symlink set up by
        // `prepare_bundle_dir` that points at the image cache). libcontainer
        // accepts an absolute `root.path`; we also need an absolute path so
        // `build_spec`'s named-user resolver can read
        // `<rootfs>/etc/{passwd,group}` at spec-build time.
        let bundle_rootfs = bundle_dir.join("rootfs");
        let runtime_spec = build_spec(&SpecInputs {
            spec,
            image_config: &image.config,
            rootfs: &bundle_rootfs,
            netns_path,
        })?;
        let config_path = bundle_dir.join("config.json");
        runtime_spec
            .save(&config_path)
            .map_err(RuntimeError::from)?;

        // 4. Build container.
        //
        // libcontainer's `with_root_path` is the *parent* directory under
        // which it writes `<container_id>/state.json` (see libcontainer
        // `init_builder.rs::create_container_dir`). So we pass
        // `self.containers_dir` (parent), not `containers_dir/<name>`. The
        // per-container dir is created by libcontainer itself; we only
        // ensure stale state from a prior crash is gone first.
        let per_container_dir = self.containers_dir.join(&name);
        if per_container_dir.exists() {
            warn!(?per_container_dir, "removing stale container state");
            fs::remove_dir_all(&per_container_dir)
                .map_err(|e| RuntimeError::io(&per_container_dir, e))?;
        }
        // `containers_dir` itself must exist (created by `Runtime::new`).

        info!(app = %name, bundle = %bundle_dir.display(), "creating container");
        let mut container: Container = ContainerBuilder::new(name.clone(), SyscallType::Linux)
            .with_root_path(&self.containers_dir)?
            .as_init(&bundle_dir)
            .with_systemd(false)
            .with_detach(true)
            .build()?;

        // libcontainer `as_init().build()` runs the init process up to the
        // "created" state. We then transition it to "running".
        container.start()?;

        let raw_pid = container
            .pid()
            .ok_or_else(|| RuntimeError::Other("container has no pid after start".into()))?
            .as_raw();
        // `as_raw()` is i32; pids are always non-negative when running.
        let pid = u32::try_from(raw_pid).map_err(|_| {
            RuntimeError::Other(format!("unexpected negative pid from libcontainer: {raw_pid}"))
        })?;

        let running = RunningApp {
            id: name.clone(),
            pid,
            image: image.id,
        };

        self.apps
            .lock()
            .expect("apps mutex poisoned")
            .insert(name, running.clone());
        Ok(running)
    }

    /// Stop and clean up a running container.
    ///
    /// `async` for API symmetry with `start_app` and to leave room for
    /// future use of `tokio` primitives (e.g. waiting on process exit via
    /// a child process abstraction).
    #[allow(clippy::unused_async)]
    pub async fn stop_app(&self, id: &str) -> Result<()> {
        let container_root = self.containers_dir.join(id);
        if !container_root.exists() {
            return Err(RuntimeError::AppNotFound(id.to_owned()));
        }

        let mut container = Container::load(container_root)?;
        if container.status() == ContainerStatus::Running {
            // Best-effort graceful SIGTERM. We always force-delete after,
            // which matches `runc rm -f` semantics.
            if let Err(e) = container.kill(Signal::from(NixSignal::SIGTERM), true) {
                debug!(?e, "SIGTERM failed, escalating");
            }
        }
        container.delete(true)?;

        self.apps
            .lock()
            .expect("apps mutex poisoned")
            .remove(id);
        Ok(())
    }

    /// Snapshot of currently running apps. Note: this is the runtime's
    /// in-memory view; it does not re-scan disk.
    #[must_use]
    pub fn list(&self) -> Vec<RunningApp> {
        let apps = self.apps.lock().expect("apps mutex poisoned");
        apps.values().cloned().collect()
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
    fn list_starts_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = Runtime::new(tmp.path().to_path_buf()).unwrap();
        assert!(rt.list().is_empty());
    }

    #[test]
    fn default_state_dir_falls_back_to_var_lib() {
        // Only check the no-env fallback; mutating the process env from a
        // test would require `unsafe`, which the crate denies.
        if std::env::var_os("BUGPOT_STATE_DIR").is_none() {
            assert_eq!(Runtime::default_state_dir(), PathBuf::from("/var/lib/bugpot"));
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

    /// Mocked lifecycle: verifies the *state-tracking* logic of `Runtime`
    /// without invoking libcontainer (which requires root and a kernel
    /// configured for namespaces). We populate `apps` directly and check
    /// that `list` / a stop-style operation surface those entries.
    #[test]
    fn list_returns_inserted_running_apps() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = Runtime::new(tmp.path().to_path_buf()).unwrap();
        let running = RunningApp {
            id: "demo".into(),
            pid: 12345,
            image: ImageId::new("sha256:test"),
        };
        rt.apps
            .lock()
            .unwrap()
            .insert(running.id.clone(), running);

        let listed = rt.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "demo");
        assert_eq!(listed[0].pid, 12345);
        assert_eq!(listed[0].image.as_str(), "sha256:test");
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
image = "docker.io/library/hello-world:latest"
port = 8080
name = "hello"
"#;
        let app: AppSpec = toml::from_str(toml_src).unwrap();
        let running = rt.start_app(&app, None).await.expect("start_app");
        assert!(running.pid > 1);
        rt.stop_app("hello").await.expect("stop_app");
    }
}
