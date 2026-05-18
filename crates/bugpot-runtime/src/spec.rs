//! Build an OCI runtime `Spec` (`config.json`) from an `AppSpec` plus the
//! image's `config.json`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use bugpot_config::AppSpec;
use oci_client::config::ConfigFile as ImageConfigFile;
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxNamespace, LinuxNamespaceBuilder,
    LinuxNamespaceType, Mount, MountBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
    UserBuilder, get_default_mounts,
};

use crate::error::{Result, RuntimeError};

/// Inputs for `Spec` construction.
///
/// Keeping this as an explicit struct rather than a long parameter list
/// makes the builder easier to test in isolation.
pub(crate) struct SpecInputs<'a> {
    pub spec: &'a AppSpec,
    /// The slot-suffixed container ID (e.g. `"myapp-a"`). Used as the
    /// cgroup leaf so blue-green rollovers can stop one slot's cgroup
    /// without killing the other's processes — earlier we keyed the
    /// cgroup off `spec.name()`, which made both slots share a cgroup
    /// and turned a perfectly correct `stop_app(from)` into a kill of
    /// the new slot's container.
    pub container_id: &'a str,
    pub image_config: &'a ImageConfigFile,
    /// Absolute path to the prepared rootfs (image layers, already
    /// extracted somewhere bugpot owns).
    pub rootfs: &'a Path,
    /// Optional network namespace path to join. If `None`, a fresh netns
    /// is created at container start.
    pub netns_path: Option<&'a Path>,
    /// Resolved host-side paths for each `spec.volumes` entry, in the
    /// same order. The runtime creates / chowns these before building
    /// the spec; `build_spec` only consumes the paths and emits bind
    /// mounts. Length must match `spec.volumes.len()`.
    pub volume_host_paths: &'a [PathBuf],
}

/// Build an OCI runtime [`Spec`] from the given inputs.
///
/// `Root.path` is set to `rootfs` (relative to the bundle dir); the caller
/// is responsible for ensuring the bundle dir contains `rootfs/`.
pub(crate) fn build_spec(inputs: &SpecInputs<'_>) -> Result<Spec> {
    let SpecInputs {
        spec,
        container_id,
        image_config,
        rootfs,
        netns_path,
        volume_host_paths,
    } = *inputs;

    // ---- Process (Args / Env / Cwd / User) ----
    let image_cfg = image_config.config.as_ref();

    let args = derive_args(image_cfg).ok_or_else(|| {
        RuntimeError::Other(format!(
            "image {:?} has neither entrypoint nor cmd",
            spec.repo
        ))
    })?;

    let env = derive_env(spec, image_cfg);
    let cwd = image_cfg
        .and_then(|c| c.working_dir.as_deref())
        .filter(|s| !s.is_empty())
        .map_or_else(|| PathBuf::from("/"), PathBuf::from);

    let user = parse_user(image_cfg.and_then(|c| c.user.as_deref()), rootfs)?;

    // Modest, container-typical capability set. Drops the dangerous ones
    // (SYS_ADMIN, NET_ADMIN, etc.). Matches the runc default minus a few.
    let caps: HashSet<Capability> = default_capabilities().into_iter().collect();
    let empty: HashSet<Capability> = HashSet::new();
    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(caps.clone())
        .effective(caps.clone())
        .permitted(caps)
        .inheritable(empty.clone())
        .ambient(empty)
        .build()?;

    let process = ProcessBuilder::default()
        .terminal(false)
        .user(user)
        .args(args)
        .env(env)
        .cwd(cwd)
        .no_new_privileges(true)
        .capabilities(capabilities)
        .build()?;

    // ---- Linux: namespaces (no per-app resource limits) ----
    //
    // bugpot leans on kernel defaults: fair-share `cpu.weight` and
    // host-wide LRU for memory. The freeze + `BUGPOT_FREEZE_MEM_LO`
    // pressure handler is the only app-level intervention; everything
    // else is the kernel's call.
    let namespaces = build_namespaces(netns_path)?;
    let seccomp = crate::seccomp::runc_default()?.clone();
    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .seccomp(seccomp)
        .cgroups_path(PathBuf::from(format!("/bugpot/{container_id}")))
        .build()?;

    // ---- Mounts ----
    let mounts = build_mounts(spec, volume_host_paths)?;

    // ---- Root ----
    // `Spec::canonicalize_rootfs` (called by libcontainer) will resolve the
    // path against the bundle directory at start time, so a relative
    // `rootfs` is fine — but we have an absolute path here so we just use it.
    let root = RootBuilder::default()
        .path(rootfs.to_path_buf())
        .readonly(false)
        .build()?;

    // ---- Annotations: bugpot-specific metadata ----
    let mut annotations: HashMap<String, String> = HashMap::new();
    annotations.insert("io.bugpot.app".into(), spec.name().to_owned());
    annotations.insert("io.bugpot.port".into(), spec.port.to_string());
    annotations.insert("io.bugpot.repo".into(), spec.repo.clone());

    let oci_spec = SpecBuilder::default()
        .version("1.0.2-dev")
        .hostname(spec.name().to_owned())
        .root(root)
        .process(process)
        .mounts(mounts)
        .linux(linux)
        .annotations(annotations)
        .build()?;

    Ok(oci_spec)
}

fn derive_args(image_cfg: Option<&oci_client::config::Config>) -> Option<Vec<String>> {
    let entrypoint = image_cfg
        .and_then(|c| c.entrypoint.as_ref())
        .cloned()
        .unwrap_or_default();
    let cmd = image_cfg
        .and_then(|c| c.cmd.as_ref())
        .cloned()
        .unwrap_or_default();

    let combined: Vec<String> = entrypoint.into_iter().chain(cmd).collect();
    if combined.is_empty() {
        None
    } else {
        Some(combined)
    }
}

fn derive_env(spec: &AppSpec, image_cfg: Option<&oci_client::config::Config>) -> Vec<String> {
    // Image envs first, then bugpot's PORT, then user-defined envs (user
    // wins on key collision).
    let mut out: Vec<String> = image_cfg
        .and_then(|c| c.env.as_ref())
        .cloned()
        .unwrap_or_default();

    // Ensure PATH exists.
    if !out.iter().any(|e| e.starts_with("PATH=")) {
        out.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }

    // Inject `PORT` (12-factor convention).
    push_env(&mut out, "PORT", &spec.port.to_string());

    for (k, v) in &spec.env {
        push_env(&mut out, k, v);
    }

    out
}

fn push_env(env: &mut Vec<String>, key: &str, value: &str) {
    let prefix = format!("{key}=");
    env.retain(|e| !e.starts_with(&prefix));
    env.push(format!("{key}={value}"));
}

fn parse_user(raw: Option<&str>, rootfs: &Path) -> Result<oci_spec::runtime::User> {
    let trimmed = raw.unwrap_or("").trim();
    if matches!(trimmed, "" | "root" | "0" | "0:0") {
        return Ok(UserBuilder::default().uid(0_u32).gid(0_u32).build()?);
    }
    let (uid, gid) = parse_uid_gid(trimmed, rootfs)?;
    Ok(UserBuilder::default().uid(uid).gid(gid).build()?)
}

/// Resolve `user[:group]` from an image config. Each side may be numeric or
/// a name; named entries are looked up in `<rootfs>/etc/{passwd,group}`.
///
/// When the group is omitted entirely (just `user`), we fall back to the
/// primary gid recorded in `/etc/passwd` for that user. If the user was
/// numeric and the group was omitted, the gid defaults to 0 to match runc.
fn parse_uid_gid(raw: &str, rootfs: &Path) -> Result<(u32, u32)> {
    let mut parts = raw.splitn(2, ':');
    let user_part = parts.next().unwrap_or("");
    let group_part = parts.next();

    let (uid, primary_gid) = resolve_user(user_part, rootfs)?;
    let gid = match group_part {
        Some(g) => resolve_group(g, rootfs)?,
        None => primary_gid.unwrap_or(0),
    };
    Ok((uid, gid))
}

/// Returns `(uid, primary_gid_from_passwd)`. The primary gid is only set
/// when the input was a name (numeric inputs don't carry a primary gid).
fn resolve_user(s: &str, rootfs: &Path) -> Result<(u32, Option<u32>)> {
    if let Ok(uid) = s.parse::<u32>() {
        return Ok((uid, None));
    }
    let path = rootfs.join("etc/passwd");
    let content = std::fs::read_to_string(&path).map_err(|_| RuntimeError::InvalidResource {
        field: "image.user",
        value: s.to_owned(),
        reason: "rootfs /etc/passwd not readable for name resolution",
    })?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 {
            continue;
        }
        if fields[0] == s {
            let uid = fields[2]
                .parse::<u32>()
                .map_err(|_| RuntimeError::InvalidResource {
                    field: "image.user",
                    value: s.to_owned(),
                    reason: "malformed uid in /etc/passwd",
                })?;
            let gid = fields[3].parse::<u32>().ok();
            return Ok((uid, gid));
        }
    }
    Err(RuntimeError::InvalidResource {
        field: "image.user",
        value: s.to_owned(),
        reason: "user name not found in rootfs /etc/passwd",
    })
}

fn resolve_group(s: &str, rootfs: &Path) -> Result<u32> {
    if let Ok(gid) = s.parse::<u32>() {
        return Ok(gid);
    }
    let path = rootfs.join("etc/group");
    let content = std::fs::read_to_string(&path).map_err(|_| RuntimeError::InvalidResource {
        field: "image.user",
        value: s.to_owned(),
        reason: "rootfs /etc/group not readable for name resolution",
    })?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[0] == s {
            return fields[2]
                .parse::<u32>()
                .map_err(|_| RuntimeError::InvalidResource {
                    field: "image.user",
                    value: s.to_owned(),
                    reason: "malformed gid in /etc/group",
                });
        }
    }
    Err(RuntimeError::InvalidResource {
        field: "image.user",
        value: s.to_owned(),
        reason: "group name not found in rootfs /etc/group",
    })
}

fn build_namespaces(netns_path: Option<&Path>) -> Result<Vec<LinuxNamespace>> {
    let pid = LinuxNamespaceBuilder::default()
        .typ(LinuxNamespaceType::Pid)
        .build()?;
    let ipc = LinuxNamespaceBuilder::default()
        .typ(LinuxNamespaceType::Ipc)
        .build()?;
    let uts = LinuxNamespaceBuilder::default()
        .typ(LinuxNamespaceType::Uts)
        .build()?;
    let mount = LinuxNamespaceBuilder::default()
        .typ(LinuxNamespaceType::Mount)
        .build()?;
    let cgroup = LinuxNamespaceBuilder::default()
        .typ(LinuxNamespaceType::Cgroup)
        .build()?;
    let mut net = LinuxNamespaceBuilder::default().typ(LinuxNamespaceType::Network);
    if let Some(path) = netns_path {
        net = net.path(path.to_path_buf());
    }

    Ok(vec![pid, ipc, uts, mount, cgroup, net.build()?])
}

fn build_mounts(spec: &AppSpec, volume_host_paths: &[PathBuf]) -> Result<Vec<Mount>> {
    // Start from the spec defaults (proc, sys, /dev/pts, ...).
    let mut mounts = get_default_mounts();

    // Add a minimal /etc/resolv.conf bind-mount placeholder so DNS works
    // once bugpot-egress wires up name resolution. The actual source path
    // is filled in at start time by the caller if it wants to override.
    // Until then, leave the host's resolv.conf bound in read-only.
    if Path::new("/etc/resolv.conf").exists()
        && let Ok(m) = MountBuilder::default()
            .destination(PathBuf::from("/etc/resolv.conf"))
            .source(PathBuf::from("/etc/resolv.conf"))
            .typ("bind")
            .options(vec![
                "rbind".to_owned(),
                "ro".to_owned(),
                "nosuid".to_owned(),
                "nodev".to_owned(),
            ])
            .build()
    {
        mounts.push(m);
    }

    // Per-app persistent volumes. The runtime has already created /
    // chowned the host directories in `ensure_volume_host_dirs`. We
    // mount them rw with the same hardening options every other bind
    // gets (nosuid + nodev keep a hostile image from elevating
    // privileges via setuid binaries dropped inside the volume).
    assert_eq!(
        volume_host_paths.len(),
        spec.volumes.len(),
        "volume_host_paths length must mirror spec.volumes",
    );
    for (v, host_path) in spec.volumes.iter().zip(volume_host_paths) {
        let m = MountBuilder::default()
            .destination(v.path.clone())
            .source(host_path.clone())
            .typ("bind")
            .options(vec![
                "rbind".to_owned(),
                "rw".to_owned(),
                "nosuid".to_owned(),
                "nodev".to_owned(),
            ])
            .build()
            .map_err(RuntimeError::from)?;
        mounts.push(m);
    }

    Ok(mounts)
}

/// A modest, container-typical capability set. Mirrors the runc default
/// for an unprivileged container.
fn default_capabilities() -> Vec<Capability> {
    use Capability::{
        AuditWrite, Chown, DacOverride, Fowner, Fsetid, Kill, Mknod, NetBindService, NetRaw,
        Setfcap, Setgid, Setpcap, Setuid, SysChroot,
    };
    vec![
        AuditWrite,
        Chown,
        DacOverride,
        Fowner,
        Fsetid,
        Kill,
        Mknod,
        NetBindService,
        NetRaw,
        Setfcap,
        Setgid,
        Setpcap,
        Setuid,
        SysChroot,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use bugpot_config::AppSpec;
    use oci_client::config::{Config as ImageConfig, ConfigFile, Rootfs};

    fn make_app_spec(repo: &str, port: u16) -> AppSpec {
        let toml = format!(
            r#"repo = "{repo}"
port = {port}
name = "myapp"

[env]
LOG_LEVEL = "info"
"#
        );
        toml::from_str(&toml).expect("parse test toml")
    }

    fn make_image_config(entrypoint: Vec<&str>, cmd: Vec<&str>) -> ConfigFile {
        ConfigFile {
            config: Some(ImageConfig {
                entrypoint: Some(entrypoint.into_iter().map(str::to_owned).collect()),
                cmd: Some(cmd.into_iter().map(str::to_owned).collect()),
                env: Some(vec!["IMAGE_VAR=from-image".into()]),
                working_dir: Some("/app".into()),
                user: Some("1000:1000".into()),
                ..Default::default()
            }),
            rootfs: Rootfs::default(),
            ..Default::default()
        }
    }

    #[test]
    fn spec_includes_env_port_user_and_no_cgroup_limits() {
        let app = make_app_spec("ghcr.io/x/y", 8081);
        let image = make_image_config(vec!["/bin/run"], vec!["--serve"]);
        let rootfs = PathBuf::from("/tmp/bugpot-test-rootfs");
        let spec = build_spec(&SpecInputs {
            spec: &app,
            container_id: "test-a",
            image_config: &image,
            rootfs: &rootfs,
            netns_path: None,
            volume_host_paths: &[],
        })
        .expect("build_spec");

        // Process: args = entrypoint ++ cmd
        let process = spec.process().as_ref().unwrap();
        assert_eq!(
            process.args().as_ref().unwrap(),
            &vec!["/bin/run".to_string(), "--serve".to_string()]
        );

        // Env: PORT + LOG_LEVEL injected; image env preserved.
        let env = process.env().as_ref().unwrap();
        assert!(env.iter().any(|e| e == "IMAGE_VAR=from-image"));
        assert!(env.iter().any(|e| e == "PORT=8081"));
        assert!(env.iter().any(|e| e == "LOG_LEVEL=info"));
        assert!(env.iter().any(|e| e.starts_with("PATH=")));

        // User
        assert_eq!(process.user().uid(), 1000);
        assert_eq!(process.user().gid(), 1000);

        // Cwd
        assert_eq!(process.cwd(), &PathBuf::from("/app"));

        // No per-app cgroup limits: bugpot relies on kernel fair-share
        // (cpu.weight default 100) + host-LRU memory pressure. The
        // freeze + memory-pressure-eviction handler is the only
        // app-level intervention. The OCI `LinuxResources` block
        // itself is non-None because `LinuxBuilder::default()` always
        // emits one (its internal devices / hugepages defaults live
        // there too), but the `memory` and `cpu` sub-fields stay
        // unset so libcontainer applies kernel defaults.
        let linux = spec.linux().as_ref().unwrap();
        let resources = linux.resources().as_ref().unwrap();
        assert!(
            resources.memory().is_none(),
            "no per-app memory cgroup limits"
        );
        assert!(resources.cpu().is_none(), "no per-app cpu cgroup limits");

        // Namespaces: net namespace path absent because netns_path = None
        let network = linux
            .namespaces()
            .as_ref()
            .unwrap()
            .iter()
            .find(|n| n.typ() == LinuxNamespaceType::Network)
            .unwrap();
        assert!(network.path().is_none());

        // Annotations
        let ann = spec.annotations().as_ref().unwrap();
        assert_eq!(ann.get("io.bugpot.port").map(String::as_str), Some("8081"));
        assert_eq!(ann.get("io.bugpot.app").map(String::as_str), Some("myapp"));
    }

    #[test]
    fn spec_joins_external_netns() {
        let app = make_app_spec("ghcr.io/x/y", 8080);
        let image = make_image_config(vec!["/bin/run"], vec![]);
        let rootfs = PathBuf::from("/tmp/bugpot-rootfs");
        let netns = PathBuf::from("/var/run/netns/bugpot-myapp");

        let spec = build_spec(&SpecInputs {
            spec: &app,
            container_id: "test-a",
            image_config: &image,
            rootfs: &rootfs,
            netns_path: Some(&netns),
            volume_host_paths: &[],
        })
        .unwrap();

        let linux = spec.linux().as_ref().unwrap();
        let network = linux
            .namespaces()
            .as_ref()
            .unwrap()
            .iter()
            .find(|n| n.typ() == LinuxNamespaceType::Network)
            .unwrap();
        assert_eq!(network.path().as_deref(), Some(netns.as_path()));
    }

    #[test]
    fn spec_attaches_default_seccomp_profile() {
        let app = make_app_spec("ghcr.io/x/y", 8080);
        let image = make_image_config(vec!["/bin/run"], vec![]);
        let spec = build_spec(&SpecInputs {
            spec: &app,
            container_id: "test-a",
            image_config: &image,
            rootfs: Path::new("/tmp/rootfs"),
            netns_path: None,
            volume_host_paths: &[],
        })
        .unwrap();

        let linux = spec.linux().as_ref().unwrap();
        let profile = linux.seccomp().as_ref().expect("seccomp attached");
        assert_eq!(
            profile.default_action(),
            oci_spec::runtime::LinuxSeccompAction::ScmpActErrno
        );
        // Sanity: rules are non-empty (full profile-shape coverage lives
        // in `seccomp::tests`).
        let rules = profile.syscalls().as_ref().expect("rules present");
        assert!(!rules.is_empty());
    }

    #[test]
    fn user_env_overrides_image_env_on_collision() {
        // PORT collision: user wants PORT=9999, app spec wants port=8080
        let toml = r#"
repo = "ghcr.io/x/y"
port = 8080
name = "x"

[env]
PORT = "9999"
"#;
        let app: AppSpec = toml::from_str(toml).unwrap();
        let image = make_image_config(vec!["/run"], vec![]);
        let spec = build_spec(&SpecInputs {
            spec: &app,
            container_id: "test-a",
            image_config: &image,
            rootfs: Path::new("/tmp/rootfs"),
            netns_path: None,
            volume_host_paths: &[],
        })
        .unwrap();

        let env = spec.process().as_ref().unwrap().env().as_ref().unwrap();
        let port_entries: Vec<_> = env.iter().filter(|e| e.starts_with("PORT=")).collect();
        assert_eq!(port_entries.len(), 1);
        assert_eq!(port_entries[0], "PORT=9999");
    }

    #[test]
    fn spec_emits_bind_mount_per_volume() {
        let toml_src = r#"
            repo = "ghcr.io/x/y"
            port = 80
            name = "myapp"

            [[volumes]]
            name = "data"
            path = "/data"

            [[volumes]]
            name = "cache"
            path = "/var/cache/app"
            "#;
        let app: AppSpec = toml::from_str(toml_src).expect("parse");
        let image = make_image_config(vec!["/bin/run"], vec![]);
        let host_paths = [
            PathBuf::from("/var/lib/bugpot/volumes/myapp/data"),
            PathBuf::from("/var/lib/bugpot/volumes/myapp/cache"),
        ];
        let spec = build_spec(&SpecInputs {
            spec: &app,
            container_id: "test-a",
            image_config: &image,
            rootfs: Path::new("/tmp/rootfs"),
            netns_path: None,
            volume_host_paths: &host_paths,
        })
        .expect("build_spec");

        let mounts = spec.mounts().as_ref().expect("mounts present");
        let data_mount = mounts
            .iter()
            .find(|m| m.destination() == Path::new("/data"))
            .expect("data mount");
        assert_eq!(
            data_mount.source().as_deref(),
            Some(Path::new("/var/lib/bugpot/volumes/myapp/data")),
        );
        assert_eq!(data_mount.typ().as_deref(), Some("bind"));
        let opts = data_mount.options().as_ref().expect("options present");
        // rw + nosuid + nodev are the hardening floor every user
        // volume gets; rbind keeps libcontainer happy with nested
        // mounts inside the volume.
        for required in ["rbind", "rw", "nosuid", "nodev"] {
            assert!(
                opts.iter().any(|o| o == required),
                "missing option {required:?}; got {opts:?}",
            );
        }
        // Second volume is also wired.
        assert!(
            mounts
                .iter()
                .any(|m| m.destination() == Path::new("/var/cache/app")),
        );
    }

    #[test]
    fn errors_when_image_has_no_entrypoint_or_cmd() {
        let app = make_app_spec("ghcr.io/x/y", 8080);
        let image = ConfigFile {
            config: Some(ImageConfig::default()),
            rootfs: Rootfs::default(),
            ..Default::default()
        };
        let err = build_spec(&SpecInputs {
            spec: &app,
            container_id: "test-a",
            image_config: &image,
            rootfs: Path::new("/tmp/rootfs"),
            netns_path: None,
            volume_host_paths: &[],
        })
        .unwrap_err();
        match err {
            RuntimeError::Other(msg) => assert!(msg.contains("entrypoint")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
