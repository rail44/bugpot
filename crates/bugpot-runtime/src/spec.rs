//! Build an OCI runtime `Spec` (`config.json`) from an `AppSpec` plus the
//! image's `config.json`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use bugpot_config::AppSpec;
use oci_client::config::ConfigFile as ImageConfigFile;
use oci_spec::runtime::{
    Capability, LinuxBuilder, LinuxCapabilitiesBuilder, LinuxCpuBuilder, LinuxMemoryBuilder,
    LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType, LinuxResourcesBuilder, Mount,
    MountBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder, UserBuilder,
    get_default_mounts,
};

use crate::error::{Result, RuntimeError};
use crate::resources;

/// Inputs for `Spec` construction.
///
/// Keeping this as an explicit struct rather than a long parameter list
/// makes the builder easier to test in isolation.
pub(crate) struct SpecInputs<'a> {
    pub spec: &'a AppSpec,
    pub image_config: &'a ImageConfigFile,
    /// Absolute path to the prepared rootfs (image layers, already
    /// extracted somewhere bugpot owns).
    pub rootfs: &'a Path,
    /// Optional network namespace path to join. If `None`, a fresh netns
    /// is created at container start.
    pub netns_path: Option<&'a Path>,
}

/// Build an OCI runtime [`Spec`] from the given inputs.
///
/// `Root.path` is set to `rootfs` (relative to the bundle dir); the caller
/// is responsible for ensuring the bundle dir contains `rootfs/`.
pub(crate) fn build_spec(inputs: &SpecInputs<'_>) -> Result<Spec> {
    let SpecInputs {
        spec,
        image_config,
        rootfs,
        netns_path,
    } = *inputs;

    // ---- Process (Args / Env / Cwd / User) ----
    let image_cfg = image_config.config.as_ref();

    let args = derive_args(image_cfg).ok_or_else(|| {
        RuntimeError::Other(format!(
            "image {:?} has neither entrypoint nor cmd",
            spec.image
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

    // ---- Linux: namespaces + resources ----
    let namespaces = build_namespaces(netns_path)?;
    let resources = build_resources(spec)?;
    let seccomp = crate::seccomp::runc_default()?.clone();
    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .resources(resources)
        .seccomp(seccomp)
        .cgroups_path(PathBuf::from(format!("/bugpot/{}", spec.name())))
        .build()?;

    // ---- Mounts ----
    let mounts = build_mounts();

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
    annotations.insert("io.bugpot.image".into(), spec.image.clone());

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
            let uid =
                fields[2]
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

fn build_resources(spec: &AppSpec) -> Result<oci_spec::runtime::LinuxResources> {
    let mut builder = LinuxResourcesBuilder::default();

    if let Some(mem) = &spec.resources.memory {
        let bytes = resources::parse_memory(mem)?;
        let mem_cfg = LinuxMemoryBuilder::default()
            .limit(i64::try_from(bytes).unwrap_or(i64::MAX))
            .build()?;
        builder = builder.memory(mem_cfg);
    }

    if let Some(cpu) = &spec.resources.cpu {
        let (quota, period) = resources::parse_cpu(cpu)?;
        let cpu_cfg = LinuxCpuBuilder::default()
            .quota(quota)
            .period(period)
            .build()?;
        builder = builder.cpu(cpu_cfg);
    }

    Ok(builder.build()?)
}

fn build_mounts() -> Vec<Mount> {
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

    mounts
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

    fn make_app_spec(image: &str, port: u16) -> AppSpec {
        let toml = format!(
            r#"image = "{image}"
port = {port}
name = "myapp"

[env]
LOG_LEVEL = "info"

[resources]
memory = "256MiB"
cpu = "0.5"
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
    fn spec_includes_env_port_and_resources() {
        let app = make_app_spec("ghcr.io/x/y:tag", 8081);
        let image = make_image_config(vec!["/bin/run"], vec!["--serve"]);
        let rootfs = PathBuf::from("/tmp/bugpot-test-rootfs");
        let spec = build_spec(&SpecInputs {
            spec: &app,
            image_config: &image,
            rootfs: &rootfs,
            netns_path: None,
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

        // Resources: memory 256MiB = 268435456 bytes; cpu 0.5 -> 50000/100000
        let linux = spec.linux().as_ref().unwrap();
        let res = linux.resources().as_ref().unwrap();
        let mem = res.memory().as_ref().unwrap();
        assert_eq!(mem.limit().unwrap(), 256 * 1024 * 1024);
        let cpu = res.cpu().as_ref().unwrap();
        assert_eq!(cpu.quota().unwrap(), 50_000);
        assert_eq!(cpu.period().unwrap(), 100_000);

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
        let app = make_app_spec("ghcr.io/x/y:tag", 8080);
        let image = make_image_config(vec!["/bin/run"], vec![]);
        let rootfs = PathBuf::from("/tmp/bugpot-rootfs");
        let netns = PathBuf::from("/var/run/netns/bugpot-myapp");

        let spec = build_spec(&SpecInputs {
            spec: &app,
            image_config: &image,
            rootfs: &rootfs,
            netns_path: Some(&netns),
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
        let app = make_app_spec("ghcr.io/x/y:tag", 8080);
        let image = make_image_config(vec!["/bin/run"], vec![]);
        let spec = build_spec(&SpecInputs {
            spec: &app,
            image_config: &image,
            rootfs: Path::new("/tmp/rootfs"),
            netns_path: None,
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
image = "ghcr.io/x/y:tag"
port = 8080
name = "x"

[env]
PORT = "9999"
"#;
        let app: AppSpec = toml::from_str(toml).unwrap();
        let image = make_image_config(vec!["/run"], vec![]);
        let spec = build_spec(&SpecInputs {
            spec: &app,
            image_config: &image,
            rootfs: Path::new("/tmp/rootfs"),
            netns_path: None,
        })
        .unwrap();

        let env = spec.process().as_ref().unwrap().env().as_ref().unwrap();
        let port_entries: Vec<_> = env.iter().filter(|e| e.starts_with("PORT=")).collect();
        assert_eq!(port_entries.len(), 1);
        assert_eq!(port_entries[0], "PORT=9999");
    }

    #[test]
    fn errors_when_image_has_no_entrypoint_or_cmd() {
        let app = make_app_spec("ghcr.io/x/y:tag", 8080);
        let image = ConfigFile {
            config: Some(ImageConfig::default()),
            rootfs: Rootfs::default(),
            ..Default::default()
        };
        let err = build_spec(&SpecInputs {
            spec: &app,
            image_config: &image,
            rootfs: Path::new("/tmp/rootfs"),
            netns_path: None,
        })
        .unwrap_err();
        match err {
            RuntimeError::Other(msg) => assert!(msg.contains("entrypoint")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
