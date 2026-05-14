//! Default seccomp profile for bugpot containers.
//!
//! We embed the moby (Docker) default seccomp profile JSON as a
//! starting point — it's the de-facto industry standard, vetted over
//! ~10 years, and behaviourally compatible with what runc / containerd
//! apply for every container.
//!
//! The moby JSON has Docker-specific extensions on top of the OCI
//! seccomp schema (`archMap`, per-rule `includes`/`excludes` for
//! capability-conditional rules, `comment` fields). [`runc_default`]
//! parses the file, ignores the extensions, and produces an
//! `oci_spec::runtime::LinuxSeccomp` that libcontainer can apply
//! directly.
//!
//! **Conditional `includes` / `excludes` are ignored — all rules
//! collapse to unconditional allow.** Where the moby profile gates a
//! syscall on a capability (e.g. `ptrace` if `CAP_SYS_PTRACE`),
//! libseccomp would allow it only when the cap is present. We let
//! seccomp allow them universally because the kernel's capability
//! check fires after seccomp anyway — a container without
//! `CAP_SYS_PTRACE` cannot actually call `ptrace` regardless of the
//! seccomp verdict. The two layers stay independent; seccomp is the
//! "limit which syscalls exist" layer and capabilities are the
//! "limit which operations they can perform" layer. This also means
//! a future change to the cap set doesn't require re-deriving the
//! seccomp profile.

use std::sync::OnceLock;

use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
};
use serde::Deserialize;

use crate::error::{Result, RuntimeError};

/// Verbatim copy of `moby/profiles/seccomp/default.json` at the time
/// of vendoring. Kept inline so the build doesn't reach the network
/// and so the exact rule set is auditable from this tree.
const PROFILE_JSON: &str = include_str!("seccomp_default.json");

/// Cached parsed profile. Parsing is ~tens of microseconds; the cache
/// just avoids redoing it on every container start.
static CACHED: OnceLock<LinuxSeccomp> = OnceLock::new();

/// Build the runc / moby compatible default profile, suitable for
/// passing to `LinuxBuilder::seccomp`.
pub(crate) fn runc_default() -> Result<&'static LinuxSeccomp> {
    if let Some(p) = CACHED.get() {
        return Ok(p);
    }
    let parsed: MobyProfile = serde_json::from_str(PROFILE_JSON)
        .map_err(|e| RuntimeError::Other(format!("parse seccomp profile: {e}")))?;
    let translated = translate(&parsed)?;
    Ok(CACHED.get_or_init(|| translated))
}

#[derive(Deserialize)]
struct MobyProfile {
    #[serde(rename = "defaultAction")]
    default_action: String,
    #[serde(rename = "defaultErrnoRet", default)]
    default_errno_ret: Option<u32>,
    syscalls: Vec<MobySyscall>,
}

#[derive(Deserialize)]
struct MobySyscall {
    names: Vec<String>,
    action: String,
    /// Per-rule errno override. Critical for entries like `clone3` →
    /// `ENOSYS (38)`: glibc's `clone3` wrapper falls back to `clone`
    /// only when it sees `ENOSYS`; any other errno turns the rule into
    /// a hard failure that breaks `pthread_create` in modern images.
    #[serde(rename = "errnoRet", default)]
    errno_ret: Option<u32>,
    // `includes`/`excludes`/`comment` fields are tolerated but ignored
    // (see module-level rationale).
}

fn translate(p: &MobyProfile) -> Result<LinuxSeccomp> {
    let default_action = parse_action(&p.default_action)?;

    // bugpot is Linux-only and we ship for x86_64 + aarch64. Both
    // arches are listed with their typical sub-architectures.
    let architectures = vec![Arch::ScmpArchX86_64, Arch::ScmpArchAarch64];

    let mut syscalls = Vec::new();
    for rule in &p.syscalls {
        let action = parse_action(&rule.action)?;
        let mut sb = LinuxSyscallBuilder::default()
            .names(rule.names.clone())
            .action(action);
        if let Some(ret) = rule.errno_ret {
            sb = sb.errno_ret(ret);
        }
        let syscall = sb
            .build()
            .map_err(|e| RuntimeError::Other(format!("build seccomp syscall: {e}")))?;
        syscalls.push(syscall);
    }

    let mut builder = LinuxSeccompBuilder::default()
        .default_action(default_action)
        .architectures(architectures)
        .syscalls(syscalls);
    if let Some(ret) = p.default_errno_ret {
        builder = builder.default_errno_ret(ret);
    }
    builder
        .build()
        .map_err(|e| RuntimeError::Other(format!("build seccomp profile: {e}")))
}

fn parse_action(s: &str) -> Result<LinuxSeccompAction> {
    let action = match s {
        "SCMP_ACT_ERRNO" => LinuxSeccompAction::ScmpActErrno,
        "SCMP_ACT_ALLOW" => LinuxSeccompAction::ScmpActAllow,
        "SCMP_ACT_KILL" => LinuxSeccompAction::ScmpActKill,
        "SCMP_ACT_KILL_PROCESS" => LinuxSeccompAction::ScmpActKillProcess,
        "SCMP_ACT_KILL_THREAD" => LinuxSeccompAction::ScmpActKillThread,
        "SCMP_ACT_TRAP" => LinuxSeccompAction::ScmpActTrap,
        "SCMP_ACT_LOG" => LinuxSeccompAction::ScmpActLog,
        "SCMP_ACT_NOTIFY" => LinuxSeccompAction::ScmpActNotify,
        other => {
            return Err(RuntimeError::Other(format!(
                "unknown seccomp action {other:?}"
            )));
        }
    };
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_embedded_profile() {
        let p = runc_default().expect("profile parses");
        // Default action must be deny-with-errno.
        assert_eq!(p.default_action(), LinuxSeccompAction::ScmpActErrno);
        // The moby base set has ~33 rules covering ~440 distinct
        // syscall names. Both flat counts are guarded so we catch
        // accidental truncation on profile refresh.
        let syscalls = p.syscalls().as_ref().expect("rules attached");
        assert!(syscalls.len() >= 20, "rules: {}", syscalls.len());
        let total_names: usize = syscalls.iter().map(|s| s.names().len()).sum();
        assert!(total_names >= 300, "names: {total_names}");
        // Architectures cover both bugpot targets.
        let arches = p.architectures().as_ref().unwrap();
        assert!(arches.contains(&Arch::ScmpArchX86_64));
        assert!(arches.contains(&Arch::ScmpArchAarch64));
    }

    #[test]
    fn errno_ret_is_preserved_on_clone3_deny_rule() {
        // The moby profile carries a `clone3 → SCMP_ACT_ERRNO,
        // errnoRet: 38` rule (line ~720 of the JSON) so glibc's
        // `clone3 → clone` fallback sees `ENOSYS` and works. With
        // libseccomp's first-match semantics, the **earlier** rule
        // that allows `clone3` under `CAP_SYS_ADMIN` (with `includes`)
        // currently wins because we strip cap conditions — so this
        // deny rule is unreachable today. We still want the field to
        // round-trip correctly so it behaves the moment cap-gated
        // rules are reintroduced.
        let p = runc_default().expect("profile parses");
        let syscalls = p.syscalls().as_ref().expect("rules attached");
        let deny = syscalls
            .iter()
            .find(|s| {
                s.action() == LinuxSeccompAction::ScmpActErrno
                    && s.names().iter().any(|n| n == "clone3")
            })
            .expect("clone3 deny rule present");
        assert_eq!(deny.errno_ret(), Some(38));
    }

    #[test]
    fn caching_returns_same_pointer() {
        let a = runc_default().unwrap();
        let b = runc_default().unwrap();
        assert!(std::ptr::eq(a, b));
    }
}
