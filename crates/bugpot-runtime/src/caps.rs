//! Linux capability checks via `/proc/self/status`.
//!
//! Covers both "running as root" (all caps) and "non-root with
//! ambient cap" (e.g. the shipped systemd unit granting selected
//! caps to the unprivileged `bugpot` user). Reads `CapEff` —
//! the effective set — which is what kernel calls check at the
//! moment of the syscall.

/// Returns `true` iff the current process holds capability `bit` in
/// its effective set.
///
/// `bit` is a Linux capability number (see
/// `include/uapi/linux/capability.h` — e.g. `CAP_CHOWN = 0`,
/// `CAP_NET_ADMIN = 12`).
///
/// Returns `false` on any failure to read or parse `/proc/self/status`
/// so the caller treats "unable to determine" the same as "missing".
#[must_use]
pub fn has_effective_cap(bit: u32) -> bool {
    let mask: u64 = 1u64 << bit;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:").map(str::trim))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .is_some_and(|bits| bits & mask != 0)
}

/// `include/uapi/linux/capability.h: CAP_CHOWN = 0`. Used by the
/// image-cache extraction path to decide whether `chown` on
/// recovered ownership bits will succeed.
pub const CAP_CHOWN: u32 = 0;

/// `include/uapi/linux/capability.h: CAP_NET_ADMIN = 12`. Required
/// by bugpotd for bridge / veth / nftables setup.
pub const CAP_NET_ADMIN: u32 = 12;
