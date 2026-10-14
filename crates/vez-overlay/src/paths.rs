//! The one place vez's on-disk locations are defined.
//!
//! Every path vez uses lives here as a constant, and the rest of the workspace reads
//! them from this module rather than repeating a literal. A fork that scatters
//! `/var/lib/<distro>/...` through its crates cannot be repointed, and repointing is the
//! one thing a fork is for: the upstream this came from had the same paths spelled out in
//! four crates, which is the mistake this module exists to not repeat.
//!
//! The split these paths implement is the whole reason vez exists. Svara's base is a
//! read-only OSTree deployment, so `/usr` comes from the image and is replaced wholesale by
//! the next one; `/etc` and `/var` are the only writable, persistent paths. Nothing
//! installed can therefore be recorded in the base rpmdb, and nothing can be written into
//! `/usr` directly. Vez records packages in its own rpmdb under `/var` and writes their
//! *files* into an overlayfs on `/usr` whose upperdir is also under `/var` — so the files
//! survive a reboot even though the mount does not.
//!
//! See `docs/plan/package-manager.md` for why the alternative — `bootc usr-overlay`, which
//! is what `dnf5 --transient` uses — cannot work: it is backed by tmpfs, so whatever it
//! installs is in RAM and is gone on the next boot.

use std::path::{Path, PathBuf};

/// The base image's rpmdb, as deployed. Read-only, and vez never writes it.
///
/// `/usr/lib/sysimage/rpm` is a symlink to this, which is why the real path is the one
/// named here: the symlink is an implementation detail of how rpm and dnf look the
/// database up, not a second database.
pub const BASE_RPMDB: &str = "/usr/share/rpm";

/// Vez's own rpmdb: every package vez installed, and nothing else.
///
/// Separate from [`BASE_RPMDB`] rather than merged into it, because `/usr` — which is where
/// the base db lives — is read-only and belongs to the image. The resolver unions the two
/// at query time instead.
pub const RPMDB: &str = "/var/lib/svara/vez/rpmdb";

/// Vez's state directory: history, reasons, versionlock, module state, GPG keys.
pub const STATE: &str = "/var/lib/svara/vez";

/// Where vez keeps its transaction history (`history.jsonl`) and package reasons
/// (`reasons.json`).
///
/// Kept apart from the rpmdb because rpm and dnf have no concept of either; dnf5 keeps its
/// equivalents in its own state directory under `/var/lib/dnf5` for the same reason.
pub const STATE_DB: &str = "/var/lib/svara/vez/state";

/// The overlayfs upperdir. **This is the directory that makes an install survive a
/// reboot**, so it must stay under `/var` and must never be moved to tmpfs.
pub const OVERLAY_UPPER: &str = "/var/lib/svara/vez/overlay/upper";

/// The overlayfs workdir. Overlayfs requires one, and it must be on the same filesystem as
/// [`OVERLAY_UPPER`].
pub const OVERLAY_WORK: &str = "/var/lib/svara/vez/overlay/work";

/// Repo metadata and downloaded packages, kept between runs so a [replay](crate::mount) can
/// reinstall without network access.
pub const CACHE: &str = "/var/cache/vez";

/// The names of the packages vez installed, one per line.
///
/// Written after every successful transaction and read by a replay, so this file plus
/// [`CACHE`] is the complete recipe for restoring the extra layer.
pub const PACKAGES_LIST: &str = "/var/lib/svara/vez/packages.list";

/// The counterpart to [`PACKAGES_LIST`] for packages installed from a local `.rpm` file.
///
/// Kept separate because a replay cannot resolve these from a repo — the name may not exist
/// in any enabled repository, and the version installed may not be the current candidate —
/// so the file itself has to be cached (see [`LOCAL_RPM_CACHE`]).
pub const LOCAL_RPM_LIST: &str = "/var/lib/svara/vez/packages-rpm.list";

/// Where the `.rpm` file for each [`LOCAL_RPM_LIST`] entry is cached as `<name>.rpm`.
pub const LOCAL_RPM_CACHE: &str = "/var/lib/svara/vez/local-rpms";

/// The main config file, in the `dnf.conf` INI subset `vez-repo` parses.
pub const CONF: &str = "/etc/vez/vez.conf";

/// Repo definitions. Vez reads the standard dnf/yum location rather than a private one, so
/// Fedora, RPM Fusion and COPR repos work unmodified.
pub const REPOS_DIR: &str = "/etc/yum.repos.d";

/// The declarative package set: what this machine should have, for `vez apply`.
///
/// Root-owned and machine-wide, in the same shape as `config/payload.toml`, so the set can
/// be copied between machines. Nothing reads it yet — see `docs/plan/package-manager.md`
/// milestone 4.
pub const PACKAGES_TOML: &str = "/etc/svara/packages.toml";

/// The extra layer's record of which deployment generation it was last built against.
///
/// Its **absence** is meaningful and harmless: a machine that has never installed anything has
/// no layer to restore. See [`crate::state`] for why a reboot does not need a replay but a
/// `bootc upgrade` does.
pub const LAYER_STATE: &str = "/var/lib/svara/vez/state/layer-state.toml";

/// Is this process running on a booted OSTree/bootc system, as opposed to a container, a
/// distrobox, or an image-build chroot?
///
/// `/run/ostree-booted` is written by the initramfs and the ostree boot unit, so it exists
/// only on a real boot and is absent in every image build — which is exactly the
/// distinction needed, and the one that `/etc/os-release` cannot make. An image build's
/// `os-release` already says `ID=svara` long before any boot, and upstream this fork came
/// from had a bug where trusting it forced the overlay path onto builds that had no
/// overlay, which split one rpmdb view into a stale base plus a separate overlay and pulled
/// unrelated already-installed packages into transactions.
pub fn is_booted_ostree() -> bool {
    Path::new("/run/ostree-booted").exists()
}

/// The kernel command line this process booted with.
pub const PROC_CMDLINE: &str = "/proc/cmdline";

/// Is `key=value` present as a whole word on a kernel command line?
///
/// Whole-word matching, not a substring search: `svara.live=1` must not be satisfied by
/// `not-svara.live=1` or `svara.live=10`. The same rule applies to systemd's
/// `ConditionKernelCommandLine=`, which is the other half of this gate — if the two ever
/// disagree, the live medium shows one thing and vez believes another.
///
/// Split out from [`is_live_medium`] so the matching rule is testable without a real
/// `/proc/cmdline`.
pub fn cmdline_has(cmdline: &str, key: &str, value: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|word| word == format!("{key}={value}"))
}

/// Is this the live medium — the ISO booted in memory — rather than an installed machine?
///
/// Told apart by `svara.live=1` on the kernel command line, which is the SAME marker the
/// systemd live gate uses: `svara-live.service` requires it and `sddm.service`'s drop-in
/// negates it. One marker, three consumers, no second source of truth.
///
/// **This is load-bearing, not informational.** A live medium has no
/// `/run/ostree-booted`, so [`crate::OverlayPaths::detect`] answers `Standalone` — in which
/// `/usr` is writable and nothing objects. But a live medium's `/usr` is a tmpfs overlay
/// built from the squashfs, so a package installed there lives in RAM and is gone at the
/// next reboot. That is precisely the failure this design exists to remove, arriving through
/// the one path that has no overlay to check for, so live mode must be refused explicitly
/// rather than inferred from a missing marker.
pub fn is_live_medium() -> bool {
    std::fs::read_to_string(PROC_CMDLINE)
        .map(|c| cmdline_has(&c, "svara.live", "1"))
        .unwrap_or(false)
}

/// [`RPMDB`] resolved under an `--installroot`, for image builds and test reproduction.
///
/// The same relative layout as the real path, so copying it out of the installroot drops
/// it path for path into a factory tree.
pub fn installroot_rpmdb(root: &Path) -> PathBuf {
    root.join("var/lib/svara/vez/rpmdb")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live medium's real cmdline, from `tools-build-iso.sh`'s GRUB entry.
    const LIVE: &str = "linux  /boot/vmlinuz svara.live=1 enforcing=0 rd.live.image root=live:CDLABEL=SVARA rd.live.dir=LiveOS rd.live.squashimg=rootfs.squashfs console=tty0 console=ttyS0,115200";
    /// An installed machine's — the same image, with no live marker.
    const INSTALLED: &str = "BOOT_IMAGE=/boot/vmlinuz-6.16.0 root=UUID=abc rhgb quiet";

    #[test]
    fn finds_the_live_marker_on_the_real_live_cmdline() {
        assert!(cmdline_has(LIVE, "svara.live", "1"));
    }

    #[test]
    fn an_installed_machine_has_no_live_marker() {
        assert!(!cmdline_has(INSTALLED, "svara.live", "1"));
    }

    #[test]
    fn the_marker_is_matched_as_a_whole_word() {
        // Each of these is a plausible way to get this wrong. A substring search would
        // accept all of them and put an installed machine into live mode, which would make
        // vez refuse to install on a machine that is perfectly capable of it.
        assert!(!cmdline_has("not-svara.live=1", "svara.live", "1"));
        assert!(!cmdline_has("xsvara.live=1", "svara.live", "1"));
        assert!(!cmdline_has("svara.live=10", "svara.live", "1"));
        assert!(!cmdline_has("svara.livex=1", "svara.live", "1"));
        // A bare `svara.live` with no value is not `svara.live=1`.
        assert!(!cmdline_has("svara.live", "svara.live", "1"));
        // ...and the real thing, including when it is not the first token.
        assert!(cmdline_has("quiet svara.live=1", "svara.live", "1"));
    }

    #[test]
    fn an_empty_or_absent_cmdline_is_not_live() {
        // Fail-safe direction: an unreadable /proc/cmdline must not make an installed machine
        // look like a live medium, or vez would refuse to work at all.
        assert!(!cmdline_has("", "svara.live", "1"));
        assert!(!cmdline_has("   \n  ", "svara.live", "1"));
    }

    #[test]
    fn paths_are_the_documented_svara_layout() {
        // One place to change, and nothing else may spell a vez path out.
        assert_eq!(RPMDB, "/var/lib/svara/vez/rpmdb");
        assert_eq!(OVERLAY_UPPER, "/var/lib/svara/vez/overlay/upper");
        assert_eq!(PACKAGES_LIST, "/var/lib/svara/vez/packages.list");
        assert_eq!(PACKAGES_TOML, "/etc/svara/packages.toml");
        assert_eq!(BASE_RPMDB, "/usr/share/rpm");
    }
}
