//! The overlayfs on `/usr` that makes an install survive a reboot.
//!
//! This is the part vez has to own on Svara, and the part that has no upstream equivalent.
//! Svara mounts its overlay from a dracut module before the system starts; `bootc
//! usr-overlay` mounts a **tmpfs**, so what it installs lives in RAM and dies at reboot.
//! That tmpfs is exactly what `dnf5 --transient` uses, and it is why a package installed
//! that way is gone after a restart — the behaviour is documented, not a bug.
//!
//! Vez instead mounts overlayfs with its upperdir on disk, under `/var`:
//!
//! ```text
//! lowerdir = /usr                  the deployment's own, read-only
//! upperdir = /var/lib/svara/vez/overlay/upper
//! workdir  = /var/lib/svara/vez/overlay/work
//! ```
//!
//! `/var` is the one writable path that survives everything else — a reboot, and a base
//! image update — so the files a package installs stay there, and the mount is rebuilt from
//! them on every boot. The rpmdb entry lives in [`crate::paths::RPMDB`], also under `/var`,
//! so metadata and files are restored together.
//!
//! **Who calls [`mount`] at boot is not settled, and nothing calls it yet.** The intent is a
//! unit named `vez-overlay.service`; the open question is whether it runs as a systemd unit
//! at `sysinit` or as a dracut module in the initramfs, which is what the upstream this
//! forked from does. `mount` is written to be callable from either, so the decision does not
//! change this file — only where the unit is installed. See `docs/research/rum.md` §5.
//!
//! **Nothing here may fall back to a tmpfs overlay.** If the mount is missing, an install
//! that silently proceeded would put the files in RAM, report success, and lose them at the
//! next reboot — the precise failure this module exists to remove. So the rule is refusal:
//! see [`ensure`].

use anyhow::{bail, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// What `/usr` looks like right now, as far as vez needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountStatus {
    /// Overlayfs is mounted on `/usr`. Installs land in the persistent upperdir.
    Mounted,
    /// `/usr` is not an overlayfs. On a booted system this means the mount failed or has
    /// not run yet, and every mutating verb must refuse.
    NotMounted,
    /// `/proc/self/mountinfo` could not be read, or carried no `/usr` entry at all. Kept
    /// distinct from [`MountStatus::NotMounted`] because a missing entry is a broken
    /// environment rather than a missing mount, and the two want different messages.
    Unknown,
}

/// The upperdir path an overlayfs mount actually reports in `/proc/self/mountinfo`, if `/usr`
/// is an overlay.
///
/// mountinfo carries the mount's options after the ` - <fstype>` separator, and overlayfs puts
/// `upperdir=...` in the super options. Reading it back is how a caller can tell WHICH overlay
/// is mounted: overlayfs applied by someone else would still show up as `Mounted`, and the
/// difference between our disk-backed upperdir and a tmpfs one is the difference between a
/// package surviving a reboot and silently vanishing at it.
///
/// Returns `None` when `/usr` is not an overlay, or when the options do not name an upperdir.
pub fn mounted_upperdir() -> Option<String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    mounted_upperdir_from(&mountinfo)
}

/// The parsing half of [`mounted_upperdir`], split out so it is testable without a real mount.
///
/// **`upperdir=` IS SEARCHED IN BOTH HALVES OF THE LINE, DELIBERATELY.** The kernel reports
/// overlayfs options in the super-option list, after the ` - <fstype>` separator: `mount` passes
/// `-o lowerdir=…,upperdir=…,workdir=…`, the kernel keeps those three as super options and leaves
/// `rw` as a mount option. A first version of this function only read the half *before* the
/// separator, and its own test caught it by returning `None` for a correctly-formed line.
/// Searching both costs nothing and is right for either placement, including a line formatted by
/// an older kernel or by a tool that splits them differently.
pub fn mounted_upperdir_from(mountinfo: &str) -> Option<String> {
    for line in mountinfo.lines() {
        // `continue`, not `?`: a line without the separator is simply not the one we want, and
        // returning None on it would give up before reaching `/usr` on most real bodies.
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let mut fields = before.split_whitespace();
        let Some(point) = fields.nth(4) else { continue };
        if decode_mountinfo_path(point) != "/usr" {
            continue;
        }
        // The fstype must be overlay, or this is not an overlay at all.
        let mut rest = after.split_whitespace();
        if rest.next() != Some("overlay") {
            return None;
        }
        // Field 6 of the left half is the mount options; everything after the fstype is the
        // super options. Either can carry `upperdir=`.
        let mount_opts = before.split_whitespace().nth(5).unwrap_or("");
        let super_opts = rest.collect::<Vec<_>>().join(" ");
        for haystack in [super_opts.as_str(), mount_opts] {
            for opt in haystack.split(',') {
                if let Some(v) = opt.strip_prefix("upperdir=") {
                    return Some(decode_mountinfo_path(v));
                }
            }
        }
        return None;
    }
    None
}

/// Find the filesystem type mounted at `mount_point` in a `/proc/self/mountinfo` body.
///
/// The format is `<id> <parent> <maj>:<min> <root> <mount point> <options> [optional
/// fields] - <fstype> <source> <super options>`. The ` - ` separator is what makes this
/// parseable: every field before it is variable in number, so counting from the left is
/// wrong. The mount point is field 5 either way.
///
/// Paths in mountinfo encode space, tab, newline and backslash in octal (`\040` etc.), so
/// the comparison is done on the decoded path; `/usr` itself never needs this, but a
/// caller passing a path with a space would otherwise silently never match.
pub fn fstype_at(mountinfo: &str, mount_point: &str) -> Option<String> {
    for line in mountinfo.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let mut fields = before.split_whitespace();
        // field 5 (1-based) is the mount point.
        let Some(point) = fields.nth(4) else { continue };
        if decode_mountinfo_path(point) != mount_point {
            continue;
        }
        // The first field after ` - ` is the filesystem type.
        if let Some(fstype) = after.split_whitespace().next() {
            return Some(fstype.to_string());
        }
    }
    None
}

/// Decode the octal escapes `/proc/self/mountinfo` uses for space, tab, newline and
/// backslash.
fn decode_mountinfo_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &raw[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(oct, 8) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Is overlayfs currently mounted on `/usr`?
pub fn status() -> MountStatus {
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return MountStatus::Unknown;
    };
    match fstype_at(&mountinfo, "/usr") {
        Some(t) if t == "overlay" => MountStatus::Mounted,
        Some(_) => MountStatus::NotMounted,
        None => MountStatus::Unknown,
    }
}

/// Mount the persistent overlay on `/usr`, or fail.
///
/// Idempotent: already-mounted is success, because the boot unit and a manual run must not
/// fight. Shells out to `mount -t overlay` rather than calling `mount(2)` directly — the
/// kernel's mount API needs a `lowerdir=...,upperdir=...,workdir=...` string either way,
/// and the util-linux command is the one whose behaviour is documented and testable.
///
/// Requires root, and requires `workdir` to be on the same filesystem as `upperdir`
/// (overlayfs refuses otherwise). Both directories are created if absent, because the boot
/// unit may run before anything else has made them.
pub fn mount(upper: &Path, work: &Path) -> Result<()> {
    match status() {
        MountStatus::Mounted => return Ok(()),
        // `Unknown` is worth attempting anyway: a container without a readable mountinfo
        // would otherwise be unable to report why it failed.
        _ => {}
    }

    for (what, dir) in [("upperdir", upper), ("workdir", work)] {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating the overlay {what} {}", dir.display()))?;
    }

    // THE UPPERDIR'S MODE IS /usr's MODE, WHICH IS WHY IT IS SET HERE AND NOT LEFT TO THE
    // UMASK. Overlayfs gives a merged directory the attributes of its upper counterpart, and
    // the upperdir IS the merged root — an upperdir of 0700 makes the overlay report /usr as
    // `drwx------`. Root still traverses that, so nothing looks wrong as root; every service
    // systemd execs AS A NON-ROOT USER is refused with EACCES, which at boot looks like
    // dbus-broker, polkit, systemd-resolved, rtkit, avahi and upower all failing together
    // and no login prompt. `create_dir_all` alone is not enough, for two reasons: it honours
    // the process umask, and it does nothing at all when the directory already exists — and
    // `tmpfiles.d/svara.conf` has usually created it already.
    //
    // THIS SET IS WHAT THE MOUNT USES, BUT IT IS NOT SUFFICIENT ON ITS OWN, and the boot is
    // what taught that: `systemd-tmpfiles-setup.service` runs a SECOND time AFTER this unit
    // and re-applies the tmpfiles entry to the upperdir. A `tmpfiles.d/svara.conf` that still
    // declared 0700 therefore overrode this and the machine came up broken regardless —
    // measured, not reasoned: tmpfiles re-ran 7 ms after the mount. The two must agree, and
    // both are 0755. The workdir is internal to overlayfs and is never merged, so it stays
    // 0700 as `tmpfiles.d/svara.conf` declares it.
    for (dir, mode) in [(upper, 0o755), (work, 0o700)] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode on {}", dir.display()))?;
    }

    let opts = format!(
        "lowerdir=/usr,upperdir={},workdir={}",
        upper.display(),
        work.display()
    );
    let out = std::process::Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &opts, "/usr"])
        .output()
        .context("running `mount -t overlay` (is util-linux present?)")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "mounting the persistent overlay on /usr failed: {}",
            stderr.trim()
        );
    }

    // Trust the result, not the exit status. `mount` can exit 0 having mounted nothing
    // useful (a second mount landing somewhere else), and an install that proceeds on a
    // wrong `upperdir` writes files that the next boot will not restore.
    match status() {
        MountStatus::Mounted => Ok(()),
        other => bail!(
            "`mount` reported success but /usr is still not an overlayfs ({other:?}); \
             refusing to treat this as a usable extra layer"
        ),
    }
}

/// The guard every mutating verb calls before it writes anything.
///
/// On a booted system the overlay **must** be up, because otherwise the package's files
/// would go to the read-only `/usr` (failing loudly, which is fine) or, worse, to a tmpfs
/// overlay someone else mounted (succeeding, then vanishing at reboot). Standalone
/// environments — distrobox, podman, an image build — have no overlay and are already
/// writable, so they are not asked for one.
///
/// **The unit exists and is verified on real hardware.** `vez-overlay.service` mounts the
/// overlay at boot, so the refusal below can name something that is actually there. Its
/// ordering (`DefaultDependencies=no`, `After=local-fs.target`, `Before=sysinit.target`) is
/// bootc's own arrangement for early `/usr` overlay work, and it was confirmed on an installed
/// machine: the unit reported `active (exited)`, `status=0/SUCCESS`, and `vez overlay status`
/// then reported `mounted on /usr`. The dracut fallback RakuOS uses was not needed. See
/// `docs/plan/package-manager.md`.
///
/// It refuses in three cases, and the second is the subtle one:
///
/// 1. the live medium — `standalone` but RAM-backed, see the top of this function;
/// 2. `/usr` is an overlay **that is not vez's** — `bootc usr-overlay` also mounts one, and
///    `Mounted` cannot tell them apart, so the upperdir is compared;
/// 3. nothing is mounted on `/usr`.
pub fn ensure(paths: &crate::OverlayPaths) -> Result<()> {
    // The live medium first, and BEFORE the Standalone early-return below. A live medium has
    // no /run/ostree-booted, so it is detected as Standalone — where the early return would
    // wave the transaction through, and the write would land in the live root's tmpfs. The
    // result is a package that installs, reports success, and is gone at the next reboot:
    // the exact failure this module exists to remove, reached through the one code path that
    // has no overlay to inspect.
    if crate::paths::is_live_medium() {
        bail!(
            "this is the live medium, not an installed system.\n\
             A package installed here would go into the live root's RAM-backed overlay and be\n\
             gone at the next reboot. Install Svara to a disk first, then install packages."
        );
    }
    if matches!(paths.mode, crate::OverlayMode::Standalone) || paths.installroot.is_some() {
        return Ok(());
    }
    match status() {
        MountStatus::Mounted => {
            // AN OVERLAY IS NOT NECESSARILY OURS. `bootc usr-overlay` also mounts an overlay on
            // /usr, and the fstype check above cannot tell them apart. Getting this wrong means
            // the exact failure this module exists to remove — an install that succeeds, reports
            // success, and is gone at reboot — so the mounted upperdir is compared with the one
            // vez configured, and a mismatch is REFUSED rather than warned about for the same
            // reason a missing mount is.
            match (mounted_upperdir(), paths.overlay_upper.to_str()) {
                (Some(actual), Some(expected)) if actual != expected => bail!(
                    "/usr is an overlayfs, but not vez's own:\n\
                     \x20 mounted upperdir:   {actual}\n\
                     \x20 vez's upperdir is:  {expected}\n\
                     An install would go to the mounted upperdir and vez would not restore it at\n\
                     the next boot. `bootc usr-overlay` is the usual cause: its overlay is backed\n\
                     by tmpfs, in RAM, and is discarded on reboot.\n\
                     Lazy-unmount the other overlay (`sudo umount -l /usr`) and reboot so\n\
                     vez-overlay.service brings up vez's."
                ),
                _ => Ok(()),
            }
        }
        MountStatus::NotMounted => bail!(
            "the persistent overlay on /usr is not mounted, so an install would not survive a reboot.\n\
             Vez deliberately does not fall back to `bootc usr-overlay`: that overlay is backed by\n\
             tmpfs, so anything installed through it is discarded on the next boot.\n\
             Start it with `sudo systemctl restart vez-overlay.service`, or `sudo vez overlay mount`.\n\
             `vez overlay status` reports what is actually mounted."
        ),
        MountStatus::Unknown => bail!(
            "could not read /proc/self/mountinfo, so vez cannot tell whether the persistent overlay\n\
             on /usr is mounted. Refusing to write rather than guessing."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mountinfo body with the shapes that matter: the root, `/usr` as an overlay, and a
    /// nested mount whose mount point is a prefix of another (`/usr` and `/usr/local`).
    const SAMPLE: &str = "\
25 30 0:24 / / rw,relatime - ext4 /dev/vda3 rw
30 25 0:26 / /usr rw,relatime - overlay overlay rw,lowerdir=/usr,upperdir=/var/lib/svara/vez/overlay/upper
31 30 0:27 / /usr/local rw,relatime - ext4 /dev/vdb1 rw
32 25 0:28 / /var rw,relatime - xfs /dev/vda4 rw
";

    #[test]
    fn finds_the_filesystem_type_at_a_mount_point() {
        assert_eq!(fstype_at(SAMPLE, "/"), Some("ext4".to_string()));
        assert_eq!(fstype_at(SAMPLE, "/usr"), Some("overlay".to_string()));
        assert_eq!(fstype_at(SAMPLE, "/var"), Some("xfs".to_string()));
    }

    #[test]
    fn a_nested_mount_does_not_shadow_its_parent() {
        // `/usr/local` being ext4 must not make `/usr` look like anything but overlay.
        // Counting fields rather than prefix-matching is what buys this.
        assert_eq!(fstype_at(SAMPLE, "/usr"), Some("overlay".to_string()));
        assert_eq!(fstype_at(SAMPLE, "/usr/local"), Some("ext4".to_string()));
    }

    #[test]
    fn decodes_octal_escapes_in_mount_points() {
        // mountinfo escapes a space as \040. A path with a space must still compare equal
        // to itself, or the entry is invisible.
        let body = "40 25 0:29 / /mnt/my\\040disk rw,relatime - ext4 /dev/vdc1 rw\n";
        assert_eq!(fstype_at(body, "/mnt/my disk"), Some("ext4".to_string()));
    }

    #[test]
    fn a_missing_mount_point_is_none_not_a_wrong_answer() {
        assert_eq!(fstype_at(SAMPLE, "/nope"), None);
        assert_eq!(fstype_at("", "/usr"), None);
    }

    #[test]
    fn a_line_without_the_separator_is_skipped() {
        // Truncated or synthetic input must not panic or match a field from the wrong line.
        assert_eq!(fstype_at("garbage without a separator\n", "/usr"), None);
    }

    #[test]
    fn reads_the_upperdir_back_out_of_mountinfo() {
        // This is how a caller tells OUR overlay from someone else's. An overlayfs applied by
        // `bootc usr-overlay` is also `Mounted`, so the fstype alone cannot distinguish a
        // disk-backed upperdir (a package survives a reboot) from a tmpfs one (it vanishes).
        let body = "\
25 30 0:24 / / rw,relatime - ext4 /dev/vda3 rw
30 25 0:26 / /usr rw,relatime - overlay overlay rw,lowerdir=/usr,upperdir=/var/lib/svara/vez/overlay/upper,workdir=/var/lib/svara/vez/overlay/work
";
        assert_eq!(
            mounted_upperdir_from(body).as_deref(),
            Some("/var/lib/svara/vez/overlay/upper")
        );
    }

    #[test]
    fn a_tmpfs_backed_overlay_is_reported_as_its_real_upperdir() {
        // The dangerous case: still an overlay, still `Mounted`, upperdir in RAM. The function
        // reports the truth — that the upperdir is not ours — and the caller decides.
        let body = "30 25 0:26 / /usr rw,relatime - overlay overlay rw,upperdir=/run/bootc/overlay,workdir=/run/bootc/work\n";
        assert_eq!(
            mounted_upperdir_from(body).as_deref(),
            Some("/run/bootc/overlay")
        );
    }

    #[test]
    fn no_usr_overlay_means_no_upperdir() {
        let body = "25 30 0:24 / / rw,relatime - ext4 /dev/vda3 rw\n";
        assert_eq!(mounted_upperdir_from(body), None);
    }

    #[test]
    fn usr_mounted_as_something_other_than_overlay_is_not_an_overlay() {
        let body = "30 25 0:26 / /usr rw,relatime - ext4 /dev/vdb1 rw\n";
        assert_eq!(mounted_upperdir_from(body), None);
    }
}
