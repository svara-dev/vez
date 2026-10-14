//! Offline-transaction support for `vez system-upgrade` in Standalone mode. A
//! Rust port of dnf5's `libdnf5::offline` plus the `dnf5 offline`/`dnf5
//! system-upgrade` plugin (upstream
//! `dnf5/commands/{offline,system-upgrade}`): download the full transaction
//! while still on the old release, then apply it before boot through
//! systemd's `system-update.target` convention
//! (`systemd-system-update-generator(8)`), so rpm, glibc, and systemd are
//! never upgraded underneath a running process tree.
//!
//! Only used under [`vez_overlay::OverlayMode::Standalone`]. A Svara overlay
//! system never does a dnf-style major-version bump this way. See
//! `system_upgrade` in `main.rs` for the Split-mode side (a normal overlay
//! package upgrade plus `bootc upgrade`).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where downloaded packages and the transaction state file live.
/// Equivalent to dnf5's `DEFAULT_DATADIR` (`/var/lib/dnf5/offline`).
pub const DATADIR: &str = "/var/lib/vez/offline";
/// systemd's "Offline Updates" trigger: `systemd-system-update-generator`
/// switches to `system-update.target` early in boot iff this exists and is a
/// symlink. The path is fixed by systemd's own contract, so it isn't
/// configurable.
pub const MAGIC_SYMLINK: &str = "/system-update";
const STATE_FILENAME: &str = "state.json";
const PACKAGES_DIRNAME: &str = "packages";
const UNIT_PATH: &str = "/etc/systemd/system/vez-system-upgrade.service";
const UNIT_NAME: &str = "vez-system-upgrade.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    DownloadIncomplete,
    DownloadComplete,
    Ready,
    TransactionIncomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub status: Status,
    pub system_releasever: String,
    pub target_releasever: String,
    pub cmd_line: String,
    #[serde(default)]
    pub poweroff_after: bool,
    /// Absolute paths of every downloaded RPM, in the order they should be
    /// handed to `rpm` at apply time.
    pub packages: Vec<PathBuf>,
}

pub fn datadir() -> PathBuf {
    PathBuf::from(DATADIR)
}

pub fn packages_dir() -> PathBuf {
    datadir().join(PACKAGES_DIRNAME)
}

fn state_path() -> PathBuf {
    datadir().join(STATE_FILENAME)
}

pub fn load_state() -> Result<Option<State>> {
    let path = state_path();
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let state: State =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(state))
}

pub fn write_state(state: &State) -> Result<()> {
    std::fs::create_dir_all(datadir())?;
    let path = state_path();
    let text = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
}

/// Removes downloaded packages and the state file but leaves the systemd unit
/// installed, like dnf5's `offline clean`. A disabled unit gated on
/// `ConditionPathExists=/system-update` is harmless to leave around.
pub fn clean() -> Result<()> {
    let _ = std::fs::remove_file(MAGIC_SYMLINK);
    let dir = datadir();
    if dir.is_dir() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    Ok(())
}

/// Writes and enables the systemd unit that `system-update.target` starts
/// before boot to run `vez system-upgrade execute`. The content is static, so
/// calling this on every `download` is idempotent. dnf5 ships this unit in
/// its package instead of writing it at runtime; vez does it here because it
/// has no separate subpackage to carry systemd units.
pub fn install_unit() -> Result<()> {
    let unit = "[Unit]\n\
Description=vez offline system upgrade\n\
ConditionPathExists=/system-update\n\
\n\
[Service]\n\
Type=oneshot\n\
ExecStart=/usr/bin/vez system-upgrade execute\n\
StandardOutput=journal+console\n\
StandardError=journal+console\n\
\n\
[Install]\n\
WantedBy=system-update.target\n";
    std::fs::write(UNIT_PATH, unit).with_context(|| format!("writing {UNIT_PATH}"))?;
    let status = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        eprintln!("warning: `systemctl daemon-reload` failed; the offline-upgrade unit may not take effect");
    }
    let status = std::process::Command::new("systemctl")
        .args(["enable", UNIT_NAME])
        .status();
    if !matches!(status, Ok(s) if s.success()) {
        eprintln!("warning: `systemctl enable {UNIT_NAME}` failed; run it manually before `system-upgrade reboot`");
    }
    Ok(())
}

/// Sanity check from `dnf5 offline reboot`: refuse to reboot into the
/// transaction if the unit isn't wanted by `system-update.target`. Otherwise
/// the machine would boot straight back to `default.target` without doing
/// anything.
pub fn unit_is_wanted() -> bool {
    Path::new("/etc/systemd/system/system-update.target.wants")
        .join(UNIT_NAME)
        .exists()
}

pub fn create_trigger_symlink() -> Result<()> {
    if !Path::new(MAGIC_SYMLINK).is_symlink() {
        std::os::unix::fs::symlink(datadir(), MAGIC_SYMLINK)
            .with_context(|| format!("creating {MAGIC_SYMLINK} -> {}", datadir().display()))?;
    }
    Ok(())
}

pub fn remove_trigger_symlink() -> Result<()> {
    if Path::new(MAGIC_SYMLINK).is_symlink() {
        std::fs::remove_file(MAGIC_SYMLINK).with_context(|| format!("removing {MAGIC_SYMLINK}"))?;
    }
    Ok(())
}

pub fn systemctl_reboot(poweroff: bool) -> Result<()> {
    if std::env::var_os("VEZ_SYSTEM_UPGRADE_NO_REBOOT").is_some() {
        eprintln!(
            "VEZ_SYSTEM_UPGRADE_NO_REBOOT is set, not {}.",
            if poweroff {
                "powering off"
            } else {
                "rebooting"
            }
        );
        return Ok(());
    }
    let verb = if poweroff { "poweroff" } else { "reboot" };
    let status = std::process::Command::new("systemctl")
        .arg(verb)
        .status()
        .with_context(|| format!("running systemctl {verb}"))?;
    anyhow::ensure!(status.success(), "systemctl {verb} failed");
    Ok(())
}
