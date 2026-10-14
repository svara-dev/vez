//! A small append-only transaction log, plus the `install`-reason tracking
//! that `autoremove`/`mark`/`history` need. dnf keeps this in a full sqlite
//! "swdb". vez has neither that infrastructure nor a need for its query
//! flexibility, so this is a JSON-lines file under
//! [`vez_overlay::OverlayPaths::state_dir`]: one line per transaction,
//! append-only, readable, easy to `grep`.
//!
//! Every write here is best-effort. Failing to record history must never fail
//! the rpm transaction, which has already happened by the time we record it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use vez_overlay::OverlayPaths;

/// Backs `history_record=` (dnf default: `true`). `false` only stops new
/// entries being *appended* to the history log. Install-reason tracking
/// (`reasons.json`, which `autoremove`/`mark` depend on) is a separate thing
/// in dnf and keeps working either way, matching dnf's split between its
/// history/swdb table and its yumdb reason tracking.
static HISTORY_RECORD: AtomicBool = AtomicBool::new(true);

pub fn set_history_record(enabled: bool) {
    HISTORY_RECORD.store(enabled, Ordering::Relaxed);
}

/// Why a package is installed. Close enough to dnf's install reason for
/// `autoremove`/`mark` to behave the same: a `Dependency` install that
/// nothing depends on anymore is an autoremove candidate, and a `User`
/// (explicit) one never is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    User,
    Dependency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Install,
    Remove,
    Upgrade,
    Reinstall,
    Downgrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: u64,
    pub unix_time: u64,
    pub action: Action,
    /// `(nevra, reason)` for every package this transaction touched.
    pub packages: Vec<(String, Reason)>,
}

fn log_path(paths: &OverlayPaths) -> PathBuf {
    paths.state_dir.join("history.jsonl")
}

fn reasons_path(paths: &OverlayPaths) -> PathBuf {
    paths.state_dir.join("reasons.json")
}

/// Appends one entry to the history log and updates the stored
/// name→[`Reason`] map (`Remove` entries drop the name from the map, since an
/// uninstalled package has no reason to track). Errors are only for callers
/// that check them. History is diagnostic, so callers should log and continue
/// on failure instead of failing an rpm transaction that already completed.
pub fn record(paths: &OverlayPaths, action: Action, packages: &[(String, Reason)]) -> Result<()> {
    std::fs::create_dir_all(&paths.state_dir)
        .with_context(|| format!("creating {}", paths.state_dir.display()))?;

    let mut reasons = read_reasons(paths).unwrap_or_default();
    for (nevra, reason) in packages {
        // Splitting `nevra` on '-' truncates a hyphenated package name (e.g.
        // `vulkan-loader`, `mesa-dri-drivers`) to its first segment and files
        // it in `reasons.json` under the wrong key. `reason_of` then returns
        // `None` (assume `User`) and `autoremove` never touches it.
        // `Nevra::parse_nevra`/`parse_nvra` split from the right, so they get
        // the name right whatever hyphens it has.
        let name = vez_core::Nevra::parse_nevra(nevra)
            .or_else(|| vez_core::Nevra::parse_nvra(nevra))
            .map(|n| n.name)
            .unwrap_or_else(|| nevra.split('-').next().unwrap_or(nevra).to_string());
        if action == Action::Remove {
            reasons.remove(&name);
        } else if *reason == Reason::User || reasons.get(&name) != Some(&Reason::User) {
            // A package the user installed explicitly in an earlier step must
            // not drop to `Dependency` just because a *later*, unrelated
            // transaction touches it (e.g. it lands in another
            // install/upgrade's download set without being one of the names
            // typed this time). Otherwise `autoremove` could remove something
            // the user asked for. `Reason::User` only goes away through an
            // explicit `vez mark remove`, which calls `set_reason` (a
            // deliberate overwrite) instead of coming through this path.
            reasons.insert(name, *reason);
        }
    }
    std::fs::write(reasons_path(paths), serde_json::to_string_pretty(&reasons)?)
        .context("writing reasons.json")?;

    if !HISTORY_RECORD.load(Ordering::Relaxed) {
        return Ok(());
    }

    let entry = HistoryEntry {
        id: next_id(paths),
        unix_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        action,
        packages: packages.to_vec(),
    };
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path(paths))
        .with_context(|| format!("opening {}", log_path(paths).display()))?;
    writeln!(f, "{}", serde_json::to_string(&entry)?)?;
    Ok(())
}

fn next_id(paths: &OverlayPaths) -> u64 {
    list(paths)
        .map(|entries| entries.last().map(|e| e.id + 1).unwrap_or(1))
        .unwrap_or(1)
}

/// Every recorded transaction, oldest first.
pub fn list(paths: &OverlayPaths) -> Result<Vec<HistoryEntry>> {
    let path = log_path(paths);
    let Ok(f) = std::fs::File::open(&path) else {
        return Ok(Vec::new());
    };
    std::io::BufReader::new(f)
        .lines()
        .filter_map(|l| l.ok())
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(&l).with_context(|| format!("parsing {}", path.display())))
        .collect()
}

fn read_reasons(paths: &OverlayPaths) -> Result<HashMap<String, Reason>> {
    let path = reasons_path(paths);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Every recorded install reason, read once. For callers that look up many
/// names (autoremove) so they don't re-read and re-parse `reasons.json` per
/// name through [`reason_of`]. Unreadable or corrupt state reads as empty,
/// the same way [`reason_of`] treats it.
pub fn all_reasons(paths: &OverlayPaths) -> HashMap<String, Reason> {
    read_reasons(paths).unwrap_or_default()
}

/// Why `name` is currently installed, if vez ever recorded it. `None` for
/// anything installed before history tracking existed (base-image packages,
/// or overlay packages from before this feature shipped), which `autoremove`
/// treats as "assume User" and never removes automatically.
pub fn reason_of(paths: &OverlayPaths, name: &str) -> Option<Reason> {
    read_reasons(paths).ok().and_then(|r| r.get(name).copied())
}

/// Sets (or resets) `name`'s reason explicitly. Used by `vez mark`.
pub fn set_reason(paths: &OverlayPaths, name: &str, reason: Reason) -> Result<()> {
    std::fs::create_dir_all(&paths.state_dir)
        .with_context(|| format!("creating {}", paths.state_dir.display()))?;
    let mut reasons = read_reasons(paths).unwrap_or_default();
    reasons.insert(name.to_string(), reason);
    std::fs::write(reasons_path(paths), serde_json::to_string_pretty(&reasons)?)
        .context("writing reasons.json")?;
    Ok(())
}

/// What `history undo`/`rollback` needs to apply: package names to remove and
/// package names to (re)install. Names only, without the recorded NEVRA:
/// `Remove` entries only ever recorded names (see the `Action::Remove` branch
/// in [`record`]), so there's no old EVR to restore, and pinning just the
/// `Install` side would make the two sides inconsistent. The names resolve
/// against whatever the repos have *now*, same as a plain `install`/`remove`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Inverse {
    pub to_remove: Vec<String>,
    pub to_install: Vec<String>,
}

/// `Remove` entries record bare package names (there's no version/release to
/// capture at removal time) while `Install`-family entries record full NEVRA
/// strings, and both come through here. A bare name with a hyphen
/// (`perl-PathTools`, `perl-Text-Tabs+Wrap`) fails both NEVRA and NVRA
/// parsing, so it has to be returned as-is. `split('-').next()` would turn it
/// into the unrelated name `perl` (see the hyphenated-name tests above; this
/// is the bare-name side of the same bug).
fn name_of(nevra: &str) -> String {
    vez_core::Nevra::parse_nevra(nevra)
        .or_else(|| vez_core::Nevra::parse_nvra(nevra))
        .map(|n| n.name)
        .unwrap_or_else(|| nevra.to_string())
}

/// The inverse of one transaction. An `Install`-family entry (install,
/// upgrade, reinstall, and downgrade are all recorded as `Install` today; see
/// the call sites of [`record`]) is undone by removing what it installed. A
/// `Remove` entry is undone by reinstalling what it removed.
pub fn inverse_of(entry: &HistoryEntry) -> Inverse {
    let names: Vec<String> = entry
        .packages
        .iter()
        .map(|(nevra, _)| name_of(nevra))
        .collect();
    match entry.action {
        Action::Remove => Inverse {
            to_remove: Vec::new(),
            to_install: names,
        },
        Action::Install | Action::Upgrade | Action::Reinstall | Action::Downgrade => Inverse {
            to_remove: names,
            to_install: Vec::new(),
        },
    }
}

/// The inverse of a range of transactions, applied most recent first
/// (`entries` doesn't need to be sorted). `rollback <id>` uses it with every
/// entry after `<id>`. If more than one transaction in the range touches a
/// name, the most recent one decides for that name. For example, installed
/// and later removed within the range nets out to "reinstall" (undoing the
/// later `Remove`) instead of doing both.
pub fn composite_inverse(entries: &[HistoryEntry]) -> Inverse {
    let mut ordered: Vec<&HistoryEntry> = entries.iter().collect();
    ordered.sort_by(|a, b| b.id.cmp(&a.id));

    let mut decided: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut result = Inverse::default();
    for entry in ordered {
        let inv = inverse_of(entry);
        for name in inv.to_remove {
            if decided.insert(name.clone()) {
                result.to_remove.push(name);
            }
        }
        for name in inv.to_install {
            if decided.insert(name.clone()) {
                result.to_install.push(name);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(tag: &str) -> OverlayPaths {
        let dir =
            std::env::temp_dir().join(format!("vez-history-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        OverlayPaths {
            state_dir: dir,
            ..OverlayPaths::default()
        }
    }

    #[test]
    fn hyphenated_dependency_name_is_tracked_correctly() {
        let paths = test_paths("vulkan");
        record(
            &paths,
            Action::Install,
            &[(
                "vulkan-loader-1.3.250.0-1.fc44.x86_64".to_string(),
                Reason::Dependency,
            )],
        )
        .unwrap();
        assert_eq!(reason_of(&paths, "vulkan-loader"), Some(Reason::Dependency));
        // The old `split('-').next()` logic would have recorded this
        // dependency's reason under "vulkan".
        assert_eq!(reason_of(&paths, "vulkan"), None);
        std::fs::remove_dir_all(&paths.state_dir).ok();
    }

    #[test]
    fn hyphenated_name_with_epoch_is_tracked_correctly() {
        let paths = test_paths("mesa");
        record(
            &paths,
            Action::Install,
            &[(
                "mesa-dri-drivers-1:23.1.4-1.fc44.x86_64".to_string(),
                Reason::Dependency,
            )],
        )
        .unwrap();
        assert_eq!(
            reason_of(&paths, "mesa-dri-drivers"),
            Some(Reason::Dependency)
        );
        std::fs::remove_dir_all(&paths.state_dir).ok();
    }

    #[test]
    fn explicit_install_reason_survives_a_later_unrelated_transaction() {
        let paths = test_paths("pskc");
        // User explicitly installs python3-pskc directly.
        record(
            &paths,
            Action::Install,
            &[("python3-pskc-1.4-1.fc44.noarch".to_string(), Reason::User)],
        )
        .unwrap();
        assert_eq!(reason_of(&paths, "python3-pskc"), Some(Reason::User));

        // A later, unrelated transaction also (re)downloads python3-pskc as
        // part of its download set (e.g. it's already installed and gets
        // swept along), but the user didn't name it this time, so the caller
        // passes Reason::Dependency. That must NOT downgrade the earlier User
        // reason.
        record(
            &paths,
            Action::Install,
            &[
                (
                    "python3-pyscard-2.2.2-6.fc44.x86_64".to_string(),
                    Reason::User,
                ),
                (
                    "python3-pskc-1.4-1.fc44.noarch".to_string(),
                    Reason::Dependency,
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            reason_of(&paths, "python3-pskc"),
            Some(Reason::User),
            "explicit install reason must not be silently downgraded"
        );
        assert_eq!(reason_of(&paths, "python3-pyscard"), Some(Reason::User));
        std::fs::remove_dir_all(&paths.state_dir).ok();
    }

    #[test]
    fn inverse_of_install_removes_and_remove_installs() {
        let install = HistoryEntry {
            id: 1,
            unix_time: 0,
            action: Action::Install,
            packages: vec![("foo-1.0-1.fc44.x86_64".to_string(), Reason::User)],
        };
        assert_eq!(
            inverse_of(&install),
            Inverse {
                to_remove: vec!["foo".to_string()],
                to_install: vec![]
            }
        );

        let remove = HistoryEntry {
            id: 2,
            unix_time: 0,
            action: Action::Remove,
            packages: vec![("bar".to_string(), Reason::User)],
        };
        assert_eq!(
            inverse_of(&remove),
            Inverse {
                to_remove: vec![],
                to_install: vec!["bar".to_string()]
            }
        );
    }

    #[test]
    fn composite_inverse_lets_most_recent_transaction_win_per_name() {
        // tx1 installs foo, tx2 removes it again. Rolling back past tx1
        // should net out to "reinstall foo" (undoing tx2's remove) without
        // also removing it for tx1.
        let tx1 = HistoryEntry {
            id: 1,
            unix_time: 0,
            action: Action::Install,
            packages: vec![("foo-1.0-1.fc44.x86_64".to_string(), Reason::User)],
        };
        let tx2 = HistoryEntry {
            id: 2,
            unix_time: 0,
            action: Action::Remove,
            packages: vec![("foo".to_string(), Reason::User)],
        };
        let inv = composite_inverse(&[tx1, tx2]);
        assert_eq!(
            inv,
            Inverse {
                to_remove: vec![],
                to_install: vec!["foo".to_string()]
            }
        );
    }
}
