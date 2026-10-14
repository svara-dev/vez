//! `vez versionlock`: a small on-disk list of [`vez_core::VersionLock`]
//! entries under [`vez_overlay::OverlayPaths::state_dir`]. Every resolve path
//! consults it: direct `install`/`upgrade`/`distro-sync`, and since each
//! entry pins an exact `epoch:version-release`/`arch`, transitive dependency
//! pulls too (see `vez_solv::build_pool_locked`). `add` records the name's
//! *currently installed* EVR/arch at lock time, like dnf5's versionlock
//! plugin, so the lock still holds across a remove and reinstall of the same
//! name instead of following whatever is installed at solve time.

use anyhow::{Context, Result};
use std::path::PathBuf;
use vez_core::VersionLock;
use vez_overlay::{OverlayContext, OverlayPaths};

fn list_path(paths: &OverlayPaths) -> PathBuf {
    paths.state_dir.join("versionlock.list")
}

pub fn list(paths: &OverlayPaths) -> Result<Vec<VersionLock>> {
    match std::fs::read_to_string(list_path(paths)) {
        Ok(s) => Ok(s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(|l| l.parse().ok())
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", list_path(paths).display())),
    }
}

/// Names only, for callers (CLI `versionlock list`, name-based existence
/// checks) that don't need the pinned EVR/arch.
pub fn list_names(paths: &OverlayPaths) -> Result<Vec<String>> {
    Ok(list(paths)?.into_iter().map(|l| l.name).collect())
}

/// Locks `name` at its currently installed EVR/arch (looked up in `overlay`),
/// or as a name-only entry with no constraint if it isn't installed yet. That
/// matches dnf5, where a versionlock entry for a package that isn't installed
/// does nothing until it is.
pub fn add(paths: &OverlayPaths, overlay: &OverlayContext, name: &str) -> Result<()> {
    let installed = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .find(|p| p.nevra.name == name);
    let entry = VersionLock {
        name: name.to_string(),
        evr: installed.map(|p| p.nevra.evr()),
        arch: installed.map(|p| p.nevra.arch.clone()),
    };
    let mut entries: Vec<VersionLock> = list(paths)?
        .into_iter()
        .filter(|l| l.name != name)
        .collect();
    entries.push(entry);
    write_all(paths, &entries)
}

pub fn delete(paths: &OverlayPaths, name: &str) -> Result<()> {
    let entries: Vec<VersionLock> = list(paths)?
        .into_iter()
        .filter(|l| l.name != name)
        .collect();
    write_all(paths, &entries)
}

pub fn clear(paths: &OverlayPaths) -> Result<()> {
    write_all(paths, &[])
}

fn write_all(paths: &OverlayPaths, entries: &[VersionLock]) -> Result<()> {
    std::fs::create_dir_all(&paths.state_dir)
        .with_context(|| format!("creating {}", paths.state_dir.display()))?;
    let mut sorted: Vec<&VersionLock> = entries.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let contents = sorted
        .iter()
        .map(|l| l.to_string())
        .collect::<Vec<_>>()
        .join("\n")
        + if sorted.is_empty() { "" } else { "\n" };
    std::fs::write(list_path(paths), contents)
        .with_context(|| format!("writing {}", list_path(paths).display()))
}
