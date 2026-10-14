//! Overlay awareness, which is why vez exists instead of being one more dnf wrapper.
//!
//! Vez keeps its **own** rpmdb for everything it installs ([`paths::RPMDB`]), separate from
//! the base image's rpmdb ([`paths::BASE_RPMDB`]). The two are never merged or diffed; vez
//! unions two independent databases at query time. That split is what stops a dependency
//! the base image already provides (glibc, libgcc) being duplicated into the extra layer
//! just because dnf could not see it was already there.
//!
//! Where the *files* go is [`paths::OVERLAY_UPPER`], and that is the part that differs from
//! every other overlay implementation on a bootc system. `dnf5 --transient` and
//! `bootc usr-overlay` both mount a **tmpfs** overlay, so what they install is in RAM and
//! is discarded at reboot. Vez mounts its own overlayfs from a directory under `/var`, so
//! the files persist; the mount is rebuilt at boot from that directory. See [`mount`].
//!
//! Not every environment vez runs in has an overlay. A distrobox/podman container or an
//! image-build chroot is a plain single-rpmdb system like any other dnf/rpm target, and
//! [`OverlayPaths::detect`] tells them apart by asking whether this is a booted OSTree
//! system ([`paths::is_booted_ostree`]). Without that, vez picks [`OverlayMode::Standalone`]
//! and behaves like plain rpm/dnf: one rpmdb at rpm's compiled-in default location, no
//! base-vs-overlay distinction, and nothing is off-limits to install or remove.

pub mod declarative;
pub mod mount;
pub mod paths;
pub mod state;

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use vez_core::{Dependency, Origin, Package};

/// Whether this run is against a real booted Svara system, where `/usr` is an image and the
/// extra layer needs an overlay, or a plain system without one (distrobox/podman, an
/// image-build environment).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OverlayMode {
    /// A booted bootc system. `base_rpmdb` is read-only and vez never writes it. `overlay_rpmdb`
    /// is vez's own db and the only one vez installs to or removes from.
    Split {
        base_rpmdb: PathBuf,
        overlay_rpmdb: PathBuf,
    },
    /// No overlay present. Vez reads and writes rpm's default dbpath (no `--dbpath` at
    /// all), same as a plain `rpm`/`dnf` call.
    Standalone,
}

/// Where vez keeps everything, resolved once per run by [`OverlayPaths::detect`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OverlayPaths {
    pub mode: OverlayMode,
    /// The overlayfs upperdir, where an installed package's *files* land (its rpmdb entry
    /// goes elsewhere). Only meaningful under [`OverlayMode::Split`], and read by
    /// [`mount`] to build the mount, and by the transaction code to inspect what a
    /// transaction changed.
    pub overlay_upper: PathBuf,
    /// The overlayfs workdir; overlayfs requires one, on the same filesystem as
    /// `overlay_upper`.
    pub overlay_work: PathBuf,
    /// Where vez keeps its own metadata that isn't an rpmdb: the transaction history log
    /// (`history.jsonl`), the versionlock list, GPG keys and module state.
    pub state_dir: PathBuf,
    /// `--installroot`: when set, package *files* land under this root (through `rpm
    /// --root`) instead of the real `/`, and vez's own rpmdb is created fresh at
    /// `<installroot>/var/lib/svara/vez/rpmdb` no matter what `mode` says. The point is a
    /// disposable, isolated write target (image builds, test reproduction setups). The
    /// *base* view doesn't change: it still reads from wherever `mode` says, which in an
    /// image-build container is the build's own rpmdb — what should count as "already
    /// provided" while prebaking.
    pub installroot: Option<PathBuf>,
}

impl Default for OverlayPaths {
    /// The canonical Svara layout, from [`paths`].
    ///
    /// Defaults to [`OverlayMode::Split`] because callers and tests that build
    /// `OverlayPaths::default()` want the historical base/overlay split. Runtime code
    /// (`vez-cli`) calls [`OverlayPaths::detect`] instead, so it picks standalone mode
    /// outside a booted system.
    fn default() -> Self {
        Self {
            mode: OverlayMode::Split {
                base_rpmdb: PathBuf::from(paths::BASE_RPMDB),
                overlay_rpmdb: PathBuf::from(paths::RPMDB),
            },
            overlay_upper: PathBuf::from(paths::OVERLAY_UPPER),
            overlay_work: PathBuf::from(paths::OVERLAY_WORK),
            state_dir: PathBuf::from(paths::STATE),
            installroot: None,
        }
    }
}

impl OverlayPaths {
    /// Picks [`OverlayMode::Split`] on a booted OSTree/bootc system and
    /// [`OverlayMode::Standalone`] otherwise, which covers distrobox/podman and
    /// image-build environments.
    ///
    /// The test is [`paths::is_booted_ostree`] and deliberately not `/etc/os-release`:
    /// a build chroot's `os-release` already says `ID=svara`, so trusting it forced the
    /// split view onto builds that had no overlay — the failure mode documented on
    /// `is_booted_ostree`.
    pub fn detect() -> Result<Self> {
        let defaults = Self::default();
        if paths::is_booted_ostree() {
            return Ok(defaults);
        }
        // Standalone keeps the overlay paths for diagnostics (there is no `--dbpath` to
        // resolve them against) but moves state out of the distro's `/var/lib/svara`,
        // which does not belong to vez and may not even be writable in a container.
        Ok(Self {
            mode: OverlayMode::Standalone,
            overlay_upper: defaults.overlay_upper,
            overlay_work: defaults.overlay_work,
            state_dir: PathBuf::from("/var/lib/vez"),
            installroot: None,
        })
    }

    /// The dbpath vez reads and writes for its own (writable/extra) view.
    /// `installroot`, when set, always wins over `mode`. Otherwise `None` under
    /// [`OverlayMode::Standalone`] means "let rpm use its default", since standalone mode is
    /// meant to behave like a plain rpm/dnf call.
    pub fn write_dbpath(&self) -> Option<PathBuf> {
        if let Some(root) = &self.installroot {
            return Some(paths::installroot_rpmdb(root));
        }
        match &self.mode {
            OverlayMode::Split { overlay_rpmdb, .. } => Some(overlay_rpmdb.clone()),
            OverlayMode::Standalone => None,
        }
    }

    /// Whether the `rpm` transaction writing to [`Self::write_dbpath`] needs `--nodeps`.
    ///
    /// True whenever that dbpath is an isolated db that can't see every package satisfying
    /// a dependency: either the bare installroot tree (no base packages in it at all) or,
    /// under [`OverlayMode::Split`], vez's extra-only rpmdb, which never contains the base
    /// image's packages. `rpm`'s dependency checker only looks at the db at `--dbpath`, so
    /// without `--nodeps` it would reject every Requires that only a base-image package
    /// satisfies (glibc, libgcc, etc.), even though vez's SAT resolver already checked
    /// satisfaction across both dbs before building this transaction.
    /// [`OverlayMode::Standalone`] doesn't need it: there `--dbpath` is left out and rpm
    /// uses its own single, complete db.
    pub fn needs_nodeps(&self) -> bool {
        self.installroot.is_some() || matches!(self.mode, OverlayMode::Split { .. })
    }
}

/// The result of loading both of vez's rpmdb views: every installed package, tagged with
/// where it came from.
pub struct OverlayContext {
    /// Base-image packages (`Split` mode only). Read-only; vez never installs or removes
    /// against this list.
    pub base: Vec<Package>,
    /// Everything vez treats as writable: the packages in its own rpmdb (`Split` mode), or
    /// every installed package (`Standalone` mode, which has no base-vs-extra distinction).
    pub overlay: Vec<Package>,
    pub mode: OverlayMode,
    /// Capability indices over `base`/`overlay`, built once at construction and reused by
    /// [`Self::satisfied_by_base`]/[`Self::satisfied`] for every dependency edge the
    /// resolver checks, so each call avoids an O(installed) linear scan. See
    /// [`vez_rpmdb::CapabilityIndex`].
    base_index: vez_rpmdb::CapabilityIndex,
    overlay_index: vez_rpmdb::CapabilityIndex,
}

impl OverlayContext {
    /// Builds a context from package lists we already have, with no rpmdb query. For tests
    /// (mainly `vez-resolver`'s) that exercise resolver logic against a fixed
    /// base/extra split without running `rpm`.
    pub fn for_test(base: Vec<Package>, overlay: Vec<Package>) -> Self {
        Self::new(
            base,
            overlay,
            OverlayMode::Split {
                base_rpmdb: PathBuf::new(),
                overlay_rpmdb: PathBuf::new(),
            },
        )
    }

    /// Builds a context from package lists we already have and an explicit `mode`. For
    /// callers (e.g. the resolver's what-if sub-contexts used while sizing `Recommends`)
    /// that derive an `OverlayContext` from an existing one's data and don't want an rpmdb
    /// query or the fixed `Split` mode of `for_test`.
    pub fn new(base: Vec<Package>, overlay: Vec<Package>, mode: OverlayMode) -> Self {
        let base_index = vez_rpmdb::CapabilityIndex::build(&base);
        let overlay_index = vez_rpmdb::CapabilityIndex::build(&overlay);
        Self {
            base,
            overlay,
            mode,
            base_index,
            overlay_index,
        }
    }

    /// Builds the context by querying the rpmdb(s) for `paths.mode`. In `Split` mode that's
    /// two independent dbs (base plus vez's extra db) with no diffing, since each one
    /// already contains only what it should. In `Standalone` mode it's one query against
    /// rpm's default dbpath.
    pub fn load(paths: &OverlayPaths) -> Result<Self> {
        // `--installroot`: base is still read from wherever `mode` says, but the
        // writable/extra view always comes from a fresh db under the installroot.
        if let Some(root) = &paths.installroot {
            let overlay_rpmdb = crate::paths::installroot_rpmdb(root);
            let base = match &paths.mode {
                OverlayMode::Split { base_rpmdb, .. } => {
                    vez_rpmdb::query_installed(Some(base_rpmdb), "base").with_context(|| {
                        format!("querying base rpmdb at {}", base_rpmdb.display())
                    })?
                }
                OverlayMode::Standalone => vez_rpmdb::query_installed(None, "base")
                    .context("querying default rpmdb as installroot base")?,
            };
            let overlay = vez_rpmdb::query_installed(Some(&overlay_rpmdb), "overlay")
                .with_context(|| {
                    format!(
                        "querying installroot extra rpmdb at {}",
                        overlay_rpmdb.display()
                    )
                })?;
            tracing::debug!(base = base.len(), overlay = overlay.len(), installroot = %root.display(), "loaded installroot overlay context");
            let base_index = vez_rpmdb::CapabilityIndex::build(&base);
            let overlay_index = vez_rpmdb::CapabilityIndex::build(&overlay);
            return Ok(Self {
                base,
                overlay,
                mode: OverlayMode::Split {
                    base_rpmdb: PathBuf::new(),
                    overlay_rpmdb,
                },
                base_index,
                overlay_index,
            });
        }
        match &paths.mode {
            OverlayMode::Split {
                base_rpmdb,
                overlay_rpmdb,
            } => {
                // No `ensure_initialized` here on purpose. This is a read-only query, and
                // `ensure_initialized` has to `create_dir_all`/`rpm --initdb` under
                // root-owned `/var/lib/svara`, which would make every read-only command
                // (`list`, `origin`) require root. Callers that write to the extra rpmdb
                // (install, remove, upgrade) initialize it right before writing; see
                // `vez_transaction`. A db that was never initialized just has nothing
                // installed, and `query_installed` already reports that as an empty list.
                let base = vez_rpmdb::query_installed(Some(base_rpmdb), "base")
                    .with_context(|| format!("querying base rpmdb at {}", base_rpmdb.display()))?;
                let overlay = vez_rpmdb::query_installed(Some(overlay_rpmdb), "overlay")
                    .with_context(|| {
                        format!("querying extra rpmdb at {}", overlay_rpmdb.display())
                    })?;
                tracing::debug!(
                    base = base.len(),
                    overlay = overlay.len(),
                    "loaded split overlay context"
                );
                let base_index = vez_rpmdb::CapabilityIndex::build(&base);
                let overlay_index = vez_rpmdb::CapabilityIndex::build(&overlay);
                Ok(Self {
                    base,
                    overlay,
                    mode: paths.mode.clone(),
                    base_index,
                    overlay_index,
                })
            }
            OverlayMode::Standalone => {
                let installed = vez_rpmdb::query_installed(None, "installed")
                    .context("querying default rpmdb")?;
                tracing::debug!(
                    installed = installed.len(),
                    "loaded standalone (no-overlay) context"
                );
                let base_index = vez_rpmdb::CapabilityIndex::build(&[]);
                let overlay_index = vez_rpmdb::CapabilityIndex::build(&installed);
                Ok(Self {
                    base: Vec::new(),
                    overlay: installed,
                    mode: OverlayMode::Standalone,
                    base_index,
                    overlay_index,
                })
            }
        }
    }

    /// Where a package (by name) currently lives, if installed at all.
    pub fn origin_of(&self, name: &str) -> Origin {
        if self.base.iter().any(|p| p.nevra.name == name) {
            Origin::Base
        } else if self.overlay.iter().any(|p| p.nevra.name == name) {
            match self.mode {
                OverlayMode::Split { .. } => Origin::Overlay,
                OverlayMode::Standalone => Origin::Installed,
            }
        } else {
            Origin::NotInstalled
        }
    }

    /// The main resolver hook: is `dep` already satisfied by the base image, so installing
    /// it would only waste space (extra-rpmdb-tracked bytes for something the base image
    /// already has)? Always `false` in `Standalone` mode. There's no base image to check
    /// there, only "is it installed at all", which [`Self::satisfied`] covers.
    pub fn satisfied_by_base(&self, dep: &Dependency, requiring_arch: Option<&str>) -> bool {
        self.base_index.provides(&self.base, dep, requiring_arch)
    }

    /// Is `dep` satisfied by the extra list alone, ignoring `base`? For callers that already
    /// checked `satisfied_by_base` and want to skip repeating it; see
    /// `vez_rpmdb_provides_overlay` in `vez-resolver`.
    pub fn overlay_satisfied(&self, dep: &Dependency, requiring_arch: Option<&str>) -> bool {
        self.overlay_index
            .provides(&self.overlay, dep, requiring_arch)
    }

    /// Is `dep` already satisfied by *anything* installed (base or extra)? Used to skip
    /// resolution for a dependency that's already met, whichever layer met it.
    pub fn satisfied(&self, dep: &Dependency, requiring_arch: Option<&str>) -> bool {
        self.satisfied_by_base(dep, requiring_arch)
            || self
                .overlay_index
                .provides(&self.overlay, dep, requiring_arch)
    }
}

/// Small helper for CLI diagnostics (`vez paths`). The resolver doesn't use it.
pub fn describe(paths: &OverlayPaths) -> String {
    match &paths.mode {
        OverlayMode::Split { base_rpmdb, overlay_rpmdb } => format!(
            "mode: split (bootc: base image + extra layer)\nbase rpmdb: {}\nextra rpmdb: {}\noverlay upperdir: {}\noverlay workdir: {}\nstate: {}",
            base_rpmdb.display(),
            overlay_rpmdb.display(),
            paths.overlay_upper.display(),
            paths.overlay_work.display(),
            paths.state_dir.display()
        ),
        OverlayMode::Standalone => "mode: standalone (no overlay — distrobox/podman or image-build environment)\ndbpath: rpm's default".to_string(),
    }
}

// packages.list / packages-rpm.list
//
// The top-level, user-facing lists of package names vez installed in the extra layer. A
// replay reads them and reinstalls everything listed after a reboot or a base image update.
// They're separate from vez's own `reasons.json`/`history.jsonl` (which track every
// package, dependencies included, under `OverlayPaths::state_dir`) because they answer a
// different question: `history` is what happened, `packages.list` is what must be true.
// Only meaningful under [`OverlayMode::Split`]; `Standalone` environments have no replay
// step to feed.
//
// There are two lists. Packages resolved from repos go in [`paths::PACKAGES_LIST`] and get
// reinstalled from repos on replay. Packages installed from a local `.rpm` file go in
// [`paths::LOCAL_RPM_LIST`], because replaying those needs the file itself and a repo can't
// resolve the name. [`paths::LOCAL_RPM_CACHE`] holds those files.

fn list_names(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn list_contains(path: &str, name: &str) -> bool {
    list_names(path).iter().any(|p| p == name)
}

/// No-op if `name` is already listed.
fn list_add(path: &str, name: &str) -> Result<()> {
    if list_contains(path, name) {
        return Ok(());
    }
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {path}"))?;
    writeln!(f, "{name}").with_context(|| format!("writing {path}"))?;
    Ok(())
}

fn list_remove(path: &str, name: &str) -> Result<()> {
    let remaining = list_names(path);
    if !remaining.iter().any(|p| p == name) {
        return Ok(());
    }
    let remaining: Vec<String> = remaining.into_iter().filter(|p| p != name).collect();
    let mut content = remaining.join("\n");
    if !remaining.is_empty() {
        content.push('\n');
    }
    std::fs::write(path, content).with_context(|| format!("writing {path}"))?;
    Ok(())
}

pub fn packages_list_names() -> Vec<String> {
    list_names(paths::PACKAGES_LIST)
}

pub fn packages_list_contains(name: &str) -> bool {
    list_contains(paths::PACKAGES_LIST, name)
}

pub fn packages_list_add(name: &str) -> Result<()> {
    list_add(paths::PACKAGES_LIST, name)
}

pub fn packages_list_remove(name: &str) -> Result<()> {
    list_remove(paths::PACKAGES_LIST, name)
}

pub fn local_rpm_list_names() -> Vec<String> {
    list_names(paths::LOCAL_RPM_LIST)
}

pub fn local_rpm_list_contains(name: &str) -> bool {
    list_contains(paths::LOCAL_RPM_LIST, name)
}

pub fn local_rpm_list_add(name: &str) -> Result<()> {
    list_add(paths::LOCAL_RPM_LIST, name)
}

pub fn local_rpm_list_remove(name: &str) -> Result<()> {
    list_remove(paths::LOCAL_RPM_LIST, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_mode_needs_nodeps_even_without_installroot() {
        // Regression test carried over from upstream. A real on-disk install (no
        // --installroot) writes to an isolated extra-only rpmdb that never contains the
        // base image's packages, so rpm's dependency checker needs --nodeps just like the
        // installroot case. Leaving it out made `rpm -Uvh` reject every Requires met by the
        // base (glibc, libgcc, etc.) even though vez's resolver had already verified them.
        let paths = OverlayPaths::default();
        assert!(matches!(paths.mode, OverlayMode::Split { .. }));
        assert!(paths.installroot.is_none());
        assert!(paths.needs_nodeps());
    }

    #[test]
    fn standalone_mode_does_not_need_nodeps() {
        let paths = OverlayPaths {
            mode: OverlayMode::Standalone,
            overlay_upper: PathBuf::new(),
            overlay_work: PathBuf::new(),
            state_dir: PathBuf::new(),
            installroot: None,
        };
        assert!(!paths.needs_nodeps());
    }

    #[test]
    fn installroot_needs_nodeps_regardless_of_mode() {
        let paths = OverlayPaths {
            mode: OverlayMode::Standalone,
            overlay_upper: PathBuf::new(),
            overlay_work: PathBuf::new(),
            state_dir: PathBuf::new(),
            installroot: Some(PathBuf::from("/tmp/factory")),
        };
        assert!(paths.needs_nodeps());
    }

    #[test]
    fn default_paths_are_the_svara_layout() {
        // The point of the `paths` module: one place to change, and nothing else may spell
        // a `vez` path out. If this test ever fails, a path moved without its callers.
        let paths = OverlayPaths::default();
        assert_eq!(
            paths.overlay_upper,
            PathBuf::from("/var/lib/svara/vez/overlay/upper")
        );
        assert_eq!(
            paths.overlay_work,
            PathBuf::from("/var/lib/svara/vez/overlay/work")
        );
        assert_eq!(paths.state_dir, PathBuf::from("/var/lib/svara/vez"));
        match paths.mode {
            OverlayMode::Split {
                base_rpmdb,
                overlay_rpmdb,
            } => {
                // The base db is the deployment's own, read-only. `/usr/lib/sysimage/rpm` is
                // a symlink to it, so naming the symlink would work but would hide which
                // file is really being read.
                assert_eq!(base_rpmdb, PathBuf::from("/usr/share/rpm"));
                assert_eq!(overlay_rpmdb, PathBuf::from("/var/lib/svara/vez/rpmdb"));
            }
            OverlayMode::Standalone => panic!("default must be the booted-system layout"),
        }
    }

    #[test]
    fn installroot_dbpath_follows_the_real_layout() {
        // A prebake copies this tree into the factory image, so the path has to match
        // `/var/lib/svara/vez/rpmdb` exactly, not merely be plausible.
        assert_eq!(
            crate::paths::installroot_rpmdb(Path::new("/tmp/factory")),
            PathBuf::from("/tmp/factory/var/lib/svara/vez/rpmdb")
        );
    }
}
