//! Shared types for vez: NEVRA identity, dependency expressions, and RPM's
//! version comparison. Every other crate builds on these. It has no
//! dependencies beyond serde so the resolver, repo metadata, and rpmdb-query
//! code can use it without pulling in tokio/reqwest/etc.

pub mod nevra;
pub mod version;
pub mod versionlock;

pub use nevra::Nevra;
pub use version::EvrCompare;
pub use versionlock::VersionLock;

use serde::{Deserialize, Serialize};

/// Where a package's installed copy lives, from vez's point of view. The
/// overlay-aware resolver is built around this: a `Base` package is already
/// present through the read-only image lowerdir, and its files and deps must
/// never be copied into the overlay upperdir again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    /// In the base image's own rpmdb, read from the live overlayfs-merged
    /// `/usr/share/rpm`. Read-only; vez never writes it.
    Base,
    /// Installed through vez's own overlay rpmdb
    /// (`/var/lib/svara/vez/rpmdb`), which is separate from the base image's
    /// db, so no merge or diff is needed.
    Overlay,
    /// No Svara overlay at all (distrobox/podman, an image build
    /// environment). vez works against one plain rpmdb, like dnf would, with
    /// no base-vs-overlay distinction.
    Installed,
    /// Not installed anywhere yet.
    NotInstalled,
}

/// A `Requires`/`Conflicts`/`Provides` comparison operator, as found in RPM
/// dependency strings (`foo >= 1.2-3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Comparator {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}

/// One entry from a package's `Requires`/`Provides`/`Conflicts`/`Obsoletes`
/// list: a capability name, optionally version-constrained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub constraint: Option<(Comparator, String)>,
}

impl Dependency {
    pub fn unversioned(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            constraint: None,
        }
    }

    /// Whether an EVR string (`epoch:version-release`) satisfies this
    /// dependency's version constraint. Unversioned deps are satisfied by
    /// any EVR of a package with a matching provided name.
    pub fn satisfied_by_evr(&self, evr: &str) -> bool {
        let Some((cmp, want)) = &self.constraint else {
            return true;
        };
        let ord = version::compare_evr_for_dep(evr, want);
        match cmp {
            Comparator::Lt => ord.is_lt(),
            Comparator::Le => ord.is_le(),
            Comparator::Eq => ord.is_eq(),
            Comparator::Ge => ord.is_ge(),
            Comparator::Gt => ord.is_gt(),
        }
    }
}

/// A package as known from repo metadata or an installed rpmdb query. Enough
/// identity and dependency info for resolution; it isn't a full RPM header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub nevra: Nevra,
    pub summary: String,
    pub provides: Vec<Dependency>,
    pub requires: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub obsoletes: Vec<Dependency>,
    /// Weak dependencies (`Recommends`). dnf installs these best-effort along
    /// with the hard `Requires` closure. A missing provider is never a
    /// resolution failure (unlike `requires`); it's just skipped.
    #[serde(default)]
    pub recommends: Vec<Dependency>,
    /// Weak dependencies (`Suggests`). Informational only; vez never installs
    /// them automatically (dnf's default `install_weak_deps` also only pulls
    /// in Recommends).
    #[serde(default)]
    pub suggests: Vec<Dependency>,
    /// Weak dependencies (`Enhances`), the reverse of `recommends`: this
    /// package improves another one that's already installed. Informational
    /// only, never installed automatically.
    #[serde(default)]
    pub enhances: Vec<Dependency>,
    /// Weak dependencies (`Supplements`), the reverse of `suggests`:
    /// installing this next to its target is desirable, as declared in this
    /// package's metadata instead of the target's. Informational only, never
    /// installed automatically.
    #[serde(default)]
    pub supplements: Vec<Dependency>,
    /// Repo-relative or absolute location of the `.rpm` payload; empty for
    /// packages sourced from a live rpmdb query (nothing to fetch).
    pub location: String,
    /// Repo id this package came from, or "installed" for rpmdb-sourced
    /// entries. Kept for diagnostics and `vez list --repo`.
    pub repo_id: String,
    /// The `priority=` of this package's repo (dnf convention: lower number
    /// wins). Defaults to dnf's default of 99 for repos/sources that don't
    /// set one, rpmdb-sourced/"installed" packages included. Priority only
    /// breaks ties between *candidate* packages from different repos and is
    /// never checked for anything already installed.
    #[serde(default = "default_repo_priority")]
    pub repo_priority: u32,
    /// The `cost=` of this package's repo (dnf convention: lower number
    /// wins). Only used to break ties between candidates that already tie on
    /// `repo_priority`. Fedora's `fedora-updates-archive.repo`, for example,
    /// sets `cost=10000` (the default is 1000) so it's only used when nothing
    /// else has the package.
    #[serde(default = "default_repo_cost")]
    pub repo_cost: u32,
    /// On-disk size once installed (rpm's `%{SIZE}` / primary.xml's `<size
    /// installed="...">`). Feeds the "Size" column and the "After this
    /// operation, N will be used" line in a dnf-style transaction summary.
    #[serde(default)]
    pub install_size: u64,
    /// Compressed `.rpm` payload size (primary.xml's `<size package="...">`).
    /// 0 for installed packages from the rpmdb, which have nothing left to
    /// download.
    #[serde(default)]
    pub download_size: u64,
    /// `<rpm:vendor>` from primary.xml (rpm's `Vendor:` header tag, e.g.
    /// "Fedora Project"). dnf's `--from-vendor` filter matches against it.
    /// Empty for rpmdb-sourced/"installed" packages (vez's rpmdb reader
    /// doesn't read this field back from an installed header yet) and for
    /// repos whose primary.xml leaves it out.
    #[serde(default)]
    pub vendor: String,
    /// `<checksum type="...">` from primary.xml (e.g. `"sha256"`): the
    /// algorithm used for the [`Package::checksum`] hex digest. Empty for
    /// rpmdb-sourced/"installed" packages, which have nothing to download or
    /// verify.
    #[serde(default)]
    pub checksum_type: String,
    /// Hex digest of the downloadable `.rpm` payload, taken from the text of
    /// primary.xml's `<checksum>` element. The downloaded bytes are checked
    /// against it before a package counts as fetched, the same integrity
    /// check dnf5/librepo do internally. Empty for rpmdb-sourced/"installed"
    /// packages.
    #[serde(default)]
    pub checksum: String,
}

/// Formats a byte count the way dnf's transaction summary does: 1024-based
/// units, one decimal place, and no decimals for plain `B`.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// dnf's default repo `priority=` (lower wins) for a repo/source that doesn't
/// set one.
pub fn default_repo_priority() -> u32 {
    99
}

/// dnf's default repo `cost=` (lower wins) for a repo/source that doesn't set
/// one.
pub fn default_repo_cost() -> u32 {
    1000
}

/// dnf5-style `"X.X MiB/s"` throughput for a finished transfer: `bytes` over
/// `elapsed` wall-clock time. The duration has a nonzero floor so a
/// sub-millisecond (or instant cached) transfer doesn't divide by zero into
/// an infinite/NaN rate.
pub fn format_speed(bytes: u64, elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs_f64().max(0.001);
    format!("{}/s", format_size((bytes as f64 / secs) as u64))
}

/// dnf5's `"00m00s"` elapsed-time format.
pub fn format_duration(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    format!("{:02}m{:02}s", secs / 60, secs % 60)
}

impl Package {
    /// A package always implicitly provides itself at its own EVR. Repo
    /// metadata's `<provides>` list doesn't always include that entry, so
    /// resolution has to check both.
    pub fn provides_self(&self) -> Dependency {
        Dependency {
            name: self.nevra.name.clone(),
            constraint: Some((Comparator::Eq, self.nevra.evr())),
        }
    }
}

/// A small `fnmatch`-style glob matcher (`*` and `?` only, no character
/// classes), shared by every crate that needs dnf-style pattern lists
/// (`exclude=`, `--repo`, `protected_packages=`, `installonlypkgs=`, …). Not
/// worth adding the `glob` crate for two wildcard characters.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn inner(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => inner(&p[1..], t) || (!t.is_empty() && inner(p, &t[1..])),
            (Some(b'?'), Some(_)) => inner(&p[1..], &t[1..]),
            (Some(pc), Some(tc)) if pc == tc => inner(&p[1..], &t[1..]),
            _ => false,
        }
    }
    if !pattern.contains(['*', '?']) {
        return pattern == text;
    }
    inner(pattern.as_bytes(), text.as_bytes())
}

/// True if `name` matches any pattern in `patterns` (plain names or
/// `glob_match` globs). This is the usual shape of dnf's
/// `protected_packages=`/`installonlypkgs=`/`exclude=` lists.
pub fn name_matches_any(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| glob_match(p, name))
}

/// True if `pattern` contains a [`glob_match`] wildcard (`*`/`?`). Used to
/// decide whether a package-name CLI argument has to be expanded against a
/// live package list (`vez remove 'firefox*'`) or can be looked up as a
/// literal name/capability.
pub fn is_glob_pattern(pattern: &str) -> bool {
    pattern.contains(['*', '?'])
}

#[cfg(test)]
mod glob_tests {
    use super::*;

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("kernel*", "kernel-core"));
        assert!(glob_match("kernel", "kernel"));
        assert!(!glob_match("kernel", "kernel-core"));
        assert!(glob_match("fire?ox", "firefox"));
        assert!(name_matches_any(
            "kernel-core",
            &["glibc".to_string(), "kernel*".to_string()]
        ));
        assert!(!name_matches_any(
            "firefox",
            &["glibc".to_string(), "kernel*".to_string()]
        ));
    }
}
