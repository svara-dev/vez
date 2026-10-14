//! Queries an on-disk rpmdb for installed packages. `rpm` handles the
//! Berkeley vs sqlite backend difference itself.
//!
//! We shell out to the `rpm` binary on purpose instead of parsing the rpmdb
//! ourselves. rpm makes no stability promise about the on-disk format, and
//! parsing it natively would be a correctness and security risk for very
//! little gain over asking rpm. vez owns resolution, repo metadata, and
//! overlay handling; rpm stays the authority on what the database says.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use vez_core::{Comparator, Dependency, Nevra, Package};

/// Field/array delimiters picked because they're very unlikely to appear
/// inside an rpm tag value, so one `--qf` pass can be split unambiguously.
const FIELD_SEP: &str = "\u{1}";
const ARRAY_SEP: &str = "\u{2}";

/// Queries every installed package in the rpmdb at `dbpath` and returns
/// enough identity and dependency data to feed the resolver. `repo_id` is
/// stamped on each result (callers use `"base"` / `"overlay"` / `"installed"`
/// for [`vez_overlay`]'s split and standalone modes).
///
/// `dbpath: None` leaves out `--dbpath`, so rpm uses its compiled-in default
/// database. That's standalone (no-overlay) mode, where vez should see
/// exactly what plain `rpm`/`dnf` would see on that system, with nothing
/// Svara-specific.
pub fn query_installed(dbpath: Option<&Path>, repo_id: &str) -> Result<Vec<Package>> {
    // A `Split`-mode overlay rpmdb that was never initialized (no install has
    // run yet) doesn't exist on disk. That means "nothing installed there"
    // and isn't an error, and checking shouldn't require creating it (which
    // needs root under `/var/lib/svara/vez`). Otherwise `rpm -qa --dbpath
    // <missing dir>` prints a real error to stderr and trips the bail below.
    if let Some(path) = dbpath {
        if !path.exists() {
            return Ok(Vec::new());
        }
    }
    // %{FILENAMES} is queried next to the explicit PROVIDENEVRS because rpm
    // resolves a file-path Requires (e.g. a scriptlet's `Requires:
    // /usr/bin/bash`) against whichever installed package's file list *owns*
    // the path. Most packages never declare a `Provides:` for paths they
    // ship. Without this, any file-based Requires on something already in the
    // base image (bash, /bin/sh, etc.) would report "nothing provides" even
    // though the file is right there.
    let qf = format!(
        "%{{NAME}}{FIELD_SEP}%{{EPOCH}}{FIELD_SEP}%{{VERSION}}{FIELD_SEP}%{{RELEASE}}{FIELD_SEP}%{{ARCH}}{FIELD_SEP}%{{SIZE}}{FIELD_SEP}%{{SUMMARY}}{FIELD_SEP}\
         [%{{PROVIDENEVRS}}{ARRAY_SEP}]{FIELD_SEP}[%{{REQUIRENEVRS}}{ARRAY_SEP}]{FIELD_SEP}[%{{RECOMMENDNEVRS}}{ARRAY_SEP}]{FIELD_SEP}[%{{FILENAMES}}{ARRAY_SEP}]\\n"
    );
    let mut cmd = Command::new("rpm");
    if let Some(dbpath) = dbpath {
        cmd.arg("--dbpath").arg(dbpath);
    }
    let output = cmd
        .arg("-qa")
        .arg("--qf")
        .arg(&qf)
        .output()
        .with_context(|| {
            format!(
                "running rpm -qa against {}",
                dbpath
                    .map(Path::display)
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "rpm's default dbpath".into())
            )
        })?;

    if !output.status.success() {
        // An empty or never-initialized rpmdb is a normal state (e.g. a new
        // overlay rpmdb before the first install). rpm exits non-zero with no
        // packages in that case too, so only real stderr output is fatal.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            anyhow::bail!("rpm -qa failed: {}", stderr.trim());
        }
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut pkg = parse_line(line)?;
            pkg.repo_id = repo_id.to_string();
            Ok(pkg)
        })
        .collect()
}

/// Reads a package's identity and dependency data from a local `.rpm` file's
/// own header, with no rpmdb or `--dbpath` involved (the same `rpm -qp`
/// pattern `repomanage` uses). This lets a caller (`vez install
/// /path/to/foo.rpm`) build a full [`Package`] for a file the resolver never
/// saw, so it goes through the same `apply_install_ex` path as a package
/// resolved from a repo.
pub fn query_local_file(path: &Path) -> Result<Package> {
    let qf = format!(
        "%{{NAME}}{FIELD_SEP}%{{EPOCH}}{FIELD_SEP}%{{VERSION}}{FIELD_SEP}%{{RELEASE}}{FIELD_SEP}%{{ARCH}}{FIELD_SEP}%{{SIZE}}{FIELD_SEP}%{{SUMMARY}}{FIELD_SEP}\
         [%{{PROVIDENEVRS}}{ARRAY_SEP}]{FIELD_SEP}[%{{REQUIRENEVRS}}{ARRAY_SEP}]{FIELD_SEP}[%{{RECOMMENDNEVRS}}{ARRAY_SEP}]{FIELD_SEP}[%{{FILENAMES}}{ARRAY_SEP}]\\n"
    );
    let output = Command::new("rpm")
        .arg("-qp")
        .arg("--qf")
        .arg(&qf)
        .arg("--nosignature")
        .arg(path)
        .output()
        .with_context(|| format!("running rpm -qp on {}", path.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "rpm -qp failed on {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .next()
        .with_context(|| format!("no output from rpm -qp on {}", path.display()))?;
    parse_line(line)
}

fn parse_line(line: &str) -> Result<Package> {
    let mut fields = line.split(FIELD_SEP);
    let name = fields.next().context("missing NAME field")?.to_string();
    let epoch_raw = fields.next().context("missing EPOCH field")?;
    let epoch = if epoch_raw == "(none)" {
        0
    } else {
        epoch_raw.parse().unwrap_or(0)
    };
    let version = fields.next().context("missing VERSION field")?.to_string();
    let release = fields.next().context("missing RELEASE field")?.to_string();
    let arch = fields.next().context("missing ARCH field")?.to_string();
    let install_size: u64 = fields.next().unwrap_or_default().parse().unwrap_or(0);
    let summary = fields.next().unwrap_or_default().to_string();
    let provides_raw = fields.next().unwrap_or_default();
    let requires_raw = fields.next().unwrap_or_default();
    let recommends_raw = fields.next().unwrap_or_default();
    let filenames_raw = fields.next().unwrap_or_default();

    let mut provides = parse_nevrs(provides_raw);
    provides.extend(
        filenames_raw
            .split(ARRAY_SEP)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|path| Dependency {
                name: path.to_string(),
                constraint: None,
            }),
    );

    Ok(Package {
        nevra: Nevra {
            name,
            epoch,
            version,
            release,
            arch,
        },
        summary,
        provides,
        requires: parse_nevrs(requires_raw),
        conflicts: Vec::new(),
        obsoletes: Vec::new(),
        recommends: parse_nevrs(recommends_raw),
        suggests: Vec::new(),
        enhances: Vec::new(),
        supplements: Vec::new(),
        location: String::new(),
        repo_id: String::new(), // filled in by caller with "base"/"overlay"
        repo_priority: vez_core::default_repo_priority(),
        repo_cost: vez_core::default_repo_cost(),
        install_size,
        download_size: 0,
        vendor: String::new(),
        checksum_type: String::new(),
        checksum: String::new(),
    })
}

/// Parses one entry of an rpm `PROVIDENEVRS`/`REQUIRENEVRS`-style array. Each
/// item is either a bare capability name or `name OP version` (e.g.
/// `libfoo.so.1()(64bit)` or `glibc >= 2.34`).
fn parse_nevrs(raw: &str) -> Vec<Dependency> {
    raw.split(ARRAY_SEP)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| {
            // Rich/boolean dependencies (`(rpm-plugin-selinux if rpm-libs)`)
            // are stored as one token containing spaces. They aren't a NAME
            // [OP VER] triple, so keep them intact instead of reading
            // "if"/"unless" as a comparator and truncating the name.
            if entry.starts_with('(') {
                return Dependency::unversioned(entry.to_string());
            }
            let mut parts = entry.splitn(3, ' ');
            let name = parts.next().unwrap_or_default().to_string();
            let op = parts.next();
            let ver = parts.next();
            match (op, ver) {
                (Some(op), Some(ver)) => {
                    let cmp = match op {
                        "<" => Some(Comparator::Lt),
                        "<=" => Some(Comparator::Le),
                        "=" => Some(Comparator::Eq),
                        ">=" => Some(Comparator::Ge),
                        ">" => Some(Comparator::Gt),
                        _ => None,
                    };
                    match cmp {
                        Some(cmp) => Dependency {
                            name,
                            constraint: Some((cmp, ver.to_string())),
                        },
                        None => Dependency::unversioned(name),
                    }
                }
                _ => Dependency::unversioned(name),
            }
        })
        .collect()
}

/// Makes sure a writable rpmdb exists at `dbpath`, creating and initializing
/// it the first time vez writes to it (e.g. the first `vez install` on a
/// freshly imaged machine). `rpm --initdb` is a no-op on an initialized db,
/// so it's safe to call before every write without tracking whether it
/// already ran.
pub fn ensure_initialized(dbpath: &Path) -> Result<()> {
    std::fs::create_dir_all(dbpath)
        .with_context(|| format!("creating rpmdb directory {}", dbpath.display()))?;
    let status = Command::new("rpm")
        .arg("--dbpath")
        .arg(dbpath)
        .arg("--initdb")
        .status()
        .context("spawning rpm --initdb")?;
    anyhow::ensure!(
        status.success(),
        "rpm --initdb --dbpath {} failed with {status}",
        dbpath.display()
    );
    Ok(())
}

/// Strips a concrete rpm ISA suffix (`(x86-64)`/`(x86-32)`) off a capability
/// name and returns the bare name plus the arch it names. rpm builds
/// auto-generate a `name(x86-64) = EVR` self-provide for every 64-bit capable
/// package. Repo metadata (primary.xml) lists it explicitly, but
/// [`Package::provides_self`] only produces the bare-name form. Without this,
/// a `Requires: foo(x86-64) = <exact EVR>` (e.g. an auto-generated package
/// pinning a sibling from the same build) never matches an installed `foo`
/// even when it satisfies the requirement exactly. The caller then treats it
/// as needing a fresh install and throws away a good installed copy for a
/// repo candidate that may be a different build (even an older one, if repo
/// priority ranks it first).
fn strip_isa_suffix(name: &str) -> Option<(&str, &str)> {
    let (base, rest) = name.rsplit_once('(')?;
    let suffix = rest.strip_suffix(')')?;
    let arch = match suffix {
        "x86-64" => "x86_64",
        "x86-32" => "i686",
        _ => return None,
    };
    Some((base, arch))
}

/// True for a package with no shared-library (`.so`) capability of its own,
/// i.e. a single-arch helper (a spawned executable, a data package, a D-Bus
/// service) and not a real multilib library that binaries link against per
/// arch. `glycin-loaders` is one: its loader binaries live at paths that
/// aren't arch-namespaced (`/usr/libexec/<name>/...`, as opposed to
/// `/usr/lib64` vs `/usr/lib`). An i686 build installed next to an x86_64
/// build adds no real 32-bit capability. It loses the file-write race against
/// the 64-bit build (rpm's file-color multilib handling keeps the
/// higher-color file and drops the other) and still drags in its own
/// transitive Requires for nothing. Since nothing links against this package
/// per arch, an ISA-tagged Requires on it (e.g. `glycin-loaders(x86-32)`) is
/// satisfied just as well by an installed build of *any* arch.
fn is_single_arch_helper(pkg: &Package) -> bool {
    !pkg.provides.iter().any(|p| p.name.contains(".so"))
}

/// Is `name` present (by capability, not only package name) in this rpmdb
/// at all? Used by the overlay layer's satisfied-by-base check.
///
/// `requiring_arch` is the arch of the package whose `Requires` is being
/// checked, when known. Repo metadata often leaves soname/symbol-version
/// capabilities (`libc.so.6(GLIBC_2.38)`, `libfoo.so.1`) without an explicit
/// `(x86-32)`/`(64bit)` ISA suffix even though they're arch-specific, and an
/// installed x86_64 `glibc`'s untagged `libc.so.6(...)` provide must not
/// satisfy an i686 package's Requires of the same name. For that class of
/// dependency, candidate providers are filtered to `requiring_arch` (or
/// `noarch`). Plain package-name and file-path capabilities aren't filtered
/// by arch, since those really are shared across arches (or carry their own
/// ISA tag that callers handle).
pub fn provides_capability(
    installed: &[Package],
    dep: &Dependency,
    requiring_arch: Option<&str>,
) -> bool {
    fn check_one(
        pkg: &Package,
        dep: &Dependency,
        requiring_arch: Option<&str>,
        is_soname_dep: bool,
        isa: Option<(&str, &str)>,
    ) -> bool {
        if is_soname_dep {
            if let Some(want_arch) = requiring_arch {
                if pkg.nevra.arch != want_arch && pkg.nevra.arch != "noarch" {
                    return false;
                }
            }
        }
        if let Some((base, want_arch)) = isa {
            let arch_ok = pkg.nevra.arch == want_arch
                || (pkg.nevra.arch != want_arch && is_single_arch_helper(pkg));
            if pkg.nevra.name == base && arch_ok {
                let satisfied = match &dep.constraint {
                    None => true,
                    Some(_) => dep.satisfied_by_evr(&pkg.nevra.evr()),
                };
                if satisfied {
                    return true;
                }
            }
        }
        pkg.provides
            .iter()
            .chain(std::iter::once(&pkg.provides_self()))
            .any(|prov| {
                if prov.name != dep.name {
                    return false;
                }
                // An unversioned dep is satisfied by any provide of the same
                // name. rpm also lets an *unversioned* provide satisfy *any*
                // versioned Requires on that name. For example lvm2's
                // `(system-release >= 23 if system-release)` is met by
                // fedora-release-container's bare `Provides: system-release` (no
                // EVR) on real dnf/rpm. Only a *versioned* provide needs its EVR
                // checked against the constraint.
                match (&dep.constraint, &prov.constraint) {
                    (None, _) | (Some(_), None) => true,
                    (Some(_), Some((_, have))) => dep.satisfied_by_evr(have),
                }
            })
    }

    let is_soname_dep = dep.name.contains(".so");
    let isa = strip_isa_suffix(&dep.name);
    installed
        .iter()
        .any(|pkg| check_one(pkg, dep, requiring_arch, is_soname_dep, isa))
}

/// Capability index over an installed-package list, built once per resolve so
/// [`CapabilityIndex::provides`] can use an O(1)-average `HashMap` lookup in
/// place of the O(installed) linear scan in `provides_capability`.
/// [`vez_overlay::OverlayContext`] builds it once and it's reused for every
/// dependency edge the resolver's BFS walks. With thousands of base packages
/// and thousands of edges, the unindexed scan (which also scans each
/// package's own `provides` list) was the main cost of dependency resolution.
///
/// Stores indices into the caller's slice instead of borrowed `&Package`s so
/// it isn't self-referential. Callers must pass the *same* slice to
/// [`CapabilityIndex::provides`] that they passed to
/// [`CapabilityIndex::build`].
pub struct CapabilityIndex {
    by_capability: std::collections::HashMap<String, Vec<usize>>,
}

impl CapabilityIndex {
    pub fn build(installed: &[Package]) -> Self {
        let mut by_capability: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, pkg) in installed.iter().enumerate() {
            by_capability
                .entry(pkg.nevra.name.clone())
                .or_default()
                .push(i);
            for p in &pkg.provides {
                by_capability.entry(p.name.clone()).or_default().push(i);
            }
        }
        Self { by_capability }
    }

    /// Same result as `provides_capability(installed, dep, requiring_arch)`,
    /// given the `installed` slice this index was [`build`](Self::build)
    /// from. An indexed candidate lookup replaces the outer linear scan; the
    /// per-candidate matching (including the ISA-suffix and soname arch
    /// filter) is the same.
    pub fn provides(
        &self,
        installed: &[Package],
        dep: &Dependency,
        requiring_arch: Option<&str>,
    ) -> bool {
        let is_soname_dep = dep.name.contains(".so");
        let isa = strip_isa_suffix(&dep.name);

        // rpm auto-generates the ISA-suffixed self-provide (`name(x86-64)`),
        // so it isn't always a literal `provides` entry. provides_capability
        // checks it with `pkg.nevra.name == base` outside the general
        // provides scan, so the index needs the same separate lookup keyed on
        // the bare `base` name.
        if let Some((base, want_arch)) = isa {
            if let Some(idxs) = self.by_capability.get(base) {
                for &i in idxs {
                    let pkg = &installed[i];
                    if is_soname_dep {
                        if let Some(want) = requiring_arch {
                            if pkg.nevra.arch != want && pkg.nevra.arch != "noarch" {
                                continue;
                            }
                        }
                    }
                    let arch_ok = pkg.nevra.arch == want_arch
                        || (pkg.nevra.arch != want_arch && is_single_arch_helper(pkg));
                    if pkg.nevra.name == base && arch_ok {
                        let satisfied = match &dep.constraint {
                            None => true,
                            Some(_) => dep.satisfied_by_evr(&pkg.nevra.evr()),
                        };
                        if satisfied {
                            return true;
                        }
                    }
                }
            }
        }

        let Some(idxs) = self.by_capability.get(dep.name.as_str()) else {
            return false;
        };
        idxs.iter().any(|&i| {
            let pkg = &installed[i];
            if is_soname_dep {
                if let Some(want_arch) = requiring_arch {
                    if pkg.nevra.arch != want_arch && pkg.nevra.arch != "noarch" {
                        return false;
                    }
                }
            }
            let self_prov = pkg.provides_self();
            // See the matching comment in `provides_capability` above: an
            // unversioned provide satisfies any versioned Requires too, as in
            // rpm's dependency comparison.
            pkg.provides
                .iter()
                .chain(std::iter::once(&self_prov))
                .filter(|prov| prov.name == dep.name)
                .any(|prov| match (&dep.constraint, &prov.constraint) {
                    (None, _) | (Some(_), None) => true,
                    (Some(_), Some((_, have))) => dep.satisfied_by_evr(have),
                })
        })
    }
}
