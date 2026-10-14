pub mod sys;

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use vez_core::{Comparator, Dependency, Package, VersionLock};

/// Thin RAII wrapper around a libsolv `Pool`. Owns every `Repo` created
/// against it (libsolv frees repos when the pool is freed), so `Repo`
/// handles borrow from `Pool` rather than owning their own lifetime.
pub struct Pool {
    raw: *mut sys::Pool,
}

impl Pool {
    pub fn new() -> Result<Self> {
        let raw = unsafe { sys::pool_create() };
        anyhow::ensure!(!raw.is_null(), "pool_create returned null");
        Ok(Self { raw })
    }

    /// Sets the RPM-style architecture policy (e.g. `"x86_64"`) used to rank
    /// multiarch candidates and decide which compatible arches can be used
    /// (i686 on x86_64, etc.). This replaces what `host_arch`/`pref_arch` in
    /// `vez-resolver` did by hand.
    pub fn set_arch(&mut self, arch: &str) -> Result<()> {
        let c = CString::new(arch)?;
        unsafe { sys::pool_setarch(self.raw, c.as_ptr()) };

        // Same flags as dnf5's `Pool` constructor (libdnf5/solv/pool.hpp),
        // checked against dnf5's source: pool_set_flag(pool,
        // POOL_FLAG_WHATPROVIDESWITHDISABLED, 1); pool_set_flag(pool,
        // POOL_FLAG_IMPLICITOBSOLETEUSESCOLORS, 1); dnf5 does NOT set
        // POOL_FLAG_OBSOLETEUSESCOLORS. We used to; it's removed because it
        // isn't in dnf5's set.
        //
        // WHATPROVIDESWITHDISABLED: the solver never offers excluded packages
        // as provides candidates. IMPLICITOBSOLETEUSESCOLORS: makes libsolv's
        // implicit "same name, newer EVR obsoletes" rule aware of arch color,
        // so packages with the same name and a different (multilib) arch
        // install side by side instead of one obsoleting the other. This is
        // what fixed glycin-loaders.i686 clobbering glycin-loaders.x86_64.
        // dnf5's own comment on the flag: "Allow packages of the same name
        // with different architectures to be installed in parallel".
        //
        // ADDFILEPROVIDESFILTERED follows load_repos_common() in dnf5's
        // repo_sack.cpp, which sets it whenever filelists.xml isn't loaded
        // (it limits file-provides matching to primary.xml's files, for speed
        // and correctness). vez-repo never parses filelists.xml, so we set it
        // unconditionally where dnf5 sets it conditionally.
        unsafe {
            sys::pool_set_flag(self.raw, sys::POOL_FLAG_WHATPROVIDESWITHDISABLED as i32, 1);
            sys::pool_set_flag(
                self.raw,
                sys::POOL_FLAG_IMPLICITOBSOLETEUSESCOLORS as i32,
                1,
            );
            sys::pool_set_flag(self.raw, sys::POOL_FLAG_ADDFILEPROVIDESFILTERED as i32, 1);
        }
        Ok(())
    }

    /// Call after all repos/solvables are added and before creating a
    /// `Solver`. libsolv builds its provides index lazily.
    pub fn createwhatprovides(&mut self) {
        unsafe { sys::pool_createwhatprovides(self.raw) };
    }

    /// Marks `repo` as *the* installed/system repo, which drives libsolv's
    /// default upgrade/erase target semantics. In Split mode this should be
    /// the combined `@System` repo (base + overlay solvables). libsolv only
    /// supports one installed repo, so which solvables must never be erased
    /// is enforced separately with `SOLVER_LOCK` jobs over
    /// `PoolBuild::base_solvables`, not by repo membership.
    pub fn set_installed(&mut self, repo: &Repo) {
        unsafe { sys::pool_set_installed(self.raw, repo.raw) };
    }

    pub fn create_repo(&mut self, name: &str) -> Result<Repo> {
        let c = CString::new(name)?;
        let raw = unsafe { sys::repo_create(self.raw, c.as_ptr()) };
        anyhow::ensure!(!raw.is_null(), "repo_create returned null");
        Ok(Repo {
            raw,
            pool: self.raw,
        })
    }

    fn str2id(&mut self, s: &str, create: bool) -> sys::Id {
        // One CString allocation per call is fine here: this only runs while
        // filling the pool once, not per solve.
        let c = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
        unsafe { sys::pool_str2id(self.raw, c.as_ptr(), create as i32) }
    }

    fn rel2id(&mut self, name: sys::Id, evr: sys::Id, op: i32, create: bool) -> sys::Id {
        unsafe { sys::pool_rel2id(self.raw, name, evr, op, create as i32) }
    }

    /// Parses an rpm rich/boolean dependency string (`(A if B)`, `(A with
    /// B)`, `(A if B else C)`, ...) into one libsolv `Id` for the whole
    /// expression; libsolv evaluates these natively while solving. Without
    /// this, a rich-dep `Requires` went to `str2id` as if it were a literal
    /// capability name that nothing matches, so every package with one was
    /// unresolvable.
    fn parse_rich_dep(&mut self, s: &str) -> sys::Id {
        let c = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
        unsafe { sys::pool_parserpmrichdep(self.raw, c.as_ptr()) }
    }

    pub fn as_raw(&mut self) -> *mut sys::Pool {
        self.raw
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        unsafe { sys::pool_free(self.raw) };
    }
}

/// A libsolv `Repo`: a named group of `Solvable`s (one vez "source": the base
/// rpmdb, the overlay rpmdb, or one repo's available packages). Freed when
/// its owning `Pool` is freed; it doesn't implement `Drop` itself, to avoid a
/// double free.
pub struct Repo {
    raw: *mut sys::Repo,
    pool: *mut sys::Pool,
}

const REL_GT: i32 = sys::REL_GT as i32;
const REL_EQ: i32 = sys::REL_EQ as i32;
const REL_LT: i32 = sys::REL_LT as i32;

fn comparator_flags(cmp: Comparator) -> i32 {
    match cmp {
        Comparator::Lt => REL_LT,
        Comparator::Le => REL_LT | REL_EQ,
        Comparator::Eq => REL_EQ,
        Comparator::Ge => REL_GT | REL_EQ,
        Comparator::Gt => REL_GT,
    }
}

impl Repo {
    /// Adds one `vez_core::Package` as a new `Solvable` in this repo, turning
    /// its NEVRA and all its dependency lists into libsolv string/rel ids.
    /// Returns the new solvable's pool-wide `Id`.
    pub fn add_package(&mut self, pool: &mut Pool, pkg: &Package) -> sys::Id {
        let p = unsafe { sys::repo_add_solvable(self.raw) };
        let s = unsafe { sys::pool_id2solvable(self.pool, p) };
        debug_assert_eq!(self.pool, pool.raw);

        unsafe {
            (*s).name = pool.str2id(&pkg.nevra.name, true);
            (*s).arch = pool.str2id(&pkg.nevra.arch, true);
            (*s).evr = pool.str2id(&pkg.nevra.evr(), true);
        }

        self.add_deps(pool, s, &pkg.provides, DepKind::Provides);
        self.add_deps(pool, s, &pkg.requires, DepKind::Requires);
        self.add_deps(pool, s, &pkg.conflicts, DepKind::Conflicts);
        // The real upstream for `openh264` (Cisco's binary blob repo) only
        // publishes an x86_64 build; there's no real i686 one. Some
        // third-party/compat repos rebuild an i686 `openh264` with a bumped
        // epoch so 32-bit apps can `dlopen` it. That rebuild inherits
        // `Obsoletes: noopenh264` from the real spec, which collides with
        // `SOLVER_FLAG_YUM_OBSOLETES` (arch-independent obsoletes matching,
        // on to match dnf5) against the official multilib `noopenh264.x86_64`
        // and gives an unsolvable rule: `openh264.i686 obsoletes noopenh264 <
        // 1:0 provided by noopenh264.x86_64`. `openh264` was never meant to
        // obsolete anything outside its own arch, so drop that Obsoletes edge
        // instead of letting it block every `vez upgrade`.
        if pkg.nevra.name == "openh264" {
            let obsoletes: Vec<Dependency> = pkg
                .obsoletes
                .iter()
                .filter(|d| d.name != "noopenh264")
                .cloned()
                .collect();
            self.add_deps(pool, s, &obsoletes, DepKind::Obsoletes);
        } else {
            self.add_deps(pool, s, &pkg.obsoletes, DepKind::Obsoletes);
        }
        self.add_deps(pool, s, &pkg.recommends, DepKind::Recommends);
        self.add_deps(pool, s, &pkg.suggests, DepKind::Suggests);

        // By libsolv convention a solvable provides its own name = evr, but
        // libsolv doesn't add that itself, so most callers of
        // repo_add_solvable add it explicitly.
        unsafe {
            let self_dep = pool.rel2id((*s).name, (*s).evr, REL_EQ, true);
            (*s).provides = sys::repo_addid_dep(self.raw, (*s).provides, self_dep, 0);
        }

        p
    }

    fn add_deps(
        &mut self,
        pool: &mut Pool,
        s: *mut sys::Solvable,
        deps: &[Dependency],
        kind: DepKind,
    ) {
        for dep in deps {
            let dep_id = if dep.constraint.is_none() && dep.name.starts_with('(') {
                pool.parse_rich_dep(&dep.name)
            } else {
                let name_id = pool.str2id(&dep.name, true);
                match &dep.constraint {
                    Some((cmp, ver)) => {
                        let evr_id = pool.str2id(ver, true);
                        pool.rel2id(name_id, evr_id, comparator_flags(*cmp), true)
                    }
                    None => name_id,
                }
            };
            unsafe {
                let field = match kind {
                    DepKind::Provides => &mut (*s).provides,
                    DepKind::Requires => &mut (*s).requires,
                    DepKind::Conflicts => &mut (*s).conflicts,
                    DepKind::Obsoletes => &mut (*s).obsoletes,
                    DepKind::Recommends => &mut (*s).recommends,
                    DepKind::Suggests => &mut (*s).suggests,
                };
                *field = sys::repo_addid_dep(self.raw, *field, dep_id, 0);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum DepKind {
    Provides,
    Requires,
    Conflicts,
    Obsoletes,
    Recommends,
    Suggests,
}

/// Result of filling a `Pool` from vez's candidate/overlay data: everything a
/// later solve step needs, including which solvable ids came from the base
/// image so it can `SOLVER_LOCK` them and keep Split mode's guarantee that
/// base packages are never erased.
pub struct PoolBuild {
    pub pool: Pool,
    /// The host arch `set_arch` configured this pool for. Kept next to `pool`
    /// because `Pool` has no getter for it and `solve()` needs it (e.g. to
    /// fall back from a suppressed or missing 32-bit pinned-install NEVRA to
    /// the host-arch build).
    pub host_arch: String,
    /// `@System` repo: base + overlay solvables, marked installed via
    /// `Pool::set_installed`.
    pub system_repo: Repo,
    /// Available-candidates repo (union of all enabled repos' packages).
    pub available_repo: Repo,
    /// Solvable ids in `system_repo` that came from the *base* image
    /// (`Origin::Base`). The solve step must `SOLVER_LOCK` every one of these
    /// so libsolv never proposes erasing or replacing them. Installed
    /// solvables from the overlay have no such restriction.
    pub base_solvables: HashSet<sys::Id>,
    /// Every solvable id added to `system_repo` (base + overlay), i.e.
    /// everything currently installed whatever its origin. Used to limit
    /// erase jobs to installed candidates, like dnf5's `add_remove`
    /// (`libdnf5/rpm/solv/goal_private.hpp`), which always gets a queue of
    /// resolved *installed*-package ids and never a name/provides selector.
    pub installed_solvables: HashSet<sys::Id>,
    /// Every solvable id added (system + available), mapped back to the
    /// `vez_core::Package` it came from, so `solve()` can turn a libsolv
    /// transaction back into vez types without rebuilding NEVRA/deps from raw
    /// pool string ids.
    pub packages: HashMap<sys::Id, Package>,
    /// Installed (base or overlay) packages that `add_filtered` above left
    /// out of the pool because they're foreign-arch builds the arch-clobber
    /// guard (`foreign_build_clobbers_host`) suppresses. They're really
    /// installed (the rpmdb still lists them) but libsolv can't see them, so
    /// a plain solve can never propose erasing them: there's no solvable id
    /// to erase. The upgrade/distro-sync handling in `solve()` uses this list
    /// to migrate them explicitly: erase the stale foreign-arch copy and, if
    /// the host-arch build of the same name isn't installed, install it. It's
    /// the same "use the 64-bit build, or skip it if that's already there"
    /// fallback that [`SolveRequest::pinned_installs`] gives a soft reset's
    /// exact-NEVRA pins, applied to `vez upgrade`/`vez system-upgrade` moving
    /// an old overlay off a leftover 32-bit install.
    pub suppressed_installed: Vec<Package>,
}

/// The ISA tag rpm's dependency generator appends to a `Requires` when it
/// wants a provider of the same arch (`glycin-libs(x86-32)`, which rpm also
/// mirrors on `Provides` where it can). Only the two arches vez's multilib
/// handling deals with matter here.
fn isa_tag(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("x86-64"),
        "i686" | "i386" | "i586" => Some("x86-32"),
        _ => None,
    }
}

/// Strips a `(x86-64)`/`(x86-32)` ISA suffix off a capability name, e.g.
/// `"librepo(x86-64)"` -> `"librepo"`, and returns the name unchanged if
/// there's no suffix. Needed because the base-name constraint relaxation
/// below (`base_names.contains(dep.name)`) only ever matched a plain
/// `Requires: librepo = <evr>`. An ISA-tagged `Requires: librepo(x86-64) =
/// <evr>` (rpm's `%{name}%{?_isa} = %{version}-%{release}` convention, used
/// by almost every -devel/-libs subpackage) never equals the plain base name
/// `"librepo"`, so it was never relaxed. With same-name+arch shadow
/// candidates kept out of the pool (which is what Split mode is for), an
/// exact-EVR ISA-tagged require pinned to a *newer* EVR than the base one
/// became unsatisfiable: `vez install librepo-devel` failed with "nothing
/// provides librepo(x86-64) = 1.21.0-1 needed by librepo-devel-1.21.0-1" even
/// though librepo is on base, just at an older build (1.20.0-5) missing the
/// newest point release.
fn strip_isa_suffix(name: &str) -> &str {
    for tag in ["(x86-64)", "(x86-32)"] {
        if let Some(stripped) = name.strip_suffix(tag) {
            return stripped;
        }
    }
    name
}

/// The same base-package version-constraint relaxation `add_filtered` applies
/// to a plain `Requires` (drop the exact-EVR pin on a require that targets a
/// name only the locked base rpmdb has, so the installed copy satisfies it
/// even if a fresh build would have wanted a newer EVR), but applied *inside*
/// a rich/boolean dependency string. Those operands never go through that
/// check, because the whole `(...)` expression is stored as one unversioned
/// `Dependency::name`.
///
/// Seen on an nvidia image: the base-installed
/// `nvidia-driver-cuda-libs.x86_64` carries `Requires:
/// (nvidia-driver-cuda-libs(x86-32) = 3:E-R if steam)` (rpm's
/// conditional-multilib generator). Once rpmfusion's i686 build moves to a
/// newer E-R than the x86_64 build baked into the image (Split mode can't
/// upgrade them together because the base x86_64 build is `SOLVER_LOCK`ed),
/// that exact-EVR operand names an i686 NEVRA that no repo has anymore, and
/// `vez install steam` failed with "package nvidia-driver-cuda-libs-…x86_64
/// requires (…(x86-32) = … if steam), but none of the providers can be
/// installed". Relaxing the operand to an unversioned
/// `nvidia-driver-cuda-libs(x86-32)` lets libsolv pull whatever i686 build
/// the repos have now, which is how dnf treats the multilib counterpart of an
/// installed package.
///
/// Only depth-0 `NAME <cmp> EVR` triples whose ISA-stripped name is a base
/// name are rewritten. Anything nested or unrecognized is left as is.
fn relax_rich_dep_base_versions(expr: &str, base_names: &HashSet<&str>) -> String {
    // Unwrap one outer `(...)` layer so operator/operand tokens sit at the
    // depth this scan calls "0", then re-wrap.
    if let Some(inner) = expr.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        return format!("({})", relax_rich_dep_base_versions(inner, base_names));
    }
    const CMPS: [&str; 6] = ["<=", ">=", "==", "=", "<", ">"];
    let toks: Vec<&str> = expr.split(' ').collect();
    let mut out: Vec<&str> = Vec::with_capacity(toks.len());
    let mut depth = 0i32;
    let mut i = 0;
    while i < toks.len() {
        let tok = toks[i];
        let start_depth = depth;
        depth += tok.matches('(').count() as i32 - tok.matches(')').count() as i32;
        // A `NAME <cmp> EVR` triple, all three tokens at depth 0, whose
        // ISA-stripped name is a base name: keep NAME, drop `<cmp> EVR`.
        if start_depth == 0
            && depth == 0
            && i + 2 < toks.len()
            && CMPS.contains(&toks[i + 1])
            && !toks[i + 2].is_empty()
            && !toks[i + 2].contains(['(', ')'])
            && base_names.contains(strip_isa_suffix(tok))
        {
            out.push(tok);
            i += 3;
            continue;
        }
        out.push(tok);
        i += 1;
    }
    out.join(" ")
}

/// Replaces a fixed allowlist of single-arch helper packages
/// (`glycin-loaders`, `pipewire`, added one by one as each was reported
/// clobbering the host-arch build's files). A "has no .so" heuristic was
/// tried first and reverted: it also caught real multilib packages like
/// `mesa-vulkan-drivers`, which ship no `.so` `Provides` of their own but are
/// real per-arch ICD/driver packages that have to stay installable in both
/// arches for Steam's 32-bit stack.
///
/// This looks at what causes the clobbering. A `<file>` entry in primary.xml
/// (`bin`/`sbin`/`usr/{bin,sbin}`/`etc`; see `primary.rs`) becomes an
/// unversioned `Provides` on that absolute path. Only the `bin`/`sbin` subset
/// is compared here, leaving out `/etc`. Real Fedora repo data
/// (`vulkan-loader`, checked with `dnf5 repoquery -l` against fedora:44)
/// shows plenty of multilib-safe packages shipping the same `/etc`
/// *directory* entries (e.g. `/etc/vulkan/icd.d`) in both arch builds, which
/// is normal shared directory ownership and not a clobber, and primary.xml's
/// `<file>` list doesn't distinguish directories from files. Comparing `/etc`
/// paths caused a bug: `vulkan-loader.i686` was suppressed over its shared
/// `/etc/vulkan*` dirs, which dropped the `vulkan(x86-32)` capability and
/// broke `vez install mesa-vulkan-drivers.i686` with "nothing provides
/// vulkan(x86-32)". `bin`/`sbin` entries are always real executables and
/// never directories, so a collision there is always a real same-file clobber
/// (e.g. `pipewire`'s `/usr/bin/pipewire`, shipped identically by both arch
/// builds of the daemon package).
///
/// A real multilib package's foreign-arch build installs its binaries and
/// libs under an arch-namespaced path (`/usr/lib` vs `/usr/lib64`) or as a
/// `.so` that never shows up as a `<file>` provide, so `host_paths` and the
/// foreign build's paths never collide for it.
///
/// This still can't see the clobber in `glycin-loaders` (checked with `dnf5
/// repoquery -l`: the only path its arch builds share is
/// `/usr/libexec/glycin-loaders/...`, a directory primary.xml never records,
/// so there's no `bin`/`sbin`/`etc` entry to compare). It's kept as a narrow
/// explicit fallback below.
///
/// A bin/sbin path collision alone isn't enough to suppress the whole
/// package. Only suppress when that wouldn't also throw away real per-arch
/// library content that the foreign build is the *only* source of. Skipping
/// this check caused two bugs:
///
/// - `glibc.i686`/`glibc.x86_64` both ship `/usr/bin/ldconfig` and
///   `/usr/bin/iconvconfig` (checked with `dnf5 repoquery -l` against
///   fedora:44). By this function's rule that's a bin-path collision, so the
///   *entire* `glibc.i686` build was suppressed over those two tools,
///   silently dropping what it's actually needed for: `/lib/libc.so.6`,
///   `/lib/ld-linux.so.2`. Every 32-bit binary that needs `libc.so.6` /
///   `ld-linux.so.2` broke (e.g. dracut-install: "could not locate dependency
///   libc.so.6" for any i686 `.so` pulled in by mesa/vulkan's i686 builds).
/// - `mangohud.i686`/`mangohud.x86_64` both ship `/usr/bin/mangoapp`,
///   `/usr/bin/mangohud`, `/usr/bin/mangohudctl` (same check). Same false
///   positive, this time dropping `/usr/lib/mangohud/libMangoHud*.so`, the
///   32-bit overlay Steam/Proton needs, so `vez install mangohud.i686` was
///   silently incomplete.
///
/// The file-path check that used to gate this (does the foreign build own any
/// provide under `/usr/lib`/`/lib`?) can't work: primary.xml's `<file>`
/// capture (see `primary.rs`) only includes bin/sbin/etc paths and never
/// library directories, so `/usr/lib/mangohud/libMangoHud.so` is invisible
/// whatever prefix is checked. The reliable signal is the package's
/// *declared* `Provides` (`<rpm:provides>`, always in primary.xml regardless
/// of file capture). A package that ships a real shared library always gets
/// rpm's automatic bare-soname `Provides` for it (checked: `mangohud.i686`
/// provides `libMangoHud.so`, `glibc.i686` provides
/// `libc.so.6`/`ld-linux.so.2`/etc.), wherever the `.so` lives. `pipewire` is
/// the case this function still has to catch: `dnf5 repoquery --provides
/// pipewire.i686` lists no soname `Provides`, only `pipewire(x86-32)` and
/// similar, because its plugin `.so`s live in the separate `pipewire-libs`
/// package. Its shared `/usr/bin/pipewire` really is its whole payload for
/// that path, so suppressing the foreign build loses nothing. glibc and
/// mangohud fail that test (they have soname `Provides`), so their bin-path
/// collision is the ordinary same-tool-name case that rpm/dnf multilib
/// resolves with file coloring (both builds installed, rpm keeps one file on
/// disk for that path) and never by suppressing the whole package.
fn foreign_build_clobbers_host(host_paths: &HashSet<&str>, foreign_pkg: &Package) -> bool {
    if foreign_pkg.nevra.name == "glycin-loaders" {
        return true;
    }
    let has_own_library_payload = foreign_pkg
        .provides
        .iter()
        .any(|p| !p.name.starts_with('/') && p.name.starts_with("lib") && p.name.contains(".so"));
    if has_own_library_payload {
        return false;
    }
    foreign_pkg.provides.iter().any(|p| {
        let is_bin_path = p.name.starts_with("/bin/")
            || p.name.starts_with("/sbin/")
            || p.name.starts_with("/usr/bin/")
            || p.name.starts_with("/usr/sbin/");
        is_bin_path && host_paths.contains(p.name.as_str())
    })
}

/// Builds a libsolv `Pool` from vez's already-loaded package lists.
/// `base`/`overlay` are what's installed now (Split mode: two separate rpmdbs
/// that never merge on disk, per `vez_core::Origin::Base`/`Overlay`). In
/// Standalone mode callers pass the single installed set as `overlay` and an
/// empty `base`. `available` is the full candidate set from enabled repos.
pub fn build_pool(
    host_arch: &str,
    base: &[Package],
    overlay: &[Package],
    available: &[Package],
) -> Result<PoolBuild> {
    build_pool_locked(host_arch, base, overlay, available, &[])
}

/// Same as [`build_pool`], except `locks` (dnf5 versionlock behavior) keeps
/// any candidate whose name is locked out of `available_repo` unless its
/// `epoch:version-release`/`arch` exactly match what the lock pins
/// ([`VersionLock::allows`]). That's what stops a *transitive* dependency
/// pull (not only a direct `install`/`upgrade`) from moving a locked package,
/// since libsolv can only select what's in the pool. A lock with no recorded
/// EVR/arch (the name wasn't installed when the lock was added) blocks
/// nothing.
pub fn build_pool_locked(
    host_arch: &str,
    base: &[Package],
    overlay: &[Package],
    available: &[Package],
    locks: &[VersionLock],
) -> Result<PoolBuild> {
    let mut pool = Pool::new()?;
    pool.set_arch(host_arch)?;

    // Names that have both a host-arch/noarch build and a foreign-arch build
    // whose file-path Provides collide with it (a single-arch helper package;
    // see `foreign_build_clobbers_host`) anywhere in base+overlay+available.
    // For these the foreign-arch build is left out of the pool and the
    // host-arch build gets its ISA tag as an extra Provides.
    let all_iter = || base.iter().chain(overlay.iter()).chain(available.iter());
    let mut host_names: HashSet<&str> = HashSet::new();
    let mut host_file_paths: HashMap<&str, HashSet<&str>> = HashMap::new();
    for pkg in all_iter() {
        if pkg.nevra.arch == host_arch || pkg.nevra.arch == "noarch" {
            host_names.insert(&pkg.nevra.name);
            let paths = host_file_paths.entry(pkg.nevra.name.as_str()).or_default();
            for p in &pkg.provides {
                if p.name.starts_with('/') {
                    paths.insert(p.name.as_str());
                }
            }
        }
    }
    let mut suppressed_names: HashSet<&str> = HashSet::new();
    for pkg in all_iter() {
        if pkg.nevra.arch != host_arch
            && pkg.nevra.arch != "noarch"
            && host_names.contains(pkg.nevra.name.as_str())
        {
            if let Some(paths) = host_file_paths.get(pkg.nevra.name.as_str()) {
                if foreign_build_clobbers_host(paths, pkg) {
                    suppressed_names.insert(pkg.nevra.name.as_str());
                }
            }
        }
    }

    // Every unversioned capability (soname `Provides` included, not only the
    // ISA tag) that a suppressed foreign-arch build offered. These get added
    // to the matching host-arch build below, so unversioned `Requires` on
    // them (e.g. `libglycin-2.so.0`, as well as `glycin-libs(x86-32)`) still
    // resolve once the foreign-arch build is out of the pool.
    let mut foreign_provides: HashMap<&str, Vec<String>> = HashMap::new();
    for pkg in all_iter() {
        if suppressed_names.contains(pkg.nevra.name.as_str())
            && pkg.nevra.arch != host_arch
            && pkg.nevra.arch != "noarch"
        {
            let entry = foreign_provides.entry(pkg.nevra.name.as_str()).or_default();
            for p in &pkg.provides {
                if p.constraint.is_none() && !entry.contains(&p.name) {
                    entry.push(p.name.clone());
                }
            }
            if let Some(tag) = isa_tag(&pkg.nevra.arch) {
                let isa_name = format!("{}({tag})", pkg.nevra.name);
                if !entry.contains(&isa_name) {
                    entry.push(isa_name);
                }
            }
        }
    }

    // Base packages are always `SOLVER_LOCK`ed (see `solve()`) and must never
    // be shadowed by a same-name overlay/available copy either. So a
    // `Requires` pinned to an exact newer EVR of a base-only package (e.g.
    // `rpm-devel = 6.1.0` requiring `rpm = 6.1.0` when base only has
    // `rpm-6.0.2`) can't be satisfied as written. Instead of failing the
    // whole solve or dropping the upgrade that carries it, strip the version
    // constraint from any `Requires` that targets a base package's name. The
    // installed, locked base copy then satisfies it (unversioned requires are
    // satisfied by any installed provider), the same way dnf/rpm treat an
    // installed dependency as satisfied whatever version a newer build might
    // have wanted. Without this, `vez upgrade`/`system-upgrade` failed with
    // "cannot install both rpm-0:6.1.0... and rpm-0:6.0.2..." whenever an
    // overlay package's upgrade needed a newer EVR of a package that only
    // exists in the base rpmdb.
    let base_names: HashSet<&str> = base.iter().map(|p| p.nevra.name.as_str()).collect();

    // `base` and `overlay` come from two independent sources (the read-only
    // base image rpmdb and the separate overlay rpmdb), and nothing
    // guarantees they don't overlap. An overlay rpmdb can keep a copy of a
    // package that's also on base (left over from before it landed on base,
    // or from this same bug on an earlier run). Without dedup, `add_filtered`
    // below creates two libsolv solvable ids for the identical NEVRA, one per
    // call. The base one gets `SOLVER_LOCK`ed (see `solve()`) while a
    // pinned-install job (`vez install` on a tracked package,
    // `resolve_pinned`) can target the other, and libsolv rejects two
    // installed solvables of the same name as "cannot install both X-EVR and
    // X-EVR". This crashed the reinstall pass of a forced replay.
    // Track every NEVRA already added so the second (overlay) call
    // skips an exact duplicate of a base solvable; the locked base copy
    // already satisfies anything the overlay copy would have.
    let mut added_nevra: HashSet<String> = HashSet::new();

    let mut suppressed_installed: Vec<Package> = Vec::new();
    let add_filtered = |repo: &mut Repo,
                        pool: &mut Pool,
                        packages: &mut HashMap<sys::Id, Package>,
                        pkgs: &[Package],
                        want_ids: Option<&mut HashSet<sys::Id>>,
                        added_nevra: &mut HashSet<String>,
                        is_installed: bool,
                        suppressed_installed: &mut Vec<Package>| {
        let mut want_ids = want_ids;
        for pkg in pkgs {
            if suppressed_names.contains(pkg.nevra.name.as_str())
                && pkg.nevra.arch != host_arch
                && pkg.nevra.arch != "noarch"
            {
                if is_installed {
                    suppressed_installed.push(pkg.clone());
                }
                continue;
            }
            if !added_nevra.insert(pkg.nevra.to_string()) {
                continue;
            }
            let mut pkg = pkg.clone();
            if let Some(extra) = foreign_provides.get(pkg.nevra.name.as_str()) {
                for name in extra {
                    if !pkg.provides.iter().any(|p| &p.name == name) {
                        pkg.provides.push(Dependency::unversioned(name.clone()));
                    }
                }
            }
            // Every rpm implicitly provides itself at its own EVR, plus (for
            // arch-sensitive builds) an ISA-tagged self-provide
            // (`name(x86-64) = evr`), which is what `%{name}%{?_isa} =
            // %{version}-%{release}`-style Requires on -devel/-libs
            // subpackages resolve against. Repo metadata and rpmdb parsing
            // don't always list these (see the doc comment on
            // `Package::provides_self`), and nothing else adds them to the
            // libsolv pool. This was hidden until Split mode excluded
            // same-name+arch duplicates from `available`: a fresh candidate
            // at the same EVR happened to satisfy the exact match. Without
            // that shadow candidate, the base/overlay/available copy must
            // carry its own self-provide, or an ISA-qualified exact-EVR
            // Requires becomes unsatisfiable. `vez upgrade` failed with
            // "nothing provides librepo(x86-64) = ... needed by
            // librepo-devel" even though librepo is on base.
            let evr = pkg.nevra.evr();
            if !pkg.provides.iter().any(|p| p.name == pkg.nevra.name) {
                pkg.provides.push(Dependency {
                    name: pkg.nevra.name.clone(),
                    constraint: Some((Comparator::Eq, evr.clone())),
                });
            }
            if let Some(tag) = isa_tag(&pkg.nevra.arch) {
                let isa_name = format!("{}({tag})", pkg.nevra.name);
                if !pkg.provides.iter().any(|p| p.name == isa_name) {
                    pkg.provides.push(Dependency {
                        name: isa_name,
                        constraint: Some((Comparator::Eq, evr)),
                    });
                }
            }
            for dep in &mut pkg.requires {
                if dep.constraint.is_some() && base_names.contains(strip_isa_suffix(&dep.name)) {
                    dep.constraint = None;
                } else if dep.constraint.is_none() && dep.name.starts_with('(') {
                    dep.name = relax_rich_dep_base_versions(&dep.name, &base_names);
                }
            }
            let id = repo.add_package(pool, &pkg);
            if let Some(ref mut ids) = want_ids {
                ids.insert(id);
            }
            packages.insert(id, pkg);
        }
    };

    let mut system_repo = pool.create_repo("@System")?;
    let mut base_solvables = HashSet::new();
    let mut installed_solvables = HashSet::new();
    let mut packages = HashMap::new();
    add_filtered(
        &mut system_repo,
        &mut pool,
        &mut packages,
        base,
        Some(&mut base_solvables),
        &mut added_nevra,
        true,
        &mut suppressed_installed,
    );
    add_filtered(
        &mut system_repo,
        &mut pool,
        &mut packages,
        overlay,
        Some(&mut installed_solvables),
        &mut added_nevra,
        true,
        &mut suppressed_installed,
    );

    // A base-owned name covers every arch it's installed under, not only the
    // arch(es) in the base rpmdb. In Split mode one arch of a name is often
    // on base (e.g. libcap-ng.x86_64, shipped on the image) while a
    // *different* arch of the same name lands in the overlay (e.g.
    // libcap-ng.i686, pulled in later for Steam's 32-bit stack). They're the
    // same logical package, so the overlay arch has to be locked together
    // with the base arch instead of updating on its own. Without this,
    // `upgrade_all` moved the overlay i686 build forward by itself, and
    // libsolv's same-name multi-install check then collided it with the
    // still-locked base x86_64 build ("cannot install both
    // libcap-ng-0:0.9.5... and libcap-ng-0:0.9.3...").
    for &id in &installed_solvables {
        if packages
            .get(&id)
            .is_some_and(|p| base_names.contains(p.nevra.name.as_str()))
        {
            base_solvables.insert(id);
        }
    }
    installed_solvables.extend(&base_solvables);
    pool.set_installed(&system_repo);

    // The core Split-mode rule: a name+arch the base image already ships is
    // satisfied *only* by the locked base copy, never by a same-name+arch
    // candidate installed fresh into the overlay. The version-constraint
    // relaxation for `base_names` above (add_filtered) only affects whether a
    // requirement is *satisfied*. It doesn't stop libsolv from installing a
    // newer same-name+arch candidate anyway when something else in a big
    // transitive closure needs a NEVRA the relaxed, unversioned require can't
    // steer it away from. Seen with `vez install stellarium`: it pulled fresh
    // overlay copies of qt6-qtbase/-gui/-svg/-declarative/qt6ct (all on base,
    // all SOLVER_LOCKed at their base EVR) at a newer version that *another*
    // new package (e.g. qt6-qtcharts) was built against, instead of using the
    // installed, locked base copies. A different arch of the same name (e.g.
    // libcap-ng.i686 for Steam's 32-bit stack when only libcap-ng.x86_64 is
    // on base) isn't affected: that exact (name, arch) isn't on base, so it's
    // still a valid overlay candidate.
    let base_name_arch: HashSet<(&str, &str)> = base
        .iter()
        .map(|p| (p.nevra.name.as_str(), p.nevra.arch.as_str()))
        .collect();

    let available_for_pool: Vec<Package> = available
        .iter()
        .filter(|pkg| !base_name_arch.contains(&(pkg.nevra.name.as_str(), pkg.nevra.arch.as_str())))
        .filter(|pkg| {
            if locks.is_empty() {
                return true;
            }
            match locks.iter().find(|l| l.name == pkg.nevra.name) {
                Some(lock) => lock.allows(&pkg.nevra.evr(), &pkg.nevra.arch),
                None => true,
            }
        })
        .cloned()
        .collect();

    let mut available_repo = pool.create_repo("available")?;
    // A *separate* set from `added_nevra` above on purpose. An `available`
    // candidate that exactly matches an installed NEVRA is the normal case
    // for a pinned reinstall job (`resolve_pinned`), and it has to stay a
    // distinct solvable so the pinned-install job can target it apart from
    // the stale installed copy. The explicit erase-old-id handling in the
    // `pinned_installs` loop in `solve()` is what prevents the "cannot
    // install both X-EVR and X-EVR" conflict. Collapsing them here instead
    // silently turned every same-EVR reinstall into a no-op, including the
    // `--downloadonly` cache priming for a forced re-cache, which
    // needs a real `to_install` entry to know what to download.
    let mut available_nevra: HashSet<String> = HashSet::new();
    let mut discard_suppressed_available: Vec<Package> = Vec::new();
    add_filtered(
        &mut available_repo,
        &mut pool,
        &mut packages,
        &available_for_pool,
        None,
        &mut available_nevra,
        false,
        &mut discard_suppressed_available,
    );

    pool.createwhatprovides();

    Ok(PoolBuild {
        pool,
        host_arch: host_arch.to_string(),
        system_repo,
        available_repo,
        base_solvables,
        installed_solvables,
        packages,
        suppressed_installed,
    })
}

/// What to change, in vez's terms (package names, as the CLI takes them).
/// [`solve`] turns it into libsolv `Job`s.
pub struct SolveRequest {
    /// `(name, arch)`. `arch` is `Some` when the caller disambiguated with
    /// `name.arch` (rpm's syntax) and that arch exists in the pool. Then
    /// `solve` targets that exact solvable instead of a bare name/provides
    /// match, so e.g. `mesa-dri-drivers.i686` still installs the i686 build
    /// even though the installed x86_64 build would make a plain by-name job
    /// see the request as already satisfied and do nothing. This was reported
    /// from the explicit multilib pre-bake step in `build.sh`.
    pub install_names: Vec<(String, Option<String>)>,
    pub erase_names: Vec<String>,
    /// dnf's `installonlypkgs=`: package names exempt from the implicit
    /// same-name obsoletes rule, so e.g. a new kernel installs next to the
    /// running one instead of upgrading it in place. Same as dnf5's
    /// `GoalPrivate::construct_job` (`SOLVER_MULTIVERSION |
    /// SOLVER_SOLVABLE_PROVIDES` per name).
    pub installonly_names: Vec<String>,
    /// dnf's protected-packages list (kernel, glibc, dnf itself, ...). Same
    /// as dnf5's `add_protected_packages` (`SOLVER_USERINSTALLED |
    /// SOLVER_SOLVABLE`): every installed solvable with one of these names is
    /// marked user-installed so libsolv's erasure/obsolete/conflict
    /// resolution never proposes removing it.
    pub protected_names: Vec<String>,
    /// dnf5's `add_upgrade`: named packages to move to their newest available
    /// EVR, or every installed package if `upgrade_all` is set and this is
    /// empty (`vez upgrade` with no args / `vez system-upgrade`). Unlike
    /// `install_names`, this only moves an *installed* package forward. A
    /// name with nothing newer is left alone instead of being an error,
    /// matching `SOLVER_UPDATE` (a no-op when already at the best EVR).
    pub upgrade_names: Vec<String>,
    pub upgrade_all: bool,
    /// dnf5's `add_distro_sync`: named packages (or every installed package
    /// if `distro_sync_all` is set and this is empty) are made to match what
    /// the enabled repos offer now, downgrades included. That's
    /// `SOLVER_DISTUPGRADE`, which syncs in either direction where
    /// `SOLVER_UPDATE` only prefers newer.
    pub distro_sync_names: Vec<String>,
    pub distro_sync_all: bool,
    /// dnf5's `add_downgrade`/`add_reinstall`: an exact target NEVRA (name,
    /// version, release, arch) the caller already chose, installed with a
    /// single-solvable `SOLVER_SOLVABLE | SOLVER_INSTALL` job.
    /// `install_names` uses `SOLVER_SOLVABLE_ONE_OF`, which lets the solver's
    /// policy pick among several candidates; this pins the job to the one
    /// solvable the caller picked. `sync_packages` in vez-cli already does
    /// the EVR selection for downgrade/reinstall, and this just gets that
    /// choice past libsolv's "already satisfied" no-op without deciding it
    /// again here.
    pub pinned_installs: Vec<(String, String, String, String)>,
    /// dnf5's `allow_uninstall_all_but_protected`: when set, libsolv's
    /// dependency resolution may erase installed packages (other than
    /// `protected_names` and base-locked solvables) to satisfy a conflict or
    /// a Requires that would otherwise make the transaction unsolvable
    /// (`SOLVER_ALLOWUNINSTALL` per installed solvable). Without it, libsolv
    /// treats every installed package as protected from removal, so a
    /// conflicting install/upgrade just fails as unsolvable instead of
    /// proposing an erasure (dnf's behavior without `--allowerasing`).
    pub allow_erasing: bool,
    /// dnf5's `multilib_policy=all` (the default is `best`, which is `false`
    /// here). For a bare `install_names` entry without an explicit `.arch`,
    /// split the candidates into one job per arch present (the
    /// `na_map`-grouped `add_install` calls in `libdnf5/base/goal.cpp`) so
    /// e.g. both `foo.x86_64` and `foo.i686` install side by side, instead of
    /// the default single `SOLVER_SOLVABLE_ONE_OF` job where the solver's
    /// policy picks one.
    pub multilib_all: bool,
    /// dnf5's `best=`: the newest available EVR has to resolve cleanly,
    /// without silently falling back to an older one that does.
    /// `SOLVER_FORCEBEST`, applied to every install/upgrade/distro-sync job
    /// (dnf5's `GoalPrivate::add_install` /`add_upgrade`/`add_distro_sync` in
    /// `libdnf5/rpm/solv/goal_private.hpp`, lines 319-370, all OR in `best ?
    /// SOLVER_FORCEBEST : 0`).
    pub best: bool,
    /// dnf5's `obsoletes=` (default `true`): when nothing is named after a
    /// requested install name and nothing `Provides` it, also search packages
    /// that `Obsoletes` it; see the fallback in the `install_names` loop
    /// below. The hand-written `Default` below sets this `true` to match
    /// dnf5's default.
    pub obsoletes: bool,
    /// dnf5's `allow_downgrade=`/`--allow-downgrade`/`--no-allow-downgrade`
    /// (default `true`): whether this request may pick an available EVR older
    /// than the installed one. Covers both a pinned-NEVRA request naming an
    /// older build and any dependency the solver would have to downgrade to
    /// satisfy a conflict. `SOLVER_FLAG_ALLOW_DOWNGRADE`.
    pub allow_downgrade: bool,
    /// dnf's `install_weak_deps=` (default `true`): whether libsolv's
    /// internal `Recommends`/`Suggests` pulls run at all for this solve,
    /// through `SOLVER_FLAG_IGNORE_RECOMMENDED` (inverted: `false` here sets
    /// the flag to `1`, i.e. ignore). This used to be always on whatever
    /// `vez_resolver::ResolveOptions::install_weak_deps` said, so turning
    /// weak deps off (`--no-recommends`, or `install_weak_deps=False` in
    /// `vez.conf`) didn't affect libsolv's own pulls.
    pub install_weak_deps: bool,
    /// Package names to push libsolv's choice away from whenever it has one
    /// (`SOLVER_DISFAVOR | SOLVER_SOLVABLE_NAME`). See the comment at the
    /// `disfavor_names` loop in [`solve`] for the bug this fixes
    /// (floorp/opera-beta bundling soname providers). `vez_resolver` computes
    /// the list from the candidate pool; nothing is hardcoded here.
    pub disfavor_names: Vec<String>,
}

impl Default for SolveRequest {
    fn default() -> Self {
        Self {
            install_names: Vec::new(),
            erase_names: Vec::new(),
            installonly_names: Vec::new(),
            protected_names: Vec::new(),
            upgrade_names: Vec::new(),
            upgrade_all: false,
            distro_sync_names: Vec::new(),
            distro_sync_all: false,
            pinned_installs: Vec::new(),
            allow_erasing: false,
            multilib_all: false,
            best: false,
            obsoletes: true,
            allow_downgrade: true,
            install_weak_deps: true,
            disfavor_names: Vec::new(),
        }
    }
}

/// Result of a successful solve: the transaction's steps, classified and
/// mapped back to `vez_core::Package` through `PoolBuild::packages`. It has
/// the shape `vez_resolver::Plan` needs without depending on that crate,
/// which keeps `vez-solv` a leaf FFI crate.
#[derive(Default, Debug)]
pub struct SolveResult {
    pub to_install: Vec<Package>,
    pub to_erase: Vec<Package>,
    pub to_upgrade: Vec<Package>,
    pub to_obsolete: Vec<Package>,
    /// Requested names that resolved to nothing in the enabled repos but were
    /// already on the base image or overlay. Treated as a no-op instead of a
    /// hard failure. See the comment at the `candidates.is_empty()` check in
    /// [`solve`].
    pub already_installed: Vec<String>,
}

/// Runs one full job through libsolv and classifies the resulting
/// transaction. Every `base.base_solvables` id is `SOLVER_LOCK`ed before
/// solving, so libsolv's conflict/erase resolution can never pick one for
/// removal or replacement. That's the one hard requirement of Svara Split
/// mode: base-image packages are read-only and must come through any overlay
/// transaction unchanged.
///
/// The policy settings (installonly, protected names, allow-erasing, weak
/// deps, best, multilib, downgrades, disfavored names) all come in through
/// `req`.
pub fn solve(build: &mut PoolBuild, req: &SolveRequest) -> Result<SolveResult> {
    let mut job = unsafe {
        let mut q: sys::Queue = std::mem::zeroed();
        sys::queue_init(&mut q);
        q
    };

    // Same approach as dnf5's `GoalPrivate::add_install`
    // (libdnf5/rpm/solv/goal_private.hpp): resolve the spec ourselves into
    // every matching solvable id first (all versions, all repos, filtered to
    // one arch when the caller used `name.arch`), then push one
    // SOLVER_SOLVABLE_ONE_OF job over that id set. ONE_OF asks libsolv to
    // install exactly one of the given solvables, with the solver's policy
    // (FOCUS_NEW/BEST_OBEY_POLICY, set below) picking the best one, and
    // SETARCH/SETEVR keep dependency resolution tied to whichever one it
    // picks instead of treating the job as an open name/provides search.
    //
    // This replaces an earlier pair of hand-built jobs (an exact-solvable
    // SOLVER_INSTALL plus a by-name SOLVER_UPDATE). They were added to fix a
    // real bug where `mesa-vulkan-drivers.i686` didn't sync an older
    // installed x86_64 sibling build, causing an rpm file conflict. But the
    // extra SOLVER_UPDATE job caused a *different* bug: it pulled in an
    // unrelated cluster of qemu/xen/QAT packages that were never installed or
    // requested. dnf5 needs no extra job for the sibling-arch sync:
    // ONE_OF+SETARCH+SETEVR alone gives the same behavior (checked: dnf5's
    // output for the same request also lists the x86_64 sibling under
    // "Upgrading" with only this job shape), so the extra job was dropped.
    //
    // Every by-name lookup in this function (requested names, pinned NEVRAs,
    // suppressed-arch migrations) used to scan all of `build.packages`, the
    // whole pool, per name; a 500-package pinned reinstall came to about 10^8
    // entry visits. Now names are indexed once. Ids are pushed in the
    // iteration order of `build.packages`, so every "first match" below picks
    // the same thing the old scans did.
    let mut ids_by_name: HashMap<&str, Vec<sys::Id>> = HashMap::new();
    for (&id, p) in &build.packages {
        ids_by_name
            .entry(p.nevra.name.as_str())
            .or_default()
            .push(id);
    }
    let ids_named =
        |name: &str| -> &[sys::Id] { ids_by_name.get(name).map(Vec::as_slice).unwrap_or(&[]) };
    // Only depends on what's installed, so it's built once instead of once
    // per requested name.
    let installed_nevra: HashSet<(&str, &str, String)> = build
        .installed_solvables
        .iter()
        .filter_map(|id| build.packages.get(id))
        .map(|p| (p.nevra.name.as_str(), p.nevra.arch.as_str(), p.nevra.evr()))
        .collect();

    let mut already_installed_names: Vec<String> = Vec::new();
    for (name, arch) in &req.install_names {
        let name_id = build.pool.str2id(name, false);
        let mut candidates: Vec<sys::Id> = if name_id == 0 {
            Vec::new()
        } else {
            ids_named(name)
                .iter()
                .copied()
                .filter(|id| {
                    arch.as_deref()
                        .is_none_or(|a| build.packages[id].nevra.arch == a)
                })
                .collect()
        };
        if candidates.is_empty() {
            // No package is literally named `name`, so treat it as a
            // capability, as dnf/dnf5 do for `dnf install <provides>` (e.g.
            // `webserver`, or a soname like `libfoo.so.1(ABI)()`): ask
            // libsolv's provides index for every solvable with a matching
            // `Provides:` entry. This is also what lets a normal `dnf
            // install`-style request reach packages that are only known by a
            // virtual or alias name. The literal-name match runs first
            // because it's the common case, it's faster, and an exact name
            // should win over a same-named Provides on some other package.
            if name_id != 0 {
                unsafe {
                    let mut ptr = sys::pool_whatprovides_ptr(build.pool.as_raw(), name_id);
                    while *ptr != 0 {
                        let id = *ptr;
                        if build
                            .packages
                            .get(&id)
                            .is_some_and(|p| arch.as_deref().is_none_or(|a| p.nevra.arch == a))
                        {
                            candidates.push(id);
                        }
                        ptr = ptr.add(1);
                    }
                }
            }
        }
        // dnf5's "binaries" fallback (`PackageQuery::resolve_pkg_spec`,
        // `libdnf5/rpm/package_query.cpp`): when `name` isn't a package name
        // or a Provides and doesn't look like a file path, try it as a
        // command name by matching `/usr/bin/<name>` and `/usr/sbin/<name>`
        // against the provides index. `createrepo_c` puts a subset of file
        // ownership (executables under bin/sbin, plus /etc) into primary.xml
        // so this resolves without the much larger filelists.xml.
        // `vez-repo`'s primary.xml parser already turns each such `<file>`
        // entry into an unversioned Provides on that path (see its `"file"`
        // case), so the same `pool_whatprovides` lookup as the Provides
        // fallback above covers it. Without this, `vez install ...
        // pipewire-pulse ...` failed with "nothing provides
        // 'pipewire-pulse'". Fedora has no package or Provides named
        // `pipewire-pulse`, only a `/usr/bin/pipewire-pulse` binary in the
        // `pipewire-pulseaudio` package (checked against real dnf5/rpm on
        // stock Fedora 44), which is what dnf5's binaries fallback finds.
        if candidates.is_empty() && !name.contains('/') {
            for prefix in ["/usr/bin/", "/usr/sbin/"] {
                let binary_path = format!("{prefix}{name}");
                let binary_id = build.pool.str2id(&binary_path, false);
                if binary_id == 0 {
                    continue;
                }
                unsafe {
                    let mut ptr = sys::pool_whatprovides_ptr(build.pool.as_raw(), binary_id);
                    while *ptr != 0 {
                        let id = *ptr;
                        if build
                            .packages
                            .get(&id)
                            .is_some_and(|p| arch.as_deref().is_none_or(|a| p.nevra.arch == a))
                        {
                            candidates.push(id);
                        }
                        ptr = ptr.add(1);
                    }
                }
                if !candidates.is_empty() {
                    break;
                }
            }
        }
        // dnf5's `obsoletes=` (default `true`): when nothing is named or
        // provides `name` (e.g. it was renamed or replaced in the repos),
        // also consider any available package whose `Obsoletes:` covers
        // `name`, like `add_obsoletes_to_data`
        // (`libdnf5/base/goal.cpp:1527-1594`). That way `dnf install
        // <old-name>` resolves to its replacement instead of failing. `false`
        // keeps vez's older, stricter behavior (literal name/provides only).
        if candidates.is_empty() && req.obsoletes {
            for (&id, p) in &build.packages {
                if !arch.as_deref().is_none_or(|a| p.nevra.arch == a) {
                    continue;
                }
                if p.obsoletes.iter().any(|d| d.name == *name) {
                    candidates.push(id);
                }
            }
        }
        // dnf5's plain `install` no-op case. When the exact NEVRA a name,
        // provides, or binary spec would resolve to is already installed
        // (base or overlay), drop the *available*-repo duplicate solvable for
        // that NEVRA from the candidates before the ONE_OF job below.
        // Otherwise `candidates` holds both the installed solvable id and a
        // separate "available" solvable id with the identical NEVRA
        // (`available_nevra` is kept separate from installed on purpose; see
        // the `available_repo` comment above, pinned reinstalls need it).
        // ONE_OF/FORCEBEST could then pick the *available* twin over the
        // installed one just because it's a different solvable id, even
        // though the NEVRA is byte-for-byte the same, and libsolv reports
        // that as a real `SOLVER_TRANSACTION_REINSTALL` step. That step
        // reaches `rpm -Uvh`/`-ivh` without `--replacepkgs`, rpm rejects it
        // with "package ... is already installed" (exit 3), and the whole
        // transaction aborts after packages have been downloaded. Seen with
        // `vez install cloudflare-warp` pulling in
        // `adoptium-temurin-java-repository`, installed at the exact version
        // the repos still offer, as a spurious reinstall that then failed to
        // apply. Newer or older candidates for the same name aren't touched;
        // only an exact NEVRA match against something installed is dropped,
        // so a real upgrade still resolves normally.
        candidates.retain(|id| {
            if build.installed_solvables.contains(id) {
                return true;
            }
            match build.packages.get(id) {
                Some(p) => !installed_nevra.contains(&(
                    p.nevra.name.as_str(),
                    p.nevra.arch.as_str(),
                    p.nevra.evr(),
                )),
                None => true,
            }
        });

        if candidates.is_empty() {
            // Svara Split mode: a requested name can already be in the base
            // image's rpmdb (or installed in the overlay) and still not
            // resolve through the enabled repos right now (renamed or dropped
            // upstream, a repo temporarily missing it, a base image built
            // from a mirror that has since rotated, etc.). For the caller
            // that isn't a failure, since what they asked for is already
            // there, so treat it as satisfied and move on instead of failing
            // the whole transaction over one name. dnf5 also treats `install`
            // of something already present as a no-op. Without this, `vez
            // install ... pipewire-pulse ...` failed with "nothing provides
            // 'pipewire-pulse'" and aborted a whole multi-package session
            // install even though pipewire-pulse was already on the base
            // image.
            let already_installed = build.installed_solvables.iter().any(|id| {
                build.packages.get(id).is_some_and(|p| {
                    arch.as_deref().is_none_or(|a| p.nevra.arch == a)
                        && (p.nevra.name == *name || p.provides.iter().any(|d| d.name == *name))
                })
            });
            if already_installed {
                already_installed_names.push(name.clone());
                continue;
            }
            match arch {
                Some(arch) => anyhow::bail!("nothing provides '{name}.{arch}'"),
                None => anyhow::bail!("nothing provides '{name}'"),
            }
        }
        // dnf5's `multilib_policy=` (`libdnf5/base/goal.cpp:1559-1640`).
        // `best` (the default) issues one `SOLVER_SOLVABLE_ONE_OF` job over
        // every arch build of `name` and lets the solver's policy pick one;
        // that's the branch below with a single `push_one_of` call. `all`
        // issues one *separate* job per arch present, so a plain `dnf install
        // foo` with both `foo.x86_64` and `foo.i686` available installs both
        // side by side. That only happens when the caller didn't already give
        // an explicit `name.arch`, matching dnf5's
        // `!utils::is_glob_pattern(arch)` guard.
        let mut by_arch: HashMap<&str, Vec<sys::Id>> = HashMap::new();
        for &id in &candidates {
            if let Some(p) = build.packages.get(&id) {
                by_arch.entry(p.nevra.arch.as_str()).or_default().push(id);
            }
        }
        let mut push_one_of = |job: &mut sys::Queue, ids: &[sys::Id]| {
            let mut queue = unsafe {
                let mut q: sys::Queue = std::mem::zeroed();
                sys::queue_init(&mut q);
                q
            };
            for &id in ids {
                unsafe { sys::queue_push(&mut queue, id) };
            }
            let what = unsafe { sys::pool_queuetowhatprovides(build.pool.as_raw(), &mut queue) };
            unsafe { sys::queue_free(&mut queue) };
            let mut flags = sys::SOLVER_INSTALL
                | sys::SOLVER_SOLVABLE_ONE_OF
                | sys::SOLVER_SETARCH
                | sys::SOLVER_SETEVR;
            if req.best {
                flags |= sys::SOLVER_FORCEBEST;
            }
            unsafe { sys::queue_push2(job, flags as sys::Id, what) };
        };
        if req.multilib_all && arch.is_none() && by_arch.len() > 1 {
            for ids in by_arch.values() {
                push_one_of(&mut job, ids);
            }
        } else {
            push_one_of(&mut job, &candidates);
        }
    }
    // Same as the "autodetect" pass in dnf5's
    // `Goal::Impl::set_exclude_from_weak` (libdnf5/base/goal.cpp): for every
    // installed package, look at its Recommends. If nothing *installed*
    // already provides a given recommend, exclude every candidate that could
    // satisfy it from being pulled in as a weak dependency in this solve.
    // libsolv's weak-dep handling for upgraded packages has no such guard
    // (SOLVER_FLAG_ADD_ALREADY_RECOMMENDED only suppresses recommends from
    // solvables whose *exact* id doesn't change in this transaction, not ones
    // upgraded in place). Without it, a package recommended by e.g.
    // systemd-container (never installed, never requested) got pulled in just
    // because systemd-container was upgraded as a side effect of an unrelated
    // request. Confirmed as the root cause of the qemu/xen/QAT cluster bug;
    // the job type wasn't.
    //
    // The index maps capabilities to providers (own name + every `Provides`
    // entry, like dnf5's `query.filter_provides(reldep_list)`) instead of
    // matching bare names. A `Recommends` target is a capability, so matching
    // it by package name misses virtual-provide recommends (and in the
    // by-name provider lookup below could skip or include the wrong package
    // that happens to share the name). vez-resolver's `CandidateIndex` does
    // the same for the same reason.
    let mut by_capability: HashMap<&str, Vec<sys::Id>> = HashMap::new();
    for (&id, pkg) in &build.packages {
        by_capability
            .entry(pkg.nevra.name.as_str())
            .or_default()
            .push(id);
        for p in &pkg.provides {
            by_capability.entry(p.name.as_str()).or_default().push(id);
        }
    }
    let installed_capabilities: HashSet<&str> = build
        .installed_solvables
        .iter()
        .filter_map(|id| build.packages.get(id))
        .flat_map(|p| {
            std::iter::once(p.nevra.name.as_str()).chain(p.provides.iter().map(|d| d.name.as_str()))
        })
        .collect();
    let mut excluded_from_weak: HashSet<String> = HashSet::new();
    for &id in &build.installed_solvables {
        let Some(pkg) = build.packages.get(&id) else {
            continue;
        };
        for rec in &pkg.recommends {
            if installed_capabilities.contains(rec.name.as_str())
                || !excluded_from_weak.insert(rec.name.clone())
            {
                continue;
            }
            for &cand_id in by_capability
                .get(rec.name.as_str())
                .map(|v| v.as_slice())
                .unwrap_or(&[])
            {
                unsafe {
                    sys::queue_push2(
                        &mut job,
                        (sys::SOLVER_SOLVABLE | sys::SOLVER_EXCLUDEFROMWEAK) as sys::Id,
                        cand_id,
                    )
                };
            }
        }
    }

    // Recommends: when choosing which providers may satisfy a capability
    // through a weak (Recommends) dependency, prefer the capability's own
    // exact-name package (if the pool has one) over other packages that only
    // `Provides` it under a different name. That's the dnf/rpm convention
    // (see the `b_exact.cmp(&a_exact)` tie-break in `matching_providers_raw`
    // for hard `Requires` in vez-resolver), applied to the weak-dep
    // resolution only libsolv does, which has no such preference built in. It
    // applies to every package's Recommends on purpose, not only installed
    // ones like the qemu/xen/QAT `excluded_from_weak` pass above: a freshly
    // requested install's own Recommends (e.g. `patool`, pulled in for
    // `bottles`) hits the same ambiguity, and by the time it's "installed"
    // the wrong package has already won. Seen with `bottles` pulling in
    // Svara's custom `mkisofs` package (`Provides: genisoimage`, kept so
    // unrelated `Requires: genisoimage` still resolve whichever
    // cdrtools-family implementation is installed) instead of the real
    // `genisoimage` package to satisfy patool's `Recommends:
    // .../genisoimage`. `mkisofs`'s `schily-libs` dependency then
    // file-conflicts with `star`/`star-libs`, pulled in for another of
    // patool's recommends, a combination stock Fedora (which has no custom
    // `mkisofs` package) never produces. Only the non-exact-name alternatives
    // are excluded, and only from *weak* resolution (SOLVER_EXCLUDEFROMWEAK),
    // so a package with a hard `Requires` on the same capability isn't
    // affected.
    let mut recommend_targets: HashSet<&str> = HashSet::new();
    for pkg in build.packages.values() {
        for rec in &pkg.recommends {
            recommend_targets.insert(rec.name.as_str());
        }
    }
    for name in recommend_targets {
        let providers = by_capability.get(name).map(|v| v.as_slice()).unwrap_or(&[]);
        if providers.len() < 2 {
            continue;
        }
        let has_exact = providers.iter().any(|&id| {
            build
                .packages
                .get(&id)
                .is_some_and(|p| p.nevra.name == name)
        });
        if !has_exact {
            continue;
        }
        for &id in providers {
            if build
                .packages
                .get(&id)
                .is_some_and(|p| p.nevra.name != name)
            {
                unsafe {
                    sys::queue_push2(
                        &mut job,
                        (sys::SOLVER_SOLVABLE | sys::SOLVER_EXCLUDEFROMWEAK) as sys::Id,
                        id,
                    )
                };
            }
        }
    }

    // Same as dnf5's `GoalPrivate::add_remove`: works on resolved *installed*
    // solvable ids (plain SOLVER_SOLVABLE, no name/provides selector). dnf5
    // never lets libsolv search for what to erase; it's always something the
    // caller already knows is installed.
    for name in &req.erase_names {
        let ids: Vec<sys::Id> = build
            .installed_solvables
            .iter()
            .filter(|id| {
                build
                    .packages
                    .get(id)
                    .is_some_and(|p| p.nevra.name == *name)
            })
            .copied()
            .collect();
        anyhow::ensure!(!ids.is_empty(), "nothing provides '{name}'");
        for id in ids {
            unsafe {
                sys::queue_push2(
                    &mut job,
                    (sys::SOLVER_ERASE | sys::SOLVER_SOLVABLE) as sys::Id,
                    id,
                )
            };
        }
    }
    // Same as the installonly handling in dnf5's
    // `GoalPrivate::construct_job`: a by-provides job instead of a
    // precomputed candidate list, so it also covers future/available builds
    // of the name and not only what's installed now.
    for name in &req.installonly_names {
        let name_id = build.pool.str2id(name, false);
        if name_id != 0 {
            unsafe {
                sys::queue_push2(
                    &mut job,
                    (sys::SOLVER_MULTIVERSION | sys::SOLVER_SOLVABLE_PROVIDES) as sys::Id,
                    name_id,
                )
            };
        }
    }
    // `vez_resolver`'s soname-provider heuristic (see
    // `looks_like_real_lib_provider` there). When an auto-generated soname
    // capability (`libfoo.so.N()(64bit)`) can be satisfied both by a small
    // dedicated library package and by an unrelated large application that
    // bundles a private copy of the same soname (seen with
    // `opera-beta`/`floorp` bundling `libvulkan.so.1`/`libavcodec.so.62`),
    // libsolv's policy for choosing among equally "cheap" alternatives can
    // pick the application and drag a whole unrelated browser into a
    // transaction that only asked for a codec lib or a gstreamer plugin.
    // `SOLVER_DISFAVOR` pushes libsolv away from these names pool-wide
    // whenever it has a choice, without excluding them. `vez install
    // opera-beta` (an explicit by-name job elsewhere in this queue) isn't
    // affected.
    for name in &req.disfavor_names {
        let name_id = build.pool.str2id(name, false);
        if name_id != 0 {
            unsafe {
                sys::queue_push2(
                    &mut job,
                    (sys::SOLVER_DISFAVOR | sys::SOLVER_SOLVABLE_NAME) as sys::Id,
                    name_id,
                )
            };
        }
    }
    // Same as dnf5's `add_protected_packages`: mark every installed solvable
    // with a protected name as user-installed so libsolv's
    // erasure/obsolete/conflict resolution never proposes removing it. That
    // enforces it in the solver, where dnf5 does it, and not only as an
    // app-level check on explicit `vez remove`.
    //
    // `SOLVER_USERINSTALLED` alone turned out not to prevent erasure under an
    // `upgrade`/`distro-sync` job (`SOLVER_UPDATE`/`SOLVER_DISTUPGRADE`),
    // even with the solvable excluded from every `SOLVER_ALLOWUNINSTALL` job
    // below: testing a protected package under `vez upgrade --allowerasing`
    // still erased it. `SOLVER_LOCK` is the hard constraint (it forbids *any*
    // state change, not just erasure). That's stricter than dnf5's
    // erasure-only protection, but it's the safe side to err on for a package
    // an admin marked untouchable.
    for name in &req.protected_names {
        for &id in &build.installed_solvables {
            if build
                .packages
                .get(&id)
                .is_some_and(|p| p.nevra.name == *name)
            {
                unsafe {
                    sys::queue_push2(
                        &mut job,
                        (sys::SOLVER_USERINSTALLED | sys::SOLVER_SOLVABLE) as sys::Id,
                        id,
                    );
                    sys::queue_push2(
                        &mut job,
                        (sys::SOLVER_LOCK | sys::SOLVER_SOLVABLE) as sys::Id,
                        id,
                    );
                }
            }
        }
    }
    // SOLVER_WEAK is a safety net. The actual fix is in `build_pool_locked`,
    // which strips version constraints from any `Requires` that targets a
    // base-only package name so the locked base copy satisfies it directly
    // (no shadow install, no skip). This flag only prevents a total solve
    // failure when some other constraint (e.g. a `Conflicts`, which that
    // relaxation doesn't cover) still makes a name's upgrade impossible
    // without touching a locked base solvable. That one name is dropped
    // instead of failing everything.
    let update_flags =
        sys::SOLVER_UPDATE | sys::SOLVER_WEAK | if req.best { sys::SOLVER_FORCEBEST } else { 0 };
    let distupgrade_flags = sys::SOLVER_DISTUPGRADE
        | sys::SOLVER_WEAK
        | if req.best { sys::SOLVER_FORCEBEST } else { 0 };
    for name in &req.upgrade_names {
        let name_id = build.pool.str2id(name, false);
        if name_id != 0 {
            unsafe {
                sys::queue_push2(
                    &mut job,
                    (update_flags | sys::SOLVER_SOLVABLE_PROVIDES) as sys::Id,
                    name_id,
                )
            };
        }
    }
    if req.upgrade_all && req.upgrade_names.is_empty() {
        unsafe {
            sys::queue_push2(
                &mut job,
                (update_flags | sys::SOLVER_SOLVABLE_ALL) as sys::Id,
                0,
            )
        };
    }
    for name in &req.distro_sync_names {
        let name_id = build.pool.str2id(name, false);
        if name_id != 0 {
            unsafe {
                sys::queue_push2(
                    &mut job,
                    (distupgrade_flags | sys::SOLVER_SOLVABLE_PROVIDES) as sys::Id,
                    name_id,
                )
            };
        }
    }
    if req.distro_sync_all && req.distro_sync_names.is_empty() {
        unsafe {
            sys::queue_push2(
                &mut job,
                (distupgrade_flags | sys::SOLVER_SOLVABLE_ALL) as sys::Id,
                0,
            )
        };
    }
    // Migrate off a stale foreign-arch install the arch-clobber guard now
    // suppresses (`build.suppressed_installed`; see its doc comment on
    // `PoolBuild`). These packages are installed but have no solvable id, so
    // libsolv can never propose erasing them. A plain `vez upgrade`/`vez
    // system-upgrade` would leave them on disk untouched and never upgraded,
    // the same "stuck on the old 32-bit copy" case the `pinned_installs`
    // fallback above handles for a soft reset's reinstall pass. Only done for
    // an upgrade/distro-sync job that targets this name (or an `_all` job); a
    // plain `vez install somethingelse` shouldn't start erasing unrelated
    // packages as a side effect.
    let mut foreign_migrations: Vec<Package> = Vec::new();
    for pkg in &build.suppressed_installed {
        let name = pkg.nevra.name.as_str();
        let targeted = req.upgrade_all
            || req.distro_sync_all
            || req.upgrade_names.iter().any(|n| n == name)
            || req.distro_sync_names.iter().any(|n| n == name);
        if !targeted {
            continue;
        }
        let host_id = ids_named(&pkg.nevra.name)
            .iter()
            .copied()
            .find(|id| build.packages[id].nevra.arch == build.host_arch);
        match host_id {
            Some(id) if !build.installed_solvables.contains(&id) => {
                unsafe {
                    sys::queue_push2(
                        &mut job,
                        (sys::SOLVER_INSTALL | sys::SOLVER_SOLVABLE) as sys::Id,
                        id,
                    )
                };
                foreign_migrations.push(pkg.clone());
            }
            Some(_) => {
                // The host-arch build is already installed, so there's
                // nothing to install; just drop the stale foreign-arch
                // leftover.
                foreign_migrations.push(pkg.clone());
            }
            None => {
                // No host-arch build anywhere (base/overlay/repos) either.
                // There's nothing sensible to migrate to, so leave the
                // foreign build alone instead of erasing it with no
                // replacement.
            }
        }
    }
    // 32-bit x86 arches. Their exact-NEVRA pin may stop resolving when a
    // package the arch-clobber guard now suppresses
    // (`foreign_build_clobbers_host` above, or an upstream repo that dropped
    // the .i686 build) is reinstalled from an old overlay's exact-NEVRA
    // snapshot (the reinstall pass of a forced replay; see the
    // comment on `installed_id` below). A pin that used to resolve can then
    // fail the *entire* soft-reset reinstall over one missing 32-bit package
    // and leave the user with no overlay at all. Instead, fall back to the
    // host-arch build of the same name/version, and if that isn't there
    // either, drop the pin and move on.
    const PINNED_X86_32: &[&str] = &["i386", "i486", "i586", "i686"];
    for (name, version, release, arch) in &req.pinned_installs {
        let matches: Vec<sys::Id> = ids_named(name)
            .iter()
            .copied()
            .filter(|id| {
                let p = &build.packages[id];
                p.nevra.version == *version && p.nevra.release == *release && p.nevra.arch == *arch
            })
            .collect();
        if matches.is_empty() && PINNED_X86_32.contains(&arch.as_str()) {
            let host_arch_matches: Vec<sys::Id> = ids_named(name)
                .iter()
                .copied()
                .filter(|id| build.packages[id].nevra.arch == build.host_arch)
                .collect();
            let already_installed_host_arch = host_arch_matches.iter().any(|id| {
                build.installed_solvables.contains(id) || build.base_solvables.contains(id)
            });
            if already_installed_host_arch {
                // The host-arch build is already present, so the 32-bit copy
                // adds nothing; skip it and continue.
                continue;
            }
            let exact_host_arch = host_arch_matches.iter().copied().find(|id| {
                build
                    .packages
                    .get(id)
                    .is_some_and(|p| p.nevra.version == *version && p.nevra.release == *release)
            });
            if let Some(id) = exact_host_arch.or_else(|| host_arch_matches.first().copied()) {
                unsafe {
                    sys::queue_push2(
                        &mut job,
                        (sys::SOLVER_INSTALL | sys::SOLVER_SOLVABLE) as sys::Id,
                        id,
                    )
                };
            }
            // Neither the exact 32-bit NEVRA nor any host-arch build of this
            // name is in the pool. There's nothing sensible to install, so
            // drop the pin instead of failing the whole reinstall.
            continue;
        }
        anyhow::ensure!(
            !matches.is_empty(),
            "nothing provides '{name}-{version}-{release}.{arch}'"
        );
        // When the exact pinned NEVRA exists as *two* solvables, one
        // installed (base or overlay, in `@System`) and one from `available`
        // (the usual case when reinstalling a package at its current
        // version), target the `available` one and erase the stale installed
        // one first. Without that erase, the old `@System` id can still
        // satisfy some *other* package's `Requires` on this name while the
        // new id is pinned with `SOLVER_INSTALL`, and libsolv rejects two
        // wanted solvables of the same name as "cannot install both X-EVR and
        // X-EVR". That was the crash in the reinstall pass of a forced replay.
        // A bare `.find()` taking whichever id came
        // first left it to chance.
        let installed_id = matches
            .iter()
            .copied()
            .find(|id| build.installed_solvables.contains(id) || build.base_solvables.contains(id));
        // Base solvables are always `SOLVER_LOCK`ed below. If the pinned
        // NEVRA is exactly what base ships, this job can't do anything: it
        // can't erase it, and installing a separate `available` id of the
        // same locked name is the "cannot install both X-EVR and X-EVR"
        // conflict this function is avoiding. Skip the job; the locked base
        // copy already satisfies it. `sync_packages` does the same base-only
        // skip in other cases (see `warn_base_only_names`).
        if installed_id.is_some_and(|id| build.base_solvables.contains(&id)) {
            continue;
        }
        let target_id = matches
            .iter()
            .copied()
            .find(|id| {
                !build.installed_solvables.contains(id) && !build.base_solvables.contains(id)
            })
            .or(installed_id)
            .expect("matches is non-empty");
        if let Some(old_id) = installed_id {
            if old_id != target_id && !build.base_solvables.contains(&old_id) {
                unsafe {
                    sys::queue_push2(
                        &mut job,
                        (sys::SOLVER_ERASE | sys::SOLVER_SOLVABLE) as sys::Id,
                        old_id,
                    )
                };
            }
        }
        unsafe {
            sys::queue_push2(
                &mut job,
                (sys::SOLVER_INSTALL | sys::SOLVER_SOLVABLE) as sys::Id,
                target_id,
            )
        };
    }
    if req.allow_erasing {
        let protected: HashSet<&str> = req.protected_names.iter().map(|s| s.as_str()).collect();
        let base: HashSet<sys::Id> = build.base_solvables.iter().copied().collect();
        for &id in &build.installed_solvables {
            if base.contains(&id) {
                continue;
            }
            if build
                .packages
                .get(&id)
                .is_some_and(|p| protected.contains(p.nevra.name.as_str()))
            {
                continue;
            }
            unsafe {
                sys::queue_push2(
                    &mut job,
                    (sys::SOLVER_ALLOWUNINSTALL | sys::SOLVER_SOLVABLE) as sys::Id,
                    id,
                )
            };
        }
    }
    for &base_id in &build.base_solvables {
        unsafe {
            sys::queue_push2(
                &mut job,
                (sys::SOLVER_LOCK | sys::SOLVER_SOLVABLE) as sys::Id,
                base_id,
            )
        };
    }

    let solver = unsafe { sys::solver_create(build.pool.as_raw()) };
    anyhow::ensure!(!solver.is_null(), "solver_create returned null");

    // Same flag set as dnf5, checked against its source
    // (libdnf5/rpm/solv/goal_private.cpp). An earlier version of this comment
    // listed flags dnf5 doesn't set (ALLOW_ARCHCHANGE, SPLITPROVIDES,
    // FOCUS_BEST, INSTALL_ALSO_UPDATES) and had ALLOW_DOWNGRADE backwards.
    //
    // dnf5's `init_solver()` sets these four on every solve:
    unsafe {
        // Don't remove packages no longer in a repo during distro-sync/dup.
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_KEEP_ORPHANS as i32, 1);
        // No arch change when FORCEBEST is set on a job.
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_BEST_OBEY_POLICY as i32, 1);
        // Support package splits through Obsoletes (dnf's classic obsoletes
        // semantics, not yum's stricter default).
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_YUM_OBSOLETES as i32, 1);
        // Reorders solutions closer to what users expect from urpm/dnf. dnf5
        // guards it with a libsolv version check, but the constant has been
        // stable since libsolv 0.6.6, and every libsolv vez targets (EL10's
        // 0.7.33, Fedora's newer ones) has it.
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_URPM_REORDER as i32, 1);
    }

    // dnf5's `GoalPrivate::resolve()` sets these four from user config
    // (`allow_downgrade`, `allow_vendor_change`, `install_weak_deps` in
    // dnf.conf) on every solve, each on by default. vez doesn't expose all of
    // these as config yet, so on by default gives dnf5's out-of-the-box
    // behavior:
    unsafe {
        // install_weak_deps (default true) → IGNORE_RECOMMENDED=0, i.e. the
        // solver doesn't ignore recommends/suggests. Driven by
        // `req.install_weak_deps` (vez-resolver's `ResolveOptions`, set from
        // `vez.conf`'s `install_weak_deps=`/`--no-recommends`), so turning
        // weak deps off also stops libsolv's internal Recommends/Suggests
        // pulls.
        sys::solver_set_flag(
            solver,
            sys::SOLVER_FLAG_IGNORE_RECOMMENDED as i32,
            if req.install_weak_deps { 0 } else { 1 },
        );
        // allow_downgrade=true by default. dnf5's `--no-allow-downgrade`
        // turns it off for one solve.
        sys::solver_set_flag(
            solver,
            sys::SOLVER_FLAG_ALLOW_DOWNGRADE as i32,
            if req.allow_downgrade { 1 } else { 0 },
        );
        // allow_vendor_change=true by default (both plain and dup variants).
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_ALLOW_VENDORCHANGE as i32, 1);
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_DUP_ALLOW_VENDORCHANGE as i32, 1);
        // Prefer the latest available version of dependencies even if the
        // transaction grows, which is dnf5's default since libsolv 0.7.30
        // (also gated on libsolv version in dnf5's source, but the constant
        // is stable across every libsolv we target).
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_FOCUS_NEW as i32, 1);
        // Force this off explicitly (it should already be libsolv's default):
        // don't re-trigger recommends that were already unsatisfied on a
        // package before this transaction just because that package is being
        // upgraded in place.
        sys::solver_set_flag(solver, sys::SOLVER_FLAG_ADD_ALREADY_RECOMMENDED as i32, 0);
    }

    let problem_count = unsafe { sys::solver_solve(solver, &mut job) };
    if problem_count > 0 {
        let mut problems = Vec::new();
        unsafe {
            let mut problem = sys::solver_next_problem(solver, 0);
            while problem != 0 {
                let cstr = sys::solver_problem2str(solver, problem);
                if !cstr.is_null() {
                    problems.push(
                        std::ffi::CStr::from_ptr(cstr)
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                problem = sys::solver_next_problem(solver, problem);
            }
            sys::solver_free(solver);
            sys::queue_free(&mut job);
        }
        anyhow::bail!("could not resolve: {}", problems.join("; "));
    }

    let trans = unsafe { sys::solver_create_transaction(solver) };
    anyhow::ensure!(!trans.is_null(), "solver_create_transaction returned null");

    let mut result = SolveResult {
        already_installed: already_installed_names,
        ..Default::default()
    };
    unsafe {
        let steps = &(*trans).steps;
        for i in 0..steps.count as isize {
            let p = *steps.elements.offset(i);
            let ty = sys::transaction_type(trans, p, sys::SOLVER_TRANSACTION_SHOW_ACTIVE as i32);
            let Some(pkg) = build.packages.get(&p) else {
                continue;
            };
            match ty as u32 {
                sys::SOLVER_TRANSACTION_INSTALL
                | sys::SOLVER_TRANSACTION_REINSTALL
                | sys::SOLVER_TRANSACTION_MULTIINSTALL => result.to_install.push(pkg.clone()),
                sys::SOLVER_TRANSACTION_ERASE => result.to_erase.push(pkg.clone()),
                sys::SOLVER_TRANSACTION_UPGRADE
                | sys::SOLVER_TRANSACTION_DOWNGRADE
                | sys::SOLVER_TRANSACTION_CHANGE => result.to_upgrade.push(pkg.clone()),
                sys::SOLVER_TRANSACTION_OBSOLETES => result.to_obsolete.push(pkg.clone()),
                _ => {}
            }
        }
        sys::transaction_free(trans);
        sys::solver_free(solver);
        sys::queue_free(&mut job);
    }
    // These never had a solvable id (see the doc comment on
    // `suppressed_installed`), so libsolv's transaction steps above can't
    // include them. Append them here now that we know which ones this
    // upgrade/distro-sync job targeted.
    result.to_erase.extend(foreign_migrations);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vez_core::Nevra;

    fn pkg(name: &str, evr: &str, arch: &str) -> Package {
        Package {
            nevra: Nevra {
                name: name.to_string(),
                epoch: 0,
                version: evr.split('-').next().unwrap().to_string(),
                release: evr.split('-').nth(1).unwrap_or("1").to_string(),
                arch: arch.to_string(),
            },
            summary: String::new(),
            provides: vec![],
            requires: vec![Dependency::unversioned("libfoo.so.1")],
            conflicts: vec![],
            obsoletes: vec![],
            recommends: vec![],
            suggests: vec![],
            enhances: vec![],
            supplements: vec![],
            location: String::new(),
            repo_id: "test".to_string(),
            repo_priority: 99,
            repo_cost: 1000,
            install_size: 0,
            download_size: 0,
            vendor: String::new(),
            checksum_type: String::new(),
            checksum: String::new(),
        }
    }

    fn pkg_providing(name: &str, evr: &str, arch: &str, provides: &str) -> Package {
        let mut p = pkg(name, evr, arch);
        p.requires.clear();
        p.provides.push(Dependency::unversioned(provides));
        p
    }

    #[test]
    fn pool_creates_and_frees_without_crashing() {
        let mut pool = Pool::new().unwrap();
        pool.createwhatprovides();
    }

    #[test]
    fn builds_pool_from_packages() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("vim", "9.0-1", "x86_64")];
        let available = vec![pkg("vim", "9.1-1", "x86_64")];
        let build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        assert_eq!(build.base_solvables.len(), 1);
    }

    #[test]
    fn solves_simple_install() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![];
        let available = vec![pkg("htop", "3.3-1", "x86_64")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();

        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("htop".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(result.to_install.len(), 1);
        assert_eq!(result.to_install[0].nevra.name, "htop");
        assert!(result.to_erase.is_empty());
    }

    #[test]
    fn install_name_falls_back_to_a_provides_match_when_no_literal_name_exists() {
        // dnf-style install by capability: nothing is named `webserver`, but
        // `httpd` Provides it, so a request for the bare capability name
        // should still resolve, like `dnf install webserver`.
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![];
        let available = vec![pkg_providing("httpd", "2.4-1", "x86_64", "webserver")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();

        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("webserver".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(result.to_install.len(), 1);
        assert_eq!(result.to_install[0].nevra.name, "httpd");
    }

    #[test]
    fn install_name_prefers_a_literal_package_name_over_a_same_named_provides() {
        // If a real package is named what was requested, it has to win over
        // an unrelated package that only Provides the same string. The
        // literal-name scan runs first and only falls back to the provides
        // index when it finds nothing.
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![];
        let available = vec![
            pkg("vim", "9.1-1", "x86_64"),
            pkg_providing("vim-enhanced", "9.1-1", "x86_64", "vim"),
        ];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();

        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("vim".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(result.to_install.len(), 1);
        assert_eq!(result.to_install[0].nevra.name, "vim");
    }

    #[test]
    fn split_mode_never_erases_base_packages() {
        // A direct erase request for a base-image package must never appear
        // to succeed and must never erase it. SOLVER_LOCK (applied to every
        // `base_solvables` id in `solve()`) turns an explicit erase job for a
        // locked solvable into a solve failure ("conflicting requests")
        // instead of a silent no-op or an actual removal. That loud failure
        // is right for Svara Split mode, where base packages are read-only.
        let base = vec![pkg("glibc", "2.39-1", "x86_64")];
        let overlay = vec![];
        let available = vec![];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();

        let err = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![],
                erase_names: vec!["glibc".to_string()],
                ..Default::default()
            },
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("conflicting"),
            "expected a solve conflict, got: {err}"
        );
    }

    #[test]
    fn installonly_names_do_not_disturb_a_plain_already_satisfied_install() {
        // `install kernel` with `kernel` installed is a ONE_OF job the
        // installed solvable already satisfies, so it's a no-op, matching
        // dnf5's "install" semantics. Adding the `SOLVER_MULTIVERSION` job
        // for `installonly_names` shouldn't change that: multiversion only
        // disables the same-name-obsoletes rule and doesn't force a new
        // install. In real dnf5, `dnf install kernel` with kernel installed
        // says "already installed" even with installonlypkgs; you have to
        // name an exact NEVRA to add a second version next to it.
        let base = vec![
            pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1"),
            pkg("kernel", "1-1", "x86_64"),
        ];
        let overlay = vec![];
        let available = vec![pkg("kernel", "2-1", "x86_64")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("kernel".to_string(), None)],
                erase_names: vec![],
                installonly_names: vec!["kernel".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert!(result.to_upgrade.is_empty());
        assert!(result.to_install.is_empty());
    }

    #[test]
    fn install_of_an_overlay_package_still_offered_at_the_same_evr_by_a_repo_is_a_no_op() {
        // `vez install cloudflare-warp` also named
        // `adoptium-temurin-java-repository`, already installed in the
        // overlay at exactly the EVR the enabled repo still offers. The
        // `available` solvable for that identical NEVRA is a separate
        // solvable id from the installed one (kept separate on purpose; see
        // the `available_nevra` comment in `build_pool`, pinned reinstalls
        // need it), so a naive ONE_OF job over both ids could pick the
        // "available" twin and libsolv would report a spurious
        // `SOLVER_TRANSACTION_REINSTALL`. That step would reach `rpm
        // -Uvh`/`-ivh` without `--replacepkgs` and fail with "package ... is
        // already installed" after packages were downloaded. The exact-NEVRA
        // dedup in the install_names loop of `solve` has to keep this a real
        // no-op: nothing to install, upgrade, or erase.
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("adoptium-temurin-java-repository", "1-20", "noarch")];
        let available = vec![pkg("adoptium-temurin-java-repository", "1-20", "noarch")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("adoptium-temurin-java-repository".to_string(), None)],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert!(result.to_upgrade.is_empty());
        assert!(result.to_install.is_empty());
    }

    #[test]
    fn upgrade_names_moves_installed_overlay_package_to_newest() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("vim", "9.0-1", "x86_64")];
        let available = vec![pkg("vim", "9.1-1", "x86_64")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_names: vec!["vim".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert_eq!(result.to_upgrade.len(), 1);
        assert_eq!(result.to_upgrade[0].nevra.version, "9.1");
    }

    #[test]
    fn upgrade_all_leaves_base_solvables_untouched() {
        // Split mode's one hard rule: SOLVER_LOCK over base_solvables has to
        // hold even for an "upgrade everything" job. A newer build of a base
        // name in `available` must never replace the locked base copy.
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("vim", "9.0-1", "x86_64")];
        let available = vec![
            pkg("vim", "9.1-1", "x86_64"),
            pkg_providing("glibc", "2.40-1", "x86_64", "libfoo.so.1"),
        ];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_all: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert!(
            result.to_upgrade.iter().all(|p| p.nevra.name != "glibc"),
            "base-locked glibc must never be upgraded, got {:?}",
            result.to_upgrade
        );
        assert!(result
            .to_upgrade
            .iter()
            .any(|p| p.nevra.name == "vim" && p.nevra.version == "9.1"));
    }

    #[test]
    fn upgrade_all_leaves_the_base_vez_package_untouched() {
        // `vez` ships in the base image, and the solver must keep treating it
        // like any other base package: SOLVER_LOCK means a newer `vez` in a
        // repo is never offered here. `vez upgrade` updates `vez` in the CLI,
        // deliberately outside the solver (see `SELF_UPGRADABLE_NAMES`); this
        // test is the guard that the solver's base lock stays put, so nothing
        // else can start moving a base package by accident.
        let base = vec![pkg_providing("vez", "0.1.0-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("htop", "3.3-1", "x86_64")];
        let available = vec![
            pkg("htop", "3.4-1", "x86_64"),
            pkg_providing("vez", "0.1.1-1", "x86_64", "libfoo.so.1"),
        ];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_all: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert!(
            result
                .to_upgrade
                .iter()
                .chain(result.to_install.iter())
                .all(|p| p.nevra.name != "vez"),
            "base-locked vez must never be moved by the solver, got {:?}",
            result.to_upgrade
        );
        assert!(result
            .to_upgrade
            .iter()
            .any(|p| p.nevra.name == "htop" && p.nevra.version == "3.4"));
    }

    #[test]
    fn upgrade_all_satisfies_a_requires_on_a_newer_base_only_package_from_the_installed_base_copy()
    {
        // An overlay package (rpm-devel) whose only available upgrade
        // Requires an exact newer EVR of a package that only exists in the
        // base rpmdb (rpm) used to fail the whole solve with "cannot install
        // both rpm-0:6.1.0... and rpm-0:6.0.2...". Base packages must never
        // move (SOLVER_LOCK) AND must never be shadowed by a same-name
        // overlay copy. So the version pin on rpm-devel's `Requires: rpm`
        // gets relaxed and is satisfied by the installed, untouched base
        // rpm-6.0.2, and rpm-devel's own upgrade to 6.1.0 goes ahead (nothing
        // skipped, nothing shadowed).
        let base = vec![{
            let mut p = pkg("rpm", "6.0.2-1", "x86_64");
            p.requires.clear();
            p
        }];
        let overlay = vec![
            {
                let mut p = pkg("rpm-devel", "6.0.2-1", "x86_64");
                p.requires = vec![Dependency {
                    name: "rpm".to_string(),
                    constraint: Some((Comparator::Eq, "6.0.2-1".to_string())),
                }];
                p
            },
            {
                let mut p = pkg("vim", "9.0-1", "x86_64");
                p.requires.clear();
                p
            },
        ];
        let available = vec![
            {
                let mut p = pkg("rpm-devel", "6.1.0-1", "x86_64");
                p.requires = vec![Dependency {
                    name: "rpm".to_string(),
                    constraint: Some((Comparator::Eq, "6.1.0-1".to_string())),
                }];
                p
            },
            {
                let mut p = pkg("vim", "9.1-1", "x86_64");
                p.requires.clear();
                p
            },
        ];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_all: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert!(
            result.to_install.iter().all(|p| p.nevra.name != "rpm"),
            "rpm must never be shadow-installed into the overlay, got {:?}",
            result.to_install
        );
        assert!(
            result.to_upgrade.iter().all(|p| p.nevra.name != "rpm"),
            "base rpm must never be touched, got {:?}",
            result.to_upgrade
        );
        assert!(
            result
                .to_upgrade
                .iter()
                .any(|p| p.nevra.name == "rpm-devel" && p.nevra.version == "6.1.0"),
            "rpm-devel's upgrade must proceed, satisfied by the base rpm copy, got {:?}",
            result.to_upgrade
        );
        assert!(
            result
                .to_upgrade
                .iter()
                .any(|p| p.nevra.name == "vim" && p.nevra.version == "9.1"),
            "unrelated vim upgrade must still proceed, got {:?}",
            result.to_upgrade
        );
    }

    #[test]
    fn relax_rich_dep_base_versions_strips_only_base_name_operands() {
        let mut base = HashSet::new();
        base.insert("nvidia-driver-cuda-libs");
        assert_eq!(
            relax_rich_dep_base_versions(
                "(nvidia-driver-cuda-libs(x86-32) = 3:610.57.04-1.fc44 if steam)",
                &base,
            ),
            "(nvidia-driver-cuda-libs(x86-32) if steam)",
        );
        // A non-base operand keeps its pin; the conditional operand is untouched.
        assert_eq!(
            relax_rich_dep_base_versions("(foo-libs(x86-32) = 1.2-3 if steam)", &base),
            "(foo-libs(x86-32) = 1.2-3 if steam)",
        );
    }

    #[test]
    fn split_mode_relaxes_a_conditional_multilib_require_on_a_drifted_base_package() {
        // Reproduced upstream against a RakuOS nvidia image (rakuos-*-nvidia:staging). The
        // base-installed nvidia-driver-cuda-libs.x86_64 carries Requires:
        // (nvidia-driver-cuda-libs(x86-32) = 3:E-R if steam) Once rpmfusion's
        // i686 build moves past the x86_64 build baked into the image (Split
        // mode can't upgrade them together because base is SOLVER_LOCKed),
        // that exact-EVR operand names an i686 NEVRA no repo has, and `vez
        // install steam` failed with "none of the providers can be
        // installed". The version pin on the base-named operand has to be
        // relaxed so libsolv pulls whatever i686 build the repos have.
        let base = vec![{
            let mut p = pkg("nvidia-driver-cuda-libs", "610.57.04-1", "x86_64");
            p.requires = vec![Dependency::unversioned(
                "(nvidia-driver-cuda-libs(x86-32) = 610.57.04-1 if steam)",
            )];
            p
        }];
        let overlay = vec![];
        let available = vec![pkg_providing("steam", "1.0-1", "x86_64", "steam"), {
            // Only a *newer* i686 build exists in the repos.
            let mut p = pkg("nvidia-driver-cuda-libs", "615.71.09-1", "i686");
            p.requires.clear();
            p
        }];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("steam".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_install.iter().any(|p| p.nevra.name == "steam"));
        assert!(
            result
                .to_install
                .iter()
                .any(|p| p.nevra.name == "nvidia-driver-cuda-libs" && p.nevra.arch == "i686"),
            "the drifted i686 nvidia lib must be pulled in, got {:?}",
            result.to_install,
        );
        assert!(
            result
                .to_upgrade
                .iter()
                .all(|p| p.nevra.name != "nvidia-driver-cuda-libs"),
            "base x86_64 build must stay put, got {:?}",
            result.to_upgrade
        );
    }

    #[test]
    fn install_never_shadows_a_base_owned_dependency_with_a_fresh_overlay_copy() {
        // Reproduced upstream against a RakuOS image (rakuos-cosmic:staging): `vez install
        // stellarium` pulled fresh overlay copies of qt6-qtbase (on base,
        // locked at 6.11.1) up to 6.11.2, because a *new* package in
        // stellarium's dependency closure (modeled here as qt6-qtcharts) was
        // only built against 6.11.2 and Requires that exact EVR by name. The
        // core Split-mode rule: a name+arch the base image ships is satisfied
        // *only* by the locked base copy, so installing stellarium must never
        // drag a same-name+arch qt6-qtbase into the overlay, even
        // transitively.
        let base = vec![pkg("qt6-qtbase", "6.11.1-1", "x86_64")];
        let overlay = vec![];
        let available = vec![
            {
                let mut p = pkg("stellarium", "26.2-2", "x86_64");
                p.requires = vec![Dependency::unversioned("qt6-qtcharts")];
                p
            },
            {
                let mut p = pkg("qt6-qtcharts", "6.11.2-1", "x86_64");
                p.requires = vec![Dependency {
                    name: "qt6-qtbase".to_string(),
                    constraint: Some((Comparator::Eq, "6.11.2-1".to_string())),
                }];
                p
            },
            // The dangerous candidate: a fresh qt6-qtbase build at the newer
            // EVR qt6-qtcharts was built against. It must never be selected,
            // because that (name, arch) already exists on base.
            pkg("qt6-qtbase", "6.11.2-1", "x86_64"),
        ];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("stellarium".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();

        assert!(
            result
                .to_install
                .iter()
                .all(|p| p.nevra.name != "qt6-qtbase"),
            "qt6-qtbase must never be shadow-installed into the overlay, got {:?}",
            result.to_install
        );
        assert!(
            result
                .to_upgrade
                .iter()
                .all(|p| p.nevra.name != "qt6-qtbase"),
            "base qt6-qtbase must never be touched, got {:?}",
            result.to_upgrade
        );
        assert!(
            result
                .to_install
                .iter()
                .any(|p| p.nevra.name == "stellarium"),
            "stellarium install must still succeed, got {:?}",
            result.to_install
        );
        assert!(result.to_install.iter().any(|p| p.nevra.name == "qt6-qtcharts"), "qt6-qtcharts install must still succeed, satisfied against the locked base qt6-qtbase, got {:?}", result.to_install);
    }

    #[test]
    fn base_package_isa_qualified_self_require_resolves_without_a_shadow_candidate() {
        // Regression from the fix above: `vez upgrade` failed with "nothing
        // provides librepo(x86-64) = 0:1.21.0-1.fc44 needed by
        // librepo-devel-0:1.21.0-1.fc44.x86_64" even though librepo IS on
        // base. rpm's `%{name}%{?_isa} = %{version}-%{release}` packaging
        // convention (used by almost every -devel/-libs subpackage) generates
        // an exact-EVR, ISA-tagged Requires like `librepo(x86-64) =
        // 1.21.0-1`. Repo metadata and rpmdb parsing don't always list the
        // matching self-provide, so before same-name+arch shadow candidates
        // were excluded from `available`, a fresh duplicate librepo candidate
        // at the same EVR happened to satisfy it. With shadowing blocked, the
        // base copy has to carry (or be given) its own self-provide, or this
        // can't be satisfied. There's no fresh librepo candidate in
        // `available` here at all (only librepo-devel), so this only passes
        // if the base copy satisfies itself.
        let mut librepo_base = pkg("librepo", "1.21.0-1", "x86_64");
        librepo_base.provides.clear(); // exercises the case where repo/rpmdb metadata left out the self-provide
        let base = vec![librepo_base];
        let overlay = vec![];
        let available = vec![{
            let mut p = pkg("librepo-devel", "1.21.0-1", "x86_64");
            p.requires = vec![Dependency {
                name: "librepo(x86-64)".to_string(),
                constraint: Some((Comparator::Eq, "0:1.21.0-1".to_string())),
            }];
            p
        }];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("librepo-devel".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();

        assert!(result.to_install.iter().any(|p| p.nevra.name == "librepo-devel"), "librepo-devel install must succeed against the base librepo's synthesized self-provide, got {:?}", result.to_install);
        assert!(
            result.to_install.iter().all(|p| p.nevra.name != "librepo"),
            "librepo must never be shadow-installed into the overlay, got {:?}",
            result.to_install
        );
    }

    #[test]
    fn base_package_older_than_isa_qualified_exact_evr_require_still_resolves() {
        // Reproduced on a real machine and again in a clean podman Split-mode
        // container: `vez install librepo-devel` (and `vez upgrade`) failed
        // with "nothing provides librepo(x86-64) = 0:1.21.0-1.fc44 needed by
        // librepo-devel-0:1.21.0-1.fc44.x86_64" even though librepo is on
        // base, just at an *older* build (1.20.0-5) than the exact EVR
        // librepo-devel's ISA-tagged Requires asks for. The base-name
        // constraint relaxation only matched a plain `Requires: librepo =
        // <evr>` against `base_names`. An ISA-tagged `librepo(x86-64) =
        // <evr>` never equaled the plain name "librepo", so the constraint
        // wasn't relaxed, and with same-name+arch shadow candidates kept out
        // of the pool (the point of Split mode) nothing could satisfy it.
        // Base packages must satisfy overlay deps unconditionally; stripping
        // the ISA suffix before the base_names check fixes it.
        let base = vec![pkg("librepo", "1.20.0-5", "x86_64")];
        let overlay = vec![];
        let available = vec![{
            let mut p = pkg("librepo-devel", "1.21.0-1", "x86_64");
            p.requires = vec![Dependency {
                name: "librepo(x86-64)".to_string(),
                constraint: Some((Comparator::Eq, "0:1.21.0-1".to_string())),
            }];
            p
        }];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("librepo-devel".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();

        assert!(
            result
                .to_install
                .iter()
                .any(|p| p.nevra.name == "librepo-devel"),
            "librepo-devel install must succeed against base's older librepo, got {:?}",
            result.to_install
        );
        assert!(result.to_install.iter().all(|p| p.nevra.name != "librepo"), "librepo must never be shadow-installed into the overlay just to satisfy a newer exact-EVR require, got {:?}", result.to_install);
    }

    #[test]
    fn upgrade_all_locks_a_foreign_arch_overlay_build_of_a_base_owned_name() {
        // libcap-ng.x86_64 ships on base (locked at 0.9.3), but
        // libcap-ng.i686 was installed later into the *overlay* (e.g. for
        // Steam's 32-bit stack): same name, different arch, different origin.
        // `upgrade_all` used to move the overlay i686 build to 0.9.5 by
        // itself, and libsolv's same-name install check then collided it with
        // the still-locked base x86_64 build. A base-owned name has to be
        // locked across every arch it's installed under, so the overlay i686
        // build stays where it is next to the base x86_64 build.
        let base = vec![{
            let mut p = pkg("libcap-ng", "0.9.3-1", "x86_64");
            p.requires.clear();
            p
        }];
        let overlay = vec![
            {
                let mut p = pkg("libcap-ng", "0.9.3-1", "i686");
                p.requires.clear();
                p
            },
            {
                let mut p = pkg("vim", "9.0-1", "x86_64");
                p.requires.clear();
                p
            },
        ];
        let available = vec![
            {
                let mut p = pkg("libcap-ng", "0.9.5-1", "x86_64");
                p.requires.clear();
                p
            },
            {
                let mut p = pkg("libcap-ng", "0.9.5-1", "i686");
                p.requires.clear();
                p
            },
            {
                let mut p = pkg("vim", "9.1-1", "x86_64");
                p.requires.clear();
                p
            },
        ];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_all: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert!(
            result
                .to_upgrade
                .iter()
                .all(|p| p.nevra.name != "libcap-ng"),
            "libcap-ng must stay locked in every arch, got {:?}",
            result.to_upgrade
        );
        assert!(
            result
                .to_install
                .iter()
                .all(|p| p.nevra.name != "libcap-ng"),
            "libcap-ng must never be shadow-installed, got {:?}",
            result.to_install
        );
        assert!(
            result
                .to_upgrade
                .iter()
                .any(|p| p.nevra.name == "vim" && p.nevra.version == "9.1"),
            "unrelated vim upgrade must still proceed, got {:?}",
            result.to_upgrade
        );
    }

    #[test]
    fn distro_sync_names_can_downgrade() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("vim", "9.1-1", "x86_64")];
        // Only an older build is available now (e.g. the repo rolled back).
        // Plain `upgrade` would never pick it, but `distro-sync` forces an
        // exact match with what's offered now.
        let available = vec![pkg("vim", "9.0-1", "x86_64")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                distro_sync_names: vec!["vim".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert_eq!(result.to_upgrade.len(), 1);
        assert_eq!(result.to_upgrade[0].nevra.version, "9.0");
    }

    #[test]
    fn pinned_install_forces_exact_downgrade_target() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("vim", "9.1-1", "x86_64")];
        let available = vec![pkg("vim", "9.0-1", "x86_64"), pkg("vim", "9.2-1", "x86_64")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                pinned_installs: vec![(
                    "vim".to_string(),
                    "9.0".to_string(),
                    "1".to_string(),
                    "x86_64".to_string(),
                )],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_erase.is_empty());
        assert_eq!(result.to_upgrade.len(), 1);
        assert_eq!(
            result.to_upgrade[0].nevra.version, "9.0",
            "pinned target must be the exact requested downgrade, not the newest 9.2 available"
        );
    }

    #[test]
    // A soft-reset reinstall of an old overlay's exact-NEVRA snapshot that
    // pins a `.i686` build which is gone now (upstream dropped it, or the
    // arch-clobber guard suppresses it) must fall back to the host-arch build
    // of the same name instead of failing the whole reinstall. See the
    // comment on `PINNED_X86_32` above.
    fn pinned_install_of_missing_i686_falls_back_to_host_arch() {
        let available = vec![pkg_providing("wine-core", "11.0-3", "x86_64", "wine-core")];
        let mut build = build_pool("x86_64", &[], &[], &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                pinned_installs: vec![(
                    "wine-core".to_string(),
                    "11.0".to_string(),
                    "3".to_string(),
                    "i686".to_string(),
                )],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.to_install.len(), 1);
        assert_eq!(result.to_install[0].nevra.arch, "x86_64");
    }

    #[test]
    // Same missing `.i686` pin, but the host-arch build is already installed.
    // The 32-bit copy has nothing left to add, so the pin should just be
    // dropped without installing a redundant duplicate or erroring.
    fn pinned_install_of_missing_i686_is_skipped_when_host_arch_already_installed() {
        let overlay = vec![pkg_providing("wine-core", "11.0-3", "x86_64", "wine-core")];
        let mut build = build_pool("x86_64", &[], &overlay, &[]).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                pinned_installs: vec![(
                    "wine-core".to_string(),
                    "11.0".to_string(),
                    "3".to_string(),
                    "i686".to_string(),
                )],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_install.is_empty());
        assert!(result.to_erase.is_empty());
        assert!(result.to_upgrade.is_empty());
    }

    #[test]
    // Split-mode soft reset where the overlay's packages.list pinned *both*
    // the x86_64 build and a (now suppressed or gone) i686 build of the same
    // name, a real case for an old wine install from before the arch-clobber
    // guard. The x86_64 pin has to resolve normally and the i686 pin has to
    // be dropped without an error, since the overlay's x86_64 copy covers it.
    fn split_mode_soft_reset_pins_both_arches_skips_i686_when_x86_64_pin_also_present() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg_providing("wine-core", "11.0-3", "x86_64", "wine-core")];
        let mut build = build_pool("x86_64", &base, &overlay, &[]).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                pinned_installs: vec![
                    (
                        "wine-core".to_string(),
                        "11.0".to_string(),
                        "3".to_string(),
                        "x86_64".to_string(),
                    ),
                    (
                        "wine-core".to_string(),
                        "11.0".to_string(),
                        "3".to_string(),
                        "i686".to_string(),
                    ),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        // The x86_64 pin is already installed at the exact pinned EVR
        // (skipped as a no-op further up in this same loop, like a base-only
        // pin), and the new fallback drops the i686 pin, so there's nothing
        // new to install.
        assert!(result.to_install.is_empty());
        assert!(result.to_erase.is_empty());
    }

    #[test]
    // Split-mode soft reset where the overlay pinned *only* the i686 build
    // (no x86_64 copy in base or overlay). The migration has to install the
    // x86_64 build instead of failing the whole reinstall.
    fn split_mode_soft_reset_pins_only_i686_resolves_to_x86_64() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let available = vec![pkg_providing("wine-core", "11.0-3", "x86_64", "wine-core")];
        let mut build = build_pool("x86_64", &base, &[], &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                pinned_installs: vec![(
                    "wine-core".to_string(),
                    "11.0".to_string(),
                    "3".to_string(),
                    "i686".to_string(),
                )],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.to_install.len(), 1);
        assert_eq!(result.to_install[0].nevra.name, "wine-core");
        assert_eq!(result.to_install[0].nevra.arch, "x86_64");
    }

    #[test]
    // `vez upgrade wine-core` where the overlay has a stale i686 build the
    // arch-clobber guard suppresses, and the x86_64 build is installed too.
    // The migration should only erase the i686 leftover, with no redundant
    // install job for the installed x86_64 copy.
    fn upgrade_names_erases_suppressed_i686_when_host_arch_already_installed() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![
            pkg_providing("wine-core", "11.0-3", "x86_64", "/usr/bin/wine-core"),
            pkg_providing("wine-core", "11.0-3", "i686", "/usr/bin/wine-core"),
        ];
        let mut build = build_pool("x86_64", &base, &overlay, &[]).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_names: vec!["wine-core".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.to_erase.len(), 1);
        assert_eq!(result.to_erase[0].nevra.arch, "i686");
        assert!(!result
            .to_install
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "x86_64"));
    }

    #[test]
    // Same scenario, but the x86_64 build isn't installed anywhere and is
    // only available from a repo. The migration should erase the stale i686
    // leftover AND install the x86_64 build.
    fn upgrade_names_migrates_suppressed_i686_to_available_x86_64() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "i686",
            "/usr/bin/wine-core",
        )];
        let available = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "x86_64",
            "/usr/bin/wine-core",
        )];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_names: vec!["wine-core".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result
            .to_erase
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "i686"));
        assert!(result
            .to_install
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "x86_64"));
    }

    #[test]
    // `vez upgrade` with no names (`upgrade_all`) should also catch the
    // suppressed i686 leftover, as well as an explicit `upgrade_names` job.
    fn upgrade_all_migrates_suppressed_i686_to_available_x86_64() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "i686",
            "/usr/bin/wine-core",
        )];
        let available = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "x86_64",
            "/usr/bin/wine-core",
        )];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_all: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result
            .to_erase
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "i686"));
        assert!(result
            .to_install
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "x86_64"));
    }

    #[test]
    // `vez system-upgrade wine-core` (distro_sync_names) should do the same
    // migration as `vez upgrade`.
    fn distro_sync_names_migrates_suppressed_i686_to_available_x86_64() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "i686",
            "/usr/bin/wine-core",
        )];
        let available = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "x86_64",
            "/usr/bin/wine-core",
        )];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                distro_sync_names: vec!["wine-core".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result
            .to_erase
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "i686"));
        assert!(result
            .to_install
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "x86_64"));
    }

    #[test]
    // `vez system-upgrade` (distro_sync_all, no names) should also catch it.
    fn distro_sync_all_migrates_suppressed_i686_to_available_x86_64() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "i686",
            "/usr/bin/wine-core",
        )];
        let available = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "x86_64",
            "/usr/bin/wine-core",
        )];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                distro_sync_all: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result
            .to_erase
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "i686"));
        assert!(result
            .to_install
            .iter()
            .any(|p| p.nevra.name == "wine-core" && p.nevra.arch == "x86_64"));
    }

    #[test]
    // A suppressed installed i686 package that this request does NOT target
    // (not named in the upgrade/distro-sync lists, and no `_all` job) must be
    // left alone. An unrelated `vez install other-pkg` shouldn't start
    // erasing unrelated packages as a side effect.
    fn suppressed_i686_is_left_alone_when_not_targeted_by_request() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![
            pkg_providing("wine-core", "11.0-3", "i686", "/usr/bin/wine-core"),
            pkg_providing("vim", "9.0-1", "x86_64", "vim"),
        ];
        let available = vec![pkg_providing(
            "wine-core",
            "11.0-3",
            "x86_64",
            "/usr/bin/wine-core",
        )];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                upgrade_names: vec!["vim".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!result.to_erase.iter().any(|p| p.nevra.name == "wine-core"));
        assert!(!result
            .to_install
            .iter()
            .any(|p| p.nevra.name == "wine-core"));
    }

    #[test]
    fn pinned_install_missing_target_is_an_error() {
        let mut build = build_pool("x86_64", &[], &[], &[]).unwrap();
        let err = solve(
            &mut build,
            &SolveRequest {
                pinned_installs: vec![(
                    "nonexistent".to_string(),
                    "1".to_string(),
                    "1".to_string(),
                    "x86_64".to_string(),
                )],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn unresolvable_request_is_an_error() {
        let mut build = build_pool("x86_64", &[], &[], &[]).unwrap();
        let err = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("nonexistent-package".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("nonexistent-package"));
    }

    #[test]
    // `vez install ... pipewire-pulse ...` failed with "nothing provides
    // 'pipewire-pulse'" and aborted a whole multi-package session install,
    // even though pipewire-pulse was on the base image. A name that's present
    // on the base image or overlay must never fail the whole transaction: the
    // base package candidate satisfies the request (and is `SOLVER_LOCK`ed as
    // usual), so `to_install` ends up empty. `already_installed`, the
    // fallback for a name that resolves to *no* candidate anywhere but is
    // still in the rpmdb (see the `candidates.is_empty()` branch in `solve`),
    // isn't needed here.
    fn install_of_a_name_already_on_base_is_a_no_op_not_an_error() {
        let base = vec![pkg("pipewire-pulse", "1.0-1", "x86_64")];
        let mut build = build_pool("x86_64", &base, &[], &[]).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("pipewire-pulse".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_install.is_empty());
        assert!(result.already_installed.is_empty());
    }

    #[test]
    fn install_of_a_name_already_in_overlay_is_a_no_op_not_an_error() {
        let overlay = vec![pkg("htop", "3.0-1", "x86_64")];
        let mut build = build_pool("x86_64", &[], &overlay, &[]).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("htop".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(result.to_install.is_empty());
        assert!(result.already_installed.is_empty());
    }

    #[test]
    // The real cause of the `pipewire-pulse` bug (checked against stock
    // Fedora 44's dnf5/rpm): no package or Provides is named
    // `pipewire-pulse`, there's only a `/usr/bin/pipewire-pulse` binary in
    // `pipewire-pulseaudio`. dnf5 resolves a bare `install pipewire-pulse`
    // through its "binaries" fallback (`/usr/bin/<name>`/`/usr/sbin/<name>`
    // against the provides index). `vez-repo`'s primary.xml parser already
    // turns such `<file>` entries into unversioned Provides (`pkg_providing`
    // stands in for that here), so `solve` has to resolve the bare name the
    // way dnf5 does instead of erroring.
    fn install_of_a_bare_name_resolves_via_its_binary_path() {
        let available = vec![pkg_providing(
            "pipewire-pulseaudio",
            "1.6.8-1",
            "x86_64",
            "/usr/bin/pipewire-pulse",
        )];
        let mut build = build_pool("x86_64", &[], &[], &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("pipewire-pulse".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.to_install.len(), 1);
        assert_eq!(result.to_install[0].nevra.name, "pipewire-pulseaudio");
        assert!(result.already_installed.is_empty());
    }

    #[test]
    // The `bottles` bug: installing `bottles` pulls in `patool`, whose
    // `Recommends: genisoimage` can be satisfied by two unrelated packages:
    // the real `genisoimage` package (own name matches) and Svara's custom
    // `mkisofs` package (which only `Provides: genisoimage` so other
    // `Requires: genisoimage` resolve whichever cdrtools-family
    // implementation is installed). libsolv's weak-dep candidate selection
    // has no exact-name preference, so `mkisofs` could win on a
    // solvable-id/arch/EVR tie-break. `mkisofs`'s `schily-libs` dependency
    // then file-conflicts with `star`/`star-libs` (pulled in by another of
    // patool's recommends), which stock Fedora (no `mkisofs` package) never
    // produces. The real `genisoimage` package must always win.
    fn recommends_prefer_the_exact_name_package_over_an_unrelated_provider() {
        let mut patool = pkg("patool", "4.0.2-1", "noarch");
        patool.requires.clear();
        patool
            .recommends
            .push(Dependency::unversioned("genisoimage"));
        let genisoimage = pkg_providing("genisoimage", "1.1.11-1", "x86_64", "genisoimage");
        let mkisofs = pkg_providing("mkisofs", "10:2024.03.21-1", "x86_64", "genisoimage");
        let available = vec![patool, genisoimage, mkisofs];
        let mut build = build_pool("x86_64", &[], &[], &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("patool".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap();
        let installed_names: Vec<&str> = result
            .to_install
            .iter()
            .map(|p| p.nevra.name.as_str())
            .collect();
        assert!(installed_names.contains(&"patool"));
        assert!(
            installed_names.contains(&"genisoimage"),
            "expected the real genisoimage package, got {installed_names:?}"
        );
        assert!(!installed_names.contains(&"mkisofs"), "mkisofs should never win over the exact-name genisoimage package, got {installed_names:?}");
    }

    #[test]
    // A name that really is missing must still fail even when *other*
    // installed base packages are in the pool. The already-installed shortcut
    // is per name, not a blanket bypass whenever base is non-empty.
    fn install_of_an_unrelated_missing_name_still_errors_when_base_is_non_empty() {
        let base = vec![pkg("pipewire-pulse", "1.0-1", "x86_64")];
        let mut build = build_pool("x86_64", &base, &[], &[]).unwrap();
        let err = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("nonexistent-package".to_string(), None)],
                erase_names: vec![],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("nonexistent-package"));
    }

    fn pkg_conflicting(name: &str, evr: &str, arch: &str, conflict: &str) -> Package {
        let mut p = pkg(name, evr, arch);
        p.conflicts.push(Dependency::unversioned(conflict));
        p
    }

    #[test]
    fn conflicting_install_fails_without_allow_erasing() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("old-codec", "1.0-1", "x86_64")];
        let available = vec![pkg_conflicting("new-codec", "2.0-1", "x86_64", "old-codec")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let err = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("new-codec".to_string(), None)],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn allow_erasing_lets_libsolv_erase_a_conflicting_installed_package() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("old-codec", "1.0-1", "x86_64")];
        let available = vec![pkg_conflicting("new-codec", "2.0-1", "x86_64", "old-codec")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let result = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("new-codec".to_string(), None)],
                allow_erasing: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(result.to_install.len(), 1);
        assert_eq!(result.to_install[0].nevra.name, "new-codec");
        assert_eq!(result.to_erase.len(), 1);
        assert_eq!(result.to_erase[0].nevra.name, "old-codec");
    }

    #[test]
    fn allow_erasing_never_erases_a_protected_package() {
        let base = vec![pkg_providing("glibc", "2.39-1", "x86_64", "libfoo.so.1")];
        let overlay = vec![pkg("old-codec", "1.0-1", "x86_64")];
        let available = vec![pkg_conflicting("new-codec", "2.0-1", "x86_64", "old-codec")];
        let mut build = build_pool("x86_64", &base, &overlay, &available).unwrap();
        let err = solve(
            &mut build,
            &SolveRequest {
                install_names: vec![("new-codec".to_string(), None)],
                allow_erasing: true,
                protected_names: vec!["old-codec".to_string()],
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}
