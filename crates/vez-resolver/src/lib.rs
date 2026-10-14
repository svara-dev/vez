//! Dependency resolution that knows about the overlay. Base-image packages go
//! into the pool as installed and locked (see `vez_solv::build_pool_locked`),
//! so a dependency the base image already provides is satisfied there and
//! never added to the install set. dnf, or any resolver working from one
//! merged "installed" view, can't make that distinction: to it, a package
//! provided by the base and one provided by the overlay look the same.
//! Nothing below ever reconsiders, re-layers, or modifies a base package.
//!
//! Solving goes through libsolv ([`vez_solv`]), the SAT solver dnf5/libdnf5
//! use. An earlier hand-rolled backtracking worklist resolver re-explored the
//! same competing-provider choice at every place it appeared in the
//! dependency tree, which multiplies out combinatorially on a big package
//! graph (Steam's real Fedora + RPM Fusion tree: 15+ minutes at 100% CPU with
//! no result). A SAT solver's unit propagation turns everything with only one
//! possible provider into a forced assignment, and each real choice gets made
//! once and shared instead of being redone per occurrence.
//!
//! Multilib: a versioned symbol capability like `libjpeg.so.62(LIBJPEG_6.2)`
//! is provided with the *same* literal text (no arch marker) by both the
//! x86_64 and i686 builds of a library. rpm doesn't tell these apart by
//! capability text; it relies on the resolver staying inside one arch's
//! dependency chain. vez's own provider matching (`check_closure`) therefore
//! carries the arch of the requiring package as a hint (`None` for a
//! top-level requested name, meaning "prefer the host arch"). An explicit ISA
//! suffix on the capability (`(x86-32)`, `(x86-64)`, `(64bit)`) overrides
//! that hint, since it's rpm's way of asking for the *other* arch's copy (how
//! a plain x86_64 package pulls in an i686 multilib dependency). Two versions
//! of the *same* (name, arch) can't be installed together, but two arches of
//! the same name can, which is how the x86_64 and i686 builds of a library
//! end up side by side.

use anyhow::Result;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use vez_core::{Dependency, EvrCompare, Package};
use vez_overlay::OverlayContext;

/// The result of resolving a set of requested package names: what needs
/// installing, plus, for display, what was skipped because the base image or
/// an existing overlay install already covers it.
#[derive(Debug, Default)]
pub struct Plan {
    /// Packages to install. There's no dependency-first ordering here; rpm's
    /// transaction ordering handles that. This is just the full install set.
    pub to_install: Vec<Package>,
    pub already_satisfied: Vec<SatisfiedBy>,
    /// Installed (base or overlay) packages that an Obsoletes entry on
    /// something in `to_install` will make `rpm -U` erase in the same
    /// transaction. vez doesn't issue a separate removal for these because
    /// rpm erases obsoleted packages during `-U` by itself, as under dnf. The
    /// list is only there so callers can show the user what's about to go
    /// away before running the transaction, like dnf's "Obsoleting" line in
    /// its plan summary.
    pub to_obsolete: Vec<Package>,
    /// Installed *overlay* packages that must be erased explicitly (a
    /// separate `rpm -e` transaction, unlike `to_obsolete`) around installing
    /// `to_install`, because something being installed `Conflicts` with them
    /// and [`ResolveOptions::allow_erasing`] was set. This is vez's version
    /// of dnf's `--allowerasing`. It never contains a *base*-image package:
    /// vez can't erase those (see the conflicts comment in `resolve_ex`), so
    /// a conflict against a base package always fails, `allow_erasing` or
    /// not.
    pub to_erase: Vec<Package>,
    /// Requested names dropped by [`ResolveOptions::skip_broken`] because no
    /// combination including them resolved. Same as dnf5's `skip_broken=`:
    /// the rest of the transaction goes through instead of the whole
    /// `install` failing over one bad, renamed, or unavailable name. Always
    /// empty unless `skip_broken` was set.
    pub skipped: Vec<String>,
    /// Requested names that are already on the base image or overlay but
    /// can't be resolved through the enabled repos anymore (renamed or
    /// dropped upstream, a repo missing them, etc.). Treated as a no-op
    /// instead of failing the whole `install`. Filled in whether or not
    /// `skip_broken` is set, unlike `skipped`. See
    /// `vez_solv::SolveResult::already_installed`.
    pub already_installed: Vec<String>,
    /// The subset of `to_install` that upgrades an installed (overlay)
    /// package to a newer EVR, as opposed to a new package pulled in as a
    /// dependency. Only [`resolve_upgrade`] and [`resolve_distro_sync`] fill
    /// it in. It lets callers like `vez check-upgrade` report what `vez
    /// upgrade` would change without redoing it with a separate version
    /// comparison that would ignore the resolver's own locking (e.g. Split
    /// mode's lock on base-owned names across all arches).
    pub to_upgrade: Vec<Package>,
}

#[derive(Debug, Clone)]
pub struct SatisfiedBy {
    pub dependency: Dependency,
    pub origin: vez_core::Origin,
}

/// Resolution settings beyond the plain hard-`Requires` closure that
/// [`resolve`] always does. See [`resolve_ex`].
#[derive(Debug, Clone)]
pub struct ResolveOptions {
    /// Whether to also pull in `Recommends` (weak deps), best-effort, next to
    /// the hard `Requires` closure. dnf's `install_weak_deps=` (default
    /// `true`). A `Recommends` target that can't be resolved (no provider, or
    /// a provider that fails to resolve itself) is skipped instead of failing
    /// the transaction, which is the difference from `Requires`. `Suggests`
    /// is never installed automatically, same as dnf (which has no setting
    /// for it either).
    pub install_weak_deps: bool,
    /// Package names (or globs) that may have several versions installed side
    /// by side: dnf's `installonlypkgs=`. A matching candidate is exempt from
    /// the usual "one version of a (name, arch) at a time" and "never replace
    /// an installed version" rules, since installing a new kernel next to the
    /// running one is the whole idea.
    pub installonly_pkgs: Vec<String>,
    /// dnf's `--allowerasing`: when a candidate being installed `Conflicts`
    /// with an installed *overlay* package, erase that package as part of the
    /// same operation instead of failing on the conflict. A base-image
    /// package is never erased this way; see [`Plan::to_erase`]. `swap`
    /// always behaves as if this were set (see `Command::Swap` in `vez-cli`),
    /// because a swap that can't move a conflicting sibling package out of
    /// the way can't swap anything.
    pub allow_erasing: bool,
    /// Top-level requested names that must turn into a real install even if
    /// some *differently named* installed package (base or overlay)
    /// `Provides` the same capability. `swap`'s install half uses it, since
    /// the literal named package has to end up installed. Without it, the
    /// usual "already satisfied by base" shortcut can skip the install
    /// entirely. Example: `vez swap libswscale-free libswscale`, where
    /// `libswscale-free` is in the *base* image (so the remove half is also a
    /// no-op, because `remove` can't touch base packages) and Provides
    /// `libswscale` as a rename. That left the free build in place without
    /// swapping anything.
    pub force_names: std::collections::HashSet<String>,
    /// dnf's protected-packages list (kernel, glibc, dnf itself, `vez.conf`'s
    /// `protected_packages=`, plus the names vez always protects). Passed
    /// through to [`vez_solv::SolveRequest::protected_names`] so libsolv
    /// itself never proposes erasing one of these as a side effect of
    /// resolving an install/upgrade's conflicts or obsoletes. An app-level
    /// check on explicit `vez remove` alone wouldn't catch that.
    pub protected_names: Vec<String>,
    /// dnf5's versionlock plugin: names of installed packages that may never
    /// move off their current EVR, even when some unrelated install/upgrade
    /// pulls them in transitively. Passed through to
    /// [`vez_solv::build_pool_locked`] so a locked name's candidate with a
    /// different EVR never enters the pool at all, instead of only being
    /// checked at the direct `install`/`upgrade`/ `distro-sync` entry points
    /// in `vez-cli`.
    pub locked_names: Vec<vez_core::VersionLock>,
    /// dnf5's `skip_broken=`/`--skip-broken`: if the full requested set can't
    /// be resolved together, drop the requested names responsible one at a
    /// time and retry, instead of failing the whole `install` over one bad
    /// name. See the retry loop in `resolve_ex`. Default `false` (also dnf5's
    /// default, `skip_broken=0`).
    pub skip_broken: bool,
    /// dnf5's `multilib_policy=`. `false` (`best`, the default) lets a bare
    /// `install foo` job cover every arch build of `foo` and leaves the pick
    /// to libsolv's policy. `true` (`all`) installs every distinct arch build
    /// side by side. Passed through to
    /// [`vez_solv::SolveRequest::multilib_all`].
    pub multilib_all: bool,
    /// dnf5's `best=`/`--best`: the newest available EVR has to resolve
    /// cleanly, without silently falling back to an older one that does.
    /// Passed through to [`vez_solv::SolveRequest::best`]. Default `false`
    /// (also dnf5's default, `best=0`).
    pub best: bool,
    /// dnf5's `obsoletes=`: when an `install` name matches nothing by name or
    /// Provides, also search packages that `Obsoletes` it. Passed through to
    /// [`vez_solv::SolveRequest::obsoletes`]. Default `true` (also dnf5's
    /// default, `obsoletes=1`).
    pub obsoletes: bool,
    /// dnf5's `allow_downgrade=`/`--allow-downgrade`/`--no-allow-downgrade`.
    /// Passed through to [`vez_solv::SolveRequest::allow_downgrade`]. Default
    /// `true`, as in dnf5.
    pub allow_downgrade: bool,
}

impl Default for ResolveOptions {
    fn default() -> Self {
        Self {
            install_weak_deps: true,
            installonly_pkgs: Vec::new(),
            allow_erasing: false,
            force_names: std::collections::HashSet::new(),
            protected_names: Vec::new(),
            locked_names: Vec::new(),
            skip_broken: false,
            multilib_all: false,
            best: false,
            obsoletes: true,
            allow_downgrade: true,
        }
    }
}

/// A capability -> providers lookup built once per [`check_closure`] call, so
/// finding candidates doesn't mean scanning every candidate package for every
/// dependency. A capability is indexed under a package's own name (an
/// unversioned `Requires` on the package itself) and under every name in its
/// `Provides` list (a `Requires` on a capability instead of a package name).
/// Those are the two ways [`dep_matches_pkg`] can match.
struct CandidateIndex<'a> {
    by_capability: HashMap<Cow<'a, str>, Vec<&'a Package>>,
}

impl<'a> CandidateIndex<'a> {
    fn build(candidates: &'a [Package]) -> Self {
        let mut by_capability: HashMap<Cow<'a, str>, Vec<&'a Package>> = HashMap::new();
        for pkg in candidates {
            by_capability
                .entry(Cow::Borrowed(pkg.nevra.name.as_str()))
                .or_default()
                .push(pkg);
            for p in &pkg.provides {
                by_capability
                    .entry(Cow::Borrowed(p.name.as_str()))
                    .or_default()
                    .push(pkg);
            }
            // rpm always auto-generates an ISA-tagged self-provide
            // (`name(x86-64)`/`name(x86-32)`) for every 64/32-bit capable
            // package, but repo primary.xml doesn't always list it in
            // `provides`. A package without the explicit entry would never be
            // indexed under that capability, so a plain `Requires:
            // foo(x86-64)` would look unsatisfiable even though `foo` is a
            // valid candidate (see `dep_matches_pkg`). This key doesn't exist
            // anywhere in `candidates`, so there's no `&'a str` to borrow;
            // it's stored as `Cow::Owned`. The earlier
            // `Box::leak`/`String::leak` version leaked one allocation per
            // ISA-capable package on every call for the life of the process.
            if let Some(isa) = match pkg.nevra.arch.as_str() {
                "x86_64" => Some("x86-64"),
                "i686" => Some("x86-32"),
                _ => None,
            } {
                let key = Cow::Owned(format!("{}({isa})", pkg.nevra.name));
                by_capability.entry(key).or_default().push(pkg);
            }
        }
        Self { by_capability }
    }

    fn lookup(&self, name: &str) -> &[&'a Package] {
        self.by_capability
            .get(name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

/// Strips the SELinux/broken-repo-dep edges described in the doc comment of
/// [`resolve_ex`] from one package's `requires`/`recommends`/`supplements`,
/// cloning only that one package. Shared by [`resolve_ex`] and
/// [`build_filtered_pool`] so this logic exists once instead of in two
/// closures kept in sync by hand.
fn filter_pkg_deps(pkg: &Package, selinux_ignored_in_scope: bool) -> Package {
    let mut p = pkg.clone();
    let keep = |dep: &&Dependency| -> bool {
        !((selinux_ignored_in_scope && is_selinux_ignored(&dep.name))
            || is_broken_repo_dep_edge_ignored(&pkg.nevra.name, &dep.name))
    };
    p.requires.retain(|req| keep(&req));
    // libsolv pulls in `recommends`/`supplements` by itself
    // (`SOLVER_FLAG_IGNORE_RECOMMENDED=0` by default; see the
    // `install_weak_deps` handling in `vez_solv::solve`), independently of
    // `requires`. Stripping only `requires` left e.g. `passt`'s `Recommends:
    // passt-selinux` free to drag SELinux packages in as weak deps, so the
    // same SELinux/broken-edge rules have to apply here too.
    p.recommends.retain(|rec| keep(&rec));
    p.supplements.retain(|sup| keep(&sup));
    p
}

/// dnf's repo `cost=` means "prefer this repo unless nothing else has the
/// package". Fedora's `fedora-updates-archive.repo` sets `cost=10000`, per
/// its own comment, "in order to prefer the normal Fedora yum repositories,
/// which means only packages that can't be found elsewhere will be downloaded
/// from here." libsolv's SAT pool (`vez_solv::build_pool_locked`) treats
/// every solvable as equally selectable whatever repo it came from, and
/// nothing upstream of it encoded repo preference. So a same-name+arch build
/// in a high-cost/low-priority repo could still win over an equal (or better)
/// copy from a lower-cost repo. Seen with `vez install gcc-c++`: it resolved
/// to Fedora's `updates-archive` (cost=10000) and failed on that repo's CDN
/// propagation lag, while `updates`/`fedora` (cost=1000) had the same build.
///
/// Applied once, before any pool is built: for each `(name, arch)`, only the
/// candidate(s) with the lowest `repo_cost` for that pair go into the pool. A
/// higher-cost repo's build of that name+arch only reaches libsolv (and can
/// only be picked, exact-NEVRA pins included) when it's the *only* source,
/// which is what `cost=` is supposed to mean. It isn't applied to the raw
/// `candidates` slice callers also use to parse request strings
/// (`match_exact_nevra_request`/`split_name_arch_request` below): a user
/// naming an exact NEVRA that only exists in a high-cost repo should still
/// get it. This only changes what libsolv reaches for by itself.
///
/// The cost filter and the SELinux/broken-edge dependency filtering from
/// [`filter_pkg_deps`] run in one pass over `candidates`, so the pool (often
/// 40k to 80k packages across a few enabled repos) is deep-cloned once. It
/// used to be two passes
/// (`prefer_low_cost_repos(candidates).iter().map(filter_pkg) .collect()`),
/// which cloned every candidate's strings and dependency `Vec`s twice in a
/// row on every `resolve_ex`/`build_filtered_pool` call.
fn build_available_pool(candidates: &[Package], selinux_ignored_in_scope: bool) -> Vec<Package> {
    let mut min_cost: HashMap<(&str, &str), u32> = HashMap::new();
    for pkg in candidates {
        let key = (pkg.nevra.name.as_str(), pkg.nevra.arch.as_str());
        min_cost
            .entry(key)
            .and_modify(|c| *c = (*c).min(pkg.repo_cost))
            .or_insert(pkg.repo_cost);
    }
    candidates
        .iter()
        .filter(|pkg| {
            pkg.repo_cost == min_cost[&(pkg.nevra.name.as_str(), pkg.nevra.arch.as_str())]
        })
        .map(|pkg| filter_pkg_deps(pkg, selinux_ignored_in_scope))
        .collect()
}

/// Splits a top-level request like `"xz-devel.i686"` into `("xz-devel",
/// Some("i686"))`, rpm/dnf's `name.arch` syntax, but only when a package
/// named `xz-devel` with arch `i686` exists among the candidates or the
/// installed set. Otherwise the whole string is treated as a literal name,
/// since an rpm package name can contain a dot.
fn split_name_arch_request<'a>(
    name: &'a str,
    candidates: &[Package],
    overlay: &OverlayContext,
) -> (&'a str, Option<&'a str>) {
    if let Some((base, arch)) = name.rsplit_once('.') {
        let known = candidates
            .iter()
            .any(|p| p.nevra.name == base && p.nevra.arch == arch)
            || overlay
                .base
                .iter()
                .chain(&overlay.overlay)
                .any(|p| p.nevra.name == base && p.nevra.arch == arch);
        if known {
            return (base, Some(arch));
        }
    }
    (name, None)
}

/// Matches `request` against a full NEVRA spec (`vez install
/// kernel-6.19.14-300.fc44.x86_64`, dnf's exact-build install syntax) instead
/// of a plain name. It compares strings directly against each candidate's
/// `name-version-release.arch` / `name-version-release` form. We have the
/// whole candidate pool, so there's no need to guess where the name ends and
/// the EVR begins; rpm names can contain hyphens, so splitting blindly is
/// ambiguous and a full scan for an exact match isn't. When a version-release
/// without `.arch` matches both an x86_64 and an i686 build, `host_arch`
/// wins.
fn match_exact_nevra_request(
    request: &str,
    candidates: &[Package],
    host_arch: &str,
) -> Option<(String, String, String, String)> {
    let mut matches: Vec<&Package> = candidates
        .iter()
        .filter(|p| {
            let with_arch = format!(
                "{}-{}-{}.{}",
                p.nevra.name, p.nevra.version, p.nevra.release, p.nevra.arch
            );
            let no_arch = format!("{}-{}-{}", p.nevra.name, p.nevra.version, p.nevra.release);
            // Also accept the `name-epoch:version-release[.arch]` form dnf5
            // prints and accepts (e.g. copied from a "nothing provides" error
            // or `dnf5 repoquery` output). `Nevra::evr()` already renders
            // `epoch:version-release`, so this is that form joined back onto
            // the name.
            let evr_with_arch = format!("{}-{}.{}", p.nevra.name, p.nevra.evr(), p.nevra.arch);
            let evr_no_arch = format!("{}-{}", p.nevra.name, p.nevra.evr());
            request == with_arch
                || request == no_arch
                || request == evr_with_arch
                || request == evr_no_arch
        })
        .collect();
    matches.sort_by_key(|p| p.nevra.arch != host_arch);
    matches.first().map(|p| {
        (
            p.nevra.name.clone(),
            p.nevra.version.clone(),
            p.nevra.release.clone(),
            p.nevra.arch.clone(),
        )
    })
}

/// Resolves `requested` package names against `candidates` (usually every
/// enabled repo's package list concatenated), skipping anything
/// [`OverlayContext`] already reports as satisfied. `host_arch` (e.g.
/// `"x86_64"`) is preferred for top-level requested names and for any
/// dependency without an inherited arch hint; the module doc comment explains
/// why a dependency needs an arch hint at all.
pub fn resolve(
    requested: &[String],
    candidates: &[Package],
    overlay: &OverlayContext,
    host_arch: &str,
) -> Result<Plan> {
    resolve_ex(
        requested,
        candidates,
        overlay,
        host_arch,
        &ResolveOptions::default(),
    )
}

/// Same as [`resolve`], with [`ResolveOptions`] controlling weak-dependency
/// and installonly-package behavior.
///
/// Backed by libsolv ([`vez_solv`]) instead of a hand-rolled SAT solver. Not
/// all of
/// `installonly_pkgs`/`allow_erasing`/`force_names`/`install_weak_deps` are
/// translated into libsolv jobs/flags yet. What's wired up is the plain
/// `Requires` closure and Split mode's rule that a base package is never
/// erased (enforced by locking every base solvable before each solve).
pub fn resolve_ex(
    requested: &[String],
    candidates: &[Package],
    overlay: &OverlayContext,
    host_arch: &str,
    options: &ResolveOptions,
) -> Result<Plan> {
    // Svara ships no SELinux userspace (see the Split-mode notes in the
    // module doc comment), and a few upstream repos ship dependencies that
    // only make sense for one specific, unrelated requiring package
    // (`is_broken_repo_dep_edge_ignored`, e.g. `ffmpeg-libs` pulling in an
    // nvidia kmod for no reason). None of these are real needs, so they're
    // removed from `Requires` before the package reaches libsolv instead of
    // ever counting as unsatisfiable dependencies.
    let selinux_ignored_in_scope = !selinux_allowed();
    let base: Vec<Package> = overlay
        .base
        .iter()
        .map(|p| filter_pkg_deps(p, selinux_ignored_in_scope))
        .collect();
    let overlay_pkgs: Vec<Package> = overlay
        .overlay
        .iter()
        .map(|p| filter_pkg_deps(p, selinux_ignored_in_scope))
        .collect();
    let available: Vec<Package> = build_available_pool(candidates, selinux_ignored_in_scope);

    let mut build = vez_solv::build_pool_locked(
        host_arch,
        &base,
        &overlay_pkgs,
        &available,
        &options.locked_names,
    )?;
    let disfavor_names = compute_soname_disfavor_names(candidates);

    let try_solve =
        |build: &mut vez_solv::PoolBuild, names: &[String]| -> Result<vez_solv::SolveResult> {
            let mut install_names: Vec<(String, Option<String>)> = Vec::new();
            let mut pinned_installs: Vec<(String, String, String, String)> = Vec::new();
            for name in names {
                if let Some(nevra) = match_exact_nevra_request(name, candidates, host_arch) {
                    pinned_installs.push(nevra);
                } else {
                    let (base_name, arch) = split_name_arch_request(name, candidates, overlay);
                    install_names.push((base_name.to_string(), arch.map(str::to_string)));
                }
            }
            vez_solv::solve(
                build,
                &vez_solv::SolveRequest {
                    install_names,
                    pinned_installs,
                    installonly_names: options.installonly_pkgs.clone(),
                    protected_names: options.protected_names.clone(),
                    allow_erasing: options.allow_erasing,
                    multilib_all: options.multilib_all,
                    best: options.best,
                    obsoletes: options.obsoletes,
                    allow_downgrade: options.allow_downgrade,
                    install_weak_deps: options.install_weak_deps,
                    disfavor_names: disfavor_names.clone(),
                    ..Default::default()
                },
            )
        };

    // dnf5's `skip_broken=`/`--skip-broken`. Instead of failing the whole
    // `install` over one bad, renamed, or unavailable name, drop whichever
    // single name (tried one at a time) makes the request solvable, and keep
    // going until everything solves or no single removal helps. The latter is
    // a real multi-package interaction that skip_broken can't fix either;
    // dnf5 reports the failure at that point too. This is best-effort and not
    // a minimal unsat-core search. It covers the common case (one typo'd or
    // unavailable package among good ones in a scripted `vez install a b c`)
    // and not every pathological multi-name conflict.
    let mut remaining: Vec<String> = requested.to_vec();
    let mut skipped: Vec<String> = Vec::new();
    let result = loop {
        match try_solve(&mut build, &remaining) {
            Ok(r) => break r,
            Err(e) => {
                if !options.skip_broken || remaining.is_empty() {
                    return Err(e);
                }
                let culprit = (0..remaining.len()).find(|&i| {
                    let candidate_set: Vec<String> = remaining
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .map(|(_, n)| n.clone())
                        .collect();
                    try_solve(&mut build, &candidate_set).is_ok()
                });
                match culprit {
                    Some(i) => skipped.push(remaining.remove(i)),
                    None => return Err(e),
                }
            }
        }
    };

    // `result.to_upgrade` holds packages libsolv moved to a newer EVR as a
    // side effect of this install (e.g. syncing an installed x86_64 build to
    // the EVR of a newly requested i686 sibling, which avoids a multilib file
    // conflict). They're real transaction members, so they go into
    // `to_install`. rpm -U handles new installs and upgrades the same way,
    // and `apply_install_ex` decides Installing vs Upgrading by comparing
    // against what's on disk, whichever list a package came from here.
    let mut to_install: Vec<Package> = result
        .to_install
        .into_iter()
        .chain(result.to_upgrade)
        .collect();

    // `force_names` (used by `download`/`swap`). libsolv's by-name INSTALL
    // job does nothing when the identical NEVRA is already installed, so a
    // name whose only purpose is "fetch this package's RPM whatever its
    // install state" (e.g. `vez replay` re-fetching every
    // installed package before rebuilding the extra layer) would silently
    // drop out of `to_install`. (Before this, `options.force_names` was set
    // by callers but never read by the resolver.) Backfill such names from
    // what's installed, matched to a same-NEVRA candidate so the downloaded
    // file is byte-identical to what's on disk, or to the newest candidate
    // for that name/arch if no repo offers the exact EVR anymore.
    if !options.force_names.is_empty() {
        let present: HashSet<String> = to_install.iter().map(|p| p.nevra.name.clone()).collect();
        for name in &options.force_names {
            if present.contains(name) {
                continue;
            }
            let Some(installed) = overlay
                .base
                .iter()
                .chain(&overlay.overlay)
                .find(|p| p.nevra.name == *name)
            else {
                continue;
            };
            let exact = candidates.iter().find(|c| {
                c.nevra.name == installed.nevra.name
                    && c.nevra.evr() == installed.nevra.evr()
                    && c.nevra.arch == installed.nevra.arch
            });
            let pick = exact.or_else(|| {
                candidates
                    .iter()
                    .filter(|c| {
                        c.nevra.name == installed.nevra.name && c.nevra.arch == installed.nevra.arch
                    })
                    .max_by(|a, b| a.nevra.evr().as_str().compare_evr(b.nevra.evr().as_str()))
            });
            if let Some(pkg) = pick {
                to_install.push(pkg.clone());
            }
        }
    }

    reject_downgrades_if_disallowed(&to_install, overlay, options)?;

    Ok(Plan {
        to_install,
        already_satisfied: Vec::new(),
        to_obsolete: result.to_obsolete,
        to_erase: result.to_erase,
        skipped,
        already_installed: result.already_installed,
        to_upgrade: Vec::new(),
    })
}

/// `SOLVER_FLAG_ALLOW_DOWNGRADE` only covers implicit dependency resolution.
/// It doesn't stop libsolv from honoring an *explicit* pinned-NEVRA install
/// job for a build older than the installed one. dnf5 enforces
/// `--no-allow-downgrade` for that case itself, so we do the same and reject
/// it up front instead of letting the transaction reach `rpm -U`, which would
/// fail anyway without `--oldpackage`.
fn reject_downgrades_if_disallowed(
    to_install: &[Package],
    overlay: &OverlayContext,
    options: &ResolveOptions,
) -> Result<()> {
    if options.allow_downgrade {
        return Ok(());
    }
    let installed: HashMap<(&str, &str), String> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .map(|p| {
            (
                (p.nevra.name.as_str(), p.nevra.arch.as_str()),
                p.nevra.evr(),
            )
        })
        .collect();
    for pkg in to_install {
        if let Some(old_evr) = installed.get(&(pkg.nevra.name.as_str(), pkg.nevra.arch.as_str())) {
            if pkg.nevra.evr().as_str().compare_evr(old_evr).is_lt() {
                anyhow::bail!(
                    "package {}-{} (which is newer than {}) is already installed — pass --allow-downgrade to downgrade",
                    pkg.nevra.name,
                    old_evr,
                    pkg.nevra
                );
            }
        }
    }
    Ok(())
}

/// The SELinux/broken-repo-dep filtering `resolve_ex` does before building
/// the pool, shared with the `upgrade`/`distro-sync`/pinned
/// downgrade-or-reinstall entry points below so they all decide it the same
/// way.
fn build_filtered_pool(
    candidates: &[Package],
    overlay: &OverlayContext,
    host_arch: &str,
    locked_names: &[vez_core::VersionLock],
) -> Result<vez_solv::PoolBuild> {
    let selinux_ignored_in_scope = !selinux_allowed();
    let base: Vec<Package> = overlay
        .base
        .iter()
        .map(|p| filter_pkg_deps(p, selinux_ignored_in_scope))
        .collect();
    let overlay_pkgs: Vec<Package> = overlay
        .overlay
        .iter()
        .map(|p| filter_pkg_deps(p, selinux_ignored_in_scope))
        .collect();
    let available: Vec<Package> = build_available_pool(candidates, selinux_ignored_in_scope);
    vez_solv::build_pool_locked(host_arch, &base, &overlay_pkgs, &available, locked_names)
}

/// `vez upgrade [names...]` / `vez system-upgrade`, like dnf5's `add_upgrade`
/// (`SOLVER_UPDATE`): the named packages (or every installed package if
/// `names` is empty) move to their newest available EVR. A name with nothing
/// newer is left alone instead of being an error, unlike the install jobs in
/// [`resolve_ex`].
pub fn resolve_upgrade(
    names: &[String],
    candidates: &[Package],
    overlay: &OverlayContext,
    host_arch: &str,
    options: &ResolveOptions,
) -> Result<Plan> {
    let mut build = build_filtered_pool(candidates, overlay, host_arch, &options.locked_names)?;

    let result = vez_solv::solve(
        &mut build,
        &vez_solv::SolveRequest {
            upgrade_names: names.to_vec(),
            upgrade_all: names.is_empty(),
            install_names: Vec::new(),
            installonly_names: options.installonly_pkgs.clone(),
            protected_names: options.protected_names.clone(),
            allow_erasing: options.allow_erasing,
            best: options.best,
            allow_downgrade: options.allow_downgrade,
            install_weak_deps: options.install_weak_deps,
            disfavor_names: compute_soname_disfavor_names(candidates),
            ..Default::default()
        },
    )?;
    let to_upgrade = result.to_upgrade;
    let to_install: Vec<Package> = result
        .to_install
        .into_iter()
        .chain(to_upgrade.clone())
        .collect();
    Ok(Plan {
        to_install,
        already_satisfied: Vec::new(),
        to_obsolete: result.to_obsolete,
        to_erase: result.to_erase,
        skipped: Vec::new(),
        already_installed: Vec::new(),
        to_upgrade,
    })
}

/// `vez distro-sync [names...]`, like dnf5's `add_distro_sync`
/// (`SOLVER_DISTUPGRADE`): the named packages (or every installed package)
/// are made to match what the enabled repos offer now, downgrading if that's
/// what's available. `resolve_upgrade` never downgrades.
pub fn resolve_distro_sync(
    names: &[String],
    candidates: &[Package],
    overlay: &OverlayContext,
    host_arch: &str,
    options: &ResolveOptions,
) -> Result<Plan> {
    let mut build = build_filtered_pool(candidates, overlay, host_arch, &options.locked_names)?;
    let result = vez_solv::solve(
        &mut build,
        &vez_solv::SolveRequest {
            distro_sync_names: names.to_vec(),
            distro_sync_all: names.is_empty(),
            installonly_names: options.installonly_pkgs.clone(),
            protected_names: options.protected_names.clone(),
            allow_erasing: options.allow_erasing,
            best: options.best,
            allow_downgrade: options.allow_downgrade,
            install_weak_deps: options.install_weak_deps,
            disfavor_names: compute_soname_disfavor_names(candidates),
            ..Default::default()
        },
    )?;
    let to_upgrade = result.to_upgrade;
    let to_install: Vec<Package> = result
        .to_install
        .into_iter()
        .chain(to_upgrade.clone())
        .collect();
    Ok(Plan {
        to_install,
        already_satisfied: Vec::new(),
        to_obsolete: result.to_obsolete,
        to_erase: result.to_erase,
        skipped: Vec::new(),
        already_installed: Vec::new(),
        to_upgrade,
    })
}

/// `vez downgrade`/`vez reinstall`. `targets` is a set of exact NEVRAs the
/// caller already picked: `sync_packages` in vez-cli does its own "highest
/// older EVR" / "exact same EVR" selection, because that's vez's policy and
/// libsolv's job model has no direct way to say it. This gets the chosen
/// target past libsolv's "already satisfied" no-op with a pinned
/// `SOLVER_SOLVABLE | SOLVER_INSTALL` job (like dnf5's
/// `add_downgrade`/`add_reinstall`), so the transaction still goes through a
/// real dependency solve and Split mode's base-package lock instead of being
/// trusted as-is.
pub fn resolve_pinned(
    targets: &[Package],
    candidates: &[Package],
    overlay: &OverlayContext,
    host_arch: &str,
    options: &ResolveOptions,
) -> Result<Plan> {
    let mut build = build_filtered_pool(candidates, overlay, host_arch, &options.locked_names)?;
    let pinned_installs: Vec<(String, String, String, String)> = targets
        .iter()
        .map(|p| {
            (
                p.nevra.name.clone(),
                p.nevra.version.clone(),
                p.nevra.release.clone(),
                p.nevra.arch.clone(),
            )
        })
        .collect();
    let result = vez_solv::solve(
        &mut build,
        &vez_solv::SolveRequest {
            pinned_installs,
            installonly_names: options.installonly_pkgs.clone(),
            protected_names: options.protected_names.clone(),
            allow_erasing: options.allow_erasing,
            allow_downgrade: options.allow_downgrade,
            install_weak_deps: options.install_weak_deps,
            ..Default::default()
        },
    )?;
    let to_install: Vec<Package> = result
        .to_install
        .into_iter()
        .chain(result.to_upgrade)
        .collect();
    // `vez downgrade` itself always implies `allow_downgrade: true`
    // (vez-cli's `sync_packages` picks the pinned target *because* it's
    // older). This guard only matters when `--no-allow-downgrade` is combined
    // with a pinned NEVRA install spec that names a build older than the
    // installed one (`vez install foo-1.0`).
    reject_downgrades_if_disallowed(&to_install, overlay, options)?;

    Ok(Plan {
        to_install,
        already_satisfied: Vec::new(),
        to_obsolete: result.to_obsolete,
        to_erase: result.to_erase,
        skipped: Vec::new(),
        already_installed: Vec::new(),
        to_upgrade: Vec::new(),
    })
}

/// Works out every other installed overlay package that must also be `rpm
/// -e`d for `vez remove <names>` to apply cleanly. dnf's `remove` computes
/// and includes the same dependent closure (reported as "The following ...
/// will also be removed") instead of passing only the requested set to the
/// transaction and failing with rpm's unhelpful "Failed dependencies" error,
/// as a plain `rpm -e` would.
///
/// Iterates to a fixed point, because erasing one broken dependent can break
/// another package's Requires (removing `selinux-policy` breaks
/// `container-selinux`, `passt-selinux`, `flatpak-selinux`, ... in one pass,
/// but a deeper chain can take more). Only a `Requires` that something in the
/// removal set actually satisfied gets rechecked, never a package's whole
/// Requires list. rpmdb-sourced `Package` entries lack the implicit
/// file-based Provides rpm generates, so a blanket check gives false
/// positives across the system.
pub fn compute_removal_closure(requested: &[Package], overlay: &OverlayContext) -> Vec<Package> {
    let mut closure: Vec<Package> = Vec::new();
    let mut removed: Vec<Package> = requested.to_vec();
    let all_installed: Vec<&Package> = overlay.base.iter().chain(&overlay.overlay).collect();

    // Two optimizations. `all_installed` and each package's `requires` don't
    // change between rounds, so each package's requires are expanded once up
    // front instead of re-parsing every requires string on every iteration.
    // And `removed`/`closure` membership is tracked in a `HashSet<Nevra>`, so
    // the per-package "already handled" check is O(1) instead of an
    // O(removed.len() + closure.len()) scan for every installed package every
    // round.
    let expanded_requires: Vec<(&Package, Vec<Dependency>)> = overlay
        .overlay
        .iter()
        .map(|p| (p, expand_rich_requires(p.requires.iter(), &all_installed)))
        .collect();
    let mut removed_set: HashSet<vez_core::Nevra> =
        removed.iter().map(|p| p.nevra.clone()).collect();
    let mut closure_set: HashSet<vez_core::Nevra> = HashSet::new();

    for _ in 0..8 {
        let providers: Vec<&Package> = overlay
            .overlay
            .iter()
            .filter(|p| !removed_set.contains(&p.nevra) && !closure_set.contains(&p.nevra))
            .chain(&overlay.base)
            .collect();
        let newly_broken: Vec<&Package> = expanded_requires
            .iter()
            .filter(|(installed, _)| {
                !removed_set.contains(&installed.nevra) && !closure_set.contains(&installed.nevra)
            })
            .filter(|(_, reqs)| {
                reqs.iter().any(|req| {
                    removed.iter().any(|r| dep_matches_pkg(req, r))
                        && !providers.iter().any(|p| dep_matches_pkg(req, p))
                })
            })
            .map(|(installed, _)| *installed)
            .collect();
        if newly_broken.is_empty() {
            break;
        }
        removed.extend(newly_broken.iter().map(|p| (*p).clone()));
        removed_set.extend(newly_broken.iter().map(|p| p.nevra.clone()));
        closure_set.extend(newly_broken.iter().map(|p| p.nevra.clone()));
        closure.extend(newly_broken.into_iter().cloned());
    }

    closure
}

/// Escape hatch for the SELinux Requires stripping below: set
/// `VEZ_ALLOW_SELINUX=1` (or any non-empty value) to let SELinux packages go
/// through dependency resolution like any other package.
fn selinux_allowed() -> bool {
    std::env::var_os("VEZ_ALLOW_SELINUX").is_some_and(|v| !v.is_empty())
}

/// Svara ships no SELinux userspace (no `selinux-policy`, no
/// `policycoreutils`, kernel/init built without it). Only `libselinux` stays,
/// because plenty of unrelated packages link against `libselinux.so.1` at
/// build time even on systems that never enforce a policy. A repo package's
/// hard `Requires: selinux-policy` (or `policycoreutils`, `rpm-plugin-selinux`,
/// etc., which real Fedora packages often carry even though nothing on a
/// system without SELinux needs them) can never be satisfied here, so it must
/// never block an otherwise installable package or get pulled in as a
/// candidate. Found while debugging `steamos-manager-powerstation`: its
/// `Requires: selinux-policy` chain ended in `rpm-plugin-selinux`'s exact-EVR
/// pin on `rpm-libs`, which the Fedora repos and Svara's own (newer than
/// Fedora's) `rpm` build could never agree on. A distro that never installs
/// any of this doesn't have that problem.
fn is_selinux_ignored(name: &str) -> bool {
    if name == "libselinux" || name.starts_with("libselinux-") || name.starts_with("libselinux(") {
        return false;
    }
    // Fedora's packaging convention: a package's own SELinux policy module
    // ships as a `<name>-selinux` subpackage (e.g. `container-selinux`,
    // `docker-selinux`, `abrt-addon-selinux`). Svara never wants a main
    // package to drag in its `-selinux` sibling either, so this matches the
    // suffix instead of using a fixed list.
    let base = name.split('(').next().unwrap_or(name);
    if base == "selinux" || base.ends_with("-selinux") {
        return true;
    }
    const IGNORED: &[&str] = &[
        "selinux-policy",
        "policycoreutils",
        "checkpolicy",
        "mcstrans",
        "setroubleshoot",
        "secilc",
        "rpm-plugin-selinux",
        "selinux-policy-any",
        "selinux-policy-base",
    ];
    IGNORED.iter().any(|p| {
        name == *p || name.starts_with(&format!("{p}-")) || name.starts_with(&format!("{p}("))
    })
}

/// Ignores broken repo metadata for one specific *requiring* package, instead
/// of every occurrence of the capability name. nvidia's kmod/dkms packages
/// have to stay installable as usual (an explicit `vez install akmod-nvidia`,
/// or the driver meta-package's own internal `Requires` on `dkms-nvidia-*`).
/// Ignoring the capability name everywhere would silently break resolution of
/// nvidia's driver stack whenever something really needs it.
///
/// Reported case: `ffmpeg-libs.i686` (pulled in only as a transitive 32-bit
/// codec dependency: `steam.i686` -> `gtk2.i686` -> `gdk-pixbuf2.i686` ->
/// `glycin-libs.i686` -> `glycin-loaders.i686` -> `libheif.i686`) carries a
/// `Requires: dkms-nvidia-580`, whose `nvidia-580-kmod-common` dependency
/// this repo pool doesn't provide. Installing 32-bit codec/compat libraries
/// for Steam should never need a kernel module, proprietary or not. It's
/// broken metadata in this one package, so only *this* package's edge to the
/// nvidia dkms/akmod family is ignored, and every other path to those
/// packages (including a direct request) still works.
///
/// Second reported case: `tuned` carries `Requires: (rpm-ostree if bootc)`, a
/// conditional Requires that becomes hard once `bootc` is in the same
/// transaction. On a Svara image build `bootc` is *always* there (it's part
/// of the base image), so every `tuned` install pulled in `rpm-ostree` and
/// its `llvm-libs`-sized dependency chain. Svara is bootc-based but never
/// runs `rpm-ostree` (image builds go through `vez` in
/// standalone/direct-rpmdb mode, without `rpm-ostree` package layering).
/// `tuned` works fine without it; the conditional Requires only exists so
/// `tuned`'s bootc integration can call an `rpm-ostree` binary Svara never
/// uses. Checked with podman/dnf5 that this isn't a vez-specific libsolv
/// quirk (dnf5 pulls in the same thing), and that removing `rpm-ostree`
/// afterwards doesn't work either: rpm's erase-time dependency check treats
/// the conditional Requires as hard once both packages are installed and
/// forces `tuned` out with it (`--no-autoremove` doesn't help, since it only
/// controls orphan sweeping and not reverse-dependency checks). Stripping the
/// edge before it reaches libsolv is the only place to fix this without
/// making every caller use `rpm -e --nodeps`.
fn is_broken_repo_dep_edge_ignored(requiring_pkg: &str, dep_name: &str) -> bool {
    (requiring_pkg == "ffmpeg-libs"
        && (dep_name.starts_with("dkms-nvidia")
            || dep_name.starts_with("akmod-nvidia")
            || dep_name.starts_with("kmod-nvidia")
            || (dep_name.starts_with("nvidia-") && dep_name.contains("-kmod"))))
        || (requiring_pkg == "tuned"
            && matches!(parse_boolean_dep(dep_name), Some(BoolExpr::If(a, b)) if a == "rpm-ostree" && b == "bootc"))
}

/// Kernel-module packaging convention (`dkms-*`/`akmod-*`/`kmod-*`), covering
/// nvidia, virtualbox, zfs, and anything else built this way. These packages
/// sometimes carry unrelated `Provides:` as well (bundled userspace libs),
/// which lets them tie on "provides capability X" with an ordinary package
/// that provides the same thing without a kernel module. See the doc comment
/// on [`is_broken_repo_dep_edge_ignored`] for the case this addresses:
/// `dkms-nvidia-580` outranking `mesa-libGL`/`libglvnd` for
/// `libglvnd-glx(x86-32)`. Only used to break ties between providers and
/// never to exclude these packages, so a direct request (or one where it's
/// the only provider) still resolves normally.
fn is_driver_package(name: &str) -> bool {
    name.starts_with("dkms-") || name.starts_with("akmod-") || name.starts_with("kmod-")
}

/// Extracts the base name from an rpm auto-generated soname `Requires`
/// capability (`libfoo.so.N()(64bit)`, `libfoo.so.N`, ...) with any `lib`
/// prefix stripped. Returns `None` if `dep_name` doesn't look like a soname
/// capability (no literal `.so` in it); plain package and virtual-provide
/// names are left alone.
fn soname_stem(dep_name: &str) -> Option<String> {
    let base = dep_name.split(".so").next()?;
    if base.len() == dep_name.len() {
        return None;
    }
    let base = base.strip_prefix("lib").unwrap_or(base);
    if base.is_empty() {
        None
    } else {
        Some(base.to_ascii_lowercase())
    }
}

/// True when `pkg_name` looks like the real library package behind a soname
/// `stem` (from [`soname_stem`]): its name contains the library's base name
/// or the other way round, ignoring a leading `lib` and case. The alternative
/// is an unrelated application that bundles a private copy of that soname.
/// Real case: `libvulkan.so.1()(64bit)` and `libavcodec.so.62()(64bit)` are
/// each provided both by a small dedicated library package (`vulkan-loader`,
/// `libavcodec`) and by `opera-beta`/`floorp`, which vendor private copies
/// under `/opt/...` for the browser's own use. EVR, repo priority, and exact
/// name matching don't separate them, so without this tiebreaker libsolv's
/// arbitrary choice among equal candidates picked the 100+ MiB browser over
/// the sub-1 MiB library and dragged a whole unrelated browser into a
/// transaction that only asked for a codec/pipewire lib or a gstreamer
/// plugin. Only a tiebreaker (see [`matching_providers_raw`]); it never
/// excludes a candidate, so `vez install opera-beta` itself still works.
fn looks_like_real_lib_provider(pkg_name: &str, stem: &str) -> bool {
    let name = pkg_name.to_ascii_lowercase();
    let name_core = name.strip_prefix("lib").unwrap_or(&name);
    !name_core.is_empty() && (name_core.contains(stem) || stem.contains(name_core))
}

/// The fix for the floorp/opera-beta browser-pull bug (see the doc comment on
/// [`looks_like_real_lib_provider`] for the case). Automatic, transitive
/// `Requires` resolution for `vez install` doesn't use this crate's candidate
/// ranking at all: `resolve_ex` and its siblings hand the whole candidate
/// pool to libsolv (`vez_solv::solve`), which picks providers itself for
/// every `Requires` it satisfies. Sorting a candidate list on the Rust side
/// (as `matching_providers_raw` does, only for `check_closure`/`vez
/// repoclosure`) never reaches that decision; testing confirmed it has no
/// effect on a real transaction.
///
/// This scans every candidate's `Provides` for anything that looks like an
/// auto-generated soname capability, groups providers by [`soname_stem`], and
/// for each stem that's provided both by "real" library packages (per
/// [`looks_like_real_lib_provider`]) and by unrelated packages bundling a
/// private copy of the same soname, returns the unrelated packages' names.
/// These go into `vez_solv::SolveRequest::disfavor_names`, which pushes
/// libsolv's choice away from them (`SOLVER_DISFAVOR`) without excluding
/// them, so `vez install opera-beta` still works.
fn compute_soname_disfavor_names(candidates: &[Package]) -> Vec<String> {
    let mut providers_by_stem: HashMap<String, HashSet<&str>> = HashMap::new();
    for pkg in candidates {
        for prov in &pkg.provides {
            if let Some(stem) = soname_stem(&prov.name) {
                providers_by_stem
                    .entry(stem)
                    .or_default()
                    .insert(pkg.nevra.name.as_str());
            }
        }
    }
    let mut disfavor: HashSet<String> = HashSet::new();
    for (stem, names) in &providers_by_stem {
        if names.len() < 2 {
            continue;
        }
        let (real, bundled): (Vec<&&str>, Vec<&&str>) = names
            .iter()
            .partition(|name| looks_like_real_lib_provider(name, stem));
        if !real.is_empty() {
            for name in bundled {
                disfavor.insert(name.to_string());
            }
        }
    }
    disfavor.into_iter().collect()
}

/// Maps an explicit ISA suffix on a capability name (rpm's way of asking for
/// the *other* arch's copy) to the arch it names. Returns `None` for a
/// capability without such a suffix; the dependency then keeps the arch hint
/// it already had. `host_arch` resolves the generic `(64bit)`/`(32bit)`
/// markers, which don't name a specific arch by themselves, unlike
/// `(x86-32)`/`(x86-64)`.
fn isa_arch(name: &str, host_arch: &str) -> Option<String> {
    let suffix = name
        .rsplit_once('(')
        .filter(|(_, rest)| rest.ends_with(')'))
        .map(|(_, rest)| &rest[..rest.len() - 1])?;
    match suffix {
        "x86-32" => Some("i686".to_string()),
        "x86-64" => Some("x86_64".to_string()),
        "64bit" if host_arch == "x86_64" => Some("x86_64".to_string()),
        "32bit" if host_arch == "x86_64" => Some("i686".to_string()),
        _ => None,
    }
}

/// Repo-wide dependency-closure check for `vez repoclosure`. For every
/// candidate whose name matches at least one of `name_patterns` (globs
/// allowed; an empty list matches everything), checks that each of its
/// `Requires` can be satisfied by *some* candidate in the full pool. It
/// checks the whole pool, not just what [`resolve`] would pull in for one
/// install, because the point is finding gaps across the repo instead of
/// simulating one transaction. Boolean/rich deps (`(a and b)`, `(a if b)`,
/// ...) and `rpmlib(...)` markers are skipped, the latter the same way
/// [`resolve_ex`] treats them. dnf's repoclosure doesn't evaluate rich dep
/// expressions either. Returns one entry per package with at least one
/// unresolved `Requires`, paired with the list of unresolved capability
/// names.
pub fn check_closure(
    candidates: &[Package],
    name_patterns: &[String],
    host_arch: &str,
) -> Vec<(String, Vec<String>)> {
    let index = CandidateIndex::build(candidates);
    let mut results = Vec::new();
    for pkg in candidates {
        if !name_patterns.is_empty() && !vez_core::name_matches_any(&pkg.nevra.name, name_patterns)
        {
            continue;
        }
        let mut missing = Vec::new();
        for req in &pkg.requires {
            if req.name.starts_with("rpmlib(") || parse_boolean_dep(&req.name).is_some() {
                continue;
            }
            let dep_arch = isa_arch(&req.name, host_arch);
            let hard_filter = dep_arch.is_some() || req.name.contains(".so");
            let providers = matching_providers_raw(
                &index,
                req,
                dep_arch.as_deref().or(Some(pkg.nevra.arch.as_str())),
                host_arch,
                hard_filter,
            );
            if providers.is_empty() {
                missing.push(req.name.clone());
            }
        }
        if !missing.is_empty() {
            results.push((pkg.nevra.to_string(), missing));
        }
    }
    results
}

/// True if a package built for `pkg_arch` can be installed on `host_arch`:
/// the same arch, `noarch`, or the host's 32-bit compat family (the x86
/// family on x86_64 or x86, 32-bit ARM on aarch64 or 32-bit ARM).
fn arch_compatible(pkg_arch: &str, host_arch: &str) -> bool {
    if pkg_arch == host_arch || pkg_arch == "noarch" {
        return true;
    }
    const X86_32: &[&str] = &["i386", "i486", "i586", "i686"];
    const ARM_32: &[&str] = &["armv7hl", "armv6hl", "armhfp"];
    if host_arch == "x86_64" {
        return X86_32.contains(&pkg_arch);
    }
    if X86_32.contains(&host_arch) {
        return X86_32.contains(&pkg_arch);
    }
    if host_arch == "aarch64" {
        return ARM_32.contains(&pkg_arch);
    }
    if ARM_32.contains(&host_arch) {
        return ARM_32.contains(&pkg_arch);
    }
    false
}

fn matching_providers_raw<'a>(
    index: &CandidateIndex<'a>,
    dep: &Dependency,
    preferred_arch: Option<&str>,
    host_arch: &str,
    hard_arch_filter: bool,
) -> Vec<&'a Package> {
    let target_arch = preferred_arch.unwrap_or(host_arch);
    let mut seen: HashSet<usize> = HashSet::new();
    let mut v: Vec<&Package> = index
        .lookup(&dep.name)
        .iter()
        .copied()
        .filter(|p| dep_matches_pkg(dep, p))
        .filter(|p| arch_compatible(&p.nevra.arch, host_arch))
        .filter(|p| seen.insert(*p as *const Package as usize))
        .collect();
    // A plain dependency (no ISA tag) stays within the requesting package's
    // own arch family where possible. rpm only crosses arches when the
    // capability text itself is ISA-tagged (handled separately: `isa_arch`
    // overrides the arch hint before this runs) or when nothing in the
    // preferred arch/noarch provides it (e.g. a noarch-only capability, or a
    // provider that only exists in the foreign arch). Without this, a
    // capability that happens to be provided by both arches (unusual, but
    // possible) could be satisfied by whichever arch the solver reached
    // first, which would make the arch hint pointless. It only applies to a
    // real `Requires` relationship (`hard_arch_filter`). A top-level *user*
    // request, or a Conflicts/Obsoletes match, has no requesting package arch
    // to stay within and may still fall back to a foreign-arch build if
    // that's the only one that works. dnf does exactly this for `steam`,
    // whose x86_64 build has an unsatisfiable transitive dependency in this
    // test repo's snapshot and falls back to the i686 build.
    if hard_arch_filter {
        let same_family: Vec<&Package> = v
            .iter()
            .copied()
            .filter(|p| p.nevra.arch == target_arch || p.nevra.arch == "noarch")
            .collect();
        if !same_family.is_empty() {
            v = same_family;
        }
    }
    let soname_stem = soname_stem(&dep.name);
    // Compute each candidate's sort key once (Schwartzian transform) instead
    // of recomputing
    // `is_driver_package`/`looks_like_real_lib_provider`/`arch_rank` inside
    // the comparator, which `sort_by` calls O(n log n) times for the same few
    // candidates during dependency-heavy resolves.
    struct SortKey<'p> {
        // A package whose real `Name:` equals the requested capability
        // outranks one that only `Provides` it, whatever the versions. Same
        // as dnf/rpm: `Provides` lets a capability resolve to a package with
        // a different real name; it isn't meant to let an unrelated (or
        // channel-variant) package outbid the one actually named. Example:
        // `brave-browser-nightly` carries `Provides: brave-browser` so other
        // packages' `Requires: brave-browser` resolve whichever channel is
        // installed. It outranked the real `brave-browser` package on EVR
        // alone (nightly versions are higher than stable), so `vez install
        // brave-browser` silently installed nightly.
        exact: bool,
        // A `dkms-`/`akmod-`/`kmod-` kernel-module package (nvidia,
        // virtualbox, zfs, ...) only belongs in a transaction when something
        // asked for it *by name*, never as an incidental provider of some
        // unrelated virtual capability. Real case: `dkms-nvidia-580` carries
        // `Provides: libglvnd-glx(x86-32)` (bundled GL dispatch libs), which
        // let it outrank `mesa-libGL`/`libglvnd` for that capability and drag
        // the whole nvidia driver stack into a `qt6-qtbase-devel` install.
        // Only applies when neither side is the exact-name match above, so
        // `vez install dkms-nvidia-580` itself is unaffected.
        driver: bool,
        // A candidate whose name looks like the real library behind a soname
        // `Requires` outranks one that only bundles a private copy of that
        // soname (see the doc comment on `looks_like_real_lib_provider`, the
        // floorp/opera-beta browser-pull bug). Always `false` for a
        // capability that isn't a soname (`soname_stem` is `None`).
        real_lib: bool,
        arch_rank: u8,
        repo_priority: u32,
        repo_cost: u32,
        // Group by real name *before* comparing EVR, so EVR only breaks ties
        // between two builds of the *same* package (pick the newer one) and
        // never across different names. For an ambiguous virtual capability
        // without an exact-name provider (e.g. `desktop-notification-daemon`,
        // provided by dozens of unrelated packages), comparing EVR strings
        // across names means nothing: `gnome-shell`'s "50.4" beat
        // `notification-daemon`'s "3.20.0" only because it's a bigger number.
        // Such a Requires always resolved to whichever unrelated provider had
        // the largest version number, which silently pulled in a whole
        // desktop shell (gdm/mutter/gnome-session and everything under them)
        // behind a printer-config tool's notification-daemon dependency.
        // Comparing name before EVR, instead of a pairwise `if a.name ==
        // b.name` branch, keeps this a valid total order: sorting needs
        // transitivity across the whole candidate set, and a field that's
        // only compared when names match can form a cycle once three or more
        // different names/repos are involved.
        name: &'p str,
        evr: String,
        repo_id: &'p str,
        arch: &'p str,
    }
    let mut keyed: Vec<(SortKey, &Package)> = v
        .into_iter()
        .map(|p| {
            let key = SortKey {
                exact: p.nevra.name == dep.name,
                driver: is_driver_package(&p.nevra.name),
                real_lib: soname_stem
                    .as_deref()
                    .is_some_and(|stem| looks_like_real_lib_provider(&p.nevra.name, stem)),
                arch_rank: arch_rank(&p.nevra.arch, target_arch),
                repo_priority: p.repo_priority,
                repo_cost: p.repo_cost,
                name: p.nevra.name.as_str(),
                evr: p.nevra.evr(),
                repo_id: p.repo_id.as_str(),
                arch: p.nevra.arch.as_str(),
            };
            (key, p)
        })
        .collect();
    keyed.sort_by(|(a, _), (b, _)| {
        b.exact
            .cmp(&a.exact)
            .then_with(|| a.driver.cmp(&b.driver))
            .then_with(|| b.real_lib.cmp(&a.real_lib))
            .then_with(|| a.arch_rank.cmp(&b.arch_rank))
            .then_with(|| a.repo_priority.cmp(&b.repo_priority))
            .then_with(|| a.repo_cost.cmp(&b.repo_cost))
            .then_with(|| a.name.cmp(b.name))
            .then_with(|| b.evr.as_str().compare_evr(a.evr.as_str()))
            .then_with(|| a.repo_id.cmp(b.repo_id))
            .then_with(|| a.arch.cmp(b.arch))
    });
    keyed.into_iter().map(|(_, p)| p).collect()
}

/// Ranks an arch against the arch we're aiming for: 0 for an exact match, 1
/// for `noarch`, 2 for anything else. Lower sorts first.
fn arch_rank(arch: &str, target_arch: &str) -> u8 {
    if arch == target_arch {
        0
    } else if arch == "noarch" {
        1
    } else {
        2
    }
}

/// True if `dep` (a Requires, Conflicts, or Obsoletes entry) matches `pkg`,
/// either by name+EVR directly or via one of `pkg`'s Provides.
fn dep_matches_pkg(dep: &Dependency, pkg: &Package) -> bool {
    if pkg.nevra.name == dep.name {
        return match &dep.constraint {
            None => true,
            Some(_) => dep.satisfied_by_evr(&pkg.nevra.evr()),
        };
    }
    if let Some((base, arch)) = strip_isa_suffix(&dep.name) {
        if pkg.nevra.name == base && pkg.nevra.arch == arch {
            let satisfied = match &dep.constraint {
                None => true,
                Some(_) => dep.satisfied_by_evr(&pkg.nevra.evr()),
            };
            if satisfied {
                return true;
            }
        }
    }
    pkg.provides.iter().any(|p| {
        p.name == dep.name
            && match (&dep.constraint, &p.constraint) {
                (None, _) => true,
                // rpm only compares versions when *both* sides have one. A
                // bare, unversioned `Provides: foo` (no EQ/GE/etc.) satisfies
                // a versioned `Requires: foo = X` by name alone, same as
                // rpm/dnf. Without this, a package whose Provides entry has
                // no version (common for a package self-providing a virtual
                // capability, e.g. a dkms package providing its own
                // `<name>-kmod`) would never satisfy any versioned Requires
                // on that capability.
                (Some(_), None) => true,
                (Some(_), Some((_, v))) => dep.satisfied_by_evr(v),
            }
    })
}

/// Strips a concrete rpm ISA suffix (`(x86-64)`/`(x86-32)`) off a capability
/// name, returning the bare name and the arch it names.
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

/// Expands rpm's conditional rich Requires (`(A if B)`, e.g.
/// `selinux-policy`'s `(rpm-plugin-selinux if rpm-libs)`) into a plain
/// `Requires: A` when `B` is currently satisfied. It's evaluated against the
/// installed set before the transaction, since that's what decided whether
/// the condition applied to this package in the first place. Only the
/// two-clause `(A if B)` form is handled; `unless`/`else` rich deps pass
/// through unexpanded (rare enough in practice not to bother yet). Without
/// this, `compute_removal_closure` never sees these as real Requires (the raw
/// string matches no package name), so it misses the
/// broken-consumer-after-upgrade cases rpm itself would reject at `rpm -U`
/// time with a "Failed dependencies" error.
fn expand_rich_requires<'a>(
    reqs: impl Iterator<Item = &'a Dependency>,
    all_installed: &[&Package],
) -> Vec<Dependency> {
    reqs.filter_map(|req| {
        let Some(inner) = req.name.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
            return Some(req.clone());
        };
        let mut parts = inner.splitn(2, " if ");
        let a = parts.next()?.trim();
        let b = parts.next()?.trim();
        // Rich deps can chain " else "/" unless " onto the condition. Strip
        // that off, since only the simple `if` clause is evaluated.
        let b = b.split(" else ").next().unwrap_or(b).trim();
        let cond = Dependency::unversioned(b);
        if all_installed.iter().any(|p| dep_matches_pkg(&cond, p)) {
            Some(Dependency::unversioned(a))
        } else {
            None
        }
    })
    .collect()
}

/// True if `chosen`'s Obsoletes list covers `candidate`, by *name*, but never
/// within the same package name. A legacy-compat package often both Provides
/// an old capability name *and* Obsoletes an old version of it (e.g.
/// `libjpeg-turbo` Provides `libjpeg = 6b-47.fc42` for backward compatibility
/// while Obsoleting `libjpeg < 6b-47`), and the i686/x86_64 builds of that
/// same package have to coexist (multilib) without one arch's Obsoletes
/// excluding the other arch's compat Provides.
#[derive(Debug)]
enum BoolExpr {
    If(String, String),
    /// `(A if B else C)`, rpm's ternary form: require `A` when `B` holds,
    /// otherwise require `C`. A plain `If` requires nothing when its
    /// condition doesn't hold.
    IfElse(String, String, String),
    Unless(String, String),
    Or(String, String),
    And(String, String),
    With(String, String),
    Without(String, String),
}

impl BoolExpr {
    fn operands(&self) -> Vec<&str> {
        match self {
            BoolExpr::If(a, b)
            | BoolExpr::Unless(a, b)
            | BoolExpr::Or(a, b)
            | BoolExpr::And(a, b)
            | BoolExpr::With(a, b)
            | BoolExpr::Without(a, b) => {
                vec![a.as_str(), b.as_str()]
            }
            BoolExpr::IfElse(a, b, c) => vec![a.as_str(), b.as_str(), c.as_str()],
        }
    }
}

/// A rich/boolean dependency's operands (e.g. the `A` in `(A if B)`) are
/// plain text, not separate XML attributes. So an operand like
/// `mesa-dri-drivers(x86-32) = 25.1.9-1.fc42` still has its version
/// constraint embedded in the text and needs the same `name <op> version`
/// splitting that `vez-rpmdb::parse_nevrs` does for `rpm -qa` output.
fn parse_dep_str(s: &str) -> Dependency {
    let mut parts = s.splitn(3, ' ');
    let name = parts.next().unwrap_or_default().to_string();
    let op = parts.next();
    let ver = parts.next();
    match (op, ver) {
        (Some(op), Some(ver)) => {
            let cmp = match op {
                "<" => Some(vez_core::Comparator::Lt),
                "<=" => Some(vez_core::Comparator::Le),
                "=" => Some(vez_core::Comparator::Eq),
                ">=" => Some(vez_core::Comparator::Ge),
                ">" => Some(vez_core::Comparator::Gt),
                _ => None,
            };
            match cmp {
                Some(cmp) => Dependency {
                    name,
                    constraint: Some((cmp, ver.to_string())),
                },
                None => Dependency::unversioned(s.to_string()),
            }
        }
        _ => Dependency::unversioned(s.to_string()),
    }
}

/// Strips one layer of redundant parens around a boolean-dep operand. rpm
/// emits things like `((linux-firmware >= X) if linux-firmware)`, where the
/// `if` operand is wrapped again. Without this, the operand's leading `(`
/// stays glued to its capability name (parsed as `"(linux-firmware"` instead
/// of `"linux-firmware"`), which matches no provider and makes the whole
/// boolean dependency unsatisfiable. Only strips when the parens really
/// enclose the whole string (not just when the first and last characters
/// happen to be parens).
fn strip_balanced_parens(s: &str) -> String {
    let mut s = s;
    while let Some(inner) = s.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        // Check that the opening '(' is matched by the closing ')' at the
        // very end and not by some earlier ')' inside `inner`, i.e. depth
        // never drops to 0 before the last character.
        let mut depth = 0i32;
        let mut closes_early = false;
        let last = inner.char_indices().last().map(|(i, _)| i);
        for (i, c) in inner.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && Some(i) != last {
                        closes_early = true;
                        break;
                    }
                }
                _ => {}
            }
        }
        if closes_early || depth != 0 {
            break;
        }
        s = inner.trim();
    }
    s.to_string()
}

/// Scans `inner` for a top-level `" if "` followed (still at paren depth 0)
/// by a later `" else "`: rpm's ternary `(A if B else C)` form. This has to
/// run before the plain binary-operator scan below. That scan finds the first
/// `" if "` and would otherwise treat everything after it (including the text
/// `" else C"`) as the condition of a plain `(A if B)`. The result is a
/// nonsense capability name that evaluates to "no provider" and makes the
/// whole rich dependency vacuously true. Reproduced with `zed`'s real
/// `(zed-cli-compat-zfs if zfs else zed-cli)` Requires: `zed-cli` never got
/// pulled in, even though `zed`'s `/usr/bin/zed` launcher lives in that
/// subpackage.
fn split_if_else(inner: &str) -> Option<(String, String, String)> {
    let mut depth = 0i32;
    let mut if_pos = None;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && if_pos.is_none() && inner[i..].starts_with(" if ") {
            if_pos = Some(i);
        }
    }
    let if_pos = if_pos?;
    let after_if = if_pos + " if ".len();
    let mut depth = 0i32;
    let mut else_pos = None;
    for (i, c) in inner[after_if..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && inner[after_if + i..].starts_with(" else ") {
            else_pos = Some(after_if + i);
            break;
        }
    }
    let else_pos = else_pos?;
    let a = strip_balanced_parens(inner[..if_pos].trim());
    let b = strip_balanced_parens(inner[after_if..else_pos].trim());
    let c = strip_balanced_parens(inner[else_pos + " else ".len()..].trim());
    if a.is_empty() || b.is_empty() || c.is_empty() {
        return None;
    }
    Some((a, b, c))
}

/// Parses a Requires entry name of the form `(A <op> B)` into a [`BoolExpr`],
/// where `<op>` is one of the RPM boolean dependency keywords. `A`/`B` can
/// contain balanced parens themselves (e.g. an ISA-suffixed capability like
/// `pipewire-alsa(x86-32)`), so the operator search only matches at paren
/// depth 0 within the outer expression. Returns `None` for an ordinary
/// (non-boolean) dependency name.
fn parse_boolean_dep(name: &str) -> Option<BoolExpr> {
    // Operands recursed into from a chained combinator (e.g. the `B with C
    // with D` remainder of `(A with B with C with D)`, or an operand already
    // unwrapped by `strip_balanced_parens`) are compound boolean expressions
    // themselves but no longer wrapped in an outer `(...)`. So strip a
    // wrapping layer whenever there is one. Unlike `strip_balanced_parens`
    // there's no closes-early check: the top-level `name` is always
    // `(...)`-wrapped, and requiring full balance would leave that wrapping
    // in place whenever the first inner group closes before the end (e.g.
    // `((A) if B)`). Then the recursive re-parse below would fail and the
    // whole sub-expression would be treated as one literal capability name.
    let inner = match name.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
        Some(inner) => inner,
        None => name,
    };
    if let Some((a, b, c)) = split_if_else(inner) {
        return Some(BoolExpr::IfElse(a, b, c));
    }
    const OPS: [(&str, fn(String, String) -> BoolExpr); 6] = [
        (
            " unless ",
            BoolExpr::Unless as fn(String, String) -> BoolExpr,
        ),
        (
            " without ",
            BoolExpr::Without as fn(String, String) -> BoolExpr,
        ),
        (" if ", BoolExpr::If as fn(String, String) -> BoolExpr),
        (" or ", BoolExpr::Or as fn(String, String) -> BoolExpr),
        (" and ", BoolExpr::And as fn(String, String) -> BoolExpr),
        (" with ", BoolExpr::With as fn(String, String) -> BoolExpr),
    ];

    let mut depth = 0i32;
    for (i, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            for (tok, make) in &OPS {
                if inner[i..].starts_with(tok) {
                    let a = strip_balanced_parens(inner[..i].trim());
                    let b = strip_balanced_parens(inner[i + tok.len()..].trim());
                    if !a.is_empty() && !b.is_empty() {
                        return Some(make(a, b));
                    }
                }
            }
        }
    }
    None
}

/// Recursively extracts the leaf capability names a `Requires` entry's raw
/// name refers to. For an ordinary dependency that's just the name. For a
/// boolean/rich dependency (e.g. `(python3.14dist(pyscard) < 3~~ with
/// python3.14dist(pyscard) >= 2)`) the string is a compound expression, and
/// simple consumers that only ask "does anything installed still require
/// capability X" (like `autoremove`'s orphan sweep) need the capability names
/// inside it. Otherwise a package required only through a rich dependency
/// looks unreferenced and gets removed, even though `rpm` itself refuses to
/// remove it.
pub fn boolean_dep_leaf_names(name: &str) -> Vec<String> {
    match parse_boolean_dep(name) {
        Some(expr) => {
            let mut out = Vec::new();
            for operand in expr.operands() {
                out.extend(boolean_dep_leaf_names(operand));
            }
            out
        }
        None => vec![parse_dep_str(name).name],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vez_core::Nevra;

    #[test]
    fn boolean_dep_leaf_names_flattens_chained_with_clauses() {
        // Real dnf5 rich dep from python3-httplib2's Requires on
        // python3.14dist(pyparsing): a 6-way `with` chain whose tail isn't
        // separately parenthesized. Regression test for `discover()` never
        // reaching the provider of a versioned `dist()` capability because
        // the chain's unparenthesized remainder was mangled into one garbage
        // leaf instead of being recursed into.
        let s = "((python3.14dist(pyparsing) < 3 or python3.14dist(pyparsing) > 3) with (python3.14dist(pyparsing) < 3.0.1 or python3.14dist(pyparsing) > 3.0.1) with (python3.14dist(pyparsing) < 3.0.2 or python3.14dist(pyparsing) > 3.0.2) with (python3.14dist(pyparsing) < 3.0.3 or python3.14dist(pyparsing) > 3.0.3) with python3.14dist(pyparsing) < 4~~ with python3.14dist(pyparsing) >= 2.4.2)";
        let leaves = boolean_dep_leaf_names(s);
        assert_eq!(leaves.len(), 10);
        assert!(leaves.iter().all(|n| n == "python3.14dist(pyparsing)"));
    }

    #[test]
    fn debug_split_if_else() {
        let parsed = parse_boolean_dep("(zed-cli-compat-zfs if zfs else zed-cli)");
        eprintln!("{:?}", parsed.as_ref().map(|e| e.operands()));
        match parsed {
            Some(BoolExpr::IfElse(a, b, c)) => {
                assert_eq!(a, "zed-cli-compat-zfs");
                assert_eq!(b, "zfs");
                assert_eq!(c, "zed-cli");
            }
            other => panic!("expected IfElse, got {other:?}"),
        }
    }

    fn pkg(name: &str, ver: &str, requires: Vec<Dependency>) -> Package {
        Package {
            nevra: Nevra {
                name: name.into(),
                epoch: 0,
                version: ver.into(),
                release: "1".into(),
                arch: "x86_64".into(),
            },
            summary: String::new(),
            provides: vec![],
            requires,
            conflicts: vec![],
            obsoletes: vec![],
            recommends: vec![],
            suggests: vec![],
            enhances: vec![],
            supplements: vec![],
            location: format!("{name}-{ver}-1.x86_64.rpm"),
            repo_id: "test".into(),
            repo_priority: 99,
            repo_cost: 1000,
            install_size: 0,
            download_size: 0,
            vendor: String::new(),
            checksum_type: String::new(),
            checksum: String::new(),
        }
    }

    fn pkg_arch(name: &str, ver: &str, arch: &str, requires: Vec<Dependency>) -> Package {
        let mut p = pkg(name, ver, requires);
        p.nevra.arch = arch.into();
        p.location = format!("{name}-{ver}-1.{arch}.rpm");
        p
    }

    fn resolve_x86_64(
        requested: &[String],
        candidates: &[Package],
        overlay: &OverlayContext,
    ) -> Result<Plan> {
        resolve(requested, candidates, overlay, "x86_64")
    }

    #[test]
    fn picks_highest_version() {
        let candidates = vec![pkg("foo", "1.0", vec![]), pkg("foo", "2.0", vec![])];
        let overlay = OverlayContext::for_test(vec![], vec![]);
        let plan = resolve_x86_64(&["foo".to_string()], &candidates, &overlay).unwrap();
        assert_eq!(plan.to_install.len(), 1);
        assert_eq!(plan.to_install[0].nevra.version, "2.0");
    }

    #[test]
    fn exact_nevra_request_installs_a_specific_build_alongside_installonly() {
        // `vez install kernel-2.0-1.x86_64` with `kernel-1.0-1` installed and
        // `installonlypkgs=kernel`. A plain `install kernel` is a same-name
        // no-op (see vez-solv's test of the same shape), but naming the exact
        // NEVRA must still install the second build side by side. That's why
        // version-pinned install specs exist.
        let candidates = vec![pkg("kernel", "1.0", vec![]), pkg("kernel", "2.0", vec![])];
        let overlay = OverlayContext::for_test(vec![], vec![pkg("kernel", "1.0", vec![])]);
        let options = ResolveOptions {
            installonly_pkgs: vec!["kernel".to_string()],
            ..Default::default()
        };
        let plan = resolve_ex(
            &["kernel-2.0-1.x86_64".to_string()],
            &candidates,
            &overlay,
            "x86_64",
            &options,
        )
        .unwrap();
        assert_eq!(plan.to_install.len(), 1);
        assert_eq!(plan.to_install[0].nevra.version, "2.0");
    }

    #[test]
    fn exact_nevra_request_without_arch_suffix_also_matches() {
        let candidates = vec![pkg("foo", "1.0", vec![])];
        let overlay = OverlayContext::for_test(vec![], vec![]);
        let plan = resolve_x86_64(&["foo-1.0-1".to_string()], &candidates, &overlay).unwrap();
        assert_eq!(plan.to_install.len(), 1);
        assert_eq!(plan.to_install[0].nevra.version, "1.0");
    }

    #[test]
    fn resolve_upgrade_reports_a_real_upgrade_in_to_upgrade() {
        let candidates = vec![pkg("foo", "1.0", vec![]), pkg("foo", "2.0", vec![])];
        let overlay = OverlayContext::for_test(vec![], vec![pkg("foo", "1.0", vec![])]);
        let options = ResolveOptions::default();
        let plan = resolve_upgrade(
            &["foo".to_string()],
            &candidates,
            &overlay,
            "x86_64",
            &options,
        )
        .unwrap();
        assert_eq!(plan.to_upgrade.len(), 1);
        assert_eq!(plan.to_upgrade[0].nevra.version, "2.0");
    }

    #[test]
    fn resolve_upgrade_never_reports_a_foreign_arch_build_of_a_base_owned_name() {
        // Regression test for `vez check-upgrade` listing libcap-ng.i686 as
        // an available update on staging even though `vez upgrade` correctly
        // skips it. libcap-ng.x86_64 is base-owned, so Split mode's base-name
        // lock (see `build_pool_locked` in vez-solv) must also lock the i686
        // build in the overlay, and `to_upgrade` has to agree with what `vez
        // upgrade` would do.
        let candidates = vec![
            pkg_arch("foo", "1.0", "x86_64", vec![]),
            pkg_arch("foo", "1.0", "i686", vec![]),
            pkg_arch("foo", "2.0", "i686", vec![]),
        ];
        let overlay = OverlayContext::for_test(
            vec![pkg_arch("foo", "1.0", "x86_64", vec![])],
            vec![pkg_arch("foo", "1.0", "i686", vec![])],
        );
        let options = ResolveOptions::default();
        let plan = resolve_upgrade(
            &["foo".to_string()],
            &candidates,
            &overlay,
            "x86_64",
            &options,
        )
        .unwrap();
        assert!(
            plan.to_upgrade.is_empty(),
            "expected no upgrade for a base-owned name's foreign-arch overlay build, got {:?}",
            plan.to_upgrade
        );
    }

    #[test]
    fn resolve_upgrade_never_reports_a_base_owned_vez_as_an_upgrade() {
        // `vez` ships in the base image, and the resolver must not offer a
        // newer repo `vez` as an upgrade target — `vez upgrade` updates it in
        // the CLI, deliberately outside the solver (see
        // `SELF_UPGRADABLE_NAMES`). This guards that the base lock still holds
        // for vez, so the CLI's self-upgrade is the only thing that moves it.
        let candidates = vec![pkg("vez", "0.1.1", vec![])];
        let overlay = OverlayContext::for_test(vec![pkg("vez", "0.1.0", vec![])], vec![]);
        let options = ResolveOptions::default();
        let plan = resolve_upgrade(
            &["vez".to_string()],
            &candidates,
            &overlay,
            "x86_64",
            &options,
        )
        .unwrap();
        assert!(
            plan.to_upgrade.is_empty() && plan.to_install.is_empty(),
            "base-owned vez must not be an upgrade target, got to_upgrade={:?} to_install={:?}",
            plan.to_upgrade,
            plan.to_install
        );
    }
}
