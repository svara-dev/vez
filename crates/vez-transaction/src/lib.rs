//! Applies a resolved [`vez_resolver::Plan`] to disk.
//!
//! vez doesn't reimplement RPM's transaction engine (cpio payload extraction,
//! scriptlet/trigger execution, digest/signature verification). That code is
//! security-sensitive and tied to the format, and `rpm` already does it right
//! and is always installed. vez's job ends at "here is the correct set of
//! packages, already downloaded, known not to duplicate anything the base
//! image provides". It then hands them to `rpm -U` pointed at
//! [`OverlayPaths::write_dbpath`] (vez's overlay rpmdb in `Split` mode, or
//! rpm's default in `Standalone`), the same way zypper/libsolv put their own
//! solver on top of librpm without reimplementing it.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use vez_core::format_duration;
use vez_core::format_speed as download_speed;
use vez_core::Package;
use vez_overlay::{OverlayMode, OverlayPaths};
use vez_repo::{get_with_retry, RepoConfig};

pub mod history;
pub mod module_state;
pub mod summary;
pub mod versionlock;
use history::Reason;

/// `diskspacecheck=`, process-wide, set once near the top of `run()` (like
/// `vez_repo::set_fastestmirror` and friends). dnf defaults to `true`.
static DISKSPACECHECK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn set_diskspacecheck(enabled: bool) {
    DISKSPACECHECK.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// statvfs-based free-space check for `diskspacecheck=`, run right before a
/// real (non-dry-run) install starts writing to disk. Walks up to the nearest
/// existing ancestor of `target` before calling `statvfs`, because the
/// overlay upperdir or installroot may not exist yet on a from-scratch
/// prebake.
fn check_disk_space(target: &Path, downloaded: &[DownloadedPackage]) -> Result<()> {
    if !DISKSPACECHECK.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let needed: u64 = downloaded.iter().map(|d| d.package.install_size).sum();
    if needed == 0 {
        return Ok(());
    }
    let mut probe = target.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(parent) => probe = parent.to_path_buf(),
            None => return Ok(()),
        }
    }
    let Some(available) = available_bytes(&probe) else {
        return Ok(());
    };
    anyhow::ensure!(
        needed <= available,
        "Error: Not enough free space in {} (need {}, have {} available) — disable this check with diskspacecheck=0",
        probe.display(),
        vez_core::format_size(needed),
        vez_core::format_size(available),
    );
    Ok(())
}

fn available_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    unsafe {
        let mut buf: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut buf) == 0 {
            Some(buf.f_bavail as u64 * buf.f_frsize as u64)
        } else {
            None
        }
    }
}

/// The path a `diskspacecheck=` probe should `statvfs` for `paths`.
/// `--installroot` always wins (that's where files land whatever `mode` is).
/// Otherwise it's the overlay upperdir in `Split` mode (where a fresh
/// install's files land), or `/` in `Standalone` (a plain rpm/dnf-style
/// install with no overlay).
fn diskspace_target(paths: &OverlayPaths) -> PathBuf {
    if let Some(root) = &paths.installroot {
        return root.clone();
    }
    match paths.mode {
        OverlayMode::Split { .. } => paths.overlay_upper.clone(),
        OverlayMode::Standalone => PathBuf::from("/"),
    }
}
use summary::{print_transaction_summary, Action, Entry};

/// Adds `--dbpath <path>` iff `paths` resolves to one. It's left out under
/// [`vez_overlay::OverlayMode::Standalone`] so rpm uses its compiled-in
/// default, the same as plain rpm/dnf. Also adds `--root <installroot>` when
/// `paths.installroot` is set, so package *files* (not only the rpmdb entry)
/// land under that root instead of the real `/`. That's dnf/rpm's
/// `--installroot` behavior, used to pre-bake the factory overlay at image
/// build time.
fn with_dbpath<'a>(cmd: &'a mut Command, paths: &OverlayPaths) -> &'a mut Command {
    if let Some(dbpath) = paths.write_dbpath() {
        if let Some(root) = &paths.installroot {
            // rpm joins `--root` + `--dbpath` itself (tested: passing the
            // root-prefixed absolute path here prepends root twice).
            // `write_dbpath()` always returns an absolute, root-prefixed
            // path, so strip the prefix off again before handing it to rpm.
            let relative = dbpath.strip_prefix(root).unwrap_or(&dbpath);
            cmd.arg("--root").arg(root);
            cmd.arg("--dbpath").arg(Path::new("/").join(relative));
        } else {
            cmd.arg("--dbpath").arg(dbpath);
        }
    } else if let Some(root) = &paths.installroot {
        cmd.arg("--root").arg(root);
    }
    cmd
}

/// The gate every mutating operation passes through before it writes anything.
///
/// Two questions, in order, and both must be answered yes:
///
/// 1. **May this system be written to at all?** [`vez_overlay::mount::ensure`] refuses on the
///    live medium, where `/usr` is a RAM-backed overlay and a package would be lost at
///    reboot. This is first because it is the one refusal that is about the *machine* rather
///    than about the layer, and because a live medium is detected as `Standalone` — where
///    nothing else here would object.
/// 2. **Is the persistent overlay up?** On a booted system, writing without it puts a
///    package's files where the next boot will not restore them.
///
/// Then it MAKES ITS OWN STATE DIRECTORY, and initializes the overlay rpmdb
/// (`create_dir_all` + `rpm --initdb`) if `paths` resolves to one and it doesn't exist yet.
/// `rpm --initdb` is a no-op on an initialized dbpath, so calling this on every write is safe.
///
/// **WHY VEZ CREATES ITS OWN DIRECTORY, AND WHY THAT WAS A REAL BUG.** It used to trust
/// `/usr/lib/tmpfiles.d/svara.conf` to have made `/var/lib/svara/vez` at boot. It had not, and
/// the first install died with:
///
/// ```text
/// error: can't create transaction lock on /var/lib/svara/vez/rpmdb/.rpm.lock
///        (No such file or directory)
/// ```
///
/// `rpm --initdb` cannot create a database whose *parent* is missing, so a directory someone
/// else was supposed to make became a hard failure on the first thing a user tried to do. The
/// lesson generalizes past this directory: a program that owns a path under `/var` must create
/// it, because package ordering, `SYSTEMD_TMPFILES` behaviour and an image build that never
/// runs tmpfiles at all are three ways for "someone else creates it" to be false.
///
/// Only called from functions in this module that are about to write (importing keys,
/// running a transaction, downloading into the cache). It is deliberately NOT called by
/// `vez_overlay`'s read-only `OverlayContext::load`: an earlier version did, which meant even
/// `vez list` and `vez origin` needed root to create a root-owned directory under
/// `/var/lib/svara/vez` before reading.
fn ensure_overlay_writable(paths: &OverlayPaths) -> Result<()> {
    // Reachable, not decorative: this was written as `mount::ensure` and left uncalled, which
    // is exactly the kind of guard that reads as protection and provides none.
    vez_overlay::mount::ensure(paths).context("checking whether this system can be written to")?;

    // ORDER MATTERS: the state directory, then the rpmdb inside it. `paths.state_dir` is
    // `/var/lib/svara/vez/state` and `STATE` is its parent, so creating both is deliberate
    // rather than redundant — the parent is what the rpmdb path needs.
    let owned = [
        paths.state_dir.clone(),
        std::path::PathBuf::from(vez_overlay::paths::STATE),
    ];
    for dir in &owned {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating vez's state directory {}", dir.display()))?;
    }

    if let Some(dbpath) = paths.write_dbpath() {
        if let Some(parent) = dbpath.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "creating the directory for the rpmdb at {}",
                    parent.display()
                )
            })?;
        }
        vez_rpmdb::ensure_initialized(&dbpath)
            .with_context(|| format!("initializing overlay rpmdb at {}", dbpath.display()))?;
    }
    Ok(())
}

pub struct DownloadedPackage {
    pub package: Package,
    pub rpm_path: PathBuf,
}

/// The `---vez-gpg-key-sep---` marker below can't appear inside an
/// ASCII-armored key body, so splitting `rpm -q`'s `%{description}` output on
/// it recovers each imported key's exact text.
const GPG_DESC_SEP: &str = "---vez-gpg-key-sep---";

/// Where the last fetched copy of an http(s) `gpgkey=` URL is cached, so
/// `import_repo_keys` can check "already imported?" without going to the
/// network on every run. Keyed by a hash of the URL and not the repo id,
/// because a repo id can be reused for a different `baseurl`/key after
/// `vez.conf` edits.
fn key_cache_path(paths: &OverlayPaths, key_url: &str) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key_url.hash(&mut hasher);
    paths
        .state_dir
        .join("gpgkeys")
        .join(format!("{:016x}.asc", hasher.finish()))
}

/// Whether `key_text` (an ASCII-armored public key) is already in the
/// dbpath's keyring. rpm stores the full key text verbatim as the
/// `%description` of a `gpg-pubkey` package, so comparing byte for byte
/// against every imported key is exact and needs no GPG parsing on our side.
fn key_already_imported(paths: &OverlayPaths, key_text: &str) -> Result<bool> {
    let mut cmd = Command::new("rpm");
    with_dbpath(&mut cmd, paths)
        .arg("-q")
        .arg("gpg-pubkey")
        .arg("--qf")
        .arg(&format!("%{{description}}\n{GPG_DESC_SEP}\n"));
    let output = cmd.output().context("spawning rpm -q gpg-pubkey")?;
    if !output.status.success() {
        // No gpg-pubkey packages imported yet (new dbpath). rpm -q exits
        // non-zero for "no package matches", which isn't an error here.
        return Ok(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let needle = key_text.trim();
    Ok(stdout.split(GPG_DESC_SEP).any(|desc| desc.trim() == needle))
}

/// Imports every configured repo's `gpgkey`(s) into the overlay's merged
/// rpmdb keyring with `rpm --import`, so `rpm -K`/`-U` can check package
/// signatures against them. Keys are fetched over HTTP(S) like any other repo
/// asset; a `file://`-style local path is read directly. When the exact same
/// key is already in the keyring, the fetch, import, and message are all
/// skipped, so running install/upgrade again doesn't print "Importing GPG
/// key" and call `rpm --import` on every command.
pub async fn import_repo_keys(
    client: &reqwest::Client,
    paths: &OverlayPaths,
    repo_configs: &[RepoConfig],
) -> Result<()> {
    ensure_overlay_writable(paths)?;
    for cfg in repo_configs {
        if !cfg.gpgcheck {
            continue;
        }
        for key_url in &cfg.gpgkeys {
            // A local copy of the last key fetched from this exact `key_url`,
            // keyed by a hash of the URL. Before this, http(s) keys were
            // fetched on *every* run just to compare against the local
            // keyring (`key_already_imported` below never touches the
            // network). So `vez` couldn't finish any gpgcheck'd operation
            // offline, or when the network to the key server was flaky, even
            // though the key was already trusted and local verification
            // didn't need a new copy. A user hit a hard `Error: importing
            // repo gpg keys` on a connect timeout to a repo's key server,
            // with the key already imported from an earlier run.
            let cache_path = key_cache_path(paths, key_url);
            let (key_text, tmp_path) =
                if key_url.starts_with("http://") || key_url.starts_with("https://") {
                    if let Ok(cached) = tokio::fs::read_to_string(&cache_path).await {
                        if key_already_imported(paths, &cached).unwrap_or(false) {
                            continue;
                        }
                    }
                    let bytes = vez_repo::with_net_options(
                        vez_repo::net_options_for_repo(cfg),
                        get_with_retry(client, key_url),
                    )
                    .await?
                    .error_for_status()?
                    .bytes()
                    .await?;
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    if let Some(parent) = cache_path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    let _ = tokio::fs::write(&cache_path, &text).await;
                    (text, None::<PathBuf>)
                } else {
                    let path = key_url.trim_start_matches("file://");
                    let text = tokio::fs::read_to_string(path)
                        .await
                        .with_context(|| format!("reading {path}"))?;
                    (text, Some(PathBuf::from(path)))
                };

            if key_already_imported(paths, &key_text).unwrap_or(false) {
                continue;
            }
            println!("Importing GPG key for repo '{}': {}", cfg.id, key_url);

            let status = match &tmp_path {
                Some(path) => {
                    let mut cmd = Command::new("rpm");
                    with_dbpath(&mut cmd, paths).arg("--import").arg(path);
                    cmd.status().context("spawning rpm --import")?
                }
                None => {
                    let tmp = std::env::temp_dir()
                        .join(format!("vez-gpgkey-{}.asc", cfg.id.replace('/', "_")));
                    tokio::fs::write(&tmp, &key_text)
                        .await
                        .with_context(|| format!("writing {}", tmp.display()))?;
                    let mut cmd = Command::new("rpm");
                    with_dbpath(&mut cmd, paths).arg("--import").arg(&tmp);
                    let s = cmd.status().context("spawning rpm --import")?;
                    let _ = tokio::fs::remove_file(&tmp).await;
                    s
                }
            };
            anyhow::ensure!(
                status.success(),
                "importing gpg key {key_url} for repo '{}' failed with {status}",
                cfg.id
            );
        }
    }
    Ok(())
}

/// The part of `pool` the download fallback in [`download_all_ex`] can ever
/// use for `to_install`: every candidate that shares a (name, arch) with
/// something being installed. A caller can build this small set up front and
/// drop its full candidate pools (gigabytes with large repos) before the
/// download/rpm phase, instead of keeping them alive only for the fallback.
pub fn restrict_alt_candidates<'a>(
    to_install: &[Package],
    pool: impl IntoIterator<Item = &'a Package>,
) -> Vec<Package> {
    let wanted: HashSet<(&str, &str)> = to_install
        .iter()
        .map(|p| (p.nevra.name.as_str(), p.nevra.arch.as_str()))
        .collect();
    pool.into_iter()
        .filter(|c| wanted.contains(&(c.nevra.name.as_str(), c.nevra.arch.as_str())))
        .cloned()
        .collect()
}

/// Returns freed heap to the OS. glibc keeps freed arena memory mapped
/// indefinitely, so after dropping the multi-gigabyte candidate pools the
/// process would otherwise hold that RSS through the whole download and rpm
/// transaction that follows (scriptlets, dracut, akmods).
pub fn release_freed_memory() {
    // SAFETY: malloc_trim has no preconditions; it only returns free pages.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// Downloads every package in the plan's install set into `cache_dir`,
/// skipping any whose target file already exists (repeat installs and retries
/// shouldn't fetch again). Same as [`download_all`], except `max_parallel`
/// (dnf's `max_parallel_downloads=`, default 3) sets how many fetches run at
/// once.
///
/// `per_repo` lays packages out like dnf5's cache:
/// `<cache_dir>/repos/<repo_id>-<hash>/packages/<filename>.rpm`, the same
/// hashed per-repo directory [`vez_repo::load_repo_ex`] uses for that repo's
/// metadata (`repo_configs` is used to compute the hash; see
/// [`vez_repo::repo_cache_dir`]). That way packages from different repos
/// never collide, a repo id pointed at a new URL doesn't serve stale rpms
/// from the old one, and `vez clean packages` can still work per repo. A
/// `repo_id` with no matching entry in `repo_configs` (shouldn't happen
/// normally, since every candidate's repo_id comes from a config in the same
/// load) falls back to the unhashed `<cache_dir>/<repo_id>/packages/` layout
/// instead of failing. Set `per_repo` to `false` when `cache_dir` is a
/// one-off destination the caller chose (`vez download --destdir`), where the
/// user expects the files directly in that directory without a repo-id
/// subdirectory.
///
/// `alt_candidates` is the cross-repo candidate pool (as loaded by
/// `load_candidates`, before resolution narrowed it to `packages`). It's only
/// used as a fallback when a package's own repo 404s on the `.rpm` file even
/// though `primary.xml` lists it (a rare but real mirror consistency gap,
/// e.g. an archive snapshot missing one file its metadata still advertises).
/// Then this looks for the same name+arch in a *different* repo: an exact
/// NEVRA match first (the same build mirrored elsewhere), then any other
/// version of that name+arch if that's all another repo has. The caller asked
/// to install this name, and a slightly different EVR that still resolves
/// beats aborting the whole transaction over one mirror's gap. Pass an empty
/// slice to turn the fallback off (only ever retry the exact package
/// requested).
pub async fn download_all_ex(
    client: &reqwest::Client,
    packages: &[Package],
    cache_dir: &Path,
    max_parallel: u32,
    per_repo: bool,
    repo_configs: &[RepoConfig],
    alt_candidates: &[Package],
) -> Result<Vec<DownloadedPackage>> {
    download_all_ex_with_metadata_root(
        client,
        packages,
        cache_dir,
        cache_dir,
        max_parallel,
        per_repo,
        repo_configs,
        alt_candidates,
    )
    .await
}

/// Same as [`download_all_ex`], but for callers whose `.rpm` destination
/// (`cache_dir`) isn't where repo *metadata* lives on disk (`vez download
/// --destdir <elsewhere>`, `vez reposync`). It points the same-repo mirror
/// fallback's `baseurl.txt` lookup at the right place. Otherwise
/// `cached_base_url` looks for `<destdir>/repos/<repo>-<hash>/baseurl.txt`,
/// which was never written (`load_candidates` cached metadata under the real
/// `cache_dir`), and falls back to guessing by prefix-searching a fresh
/// mirror list. That guess can miss completely for a `metalink=` repo, which
/// is the `gtk-vnc2` 404-with-no-fallback bug this function fixes for the
/// common (`cache_dir == metadata_root`) case.
pub async fn download_all_ex_with_metadata_root(
    client: &reqwest::Client,
    packages: &[Package],
    cache_dir: &Path,
    metadata_root: &Path,
    max_parallel: u32,
    per_repo: bool,
    repo_configs: &[RepoConfig],
    alt_candidates: &[Package],
) -> Result<Vec<DownloadedPackage>> {
    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("creating cache dir {}", cache_dir.display()))?;

    for pkg in packages {
        anyhow::ensure!(
            !pkg.location.is_empty(),
            "package '{}' has no download location (not repo-sourced?)",
            pkg.nevra
        );
    }

    // Looked up by repo id on every `dest_of`/`net_opts` call below (once per
    // package, plus once per repo group), so a `HashMap` keeps that O(1)
    // instead of a linear `repo_configs.iter().find()` per call. `or_insert`
    // keeps the *first* config for a duplicated id, same as the `.find()` it
    // replaced.
    let mut repo_by_id: HashMap<&str, &RepoConfig> = HashMap::with_capacity(repo_configs.len());
    for c in repo_configs {
        repo_by_id.entry(c.id.as_str()).or_insert(c);
    }

    let dest_of = |pkg: &Package| -> PathBuf {
        if per_repo {
            match repo_by_id.get(pkg.repo_id.as_str()) {
                Some(cfg) => vez_repo::repo_cache_dir(&cache_dir.join("repos"), cfg)
                    .join("packages")
                    .join(cache_filename(pkg)),
                None => cache_dir
                    .join(&pkg.repo_id)
                    .join("packages")
                    .join(cache_filename(pkg)),
            }
        } else {
            cache_dir.join(cache_filename(pkg))
        }
    };

    // A fallback build has to do more than exist: its own `Requires` (rpm
    // auto-generates exact-EVR ones between subpackages of the same source,
    // e.g. `gcc-c++` on `gcc`) must still hold against what's landing in this
    // transaction. Otherwise swapping in a build with a different EVR
    // silently produces a combination `rpm` refuses at transaction time (e.g.
    // a `gcc-c++-16.0.1` fallback next to the originally resolved
    // `gcc-16.1.1-2`). Built from the original `packages` list, before any
    // fallback, because those EVRs are what will be installed whichever repo
    // each package's bytes come from.
    let planned_evr: HashMap<&str, String> = packages
        .iter()
        .map(|p| (p.nevra.name.as_str(), p.nevra.evr()))
        .collect();

    let to_fetch: Vec<(usize, &Package)> = packages
        .iter()
        .enumerate()
        .filter(|(_, pkg)| !dest_of(pkg).exists())
        .collect();
    if !to_fetch.is_empty() {
        println!("Downloading Packages:");
    }
    let total = to_fetch.len();
    let name_w = to_fetch
        .iter()
        .map(|(_, pkg)| cache_filename(pkg).len())
        .max()
        .unwrap_or(0);
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let total_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_parallel.max(1) as usize));
    let overall_start = std::time::Instant::now();

    // One indicatif-rendered animated bar for the whole batch, plus one per
    // in-flight package under it. This replaced a hand-rolled
    // `\r`+ANSI-escape redraw that worked but badly reimplemented what
    // indicatif already does: layout that respects terminal width, smooth
    // redraw timing, and stacking several bars without fighting interleaved
    // `println!` output.
    let expected_total: u64 = to_fetch.iter().map(|(_, pkg)| pkg.download_size).sum();
    let multi = indicatif::MultiProgress::new();
    let main_bar = multi.add(indicatif::ProgressBar::new(expected_total));
    main_bar.set_style(
        indicatif::ProgressStyle::with_template("{msg} [{bar:30.cyan/blue}] {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>12} eta {eta:>4}")
            .unwrap()
            .progress_chars("=> ")
            // indicatif's `{eta}` comes straight from its smoothed rate
            // estimate with no clamp. When a package stalls at about 0 B/s (a
            // slow or dead mirror the retry loop hasn't moved off yet), the
            // rate drops toward zero and `{eta}` shows nonsense like
            // "278512y" where a user expects something that reads as
            // "unknown". Show a placeholder in that case.
            .with_key("eta", |state: &indicatif::ProgressState, w: &mut dyn std::fmt::Write| {
                let remaining = state.eta();
                if remaining.as_secs() >= 60 * 60 * 24 * 365 {
                    let _ = write!(w, "--:--");
                } else {
                    let _ = write!(w, "{}", format_duration(remaining));
                }
            }),
    );
    main_bar.set_message("Total");
    main_bar.enable_steady_tick(std::time::Duration::from_millis(200));

    // `resolve_mirrors_cached` reads a repo's `mirrorlist=`/`metalink=`
    // document from
    // `<cache_root>/<repo>-<hash>/{mirrorlist.txt,metalink.xml}` when it's
    // younger than `metadata_expire=` (dnf5 caches the same file under
    // `/var/cache/libdnf5/<repo>-<hash>/metalink.xml`) instead of fetching it
    // again. It's the same for every package from that repo, and this run's
    // `load_candidates` just populated it. Resolving it once per *repo* here,
    // instead of once per *package* inside each spawned task below, also
    // means a cold or expired cache only costs one round trip per repo, done
    // concurrently up front.
    //
    // Each entry pairs a repo's mirror list with two mirrors. One is the
    // exact mirror its cached `location`s were built from (`baseurl.txt`; see
    // `cached_base_url`). That's needed so extracting hrefs below doesn't
    // depend on that mirror still being in the cached list: Fedora's metalink
    // endpoint returns a geo-sorted, randomized subset per request, so two
    // resolutions can disagree on membership even within one cache window.
    // The other is a freshly probed "best right now" mirror
    // (`resolve_base_url`, a live `HEAD` per mirror on every call regardless
    // of the list cache), so the *first* download attempt goes to whichever
    // mirror is responding now instead of trusting a `baseurl.txt` that can
    // be hours or days old under `metadata_expire=` and may have gone stale
    // or slow since.
    let repo_mirrors: std::sync::Arc<
        HashMap<String, (Vec<String>, Option<String>, Option<String>)>,
    > = {
        let mut unique_repo_ids: Vec<&str> = to_fetch
            .iter()
            .map(|(_, pkg)| pkg.repo_id.as_str())
            .collect();
        unique_repo_ids.sort_unstable();
        unique_repo_ids.dedup();
        let mut resolve_tasks = Vec::with_capacity(unique_repo_ids.len());
        for repo_id in unique_repo_ids {
            if let Some(cfg) = repo_by_id.get(repo_id).map(|c| (*c).clone()) {
                let client = client.clone();
                let cache_root = metadata_root.join("repos");
                resolve_tasks.push(tokio::spawn(async move {
                    let mirrors =
                        vez_repo::resolve_ranked_mirrors(&client, &cfg, &cache_root, false)
                            .await
                            .unwrap_or_default();
                    let used = vez_repo::cached_base_url(&cache_root, &cfg);
                    let preferred = vez_repo::resolve_base_url(&client, &cfg, &cache_root)
                        .await
                        .ok();
                    (cfg.id, mirrors, used, preferred)
                }));
            }
        }
        let mut map = HashMap::with_capacity(resolve_tasks.len());
        for task in resolve_tasks {
            if let Ok((repo_id, mirrors, used, preferred)) = task.await {
                map.insert(repo_id, (mirrors, used, preferred));
            }
        }
        std::sync::Arc::new(map)
    };

    // Group `to_fetch` by repo_id. Each group becomes one (or a few, on
    // retry) `lr_download_packages` batch call against that repo's ranked
    // mirror list, the same "one cached handle, one repo, one batch call"
    // shape dnf5's `RepoDownloader`/`PackageDownloader` use, replacing the
    // old per-package, per-URL loop in Rust. librepo does the mirror
    // cycling/failover and the per-target checksum checks inside that one
    // call.
    let mut groups: Vec<(String, Vec<(usize, Package)>)> = Vec::new();
    for (idx, pkg) in to_fetch {
        match groups.iter_mut().find(|(rid, _)| *rid == pkg.repo_id) {
            Some(g) => g.1.push((idx, pkg.clone())),
            None => groups.push((pkg.repo_id.clone(), vec![(idx, pkg.clone())])),
        }
    }
    // The fallback below only looks at alternatives with the same (name,
    // arch) as a package being downloaded, so copy only those instead of the
    // whole cross-repo pool (every enabled repo's full package list, which is
    // gigabytes with Fedora + updates-archive).
    let wanted: HashSet<(&str, &str)> = packages
        .iter()
        .map(|p| (p.nevra.name.as_str(), p.nevra.arch.as_str()))
        .collect();
    let alt_candidates_owned = std::sync::Arc::new(
        alt_candidates
            .iter()
            .filter(|c| wanted.contains(&(c.nevra.name.as_str(), c.nevra.arch.as_str())))
            .cloned()
            .collect::<Vec<Package>>(),
    );
    let planned_evr_owned: std::sync::Arc<HashMap<String, String>> = std::sync::Arc::new(
        planned_evr
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    );
    // An owned clone of everything `dest_of` needs, so the alt-candidate
    // fallback (which works out a *new* package's destination inside a
    // 'static spawned task, unlike every other `dest_of` call site in this
    // function) doesn't have to borrow this function's stack.
    let repo_by_id_owned: HashMap<String, RepoConfig> = repo_by_id
        .iter()
        .map(|(id, c)| (id.to_string(), (*c).clone()))
        .collect();
    let dest_of_owned = std::sync::Arc::new((cache_dir.to_path_buf(), per_repo, repo_by_id_owned));

    let mut tasks = Vec::with_capacity(groups.len());
    for (repo_id, members) in groups {
        let semaphore = semaphore.clone();
        let counter = counter.clone();
        let total_bytes = total_bytes.clone();
        let multi = multi.clone();
        let main_bar = main_bar.clone();
        let repo_mirrors = repo_mirrors.clone();
        let alt_candidates_owned = alt_candidates_owned.clone();
        let planned_evr_owned = planned_evr_owned.clone();
        let dest_of_owned = dest_of_owned.clone();
        // `dest_of`/`cache_filename` borrow
        // `per_repo`/`repo_configs`/`cache_dir`, which don't outlive this
        // function, so they're turned into owned values before the 'static
        // spawned task below.
        let members: Vec<(usize, Package, PathBuf, String)> = members
            .into_iter()
            .map(|(idx, pkg)| {
                let dest = dest_of(&pkg);
                let filename = cache_filename(&pkg);
                (idx, pkg, dest, filename)
            })
            .collect();

        tasks.push(tokio::spawn(async move {
            for (_, _, dest, _) in &members {
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await.with_context(|| format!("creating {}", parent.display()))?;
                }
            }

            // `cached_used`/`preferred`, for the same reasons as above: the
            // exact mirror `location` was built from (authoritative,
            // `baseurl.txt`) plus a live re-probe of whichever mirror answers
            // fastest right now, tried before it. `mirrors` is the repo's
            // full ranked list, handed to librepo through `LRO_URLS` so
            // librepo cycles through it instead of a manual per-URL loop in
            // Rust.
            //
            // This repo's own proxy/auth/TLS-client settings, if any, apply
            // to every librepo handle the batch download below creates, the
            // same per-repo scoping [`load_repo`] uses for metadata fetches.
            let net_opts = dest_of_owned.2.get(&repo_id).map(vez_repo::net_options_for_repo).unwrap_or_else(vez_repo::default_net_options);
            let (mirrors, cached_used, preferred) = repo_mirrors.get(&repo_id).cloned().unwrap_or_default();
            let used = cached_used.clone().or_else(|| members.first().and_then(|(_, pkg, _, _)| mirrors.iter().filter(|m| pkg.location.starts_with(m.as_str())).max_by_key(|m| m.len()).cloned()));
            let mut urls: Vec<String> = Vec::new();
            if let Some(used) = &used {
                if let Some(preferred) = &preferred {
                    if preferred != used {
                        urls.push(preferred.clone());
                    }
                }
                urls.push(used.clone());
                for m in &mirrors {
                    if m != used && Some(m) != preferred.as_ref() {
                        urls.push(m.clone());
                    }
                }
            }

            let _permit = semaphore.acquire_owned().await.expect("semaphore never closed");
            let start = std::time::Instant::now();

            // Per-package progress bar and counter, same UI as before, now
            // driven by librepo's `LrProgressCb` per target inside the shared
            // batch call instead of a per-package async download.
            struct Bar {
                idx: usize,
                pkg: Package,
                dest: PathBuf,
                filename: String,
                progress: std::sync::Arc<std::sync::atomic::AtomicU64>,
                child_bar: indicatif::ProgressBar,
                ticker: tokio::task::JoinHandle<()>,
                n: usize,
            }
            let mut bars: Vec<Bar> = Vec::with_capacity(members.len());
            for (idx, pkg, dest, filename) in &members {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let child_bar = multi.add(indicatif::ProgressBar::new(pkg.download_size));
                child_bar.set_style(
                    indicatif::ProgressStyle::with_template(&format!("[{n}/{total}] {{msg:<{name_w}}} [{{bar:20.green/blue}}] {{bytes:>10}}/{{total_bytes:<10}} {{bytes_per_sec:>12}}"))
                        .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar())
                        .progress_chars("=> "),
                );
                child_bar.set_message(filename.clone());
                child_bar.enable_steady_tick(std::time::Duration::from_millis(200));
                let ticker = {
                    let progress = progress.clone();
                    let child_bar = child_bar.clone();
                    let main_bar = main_bar.clone();
                    tokio::spawn(async move {
                        let mut last = 0u64;
                        loop {
                            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                            let cur = progress.load(std::sync::atomic::Ordering::Relaxed);
                            child_bar.set_position(cur);
                            if cur > last {
                                main_bar.inc(cur - last);
                                last = cur;
                            }
                        }
                    })
                };
                bars.push(Bar { idx: *idx, pkg: pkg.clone(), dest: dest.clone(), filename: filename.clone(), progress, child_bar, ticker, n });
            }

            // `pending` shrinks every round to only the targets that failed
            // the round before. Same `ROUNDS` semantics as before (go through
            // the whole mirror set, back off, try again), but each round is
            // now one batch call instead of a per-package, per-URL loop.
            let mut pending: Vec<usize> = (0..bars.len()).collect();
            let mut errors: HashMap<usize, String> = HashMap::new();
            const ROUNDS: u32 = 3;
            for round in 1..=ROUNDS {
                if pending.is_empty() {
                    break;
                }
                let dir_base = |loc: &str| -> Option<(String, String)> { loc.rsplit_once('/').map(|(d, f)| (d.to_string(), f.to_string())) };
                let specs: Vec<vez_repo::BatchSpec> = pending
                    .iter()
                    .map(|&i| {
                        let b = &bars[i];
                        let href = used.as_deref().and_then(|u| b.pkg.location.strip_prefix(u)).map(|h| h.trim_start_matches('/').to_string());
                        // With a usable `href` and a non-empty mirror list
                        // for the repo, `base_url` stays unset so this target
                        // resolves against the handle's `LRO_URLS` (librepo
                        // cycles through the mirrors). Otherwise it falls
                        // back to a single-mirror target built from this
                        // package's own `location`.
                        let (relative_url, base_url) = match href {
                            Some(h) if !urls.is_empty() => (h, None),
                            _ => match dir_base(&b.pkg.location) {
                                Some((dir, file)) => (file, Some(dir)),
                                None => (b.pkg.location.clone(), None),
                            },
                        };
                        vez_repo::BatchSpec {
                            relative_url,
                            dest: b.dest.clone(),
                            checksum_type: b.pkg.checksum_type.clone(),
                            checksum: b.pkg.checksum.clone(),
                            expected_size: b.pkg.download_size as i64,
                            progress: Some(b.progress.clone()),
                            base_url,
                        }
                    })
                    .collect();

                let results = vez_repo::with_net_options(net_opts.clone(), vez_repo::download_packages_batch(urls.clone(), specs, max_parallel as u64)).await;
                match results {
                    Ok(outcomes) => {
                        let mut still_pending = Vec::new();
                        for (&i, outcome) in pending.iter().zip(outcomes.iter()) {
                            if outcome.ok {
                                errors.remove(&i);
                            } else {
                                errors.insert(i, outcome.error.clone().unwrap_or_else(|| "download failed".to_string()));
                                still_pending.push(i);
                            }
                        }
                        pending = still_pending;
                    }
                    Err(e) => {
                        // A function-level librepo error (not per target):
                        // every target still pending in this round failed the
                        // same way.
                        for &i in &pending {
                            errors.insert(i, e.to_string());
                        }
                    }
                }
                if !pending.is_empty() && round < ROUNDS {
                    tokio::time::sleep(std::time::Duration::from_millis(1000 * 2u64.pow(round - 1))).await;
                }
            }

            // Anything still failing after `ROUNDS` batch attempts against
            // its own repo falls back to an alt candidate from another repo,
            // with the same EVR checks as before. Each attempt is a
            // single-item batch call against that alt's own repo/mirror,
            // split into dir + basename. That's good enough for this rare
            // path; the main group call above uses the repo's full ranked
            // mirror list.
            let dest_of_local = |pkg: &Package| -> PathBuf {
                let (cache_dir, per_repo, repo_by_id) = &*dest_of_owned;
                if *per_repo {
                    match repo_by_id.get(pkg.repo_id.as_str()) {
                        Some(cfg) => vez_repo::repo_cache_dir(&cache_dir.join("repos"), cfg).join("packages").join(cache_filename(pkg)),
                        None => cache_dir.join(&pkg.repo_id).join("packages").join(cache_filename(pkg)),
                    }
                } else {
                    cache_dir.join(cache_filename(pkg))
                }
            };
            for &i in &pending.clone() {
                let b = &bars[i];
                let mut alts: Vec<&Package> = alt_candidates_owned
                    .iter()
                    .filter(|c| c.nevra.name == b.pkg.nevra.name && c.nevra.arch == b.pkg.nevra.arch && c.repo_id != b.pkg.repo_id)
                    .filter(|c| c.requires.iter().all(|dep| match planned_evr_owned.get(dep.name.as_str()) {
                        Some(evr) => dep.satisfied_by_evr(evr),
                        None => true,
                    }))
                    .collect();
                alts.sort_by(|a, c| (c.nevra == b.pkg.nevra).cmp(&(a.nevra == b.pkg.nevra)));
                let mut resolved = false;
                for alt in alts {
                    let Some((dir, file)) = alt.location.rsplit_once('/') else { continue };
                    let alt_dest = dest_of_local(alt);
                    if let Some(parent) = alt_dest.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    let spec = vez_repo::BatchSpec { relative_url: file.to_string(), dest: alt_dest.clone(), checksum_type: alt.checksum_type.clone(), checksum: alt.checksum.clone(), expected_size: alt.download_size as i64, progress: Some(bars[i].progress.clone()), base_url: None };
                    match vez_repo::with_net_options(net_opts.clone(), vez_repo::download_packages_batch(vec![dir.to_string()], vec![spec], 1)).await {
                        Ok(outcomes) if outcomes.first().is_some_and(|o| o.ok) => {
                            multi.suspend(|| println!("  (falling back to {} from repo '{}' — '{}' isn't available from its own repo)", alt.nevra, alt.repo_id, b.pkg.nevra));
                            bars[i].pkg = alt.clone();
                            bars[i].dest = alt_dest;
                            errors.remove(&i);
                            resolved = true;
                            break;
                        }
                        Ok(outcomes) => {
                            if let Some(o) = outcomes.into_iter().next() {
                                errors.insert(i, o.error.unwrap_or_else(|| "download failed".to_string()));
                            }
                        }
                        Err(e) => {
                            errors.insert(i, e.to_string());
                        }
                    }
                }
                let _ = resolved;
            }

            let elapsed = start.elapsed();
            let mut fetched = Vec::new();
            let mut first_err = None;
            for (pos, bar) in bars.into_iter().enumerate() {
                bar.ticker.abort();
                bar.child_bar.finish_and_clear();
                match errors.remove(&pos) {
                    None => {
                        let size = tokio::fs::metadata(&bar.dest).await.with_context(|| format!("stat {}", bar.dest.display()))?.len();
                        total_bytes.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
                        multi.suspend(|| println!("[{}/{total}] {:<name_w$} 100% | {:>10} | {:>10} | {}", bar.n, bar.filename, download_speed(size, elapsed), vez_core::format_size(size), format_duration(elapsed)));
                        fetched.push((bar.idx, bar.pkg, bar.dest));
                    }
                    Some(err) if first_err.is_none() => {
                        first_err = Some(anyhow::anyhow!("downloading '{}': {}", bar.pkg.nevra, err));
                    }
                    Some(_) => {}
                }
            }
            if let Some(e) = first_err {
                return Err(e);
            }
            Ok::<Vec<(usize, Package, PathBuf)>, anyhow::Error>(fetched)
        }));
    }
    let mut fetched: HashMap<usize, (Package, PathBuf)> = HashMap::new();
    for task in tasks {
        let group_result: Vec<(usize, Package, PathBuf)> =
            task.await.context("download task panicked")??;
        for (idx, pkg, dest) in group_result {
            fetched.insert(idx, (pkg, dest));
        }
    }
    main_bar.finish_and_clear();

    if total > 0 {
        println!("{}", "-".repeat(80));
        let elapsed = overall_start.elapsed();
        let bytes = total_bytes.load(std::sync::atomic::Ordering::Relaxed);
        println!(
            "[{total}/{total}] {:<name_w$} 100% | {:>10} | {:>10} | {}",
            "Total",
            download_speed(bytes, elapsed),
            vez_core::format_size(bytes),
            format_duration(elapsed)
        );
    }

    Ok(packages
        .iter()
        .enumerate()
        .map(|(idx, pkg)| match fetched.remove(&idx) {
            Some((actual_pkg, actual_dest)) => DownloadedPackage {
                package: actual_pkg,
                rpm_path: actual_dest,
            },
            None => DownloadedPackage {
                package: pkg.clone(),
                rpm_path: dest_of(pkg),
            },
        })
        .collect())
}

/// Same as [`download_all_ex`] with dnf's default `max_parallel_downloads=3`
/// and `per_repo=true`. Kept for callers (mostly tests) without a `vez.conf`
/// to read the real value from.
pub async fn download_all(
    client: &reqwest::Client,
    packages: &[Package],
    cache_dir: &Path,
) -> Result<Vec<DownloadedPackage>> {
    download_all_ex(client, packages, cache_dir, 3, true, &[], &[]).await
}

/// rpm's `-vh` phase-header lines. They end in a hash-fill bar like a
/// per-package completion line but aren't one, so they must never count
/// against the package total in `steps`.
fn is_rpm_phase_header(name_part: &str) -> bool {
    matches!(
        name_part,
        "Verifying..."
            | "Preparing..."
            | "Preparing packages..."
            | "Updating / installing..."
            | "Cleaning up / removing..."
            | "Removing packages..."
    )
}

/// Runs an `rpm` [`Command`] the caller already set up (verb, flags, package
/// args, plus `-v`) with `--percent` added, and turns rpm's `pkgname   %%
/// <float>` / `%% <float>` percent-callback lines into a live indicatif
/// display: an animated bar for the current package, stacked under an
/// aggregate bar weighted by `install_size` across the whole transaction.
/// Same `MultiProgress` approach as the download side.
///
/// `steps` is `(name, install_size)` in the exact order packages were passed
/// to rpm, and is used to label and weight each package as its percent
/// updates come in. rpm can reorder a transaction internally for dependency
/// reasons, so this attributes percent *events* by position instead of
/// trusting rpm's name text (often truncated to fit the column). That's fine
/// for a progress display and nothing depends on it for correctness.
/// Phase-header lines (`Verifying...`, `Preparing...`, etc.) and everything
/// else (scriptlet output) go through `multi.suspend`, which clears the live
/// bars for a moment so printed lines don't get mixed into them. `stderr`
/// stays inherited, so real errors and scriptlet stderr still show up live.
fn run_rpm_transaction(
    mut cmd: Command,
    steps: &[(String, u64)],
    verb: &str,
    batch: &[&DownloadedPackage],
) -> Result<()> {
    use std::io::{BufRead, BufReader, Read};

    cmd.arg("--percent");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context("spawning rpm")?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    // Read on a separate thread. rpm can write enough to the stderr pipe to
    // fill its OS buffer before we finish draining stdout, which would
    // deadlock (rpm blocks writing while we block reading the other pipe).
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut buf);
        buf
    });
    let reader = BufReader::new(stdout);

    let total = steps.len();
    let total_size: u64 = steps.iter().map(|(_, size)| *size).sum();
    let mut n = 0usize;
    let mut last = std::time::Instant::now();

    let multi = indicatif::MultiProgress::new();
    let main_bar = multi.add(indicatif::ProgressBar::new(total_size));
    main_bar.set_style(
        indicatif::ProgressStyle::with_template(
            "Overall  [{bar:30.cyan/blue}] {bytes:>10}/{total_bytes:<10} {bytes_per_sec:>12}",
        )
        .unwrap()
        .progress_chars("=> "),
    );
    main_bar.enable_steady_tick(std::time::Duration::from_millis(200));
    let pkg_bar = multi.add(indicatif::ProgressBar::new(100));
    pkg_bar.set_style(
        indicatif::ProgressStyle::with_template(
            "[{prefix}] {msg:<28} [{bar:30.green/blue}] {percent:>3}%",
        )
        .unwrap()
        .progress_chars("=> "),
    );
    pkg_bar.enable_steady_tick(std::time::Duration::from_millis(200));

    for line in reader.lines() {
        let line = line.context("reading rpm output")?;
        let trimmed = line.trim_end();
        if let Some(pct_idx) = trimmed.find("%%") {
            let prefix = trimmed[..pct_idx].trim();
            let pct: f64 = trimmed[pct_idx + 2..].trim().parse().unwrap_or(0.0);
            if !prefix.is_empty() && is_rpm_phase_header(prefix) {
                let prefix = prefix.to_string();
                multi.suspend(|| println!("{prefix}"));
                continue;
            }
            if n >= total {
                continue;
            }
            let (name, size) = &steps[n];
            pkg_bar.set_prefix(format!("{}/{total}", n + 1));
            pkg_bar.set_message(format!("{verb} {name}"));
            pkg_bar.set_position(pct.clamp(0.0, 100.0) as u64);
            let pkg_bytes = ((*size as f64) * (pct / 100.0)) as u64;
            main_bar.set_position(
                (total_size - steps[n..].iter().map(|(_, s)| *s).sum::<u64>()) + pkg_bytes,
            );
            if pct >= 100.0 {
                let elapsed = last.elapsed();
                last = std::time::Instant::now();
                n += 1;
                let (name, size) = (name.clone(), *size);
                multi.suspend(|| {
                    println!(
                        "[{n}/{total}] {verb} {name:<28} 100% | {:>10} | {:>10} | {}",
                        vez_core::format_speed(size, elapsed),
                        vez_core::format_size(size),
                        vez_core::format_duration(elapsed)
                    );
                });
            }
        } else if !trimmed.trim_start_matches(['#', ' ']).is_empty()
            && !trimmed.chars().all(|c| c == '#' || c == ' ')
        {
            let trimmed = trimmed.to_string();
            multi.suspend(|| println!("{trimmed}"));
        }
    }
    pkg_bar.finish_and_clear();
    main_bar.finish_and_clear();

    let status = child.wait().context("waiting for rpm")?;
    let stderr_text = stderr_handle.join().unwrap_or_default();
    if !status.success() {
        // rpm also exits nonzero when a package's %post/%postun scriptlet
        // fails (e.g. an akmod build script refusing to run as root). That
        // happens *after* the package's files are committed, so the install
        // worked even though the exit status says otherwise. A real
        // pre-transaction rejection (unmet deps, file conflicts) never gets
        // this far: rpm refuses the whole transaction up front and prints no
        // "Installing" progress lines at all. Tell the two apart by whether
        // we saw every package's line.
        if n < total {
            // rpm's embedded signature/digest check (part of this real
            // transaction; a separate `rpm -K` pre-flight used to be run here
            // too and broke outright when a newer rpm changed `-K`'s stdout
            // wording, rejecting good packages) rejected something before any
            // package was written. If that's what happened, the cached copy
            // is either corrupt/tampered or the caller hasn't imported the
            // signing key yet. Either way, deleting it lets
            // `apply_install_with_signature_retry` (vez-cli) download it
            // again and retry once instead of getting stuck on a bad cache
            // file forever.
            let lower = stderr_text.to_lowercase();
            let looks_like_signature_failure = lower.contains("signature")
                || lower.contains("digest")
                || lower.contains("does not verify")
                || lower.contains("nokey")
                || lower.contains("public key");
            if looks_like_signature_failure {
                for d in batch {
                    let _ = std::fs::remove_file(&d.rpm_path);
                }
                anyhow::bail!(
                    "signature verification failed during rpm transaction: {}",
                    stderr_text.trim()
                );
            }
            anyhow::bail!(
                "rpm transaction failed with {status}: {}",
                stderr_text.trim()
            );
        }
        eprintln!("warning: rpm exited with {status} (a package scriptlet failed) — all {total} package(s) were installed; continuing");
    }
    Ok(())
}

fn cache_filename(pkg: &Package) -> String {
    pkg.location
        .rsplit('/')
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| pkg.nevra.to_string())
}

/// Runs `rpm -Uvh --dbpath <merged rpmdb>` against the downloaded set.
/// Installs end up in the overlay upperdir automatically: the merged rpmdb
/// path *is* `/usr/share/rpm` (merged by the kernel), so any write rpm makes
/// there is copied up into `overlay/upper`. vez never touches `upperdir`
/// paths directly, following the same "always go through the merged view"
/// rule `overlay_mount.rs` documents for itself.
///
/// `dry_run` maps to `rpm --test`: resolves and validates the transaction
/// (file conflicts, missing deps rpm checks again itself, disk space) without
/// writing anything, for `vez install --dry-run`.
///
/// Signature/digest verification runs inside the real rpm transaction (rpm
/// always checks unless the package's repo has `gpgcheck = false` or
/// `no_gpgchecks` is set). Callers should run [`import_repo_keys`] first so
/// the keyring has keys to check against.
///
/// `explicit_names` are the package names the user asked for on the command
/// line (`vez install foo`), recorded with [`Reason::User`] in the history
/// log. Everything else downloaded (pulled in to satisfy a dependency) is
/// recorded as [`Reason::Dependency`], matching dnf's install-reason
/// semantics so `autoremove`/`mark` behave the same way.
///
/// `no_gpgchecks` turns signature verification off entirely for this run
/// (dnf's `--no-gpgchecks`), overriding every repo's `gpgcheck=`.
///
/// `force_replace` maps to `rpm -Uvh --replacepkgs --oldpackage`, needed for
/// `reinstall` (same EVR, which rpm would otherwise refuse as a no-op) and
/// for `downgrade`/`distro-sync` (an older EVR than installed, which rpm
/// would otherwise refuse as "package already installed" / a downgrade).
pub fn apply_install(
    paths: &OverlayPaths,
    downloaded: &[DownloadedPackage],
    repo_configs: &[RepoConfig],
    dry_run: bool,
    explicit_names: &[String],
    no_gpgchecks: bool,
    assume_yes: bool,
) -> Result<()> {
    apply_install_ex(
        paths,
        downloaded,
        repo_configs,
        dry_run,
        explicit_names,
        no_gpgchecks,
        false,
        false,
        &[],
        assume_yes,
        false,
    )
}

/// dnf-style `Is this ok [y/N]:` prompt, shown right after a transaction
/// summary and before anything on disk changes. Skipped (auto-confirmed) with
/// `-y`/`--assumeyes`, which is what the flag is for.
///
/// Public so callers that print their own transaction summary before
/// downloading (e.g. `install_ex`/`upgrade`/`sync_packages` in `vez-cli`) can
/// ask for confirmation right there, before spending time and bandwidth on
/// `download_all_ex`. See the `already_confirmed` param of
/// `apply_install_ex`.
pub fn confirm_transaction(assume_yes: bool) -> Result<bool> {
    confirm_transaction_ex(assume_yes, false, false)
}

/// Full form of [`confirm_transaction`] with dnf5's `assumeno`/`defaultyes`
/// precedence (`libdnf5-cli::utils::userconfirm`): `assume_no` beats
/// `assume_yes` (both skip the prompt), and `default_yes` only changes what
/// an empty (Enter-only) answer means; it still prompts.
pub fn confirm_transaction_ex(
    assume_yes: bool,
    assume_no: bool,
    default_yes: bool,
) -> Result<bool> {
    if assume_no {
        return Ok(false);
    }
    if assume_yes {
        return Ok(true);
    }
    use std::io::Write;
    print!(
        "\n{}",
        if default_yes {
            "Is this ok [Y/n]: "
        } else {
            "Is this ok [y/N]: "
        }
    );
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading confirmation")?;
    let choice = input.trim().to_lowercase();
    if choice.is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(choice.as_str(), "y" | "yes"))
}

/// Full form of [`apply_install`] with `force_replace`; see its doc.
///
/// `noscripts` maps to `rpm --noscripts` (dnf's
/// `--setopt=tsflags=noscripts`). Used automatically by `--installroot` (see
/// below) and by `--setopt tsflags=noscripts` on the command line for real
/// installs, e.g. kernel packages whose scriptlets shouldn't run mid-build or
/// in a container that can't handle them.
///
/// `installonly_pkgs` (`installonlypkgs=`, dnf-style globs) is taken out of
/// the main `-Uvh` call and installed with a second `rpm -ivh`. Plain `-U`
/// treats any package with the same name as an in-place upgrade and erases
/// the older version, whatever the resolver decided to keep. Real kernel RPMs
/// avoid this through an internal rpm header tag (the `installonlypkg` flag
/// near `RPMTAG_INSTALLTID`) that dnf/rpm both special-case, but vez can't
/// assume every package configured as installonly carries that tag, so it
/// enforces coexistence itself the way `rpm -i` always has: never replacing
/// anything implicitly.
pub fn apply_install_ex(
    paths: &OverlayPaths,
    downloaded: &[DownloadedPackage],
    repo_configs: &[RepoConfig],
    dry_run: bool,
    explicit_names: &[String],
    no_gpgchecks: bool,
    force_replace: bool,
    noscripts: bool,
    installonly_pkgs: &[String],
    assume_yes: bool,
    // Set when the caller already printed a transaction summary and got a `y`
    // from `confirm_transaction` *before* calling `download_all_ex` (dnf
    // always asks before spending bandwidth, not after). When true, the
    // summary and prompt below are skipped instead of asking a second time
    // about the downloaded set.
    already_confirmed: bool,
) -> Result<()> {
    if downloaded.is_empty() {
        println!("Nothing to do.");
        return Ok(());
    }
    // A dry run never touches the real overlay rpmdb (it only resolves and
    // prints the plan below), so it mustn't need root to open or init that
    // dbpath either. That would defeat the point of a cheap, unprivileged
    // "will this even resolve" check against a whole package list.
    if !dry_run {
        ensure_overlay_writable(paths)?;
    }

    // Classify each downloaded package against whatever is installed under
    // the same name, so the summary table can label it
    // Installing/Upgrading/Downgrading/Reinstalling like dnf5 instead of
    // putting everything under one "Installing:".
    let overlay_ctx = vez_overlay::OverlayContext::load(paths).ok();
    // Keyed by (name, arch), not just name. Multilib packages (e.g.
    // `mesa-filesystem`/`llvm-filesystem`) can have both an x86_64 and an
    // i686 build installed side by side, and a name-only lookup would pair a
    // newly added i686 candidate with the installed x86_64 build and mislabel
    // a plain side-by-side install as "Reinstalling"/"replacing" the other
    // arch.
    let installed_by_name: HashMap<(&str, &str), &Package> = overlay_ctx
        .as_ref()
        .map(|ctx| {
            ctx.base
                .iter()
                .chain(&ctx.overlay)
                .map(|p| ((p.nevra.name.as_str(), p.nevra.arch.as_str()), p))
                .collect()
        })
        .unwrap_or_default();
    let entries: Vec<Entry> = downloaded
        .iter()
        .map(|d| {
            let pkg = &d.package;
            match installed_by_name.get(&(pkg.nevra.name.as_str(), pkg.nevra.arch.as_str())) {
                Some(old) => {
                    let cmp = vez_core::EvrCompare::compare_evr(
                        pkg.nevra.evr().as_str(),
                        &old.nevra.evr(),
                    );
                    let action = match cmp {
                        std::cmp::Ordering::Equal => Action::Reinstalling,
                        std::cmp::Ordering::Greater => Action::Upgrading,
                        std::cmp::Ordering::Less => Action::Downgrading,
                    };
                    Entry::new(action, pkg).replacing(old)
                }
                None => Entry::new(Action::Installing, pkg),
            }
        })
        .collect();
    if !already_confirmed {
        print_transaction_summary(&entries);

        if !dry_run && !confirm_transaction(assume_yes)? {
            println!("Operation aborted.");
            return Ok(());
        }
    }

    if dry_run {
        // Nothing below this point is safe (or useful) to run unprivileged:
        // the rpm `--test` call needs to open the real overlay dbpath, which
        // a dry run never initializes above. The plan already printed by
        // `print_transaction_summary` is what a dry run is for (whether it
        // resolves and what it would do), so stop here.
        println!("Transaction test succeeded.");
        return Ok(());
    }

    check_disk_space(&diskspace_target(paths), downloaded)?;

    if no_gpgchecks {
        println!("Skipping GPG signature verification (--no-gpgchecks).");
    } else if repo_configs.is_empty() {
        // No repo metadata at all means every package here came from a local
        // file or URL install (`vez install ./foo.rpm` / `vez install
        // https://.../foo.rpm`) instead of repo resolution. There's no
        // `gpgcheck=`/`gpgkey=` to check against, and no guarantee the
        // signer's key has been imported. dnf's default for this case
        // (`localpkg_gpgcheck=False`) is to skip the check instead of
        // rejecting every unsigned or untrusted local/URL rpm.
        println!("Skipping GPG signature verification (local/URL RPM install).");
    } else {
        // Signature/digest verification happens inside the real `rpm
        // -Uvh`/`-ivh` transaction below (rpm always checks unless
        // `--nosignature --nodigest` is passed, which only happens in the two
        // cases handled above). A separate `rpm -K` pre-flight used to run as
        // well and text-parse its stdout for "OK"/"NOT OK". It broke when a
        // newer rpm changed `-K`'s wording and rejected good packages with a
        // nonsensical "signature verification failed ... digests signatures
        // OK" error. rpm's own check inside the transaction (exit status, not
        // matched stdout strings) is now the only check.
        println!("Verifying package signatures...");
    }

    // Real `installonly_pkgs` (kernel-style packages that coexist side by
    // side) AND ordinary new-arch multilib additions (e.g. adding
    // `mesa-filesystem.i686` next to an installed `mesa-filesystem.x86_64`)
    // both need the separate `-ivh` batch below and not `-Uvh`. That looks
    // redundant, since `rpm -U` is documented as "install, replacing an older
    // version of the same package if present". But rpm's same-name upgrade
    // collapsing keys on Name alone for packages without ELF-colored files to
    // tell multilib builds apart (e.g. `mesa-filesystem`, `llvm-filesystem`,
    // pure metadata/license packages). A real `rpm -Uvh
    // mesa-filesystem-X.i686.rpm` on a system with `mesa-filesystem-X.x86_64`
    // installed fails with "mesa-filesystem(x86-64) = X is needed by
    // (installed) mesa-dri-drivers-X.x86_64": rpm's dependency check treats
    // the i686 upgrade as having replaced the x86_64 Provides, even though
    // nothing in the transaction should touch the x86_64 build. `rpm -i`
    // never tries that same-name replacement, so it adds the new arch
    // cleanly. An earlier version sent *every* new-arch package through
    // `-ivh`, which could split a dependency pair in the same transaction
    // (e.g. `xz-devel.i686` requiring `xz-libs.i686`) across the two
    // non-atomic rpm calls when only one side had an installed other-arch
    // copy that triggered the old name-only classification. This version
    // still classifies per package by "is (name, arch) new while `name` is
    // installed under a *different* arch", but the resolver makes sure a
    // dependency between two candidates in the same transaction lands in the
    // same batch by that rule (both halves of a multilib pair like
    // `xz-devel.i686`/`xz-libs.i686` usually get the same answer to "does
    // this name have another arch installed"), and `-Uvh` still runs first so
    // a truly new name in that batch exists before `-ivh` needs it.
    let (installonly, upgradeable): (Vec<&DownloadedPackage>, Vec<&DownloadedPackage>) =
        downloaded.iter().partition(|d| {
            let pkg = &d.package;
            vez_core::name_matches_any(&pkg.nevra.name, installonly_pkgs)
                || (!installed_by_name
                    .contains_key(&(pkg.nevra.name.as_str(), pkg.nevra.arch.as_str()))
                    && installed_by_name
                        .iter()
                        .any(|(&(name, arch), _)| name == pkg.nevra.name && arch != pkg.nevra.arch))
        });

    let run_rpm = |verb: &str, pkgs: &[&DownloadedPackage], extra_nodeps: bool| -> Result<()> {
        if pkgs.is_empty() {
            return Ok(());
        }

        let mut cmd = Command::new("rpm");
        with_dbpath(&mut cmd, paths).arg(verb);
        if no_gpgchecks || repo_configs.is_empty() {
            // rpm's transaction step runs its own signature/digest check by
            // default whatever `--no-gpgchecks` says. Without turning that
            // off here too, an unsigned or self-signed package from a test or
            // local repo still gets rejected at `rpm -Uvh` even though the
            // user asked to skip verification.
            //
            // `repo_configs.is_empty()` is the same local/URL RPM install
            // case handled above (see the "Skipping GPG signature
            // verification (local/URL RPM install)" branch). vez decided not
            // to run its own check there and said so, but without this, rpm's
            // check still ran underneath and rejected the package (typically
            // unsigned, e.g. a locally built akmod RPM) with "does not
            // verify: no signature" regardless of what we printed.
            cmd.arg("--nosignature").arg("--nodigest");
        }
        // `--oldpackage` always. The resolver decides whether a downgrade is
        // acceptable, not `rpm`
        // (`SOLVER_FLAG_ALLOW_DOWNGRADE`/`req.allow_downgrade`, on by default
        // to match dnf5; see vez-solv's comment on that flag). By the time a
        // resolved plan gets here, any `Downgrade` step in it is intentional
        // and the SAT solver already checked it against the rest of the
        // transaction. dnf5 doesn't ask `rpm` for permission again at apply
        // time either. Without this, `rpm -Uvh` rejects the downgrade with
        // "package ... (which is newer than ...) is already installed" (exit
        // 23) even though the resolver's printed plan listed it under
        // "Downgrading:". Seen with `vez install steam inputplumber ...
        // gamescope-session-steam` on the KDE base image, when the repos'
        // current `libsoup3.i686` build was older than the installed
        // `libsoup3.x86_64`: the solver correctly allowed a same-name arch
        // sync and `rpm` refused it. `--replacepkgs` stays gated on
        // `force_replace`; that's the unrelated "same NEVRA installed,
        // reinstall anyway" case (`swap`/`--force`).
        cmd.arg("--oldpackage");
        if force_replace {
            cmd.arg("--replacepkgs");
        }
        if extra_nodeps {
            // The two-batch split below (`-ivh`/`-Uvh`) only exists to work
            // around an rpm quirk (see the long comment where the split
            // happens). It has nothing to do with whether dependencies can be
            // satisfied, which the SAT resolver already checked across the
            // *whole* download set before this function ran. When the split's
            // two ordering requirements (file-conflict safety vs.
            // dependencies across batches being available) conflict, no
            // single order of two non-atomic calls works, so this batch's
            // dependency check against a sibling batch that by construction
            // hasn't run yet is a false positive caused by our batching, not
            // an unmet dependency.
            cmd.arg("--nodeps");
        }
        if paths.needs_nodeps() {
            // Under --installroot, and in a real Split-mode overlay install,
            // the target dbpath only has overlay-owned packages. Requires
            // satisfied by the base (glibc, libstdc++, etc.) have no Provides
            // record there (see the doc comment on
            // `OverlayPaths::needs_nodeps`). vez's SAT resolver already
            // checked dependencies across base+overlay before building this
            // transaction, so rpm's db-only check is redundant and would
            // reject every capability the base provides.
            cmd.arg("--nodeps");
        }
        if noscripts {
            // Explicit opt-out only (`--setopt tsflags=noscripts`, or the
            // very first installroot layer before a shell exists; callers
            // that know their installroot has no /bin/sh yet should pass it).
            // `with_dbpath` already gives rpm `--root <installroot>` for an
            // installroot build, so rpm chroots in and runs %post/%postun
            // scriptlets (including the
            // `%systemd_post`/`systemd-update-helper install-system-units`
            // macros that enable shipped services) against that root, like a
            // real dnf --installroot build, once the installroot has a
            // working environment. This used to skip scripts for every
            // installroot install, which silently dropped every
            // service-enablement macro from every image build.
            cmd.arg("--noscripts");
        }
        if dry_run {
            cmd.arg("--test");
            println!("Running transaction test");
        } else {
            println!("Running transaction");
        }
        for d in pkgs {
            cmd.arg(&d.rpm_path);
        }

        if dry_run {
            // `--test` never installs anything, so its (much shorter)
            // dependency-check output isn't worth reformatting.
            let status = cmd.status().context("spawning rpm")?;
            anyhow::ensure!(status.success(), "rpm transaction failed with {status}");
        } else {
            let steps: Vec<(String, u64)> = pkgs
                .iter()
                .map(|d| (d.package.nevra.to_string(), d.package.install_size))
                .collect();
            run_rpm_transaction(cmd, &steps, "Installing", pkgs)?;
        }
        Ok(())
    };

    // These are two separate, non-atomic `rpm` calls, so which one runs first
    // matters, and it can go either way:
    //
    // - If the *same name* appears in both batches (a real cross-arch
    //   pairing, e.g. `ngtcp2.x86_64` upgrading in `-Uvh` while `ngtcp2.i686`
    //   is newly added in `-ivh`), `-Uvh` has to run first. The new-arch
    //   `-ivh` install can share on-disk files (docs, `%doc` dirs) with the
    //   other arch's build of the same name, and if `-ivh` ran while that
    //   other arch was still at its old EVR, rpm's file-conflict check would
    //   reject the new-arch install.
    // - Otherwise, if anything in `-Uvh` `Requires` a package that only
    //   exists in `-ivh` (e.g. `mesa-vulkan-drivers-freeworld.i686`, a new
    //   name with no other-arch sibling so it lands in `-Uvh`, requiring
    //   `mesa-filesystem.i686`, a new arch of an installed name that lands in
    //   `-ivh`), `-ivh` has to run first, or `-Uvh`'s dependency check fails
    //   against a package that doesn't exist yet.
    //
    // Both orderings have failed for real (a mesa i686 driver install on an
    // image build hit the second one). No fixed order is always safe, so pick
    // per transaction.
    //
    // `Requires` are capability strings (plain names, sonames like
    // `libLLVM.so.22.1`, or ISA-suffixed `mesa-filesystem(x86-32)`), not
    // always package names. Matching only against the package *names* in
    // `installonly` (as an earlier version did) misses every soname or
    // ISA-suffixed dependency, which silently skipped the reorder in exactly
    // the multilib case it's for. Match against what each package `Provides`
    // (plus its implicit self-provide) instead.
    let provides_capability = |pkg: &Package, want: &str| -> bool {
        pkg.provides.iter().any(|p| p.name == want)
            || pkg.provides_self().name == want
            || pkg.nevra.name == want
    };
    let paired_cross_arch_name = upgradeable.iter().any(|u| {
        installonly
            .iter()
            .any(|i| i.package.nevra.name == u.package.nevra.name)
    });
    let upgradeable_needs_installonly = upgradeable.iter().any(|d| {
        d.package.requires.iter().any(|req| {
            installonly
                .iter()
                .any(|i| provides_capability(&i.package, &req.name))
                && !upgradeable
                    .iter()
                    .any(|u| provides_capability(&u.package, &req.name))
        })
    });
    // Both batches always run with `--nodeps`. A package's Provides and its
    // dependents can sit in *both* batches at once (e.g. `libcurl.i686` lands
    // in one batch with one dependent in the same batch and another in the
    // other batch). No fixed order of two non-atomic calls can satisfy every
    // such cross-batch edge, so rpm's per-call dependency check is unreliable
    // here whatever the order, not only in the conflicting-order case. The
    // SAT resolver already checked satisfiability across the *whole* download
    // set before this function ran, so this redundant check is always a false
    // positive from our own batching and never a real unmet dependency.
    let split_live = matches!(paths.mode, OverlayMode::Split { .. }) && paths.installroot.is_none();
    let file_lists = if split_live {
        downloaded_file_lists(downloaded)
    } else {
        Vec::new()
    };
    if split_live {
        repair_stale_opt_paths(&file_lists);
    }
    // With rpm's dependency check off for both calls (see above), only the
    // file-conflict ordering still matters: `-Uvh` runs first whenever a name
    // is paired across both batches.
    if !paired_cross_arch_name && upgradeable_needs_installonly {
        run_rpm("-ivh", &installonly, true)?;
        run_rpm("-Uvh", &upgradeable, true)?;
    } else {
        run_rpm("-Uvh", &upgradeable, true)?;
        run_rpm("-ivh", &installonly, true)?;
    }

    if split_live {
        let names: Vec<&str> = downloaded
            .iter()
            .map(|d| d.package.nevra.name.as_str())
            .collect();
        relocate_opt_installs(paths, &names);
        restore_setuid_bits(paths, &names);
        run_post_install_cache_triggers(downloaded, &file_lists);
        sync_modprobe_configs(paths, downloaded, &file_lists);
    }

    // Always run ldconfig, in every mode, as a safety net. Regenerating
    // `/etc/ld.so.cache` is normally glibc's own `%transfiletriggerin` on
    // `/usr/lib64`/`/usr/lib`/etc, a cross-package trigger that fires
    // whenever a transaction touches those directories. It's the same kind of
    // trigger that `run_post_install_cache_triggers` above makes up for in
    // Split mode (glib schemas, mime db, ...). ldconfig wasn't added there
    // because Standalone mode (one real dbpath, e.g. `--installroot`
    // base-image builds and CI) was assumed to get it from rpm's own
    // transaction. Then a CI base-image build (`--installroot`, Standalone
    // mode) installed a full package set with new shared libraries, and
    // dracut's initramfs generation right after failed with `dracut-install:
    // ERROR: could not locate dependency libc.so.6` for libraries that were
    // on disk. `dracut-install` resolves ELF `NEEDED` entries through the
    // ldconfig cache, not by walking the filesystem, and a scriptlet or
    // trigger that failed silently (see the "a package scriptlet failed...
    // continuing" warning below) had left `/etc/ld.so.cache` stale or missing
    // in the target root. `ldconfig` is idempotent and cheap, so always run
    // it against the root this transaction targeted instead of trusting rpm's
    // trigger to have fired.
    if !dry_run {
        let mut ldconfig = Command::new("ldconfig");
        if let Some(root) = &paths.installroot {
            ldconfig.arg("-r").arg(root);
        }
        match ldconfig.output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                eprintln!("  WARNING: ldconfig exited with {}", out.status);
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.trim().is_empty() {
                    eprint!("{stderr}");
                }
            }
            Err(_) => {} // ldconfig not installed, so there's nothing to regenerate the cache with
        }
    }

    println!("Complete!");

    let entries: Vec<(String, Reason)> = downloaded
        .iter()
        .map(|d| {
            let reason = if explicit_names.contains(&d.package.nevra.name) {
                Reason::User
            } else {
                Reason::Dependency
            };
            (d.package.nevra.to_string(), reason)
        })
        .collect();
    if let Err(e) = history::record(paths, history::Action::Install, &entries) {
        tracing::warn!(error = %e, "failed to record transaction history");
    }
    Ok(())
}

/// Packages (`.rpm` paths or installed names) per batched `rpm` call. Keeps
/// argv well under ARG_MAX even with long cache paths.
const RPM_BATCH: usize = 256;

/// Every downloaded package's file list, read from the `.rpm` headers with
/// one `rpm -qp` per [`RPM_BATCH`] packages and shared by every post-install
/// pass below. These passes used to spawn `rpm -qlp` once per package *per
/// pass*, i.e. thousands of rpm processes for a large (re)install at boot.
/// Index-aligned with `downloaded`.
fn downloaded_file_lists(downloaded: &[DownloadedPackage]) -> Vec<Vec<String>> {
    // FILENAMES are always absolute paths, so a line that doesn't start with
    // '/' can't be mistaken for one.
    const MARKER: &str = "@vez-pkg@";
    let mut lists = Vec::with_capacity(downloaded.len());
    for chunk in downloaded.chunks(RPM_BATCH) {
        let batched = Command::new("rpm")
            .arg("-qp")
            .arg("--qf")
            .arg(format!("{MARKER}\\n[%{{FILENAMES}}\\n]"))
            .args(chunk.iter().map(|d| &d.rpm_path))
            .output()
            .ok()
            .and_then(|out| {
                let mut per_pkg: Vec<Vec<String>> = Vec::with_capacity(chunk.len());
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    if line == MARKER {
                        per_pkg.push(Vec::new());
                    } else if let Some(cur) = per_pkg.last_mut().filter(|_| line.starts_with('/')) {
                        cur.push(line.to_string());
                    }
                }
                // rpm reports an unreadable file on stderr and moves on to
                // the next one, which would shift every following list onto
                // the wrong package. Only trust the batch if exactly one
                // marker per package came back.
                (per_pkg.len() == chunk.len()).then_some(per_pkg)
            });
        match batched {
            Some(per_pkg) => lists.extend(per_pkg),
            None => lists.extend(chunk.iter().map(|d| single_rpm_file_list(&d.rpm_path))),
        }
    }
    lists
}

fn single_rpm_file_list(rpm_path: &Path) -> Vec<String> {
    match Command::new("rpm").arg("-qlp").arg(rpm_path).output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.starts_with('/'))
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// `rpm -q --dump` over many installed package names, one call per
/// [`RPM_BATCH`] names, output concatenated. A name that isn't installed only
/// adds a "package X is not installed" line, which every caller's column
/// parsing already ignores (no `/`-prefixed path, no octal mode), so rpm's
/// non-zero exit in that case isn't treated as fatal.
fn rpm_dump_installed(paths: &OverlayPaths, names: &[&str]) -> String {
    let mut all = String::new();
    for chunk in names.chunks(RPM_BATCH) {
        let mut cmd = Command::new("rpm");
        with_dbpath(&mut cmd, paths)
            .arg("-q")
            .arg("--dump")
            .args(chunk);
        if let Ok(out) = cmd.output() {
            all.push_str(&String::from_utf8_lossy(&out.stdout));
        }
    }
    all
}

/// Guards against `rpm`'s cpio payload extraction failing outright when a
/// package about to be installed ships files under `/opt/<name>/...` and
/// `/opt/<name>` already exists in a state cpio can't reconcile. Seen as
/// `cpio: mkdir failed - File exists` (followed by `No data available` on the
/// next file in the same payload) during a plain first-time `vez install`.
/// `relocate_opt_installs` below only runs *after* a successful transaction,
/// so it can't repair this, and nothing ran *before* the transaction to make
/// sure `/opt/<name>` is either absent or the live compat symlink into
/// `/usr/lib/opt/<name>` before cpio touches it. The likely real-world cause
/// is a `/usr/lib/opt/<name>` payload that was lost separately from `/opt`,
/// e.g. a replay clearing the overlay upper (which holds
/// `/usr/lib/opt`) while `/opt`'s compat symlink or a stale directory
/// survives on the real, non-overlaid root. Any leftover non-symlink entry at
/// `/opt/<name>` (a plain directory from an interrupted earlier install, or a
/// stray file) hits the same cpio failure and gets repaired the same way
/// here.
///
/// For each package about to be installed, look up its `/opt/<name>` top
/// levels in the downloaded `.rpm` (no install needed yet), then:
/// - leave `/opt/<name>` alone if it's already the expected symlink into
///   `/usr/lib/opt/<name>`, since cpio writes straight through it;
/// - otherwise remove it (dir or file), so cpio gets a clean path to create,
///   which is the state a real first-time install has.
///
/// Only meaningful under `OverlayMode::Split` with no `--installroot`, same
/// as `relocate_opt_installs`.
fn repair_stale_opt_paths(file_lists: &[Vec<String>]) {
    use std::path::Path;

    let mut tops: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in file_lists.iter().flatten() {
        let Some(rel) = line.strip_prefix("/opt/") else {
            continue;
        };
        if let Some(top) = rel.split('/').next().filter(|t| !t.is_empty()) {
            tops.insert(top.to_string());
        }
    }

    for top in tops {
        let opt_path = Path::new("/opt").join(&top);
        let target = Path::new("/usr/lib/opt").join(&top);
        let Ok(meta) = opt_path.symlink_metadata() else {
            continue;
        };
        if meta.file_type().is_symlink() && std::fs::read_link(&opt_path).is_ok_and(|l| l == target)
        {
            // Already the expected compat symlink. cpio writes through it
            // into the real location, which is part of the overlay.
            continue;
        }
        eprintln!(
            "  Clearing stale /opt/{top} ({}) before install so rpm can create it fresh",
            if meta.is_dir() {
                "directory"
            } else {
                "file/symlink"
            }
        );
        let result = if meta.is_dir() {
            std::fs::remove_dir_all(&opt_path)
        } else {
            std::fs::remove_file(&opt_path)
        };
        if let Err(e) = result {
            eprintln!(
                "  WARNING: could not clear stale {}: {e}",
                opt_path.display()
            );
        }
    }
}

/// Split mode's overlay only covers `/usr` (`overlay_mount.rs` mounts
/// `lowerdir={SYSROOT}/usr,upperdir=...` and nothing else). An RPM that ships
/// files under `/opt/<name>` therefore writes to the real, non-overlaid
/// `/opt` on the persistent root and never becomes part of the overlay.
/// rpm-ostree solves this the way Fedora handles `/home` and (by default)
/// `/opt`: a compat symlink baked into the image once. We can't do that
/// unconditionally because the base image leaves `/opt` a real directory
/// (nothing ships into it today), so vez does the equivalent relocation
/// itself at install time. It moves whatever a package wrote under `/opt/...`
/// to `/usr/lib/opt/...` (which is under `/usr`, so it's in the overlay
/// upper), then replaces the original top-level `/opt/<name>` with a symlink
/// into `/usr/lib/opt/<name>` so anything that expects `/opt/<name>` still
/// finds it. `/opt` and `/usr` are different mounts once the overlay is live
/// (overlayfs is only mounted at `/usr`), so a plain `rename()` across that
/// boundary fails with `EXDEV`. It copies and removes instead, keeping the
/// source's permission bits (so nothing under /opt loses e.g. a setuid bit in
/// the move). Only meaningful under `OverlayMode::Split` with no
/// `--installroot`, same as `restore_setuid_bits` below: an `--installroot`
/// build has no live overlay mount for this to matter against.
fn relocate_opt_installs(paths: &OverlayPaths, names: &[&str]) {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    let mut top_level: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Whether `/opt/<top>` is already the compat symlink into
    // `/usr/lib/opt/<top>`, cached per top-level name across every package
    // handled in this call. It can only change once (created at the end of
    // this function, for the *first* package that populates that top-level
    // name). This matters for packages that share a top-level `/opt`
    // directory (e.g. every `brave-browser*` package ships under
    // `/opt/brave.com`). Once the first one has turned `/opt/brave.com` into
    // the symlink, the *second* package's `rpm -Uvh` already wrote its files
    // through that symlink into `/usr/lib/opt/brave.com/...`, so `path` here
    // and its correct location are the same file reached two ways. Treating
    // it as still needing relocation and running `fs::copy(src, dest)` would
    // open the same inode for read and (truncating) write at once and destroy
    // it. So once a top level is known to be relocated, every file under it
    // is skipped instead of copied.
    let mut already_relocated: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();

    {
        let dump = rpm_dump_installed(paths, names);
        for line in dump.lines() {
            // rpm --dump columns: path size mtime digest mode owner group isconfig isdoc rdev symlink
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 {
                continue;
            }
            let path = cols[0];
            let Some(rel) = path.strip_prefix("/opt/") else {
                continue;
            };
            if rel.is_empty() {
                continue;
            }
            let Some(top) = rel.split('/').next().filter(|t| !t.is_empty()) else {
                continue;
            };
            top_level.insert(top.to_string());
            let relocated = *already_relocated.entry(top.to_string()).or_insert_with(|| {
                Path::new("/opt")
                    .join(top)
                    .symlink_metadata()
                    .is_ok_and(|m| m.file_type().is_symlink())
            });
            if relocated {
                // Already in the right place through the live symlink;
                // nothing to move.
                continue;
            }
            let Ok(mode) = u32::from_str_radix(cols[4], 8) else {
                continue;
            };
            if mode & 0o170000 == 0o040000 {
                // A plain directory entry. It was only needed for the
                // top-level bookkeeping above; `create_dir_all` on the
                // destination side (below) recreates the tree as needed.
                continue;
            }
            let src = Path::new(path);
            let Ok(src_meta) = src.symlink_metadata() else {
                continue;
            };
            let dest = Path::new("/usr/lib/opt").join(rel);
            if let Some(parent) = dest.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("  WARNING: could not create {}: {e}", parent.display());
                    continue;
                }
            }
            let result = if src_meta.file_type().is_symlink() {
                std::fs::read_link(src).and_then(|target| {
                    let _ = std::fs::remove_file(&dest);
                    std::os::unix::fs::symlink(&target, &dest)
                })
            } else {
                std::fs::copy(src, &dest).and_then(|_| {
                    std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(src_meta.permissions().mode()),
                    )
                })
            };
            match result {
                Ok(()) => {
                    let _ = std::fs::remove_file(src);
                }
                Err(e) => eprintln!(
                    "  WARNING: could not relocate {} to {}: {e}",
                    src.display(),
                    dest.display()
                ),
            }
        }
    }

    for top in top_level {
        let opt_path = Path::new("/opt").join(&top);
        let target = Path::new("/usr/lib/opt").join(&top);
        if !target.exists()
            || opt_path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
        {
            continue;
        }
        if opt_path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&opt_path) {
                eprintln!(
                    "  WARNING: could not remove {} to replace it with a symlink: {e}",
                    opt_path.display()
                );
                continue;
            }
        }
        match std::os::unix::fs::symlink(&target, &opt_path) {
            Ok(()) => println!("  Relocated /opt/{top} -> {}", target.display()),
            Err(e) => eprintln!(
                "  WARNING: could not symlink {} -> {}: {e}",
                opt_path.display(),
                target.display()
            ),
        }
    }
}

/// Collects the top-level `/opt/<name>` components a set of still-installed
/// packages owns, by reading their file lists with `rpm -q --dump` before
/// they're erased (afterwards there's nothing to query). Feeds
/// `cleanup_opt_relocations` below.
fn opt_top_level_names(
    paths: &OverlayPaths,
    qualified_names: &[String],
) -> std::collections::HashSet<String> {
    let mut tops = std::collections::HashSet::new();
    let names: Vec<&str> = qualified_names.iter().map(String::as_str).collect();
    for line in rpm_dump_installed(paths, &names).lines() {
        let Some(path) = line.split_whitespace().next() else {
            continue;
        };
        let Some(rel) = path.strip_prefix("/opt/") else {
            continue;
        };
        if let Some(top) = rel.split('/').next().filter(|t| !t.is_empty()) {
            tops.insert(top.to_string());
        }
    }
    tops
}

/// Reverses `relocate_opt_installs` once no package owns anything under a
/// relocated `/opt/<name>` -> `/usr/lib/opt/<name>` symlink anymore. `rpm
/// -evh` already erased the files from `/usr/lib/opt/<name>` (that's where
/// they lived), so this only drops the now-empty directory and the compat
/// symlink at `/opt/<name>`. Leaving a dangling symlink after its last user
/// is gone would be worse than plain, unrelocated `/opt` removal. If another
/// installed package shares the same top-level `/opt/<name>`,
/// `/usr/lib/opt/<name>` isn't empty yet and both the directory and the
/// symlink are left alone.
fn cleanup_opt_relocations(tops: &std::collections::HashSet<String>) {
    use std::path::Path;
    for top in tops {
        let target = Path::new("/usr/lib/opt").join(top);
        let opt_path = Path::new("/opt").join(top);
        // `rpm -e` only rmdir()s the *specific* parent directories of the
        // files it erased, through whatever path it walked (here the live
        // `/opt/<top>` symlink). It doesn't prune every directory back up to
        // `<top>`, so a package that shared `<top>` with something still
        // installed, or whose subdirectories rpm didn't fully unwind, can
        // leave harmless empty leaf directories under `/usr/lib/opt/<top>`.
        // Treat the whole tree as removable if every leaf under it is an
        // empty directory (no files anywhere), not only when the top-level
        // dir itself is empty.
        if !prune_if_all_empty(&target) {
            continue;
        }
        if opt_path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            match std::fs::remove_file(&opt_path) {
                Ok(()) => println!(
                    "  Removed relocated /opt/{top} symlink (no files left under {})",
                    target.display()
                ),
                Err(e) => eprintln!("  WARNING: could not remove {}: {e}", opt_path.display()),
            }
        }
    }
}

/// Recursively removes `dir` if it and everything under it contain no files,
/// only empty directories all the way down. Returns whether `dir` itself was
/// removed. A single file anywhere in the tree stops the whole prune and
/// leaves everything as it is, so it never deletes real content.
fn prune_if_all_empty(dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut all_empty = true;
    for entry in entries.flatten() {
        // `file_type()` here is effectively `lstat` (it doesn't follow
        // symlinks), so a symlink never counts as a directory below.
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        if is_dir {
            if !prune_if_all_empty(&entry.path()) {
                all_empty = false;
            }
        } else {
            all_empty = false;
        }
    }
    all_empty && std::fs::remove_dir(dir).is_ok()
}

/// overlayfs strips setuid/setgid bits when a file is first written into the
/// upperdir. rpm's install just wrote every file this transaction touched
/// there, so anything the RPM declared setuid/setgid (sudo, ping, fusermount,
/// etc.) comes out without its privilege bit. Read the mode the package
/// declared with `rpm -q --dump` and apply it to the upperdir copy. Only
/// meaningful under `OverlayMode::Split` with no `--installroot` (a real,
/// live Svara overlay); an `--installroot` build is a disposable tree with
/// no live overlay mount to strip bits in the first place.
fn restore_setuid_bits(paths: &OverlayPaths, names: &[&str]) {
    use std::os::unix::fs::PermissionsExt;
    {
        let dump = rpm_dump_installed(paths, names);
        for line in dump.lines() {
            // rpm --dump columns: path size mtime digest mode owner group isconfig isdoc rdev symlink
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 5 {
                continue;
            }
            let path = cols[0];
            let Ok(mode) = u32::from_str_radix(cols[4], 8) else {
                continue;
            };
            if mode & 0o6000 == 0 {
                continue;
            }
            let Some(rel) = path.strip_prefix("/usr/") else {
                continue;
            };
            let upper_path = paths.overlay_upper.join(rel);
            if !upper_path.exists() {
                continue;
            }
            let full_mode = mode & 0o7777;
            match std::fs::set_permissions(&upper_path, std::fs::Permissions::from_mode(full_mode))
            {
                Ok(()) => println!(
                    "  Restored setuid mode {full_mode:04o} on {}",
                    upper_path.display()
                ),
                Err(e) => eprintln!(
                    "  WARNING: could not restore mode on {}: {e}",
                    upper_path.display()
                ),
            }
        }
    }
}

/// Pulls one scriptlet block out of `rpm -q(p) --scripts` output to re-run it
/// through `/bin/sh`, but only if rpm would have run it through a shell. rpm
/// labels each block `<marker><interp>):` with the script on the next line,
/// and `<interp>` isn't always `/bin/sh`. Lua scriptlets (`<lua>`, used by
/// e.g. glibc and crypto-policies) run in rpm's embedded Lua interpreter, and
/// piping their text into `/bin/sh -c` only produces Lua syntax errors. rpm
/// already ran the scriptlet correctly (with its declared interpreter) during
/// the real transaction. This function only feeds the extra re-run passes in
/// this file, which react to `daemon-reload` and don't replace rpm's own
/// scriptlet execution, so skipping non-shell interpreters loses nothing: the
/// real scriptlet still ran once.
fn extract_shell_scriptlet<'a>(scripts: &'a str, marker: &str) -> Option<&'a str> {
    let rest = scripts.split(marker).nth(1)?;
    let (interp, rest) = rest.split_once("):\n")?;
    if interp.trim() != "/bin/sh" && interp.trim() != "sh" {
        return None;
    }
    let rest = rest
        .split("\npostinstall scriptlet")
        .next()
        .unwrap_or(rest)
        .split("\npreuninstall scriptlet")
        .next()
        .unwrap_or(rest)
        .split("\npostuninstall scriptlet")
        .next()
        .unwrap_or(rest)
        .split("\npretrans scriptlet")
        .next()
        .unwrap_or(rest)
        .split("\nposttrans scriptlet")
        .next()
        .unwrap_or(rest);
    Some(rest)
}

/// Cross-package RPM "file triggers" (glib2's `%transfiletriggerin` that
/// recompiles GSettings schemas, hicolor-icon-theme's icon cache,
/// desktop-file-utils' desktop database, shared-mime-info's mime database,
/// systemd's unit reload/preset trigger) only fire when the *triggering*
/// package (glib2, systemd, etc.) is registered in the same rpm dbpath the
/// transaction targets (see the doc comment on `needs_nodeps`). In
/// `OverlayMode::Split` the transaction runs against an overlay-only dbpath
/// that never contains those base-owned packages, so rpm never fires them.
/// Installing `virt-manager` (which ships
/// `/usr/share/glib-2.0/schemas/org.virt-manager.virt-manager.gschema.xml`)
/// left the compiled `gschemas.compiled` index stale, and virt-manager
/// aborted at startup with "Settings schema ... is not installed". The
/// overlay is mounted live, so the merged `/usr/share/...` tree already has
/// the new files when this runs. Just re-run the regen command a real dnf
/// transaction's file trigger would have run, once per matched directory for
/// the whole transaction (using the file lists already read from every
/// downloaded package) and not once per package.
fn run_post_install_cache_triggers(downloaded: &[DownloadedPackage], file_lists: &[Vec<String>]) {
    if downloaded.is_empty() {
        return;
    }

    let mut needs_glib_schemas = false;
    let mut needs_mime_db = false;
    let mut needs_desktop_db = false;
    let mut needs_fc_cache = false;
    let mut icon_theme_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut shipped_units: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Which downloaded packages (by index) ship a unit themselves. Only their
    // `%post` needs re-running after `daemon-reload` below.
    let mut unit_shippers: Vec<usize> = Vec::new();

    for (idx, path) in file_lists
        .iter()
        .enumerate()
        .flat_map(|(i, files)| files.iter().map(move |f| (i, f.as_str())))
    {
        if let Some(rest) = path.strip_prefix("/usr/share/glib-2.0/schemas/") {
            needs_glib_schemas |= !rest.is_empty();
        } else if path.starts_with("/usr/share/mime/") {
            needs_mime_db = true;
        } else if path.starts_with("/usr/share/applications/") {
            needs_desktop_db = true;
        } else if path.starts_with("/usr/share/fonts/") {
            needs_fc_cache = true;
        } else if let Some(rest) = path.strip_prefix("/usr/share/icons/") {
            if let Some(theme) = rest.split('/').next().filter(|t| !t.is_empty()) {
                icon_theme_dirs.insert(format!("/usr/share/icons/{theme}"));
            }
        } else if let Some(rest) = path.strip_prefix("/usr/lib/systemd/system/") {
            // Only a bare unit directly in the directory (skip drop-in
            // `.wants/`/`.requires/`/`.d/` entries and anything nested).
            let is_unit = rest.ends_with(".service")
                || rest.ends_with(".socket")
                || rest.ends_with(".timer")
                || rest.ends_with(".path")
                || rest.ends_with(".target");
            if is_unit && !rest.contains('/') {
                shipped_units.insert(rest.to_string());
                if unit_shippers.last() != Some(&idx) {
                    unit_shippers.push(idx);
                }
            }
        }
    }

    // Captured instead of inherited: `glib-compile-schemas` in particular
    // prints a huge wall of "Ignoring override for key ..." noise to stderr
    // for perfectly normal overrides, which buried the rest of the
    // transaction's output. Only show it if the command failed.
    let run =
        |label: &str, program: &str, args: &[&str]| match Command::new(program).args(args).output()
        {
            Ok(out) if out.status.success() => println!("  {label}: {program} {}", args.join(" ")),
            Ok(out) => {
                eprintln!(
                    "  WARNING: {program} {} exited with {}",
                    args.join(" "),
                    out.status
                );
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.trim().is_empty() {
                    eprint!("{stderr}");
                }
            }
            Err(_) => {} // tool not installed, so nothing to regenerate with (same as a real transaction without the owning package)
        };

    if needs_glib_schemas {
        run(
            "Regenerated cache",
            "glib-compile-schemas",
            &["/usr/share/glib-2.0/schemas"],
        );
    }
    if needs_mime_db {
        run(
            "Regenerated cache",
            "update-mime-database",
            &["/usr/share/mime"],
        );
    }
    if needs_desktop_db {
        run(
            "Regenerated cache",
            "update-desktop-database",
            &["/usr/share/applications"],
        );
    }
    if needs_fc_cache {
        // No `-f`: that rebuilds every font directory's cache even when it's
        // up to date. Plain `fc-cache` only refreshes directories whose mtime
        // changed, which is what this install touched.
        run("Regenerated cache", "fc-cache", &[]);
    }
    // systemd's own `%transfiletriggerin` on /usr/lib/systemd/system (owned
    // by the `systemd` package, not the one we're installing) normally runs
    // `systemctl daemon-reload` after a unit file lands. Same cross-package
    // trigger gap as the glib schemas case above, since `systemd` is never
    // registered in the overlay-only dbpath.
    if !shipped_units.is_empty() {
        run("Systemd", "systemctl", &["daemon-reload"]);
        // A blind `systemctl preset` only enables a unit when a matching
        // preset policy file says so. Most systems' catch-all policy is
        // "disable *", so it does nothing for a unit whose package calls
        // `systemctl enable` explicitly in its own `%post`. (rpm's
        // `%systemd_post` macro presets on first install, but plenty of
        // packages, e.g. nix-daemon, ship a hand-written `%post` with a
        // literal `enable`/`start`.) That `%post` already ran in this rpm
        // transaction (scriptlets aren't skipped here; see the doc comment on
        // `noscripts`), so it isn't lost, but it may have had no effect if it
        // called `systemctl` before `daemon-reload` saw the new unit file. So
        // re-run the package's actual `%post` after the reload, and the unit
        // ends up enabled/started the way the package's own scriptlet asked
        // for instead of the way a guessed preset policy would leave it. This
        // used to hand-tokenize the scriptlet looking for lines starting with
        // a bare `systemctl `/`systemd-update-helper ` prefix, which missed
        // anything wrapped in a shell conditional or set through a variable
        // (e.g. libvirt's subpackages, whose `%systemd_post`-generated
        // `%post` blocks branch on `$1` and quote the unit list instead of
        // emitting one flat `systemctl ...` line). rpm runs `%post` through
        // `/bin/sh`, so we do too instead of parsing shell as plain text.
        // `$1` is `1` to match the "first install" case `%systemd_post`
        // checks for, since this only runs for freshly downloaded packages.
        //
        // Only packages that ship a unit themselves are re-run. A `%post` in
        // a package without a unit has nothing the reload could have changed,
        // and re-running every package's `%post` whenever *any* of them
        // shipped a unit meant hundreds of redundant scriptlets (ldconfig,
        // cache rebuilds, ...) on a large reinstall at boot.
        for &idx in &unit_shippers {
            let d = &downloaded[idx];
            let Ok(out) = Command::new("rpm")
                .args(["-qp", "--scripts"])
                .arg(&d.rpm_path)
                .output()
            else {
                continue;
            };
            if !out.status.success() {
                continue;
            }
            let scripts = String::from_utf8_lossy(&out.stdout);
            let Some(post) = extract_shell_scriptlet(&scripts, "postinstall scriptlet (using ")
            else {
                continue;
            };
            if post.trim().is_empty() {
                continue;
            }
            match Command::new("/bin/sh")
                .arg("-c")
                .arg(post)
                .arg("post")
                .arg("1")
                .output()
            {
                Ok(out) if out.status.success() => {
                    println!("  Ran postinstall scriptlet: {}", d.rpm_path.display())
                }
                Ok(out) => {
                    eprintln!(
                        "  WARNING: postinstall scriptlet for {} exited with {}",
                        d.rpm_path.display(),
                        out.status
                    );
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if !stderr.trim().is_empty() {
                        eprint!("{stderr}");
                    }
                }
                Err(_) => {}
            }
        }

        // For most packages the re-run `%post` above only calls a bare
        // `systemctl enable` (no `--now`). That's what `%systemd_post` emits,
        // because in a normal rpm transaction the service is expected to
        // start on the *next* boot. vez's overlay install applies live,
        // though, so a service the transaction just enabled should also be
        // running afterwards instead of waiting for a reboot the user has no
        // reason to expect. Only start units that ended up enabled (not just
        // present) and aren't active yet, so this never fights a package that
        // left its unit disabled or masked on purpose.
        //
        // Skipped inside a container build. `vez install` also runs in `bootc
        // container lint`-style image builds (podman/buildah `RUN` steps),
        // which apply this same Split-mode transaction to a buildroot.
        // Checking for `/run/systemd/system` isn't enough, because some of
        // those build environments run a real systemd as PID 1 inside the
        // build container (so scriptlets can call `systemctl` at all), and
        // then that directory exists there too. `systemctl start` there isn't
        // a no-op: it starts the real service (dbus activation, cryptsetup,
        // akmods, etc.) inside the disconnected build container and leaves
        // runtime state in /run and /tmp, which fails bootc's container lint
        // (`nonempty-run-tmp`, and the `runtime-deps` "path led outside of
        // the filesystem" lint once a started service touches a mount or
        // symlink that only makes sense on a real root). podman and buildah
        // both mark every `RUN` step clearly: they write `/run/.containerenv`
        // into the container filesystem and set the `container` environment
        // variable. Check both, since systemd's own container detection uses
        // either one.
        let in_container_build =
            Path::new("/run/.containerenv").exists() || std::env::var_os("container").is_some();
        if !in_container_build && Path::new("/run/systemd/system").is_dir() {
            for unit in &shipped_units {
                let Ok(out) = Command::new("systemctl")
                    .args(["is-enabled", unit.as_str()])
                    .output()
                else {
                    continue;
                };
                let state = String::from_utf8_lossy(&out.stdout);
                let state = state.trim();
                if state != "enabled" && state != "enabled-runtime" && state != "static" {
                    continue;
                }
                if state == "static" {
                    continue; // static units have no [Install] section, so nothing "enabled" them
                }
                let already_active = Command::new("systemctl")
                    .args(["is-active", "--quiet", unit.as_str()])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !already_active {
                    run("Systemd", "systemctl", &["start", unit.as_str()]);
                }
            }
        }
    }
    for dir in &icon_theme_dirs {
        if Path::new(dir).join("index.theme").exists() {
            run(
                "Regenerated cache",
                "gtk-update-icon-cache",
                &["-f", "-q", dir],
            );
        }
    }
}

/// Directory under `state_dir` with one file per package whose
/// modprobe.d/modules-load.d config vez copied into `/etc` (see
/// [`sync_modprobe_configs`]). Each file lists the `/etc` paths that
/// package's copy created, so [`cleanup_modprobe_configs`] knows exactly what
/// to remove on uninstall without guessing from the package name.
fn modprobe_sync_state_dir(paths: &OverlayPaths) -> PathBuf {
    paths.state_dir.join("modprobe-sync")
}

/// Nvidia's driver packages ship `nvidia-modprobe`, a setuid helper that
/// creates `/dev/nvidia*` device nodes and loads the driver modules on demand
/// itself, so the generic sync/cleanup here does not need to manage their
/// modprobe.d/modules-load.d state.
///
/// TODO(verify): this skip was inherited from the upstream fork, where a
/// separate desktop-switcher flow also managed these files. **Svara has no such
/// flow**: `shell/` and `backend/` mention Nvidia only to *read*
/// `nvidia-smi` for the resources widget (`backend/internal/resources`), and
/// nothing in this repository installs, swaps or configures a driver. So the
/// original justification does not hold here and has been replaced rather than
/// repeated. The skip itself is left in place because `nvidia-modprobe` loading
/// the modules on demand is a real reason not to also copy configs, but that is
/// now the whole reason, and nobody has verified it on a machine with an Nvidia
/// driver installed through vez. If the driver does not load on demand on such a
/// machine, this is the first thing to suspect.
///
/// Matches by name instead of an exact package list because Nvidia's packaging
/// spans `nvidia-driver`, `nvidia-driver-cuda`, `nvidia-kmod*`,
/// `nvidia-modprobe`, `nvidia-settings`, `akmod-nvidia`,
/// `xorg-x11-drv-nvidia*`.
fn is_nvidia_package(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("nvidia")
}

/// Copies each newly installed package's `modprobe.d`/`modules-load.d` `.conf`
/// files into `/etc`.
///
/// The reason is ordering, and it is worth writing down because it depends on
/// when Svara's overlay comes up. A package ships those files under `/usr/lib`,
/// so a package vez installed has them in the overlay upper. The
/// early-boot `systemd-modules-load.service` that runs from the *initrd* cannot
/// see an overlay that a system unit mounts later, so a config only the overlay
/// provides would be missed by an initrd load.
///
/// `/etc` does not have that problem: it is outside the overlay/`/usr` split
/// entirely, always the real persistent `/etc`, so a file placed there is read
/// by the ordinary `systemd-modules-load.service` on every normal boot with no
/// initrd involvement. Copying once at install time therefore works whatever the
/// overlay's mount ordering turns out to be, which is the point: it does not
/// depend on the one thing in this design that is decided elsewhere.
///
/// If the overlay mount is ever moved into the initramfs (see
/// `docs/plan/package-manager.md`, the overlay-timing risk), the ordinary load
/// would see the overlay's own copies and this copy becomes belt-and-braces
/// rather than load-bearing. It is harmless either way, and it is not removed
/// until that ordering is verified on a real boot.
///
/// Only copies files a package ships outside `/etc` (i.e. under `/usr/lib` or
/// `/usr/share`); a package that ships directly into `/etc` is already
/// tracked by rpm and doesn't need this. Never overwrites an existing
/// destination (a local override or an earlier package's file with the same
/// name), so a collision is left alone instead of being silently clobbered.
fn sync_modprobe_configs(
    paths: &OverlayPaths,
    downloaded: &[DownloadedPackage],
    file_lists: &[Vec<String>],
) {
    let state_dir = modprobe_sync_state_dir(paths);

    for (d, listing) in downloaded.iter().zip(file_lists) {
        if is_nvidia_package(&d.package.nevra.name) {
            continue;
        }
        let mut created: Vec<String> = Vec::new();

        for path in listing.iter().map(String::as_str) {
            if path.starts_with("/etc/modprobe.d/") || path.starts_with("/etc/modules-load.d/") {
                continue; // already tracked by rpm in place, nothing to do
            }
            let Some((subdir, basename)) =
                (if let Some(rest) = path.strip_prefix("/usr/lib/modprobe.d/") {
                    Some(("modprobe.d", rest))
                } else if let Some(rest) = path.strip_prefix("/usr/lib/modules-load.d/") {
                    Some(("modules-load.d", rest))
                } else {
                    None
                })
            else {
                continue;
            };
            if !basename.ends_with(".conf") || basename.contains('/') {
                continue;
            }

            let dest = PathBuf::from(format!("/etc/{subdir}/{basename}"));
            if dest.exists() {
                continue;
            }
            let Ok(contents) = fs::read(path) else {
                continue;
            };
            if fs::create_dir_all(dest.parent().unwrap())
                .and_then(|_| fs::write(&dest, &contents))
                .is_ok()
            {
                println!("  Activated {} config: {}", subdir, dest.display());
                created.push(dest.display().to_string());
            }
        }

        if !created.is_empty() {
            let _ = fs::create_dir_all(&state_dir);
            let _ = fs::write(
                state_dir.join(format!("{}.list", d.package.nevra.name)),
                created.join("\n"),
            );
        }
    }
}

/// Removes whatever [`sync_modprobe_configs`] copied into `/etc` for a
/// package being uninstalled. Uses the per-package list written at install
/// time instead of working it out from the removed package's file list,
/// because `rpm -qlp` needs a `.rpm` file or a still-installed entry to query
/// and neither is guaranteed to exist by the time this runs.
fn cleanup_modprobe_configs(paths: &OverlayPaths, to_remove: &[Package]) {
    let state_dir = modprobe_sync_state_dir(paths);
    for pkg in to_remove {
        if is_nvidia_package(&pkg.nevra.name) {
            continue;
        }
        let state_file = state_dir.join(format!("{}.list", pkg.nevra.name));
        let Ok(contents) = fs::read_to_string(&state_file) else {
            continue;
        };
        for line in contents.lines().filter(|l| !l.trim().is_empty()) {
            if fs::remove_file(line).is_ok() {
                println!("  Deactivated config: {line}");
            }
        }
        let _ = fs::remove_file(&state_file);
    }
}

/// The removal counterpart of the `%post` re-run in
/// [`run_post_install_cache_triggers`]. It re-runs the real `%preun`
/// scriptlet (stop/disable) of each package about to be removed, as a safety
/// net next to rpm's own scriptlet execution, so a unit that was enabled
/// before removal doesn't stay enabled. Otherwise, e.g., a leftover
/// `foo.service` symlink under `/etc/systemd/system/multi-user.target.wants/`
/// pointing at a unit file that's about to disappear would stay behind as a
/// dangling enablement that systemd silently carries forward.
///
/// Reads scripts from the *installed* copy (`rpm -q --scripts`, against this
/// transaction's dbpath) instead of a downloaded `.rpm` file. Unlike install,
/// there's no freshly downloaded package to query, only what's in the
/// overlay/base rpmdb of `paths`. Must run before the `rpm -evh` erase below:
/// `%preun`'s own `systemctl` calls also run before files are removed, since
/// disabling a unit is most reliable while its unit file still exists.
///
/// Runs the extracted `%preun` block through `/bin/sh -c`, the same way
/// `run_post_install_cache_triggers` does for `%post`, and not with a
/// line-by-line `systemctl `/`systemd-update-helper ` prefix scan. That scan
/// misses anything wrapped in a shell conditional or set through a variable
/// (the same bug `%post`'s hand tokenizer had; `%systemd_preun`-generated
/// blocks branch on `$1` and quote the unit list instead of emitting a bare
/// `systemctl ...` line). `$1` is `0` to match "last uninstall", the case
/// `%systemd_preun` checks for, since this only runs for packages being
/// removed, not upgraded.
fn run_pre_remove_systemd_disable(paths: &OverlayPaths, to_remove: &[Package]) {
    for pkg in to_remove {
        let qualified = format!("{}.{}", pkg.nevra.name, pkg.nevra.arch);
        let mut cmd = Command::new("rpm");
        with_dbpath(&mut cmd, paths)
            .arg("-q")
            .arg("--scripts")
            .arg(&qualified);
        let Ok(out) = cmd.output() else { continue };
        if !out.status.success() {
            continue;
        }
        let scripts = String::from_utf8_lossy(&out.stdout);
        let Some(preun) = extract_shell_scriptlet(&scripts, "preuninstall scriptlet (using ")
        else {
            continue;
        };
        if preun.trim().is_empty() {
            continue;
        }
        match Command::new("/bin/sh")
            .arg("-c")
            .arg(preun)
            .arg("preun")
            .arg("0")
            .output()
        {
            Ok(out) if out.status.success() => {
                println!("  Ran preuninstall scriptlet: {qualified}")
            }
            Ok(out) => {
                eprintln!(
                    "  WARNING: preuninstall scriptlet for {qualified} exited with {}",
                    out.status
                );
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.trim().is_empty() {
                    eprint!("{stderr}");
                }
            }
            Err(_) => {}
        }
    }
}

/// `rpm -e` against the merged dbpath, for `vez remove`.
///
/// `protected` is the combined `protected_packages=` list (dnf.conf) plus the
/// names vez always protects (`vez` itself). Every requested name is checked
/// against it by glob before anything is removed, so a protected package
/// can't be erased even as a side effect of `autoremove`/`swap` including it
/// among other names.
pub fn apply_remove(
    paths: &OverlayPaths,
    names: &[String],
    dry_run: bool,
    protected: &[String],
    assume_yes: bool,
) -> Result<()> {
    apply_remove_ex(paths, names, dry_run, protected, false, assume_yes)
}

/// Resolves a `remove`-style name (a bare package name or a `name.arch`)
/// against the installed set. A qualified name matches exactly the one
/// package with that name+arch. A bare name matches every installed package
/// with that name, which can be more than one under multilib (e.g. a bare
/// `libnsl` with both `.x86_64` and `.i686` installed). Being permissive here
/// is fine because the final `rpm -evh` call always re-qualifies every
/// resolved package as `name.arch`, so an ambiguous bare name never reaches
/// `rpm` to be rejected.
///
/// Falls back to a `Provides:` match when nothing is installed under that
/// literal name. This is the removal side of `install`'s fallback to the
/// provides index in `vez-solv` (see its doc comment): `dnf remove webserver`
/// removes whichever installed package provides `webserver`, not only a
/// package literally named that, and vez's remove used to look at literal
/// names only.
fn resolve_remove_name<'a>(
    overlay: &'a vez_overlay::OverlayContext,
    name: &str,
) -> Vec<&'a Package> {
    if let Some((base, arch)) = name.rsplit_once('.') {
        let qualified: Vec<&Package> = overlay
            .base
            .iter()
            .chain(&overlay.overlay)
            .filter(|p| p.nevra.name == base && p.nevra.arch == arch)
            .collect();
        if !qualified.is_empty() {
            return qualified;
        }
    }
    let by_name: Vec<&Package> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .filter(|p| p.nevra.name == name)
        .collect();
    if !by_name.is_empty() {
        return by_name;
    }
    overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .filter(|p| p.provides.iter().any(|d| d.name == name))
        .collect()
}

/// Full form of [`apply_remove`] with `nodeps`.
///
/// `nodeps` maps to `rpm -e --nodeps`, used by `swap`, which erases the old
/// side of the pair before installing the new one (see the doc on
/// `Command::Swap`). rpm's CLI can't put an install and an erase in the same
/// transaction set the way librpm can, so a swap that's part of a sequence of
/// pairs (e.g. build.sh swapping `ffmpeg-free`→`ffmpeg` and then
/// `libavcodec-free`→`libavcodec`) hits a real, correct rpm dependency error
/// here: sibling `-free` packages that haven't been swapped yet still
/// `Requires` the one being erased. A strict `-e` would block every swap but
/// the last in such a sequence. `--nodeps` accepts that the system is briefly
/// inconsistent between swaps, the way dnf's single combined transaction is
/// briefly "erased A, B not installed yet" internally; it's consistent again
/// once the whole sequence finishes.
pub fn apply_remove_ex(
    paths: &OverlayPaths,
    names: &[String],
    dry_run: bool,
    protected: &[String],
    nodeps: bool,
    assume_yes: bool,
) -> Result<()> {
    if names.is_empty() {
        return Ok(());
    }
    if let Some(blocked) = names
        .iter()
        .find(|n| vez_core::name_matches_any(n, protected))
    {
        anyhow::bail!("'{blocked}' is a protected package and cannot be removed");
    }
    if !dry_run {
        ensure_overlay_writable(paths)?;
    }

    // dnf's `remove` skips names that aren't installed ("No match for
    // argument") instead of failing the whole transaction. A caller passing
    // several names (a glob-expanded pattern, a fixed list a build script
    // always runs) shouldn't have one already-absent package abort removal of
    // everything else.
    let overlay = vez_overlay::OverlayContext::load(paths).context("loading overlay context")?;
    let mut to_remove: Vec<Package> = Vec::new();
    for n in names {
        let matches = resolve_remove_name(&overlay, n);
        if matches.is_empty() {
            println!("No match for argument: {n}");
            continue;
        }
        for pkg in matches {
            if !to_remove.iter().any(|p: &Package| p.nevra == pkg.nevra) {
                to_remove.push(pkg.clone());
            }
        }
    }
    if to_remove.is_empty() {
        println!("Nothing to remove.");
        return Ok(());
    }

    // dnf's `remove` doesn't pass only the requested set to the transaction
    // and let it fail on the first installed dependent. It computes the whole
    // dependent closure up front (its "The following ... will also be
    // removed" prompt). `--nodeps` opts out of that, as it does for the `rpm
    // -e` call below.
    if !nodeps {
        let dependents = vez_resolver::compute_removal_closure(&to_remove, &overlay);
        if let Some(blocked) = dependents
            .iter()
            .find(|p| vez_core::name_matches_any(&p.nevra.name, protected))
        {
            anyhow::bail!("'{}' is a protected package and would be removed as a dependent of this transaction", blocked.nevra.name);
        }
        if !dependents.is_empty() {
            println!("The following packages will also be removed (dependents):");
            for pkg in &dependents {
                println!("  {}", pkg.nevra);
            }
            for pkg in dependents {
                if !to_remove.iter().any(|p| p.nevra == pkg.nevra) {
                    to_remove.push(pkg);
                }
            }
        }
    }

    let entries: Vec<Entry> = to_remove
        .iter()
        .map(|pkg| Entry::new(Action::Removing, pkg))
        .collect();
    print_transaction_summary(&entries);

    // A dry run only resolves and simulates, and the summary above is the
    // whole answer, so stop here instead of running a real `rpm --test`
    // against the overlay dbpath (which needs it initialized and opened, i.e.
    // root) only to throw the result away.
    if dry_run {
        println!("Transaction test succeeded.");
        return Ok(());
    }

    if !confirm_transaction(assume_yes)? {
        println!("Operation aborted.");
        return Ok(());
    }

    // Always fully qualified as `name.arch` here, however the caller wrote
    // it. Every entry in `to_remove` is a concrete resolved package, and `rpm
    // -e name` fails as ambiguous ("specifies multiple packages") as soon as
    // two installed packages share a name across multilib arches.
    let qualified_names: Vec<String> = to_remove
        .iter()
        .map(|p| format!("{}.{}", p.nevra.name, p.nevra.arch))
        .collect();

    // `--installroot` builds a disposable tree that may not even have a
    // `/bin/sh` yet (e.g. an empty overlay-prebake installroot). Same
    // reasoning as `run_pre_remove_systemd_disable` below: a bare installroot
    // has no systemd/service state for a `%preun` to act on, and rpm's
    // scriptlet exec would just fail against it. Unlike install, remove never
    // needs a populated `--installroot` to run its removal scriptlets, so
    // this is unconditional instead of an explicit opt-out.
    if paths.installroot.is_none() {
        run_pre_remove_systemd_disable(paths, &to_remove);
    }

    let mut cmd = Command::new("rpm");
    with_dbpath(&mut cmd, paths).arg("-evh");
    if paths.installroot.is_some() {
        cmd.arg("--noscripts");
    } else {
        // `run_pre_remove_systemd_disable` above already ran each package's
        // real `%preun` once. Without this, rpm's `-evh` here runs it a
        // *second* time. That's fine for an idempotent scriptlet but fatal
        // for one that isn't: e.g. genisoimage/star's `%preun` calls
        // `alternatives --remove`, which fails the second time because the
        // first (manual) run already removed it. A failed `%preun` aborts
        // that package's erase ("error: %preun(...) scriptlet failed" /
        // "erase failed"), unlike a %post/%postun failure, which rpm treats
        // as non-fatal because the files are already committed, and that
        // takes down the whole transaction. `--nopreun` only skips rpm's own
        // redundant preun run; `%postun` and everything else still run.
        cmd.arg("--nopreun");
    }
    // In Split mode (and with --installroot), the dbpath rpm opens here is
    // the overlay-only rpmdb, which knows nothing about base-image packages.
    // Without `--nodeps`, rpm runs its erase dependency check against that
    // incomplete view. vez's `compute_removal_closure` above already did the
    // real check (it merges base + overlay to decide what else has to go), so
    // a second check that can't see the base can only be redundant when it
    // agrees and wrong when it doesn't. Reported case: removing `steam` was
    // refused because a multilib i686 helper package visible to rpm's
    // overlay-only view looked unsatisfied, even though the real dependency
    // graph (including base) was fine. Same reasoning
    // `OverlayPaths::needs_nodeps` applies to install.
    if nodeps || paths.needs_nodeps() {
        cmd.arg("--nodeps");
    }
    println!("Running transaction");
    for n in &qualified_names {
        cmd.arg(n);
    }

    let steps: Vec<(String, u64)> = to_remove
        .iter()
        .zip(&qualified_names)
        .map(|(p, n)| (n.clone(), p.install_size))
        .collect();

    // Has to be collected from the still-installed packages' file lists
    // *before* `rpm -evh` erases them below, because `rpm -q --dump` has
    // nothing to query once a package is gone. See the doc comment on
    // `relocate_opt_installs` for why `/opt/<name>` may be a symlink into
    // `/usr/lib/opt/<name>` in the first place.
    let split_live = matches!(paths.mode, OverlayMode::Split { .. }) && paths.installroot.is_none();
    let opt_tops = if split_live {
        opt_top_level_names(paths, &qualified_names)
    } else {
        Default::default()
    };

    run_rpm_transaction(cmd, &steps, "Removing", &[])?;

    if split_live {
        cleanup_modprobe_configs(paths, &to_remove);
        cleanup_opt_relocations(&opt_tops);
    }

    println!("Complete!");

    let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let entries: Vec<(String, Reason)> = to_remove
        .iter()
        .filter(|p| seen_names.insert(p.nevra.name.as_str()))
        .map(|p| (p.nevra.name.clone(), Reason::User))
        .collect();
    if let Err(e) = history::record(paths, history::Action::Remove, &entries) {
        tracing::warn!(error = %e, "failed to record transaction history");
    }
    Ok(())
}
