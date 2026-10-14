mod offline;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::ToSocketAddrs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use vez_core::{Dependency, EvrCompare, Package};
use vez_overlay::{OverlayContext, OverlayMode, OverlayPaths};
use vez_repo::RepoConfig;
use vez_transaction::history::{self, Reason};

// vez: Svara's overlay-aware package manager. It reads plain yum/dnf repo
// metadata and resolves and applies transactions itself.
/// Default repo directory, the same as dnf's built-in default.
const DEFAULT_REPO_DIR: &str = "/etc/yum.repos.d";
/// Default cache directory.
const DEFAULT_CACHE_DIR: &str = "/var/cache/vez";

#[derive(Parser)]
#[command(name = "vez", version)]
struct Cli {
    /// Path to vez's main config file (dnf.conf-compatible `[main]` section).
    #[arg(long, default_value = vez_repo::main_config::DEFAULT_CONF_PATH, global = true)]
    config: PathBuf,

    /// Directory of dnf/yum-style `.repo` files.
    #[arg(long, default_value = DEFAULT_REPO_DIR, global = true)]
    repo_dir: PathBuf,

    /// Where downloaded .rpm files are cached before install.
    #[arg(long, default_value = DEFAULT_CACHE_DIR, global = true)]
    cache_dir: PathBuf,

    /// Assume "yes" to any prompt.
    #[arg(short = 'y', long = "assumeyes", global = true)]
    assume_yes: bool,
    /// Assume "no" to any prompt.
    #[arg(long = "assumeno", global = true)]
    assume_no: bool,
    /// Default answer to confirmation prompts is "yes" (config-only; dnf5 has
    /// no CLI flag for it either).
    #[arg(skip)]
    default_yes: bool,
    /// Suppress non-essential output.
    #[arg(short = 'q', long = "quiet", global = true)]
    quiet: bool,
    /// Exclude a package (by name, globs allowed) from consideration.
    /// Repeatable.
    #[arg(short = 'x', long = "exclude", global = true, value_delimiter = ',')]
    exclude: Vec<String>,
    /// Run entirely from cached repo metadata; error instead of touching the network.
    #[arg(short = 'C', long = "cacheonly", global = true)]
    cacheonly: bool,
    /// Force a repo metadata refresh, ignoring `metadata_expire=`.
    #[arg(long = "refresh", global = true)]
    refresh: bool,
    /// Restrict operations to these repo ids (globs allowed, repeatable).
    #[arg(
        long = "repo",
        visible_alias = "repoid",
        global = true,
        value_delimiter = ','
    )]
    repo: Vec<String>,
    /// Enable a repo (by id, globs allowed) for this run only, even if it's
    /// disabled. Repeatable.
    #[arg(
        long = "enablerepo",
        visible_alias = "enable-repo",
        global = true,
        value_delimiter = ','
    )]
    enablerepo: Vec<String>,
    /// Disable a repo (by id, globs allowed) for this run only, even if it's
    /// enabled. Repeatable.
    #[arg(
        long = "disablerepo",
        visible_alias = "disable-repo",
        global = true,
        value_delimiter = ','
    )]
    disablerepo: Vec<String>,
    /// Skip GPG signature verification entirely for this run.
    #[arg(long = "no-gpgchecks", visible_alias = "nogpgcheck", global = true)]
    no_gpgchecks: bool,
    /// dnf-style `KEY=VALUE` config override, repeatable. vez only acts on
    /// `tsflags=noscripts` (skip rpm scriptlets); other keys are accepted and
    /// ignored.
    #[arg(long = "setopt", global = true)]
    setopt: Vec<String>,
    /// Allow removing conflicting or obsoleted packages to complete a
    /// transaction instead of refusing. Same as dnf's `--allowerasing`.
    #[arg(long = "allowerasing", global = true)]
    allowerasing: bool,
    /// The newest available version has to resolve cleanly, with no quiet
    /// fallback to an older one. dnf's `--best`.
    #[arg(long = "best", global = true)]
    best: bool,
    /// Drop package names that don't match anything in the enabled repos
    /// instead of failing the whole transaction. dnf's `--skip-unavailable`.
    /// Only affects `install`.
    #[arg(long = "skip-unavailable", global = true)]
    skip_unavailable: bool,
    /// Add a temporary repo from a `name,baseurl` pair, for this run only.
    /// dnf's `--repofrompath`. Repeatable.
    #[arg(long = "repofrompath", global = true)]
    repofrompath: Vec<String>,
    /// Don't remove dependency-only packages that are no longer needed after
    /// this `remove`. dnf's `--no-autoremove`.
    #[arg(long = "no-autoremove", visible_alias = "noautoremove", global = true)]
    no_autoremove: bool,
    /// Operate on an alternate root instead of the real `/`, like dnf/rpm's
    /// `--installroot`. Used to pre-bake an overlay for image builds and for
    /// isolated testing.
    #[arg(long = "installroot", global = true)]
    installroot: Option<PathBuf>,
    /// Don't pull in weak dependencies (`Recommends`) for this run. Shorthand
    /// for dnf's `--setopt install_weak_deps=false`.
    #[arg(long = "no-recommends", global = true)]
    no_recommends: bool,
    /// If the full requested `install` set can't be resolved together, drop
    /// the names responsible and continue with the rest. dnf's
    /// `--skip-broken`.
    #[arg(long = "skip-broken", global = true)]
    skip_broken: bool,
    /// Install every architecture build of a matched package side by side
    /// instead of just one. dnf's `multilib_policy=all`.
    #[arg(long = "multilib-all", global = true)]
    multilib_all: bool,
    /// Resolve and download for a different architecture than the host's.
    /// dnf5's `--forcearch`. Useful when pre-baking an overlay/installroot
    /// for a foreign arch.
    #[arg(long = "forcearch", global = true)]
    forcearch: Option<String>,
    /// Restrict candidate resolution to packages from a specific repo id
    /// (globs allowed, repeatable). dnf5's `--from-repo`. Unlike `--repo`,
    /// every enabled repo's metadata is still loaded for dependency checks.
    #[arg(long = "from-repo", global = true, value_delimiter = ',')]
    from_repo: Vec<String>,
    /// Restrict candidate resolution to packages whose `Vendor:` tag matches.
    /// dnf5's `--from-vendor`, repeatable.
    #[arg(long = "from-vendor", global = true, value_delimiter = ',')]
    from_vendor: Vec<String>,
    /// Resolve and download the transaction but don't apply it. dnf5's
    /// `--downloadonly`. Applies to `install`/`upgrade`/`downgrade`/
    /// `reinstall`/`distro-sync`/`autoremove`/`swap`.
    #[arg(long = "downloadonly", global = true)]
    downloadonly: bool,
    /// With `--downloadonly`, where to write the downloaded `.rpm`s. Defaults
    /// to `--cache-dir`.
    #[arg(long = "destdir", global = true)]
    destdir: Option<PathBuf>,
    /// Allow resolving to an older version than the installed one. dnf5's
    /// `--allow-downgrade`. This is already the default; the flag exists to
    /// match dnf5 and to be explicit. See `--no-allow-downgrade`.
    #[arg(
        long = "allow-downgrade",
        global = true,
        conflicts_with = "no_allow_downgrade"
    )]
    allow_downgrade: bool,
    /// Forbid the resolver from downgrading anything to satisfy this request.
    /// dnf5's `--no-allow-downgrade`.
    #[arg(long = "no-allow-downgrade", global = true)]
    no_allow_downgrade: bool,

    /// Not a real flag; filled in from `vez.conf` after parsing.
    #[arg(skip)]
    main_conf: vez_repo::main_config::MainConfig,

    #[command(subcommand)]
    command: Command,
}

use vez_core::glob_match;

/// Expands any `@group-id` or `@^environment-id` entry in `names` (dnf's
/// comps install syntax, e.g. `@fonts @hardware-support
/// @^workstation-product-environment`) into its member package names, leaving
/// plain package names alone. `@id` pulls in a group's mandatory + default
/// packagereqs (dnf's default `group install` set; see
/// [`vez_repo::comps::parse_comps_xml`]). `@^id` pulls in every `<grouplist>`
/// group of an environment (`<optionlist>` excluded), expanded the same way.
/// Matches by `id` first, then by the human-readable `name`
/// case-insensitively (dnf accepts either on the command line). Errors if a
/// `@`/`@^` name matches no group or environment in any enabled repo's comps
/// data.
fn expand_groups(
    names: &[String],
    groups: &[vez_repo::Group],
    environments: &[vez_repo::Environment],
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let add_group = |group: &vez_repo::Group,
                     out: &mut Vec<String>,
                     seen: &mut std::collections::HashSet<String>| {
        println!("Adding packages from group '{}':", group.name);
        for pkg in &group.packages {
            if seen.insert(pkg.clone()) {
                println!("  {pkg}");
                out.push(pkg.clone());
            }
        }
    };
    for name in names {
        if let Some(id) = name.strip_prefix("@^") {
            let env = environments.iter().find(|e| e.id == id).or_else(|| {
                environments
                    .iter()
                    .find(|e| e.name.eq_ignore_ascii_case(id))
            });
            let env = env.with_context(|| {
                format!("environment '{id}' not found (no comps data for it in any enabled repo)")
            })?;
            println!("Adding groups from environment '{}':", env.name);
            for group_id in &env.group_ids {
                let group = groups.iter().find(|g| &g.id == group_id);
                let Some(group) = group else {
                    eprintln!("warning: environment '{}' references group '{group_id}', which has no comps data in any enabled repo", env.name);
                    continue;
                };
                add_group(group, &mut out, &mut seen);
            }
        } else if let Some(id) = name.strip_prefix('@') {
            let group = groups
                .iter()
                .find(|g| g.id == id)
                .or_else(|| groups.iter().find(|g| g.name.eq_ignore_ascii_case(id)));
            let group = group.with_context(|| {
                format!("group '{id}' not found (no comps data for it in any enabled repo)")
            })?;
            add_group(group, &mut out, &mut seen);
        } else if seen.insert(name.clone()) {
            out.push(name.clone());
        }
    }
    Ok(out)
}

/// True if `--setopt tsflags=noscripts` (or `...,noscripts,...` in a
/// comma-separated tsflags value) was passed. That's the only `--setopt` key
/// vez acts on.
fn setopt_noscripts(cli: &Cli) -> bool {
    cli.setopt.iter().any(|kv| match kv.split_once('=') {
        Some((k, v)) if k.trim() == "tsflags" => v.split(',').any(|f| f.trim() == "noscripts"),
        _ => false,
    })
}

/// Merges `vez.conf`'s `[main]` section into `cli` wherever the matching flag
/// wasn't given a non-default value on the command line. Command-line flags
/// always win, like dnf (`cmdline > config file > built-in default`).
/// `repo_dir`/`cache_dir` use "still equal to the hardcoded default" to mean
/// "not passed explicitly", since clap doesn't say which. A user who passes
/// the exact default path explicitly looks the same as one who didn't pass
/// it, which is harmless because both mean the same value.
fn apply_main_config(cli: &mut Cli, conf: &vez_repo::main_config::MainConfig) {
    if cli.repo_dir == PathBuf::from(DEFAULT_REPO_DIR) {
        if let Some(dir) = &conf.reposdir {
            cli.repo_dir = dir.clone();
        }
    }
    if cli.cache_dir == PathBuf::from(DEFAULT_CACHE_DIR) {
        if let Some(dir) = &conf.cachedir {
            cli.cache_dir = dir.clone();
        }
    }
    cli.assume_yes = cli.assume_yes || conf.assumeyes;
    cli.no_gpgchecks = cli.no_gpgchecks || !conf.gpgcheck;
    cli.assume_no = cli.assume_no || conf.assumeno;
    cli.default_yes = conf.defaultyes;
    // `disable_excludes=main` (or `*`) turns `exclude=`/`--exclude` filtering
    // off entirely: dnf's escape hatch for a system-wide exclude that gets in
    // the way of one particular install.
    let excludes_disabled = conf
        .disable_excludes
        .iter()
        .any(|s| s == "main" || s == "*");
    if !excludes_disabled {
        for pat in &conf.exclude {
            if !cli.exclude.iter().any(|e| e == pat) {
                cli.exclude.push(pat.clone());
            }
        }
    }
}

/// Backs `ip_resolve=ipv4`/`ipv6` (dnf5's `CURLOPT_IPRESOLVE`). It resolves
/// with the same async system resolver reqwest would use, then drops
/// whichever address family wasn't asked for. `reqwest::ClientBuilder` has
/// `local_address()` (binds the *outgoing* socket, doesn't restrict which
/// family gets dialed) and `dns_resolver()` (replaces the whole resolver).
/// Only the second can restrict the family, so this plugs in there.
struct FamilyFilterResolver {
    want_v4: bool,
    want_v6: bool,
}

impl reqwest::dns::Resolve for FamilyFilterResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let want_v4 = self.want_v4;
        let want_v6 = self.want_v6;
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|a| (want_v4 && a.is_ipv4()) || (want_v6 && a.is_ipv6()))
                .collect();
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Builds the shared `reqwest::Client` every subcommand uses to talk to repos
/// and mirrors. `timeout=` from `vez.conf` (dnf's default is 30s, matching
/// [`vez_repo::main_config::MainConfig::default`]) is *not* applied as
/// reqwest's whole-request `.timeout()`, on purpose. That timeout covers
/// everything from connect to the end of the body, so a package that takes
/// longer than `timeout` seconds to download (a large RPM from a slower
/// mirror) would be killed mid-transfer and, with no resume support, restarted
/// from byte 0 every time. That's backwards: big packages should be more
/// robust, not less. dnf's `timeout=` is a *stall* timeout (abort if no data
/// arrives for that long), not a cap on total transfer time, so only
/// `.connect_timeout()` is set here and the stall check is applied per chunk
/// in [`vez_repo::get_bytes_with_retry`]. The retry *count* (`retries=`) is set
/// separately through the process-wide [`vez_repo::set_max_attempts`] call in
/// `main`, and [`vez_repo::get_with_retry`] reads it from there, not from this
/// client.
fn build_client(cli: &Cli) -> Result<reqwest::Client> {
    let user_agent = cli
        .main_conf
        .user_agent
        .clone()
        .unwrap_or_else(|| concat!("vez/", env!("CARGO_PKG_VERSION")).to_string());
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .connect_timeout(std::time::Duration::from_secs(cli.main_conf.timeout))
        // `sslverify=0` is dnf's escape hatch for a repo behind a broken or
        // self-signed cert chain. Never the default; only an explicit opt-out
        // through vez.conf/--setopt.
        .danger_accept_invalid_certs(!cli.main_conf.sslverify);
    builder = match cli.main_conf.ip_resolve.as_str() {
        "ipv4" => builder.dns_resolver(std::sync::Arc::new(FamilyFilterResolver {
            want_v4: true,
            want_v6: false,
        })),
        "ipv6" => builder.dns_resolver(std::sync::Arc::new(FamilyFilterResolver {
            want_v4: false,
            want_v6: true,
        })),
        _ => builder,
    };
    if let Some(proxy_url) = &cli.main_conf.proxy {
        let mut proxy = reqwest::Proxy::all(proxy_url)
            .with_context(|| format!("invalid proxy= URL '{proxy_url}'"))?;
        if let Some(user) = &cli.main_conf.proxy_username {
            proxy = proxy.basic_auth(user, cli.main_conf.proxy_password.as_deref().unwrap_or(""));
        }
        builder = builder.proxy(proxy);
    }
    // `username=`/`password=`: global default repo basic auth, sent as a
    // default `Authorization` header on every request this client makes.
    // reqwest's `ClientBuilder` has no per-client `basic_auth()` (it's only
    // on `RequestBuilder`), so the header is built by hand.
    if let Some(user) = &cli.main_conf.username {
        use base64::Engine;
        let creds = format!(
            "{}:{}",
            user,
            cli.main_conf.password.as_deref().unwrap_or("")
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(mut value) = reqwest::header::HeaderValue::from_str(&format!("Basic {encoded}")) {
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
            builder = builder.default_headers(headers);
        }
    }
    builder.build().context("building HTTP client")
}

/// Runs `apply` (an `apply_install_ex` call) against `downloaded`. If it
/// fails because a package's cached copy failed signature verification,
/// downloads again and retries once before giving up.
///
/// The failed transaction already deleted the bad file it rejected, so
/// calling `download_all_ex` again for the same `to_install` set only fetches
/// what was just deleted (`dest_of(pkg).exists()` skips everything that's
/// still good). That turns "abort the transaction and make the user notice
/// and rerun the command" into one automatic recovery from a corrupted or
/// stale mirror copy, the same kind of transient failure `get_with_retry`/
/// `download_to_file_with_retry` already retry for connection errors.
async fn apply_install_with_signature_retry(
    client: &reqwest::Client,
    mut downloaded: Vec<vez_transaction::DownloadedPackage>,
    to_install: &[Package],
    cache_dir: &Path,
    max_parallel: u32,
    repo_configs: &[RepoConfig],
    fallback_candidates: &[Package],
    apply: impl Fn(&[vez_transaction::DownloadedPackage]) -> Result<()>,
) -> Result<Vec<vez_transaction::DownloadedPackage>> {
    match apply(&downloaded) {
        Ok(()) => Ok(downloaded),
        Err(e) if format!("{e:#}").contains("signature verification failed") => {
            eprintln!("warning: {e:#}");
            eprintln!("Re-downloading the affected package(s) and retrying once...");
            downloaded = vez_transaction::download_all_ex(
                client,
                to_install,
                cache_dir,
                max_parallel,
                true,
                repo_configs,
                fallback_candidates,
            )
            .await
            .context("downloading packages")?;
            apply(&downloaded).context("applying rpm transaction")?;
            Ok(downloaded)
        }
        Err(e) => Err(e).context("applying rpm transaction"),
    }
}

/// Applies `vez.conf`'s `metadata_expire=` (if set) to any repo that didn't
/// set its own, the same fallback dnf uses. A repo counts as "didn't set it"
/// while it's still equal to [`vez_repo::DEFAULT_METADATA_EXPIRE`], so a repo
/// that explicitly sets exactly the default looks the same as one that didn't
/// set it. Harmless, since both want the same value.
fn apply_metadata_expire_default(
    configs: &mut [RepoConfig],
    conf: &vez_repo::main_config::MainConfig,
) {
    let Some(default) = conf.metadata_expire else {
        return;
    };
    for cfg in configs {
        if cfg.metadata_expire == vez_repo::DEFAULT_METADATA_EXPIRE {
            cfg.metadata_expire = default;
        }
    }
}

/// Lowers this process to Nice=19 / IOSchedulingClass=best-effort(2) /
/// IOSchedulingPriority=7, close to what vez-makecache.service asks systemd
/// for (the unit itself uses the idle CPU and IO classes). Used before a
/// forced metadata refresh, a bulk background download and parse that
/// shouldn't compete with the caller's foreground work. Best-effort: any
/// failure (e.g. no permission to lower niceness further, a sandboxed
/// environment) is ignored, since this is a courtesy and not needed for
/// correctness.
fn lower_priority_for_background_fetch() {
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
        // ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(class, data)),
        // where IOPRIO_PRIO_VALUE packs (class << 13) | data. Class 2 is
        // IOPRIO_CLASS_BE (best-effort); priority 7 is its lowest level.
        const IOPRIO_WHO_PROCESS: libc::c_int = 1;
        const IOPRIO_CLASS_BE: libc::c_int = 2;
        const IOPRIO_PRIO_BE_LOWEST: libc::c_int = 7;
        let ioprio = (IOPRIO_CLASS_BE << 13) | IOPRIO_PRIO_BE_LOWEST;
        libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0, ioprio);
    }
}

/// Best-effort equivalent of dnf5's `protect_running_kernel` (see
/// `GoalPrivate::limit_installonly_packages`/`PackageSack::get_running_kernel_id`
/// in dnf5's source). The booted kernel build must never be pruned by
/// `installonly_limit=` or removed outright, because either leaves the running
/// system broken or unbootable until a reboot lands on a different kernel.
/// dnf5 finds it by asking the rpmdb which package owns
/// `/boot/vmlinuz-<uname -r>` (falling back to `/lib/modules/<uname -r>`). vez
/// has no cheap file-ownership query across Split mode's base+overlay the way
/// dnf5 has with its single rpmdb, so this relies on something Fedora's kernel
/// packaging already guarantees: the running kernel's `version-release` is
/// exactly `uname -r` without the trailing `.<arch>` (e.g. `uname -r` of
/// `6.19.14-300.fc44.x86_64` on x86_64 <-> kernel package EVR
/// `6.19.14-300.fc44`). A plain string match against every installed package's
/// EVR finds it without touching the filesystem.
fn running_kernel_evr(host_arch: &str) -> Option<String> {
    let out = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let release = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Some(
        release
            .strip_suffix(&format!(".{host_arch}"))
            .map(str::to_string)
            .unwrap_or(release),
    )
}

/// Combines `vez.conf`'s `protected_packages=` with the names vez always
/// protects (just `vez` itself for now), for passing to
/// [`vez_transaction::apply_remove`].
fn protected_packages(cli: &Cli) -> Vec<String> {
    let mut protected = cli.main_conf.protected_packages.clone();
    for p in vez_repo::main_config::ALWAYS_PROTECTED {
        protected.push(p.to_string());
    }
    protected
}

/// Builds the [`vez_resolver::ResolveOptions`] every resolve call site
/// shares, from `vez.conf` plus this run's `--no-recommends` override.
fn resolve_options(cli: &Cli, paths: &OverlayPaths) -> vez_resolver::ResolveOptions {
    vez_resolver::ResolveOptions {
        install_weak_deps: cli.main_conf.install_weak_deps && !cli.no_recommends,
        installonly_pkgs: cli.main_conf.installonlypkgs.clone(),
        allow_erasing: cli.allowerasing,
        force_names: std::collections::HashSet::new(),
        protected_names: protected_packages(cli),
        locked_names: vez_transaction::versionlock::list(paths).unwrap_or_default(),
        skip_broken: cli.main_conf.skip_broken || cli.skip_broken,
        multilib_all: cli.main_conf.multilib_policy == "all" || cli.multilib_all,
        best: cli.main_conf.best || cli.best,
        obsoletes: cli.main_conf.obsoletes,
        allow_downgrade: !cli.no_allow_downgrade,
    }
}

/// `--from-repo`/`--from-vendor`: narrows the *candidate* pool (not the set
/// of loaded repos; see `effective_repo_configs` for that) to matching
/// packages right before it goes to the resolver. Packages that don't match
/// are moved into `removed` instead of being dropped. Does nothing when
/// neither flag is given.
fn apply_from_filters(cli: &Cli, candidates: &mut Vec<Package>, removed: &mut Vec<Package>) {
    if cli.from_repo.is_empty() && cli.from_vendor.is_empty() {
        return;
    }
    retain_into(candidates, removed, |pkg| {
        (cli.from_repo.is_empty()
            || cli
                .from_repo
                .iter()
                .any(|pat| glob_match(pat, &pkg.repo_id)))
            && (cli.from_vendor.is_empty()
                || cli
                    .from_vendor
                    .iter()
                    .any(|pat| glob_match(pat, &pkg.vendor)))
    });
}

/// `Vec::retain`, except rejected elements are moved into `removed` instead
/// of being dropped. That's how candidates the resolver mustn't see still
/// reach the download-fallback pool without cloning the whole candidate list.
fn retain_into(
    items: &mut Vec<Package>,
    removed: &mut Vec<Package>,
    mut keep: impl FnMut(&Package) -> bool,
) {
    let (kept, rejected): (Vec<Package>, Vec<Package>) =
        std::mem::take(items).into_iter().partition(|p| keep(p));
    *items = kept;
    removed.extend(rejected);
}

/// The download-fallback pool for `to_install` (see `load_candidates`): only
/// the candidates that share a (name, arch) with something being installed,
/// which is all the fallback ever looks at. Callers can then drop the full
/// `candidates`/`fallback_extra` pools before the download and rpm phase.
fn download_alternatives(
    to_install: &[Package],
    candidates: &[Package],
    fallback_extra: &[Package],
) -> Vec<Package> {
    vez_transaction::restrict_alt_candidates(to_install, candidates.iter().chain(fallback_extra))
}

/// Frees the big metadata pools once resolution is done and returns the
/// memory to the OS before the (possibly long) download + rpm transaction.
/// Otherwise gigabytes of repo metadata we're done with stay resident through
/// every scriptlet, dracut, and akmods run.
fn release_pools<T>(pools: T) {
    drop(pools);
    vez_transaction::release_freed_memory();
}

/// `--downloadonly`: resolve normally, but fetch `to_install` into
/// `--destdir` (or `--cache-dir`) instead of running the rpm transaction.
/// Shared by every install-like command. dnf5's `--downloadonly` doesn't
/// import repo gpg keys either (nothing gets installed), so this skips
/// `import_repo_keys` too.
async fn download_only(
    cli: &Cli,
    client: &reqwest::Client,
    to_install: &[Package],
    repo_configs: &[RepoConfig],
    fallback_candidates: &[Package],
) -> Result<()> {
    let per_repo = cli.destdir.is_none();
    let dest = cli.destdir.as_deref().unwrap_or(&cli.cache_dir);
    let downloaded = vez_transaction::download_all_ex_with_metadata_root(
        client,
        to_install,
        dest,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        per_repo,
        repo_configs,
        fallback_candidates,
    )
    .await
    .context("downloading packages")?;
    for d in &downloaded {
        println!("{}", d.rpm_path.display());
    }
    Ok(())
}

/// Applies `--repo`/`--enablerepo`/`--disablerepo` on top of each repo's own
/// `enabled=` setting, with dnf5's precedence: `--repo` (if given) is an
/// allow-list that overrides everything, then `--disablerepo` beats
/// `--enablerepo`, which beats the file's own `enabled=`.
fn effective_repo_configs(cli: &Cli, all: Vec<RepoConfig>) -> Vec<RepoConfig> {
    all.into_iter()
        .filter(|cfg| {
            if !cli.repo.is_empty() {
                return cli.repo.iter().any(|pat| glob_match(pat, &cfg.id));
            }
            let mut enabled = cfg.enabled;
            if cli.enablerepo.iter().any(|pat| glob_match(pat, &cfg.id)) {
                enabled = true;
            }
            if cli.disablerepo.iter().any(|pat| glob_match(pat, &cfg.id)) {
                enabled = false;
            }
            enabled
        })
        .collect()
}

#[derive(Subcommand)]
enum Command {
    /// Easter egg.
    #[command(hide = true)]
    Vez,
    /// Resolve and install one or more packages.
    #[command(visible_aliases = ["in", "pour"])]
    Install {
        packages: Vec<String>,
        /// Resolve and validate only; don't download or write anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove one or more packages.
    #[command(visible_aliases = ["rm", "erase"])]
    Remove {
        packages: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Upgrade one or more installed packages to the newest available
    /// version. Only works on the overlay: a base-image package named
    /// explicitly is reported instead of being layered into the overlay,
    /// since the base image is read-only. The one exception is `vez` itself,
    /// which is updated in place by layering a copy into the overlay — the
    /// base image's copy stays underneath as the recovery. `--minimal`
    /// (dnf5's `upgrade-minimal`) isn't implemented; a plain upgrade always
    /// picks the newest candidate.
    #[command(visible_aliases = ["up", "update"])]
    Upgrade {
        packages: Vec<String>,
        #[arg(long)]
        dry_run: bool,
        /// Only upgrade to a candidate covered by this exact advisory id
        /// (e.g. `FEDORA-2024-abc123`). Repeatable.
        #[arg(long = "advisory")]
        advisory: Vec<String>,
        /// Only upgrade to candidates covered by a security advisory.
        #[arg(long)]
        security: bool,
        /// Only upgrade to candidates covered by a bugfix advisory.
        #[arg(long)]
        bugfix: bool,
        /// Only upgrade to candidates covered by an enhancement advisory.
        #[arg(long)]
        enhancement: bool,
        /// Only upgrade to candidates covered by an advisory at/above this
        /// severity (`critical`/`important`/`moderate`/`low`).
        #[arg(long = "advisory-severity")]
        advisory_severity: Option<String>,
    },
    /// Mode-aware system upgrade: dnf5's `system-upgrade` on a plain host,
    /// Svara's image-update flow on an overlay system.
    ///
    /// On a plain host, running it with no subcommand is an error. Do a major
    /// version bump (e.g. Fedora 44 -> 45) with `download --releasever=X` to
    /// resolve and download the new release's packages, `reboot` to stage it
    /// and reboot into applying it, `clean` to discard a staged transaction,
    /// and `log`/`status` to look at past and current runs.
    ///
    /// On a Svara overlay system, running it with no subcommand does a
    /// normal overlay package upgrade (same as `vez upgrade`), then checks
    /// for and stages a new base image. A new release comes as a new image
    /// there, so the `download`/`reboot`/`execute`/`clean`/`log`/`status`
    /// subcommands only work on a plain host.
    SystemUpgrade {
        #[command(subcommand)]
        action: Option<SystemUpgradeAction>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Reinstall one or more installed packages at their exact current
    /// version, e.g. to repair a corrupted or modified install.
    #[command(visible_alias = "rei")]
    Reinstall {
        packages: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Downgrade one or more installed packages to the newest available
    /// version older than what's installed.
    #[command(visible_alias = "dg")]
    Downgrade {
        packages: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Make installed packages match the best available repo version exactly,
    /// upgrading or downgrading as needed (`upgrade` only ever moves
    /// forward). With no names given, every package installed in the overlay
    /// is synced.
    #[command(visible_aliases = ["dsync", "distrosync"])]
    DistroSync {
        packages: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Removes overlay packages that were pulled in only as a dependency
    /// and are no longer required by anything still installed. Packages
    /// installed explicitly (or `vez mark install`ed) are never touched.
    Autoremove {
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove `remove_spec` and install `install_spec` as two back-to-back
    /// transactions, which approximates dnf's single-transaction swap.
    Swap {
        remove_spec: String,
        install_spec: String,
    },
    /// Change a package's recorded install reason, controlling whether
    /// `autoremove` may remove it later.
    Mark {
        #[command(subcommand)]
        action: MarkAction,
    },
    /// Checks the installed package set for problems: unmet dependencies,
    /// conflicts between installed packages, obsoleted packages, and
    /// duplicate name.arch installs. With no flags every check runs; pass
    /// some of them to run only those.
    ///
    /// By default it checks base+overlay combined, like dnf5's merged rpmdb
    /// view. In Split mode, `--base` limits it to the base image's rpmdb and
    /// `--overlay` to vez's overlay rpmdb, so a resolver problem can be
    /// pinned to one side instead of only showing up as a base+overlay
    /// cross-conflict. Handy for finding which side introduced an issue.
    /// Neither has any effect in Standalone mode (there's no base/overlay
    /// split).
    Check {
        /// Report unmet `Requires` and installed-vs-installed `Conflicts`.
        #[arg(long)]
        dependencies: bool,
        /// Report multiple installed versions of the same name.arch (other
        /// than packages like the kernel that are expected to coexist).
        #[arg(long)]
        duplicates: bool,
        /// Report installed packages obsoleted by another installed package.
        #[arg(long)]
        obsoleted: bool,
        /// In Split mode, check only the base image's rpmdb. Conflicts
        /// with `--overlay`.
        #[arg(long, conflicts_with = "overlay")]
        base: bool,
        /// In Split mode, check only vez's overlay rpmdb. Conflicts with
        /// `--base`.
        #[arg(long, conflicts_with = "base")]
        overlay: bool,
    },
    /// List installed packages, optionally filtered by a name substring.
    /// Lists overlay installs by default; `--base` lists the base image's
    /// package set instead.
    #[command(visible_alias = "ls")]
    List {
        filter: Option<String>,
        /// List base-image packages instead of overlay-installed ones.
        /// Also scopes `--extras`/`--obsoletes`/`--upgrades` to the base
        /// set; has no effect on `--available` or `--autoremove`.
        #[arg(long)]
        base: bool,
        /// List repo candidates that aren't installed. dnf's `list
        /// --available`.
        #[arg(long)]
        available: bool,
        /// List installed packages that no enabled repo provides. dnf's `list
        /// --extras` (locally built or sideloaded, or from a removed repo).
        #[arg(long)]
        extras: bool,
        /// List installed packages obsoleted by an available repo candidate.
        /// dnf's `list --obsoletes`.
        #[arg(long)]
        obsoletes: bool,
        /// List installed packages with a newer version available. dnf's
        /// `list --upgrades`.
        #[arg(long)]
        upgrades: bool,
        /// List the packages `vez autoremove` would remove, without removing
        /// anything. dnf's `list --autoremove`. Always limited to the
        /// overlay; `--base` has no effect.
        #[arg(long)]
        autoremove: bool,
        /// With `--available`, list every build (EVR) a repo offers instead
        /// of just the newest. dnf's `list --showduplicates`.
        #[arg(long)]
        showduplicates: bool,
    },
    /// Search enabled repos' package name and summary for a substring.
    #[command(visible_alias = "se")]
    Search {
        query: String,
        /// Show which repo each result came from.
        #[arg(long)]
        showrepo: bool,
    },
    /// Shows what's installed or available that provides a capability (a
    /// name, a versioned dep, or a file path). Like dnf's `provides`.
    #[command(visible_alias = "whatprovides")]
    Provides { capability: String },
    /// Lists installed packages that have a newer version available, without
    /// downloading or installing anything. Uses the same candidate selection
    /// as `upgrade` and prints it instead of applying it. This includes `vez`
    /// itself, which `upgrade` updates in place.
    #[command(visible_alias = "check-update")]
    CheckUpgrade {
        packages: Vec<String>,
        /// Emit `{"updates": [...]}` instead of plain text, for callers
        /// that parse the result (e.g. Svara's own update checker in `svara`).
        #[arg(long)]
        json: bool,
    },
    /// Queries repo package metadata. A subset of dnf's `repoquery`: there's
    /// no `--list` (file listing), but name/glob matching, `--installed`/
    /// `--available`, `--whatprovides`, `--whatrequires`, `--requires`, and
    /// `--provides` all work.
    #[command(visible_alias = "rq")]
    Repoquery {
        pattern: Option<String>,
        /// Only installed packages (base + overlay); no repo query at all.
        #[arg(long)]
        installed: bool,
        /// Only available (repo) packages. This is the default when neither
        /// this nor `--installed` is given.
        #[arg(long)]
        available: bool,
        /// List packages (installed by default, or repo candidates with
        /// `--available`) that provide this capability.
        #[arg(long)]
        whatprovides: Option<String>,
        /// List packages that `Requires` this capability.
        #[arg(long)]
        whatrequires: Option<String>,
        /// List packages that `Conflicts` with this capability.
        #[arg(long)]
        whatconflicts: Option<String>,
        /// List packages that `Obsoletes` this capability.
        #[arg(long)]
        whatobsoletes: Option<String>,
        /// List packages that `Recommends` this capability (weak dep).
        #[arg(long)]
        whatrecommends: Option<String>,
        /// List packages that `Enhances` this capability (weak dep).
        #[arg(long)]
        whatenhances: Option<String>,
        /// List packages that `Suggests` this capability (weak dep).
        #[arg(long)]
        whatsuggests: Option<String>,
        /// List packages that `Supplements` this capability (weak dep).
        #[arg(long)]
        whatsupplements: Option<String>,
        /// With `--whatrequires`, follow the reverse-dependency closure
        /// transitively (packages requiring a match's own provides, and so
        /// on) instead of stopping at direct requirers.
        #[arg(long)]
        recursive: bool,
        /// Only match packages of this architecture (glob-capable).
        #[arg(long)]
        arch: Option<String>,
        /// Only show packages that have more than one build available
        /// (same name+arch, different EVR) among the matched pool.
        #[arg(long)]
        duplicates: bool,
        /// Print full detailed info (same shape as `vez info`) for each
        /// match instead of its NEVRA.
        #[arg(short, long)]
        info: bool,
        /// dnf-style custom output format, e.g. `%{name}-%{evr}.%{arch}`.
        /// Recognized tags: name, epoch, version, release, evr, arch,
        /// nevra, summary, repoid, size, installsize, location.
        #[arg(long, visible_alias = "qf")]
        queryformat: Option<String>,
        /// Print each matched package's `Requires` instead of its NEVRA.
        #[arg(long)]
        requires: bool,
        /// Print each matched package's `Provides` instead of its NEVRA.
        #[arg(long)]
        provides: bool,
        /// Print each matched package's `Conflicts` instead of its NEVRA.
        #[arg(long)]
        conflicts: bool,
        /// Print each matched package's `Obsoletes` instead of its NEVRA.
        #[arg(long)]
        obsoletes: bool,
        /// Print each matched package's `Recommends` instead of its NEVRA.
        #[arg(long)]
        recommends: bool,
        /// Print each matched package's `Enhances` instead of its NEVRA.
        #[arg(long)]
        enhances: bool,
        /// Print each matched package's `Suggests` instead of its NEVRA.
        #[arg(long)]
        suggests: bool,
        /// Print each matched package's `Supplements` instead of its NEVRA.
        #[arg(long)]
        supplements: bool,
        /// Only match source packages (arch `src`). dnf5's `--srpm`.
        #[arg(long, alias = "source")]
        srpm: bool,
        /// Print each match's repo `location` (download path) instead of
        /// its NEVRA.
        #[arg(long)]
        location: bool,
        /// Print `name-version-release` instead of the full NEVRA.
        #[arg(long)]
        nvr: bool,
        /// Print `epoch:name-version-release.arch`.
        #[arg(long)]
        envra: bool,
        /// Installed packages that no configured repo has (matched by name).
        /// dnf's `--extras`. Always queries the installed set, whatever
        /// `--installed`/`--available` say.
        #[arg(long)]
        extras: bool,
        /// Installed packages with a newer version available in a configured
        /// repo. dnf's `--upgrades`. Always queries the installed set,
        /// whatever `--installed`/`--available` say.
        #[arg(long)]
        upgrades: bool,
        /// Prints the `--queryformat` tags vez recognizes, then exits.
        #[arg(long)]
        querytags: bool,
    },
    /// Shows detailed info (NEVRA, repo, summary) for a package name.
    #[command(visible_aliases = ["if", "more"])]
    Info { package: String },
    /// Lists overlay packages that nothing else installed depends on. dnf's
    /// "leaf" concept, roughly "what was installed on purpose and nothing
    /// else needs".
    Leaves,
    /// Show whether a package is installed, and if so from the base image
    /// or the overlay.
    Origin { package: String },
    /// Print the overlay paths vez is using.
    Paths,
    /// Show what the declared package set would change, without changing it.
    ///
    /// Reads /etc/svara/packages.toml and reports three things: what it would install, what it
    /// already has, and which vez-installed packages the set does not mention. The last is
    /// reported and NEVER acted on — see `vez_overlay::declarative`.
    Diff,
    /// Make this machine match the declared package set.
    ///
    /// Additive and idempotent: installs what is declared and missing, changes nothing else,
    /// and therefore does nothing at all when run twice. It never removes anything.
    Apply {
        /// Print the plan and stop, exactly as `vez diff` does.
        #[arg(long)]
        dry_run: bool,
    },
    /// Report or bring up the persistent overlay on /usr.
    ///
    /// The overlay is what makes an installed package survive a reboot: its upper directory
    /// lives under /var, and the mount is rebuilt from there at every boot. `mount` is what
    /// vez-overlay.service runs, and is idempotent so running it by hand is safe.
    ///
    /// Deliberately NOT `bootc usr-overlay`: that mounts a tmpfs overlay and loses
    /// everything at reboot, which is the failure this command exists to avoid.
    Overlay {
        #[command(subcommand)]
        action: OverlayAction,
    },
    /// Unconditionally refresh cached repo metadata for every enabled repo.
    #[command(visible_alias = "mc", alias = "makecache")]
    MakeCache,
    /// Enable or disable a Copr repo.
    Copr {
        #[command(subcommand)]
        action: CoprAction,
    },
    /// Clears cached data under `--cache-dir`.
    Clean {
        #[arg(value_enum, default_value = "all")]
        what: CleanWhat,
    },
    /// Resolves and downloads packages (and their dependencies) without
    /// installing them.
    Download {
        packages: Vec<String>,
        /// Where to write downloaded `.rpm`s. Defaults to `--cache-dir`.
        #[arg(long)]
        destdir: Option<PathBuf>,
        /// Download the `.src.rpm` instead of the binary package. dnf5's
        /// `--srpm` (`--source` is accepted as dnf4's alias for the same
        /// flag). Needs a source repo enabled (e.g. Fedora's `*-source`
        /// repos).
        #[arg(long, alias = "source")]
        srpm: bool,
        /// Load repo metadata against a different `$releasever` than the
        /// running system's. dnf's `download --releasever=X`.
        #[arg(long)]
        releasever: Option<String>,
    },
    /// Installs `<name>-debuginfo` for one or more already-named packages.
    /// Needs the debuginfo packages to be present in a configured repo
    /// (e.g. Fedora's `*-debuginfo` repos).
    DebuginfoInstall {
        packages: Vec<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Prints the RPM changelog for one or more installed packages.
    Changelog { packages: Vec<String> },
    /// Scans running processes for ones using a shared library or binary that
    /// has since been deleted or replaced on disk (e.g. after an update). A
    /// partial equivalent of dnf's `needs-restarting`: it reports affected
    /// PIDs, not systemd units.
    NeedsRestarting,
    /// Lists or shows details for configured repos.
    Repo {
        #[command(subcommand)]
        action: RepoAction,
    },
    /// Views recorded install/remove transactions. Bare `vez history` (no
    /// subcommand) matches `dnf history`/`dnf5 history`: it defaults to
    /// `list`.
    History {
        #[command(subcommand)]
        action: Option<HistoryAction>,
    },
    /// Excludes packages from `upgrade`/`distro-sync` candidate selection.
    Versionlock {
        #[command(subcommand)]
        action: VersionlockAction,
    },
    /// Minimal `.repo` file editing: enable/disable existing repos, or add
    /// a new one from a bare `baseurl=`.
    ConfigManager {
        /// Repo id(s) to enable. Repeatable.
        #[arg(long = "set-enabled")]
        set_enabled: Vec<String>,
        /// Repo id(s) to disable. Repeatable.
        #[arg(long = "set-disabled")]
        set_disabled: Vec<String>,
        /// `id=baseurl` pairs to write as a new `<id>.repo` file. Repeatable.
        /// Only a plain baseurl works (not a `.repo` file URL).
        #[arg(long = "add-repo")]
        add_repo: Vec<String>,
        /// dnf5-style `config-manager addrepo` subcommand (as opposed to the
        /// dnf4-style `--add-repo`/`--set-enabled` flags above).
        #[command(subcommand)]
        action: Option<ConfigManagerAction>,
    },
    /// Alias for `repo info` (dnf5 top-level compat command).
    Repoinfo { id: String },
    /// Alias for `repo list` (dnf5 top-level compat command).
    Repolist {
        #[arg(long)]
        all: bool,
    },
    /// Comps group management: `@id` install syntax, `group list/info/
    /// install/remove`. `install`/`remove` act on a group's mandatory and
    /// default members, same as dnf's default group transaction.
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Comps environment management: `@^id` install syntax, `environment
    /// list/info/install/remove`. `install`/`remove` act on every group in
    /// the environment, same as dnf's default environment transaction.
    Environment {
        #[command(subcommand)]
        action: EnvironmentAction,
    },
    /// Module streams (modularity): list, info, enable, disable, reset,
    /// install, and remove.
    Module {
        #[command(subcommand)]
        action: ModuleAction,
    },
    /// Security/bugfix/enhancement advisories (updateinfo). Not every repo
    /// (especially third-party ones) publishes this data.
    #[command(visible_alias = "updateinfo")]
    Advisory {
        #[command(subcommand)]
        action: AdvisoryAction,
    },
    /// Offline (reboot-time) transactions. Not implemented yet.
    Offline,
    /// Alias for `offline upgrade`. Not implemented yet; see `offline`.
    #[command(name = "offline-upgrade")]
    OfflineUpgrade,
    /// Alias for `offline distro-sync`. Not implemented yet; see `offline`.
    #[command(name = "offline-distrosync")]
    OfflineDistrosync,
    /// Mirrors a repo's packages to local disk. Respects the global
    /// `--repo`/`--repoid` filter for which repo(s) to sync.
    Reposync {
        /// Where to write downloaded `.rpm`s. Defaults to `--cache-dir`.
        #[arg(long = "download-path", short = 'p')]
        download_path: Option<PathBuf>,
        /// Only download the newest version of each package (dnf's default
        /// downloads every version).
        #[arg(long = "newest-only")]
        newest_only: bool,
        /// Write files flat into the download path instead of nesting them
        /// under a per-repo-id subdirectory.
        #[arg(long = "norepopath")]
        norepopath: bool,
    },
    /// Prunes old package versions from a local directory of `.rpm` files,
    /// grouped by name+arch.
    Repomanage {
        /// Directory to scan for `.rpm` files (recursively).
        path: PathBuf,
        /// Print the newest version(s) per package instead of the old ones.
        #[arg(long)]
        new: bool,
        /// How many of the newest versions per package count as "new" (kept)
        /// instead of "old" (prunable). dnf-utils' `repomanage --keep`.
        #[arg(long, default_value_t = 1)]
        keep: u32,
    },
    /// Reports packages whose dependencies nothing in the enabled repos can
    /// satisfy. It checks the whole repo and doesn't simulate an install.
    Repoclosure {
        /// Restrict which packages get checked (glob-capable, repeatable).
        /// Empty means check everything.
        #[arg(long)]
        pkg: Vec<String>,
    },
    /// Installs build dependencies from a `.spec` or `.src.rpm` file.
    #[command(name = "builddep", visible_alias = "build-dep")]
    BuildDep {
        /// Path to the `.spec` or `.src.rpm` file.
        spec: PathBuf,
        /// rpm macro definition `NAME VALUE`, repeatable. dnf's `builddep
        /// --define`.
        #[arg(long = "define")]
        define: Vec<String>,
        /// Resolve and validate only; don't download or write anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Re-apply everything installed on top of the image.
    ///
    /// This is what makes an extra package survive a **base image update**. A reboot does not
    /// need it — the overlay upperdir is on disk under /var, so the layer is still there — but
    /// `bootc upgrade` replaces /usr with a new deployment while the upperdir still holds files
    /// extracted over the old one. Overlayfs merges them, so an installed package silently
    /// shadows the new base wherever their file sets overlap. This re-applies the recorded set
    /// so the layer matches the deployment it is now layered on.
    Replay {
        /// Do nothing unless a replay is actually needed.
        ///
        /// A replay is needed when the deployment generation has moved since the layer was last
        /// applied — an upgrade or a rollback. This is the form `vez-replay.service` runs at
        /// boot, so a machine that has not updated does no work.
        #[arg(long)]
        check: bool,
        /// Re-apply even when the deployment has not moved.
        #[arg(long)]
        force: bool,
        /// Resolve and report only; don't download or write anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Runs an arbitrary transaction spec file. Not implemented yet.
    Do,
    /// dnf-automatic equivalent: a non-interactive upgrade for a periodic
    /// timer or cron job, driven by `automatic.conf`. Resolves an upgrade,
    /// optionally downloads it, and optionally applies it.
    Automatic {
        /// Apply `random_sleep=`'s random delay before doing anything. dnf5's
        /// `--timer`, to spread load when many machines run on the same
        /// schedule.
        #[arg(long)]
        timer: bool,
        /// Override `download_updates=` on for this run.
        #[arg(long, conflicts_with = "no_downloadupdates")]
        downloadupdates: bool,
        /// Override `download_updates=` off for this run.
        #[arg(long)]
        no_downloadupdates: bool,
        /// Override `apply_updates=` on for this run.
        #[arg(long, conflicts_with_all = ["no_installupdates", "no_downloadupdates"])]
        installupdates: bool,
        /// Override `apply_updates=` off for this run.
        #[arg(long)]
        no_installupdates: bool,
    },
    /// Generates a shell completion script for `vez`.
    Completions { shell: clap_complete::Shell },
}

#[derive(Subcommand)]
enum OverlayAction {
    /// Report whether the persistent overlay is up, and where its upperdir is.
    ///
    /// Read-only and needs no root, so it is the first thing to run on a machine where an
    /// install was refused.
    Status,
    /// Mount the persistent overlay on /usr.
    ///
    /// Idempotent: already-mounted is success. This is what `vez-overlay.service` runs at
    /// boot, and running it by hand achieves the same thing until the next reboot.
    Mount,
}

#[derive(Subcommand)]
enum SystemUpgradeAction {
    /// Resolve a full distro-sync transaction against `--releasever` and
    /// download every package it needs without touching the running system
    /// yet. Only works on a plain (non-overlay) host.
    Download {
        /// The target major release, e.g. `45`.
        #[arg(long)]
        releasever: String,
        /// Upgrade in place instead of distro-sync: never install a package
        /// older than the installed one. dnf5's `--no-downgrade`.
        #[arg(long)]
        no_downgrade: bool,
        packages: Vec<String>,
    },
    /// Stage the downloaded transaction for pre-boot application and
    /// reboot. Only works on a plain (non-overlay) host.
    Reboot {
        /// Power off instead of rebooting once the transaction completes.
        #[arg(long)]
        poweroff: bool,
    },
    /// Internal use only: applies the staged transaction during boot.
    Execute,
    /// Discard a stored offline transaction and any downloaded packages.
    /// Only works on a plain (non-overlay) host.
    Clean,
    /// Show logs from past offline transactions. Only works on a plain
    /// (non-overlay) host.
    Log,
    /// Show the status of the currently stored offline transaction, if
    /// any. Only works on a plain (non-overlay) host.
    Status,
}

#[derive(Subcommand)]
enum GroupAction {
    List {
        /// Only groups that are fully installed (base or overlay). dnf5's
        /// `group list --installed`.
        #[arg(long)]
        installed: bool,
        /// Only groups that aren't fully installed. dnf5's `group list
        /// --available`.
        #[arg(long)]
        available: bool,
    },
    Info {
        id: String,
    },
    Install {
        id: String,
    },
    /// Upgrades every installed member of this group to its newest available
    /// version. dnf5's `group upgrade`.
    Upgrade {
        id: String,
    },
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
enum EnvironmentAction {
    List {
        /// Only environments that are fully installed. dnf5's `environment
        /// list --installed`.
        #[arg(long)]
        installed: bool,
        /// Only environments that aren't fully installed. dnf5's `environment
        /// list --available`.
        #[arg(long)]
        available: bool,
    },
    Info {
        id: String,
    },
    Install {
        id: String,
    },
    /// Upgrades every installed package that belongs to this environment's
    /// groups. dnf5's `environment upgrade`.
    Upgrade {
        id: String,
    },
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
enum ModuleAction {
    List,
    Info {
        name: String,
    },
    Enable {
        name: String,
    },
    Disable {
        name: String,
    },
    Reset {
        name: String,
    },
    /// Enables the module's stream and installs the named profile's packages:
    /// `name`, `name:stream`, or `name:stream/profile`.
    Install {
        name: String,
    },
    /// Removes the packages that belong to the given module's installed
    /// profile(s). It doesn't disable or reset the module stream; use `module
    /// disable`/`module reset` for that.
    Remove {
        name: String,
    },
}

/// Shared filters for every `advisory` subcommand.
#[derive(clap::Args)]
struct AdvisoryFilters {
    /// Which bucket of advisories to consider (default: `--available`).
    #[arg(long)]
    available: bool,
    /// Advisories covering a package already installed at that exact EVR.
    #[arg(long)]
    installed: bool,
    /// Advisories covering an installed package with a newer available EVR.
    #[arg(long)]
    updates: bool,
    /// All three buckets combined.
    #[arg(long)]
    all: bool,
    /// Only this advisory id (repeatable).
    #[arg(long = "advisory")]
    advisory: Vec<String>,
    #[arg(long)]
    bugfix: bool,
    #[arg(long)]
    security: bool,
    #[arg(long)]
    enhancement: bool,
    #[arg(long)]
    newpackage: bool,
    /// Only advisories at/above this severity (`critical`/`important`/
    /// `moderate`/`low`).
    #[arg(long)]
    severity: Option<String>,
    /// Package name-spec(s) (globs allowed) that limit which advisories are
    /// shown. Empty means every advisory in the selected bucket.
    packages: Vec<String>,
}

/// `vez upgrade --advisory=`/`--security`/`--bugfix`/`--enhancement`/
/// `--advisory-severity=`. Same filter shape as [`AdvisoryFilters`], without
/// the bucket and package-name arguments, which `upgrade` doesn't take.
struct AdvisoryUpgradeFilter<'a> {
    ids: &'a [String],
    security: bool,
    bugfix: bool,
    enhancement: bool,
    severity: Option<&'a str>,
}

impl AdvisoryUpgradeFilter<'_> {
    /// No filter: every candidate is eligible, same as `upgrade` without any
    /// of the `--advisory*` flags. Used by internal callers (`group upgrade`,
    /// `environment upgrade`, the Split-mode overlay upgrade inside
    /// `system-upgrade`) that call [`upgrade`] directly instead of through
    /// the CLI's `Command::Upgrade` arm.
    const NONE: AdvisoryUpgradeFilter<'static> = AdvisoryUpgradeFilter {
        ids: &[],
        security: false,
        bugfix: false,
        enhancement: false,
        severity: None,
    };

    fn is_active(&self) -> bool {
        !self.ids.is_empty()
            || self.security
            || self.bugfix
            || self.enhancement
            || self.severity.is_some()
    }

    fn matches(&self, adv: &vez_repo::Advisory) -> bool {
        if !self.ids.is_empty() && !self.ids.contains(&adv.id) {
            return false;
        }
        let want_kind = self.security || self.bugfix || self.enhancement;
        if want_kind {
            let ok = (self.security && adv.kind == vez_repo::updateinfo::AdvisoryKind::Security)
                || (self.bugfix && adv.kind == vez_repo::updateinfo::AdvisoryKind::Bugfix)
                || (self.enhancement
                    && adv.kind == vez_repo::updateinfo::AdvisoryKind::Enhancement);
            if !ok {
                return false;
            }
        }
        if let Some(sev) = self.severity {
            if adv.severity < vez_repo::updateinfo::Severity::parse_cli(sev) {
                return false;
            }
        }
        true
    }
}

#[derive(Subcommand)]
enum AdvisoryAction {
    /// One line per matching advisory: id, type, severity, title.
    List {
        #[command(flatten)]
        filters: AdvisoryFilters,
    },
    /// Full detail (title, severity, issued date, description, covered
    /// packages) per matching advisory.
    Info {
        #[command(flatten)]
        filters: AdvisoryFilters,
    },
    /// Counts of matching advisories, grouped by type.
    Summary {
        #[command(flatten)]
        filters: AdvisoryFilters,
    },
}

#[derive(Subcommand)]
enum ConfigManagerAction {
    /// dnf5-style `config-manager addrepo`: adds a repo either from a remote
    /// or local `.repo` file (kept verbatim, with the ids and options it was
    /// published with) or from an explicit `--id`/baseurl pair.
    Addrepo {
        /// URL (or local path) of an existing `.repo` file to download and
        /// save verbatim. Repeatable.
        #[arg(long = "from-repofile")]
        from_repofile: Vec<String>,
        /// Repo id for a `--set baseurl=...`-style add (only used when
        /// `--from-repofile` isn't given).
        #[arg(long = "id")]
        id: Option<String>,
        /// `key=value` repo options for an add by `--id`. Only `baseurl=` is
        /// supported right now.
        #[arg(long = "set")]
        set: Vec<String>,
    },
}

#[derive(Subcommand)]
enum RepoAction {
    /// Lists configured repos and whether each is enabled.
    List {
        /// Also list disabled repos (dnf's default `repo list` shows
        /// enabled only).
        #[arg(long)]
        all: bool,
    },
    /// Shows one repo's full configuration.
    Info { id: String },
}

#[derive(Subcommand)]
enum HistoryAction {
    /// Lists every recorded transaction, oldest first.
    List,
    /// Shows one transaction's full package list by id.
    Info { id: u64 },
    /// Reverses one transaction: packages it installed are removed,
    /// packages it removed are reinstalled at whatever version is
    /// currently available.
    Undo {
        id: u64,
        #[arg(long)]
        dry_run: bool,
    },
    /// Re-applies transaction `<id>` forward, as if it were run again now.
    Redo {
        id: u64,
        #[arg(long)]
        dry_run: bool,
    },
    /// Undoes every transaction after `<id>`, most recent first, returning
    /// the system to its state right after `<id>` completed.
    Rollback {
        id: u64,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum VersionlockAction {
    Add { package: String },
    Delete { package: String },
    List,
    Clear,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum CleanWhat {
    All,
    Packages,
    Metadata,
}

#[derive(Subcommand)]
enum CoprAction {
    /// Enable `owner/project`, auto-detecting the right chroot from
    /// `/etc/os-release` (`ID_LIKE`/`ID` + `VERSION_ID`) unless one is
    /// given explicitly.
    Enable {
        owner_project: String,
        /// Override the auto-detected chroot, e.g. `fedora-44-x86_64`.
        chroot: Option<String>,
    },
    /// Disable (remove) a previously-enabled Copr project's repo file.
    Disable { owner_project: String },
}

#[derive(Subcommand)]
enum MarkAction {
    /// Marks one or more packages as explicitly (user-)installed, exempting
    /// them from `autoremove`.
    Install { packages: Vec<String> },
    /// Marks one or more packages as dependency-installed, which makes them
    /// `autoremove` candidates once nothing else requires them. For example,
    /// `mark dependency $(rpm -qa --qf '%{NAME} ')` marks every installed
    /// package as a dependency at image build time.
    Dependency { packages: Vec<String> },
}

fn main() -> std::process::ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("Error: failed to start async runtime: {err:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let result = run().await;
        if let Err(err) = result {
            eprintln!("Error: {err:#}");
            eprintln!("If you think this is a bug, please report it: https://github.com/svara-dev/vez/issues");
            return std::process::ExitCode::FAILURE;
        }
        std::process::ExitCode::SUCCESS
    })
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let mut cli = Cli::parse();
    let mut main_conf = vez_repo::main_config::load(&cli.config)
        .with_context(|| format!("loading {}", cli.config.display()))?;
    vez_repo::main_config::apply_setopt(&mut main_conf, &cli.setopt);
    apply_main_config(&mut cli, &main_conf);
    vez_repo::set_max_attempts(main_conf.retries);
    vez_repo::set_stall_timeout(main_conf.timeout);
    vez_repo::set_minrate(main_conf.minrate);
    vez_transaction::history::set_history_record(main_conf.history_record);
    vez_repo::set_fastestmirror(main_conf.fastestmirror);
    vez_repo::set_default_net_options(vez_repo::NetOptions {
        proxy: main_conf.proxy.clone(),
        proxy_userpwd: main_conf
            .proxy_username
            .clone()
            .map(|u| format!("{u}:{}", main_conf.proxy_password.as_deref().unwrap_or(""))),
        username: None,
        password: None,
        sslcacert: None,
        sslclientcert: None,
        sslclientkey: None,
    });
    vez_repo::set_group_package_types(main_conf.group_package_types.clone());
    vez_transaction::set_diskspacecheck(main_conf.diskspacecheck);
    cli.main_conf = main_conf;
    // Auto-detects: a real Svara overlay system gets `Split` mode (vez's own
    // overlay rpmdb, separate from the base image's), and anything else
    // (distrobox/podman, an image-build environment) gets `Standalone`, a
    // single plain rpmdb like dnf uses.
    let mut paths = OverlayPaths::detect()?;
    paths.installroot = cli.installroot.clone();

    // Every command that changes real system state (the overlay rpmdb,
    // /etc/yum.repos.d, vez's state dir under /var/lib/svara/vez) needs root.
    // Fail early with a clear message before resolving or downloading
    // anything, instead of getting partway through a transaction and hitting
    // a permission error from `rpm`/`open()` deep in the pipeline.
    // `--installroot` is exempt: it writes into a disposable tree the caller
    // owns (image-build prebake, test setups), not the real system.
    // `--dry-run` is exempt too, because it only resolves and validates and
    // never touches the rpmdb, repo files, or state dir. Requiring root there
    // would just make "will this even resolve" checks (e.g. checking a
    // package list before a real install) need sudo for no reason.
    if let Some(name) =
        (paths.installroot.is_none() && !is_root() && !command_is_dry_run(&cli.command))
            .then(|| command_needs_root(&cli.command))
            .flatten()
    {
        anyhow::bail!("vez {name} requires root — try: sudo vez {name}");
    }

    match &cli.command {
        Command::Paths => {
            println!("{}", vez_overlay::describe(&paths));
        }
        Command::Diff => {
            let plan = declared_plan(&paths)?;
            print_plan(&plan, false);
        }
        Command::Apply { dry_run } => {
            let plan = declared_plan(&paths)?;
            print_plan(&plan, *dry_run);
            if plan.install.is_empty() {
                return Ok(());
            }
            if *dry_run {
                return Ok(());
            }
            // The plan is already computed, so this is the same list `diff` printed. Passing
            // it through the ordinary install path is what makes `apply` and `diff` agree by
            // construction rather than by two implementations being kept in step.
            install(&cli, &paths, &plan.install, false).await?;
        }
        Command::Overlay { action } => match action {
            OverlayAction::Status => {
                use vez_overlay::mount::MountStatus;
                let status = vez_overlay::mount::status();
                let live = vez_overlay::paths::is_live_medium();
                println!("upperdir: {}", paths.overlay_upper.display());
                println!("workdir:  {}", paths.overlay_work.display());
                match status {
                    MountStatus::Mounted => println!("overlay:  mounted on /usr (writes go to the upperdir above, and survive a reboot)"),
                    MountStatus::NotMounted => println!("overlay:  NOT mounted on /usr"),
                    MountStatus::Unknown => println!("overlay:  unknown (could not read /proc/self/mountinfo)"),
                }
                // WHICH upperdir, not just whether one exists. `bootc usr-overlay` is also an
                // overlay on /usr, so "mounted" alone cannot distinguish a disk-backed upperdir
                // from a tmpfs one — and that difference is an install surviving a reboot versus
                // silently vanishing at it.
                if let Some(actual) = vez_overlay::mount::mounted_upperdir() {
                    println!("mounted upperdir: {actual}");
                    if actual != paths.overlay_upper.display().to_string() {
                        println!("  ^ NOT vez's upperdir — an install would not be restored here at the next boot.");
                    }
                }
                // Say what it means, not just what it is: a bare "NOT mounted" leaves the user
                // to work out whether that is a problem, and on a live medium it is not.
                if live {
                    println!("live:     yes (svara.live=1 on the kernel command line)");
                    println!("\nThis is the live medium, so /usr is RAM-backed and an install would not survive a reboot.");
                    println!("Install Svara to a disk first; vez refuses to install here on purpose.");
                } else if matches!(paths.mode, OverlayMode::Standalone) {
                    println!("\nRunning standalone (no bootc deployment), so there is no overlay to mount and nothing to restore.");
                } else if status != MountStatus::Mounted {
                    println!("\nInstalls are refused until this is mounted. Try: sudo systemctl restart vez-overlay.service");
                }
            }
            OverlayAction::Mount => {
                vez_overlay::mount::mount(&paths.overlay_upper, &paths.overlay_work)?;
                println!("mounted the persistent overlay on /usr");
                println!("upperdir: {}", paths.overlay_upper.display());
                println!("\nThis does NOT survive a reboot by itself; vez-overlay.service does that at boot.");
            }
        },
        Command::Origin { package } => {
            let overlay = OverlayContext::load(&paths).context("loading overlay context")?;
            println!("{package}: {:?}", overlay.origin_of(package));
        }
        Command::Vez => println!("Put the bottle down kid you had enough."),
        Command::Install { packages, dry_run } => install(&cli, &paths, packages, *dry_run).await?,
        Command::Remove { packages, dry_run } => {
            let overlay_for_glob = OverlayContext::load(&paths).context("loading overlay context")?;
            let installed_names: Vec<&str> = overlay_for_glob.base.iter().chain(&overlay_for_glob.overlay).map(|p| p.nevra.name.as_str()).collect();
            let packages = &expand_name_patterns(packages, &installed_names);
            let host_arch = detect_host_arch(&cli);
            if let Some(running) = cli.main_conf.protect_running_kernel.then(|| running_kernel_evr(&host_arch)).flatten() {
                if let Some(blocked) = overlay_for_glob
                    .base
                    .iter()
                    .chain(&overlay_for_glob.overlay)
                    .find(|p| format!("{}-{}", p.nevra.version, p.nevra.release) == running && packages.iter().any(|n| *n == p.nevra.name || *n == format!("{}.{}", p.nevra.name, p.nevra.arch)))
                {
                    anyhow::bail!("'{}' is the currently running kernel and cannot be removed", blocked.nevra);
                }
            }
            // Captured before removal so the removed packages' own
            // Requires/Recommends can still be walked. Feeds the scoped
            // autoremove sweep below.
            let removed: Vec<&Package> = overlay_for_glob
                .base
                .iter()
                .chain(&overlay_for_glob.overlay)
                .filter(|p| packages.iter().any(|n| *n == p.nevra.name || *n == format!("{}.{}", p.nevra.name, p.nevra.arch)))
                .collect();
            let scope = removed_dependency_closure_names(&removed, &overlay_for_glob);
            vez_transaction::apply_remove(&paths, packages, *dry_run, &protected_packages(&cli), cli.assume_yes)?;
            if matches!(paths.mode, OverlayMode::Split { .. }) && !dry_run {
                for name in packages {
                    vez_overlay::packages_list_remove(name)?;
                    if vez_overlay::local_rpm_list_contains(name) {
                        vez_overlay::local_rpm_list_remove(name)?;
                        let cached = Path::new(vez_overlay::paths::LOCAL_RPM_CACHE).join(format!("{name}.rpm"));
                        std::fs::remove_file(cached).ok();
                    }
                }
            }
            // `clean_requirements_on_remove=` (dnf default: true): sweep
            // dependency-only packages that are no longer needed right after
            // a remove, not only when the user runs `autoremove`. Limited to
            // the removed packages' own dependency closure (see
            // `removed_dependency_closure_names`), like dnf5's
            // `SOLVER_CLEANDEPS` in the same solve, so unrelated orphans that
            // were already there aren't swept.
            if cli.main_conf.clean_requirements_on_remove && !cli.no_autoremove && !dry_run {
                autoremove_ex(&cli, &paths, false, Some(&scope))?;
            }
        }
        Command::Upgrade { packages, dry_run, advisory, security, bugfix, enhancement, advisory_severity } => {
            let filter = AdvisoryUpgradeFilter { ids: advisory, security: *security, bugfix: *bugfix, enhancement: *enhancement, severity: advisory_severity.as_deref() };
            upgrade(&cli, &paths, packages, *dry_run, &filter).await?
        }
        Command::SystemUpgrade { action, dry_run } => system_upgrade(&cli, &paths, action.as_ref(), *dry_run).await?,
        Command::Reinstall { packages, dry_run } => {
            // Local .rpm file arguments (e.g. akmods' `dnf reinstall
            // --disablerepo='*' <freshly-built-kmod.rpm>`) skip
            // repo-candidate resolution and the installed-package check
            // below, same as `install`, because they carry their own header.
            // This also covers a package that was never installed before:
            // dnf's `reinstall` of a local file behaves like a plain install.
            let (rpm_files, names) = split_local_rpm_args(packages);
            if !rpm_files.is_empty() {
                install_local_rpm_files(&cli, &paths, &rpm_files, *dry_run, true).await?;
            }
            if !names.is_empty() {
                sync_packages(&cli, &paths, &names, *dry_run, SyncMode::Reinstall).await?;
            }
        }
        Command::Downgrade { packages, dry_run } => sync_packages(&cli, &paths, packages, *dry_run, SyncMode::Downgrade).await?,
        Command::DistroSync { packages, dry_run } => sync_packages(&cli, &paths, packages, *dry_run, SyncMode::DistroSync).await?,
        Command::Autoremove { dry_run } => autoremove(&cli, &paths, *dry_run)?,
        Command::Swap { remove_spec, install_spec } => {
            vez_transaction::apply_remove_ex(&paths, std::slice::from_ref(remove_spec), false, &protected_packages(&cli), true, cli.assume_yes)?;
            install_ex(&cli, &paths, std::slice::from_ref(install_spec), false, true).await?;
        }
        Command::Mark { action } => {
            let overlay_for_glob = OverlayContext::load(&paths).context("loading overlay context")?;
            let installed_names: Vec<&str> = overlay_for_glob.base.iter().chain(&overlay_for_glob.overlay).map(|p| p.nevra.name.as_str()).collect();
            match action {
                MarkAction::Install { packages } => {
                    for package in &expand_name_patterns(packages, &installed_names) {
                        history::set_reason(&paths, package, Reason::User)?;
                        println!("Marked {package} as user-installed.");
                    }
                }
                MarkAction::Dependency { packages } => {
                    for package in &expand_name_patterns(packages, &installed_names) {
                        history::set_reason(&paths, package, Reason::Dependency)?;
                        println!("Marked {package} as dependency-installed.");
                    }
                }
            }
        }
        Command::Check { dependencies, duplicates, obsoleted, base, overlay } => {
            let (dependencies, duplicates, obsoleted) = if !dependencies && !duplicates && !obsoleted { (true, true, true) } else { (*dependencies, *duplicates, *obsoleted) };
            // In Split mode `--base`/`--overlay` split the checked set so a
            // resolver problem can be pinned to one side. Both do nothing in
            // Standalone mode (see the flags' doc comments).
            let scope = if *base {
                CheckScope::Base
            } else if *overlay {
                CheckScope::Overlay
            } else {
                CheckScope::All
            };
            check(&paths, &cli.main_conf.installonlypkgs, dependencies, duplicates, obsoleted, scope)?
        }
        Command::List { filter, base, available, extras, obsoletes, upgrades, autoremove, showduplicates } => {
            let overlay = OverlayContext::load(&paths).context("loading overlay context")?;
            // `--base` picks the read-only base image's packages instead of
            // the overlay's own installs, for every filter below that works
            // on the installed set. `Standalone` mode has no base/overlay
            // split (everything installed is in `overlay.overlay`), so
            // `--base` there lists the same single installed set instead of
            // always coming back empty.
            let installed: &[Package] = match (&overlay.mode, base) {
                (OverlayMode::Split { .. }, true) => &overlay.base,
                (OverlayMode::Split { .. }, false) | (OverlayMode::Standalone, _) => &overlay.overlay,
            };
            let matches_filter = |name: &str| filter.as_deref().is_none_or(|f| name.contains(f));

            if *autoremove {
                // Always limited to the overlay (see the flag's doc comment).
                // `--base` is ignored on purpose here, the same way `vez
                // autoremove` only ever sweeps `overlay.overlay`.
                let protected_names = protected_packages(&cli);
                for pkg in compute_autoremove_candidates(&paths, &overlay, &protected_names, None) {
                    if matches_filter(&pkg.nevra.name) {
                        println!("{}", pkg.nevra);
                    }
                }
            } else if *available || *extras || *obsoletes || *upgrades {
                let (_, candidates, _groups, _environments, ..) = load_candidates(&cli).await?;
                if *available {
                    let installed_nevras: std::collections::HashSet<&vez_core::Nevra> = overlay.base.iter().chain(&overlay.overlay).map(|p| &p.nevra).collect();
                    let mut shown: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
                    let mut sorted: Vec<&Package> = candidates.iter().filter(|c| !installed_nevras.contains(&c.nevra)).collect();
                    sorted.sort_by(|a, b| a.nevra.name.cmp(&b.nevra.name).then_with(|| b.nevra.evr().as_str().compare_evr(a.nevra.evr().as_str())));
                    for pkg in sorted {
                        if !matches_filter(&pkg.nevra.name) {
                            continue;
                        }
                        // Without `--showduplicates`, only the newest build
                        // per name+arch. `sorted` is ordered by name, then
                        // EVR descending, so the first one seen for each
                        // (name, arch) pair is the newest build.
                        if !showduplicates && !shown.insert((pkg.nevra.name.as_str(), pkg.nevra.arch.as_str())) {
                            continue;
                        }
                        println!("{} : {}", pkg.nevra, pkg.repo_id);
                    }
                }
                if *extras {
                    let repo_names: std::collections::HashSet<&str> = candidates.iter().map(|c| c.nevra.name.as_str()).collect();
                    for pkg in installed {
                        if matches_filter(&pkg.nevra.name) && !repo_names.contains(pkg.nevra.name.as_str()) {
                            println!("{}", pkg.nevra);
                        }
                    }
                }
                if *obsoletes {
                    for pkg in installed {
                        if matches_filter(&pkg.nevra.name) && candidates.iter().any(|c| pkg_obsoletes(c, &pkg.nevra.name)) {
                            println!("{}", pkg.nevra);
                        }
                    }
                }
                if *upgrades {
                    for pkg in installed {
                        if !matches_filter(&pkg.nevra.name) {
                            continue;
                        }
                        if let Some(newer) = candidates
                            .iter()
                            .filter(|c| c.nevra.name == pkg.nevra.name && c.nevra.arch == pkg.nevra.arch && c.nevra.evr().as_str().compare_evr(&pkg.nevra.evr()) == std::cmp::Ordering::Greater)
                            .max_by(|a, b| a.nevra.evr().as_str().compare_evr(b.nevra.evr().as_str()))
                        {
                            println!("{} -> {} ({})", pkg.nevra, newer.nevra, newer.repo_id);
                        }
                    }
                }
            } else {
                for pkg in installed {
                    if matches_filter(&pkg.nevra.name) {
                        println!("{}", pkg.nevra);
                    }
                }
            }
        }
        Command::Search { query, showrepo } => {
            let (_, candidates, _groups, _environments, ..) = load_candidates(&cli).await?;
            let query_lower = query.to_lowercase();
            for pkg in &candidates {
                if pkg.nevra.name.to_lowercase().contains(&query_lower) || pkg.summary.to_lowercase().contains(&query_lower) {
                    if *showrepo {
                        println!("{} : {} [{}]", pkg.nevra, pkg.summary, pkg.repo_id);
                    } else {
                        println!("{} : {}", pkg.nevra, pkg.summary);
                    }
                }
            }
        }
        Command::Provides { capability } => provides(&cli, &paths, capability).await?,
        Command::CheckUpgrade { packages, json } => check_upgrade(&cli, &paths, packages, *json).await?,
        Command::Repoquery {
            pattern,
            installed,
            available,
            whatprovides,
            whatrequires,
            whatconflicts,
            whatobsoletes,
            whatrecommends,
            whatenhances,
            whatsuggests,
            whatsupplements,
            recursive,
            arch,
            duplicates,
            info,
            queryformat,
            requires,
            provides,
            conflicts,
            obsoletes,
            recommends,
            enhances,
            suggests,
            supplements,
            srpm,
            location,
            nvr,
            envra,
            extras,
            upgrades,
            querytags,
        } => {
            repoquery(
                &cli,
                &paths,
                RepoqueryArgs {
                    pattern: pattern.as_deref(),
                    installed: *installed,
                    available: *available,
                    whatprovides: whatprovides.as_deref(),
                    whatrequires: whatrequires.as_deref(),
                    whatconflicts: whatconflicts.as_deref(),
                    whatobsoletes: whatobsoletes.as_deref(),
                    whatrecommends: whatrecommends.as_deref(),
                    whatenhances: whatenhances.as_deref(),
                    whatsuggests: whatsuggests.as_deref(),
                    whatsupplements: whatsupplements.as_deref(),
                    recursive: *recursive,
                    arch: arch.as_deref(),
                    duplicates: *duplicates,
                    info: *info,
                    queryformat: queryformat.as_deref(),
                    requires: *requires,
                    provides: *provides,
                    conflicts: *conflicts,
                    obsoletes: *obsoletes,
                    recommends: *recommends,
                    enhances: *enhances,
                    suggests: *suggests,
                    supplements: *supplements,
                    srpm: *srpm,
                    location: *location,
                    nvr: *nvr,
                    envra: *envra,
                    extras: *extras,
                    upgrades: *upgrades,
                    querytags: *querytags,
                },
            )
            .await?
        }
        Command::Info { package } => info(&cli, &paths, package).await?,
        Command::Leaves => leaves(&paths)?,
        Command::MakeCache => make_cache(&cli).await?,
        Command::Copr { action } => match action {
            CoprAction::Enable { owner_project, chroot } => {
                let client = build_client(&cli)?;
                let path = vez_repo::copr::enable(&client, owner_project, chroot.as_deref(), &cli.repo_dir)
                    .await
                    .with_context(|| format!("enabling copr repo '{owner_project}'"))?;
                println!("Enabled {owner_project} -> {}", path.display());
            }
            CoprAction::Disable { owner_project } => {
                vez_repo::copr::disable(owner_project, &cli.repo_dir).with_context(|| format!("disabling copr repo '{owner_project}'"))?;
                println!("Disabled {owner_project}.");
            }
        },
        Command::Clean { what } => clean(&cli, *what)?,
        Command::Download { packages, destdir, srpm, releasever } => download(&cli, &paths, packages, destdir.as_deref(), *srpm, releasever.as_deref()).await?,
        Command::DebuginfoInstall { packages, dry_run } => {
            let debuginfo_names: Vec<String> = packages.iter().map(|p| format!("{p}-debuginfo")).collect();
            install(&cli, &paths, &debuginfo_names, *dry_run).await?
        }
        Command::Changelog { packages } => changelog(&paths, packages)?,
        Command::NeedsRestarting => needs_restarting()?,
        Command::Repo { action } => match action {
            RepoAction::List { all } => repo_list(&cli, *all)?,
            RepoAction::Info { id } => repo_info(&cli, id)?,
        },
        Command::Repoinfo { id } => repo_info(&cli, id)?,
        Command::Repolist { all } => repo_list(&cli, *all)?,
        Command::History { action } => match action.as_ref().unwrap_or(&HistoryAction::List) {
            HistoryAction::List => {
                println!("{:>4}  {:<19}  {:<10}  {:>8}", "ID", "Date and time", "Action(s)", "Altered");
                for entry in history::list(&paths)? {
                    println!(
                        "{:>4}  {:<19}  {:<10}  {:>8}",
                        entry.id,
                        format_unix_time(entry.unix_time),
                        format!("{:?}", entry.action),
                        entry.packages.len()
                    );
                }
            }
            HistoryAction::Info { id } => {
                let entries = history::list(&paths)?;
                let entry = entries.iter().find(|e| e.id == *id).with_context(|| format!("no transaction with id {id}"))?;
                println!("Transaction ID : {}", entry.id);
                println!("Begin time     : {}", format_unix_time(entry.unix_time));
                println!("Action         : {:?}", entry.action);
                println!("Altered        : {} package(s)", entry.packages.len());
                println!();
                println!("{:<10}  {:<45}  {}", "Action", "Package", "Reason");
                for (nevra, reason) in &entry.packages {
                    println!("{:<10}  {:<45}  {:?}", format!("{:?}", entry.action), nevra, reason);
                }
            }
            HistoryAction::Undo { id, dry_run } => {
                let entries = history::list(&paths)?;
                let entry = entries.iter().find(|e| e.id == *id).with_context(|| format!("no transaction with id {id}"))?;
                apply_history_inverse(&cli, &paths, history::inverse_of(entry), *dry_run).await?;
            }
            HistoryAction::Rollback { id, dry_run } => {
                let entries = history::list(&paths)?;
                anyhow::ensure!(entries.iter().any(|e| e.id == *id), "no transaction with id {id}");
                let after: Vec<_> = entries.into_iter().filter(|e| e.id > *id).collect();
                if after.is_empty() {
                    println!("Nothing to roll back — transaction {id} is already the most recent.");
                } else {
                    apply_history_inverse(&cli, &paths, history::composite_inverse(&after), *dry_run).await?;
                }
            }
            HistoryAction::Redo { id, dry_run } => {
                let entries = history::list(&paths)?;
                let entry = entries.iter().find(|e| e.id == *id).with_context(|| format!("no transaction with id {id}"))?;
                let names: Vec<String> = entry.packages.iter().map(|(nevra, _)| {
                    vez_core::Nevra::parse_nevra(nevra).or_else(|| vez_core::Nevra::parse_nvra(nevra)).map(|n| n.name).unwrap_or_else(|| nevra.clone())
                }).collect();
                match entry.action {
                    history::Action::Remove => {
                        vez_transaction::apply_remove_ex(&paths, &names, *dry_run, &protected_packages(&cli), true, cli.assume_yes)?;
                    }
                    history::Action::Install | history::Action::Upgrade | history::Action::Reinstall | history::Action::Downgrade => {
                        install(&cli, &paths, &names, *dry_run).await?;
                    }
                }
            }
        },
        Command::Versionlock { action } => match action {
            VersionlockAction::Add { package } => {
                let overlay = OverlayContext::load(&paths).context("loading overlay context")?;
                vez_transaction::versionlock::add(&paths, &overlay, package)?;
                println!("Locked {package}.");
            }
            VersionlockAction::Delete { package } => {
                vez_transaction::versionlock::delete(&paths, package)?;
                println!("Unlocked {package}.");
            }
            VersionlockAction::List => {
                for lock in vez_transaction::versionlock::list(&paths)? {
                    match (lock.evr, lock.arch) {
                        (Some(evr), Some(arch)) => println!("{} ({evr}.{arch})", lock.name),
                        _ => println!("{}", lock.name),
                    }
                }
            }
            VersionlockAction::Clear => {
                vez_transaction::versionlock::clear(&paths)?;
                println!("Cleared versionlock.");
            }
        },
        Command::ConfigManager { set_enabled, set_disabled, add_repo, action } => {
            for id in set_enabled {
                vez_repo::config_manager::set_enabled(&cli.repo_dir, id, true).with_context(|| format!("enabling '{id}'"))?;
                println!("Enabled {id}.");
            }
            for id in set_disabled {
                vez_repo::config_manager::set_enabled(&cli.repo_dir, id, false).with_context(|| format!("disabling '{id}'"))?;
                println!("Disabled {id}.");
            }
            for spec in add_repo {
                let (id, url) = spec.split_once('=').with_context(|| format!("--add-repo expects 'id=baseurl', got '{spec}'"))?;
                let vars = detect_vars(&cli);
                let path = vez_repo::config_manager::add_repo(&cli.repo_dir, id, url, &vars)?;
                println!("Added {id} -> {}", path.display());
            }
            match action {
                Some(ConfigManagerAction::Addrepo { from_repofile, id, set }) => {
                    for source in from_repofile {
                        let contents = if source.starts_with("http://") || source.starts_with("https://") {
                            let client = build_client(&cli)?;
                            client.get(source).send().await.with_context(|| format!("downloading '{source}'"))?.error_for_status().with_context(|| format!("downloading '{source}'"))?.text().await.with_context(|| format!("reading body of '{source}'"))?
                        } else {
                            std::fs::read_to_string(source).with_context(|| format!("reading '{source}'"))?
                        };
                        let filename = source.rsplit('/').next().filter(|s| !s.is_empty() && s.ends_with(".repo")).unwrap_or("downloaded.repo");
                        std::fs::create_dir_all(&cli.repo_dir).with_context(|| format!("creating {}", cli.repo_dir.display()))?;
                        let path = cli.repo_dir.join(filename);
                        std::fs::write(&path, &contents).with_context(|| format!("writing {}", path.display()))?;
                        println!("Added from {source} -> {}", path.display());
                    }
                    if let Some(id) = id {
                        let baseurl = set
                            .iter()
                            .find_map(|kv| kv.strip_prefix("baseurl="))
                            .with_context(|| "--id requires --set baseurl=<url>")?;
                        let vars = detect_vars(&cli);
                        let path = vez_repo::config_manager::add_repo(&cli.repo_dir, id, baseurl, &vars)?;
                        println!("Added {id} -> {}", path.display());
                    }
                }
                None => {}
            }
        }
        Command::Group { action } => match action {
            GroupAction::List { installed, available } => {
                let (_, _, groups, _environments, ..) = load_candidates(&cli).await?;
                let installed_names: std::collections::HashSet<String> = if *installed || *available {
                    let overlay = OverlayContext::load(&paths).context("loading overlay context")?;
                    overlay.base.iter().chain(&overlay.overlay).map(|p| p.nevra.name.clone()).collect()
                } else {
                    std::collections::HashSet::new()
                };
                let is_group_installed = |g: &vez_repo::Group| !g.packages.is_empty() && g.packages.iter().all(|p| installed_names.contains(p));
                let shown: Vec<&vez_repo::Group> = groups
                    .iter()
                    .filter(|g| if *installed { is_group_installed(g) } else { true })
                    .filter(|g| if *available { !is_group_installed(g) } else { true })
                    .collect();
                if shown.is_empty() {
                    println!("No groups available (no comps data in enabled repos).");
                } else {
                    println!("Available groups:");
                    for g in shown {
                        println!("  {} ({})", g.name, g.id);
                    }
                }
            }
            GroupAction::Info { id } => {
                let (_, _, groups, _environments, ..) = load_candidates(&cli).await?;
                let g = groups.iter().find(|g| g.id == *id).or_else(|| groups.iter().find(|g| g.name.eq_ignore_ascii_case(id))).with_context(|| format!("group '{id}' not found"))?;
                println!("Group   : {}", g.name);
                println!("Group-Id: {}", g.id);
                println!("Packages:");
                for p in &g.packages {
                    println!("  {p}");
                }
            }
            GroupAction::Install { id } => install(&cli, &paths, &[format!("@{id}")], false).await?,
            GroupAction::Upgrade { id } => {
                let (_, _, groups, _environments, ..) = load_candidates(&cli).await?;
                let g = groups.iter().find(|g| g.id == *id).or_else(|| groups.iter().find(|g| g.name.eq_ignore_ascii_case(id))).with_context(|| format!("group '{id}' not found"))?;
                upgrade(&cli, &paths, &g.packages, false, &AdvisoryUpgradeFilter::NONE).await?;
            }
            GroupAction::Remove { id } => {
                let (_, _, groups, _environments, ..) = load_candidates(&cli).await?;
                let g = groups.iter().find(|g| g.id == *id).or_else(|| groups.iter().find(|g| g.name.eq_ignore_ascii_case(id))).with_context(|| format!("group '{id}' not found"))?;
                let overlay_for_scope = OverlayContext::load(&paths).context("loading overlay context")?;
                let removed: Vec<&Package> = overlay_for_scope.base.iter().chain(&overlay_for_scope.overlay).filter(|p| g.packages.iter().any(|n| *n == p.nevra.name)).collect();
                let scope = removed_dependency_closure_names(&removed, &overlay_for_scope);
                vez_transaction::apply_remove(&paths, &g.packages, false, &protected_packages(&cli), cli.assume_yes)?;
                if cli.main_conf.clean_requirements_on_remove && !cli.no_autoremove {
                    autoremove_ex(&cli, &paths, false, Some(&scope))?;
                }
            }
        },
        Command::Environment { action } => match action {
            EnvironmentAction::List { installed, available } => {
                let (_, _, groups, environments, ..) = load_candidates(&cli).await?;
                let installed_names: std::collections::HashSet<String> = if *installed || *available {
                    let overlay = OverlayContext::load(&paths).context("loading overlay context")?;
                    overlay.base.iter().chain(&overlay.overlay).map(|p| p.nevra.name.clone()).collect()
                } else {
                    std::collections::HashSet::new()
                };
                let is_env_installed = |e: &vez_repo::Environment| {
                    !e.group_ids.is_empty()
                        && e.group_ids.iter().all(|gid| {
                            groups.iter().find(|g| &g.id == gid).is_some_and(|g| !g.packages.is_empty() && g.packages.iter().all(|p| installed_names.contains(p)))
                        })
                };
                let shown: Vec<&vez_repo::Environment> = environments
                    .iter()
                    .filter(|e| if *installed { is_env_installed(e) } else { true })
                    .filter(|e| if *available { !is_env_installed(e) } else { true })
                    .collect();
                if shown.is_empty() {
                    println!("No environments available (no comps data in enabled repos).");
                } else {
                    println!("Available environments:");
                    for e in shown {
                        println!("  {} ({})", e.name, e.id);
                    }
                }
            }
            EnvironmentAction::Info { id } => {
                let (_, _, groups, environments, ..) = load_candidates(&cli).await?;
                let e = environments.iter().find(|e| e.id == *id).or_else(|| environments.iter().find(|e| e.name.eq_ignore_ascii_case(id))).with_context(|| format!("environment '{id}' not found"))?;
                println!("Environment   : {}", e.name);
                println!("Environment-Id: {}", e.id);
                println!("Groups:");
                for group_id in &e.group_ids {
                    let name = groups.iter().find(|g| &g.id == group_id).map(|g| g.name.as_str()).unwrap_or(group_id.as_str());
                    println!("  {name} ({group_id})");
                }
            }
            EnvironmentAction::Install { id } => install(&cli, &paths, &[format!("@^{id}")], false).await?,
            EnvironmentAction::Upgrade { id } => {
                let (_, _, groups, environments, ..) = load_candidates(&cli).await?;
                let e = environments.iter().find(|e| e.id == *id).or_else(|| environments.iter().find(|e| e.name.eq_ignore_ascii_case(id))).with_context(|| format!("environment '{id}' not found"))?;
                let mut pkgs = Vec::new();
                let mut seen = std::collections::HashSet::new();
                for group_id in &e.group_ids {
                    let Some(g) = groups.iter().find(|g| &g.id == group_id) else { continue };
                    for p in &g.packages {
                        if seen.insert(p.clone()) {
                            pkgs.push(p.clone());
                        }
                    }
                }
                anyhow::ensure!(!pkgs.is_empty(), "environment '{id}' has no known packages to upgrade (no comps data for its groups)");
                upgrade(&cli, &paths, &pkgs, false, &AdvisoryUpgradeFilter::NONE).await?;
            }
            EnvironmentAction::Remove { id } => {
                let (_, _, groups, environments, ..) = load_candidates(&cli).await?;
                let e = environments.iter().find(|e| e.id == *id).or_else(|| environments.iter().find(|e| e.name.eq_ignore_ascii_case(id))).with_context(|| format!("environment '{id}' not found"))?;
                let mut pkgs = Vec::new();
                let mut seen = std::collections::HashSet::new();
                for group_id in &e.group_ids {
                    let Some(g) = groups.iter().find(|g| &g.id == group_id) else { continue };
                    for p in &g.packages {
                        if seen.insert(p.clone()) {
                            pkgs.push(p.clone());
                        }
                    }
                }
                anyhow::ensure!(!pkgs.is_empty(), "environment '{id}' has no known packages to remove (no comps data for its groups)");
                let overlay_for_scope = OverlayContext::load(&paths).context("loading overlay context")?;
                let removed: Vec<&Package> = overlay_for_scope.base.iter().chain(&overlay_for_scope.overlay).filter(|p| pkgs.iter().any(|n| *n == p.nevra.name)).collect();
                let scope = removed_dependency_closure_names(&removed, &overlay_for_scope);
                vez_transaction::apply_remove(&paths, &pkgs, false, &protected_packages(&cli), cli.assume_yes)?;
                if cli.main_conf.clean_requirements_on_remove && !cli.no_autoremove {
                    autoremove_ex(&cli, &paths, false, Some(&scope))?;
                }
            }
        },
        Command::Module { action } => match action {
            ModuleAction::List => {
                let (_, _, _, _, modules, module_defaults, ..) = load_candidates(&cli).await?;
                anyhow::ensure!(!modules.is_empty(), "no modular content in enabled repos");
                let module_paths = OverlayPaths::detect()?;
                let enabled_streams = vez_transaction::module_state::enabled(&module_paths)?;
                let disabled_modules = vez_transaction::module_state::disabled(&module_paths)?;
                let mut names: Vec<&str> = modules.iter().map(|m| m.name.as_str()).collect();
                names.sort();
                names.dedup();
                println!("{:<20} {:<10} {:<24} Summary", "Name", "Stream", "Profiles");
                for name in names {
                    let mut streams: Vec<&vez_repo::Module> = modules.iter().filter(|m| m.name == name).collect();
                    streams.sort_by(|a, b| a.stream.cmp(&b.stream));
                    for m in streams {
                        let tag = if disabled_modules.contains(&m.name) {
                            " [d]"
                        } else if enabled_streams.get(&m.name).map(String::as_str) == Some(m.stream.as_str()) {
                            " [e]"
                        } else if module_defaults.get(&m.name).map(String::as_str) == Some(m.stream.as_str()) {
                            " [default]"
                        } else {
                            ""
                        };
                        let profiles: Vec<&str> = m.profiles.iter().map(|(n, _)| n.as_str()).collect();
                        println!("{:<20} {:<10} {:<24} {}{}", m.name, m.stream, profiles.join(", "), m.summary, tag);
                    }
                }
            }
            ModuleAction::Info { name } => {
                let (_, _, _, _, modules, module_defaults, ..) = load_candidates(&cli).await?;
                let (mod_name, stream_filter) = name.split_once(':').map(|(n, s)| (n.to_string(), Some(s.to_string()))).unwrap_or_else(|| (name.clone(), None));
                let mut matches: Vec<&vez_repo::Module> = modules.iter().filter(|m| m.name == mod_name && stream_filter.as_deref().is_none_or(|s| s == m.stream)).collect();
                anyhow::ensure!(!matches.is_empty(), "module '{name}' not found");
                matches.sort_by(|a, b| a.stream.cmp(&b.stream));
                for m in matches {
                    let is_default = module_defaults.get(&m.name).map(String::as_str) == Some(m.stream.as_str());
                    println!("Name         : {}", m.name);
                    println!("Stream       : {}{}", m.stream, if is_default { " [d]" } else { "" });
                    println!("Version      : {}", m.version);
                    println!("Context      : {}", m.context);
                    println!("Architecture : {}", m.arch);
                    println!("Profiles     :");
                    for (pname, rpms) in &m.profiles {
                        println!("  {} : {}", pname, rpms.join(", "));
                    }
                    println!("Summary      : {}", m.summary);
                    println!("Description  : {}", m.description);
                    println!("Artifacts    :");
                    for a in &m.artifacts {
                        println!("  {a}");
                    }
                    println!();
                }
            }
            ModuleAction::Enable { name } => {
                let (_, _, _, _, modules, module_defaults, ..) = load_candidates(&cli).await?;
                let (mod_name, stream) = name
                    .split_once(':')
                    .map(|(n, s)| (n.to_string(), s.to_string()))
                    .or_else(|| module_defaults.get(name).map(|s| (name.clone(), s.clone())))
                    .with_context(|| format!("module '{name}' has no default stream; specify one explicitly as 'name:stream'"))?;
                anyhow::ensure!(modules.iter().any(|m| m.name == mod_name && m.stream == stream), "module '{mod_name}:{stream}' not found in any enabled repo");
                vez_transaction::module_state::enable(&OverlayPaths::detect()?, &mod_name, &stream)?;
                println!("Enabled module stream '{mod_name}:{stream}'.");
            }
            ModuleAction::Disable { name } => {
                vez_transaction::module_state::disable(&OverlayPaths::detect()?, name)?;
                println!("Disabled module '{name}' — every stream's packages are now blocked.");
            }
            ModuleAction::Reset { name } => {
                vez_transaction::module_state::reset(&OverlayPaths::detect()?, name)?;
                println!("Reset module '{name}' to its repo-default state.");
            }
            ModuleAction::Install { name } => {
                let (_, _, _, _, modules, module_defaults, ..) = load_candidates(&cli).await?;
                let (rest, profile) = name.split_once('/').map(|(r, p)| (r.to_string(), Some(p.to_string()))).unwrap_or_else(|| (name.clone(), None));
                let (mod_name, stream) = rest
                    .split_once(':')
                    .map(|(n, s)| (n.to_string(), s.to_string()))
                    .or_else(|| module_defaults.get(&rest).map(|s| (rest.clone(), s.clone())))
                    .with_context(|| format!("module '{rest}' has no default stream; specify one explicitly as 'name:stream'"))?;
                let m = modules.iter().find(|m| m.name == mod_name && m.stream == stream).with_context(|| format!("module '{mod_name}:{stream}' not found in any enabled repo"))?;
                let rpms: Vec<String> = match &profile {
                    Some(p) => m.profiles.iter().find(|(n, _)| n == p).map(|(_, rpms)| rpms.clone()).with_context(|| format!("module '{mod_name}:{stream}' has no profile '{p}'"))?,
                    None => m
                        .profiles
                        .iter()
                        .find(|(n, _)| n == "default")
                        .map(|(_, rpms)| rpms.clone())
                        .unwrap_or_else(|| m.profiles.iter().flat_map(|(_, rpms)| rpms.iter().cloned()).collect::<std::collections::HashSet<_>>().into_iter().collect()),
                };
                anyhow::ensure!(!rpms.is_empty(), "module '{mod_name}:{stream}' has no packages to install");
                let module_paths = OverlayPaths::detect()?;
                vez_transaction::module_state::enable(&module_paths, &mod_name, &stream)?;
                println!("Enabled module stream '{mod_name}:{stream}'.");
                install(&cli, &paths, &rpms, false).await?;
            }
            ModuleAction::Remove { name } => {
                let (_, _, _, _, modules, module_defaults, ..) = load_candidates(&cli).await?;
                let (rest, profile) = name.split_once('/').map(|(r, p)| (r.to_string(), Some(p.to_string()))).unwrap_or_else(|| (name.clone(), None));
                let (mod_name, stream) = rest
                    .split_once(':')
                    .map(|(n, s)| (n.to_string(), s.to_string()))
                    .or_else(|| module_defaults.get(&rest).map(|s| (rest.clone(), s.clone())))
                    .with_context(|| format!("module '{rest}' has no default stream; specify one explicitly as 'name:stream'"))?;
                let m = modules.iter().find(|m| m.name == mod_name && m.stream == stream).with_context(|| format!("module '{mod_name}:{stream}' not found in any enabled repo"))?;
                let rpms: Vec<String> = match &profile {
                    Some(p) => m.profiles.iter().find(|(n, _)| n == p).map(|(_, rpms)| rpms.clone()).with_context(|| format!("module '{mod_name}:{stream}' has no profile '{p}'"))?,
                    None => m.profiles.iter().flat_map(|(_, rpms)| rpms.iter().cloned()).collect::<std::collections::HashSet<_>>().into_iter().collect(),
                };
                anyhow::ensure!(!rpms.is_empty(), "module '{mod_name}:{stream}' has no packages to remove");
                let overlay_for_scope = OverlayContext::load(&paths).context("loading overlay context")?;
                let removed: Vec<&Package> = overlay_for_scope.base.iter().chain(&overlay_for_scope.overlay).filter(|p| rpms.iter().any(|n| *n == p.nevra.name)).collect();
                let scope = removed_dependency_closure_names(&removed, &overlay_for_scope);
                vez_transaction::apply_remove(&paths, &rpms, false, &protected_packages(&cli), cli.assume_yes)?;
                if cli.main_conf.clean_requirements_on_remove && !cli.no_autoremove {
                    autoremove_ex(&cli, &paths, false, Some(&scope))?;
                }
            }
        },
        Command::Advisory { action } => advisory(&cli, &paths, action).await?,
        Command::Offline => anyhow::bail!("offline transactions are not yet implemented: vez has no offline-transaction staging or systemd integration"),
        Command::OfflineUpgrade => anyhow::bail!("offline-upgrade is not yet implemented: see 'vez offline'"),
        Command::OfflineDistrosync => anyhow::bail!("offline-distrosync is not yet implemented: see 'vez offline'"),
        Command::Reposync { download_path, newest_only, norepopath } => reposync(&cli, download_path.as_deref(), *newest_only, *norepopath).await?,
        Command::Repomanage { path, new, keep } => repomanage(path, *new, *keep)?,
        Command::Repoclosure { pkg } => repoclosure(&cli, pkg).await?,
        Command::BuildDep { spec, define, dry_run } => builddep(&cli, &paths, spec, define, *dry_run).await?,
        Command::Replay { check, force, dry_run } => replay(&cli, &paths, *check, *force, *dry_run).await?,
        Command::Do => anyhow::bail!("do is not yet implemented"),
        Command::Automatic { timer, downloadupdates, no_downloadupdates, installupdates, no_installupdates } => {
            let overrides = AutomaticOverrides {
                timer: *timer,
                download_updates: if *downloadupdates { Some(true) } else if *no_downloadupdates { Some(false) } else { None },
                apply_updates: if *installupdates { Some(true) } else if *no_installupdates { Some(false) } else { None },
            };
            let mut cli = cli;
            automatic(&mut cli, &paths, overrides).await?
        }
        Command::Completions { shell } => {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(*shell, &mut cmd, name, &mut std::io::stdout());
        }
    }
    Ok(())
}

/// True when running as `uid 0`, the only case where vez's writes to system
/// paths (rpmdb, `/etc/yum.repos.d`, `/var/lib/svara/vez`) succeed.
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Flatpak side of a Split-mode `vez system-upgrade`. Updates `--system`
/// remotes always, and also updates `--user` remotes for the user who ran
/// `vez` (`system-upgrade` needs root, so `vez` runs as uid 0 by this point),
/// but only if that user has `--user` flatpak remotes configured at all. Best
/// effort throughout: no flatpak installed, no invoking user we can figure
/// out, or a `flatpak` failure are reported and skipped instead of failing
/// the whole system-upgrade over an optional component.
fn flatpak_system_upgrade() {
    if std::process::Command::new("flatpak")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }

    println!("Updating system Flatpaks...");
    match std::process::Command::new("flatpak")
        .args(["update", "-y", "--system"])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("warning: `flatpak update --system` exited with status {s}"),
        Err(e) => eprintln!("warning: couldn't run `flatpak update --system`: {e}"),
    }

    // The user who invoked `vez`, if it was run as root via
    // sudo/pkexec/polkit. `--user` flatpak state lives under that user's
    // home, not root's, so it has to be queried and updated as them, not as
    // uid 0.
    let Some(user) = invoking_user() else { return };

    let remotes = std::process::Command::new("runuser")
        .args([
            "-u",
            &user,
            "--",
            "flatpak",
            "remotes",
            "--user",
            "--columns=name",
        ])
        .output();
    let has_user_remotes = match remotes {
        Ok(out) if out.status.success() => !String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        _ => false,
    };
    if !has_user_remotes {
        return;
    }

    println!("Updating {user}'s user Flatpaks...");
    match std::process::Command::new("runuser")
        .args(["-u", &user, "--", "flatpak", "update", "-y", "--user"])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("warning: `flatpak update --user` for {user} exited with status {s}"),
        Err(e) => eprintln!("warning: couldn't run `flatpak update --user` for {user}: {e}"),
    }
}

/// The non-root user who invoked `vez` through `sudo`/`pkexec`/polkit (which
/// `system-upgrade` requires). `SUDO_USER`/`PKEXEC_UID` are what those tools
/// set for this purpose. `None` when vez was started directly as root (a root
/// login shell, a systemd unit), where there's no particular user.
fn invoking_user() -> Option<String> {
    if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() && user != "root" {
            return Some(user);
        }
    }
    if let Ok(uid) = std::env::var("PKEXEC_UID") {
        let out = std::process::Command::new("id")
            .args(["-nu", &uid])
            .output()
            .ok()?;
        if out.status.success() {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !name.is_empty() && name != "root" {
                return Some(name);
            }
        }
    }
    None
}

/// Returns `Some(display name)` for every subcommand that writes real system
/// state (the overlay/base rpmdb through an `rpm` transaction, repo files
/// under `/etc/yum.repos.d`, or vez's state dir under `/var/lib/svara/vez`:
/// history log, versionlock, module state), so `main` can reject it up front
/// instead of failing partway through a transaction with a raw
/// permission-denied error. Read-only/query commands (`list`, `search`,
/// `info`, `repoquery`, `changelog`, `history`, `paths`, ...) return `None`
/// and run unprivileged, as in dnf.
fn command_needs_root(cmd: &Command) -> Option<&'static str> {
    match cmd {
        Command::Install { .. } => Some("install"),
        Command::Remove { .. } => Some("remove"),
        Command::Upgrade { .. } => Some("upgrade"),
        Command::SystemUpgrade { .. } => Some("system-upgrade"),
        Command::Reinstall { .. } => Some("reinstall"),
        Command::Downgrade { .. } => Some("downgrade"),
        Command::DistroSync { .. } => Some("distro-sync"),
        Command::Autoremove { .. } => Some("autoremove"),
        Command::Swap { .. } => Some("swap"),
        Command::Mark { .. } => Some("mark"),
        Command::DebuginfoInstall { .. } => Some("debuginfo-install"),
        Command::Clean { .. } => Some("clean"),
        // `overlay status` is read-only and deliberately absent here: it is the first thing to
        // run when an install was refused, and it must work without root. `diff` is absent for
        // the same reason — planning is the thing you do BEFORE deciding to install.
        Command::Overlay {
            action: OverlayAction::Mount,
        } => Some("overlay mount"),
        Command::Apply { .. } => Some("apply"),
        // `replay` re-installs packages, so it needs root. `--dry-run` is exempted by
        // `command_is_dry_run` below.
        Command::Replay { .. } => Some("replay"),
        Command::Copr {
            action: CoprAction::Enable { .. } | CoprAction::Disable { .. },
        } => Some("copr"),
        Command::Versionlock {
            action:
                VersionlockAction::Add { .. }
                | VersionlockAction::Delete { .. }
                | VersionlockAction::Clear,
        } => Some("versionlock"),
        Command::ConfigManager { .. } => Some("config-manager"),
        Command::Group {
            action:
                GroupAction::Install { .. } | GroupAction::Remove { .. } | GroupAction::Upgrade { .. },
        } => Some("group"),
        Command::Environment {
            action:
                EnvironmentAction::Install { .. }
                | EnvironmentAction::Remove { .. }
                | EnvironmentAction::Upgrade { .. },
        } => Some("environment"),
        Command::Module {
            action:
                ModuleAction::Enable { .. }
                | ModuleAction::Disable { .. }
                | ModuleAction::Reset { .. }
                | ModuleAction::Install { .. }
                | ModuleAction::Remove { .. },
        } => Some("module"),
        Command::History {
            action:
                Some(
                    HistoryAction::Undo { .. }
                    | HistoryAction::Redo { .. }
                    | HistoryAction::Rollback { .. },
                ),
        } => Some("history"),
        _ => None,
    }
}

/// `true` for a root-gated command that was also given `--dry-run`. The root
/// check in `main` exempts these because they don't write anything. Commands
/// without a `dry_run` field (`clean`, `copr`, `versionlock`,
/// `config-manager`, `group`, `environment`, `module`, `swap`, `mark`) always
/// change real state whatever the flags, so they're not listed.
fn command_is_dry_run(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Install { dry_run: true, .. }
            | Command::Apply { dry_run: true }
            | Command::Replay { dry_run: true, .. }
            | Command::Remove { dry_run: true, .. }
            | Command::Upgrade { dry_run: true, .. }
            | Command::SystemUpgrade { dry_run: true, .. }
            | Command::Reinstall { dry_run: true, .. }
            | Command::Downgrade { dry_run: true, .. }
            | Command::DistroSync { dry_run: true, .. }
            | Command::Autoremove { dry_run: true }
            | Command::DebuginfoInstall { dry_run: true, .. }
            | Command::History {
                action: Some(
                    HistoryAction::Undo { dry_run: true, .. }
                        | HistoryAction::Redo { dry_run: true, .. }
                        | HistoryAction::Rollback { dry_run: true, .. }
                )
            }
    )
}

/// Fetches every enabled repo's package list, shared by `install`, `upgrade`,
/// and `search` so they all see the same repo set the same way (deduplicating
/// is up to the caller). `cli.refresh` forces a new download whatever each
/// repo's `metadata_expire=` says. `cli.cacheonly` forbids any network access
/// and errors if nothing is cached. Repo metadata is cached under
/// `<cache_dir>/repos`, separate from `download_all`'s package cache in the
/// same `cache_dir`. `cli.repo`/`--enablerepo`/`--disablerepo` narrow which
/// repos are used at all (see [`effective_repo_configs`]), and `cli.exclude`
/// drops matching package names from the candidate pool so the resolver never
/// sees them (dnf's `-x`/`--exclude`).
async fn load_candidates(
    cli: &Cli,
) -> Result<(
    Vec<RepoConfig>,
    Vec<Package>,
    Vec<vez_repo::Group>,
    Vec<vez_repo::Environment>,
    Vec<vez_repo::Module>,
    std::collections::HashMap<String, String>,
    Vec<Package>,
    Vec<vez_repo::Advisory>,
)> {
    load_candidates_with_vars(cli, detect_vars(cli), cli.refresh).await
}

/// Same as [`load_candidates`], but always refreshes regardless of
/// `cli.refresh`/`metadata_expire=`. For callers like `check-upgrade`, where
/// reporting against stale cached metadata is worse than useless.
async fn load_candidates_force_refresh(
    cli: &Cli,
) -> Result<(
    Vec<RepoConfig>,
    Vec<Package>,
    Vec<vez_repo::Group>,
    Vec<vez_repo::Environment>,
    Vec<vez_repo::Module>,
    std::collections::HashMap<String, String>,
    Vec<Package>,
    Vec<vez_repo::Advisory>,
)> {
    load_candidates_with_vars(cli, detect_vars(cli), true).await
}

/// `RepoVars::detect()` with `--forcearch` applied on top. dnf5's
/// `--forcearch` overrides `$basearch` in repo URLs *and* the `host_arch` of
/// every resolver call, so anything that would call `RepoVars::detect()`
/// directly should come through here.
fn detect_vars(cli: &Cli) -> vez_repo::RepoVars {
    let mut vars = vez_repo::RepoVars::detect_with_varsdir(cli.main_conf.varsdir.as_deref());
    if let Some(arch) = &cli.forcearch {
        vars.basearch = arch.clone();
    }
    vars
}

/// Same as [`detect_vars`], but only the `basearch`, for the many call sites
/// that just need `host_arch` for the resolver and not a full
/// [`RepoVars`](vez_repo::RepoVars).
fn detect_host_arch(cli: &Cli) -> String {
    cli.forcearch
        .clone()
        .unwrap_or_else(|| vez_repo::RepoVars::detect().basearch)
}

/// Every repo this invocation should use: `.repo` files plus
/// `--repofrompath`, with `vez.conf` defaults applied and
/// `--repo`/`--enablerepo`/`--disablerepo` resolved. Errors if nothing is
/// left enabled.
fn enabled_repo_configs(cli: &Cli, vars: &vez_repo::RepoVars) -> Result<Vec<RepoConfig>> {
    let mut all_configs = vez_repo::load_repo_configs(&cli.repo_dir, vars)
        .with_context(|| format!("loading repo configs from {}", cli.repo_dir.display()))?;
    apply_metadata_expire_default(&mut all_configs, &cli.main_conf);
    // `--repofrompath name,url` (dnf): a temporary repo enabled for this run
    // only. It's added to the in-memory config list and not written to
    // `cli.repo_dir`, because (unlike `config-manager addrepo`) it isn't
    // meant to outlive this invocation.
    for spec in &cli.repofrompath {
        let (id, url) = spec
            .split_once(',')
            .with_context(|| format!("--repofrompath '{spec}' must be 'name,url'"))?;
        all_configs.push(RepoConfig {
            id: id.to_string(),
            name: id.to_string(),
            base_url: Some(url.trim_end_matches('/').to_string()),
            mirrorlist: None,
            metalink: None,
            gpgcheck: false,
            gpgkeys: Vec::new(),
            metadata_expire: vez_repo::DEFAULT_METADATA_EXPIRE,
            enabled: true,
            priority: vez_core::default_repo_priority(),
            cost: vez_core::default_repo_cost(),
            exclude: Vec::new(),
            includepkgs: Vec::new(),
            skip_if_unavailable: None,
            proxy: None,
            proxy_username: None,
            proxy_password: None,
            username: None,
            password: None,
            sslcacert: None,
            sslclientcert: None,
            sslclientkey: None,
        });
    }
    let repo_configs = effective_repo_configs(cli, all_configs);
    anyhow::ensure!(
        !repo_configs.is_empty(),
        "no enabled repos found in {}",
        cli.repo_dir.display()
    );

    Ok(repo_configs)
}

/// `vez makecache` (and `vez-makecache.service`): refreshes every enabled
/// repo's on-disk metadata cache and nothing else. Unlike every other command
/// it never builds the candidate pool. (The old version ran the whole
/// `load_candidates` pipeline, with every repo's packages in memory, dedup, a
/// fallback clone, and module filtering, just to print a repo count.) A repo
/// whose `repomd.xml` hasn't changed costs one small request instead of a
/// full download, parse, and cache rewrite.
async fn make_cache(cli: &Cli) -> Result<()> {
    anyhow::ensure!(
        !cli.cacheonly,
        "--cacheonly forbids fetching repo metadata, which is all makecache does"
    );
    // Background bulk fetch, so the same background priority as any
    // `--refresh`.
    lower_priority_for_background_fetch();
    let repo_configs = enabled_repo_configs(cli, &detect_vars(cli))?;
    let repo_cache_root = cli.cache_dir.join("repos");
    let client = build_client(cli)?;
    eprintln!("Updating and loading repositories:");
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REPO_LOADS));
    let mut set = tokio::task::JoinSet::new();
    for (idx, cfg) in repo_configs.iter().cloned().enumerate() {
        let client = client.clone();
        let repo_cache_root = repo_cache_root.clone();
        let permits = permits.clone();
        set.spawn(async move {
            let _permit = permits
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            let result = vez_repo::refresh_repo(&client, &cfg, &repo_cache_root).await;
            (idx, result)
        });
    }
    let mut results: Vec<Option<Result<bool>>> = (0..repo_configs.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        let (idx, result) = joined.context("repo metadata refresh task panicked")?;
        results[idx] = Some(result);
    }
    for (cfg, result) in repo_configs.iter().zip(results) {
        match result.expect("every repo index is spawned exactly once") {
            Ok(_) => {}
            Err(e)
                if cfg
                    .skip_if_unavailable
                    .unwrap_or(cli.main_conf.skip_if_unavailable) =>
            {
                eprintln!("warning: skipping unavailable repo '{}': {e:#}", cfg.id);
            }
            Err(e) => return Err(e).with_context(|| format!("loading repo '{}'", cfg.id)),
        }
    }
    eprintln!("Repositories loaded.");
    println!("Refreshed metadata for {} repo(s).", repo_configs.len());
    Ok(())
}

/// See `load_candidates_with_vars`'s repo-load fan-out.
const MAX_CONCURRENT_REPO_LOADS: usize = 2;

/// Same as [`load_candidates`], but against an explicitly supplied
/// [`RepoVars`](vez_repo::RepoVars) instead of the host's detected
/// `$releasever`/`$basearch`. `system-upgrade download --releasever=X` uses
/// this to load a *different* major release's repos without touching the
/// running system's own view.
async fn load_candidates_with_vars(
    cli: &Cli,
    vars: vez_repo::RepoVars,
    refresh: bool,
) -> Result<(
    Vec<RepoConfig>,
    Vec<Package>,
    Vec<vez_repo::Group>,
    Vec<vez_repo::Environment>,
    Vec<vez_repo::Module>,
    std::collections::HashMap<String, String>,
    Vec<Package>,
    Vec<vez_repo::Advisory>,
)> {
    // A forced metadata refresh (`vez makecache`, or any command with
    // `--refresh`) is a full repo download that can compete with the user's
    // foreground work for CPU and disk. vez-makecache.service already asks
    // systemd for low priority on that unit (Nice=19 and an idle CPU/IO
    // class). Apply the same Nice=19 plus best-effort IO priority 7 here so
    // an interactive `--refresh` gets similar treatment outside the service.
    if refresh {
        lower_priority_for_background_fetch();
    }
    let repo_configs = enabled_repo_configs(cli, &vars)?;

    let repo_cache_root = cli.cache_dir.join("repos");
    let client = build_client(cli)?;
    let mut candidates = Vec::new();
    let mut groups = Vec::new();
    let mut environments = Vec::new();
    let mut modules = Vec::new();
    let mut module_defaults = std::collections::HashMap::new();
    let mut advisories = Vec::new();
    eprintln!("Updating and loading repositories:");
    // Each repo's metadata load (mirror probe + repomd + primary.xml +
    // comps/modules) is its own series of network round trips, so run them
    // for several repos at once instead of one after another. With a dozen or
    // more enabled repos (common on Svara images), loading them one by one
    // was the biggest wall-clock cost of every install. Results are still
    // applied in the original config order below, so output and error
    // attribution stay deterministic.
    //
    // The number running at once is capped. A repo load that has to fetch
    // holds that repo's parsed package list (hundreds of MB for Fedora /
    // updates-archive) while its other requests are in flight, so without a
    // cap every repo's metadata would be in memory at the same time. The
    // process's lower niceness (lower_priority_for_background_fetch) gives
    // CPU and IO to other work but does nothing to limit RAM. Two at a time
    // keeps most of the network overlap.
    let load_permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REPO_LOADS));
    let mut load_set = tokio::task::JoinSet::new();
    for (idx, cfg) in repo_configs.iter().cloned().enumerate() {
        let client = client.clone();
        let repo_cache_root = repo_cache_root.clone();
        let cacheonly = cli.cacheonly;
        let load_permits = load_permits.clone();
        load_set.spawn(async move {
            let _permit = load_permits
                .acquire_owned()
                .await
                .expect("semaphore never closed");
            let result =
                vez_repo::load_repo_ex(&client, &cfg, &repo_cache_root, refresh, cacheonly).await;
            (idx, cfg, result)
        });
    }
    let mut loaded: Vec<Option<(RepoConfig, Result<vez_repo::Repo>)>> =
        (0..repo_configs.len()).map(|_| None).collect();
    while let Some(joined) = load_set.join_next().await {
        let (idx, cfg, result) = joined.context("repo metadata load task panicked")?;
        loaded[idx] = Some((cfg, result));
    }
    for slot in loaded {
        let (cfg, result) = slot.expect("every repo index is spawned exactly once");
        match result {
            Ok(repo) => {
                candidates.extend(repo.packages);
                groups.extend(repo.groups);
                environments.extend(repo.environments);
                modules.extend(repo.modules);
                module_defaults.extend(repo.module_defaults);
                advisories.extend(repo.advisories);
            }
            // `skip_if_unavailable=` (dnf default: false): an unreachable
            // repo shouldn't abort resolution for every other repo as long as
            // the admin opted into that risk. A repo's own
            // `skip_if_unavailable=` overrides the `[main]` default when set,
            // like dnf's per-section semantics.
            Err(e)
                if cfg
                    .skip_if_unavailable
                    .unwrap_or(cli.main_conf.skip_if_unavailable) =>
            {
                eprintln!("warning: skipping unavailable repo '{}': {e:#}", cfg.id);
            }
            Err(e) => return Err(e).with_context(|| format!("loading repo '{}'", cfg.id)),
        }
    }
    eprintln!("Repositories loaded.");
    // Download-fallback pool. When a package's own repo 404s mid-download,
    // `download_all_ex` retries an *identical* build mirrored under another
    // repo id (or, failing that, another EVR of the same name+arch). That
    // needs every repo's copy, including the exact-NEVRA duplicates and the
    // packages removed from `candidates` below by
    // `--from-repo`/`--from-vendor` and module filtering. The resolver must
    // never see those. So instead of cloning the whole pool up front (a
    // second full copy of every enabled repo's metadata, over a GB with
    // Fedora + updates-archive), everything taken out of `candidates` from
    // here on is *moved* into `fallback_extra`. The full fallback pool is
    // always `candidates` + `fallback_extra` (see `download_alternatives`).
    let mut fallback_extra: Vec<Package> = Vec::new();
    // The same build (identical NEVRA) can be listed by more than one enabled
    // repo (e.g. a package in both `fedora` and `updates`, or two overlapping
    // mirrored repos). As separate `Package` entries each one becomes its own
    // SAT variable, which defeats the resolver's Conflicts and
    // at-most-one-per-version clauses: a clause on one duplicate's variable
    // doesn't stop the solver from satisfying demand through the *other*
    // duplicate's variable. That's how `nodejs22-bin` and `nodejs24-bin`,
    // each with `Conflicts: alternative-for(nodejs-bin)` against the other,
    // both got selected. Collapse to one candidate per NEVRA, keeping the
    // copy that sorts first by repo priority (dnf convention: lower wins), so
    // the repo a package's metadata is attributed to doesn't change.
    {
        let mut best: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, pkg) in candidates.iter().enumerate() {
            let key = pkg.nevra.to_string();
            match best.get(&key) {
                Some(&j)
                    if (candidates[j].repo_priority, candidates[j].repo_cost)
                        <= (pkg.repo_priority, pkg.repo_cost) => {}
                _ => {
                    best.insert(key, i);
                }
            }
        }
        let mut keep: Vec<bool> = vec![false; candidates.len()];
        for &i in best.values() {
            keep[i] = true;
        }
        let mut i = 0;
        retain_into(&mut candidates, &mut fallback_extra, |_| {
            let k = keep[i];
            i += 1;
            k
        });
    }
    if !cli.exclude.is_empty() {
        let keep = |pkg: &Package| {
            !cli.exclude
                .iter()
                .any(|pat| glob_match(pat, &pkg.nevra.name))
        };
        candidates.retain(keep);
        fallback_extra.retain(keep);
    }
    // `includepkgs=` (dnf: when non-empty, only these names can be resolver
    // candidates at all, including as dependency targets, like dnf's
    // repo-level allow-list).
    if !cli.main_conf.includepkgs.is_empty() {
        let keep = |pkg: &Package| {
            cli.main_conf
                .includepkgs
                .iter()
                .any(|pat| glob_match(pat, &pkg.nevra.name))
        };
        candidates.retain(keep);
        fallback_extra.retain(keep);
    }
    // Per-repo `exclude=`/`includepkgs=`. In dnf, a `.repo` section's own
    // exclude/includepkgs only narrows candidates from *that* repo, on top of
    // the global lists above: a package excluded globally stays excluded
    // everywhere, but a per-repo exclude on repo A doesn't touch a build of
    // the same name from repo B.
    let repo_exclude: std::collections::HashMap<&str, &[String]> = repo_configs
        .iter()
        .filter(|c| !c.exclude.is_empty())
        .map(|c| (c.id.as_str(), c.exclude.as_slice()))
        .collect();
    let repo_include: std::collections::HashMap<&str, &[String]> = repo_configs
        .iter()
        .filter(|c| !c.includepkgs.is_empty())
        .map(|c| (c.id.as_str(), c.includepkgs.as_slice()))
        .collect();
    if !repo_exclude.is_empty() {
        let keep = |pkg: &Package| {
            !repo_exclude
                .get(pkg.repo_id.as_str())
                .is_some_and(|pats| pats.iter().any(|pat| glob_match(pat, &pkg.nevra.name)))
        };
        candidates.retain(keep);
        fallback_extra.retain(keep);
    }
    if !repo_include.is_empty() {
        let keep = |pkg: &Package| {
            repo_include
                .get(pkg.repo_id.as_str())
                .is_none_or(|pats| pats.iter().any(|pat| glob_match(pat, &pkg.nevra.name)))
        };
        candidates.retain(keep);
        fallback_extra.retain(keep);
    }
    // `--from-repo`/`--from-vendor` narrow candidates the same way as the
    // `--exclude`/`includepkgs` filters above. The fallback pool keeps every
    // repo's copy on purpose (the download fallback needs to see a mirrored
    // build even if the resolver wasn't allowed to pick it), so the filtered
    // packages are moved into `fallback_extra` instead of being dropped.
    apply_from_filters(cli, &mut candidates, &mut fallback_extra);

    // Module filtering. A package that belongs to a module:stream build (its
    // NEVRA is in a module's `artifacts`) is only a real candidate if that
    // module's *active* stream (an explicit `module enable`, otherwise the
    // repo's `modulemd-defaults`) is the one the build belongs to. dnf hides
    // every inactive stream's RPMs from plain `install`/`list`/resolution the
    // same way. A `module disable` blocks every stream. Non-modular packages
    // (nearly every package in any repo) aren't affected.
    if !modules.is_empty() {
        let module_paths =
            vez_overlay::OverlayPaths::detect().unwrap_or_else(|_| vez_overlay::OverlayPaths {
                mode: vez_overlay::OverlayMode::Standalone,
                overlay_upper: std::path::PathBuf::new(),
                overlay_work: std::path::PathBuf::new(),
                state_dir: std::path::PathBuf::from("/var/lib/vez"),
                installroot: None,
            });
        let enabled_streams =
            vez_transaction::module_state::enabled(&module_paths).unwrap_or_default();
        let disabled_modules =
            vez_transaction::module_state::disabled(&module_paths).unwrap_or_default();

        let mut artifact_module: std::collections::HashMap<
            (String, String, String),
            (String, String),
        > = std::collections::HashMap::new();
        for m in &modules {
            for a in &m.artifacts {
                if let Some(n) = vez_core::Nevra::parse_nevra(a) {
                    let evr = n.evr();
                    artifact_module
                        .insert((n.name, evr, n.arch), (m.name.clone(), m.stream.clone()));
                }
            }
        }

        retain_into(&mut candidates, &mut fallback_extra, |pkg| {
            let Some((mod_name, mod_stream)) = artifact_module.get(&(
                pkg.nevra.name.clone(),
                pkg.nevra.evr(),
                pkg.nevra.arch.clone(),
            )) else {
                return true;
            };
            if disabled_modules.contains(mod_name) {
                return false;
            }
            let active_stream = enabled_streams
                .get(mod_name)
                .or_else(|| module_defaults.get(mod_name));
            active_stream.is_some_and(|s| s == mod_stream)
        });
    }

    Ok((
        repo_configs,
        candidates,
        groups,
        environments,
        modules,
        module_defaults,
        fallback_extra,
        advisories,
    ))
}

/// dnf-style glob support for package-name arguments (`vez remove
/// 'firefox*'`, `vez upgrade 'kernel*'`); otherwise every command below only
/// matches exact literal names. Expansion happens once, up front, against
/// `pool` (the list of names that exist right now for that command: installed
/// packages for
/// remove/upgrade/reinstall/downgrade/distro-sync/check-upgrade/mark,
/// available repo candidates for install), so every exact-match code path
/// downstream (error messages included) keeps working unchanged on the
/// expanded literal names.
///
/// A pattern without a glob metacharacter passes through unchanged, even if
/// it matches nothing in `pool`, which keeps the "package 'x' is not
/// installed" / "nothing provides 'x'" errors for plain typos. A pattern that
/// *is* a glob is expanded against `pool` (deduplicated, in first-match
/// order). If it matches nothing, it's dropped with a warning instead of
/// becoming a nonsense literal name.
fn expand_name_patterns(patterns: &[String], pool: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pat in patterns {
        if !vez_core::is_glob_pattern(pat) {
            out.push(pat.clone());
            continue;
        }
        let mut matched = false;
        for &name in pool {
            if vez_core::glob_match(pat, name) && !out.iter().any(|n| n == name) {
                out.push(name.to_string());
                matched = true;
            }
        }
        if !matched {
            println!("No match for pattern: {pat}");
        }
    }
    out
}

/// Prints a note for any name in `names` that's a base-image package with no
/// overlay copy. Every mutating command leaves those out of its overlay-only
/// candidate pool, so without this the user would see "nothing to do" with no
/// explanation of why an installed package was skipped.
fn warn_base_only_names(names: &[String], overlay: &OverlayContext, verb: &str) {
    for name in names {
        // The self-upgradable names are the deliberate exception to this rule
        // (see `SELF_UPGRADABLE_NAMES`): they *are* layered into the overlay,
        // so warning that vez "will not layer a copy" would be false.
        if vez_repo::main_config::SELF_UPGRADABLE_NAMES.contains(&name.as_str()) {
            continue;
        }
        let in_overlay = overlay.overlay.iter().any(|p| &p.nevra.name == name);
        let in_base = overlay.base.iter().any(|p| &p.nevra.name == name);
        if in_base && !in_overlay {
            println!("'{name}' is provided by the base image; vez will not layer a copy into the overlay to {verb} it — skipping.");
        }
    }
}

/// The newest candidate for a self-upgradable base package (see
/// `SELF_UPGRADABLE_NAMES`), if it is strictly newer than the best copy
/// installed (base or overlay).
///
/// This is the one place `vez upgrade` reaches past its overlay-only rule. The
/// solver keeps every base solvable locked and never offers one as an upgrade
/// target, so the self-upgradable names are chosen here instead and handed to
/// the normal download/apply pipeline as a plain install. That is safe because
/// the apply is `rpm -U` against the *overlay* rpmdb only
/// (`/var/lib/svara/vez/rpmdb`); the base image's rpmdb is never opened, so the
/// base copy stays put underneath as the recovery.
fn self_upgrade_target(
    name: &str,
    candidates: &[Package],
    overlay: &OverlayContext,
    locked: &[String],
    host_arch: &str,
) -> Option<Package> {
    // A versionlocked name is excluded everywhere else; exclude it here too.
    if locked.iter().any(|n| n.as_str() == name) {
        return None;
    }
    let installed = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .filter(|p| p.nevra.name.as_str() == name)
        .max_by(|a, b| a.nevra.evr().as_str().compare_evr(b.nevra.evr().as_str()))?;
    candidates
        .iter()
        .filter(|c| {
            c.nevra.name.as_str() == name
                && (c.nevra.arch.as_str() == host_arch || c.nevra.arch == "noarch")
                && c.nevra.evr().as_str().compare_evr(&installed.nevra.evr())
                    == std::cmp::Ordering::Greater
        })
        .max_by(|a, b| a.nevra.evr().as_str().compare_evr(b.nevra.evr().as_str()))
        .cloned()
}

/// The self-upgradable base packages this run should update: all of them for a
/// bare `vez upgrade` (which means "everything"), or the ones named explicitly.
/// Empty when the name is installed nowhere or already newest.
fn self_upgrade_targets(
    names: &[String],
    candidates: &[Package],
    overlay: &OverlayContext,
    locked: &[String],
    host_arch: &str,
) -> Vec<Package> {
    let mut targets = Vec::new();
    for name in vez_repo::main_config::SELF_UPGRADABLE_NAMES {
        let name: &str = name;
        if !names.is_empty() && !names.iter().any(|q| q.as_str() == name) {
            continue;
        }
        if let Some(pkg) = self_upgrade_target(name, candidates, overlay, locked, host_arch) {
            targets.push(pkg);
        }
    }
    targets
}

/// `vez system-upgrade`, mode-aware; see the doc comment on
/// `Command::SystemUpgrade` for the details. Standalone mode dispatches to
/// the download/reboot/execute/clean/log/status offline-transaction code in
/// `offline.rs`. Split mode runs a normal overlay upgrade followed by a
/// `bootc upgrade` staging check, and refuses every Standalone-only
/// subcommand.
async fn system_upgrade(
    cli: &Cli,
    paths: &OverlayPaths,
    action: Option<&SystemUpgradeAction>,
    dry_run: bool,
) -> Result<()> {
    match &paths.mode {
        OverlayMode::Split { .. } => {
            anyhow::ensure!(
                action.is_none(),
                "system-upgrade subcommands are Standalone-only — this is a Svara overlay system. \
                 A new major release arrives as a new base image; run `vez system-upgrade` with no \
                 subcommand to upgrade overlay packages and stage it."
            );
            upgrade(cli, paths, &[], dry_run, &AdvisoryUpgradeFilter::NONE)
                .await
                .context("upgrading overlay packages")?;
            if dry_run {
                return Ok(());
            }
            flatpak_system_upgrade();
            println!("Checking for a new base image...");
            let status = std::process::Command::new("bootc").arg("upgrade").status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => eprintln!("warning: `bootc upgrade` exited with status {s}"),
                Err(e) => eprintln!("warning: couldn't run `bootc upgrade`: {e}"),
            }
            Ok(())
        }
        OverlayMode::Standalone => match action {
            None => anyhow::bail!(
                "system-upgrade needs a subcommand in Standalone mode, e.g. \
                 `vez system-upgrade download --releasever=45`. See `vez system-upgrade --help`."
            ),
            Some(SystemUpgradeAction::Download {
                releasever,
                no_downgrade,
                packages,
            }) => system_upgrade_download(cli, paths, releasever, *no_downgrade, packages).await,
            Some(SystemUpgradeAction::Reboot { poweroff }) => system_upgrade_reboot(*poweroff),
            Some(SystemUpgradeAction::Execute) => system_upgrade_execute(cli, paths).await,
            Some(SystemUpgradeAction::Clean) => {
                offline::clean().context("cleaning offline transaction state")
            }
            Some(SystemUpgradeAction::Log) => system_upgrade_log(),
            Some(SystemUpgradeAction::Status) => system_upgrade_status(),
        },
    }
}

async fn system_upgrade_download(
    cli: &Cli,
    paths: &OverlayPaths,
    target_releasever: &str,
    no_downgrade: bool,
    packages: &[String],
) -> Result<()> {
    let system_vars = detect_vars(cli);
    anyhow::ensure!(
        system_vars.releasever != target_releasever,
        "need a --releasever greater than the current system version ({})",
        system_vars.releasever
    );

    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let target_vars = vez_repo::RepoVars {
        releasever: target_releasever.to_string(),
        basearch: system_vars.basearch.clone(),
        custom: system_vars.custom.clone(),
    };
    println!("Downloading everything needed to upgrade to release {target_releasever}...");
    let (
        repo_configs,
        candidates,
        _groups,
        _environments,
        _modules,
        _module_defaults,
        fallback_extra,
        advisories,
    ) = load_candidates_with_vars(cli, target_vars, cli.refresh)
        .await
        .context("loading target-release repositories")?;

    let installed_names: Vec<String> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .map(|p| p.nevra.name.clone())
        .collect();
    let names = if packages.is_empty() {
        installed_names
    } else {
        packages.to_vec()
    };

    let options = resolve_options(cli, paths);
    let host_arch = system_vars.basearch.clone();
    let plan = if no_downgrade {
        vez_resolver::resolve_upgrade(&names, &candidates, &overlay, &host_arch, &options)
            .context("resolving upgrade transaction")?
    } else {
        vez_resolver::resolve_distro_sync(&names, &candidates, &overlay, &host_arch, &options)
            .context("resolving distro-sync transaction")?
    };

    anyhow::ensure!(
        !plan.to_install.is_empty(),
        "nothing to download — no upgrade candidates found for release {target_releasever}"
    );
    let alternatives = download_alternatives(&plan.to_install, &candidates, &fallback_extra);
    release_pools((candidates, fallback_extra, advisories));

    println!("Downloading {} package(s):", plan.to_install.len());
    for pkg in &plan.to_install {
        println!("  {} ({})", pkg.nevra, pkg.repo_id);
    }

    let client = build_client(cli)?;
    let dest = offline::packages_dir();
    std::fs::create_dir_all(&dest).with_context(|| format!("creating {}", dest.display()))?;
    let downloaded = vez_transaction::download_all_ex_with_metadata_root(
        &client,
        &plan.to_install,
        &dest,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        false,
        &repo_configs,
        &alternatives,
    )
    .await
    .context("downloading packages")?;

    let cmd_line = format!(
        "vez system-upgrade download --releasever={target_releasever}{}",
        if no_downgrade { " --no-downgrade" } else { "" }
    );
    let state = offline::State {
        status: offline::Status::DownloadComplete,
        system_releasever: system_vars.releasever,
        target_releasever: target_releasever.to_string(),
        cmd_line,
        poweroff_after: false,
        packages: downloaded.iter().map(|d| d.rpm_path.clone()).collect(),
    };
    offline::write_state(&state)?;
    offline::install_unit().context("installing vez-system-upgrade.service")?;

    println!("Download complete! Use `vez system-upgrade reboot` to start the upgrade.");
    Ok(())
}

fn system_upgrade_reboot(poweroff: bool) -> Result<()> {
    let state = offline::load_state()?.context(
        "no offline transaction is stored — run `vez system-upgrade download --releasever=X` first",
    )?;
    anyhow::ensure!(
        matches!(
            state.status,
            offline::Status::DownloadComplete | offline::Status::Ready
        ),
        "system is not ready for the offline transaction (status: {:?})",
        state.status
    );
    anyhow::ensure!(
        offline::packages_dir().is_dir(),
        "downloaded-package directory {} does not exist",
        offline::packages_dir().display()
    );
    anyhow::ensure!(
        offline::unit_is_wanted(),
        "vez-system-upgrade.service is not wanted by system-update.target — re-run `vez system-upgrade download` to reinstall it"
    );

    println!(
        "The system will now reboot to upgrade to release version {}.",
        state.target_releasever
    );
    offline::create_trigger_symlink()?;

    let mut state = state;
    state.status = offline::Status::Ready;
    state.poweroff_after = poweroff;
    offline::write_state(&state)?;

    offline::systemctl_reboot(poweroff)
}

/// Internal: run by `vez-system-upgrade.service` during the
/// `system-update.target` boot phase. Applies every downloaded RPM in one
/// `rpm` transaction, fully offline (no repo or network access; the packages
/// were already fetched and gpg-verified during `download`).
async fn system_upgrade_execute(cli: &Cli, paths: &OverlayPaths) -> Result<()> {
    anyhow::ensure!(
        unsafe { libc::geteuid() } == 0,
        "system-upgrade execute must run as root"
    );
    anyhow::ensure!(
        Path::new(offline::MAGIC_SYMLINK).is_symlink(),
        "trigger file does not exist, exiting"
    );

    let mut state = offline::load_state()?.context("no offline transaction state found")?;
    anyhow::ensure!(
        state.status == offline::Status::Ready,
        "use `vez system-upgrade reboot` to begin the transaction"
    );

    println!("Starting system upgrade. This will take a while.");
    offline::remove_trigger_symlink()?;

    state.status = offline::Status::TransactionIncomplete;
    offline::write_state(&state)?;

    anyhow::ensure!(
        !state.packages.is_empty(),
        "stored transaction has no packages"
    );
    let dbpath = match &paths.mode {
        OverlayMode::Split { overlay_rpmdb, .. } => Some(overlay_rpmdb.clone()),
        OverlayMode::Standalone => None,
    };
    let mut rpm_args = vec![
        "--upgrade".to_string(),
        "--replacepkgs".to_string(),
        "--replacefiles".to_string(),
    ];
    if !cli.main_conf.gpgcheck {
        rpm_args.push("--nosignature".to_string());
    }
    if let Some(dbpath) = &dbpath {
        rpm_args.push("--dbpath".to_string());
        rpm_args.push(dbpath.display().to_string());
    }
    for pkg in &state.packages {
        rpm_args.push(pkg.display().to_string());
    }
    let status = std::process::Command::new("rpm")
        .args(&rpm_args)
        .status()
        .context("running rpm to apply the offline transaction")?;

    if !status.success() {
        eprintln!("Transaction failed: rpm exited with {status}");
        anyhow::bail!("offline transaction failed");
    }

    println!("Transaction complete! Cleaning up and rebooting...");
    let poweroff_after = state.poweroff_after;
    offline::clean()?;
    offline::systemctl_reboot(poweroff_after)
}

fn system_upgrade_log() -> Result<()> {
    let status = std::process::Command::new("journalctl")
        .args(["-u", "vez-system-upgrade.service"])
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => anyhow::bail!("couldn't read logs via journalctl — is systemd-journald running?"),
    }
}

fn system_upgrade_status() -> Result<()> {
    match offline::load_state()? {
        None => println!("No offline transaction is stored."),
        Some(state) => match state.status {
            offline::Status::DownloadIncomplete => println!("No offline transaction is stored."),
            offline::Status::DownloadComplete | offline::Status::Ready => {
                println!("An offline transaction was initiated by the following command:");
                println!("\t{}", state.cmd_line);
                println!("Run `vez system-upgrade reboot` to reboot and perform the offline transaction.");
            }
            offline::Status::TransactionIncomplete => {
                println!("An offline transaction was started, but it did not finish. Run `vez system-upgrade log` for more information.");
                println!("The command that initiated the transaction was:");
                println!("\t{}", state.cmd_line);
            }
        },
    }
    Ok(())
}

/// Finds, for each installed package matching `names` (or every installed
/// package if `names` is empty), the highest-EVR candidate with the same name
/// across enabled repos that's strictly newer than the installed one, then
/// runs it through the same download/verify/apply pipeline as `install`. `rpm
/// -U` upgrades in place, so it doesn't need a separate code path.
///
/// Always limited to `overlay.overlay`, never `overlay.base`, even when a name
/// is given explicitly. The base image is read-only, so "upgrading" a base
/// package can't upgrade it in place: it would quietly layer a duplicate copy
/// into the overlay that shadows the base package from then on, with no way
/// back short of a soft reset. dnf, working from one merged "installed" view,
/// has no such distinction to make. It's the reason vez exists, so a bare `vez
/// upgrade <name>` must never do this by accident. A name that only exists in
/// the base image is reported instead of silently dropped.
///
/// THE ONE EXCEPTION IS `vez` ITSELF (`SELF_UPGRADABLE_NAMES`). It is the only
/// base package with a channel of its own, and keeping it current must not cost
/// an image rebuild — so for that name the overlay copy is made on purpose,
/// through `self_upgrade_targets` below rather than the resolver (whose base
/// lock is left untouched). The base image's copy is never modified: the apply
/// writes only the overlay rpmdb, so it stays underneath as the recovery.
async fn upgrade(
    cli: &Cli,
    paths: &OverlayPaths,
    names: &[String],
    dry_run: bool,
    advisory_filter: &AdvisoryUpgradeFilter<'_>,
) -> Result<()> {
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let (
        repo_configs,
        mut candidates,
        _groups,
        _environments,
        _modules,
        _module_defaults,
        mut fallback_extra,
        advisories,
    ) = load_candidates(cli).await?;

    let installed_names: Vec<&str> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .map(|p| p.nevra.name.as_str())
        .collect();
    let names = &expand_name_patterns(names, &installed_names);

    let locked = vez_transaction::versionlock::list_names(paths)?;
    let host_arch = detect_host_arch(cli);
    warn_base_only_names(names, &overlay, "upgrade");
    let installed: Vec<&Package> = overlay
        .overlay
        .iter()
        .filter(|pkg| names.is_empty() || names.contains(&pkg.nevra.name))
        .filter(|pkg| !locked.contains(&pkg.nevra.name))
        .collect();

    // The self-upgradable base packages (see `SELF_UPGRADABLE_NAMES`) are not
    // in `installed`, which is overlay-only by design, so they are selected
    // here and appended to the transaction below. Skipped under an advisory
    // filter: `vez` is never the subject of an advisory, and `--security` must
    // not quietly pull a non-security update.
    let self_targets = if advisory_filter.is_active() {
        Vec::new()
    } else {
        self_upgrade_targets(names, &candidates, &overlay, &locked, &host_arch)
    };

    // Named explicitly (never `upgrade_all`) even for a bare `vez upgrade`,
    // so versionlock's per-name exclusion (already applied to `installed`
    // above) still applies. `SOLVER_SOLVABLE_ALL` has no way to skip
    // individual names.
    let upgrade_names: Vec<String> = installed.iter().map(|p| p.nevra.name.clone()).collect();
    if upgrade_names.is_empty() && self_targets.is_empty() {
        println!("Nothing to upgrade — everything is already at the newest available version.");
        return Ok(());
    }

    // `--advisory=`/`--security`/`--bugfix`/`--enhancement`/
    // `--advisory-severity=` narrow which *candidate builds* the resolver may
    // pick as the upgrade target for a named package. Any candidate NEVRA
    // that no matching advisory covers is removed from the pool before
    // resolution, like dnf5's advisory-filtered upgrade. Dependencies pulled
    // in transitively (not in `upgrade_names`) aren't filtered, since an
    // advisory covers the packages it patches and not their whole dependency
    // closure.
    if advisory_filter.is_active() {
        let covered: std::collections::HashSet<&str> = advisories
            .iter()
            .filter(|a| advisory_filter.matches(a))
            .flat_map(|a| a.packages.iter().map(String::as_str))
            .collect();
        // Moved, not dropped: they stay available to the download fallback,
        // the same as before the fallback pool stopped being a full clone.
        retain_into(&mut candidates, &mut fallback_extra, |c| {
            !upgrade_names.contains(&c.nevra.name) || covered.contains(c.nevra.to_string().as_str())
        });
    }

    let mut options = resolve_options(cli, paths);
    options.allow_erasing = cli.allowerasing;
    // `resolve_upgrade` reads an empty name list as `upgrade_all`, so it must
    // not be called when the only thing to do is the self-upgrade. Skipping the
    // solve is correct for a self target: it has no dependency closure to
    // resolve (its `Requires` are base packages already installed), and its
    // apply is `rpm -U` against the overlay db regardless.
    let plan = if upgrade_names.is_empty() {
        vez_resolver::Plan::default()
    } else {
        vez_resolver::resolve_upgrade(&upgrade_names, &candidates, &overlay, &host_arch, &options)
            .context("resolving dependencies")?
    };
    let mut to_install = plan.to_install;
    to_install.extend(self_targets);
    let alternatives = download_alternatives(&to_install, &candidates, &fallback_extra);
    release_pools((candidates, fallback_extra, advisories));

    if to_install.is_empty() {
        println!("Nothing to upgrade — everything is already at the newest available version.");
        return Ok(());
    }

    println!("Upgrading {} package(s):", to_install.len());
    for pkg in &to_install {
        println!("  {} ({})", pkg.nevra, pkg.repo_id);
    }

    // `plan.to_erase` comes straight from libsolv's solve (see the
    // `allow_erasing`/`protected_names` jobs in `resolve_upgrade`), which
    // already respects protected packages. The old Rust-side
    // `compute_erasures` pass that used to run here didn't.
    let to_erase = plan.to_erase;
    if !to_erase.is_empty() {
        println!("Erasing (would otherwise break with this upgrade):");
        for pkg in &to_erase {
            println!("  {}", pkg.nevra);
        }
        let erase_names: Vec<String> = to_erase
            .iter()
            .map(|p| format!("{}.{}", p.nevra.name, p.nevra.arch))
            .collect();
        vez_transaction::apply_remove_ex(
            paths,
            &erase_names,
            dry_run,
            &protected_packages(cli),
            true,
            cli.assume_yes,
        )
        .context("erasing conflicting packages")?;
    }

    if dry_run {
        println!("Transaction test succeeded.");
        return Ok(());
    }

    let client = build_client(cli)?;
    if cli.downloadonly {
        return download_only(cli, &client, &to_install, &repo_configs, &alternatives).await;
    }

    if !vez_transaction::confirm_transaction_ex(cli.assume_yes, cli.assume_no, cli.default_yes)? {
        println!("Operation aborted.");
        return Ok(());
    }

    vez_transaction::import_repo_keys(&client, paths, &repo_configs)
        .await
        .context("importing repo gpg keys")?;
    let downloaded = vez_transaction::download_all_ex(
        &client,
        &to_install,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        true,
        &repo_configs,
        &alternatives,
    )
    .await
    .context("downloading packages")?;
    // Upgrades keep whatever reason the package already had. Treat every
    // upgraded package as User here instead of guessing, since
    // `apply_install` has no way to look up the previous reason and an
    // upgrade is never how a package first gets pulled in.
    let explicit_names: Vec<String> = to_install.iter().map(|p| p.nevra.name.clone()).collect();
    let downloaded = apply_install_with_signature_retry(
        &client,
        downloaded,
        &to_install,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        &repo_configs,
        &alternatives,
        |d| {
            vez_transaction::apply_install_ex(
                paths,
                d,
                &repo_configs,
                dry_run,
                &explicit_names,
                cli.no_gpgchecks,
                cli.allowerasing,
                setopt_noscripts(cli),
                &cli.main_conf.installonlypkgs,
                cli.assume_yes,
                true,
            )
        },
    )
    .await?;
    cleanup_downloaded(cli, &downloaded, dry_run);

    // Record any self-upgradable package that was just layered in, so
    // `vez-replay.service` re-applies it after a base-image update. A repo
    // install records every top-level name the same way, and
    // `install_local_rpm_files` does it for a local RPM; `list_add` is
    // idempotent.
    for pkg in &to_install {
        if vez_repo::main_config::SELF_UPGRADABLE_NAMES.contains(&pkg.nevra.name.as_str()) {
            vez_overlay::packages_list_add(&pkg.nevra.name)
                .with_context(|| format!("recording {}", pkg.nevra.name))?;
        }
    }
    Ok(())
}

/// Installs the `BuildRequires` of a `.spec` file (or the equivalent
/// `Requires` in a `.src.rpm`'s header), letting the system rpm tools do the
/// macro-aware parsing: `rpmspec` for a `.spec`, `rpm -qp` for a `.src.rpm`
/// (an srpm stores its BuildRequires as plain header Requires, which is also
/// how dnf's `builddep` reads them).
async fn builddep(
    cli: &Cli,
    paths: &OverlayPaths,
    spec: &Path,
    define: &[String],
    dry_run: bool,
) -> Result<()> {
    anyhow::ensure!(spec.is_file(), "no such file: {}", spec.display());

    let is_srpm = spec.extension().is_some_and(|e| e == "rpm");
    let mut cmd = std::process::Command::new(if is_srpm { "rpm" } else { "rpmspec" });
    if is_srpm {
        cmd.args(["-qp", "--requires"]);
    } else {
        cmd.args(["-q", "--buildrequires"]);
    }
    for d in define {
        cmd.arg("--define").arg(d);
    }
    cmd.arg(spec);

    let out = cmd.output().with_context(|| {
        format!(
            "running {} on {}",
            if is_srpm {
                "rpm -qp --requires"
            } else {
                "rpmspec -q --buildrequires"
            },
            spec.display()
        )
    })?;
    anyhow::ensure!(
        out.status.success(),
        "{} failed on {}:\n{}",
        if is_srpm {
            "rpm -qp --requires"
        } else {
            "rpmspec -q --buildrequires"
        },
        spec.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );

    // Each line is a capability, optionally with a version constraint ("foo
    // >= 1.2.3"). vez's resolver matches by bare name/capability, so drop the
    // constraint. `rpmlib(...)` features are virtual, always satisfied by rpm
    // itself, and never resolve to a real package.
    let names: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("rpmlib("))
        .map(|l| l.split_whitespace().next().unwrap_or(l).to_string())
        .collect();

    if names.is_empty() {
        println!("No build dependencies found for {}.", spec.display());
        return Ok(());
    }

    println!("Installing build dependencies for {}:", spec.display());
    for name in &names {
        println!("  {name}");
    }
    install(cli, paths, &names, dry_run).await
}

async fn install(
    cli: &Cli,
    paths: &OverlayPaths,
    packages: &[String],
    dry_run: bool,
) -> Result<()> {
    install_ex(cli, paths, packages, dry_run, false).await
}

/// Formats a unix timestamp as `YYYY-MM-DD HH:MM:SS` (UTC) using Howard
/// Hinnant's `days_from_civil`/`civil_from_days` calendar math, so we don't
/// need a date/time crate for one display-only conversion.
fn format_unix_time(unix_time: u64) -> String {
    let days = (unix_time / 86400) as i64;
    let secs_of_day = unix_time % 86400;
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_num = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m_num <= 2 { y + 1 } else { y };

    format!("{y:04}-{m_num:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

/// Applies a [`history::Inverse`] (from `undo`/`rollback`) by reusing the
/// plain `install`/`remove` pipelines, so it gets the same confirmation
/// prompt, `--dry-run` handling, versionlock, kernel/protected-package
/// guards, and history recording (undoing a transaction is recorded as a new
/// transaction, as in dnf5). The remove side uses `--nodeps`, like
/// `sync_packages` erasing conflicting packages elsewhere in this file: undo
/// already knows exactly which names it wants gone, and a second rpm-level
/// dependency check against an overlay-only rpmdb view can only be redundant
/// or wrong (see the comment at the `--nodeps` call site in
/// `apply_remove_ex`).
async fn apply_history_inverse(
    cli: &Cli,
    paths: &OverlayPaths,
    inverse: history::Inverse,
    dry_run: bool,
) -> Result<()> {
    if inverse.to_remove.is_empty() && inverse.to_install.is_empty() {
        println!("Nothing to do.");
        return Ok(());
    }
    if !inverse.to_remove.is_empty() {
        vez_transaction::apply_remove_ex(
            paths,
            &inverse.to_remove,
            dry_run,
            &protected_packages(cli),
            true,
            cli.assume_yes,
        )
        .context("undoing install(s)")?;
    }
    if !inverse.to_install.is_empty() {
        install(cli, paths, &inverse.to_install, dry_run)
            .await
            .context("undoing remove(s)")?;
    }
    Ok(())
}

/// Full form of [`install`] with `force_allow_erasing`, used only by
/// `Command::Swap`. A swap needs conflict-clearing erasure whether or not the
/// user passed `--allowerasing`, because a swap that can't move a conflicting
/// sibling package out of the way (e.g. `libavfilter`'s dependency on
/// `ocl-icd` conflicting with an installed `OpenCL-ICD-Loader`) can't swap
/// anything. dnf's `swap` doesn't put this behind a separate flag either.
async fn install_ex(
    cli: &Cli,
    paths: &OverlayPaths,
    packages: &[String],
    dry_run: bool,
    force_allow_erasing: bool,
) -> Result<()> {
    anyhow::ensure!(!packages.is_empty(), "no packages given");

    // URL .rpm arguments (dnf's `dnf install https://.../foo.rpm`): fetch
    // them into the local-rpm cache first, then continue into the same
    // local-file install path below. Anything that isn't a local file and
    // doesn't look like a URL stays in `packages` to be resolved as a package
    // name.
    let (url_rpms, packages): (Vec<String>, Vec<String>) =
        packages.iter().cloned().partition(|p| {
            (p.starts_with("http://") || p.starts_with("https://")) && p.ends_with(".rpm")
        });
    let mut downloaded_url_rpms = Vec::new();
    if !url_rpms.is_empty() {
        let client = build_client(cli)?;
        std::fs::create_dir_all(vez_overlay::paths::LOCAL_RPM_CACHE)
            .with_context(|| format!("creating {}", vez_overlay::paths::LOCAL_RPM_CACHE))?;
        for url in &url_rpms {
            let filename = url
                .rsplit('/')
                .next()
                .filter(|f| !f.is_empty())
                .unwrap_or("download.rpm");
            let dest = Path::new(vez_overlay::paths::LOCAL_RPM_CACHE).join(filename);
            println!("Downloading {url}...");
            let resp = vez_repo::get_with_retry(&client, url)
                .await?
                .error_for_status()
                .with_context(|| format!("fetching {url}"))?;
            let bytes = resp
                .bytes()
                .await
                .with_context(|| format!("reading {url}"))?;
            tokio::fs::write(&dest, &bytes)
                .await
                .with_context(|| format!("writing {}", dest.display()))?;
            downloaded_url_rpms.push(dest.to_string_lossy().into_owned());
        }
    }

    // Local .rpm file arguments install straight from their own header
    // instead of going through repo-candidate resolution. vez's resolver only
    // knows about repo metadata and has no concept of "this is a file, not a
    // name" the way dnf's local-rpm install does.
    let (rpm_files, packages) = split_local_rpm_args(&packages);
    let rpm_files: Vec<String> = downloaded_url_rpms.into_iter().chain(rpm_files).collect();
    if !rpm_files.is_empty() {
        install_local_rpm_files(cli, paths, &rpm_files, dry_run, force_allow_erasing).await?;
    }
    if packages.is_empty() {
        return Ok(());
    }
    let packages = packages.as_slice();

    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let (
        repo_configs,
        mut candidates,
        groups,
        environments,
        modules,
        _module_defaults,
        mut fallback_extra,
        advisories,
    ) = load_candidates(cli).await?;
    let client = build_client(cli)?;
    let host_arch = detect_host_arch(cli);

    // versionlock (like dnf5): a locked name must never resolve to a
    // candidate whose EVR/arch differs from what it was locked at, even
    // through a plain `install`. dnf's versionlock plugin applies its
    // excludes to the package sack every resolve uses, not only
    // `upgrade`/`distro-sync`. `resolve_ex` already enforces this at the
    // libsolv pool level for every path (direct and transitive) through
    // `options.locked_names`, but filtering `candidates` here too keeps a
    // locked, mismatched name out of `expand_groups`/name-pattern expansion
    // below. That way a bare `vez install sqlite-libs` with a stale lock
    // reports "nothing available" instead of doing nothing because of the
    // pool filter and then failing later with a confusing error.
    let locked = vez_transaction::versionlock::list(paths)?;
    if !locked.is_empty() {
        // Moved into the fallback pool instead of dropped: the download
        // fallback has always seen every repo's copy (see `load_candidates`).
        retain_into(&mut candidates, &mut fallback_extra, |pkg| {
            match locked.iter().find(|l| l.name == pkg.nevra.name) {
                Some(lock) => lock.allows(&pkg.nevra.evr(), &pkg.nevra.arch),
                None => true,
            }
        });
    }

    let packages = expand_groups(packages, &groups, &environments)?;
    let candidate_names: Vec<&str> = candidates.iter().map(|c| c.nevra.name.as_str()).collect();
    let packages = expand_name_patterns(&packages, &candidate_names);
    let packages = &packages;

    let packages: Vec<String> = if cli.skip_unavailable {
        let (available, missing): (Vec<String>, Vec<String>) =
            packages.iter().cloned().partition(|name| {
                candidates
                    .iter()
                    .any(|c| c.nevra.name == *name || c.provides.iter().any(|p| p.name == *name))
            });
        for name in &missing {
            println!("Skipping unavailable package: {name}");
        }
        available
    } else {
        packages.to_vec()
    };
    anyhow::ensure!(
        !packages.is_empty(),
        "no packages left to install after --skip-unavailable filtering"
    );

    // A name already in packages.list *and* present in the overlay is a
    // repeated, explicit `install` of something the user already has. Treat
    // it as "repair this and what it depends on", unlike an already-satisfied
    // dependency, which is a quiet no-op. Only meaningful under `Split`;
    // `Standalone` environments have no packages.list.
    //
    // Requiring the package to actually be in the overlay (not just listed in
    // packages.list) matters because packages.list survives a soft reset
    // while the overlay is wiped. After a soft reset (or on first boot, where
    // packages.list is pre-seeded from the factory before anything is
    // installed) every name is "tracked" but none are installed. Sending
    // those down the reinstall path would fail right away (nothing to
    // reinstall) and abort the whole install, and a replay that gave up at the
    // first one would leave the extra layer never rebuilt.
    let (already_listed, packages): (Vec<String>, Vec<String>) =
        if matches!(paths.mode, OverlayMode::Split { .. }) {
            packages.into_iter().partition(|name| {
                vez_overlay::packages_list_contains(name)
                    && overlay.overlay.iter().any(|p| p.nevra.name == *name)
            })
        } else {
            (Vec::new(), packages)
        };
    if !already_listed.is_empty() {
        // Resolved against this command's own overlay/candidate loads instead
        // of loading the rpmdb and every repo a second time. This is the
        // boot-time overlay-sync path (`install --cacheonly <packages.list>`
        // with most names already tracked). The overlay is the same as what a
        // reload would see, since nothing on disk has changed since it was
        // loaded.
        let names = reinstall_closure(&overlay, &already_listed);
        println!(
            "Already tracked — reinstalling {} and its overlay dependencies...",
            names.len()
        );
        let plan = plan_sync(
            cli,
            paths,
            &names,
            SyncMode::Reinstall,
            &overlay,
            &candidates,
        )?;
        let alternatives = download_alternatives(&plan.to_install, &candidates, &fallback_extra);
        if packages.is_empty() {
            // Nothing left for this command to resolve itself, so the pools
            // can go before the download + rpm phase.
            release_pools((
                overlay,
                candidates,
                fallback_extra,
                groups,
                environments,
                modules,
                advisories,
            ));
            return apply_sync(
                cli,
                paths,
                SyncMode::Reinstall,
                plan,
                &repo_configs,
                &alternatives,
                dry_run,
            )
            .await;
        }
        apply_sync(
            cli,
            paths,
            SyncMode::Reinstall,
            plan,
            &repo_configs,
            &alternatives,
            dry_run,
        )
        .await?;
    }
    if packages.is_empty() {
        return Ok(());
    }
    let packages = packages.as_slice();

    let mut options = resolve_options(cli, paths);
    options.allow_erasing |= force_allow_erasing;
    // `force_allow_erasing` is only set by `swap`'s install half. A swap has
    // to install the named package even if some installed package with a
    // different name (usually a base-image one the swap's remove half
    // couldn't touch) already Provides the same capability. See
    // `ResolveOptions::force_names`.
    if force_allow_erasing {
        options.force_names.extend(packages.iter().cloned());
    }
    let plan = if cli.skip_unavailable {
        // The earlier name-or-provides pre-filter is only a heuristic. A
        // candidate can list `name` in its `Provides` (a loose text match)
        // without that name being resolvable by `vez-solv`'s `install_names`
        // job, which only matches literal package names. For example,
        // `heif-pixbuf-loader` shows up in a provides scan but isn't a
        // package name or a capability `vez-solv` interns, so it passed the
        // pre-filter as "available" and then still failed the whole install
        // with "nothing provides" from inside the solver. Retry based on the
        // solver's answer instead: drop exactly the name it says it can't
        // provide and try again, so "unavailable" means whatever the solver
        // can't satisfy, not what a text scan over Provides guesses.
        let mut packages: Vec<String> = packages.to_vec();
        loop {
            match vez_resolver::resolve_ex(&packages, &candidates, &overlay, &host_arch, &options) {
                Ok(plan) => break plan,
                Err(e) => {
                    let msg = e.to_string();
                    let culprit = msg
                        .strip_prefix("nothing provides '")
                        .and_then(|rest| rest.strip_suffix('\''))
                        .and_then(|name| {
                            let bare = name.split('.').next().unwrap_or(name);
                            packages
                                .iter()
                                .find(|p| p.as_str() == name || p.as_str() == bare)
                                .cloned()
                        });
                    match culprit {
                        Some(name) => {
                            println!("Skipping unavailable package: {name}");
                            packages.retain(|p| *p != name);
                            anyhow::ensure!(
                                !packages.is_empty(),
                                "no packages left to install after --skip-unavailable filtering"
                            );
                        }
                        None => return Err(e).context("resolving dependencies"),
                    }
                }
            }
        }
    } else {
        vez_resolver::resolve_ex(packages, &candidates, &overlay, &host_arch, &options)
            .context("resolving dependencies")?
    };

    for name in &plan.skipped {
        println!("Skipping broken package: {name}");
    }
    for name in &plan.already_installed {
        println!("{name} is already installed (base image or overlay) — skipping");
    }

    if plan.to_install.is_empty() {
        if !plan.already_installed.is_empty() && plan.already_satisfied.is_empty() {
            return Ok(());
        }
        println!("Nothing to do — every requested package is already satisfied:");
        for s in &plan.already_satisfied {
            println!("  {} (via {:?})", s.dependency.name, s.origin);
        }
        return Ok(());
    }

    // Classify each planned package against whatever is installed under the
    // same (name, arch), so this preview before downloading uses the same
    // Installing/Upgrading/Downgrading/Reinstalling table as the summary in
    // `apply_install_ex` after downloading, instead of a flat list of names.
    let installed_by_name: std::collections::HashMap<(&str, &str), &Package> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .map(|p| ((p.nevra.name.as_str(), p.nevra.arch.as_str()), p))
        .collect();
    let entries: Vec<vez_transaction::summary::Entry> = plan
        .to_install
        .iter()
        .map(|pkg| {
            match installed_by_name.get(&(pkg.nevra.name.as_str(), pkg.nevra.arch.as_str())) {
                Some(old) => {
                    let action = match vez_core::EvrCompare::compare_evr(
                        pkg.nevra.evr().as_str(),
                        &old.nevra.evr(),
                    ) {
                        std::cmp::Ordering::Equal => vez_transaction::summary::Action::Reinstalling,
                        std::cmp::Ordering::Greater => vez_transaction::summary::Action::Upgrading,
                        std::cmp::Ordering::Less => vez_transaction::summary::Action::Downgrading,
                    };
                    vez_transaction::summary::Entry::new(action, pkg).replacing(old)
                }
                None => vez_transaction::summary::Entry::new(
                    vez_transaction::summary::Action::Installing,
                    pkg,
                ),
            }
        })
        .collect();
    vez_transaction::summary::print_transaction_summary(&entries);
    if !plan.already_satisfied.is_empty() {
        println!(
            "Skipped ({} already satisfied dependencies):",
            plan.already_satisfied.len()
        );
    }
    if !plan.to_obsolete.is_empty() {
        // rpm -U erases these automatically as part of the same transaction
        // (see the doc comment on Plan::to_obsolete). This is only a heads-up
        // before the transaction runs, like dnf's "Obsoleting" line in its
        // plan summary.
        println!("Obsoleting:");
        for pkg in &plan.to_obsolete {
            println!("  {}", pkg.nevra);
        }
    }
    if !plan.to_erase.is_empty() {
        // Unlike `to_obsolete`, rpm won't erase these by itself. They're
        // conflicting overlay packages `--allowerasing` chose to clear out of
        // the way (see the doc comment on `Plan::to_erase`), so vez runs an
        // explicit `rpm -e` for them before the install transaction. Same
        // remove-then-install order `swap` uses, for the same reason:
        // installing first would hit the file/name conflict this path exists
        // to avoid.
        println!("Erasing (conflicts with the above):");
        for pkg in &plan.to_erase {
            println!("  {}", pkg.nevra);
        }
        let erase_names: Vec<String> = plan
            .to_erase
            .iter()
            .map(|p| format!("{}.{}", p.nevra.name, p.nevra.arch))
            .collect();
        vez_transaction::apply_remove_ex(
            paths,
            &erase_names,
            dry_run,
            &protected_packages(cli),
            true,
            cli.assume_yes,
        )
        .context("erasing conflicting packages")?;
    }

    // A dry run only resolves and simulates. The transaction summary printed
    // above (plus any erase-conflict lines) fully answers "what would this
    // do", so stop here instead of downloading every planned package's `.rpm`
    // just to throw it away. This is also what lets a dry run run
    // unprivileged (no GPG-key import into the real overlay dbpath, no real
    // rpm transaction test against it).
    if dry_run {
        println!("Transaction test succeeded.");
        return Ok(());
    }

    let alternatives = download_alternatives(&plan.to_install, &candidates, &fallback_extra);
    release_pools((
        overlay,
        candidates,
        fallback_extra,
        groups,
        environments,
        modules,
        advisories,
    ));

    if cli.downloadonly {
        return download_only(cli, &client, &plan.to_install, &repo_configs, &alternatives).await;
    }

    // Ask before spending time or bandwidth on the download below. The
    // summary above already has everything needed to decide, so there's no
    // reason to make the user wait through a full `download_all_ex` only to
    // find `apply_install_ex` asking the same question.
    if !vez_transaction::confirm_transaction_ex(cli.assume_yes, cli.assume_no, cli.default_yes)? {
        println!("Operation aborted.");
        return Ok(());
    }

    vez_transaction::import_repo_keys(&client, paths, &repo_configs)
        .await
        .context("importing repo gpg keys")?;
    let downloaded = vez_transaction::download_all_ex(
        &client,
        &plan.to_install,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        true,
        &repo_configs,
        &alternatives,
    )
    .await
    .context("downloading packages")?;
    // Only the names the user typed count as `User` reasons. Everything else
    // in `plan.to_install` was pulled in to satisfy a dependency of those, so
    // it's recorded as `Dependency`, which is the distinction `autoremove`
    // needs later.
    let downloaded = apply_install_with_signature_retry(
        &client,
        downloaded,
        &plan.to_install,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        &repo_configs,
        &alternatives,
        |d| {
            vez_transaction::apply_install_ex(
                paths,
                d,
                &repo_configs,
                dry_run,
                packages,
                cli.no_gpgchecks,
                options.allow_erasing,
                setopt_noscripts(cli),
                &cli.main_conf.installonlypkgs,
                cli.assume_yes,
                true,
            )
        },
    )
    .await?;
    cleanup_downloaded(cli, &downloaded, dry_run);
    prune_installonly(cli, paths)?;
    // Only the top-level names the user asked for, not the whole dependency
    // closure. packages.list only exists so a replay knows what to request
    // again, and the resolver brings dependencies back in by itself.
    if matches!(paths.mode, OverlayMode::Split { .. }) {
        for name in packages {
            vez_overlay::packages_list_add(name)?;
        }
    }
    Ok(())
}

/// Splits command-line package arguments into local `.rpm` files and
/// everything else (package names/specs). A local file is any argument ending
/// in `.rpm` that exists as a regular file: an absolute path
/// (`/tmp/foo.rpm`), a relative one (`./foo.rpm`, `../pkgs/foo.rpm`,
/// `pkgs/foo.rpm`), or a bare filename in the directory vez was run from
/// (`foo.rpm`). Local files come back canonicalized to absolute paths, so
/// nothing downstream (header read, the rpm/librpm transaction, the local-rpm
/// cache copy, scriptlet/`/opt` checks) depends on the caller's working
/// directory.
fn split_local_rpm_args(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut rpm_files = Vec::new();
    let mut names = Vec::new();
    for arg in args {
        let path = Path::new(arg);
        if arg.ends_with(".rpm") && path.is_file() {
            let absolute = std::fs::canonicalize(path)
                .or_else(|_| std::path::absolute(path))
                .unwrap_or_else(|_| path.to_path_buf());
            rpm_files.push(absolute.to_string_lossy().into_owned());
        } else {
            names.push(arg.clone());
        }
    }
    (rpm_files, names)
}

/// Installs local `.rpm` files straight from their own header
/// (name/EVR/arch/provides/requires) instead of through vez's repo-backed
/// resolver, which has no concept of "this is a file, not a name". In `Split`
/// overlay mode the *newest* copy of each installed file is cached under
/// `LOCAL_RPM_CACHE` and its name recorded in `LOCAL_RPM_LIST`.
/// A replay reinstalls it from that cached file the same way it replays
/// `PACKAGES_LIST`, rather than trying to resolve a repo name again.
async fn install_local_rpm_files(
    cli: &Cli,
    paths: &OverlayPaths,
    rpm_files: &[String],
    dry_run: bool,
    force_replace: bool,
) -> Result<()> {
    let mut downloaded = Vec::new();
    for path in rpm_files {
        let package = vez_rpmdb::query_local_file(Path::new(path))
            .with_context(|| format!("reading RPM header from {path}"))?;
        downloaded.push(vez_transaction::DownloadedPackage {
            package,
            rpm_path: PathBuf::from(path),
        });
    }

    // Under dnf, a plain `install` (not `reinstall`) of a local file that's
    // already installed at the exact same NEVRA does nothing. For example,
    // akmods' `find /var/cache/akmods -name '*.rpm' | xargs vez install -y`
    // runs right after akmods' own internal `reinstall` already put the same
    // rpm in place, so this second pass would otherwise hand rpm a package it
    // refuses as "already installed" (exit 2) and fail the whole build.
    if !force_replace {
        let overlay = OverlayContext::load(paths).context("loading overlay context")?;
        downloaded.retain(|d| {
            let already = overlay
                .base
                .iter()
                .chain(&overlay.overlay)
                .any(|p| p.nevra == d.package.nevra);
            if already {
                println!("Package {} is already installed.", d.package.nevra);
            }
            !already
        });
    }
    if downloaded.is_empty() {
        return Ok(());
    }

    let names: Vec<String> = downloaded
        .iter()
        .map(|d| d.package.nevra.name.clone())
        .collect();
    println!(
        "Installing {} local RPM file(s): {}",
        downloaded.len(),
        names.join(", ")
    );
    vez_transaction::apply_install_ex(
        paths,
        &downloaded,
        &[],
        dry_run,
        &names,
        cli.no_gpgchecks,
        force_replace,
        setopt_noscripts(cli),
        &[],
        cli.assume_yes,
        false,
    )
    .context("applying rpm transaction")?;

    if !dry_run && matches!(paths.mode, OverlayMode::Split { .. }) {
        std::fs::create_dir_all(vez_overlay::paths::LOCAL_RPM_CACHE)
            .with_context(|| format!("creating {}", vez_overlay::paths::LOCAL_RPM_CACHE))?;
        for d in &downloaded {
            let dest = Path::new(vez_overlay::paths::LOCAL_RPM_CACHE)
                .join(format!("{}.rpm", d.package.nevra.name));
            std::fs::copy(&d.rpm_path, &dest).with_context(|| {
                format!("caching {} to {}", d.rpm_path.display(), dest.display())
            })?;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644))
                .with_context(|| format!("setting permissions on {}", dest.display()))?;
            vez_overlay::local_rpm_list_add(&d.package.nevra.name)?;
        }
    }
    Ok(())
}

/// Works out what a repeated `install` of already-tracked `names` should
/// reinstall: each of `names` plus every installed overlay package in their
/// `Requires` closure. Installing something that's already in packages.list
/// means "make sure this and what it depends on are intact", not a no-op.
fn reinstall_closure(overlay: &OverlayContext, names: &[String]) -> Vec<String> {
    let mut closure: std::collections::HashSet<String> = names.iter().cloned().collect();
    let mut frontier: Vec<String> = names.to_vec();
    while let Some(name) = frontier.pop() {
        let Some(pkg) = overlay.overlay.iter().find(|p| p.nevra.name == name) else {
            continue;
        };
        for dep in &pkg.requires {
            if let Some(dep_pkg) = overlay.overlay.iter().find(|p| {
                p.nevra.name == dep.name || p.provides.iter().any(|prov| prov.name == dep.name)
            }) {
                if closure.insert(dep_pkg.nevra.name.clone()) {
                    frontier.push(dep_pkg.nevra.name.clone());
                }
            }
        }
    }
    closure.into_iter().collect()
}

/// `installonly_limit=` (dnf default: 3). After an install that may have
/// added another version of an `installonlypkgs=` name (the kernel family by
/// default), erase the oldest extra overlay-owned versions of that name so
/// the count is back at the limit. Only ever touches overlay-owned installs:
/// a `Base` copy lives on the read-only image and vez can't remove it anyway.
fn prune_installonly(cli: &Cli, paths: &OverlayPaths) -> Result<()> {
    let limit = cli.main_conf.installonly_limit;
    if limit == 0 || cli.main_conf.installonlypkgs.is_empty() {
        return Ok(());
    }
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let host_arch = detect_host_arch(cli);
    let running_kernel = running_kernel_evr(&host_arch);
    let mut by_name: std::collections::BTreeMap<String, Vec<&Package>> =
        std::collections::BTreeMap::new();
    for pkg in &overlay.overlay {
        if vez_core::name_matches_any(&pkg.nevra.name, &cli.main_conf.installonlypkgs) {
            by_name.entry(pkg.nevra.name.clone()).or_default().push(pkg);
        }
    }
    for (_name, mut versions) in by_name {
        if versions.len() <= limit as usize {
            continue;
        }
        versions.sort_by(|a, b| a.nevra.evr().as_str().compare_evr(&b.nevra.evr()));
        let excess = versions.len() - limit as usize;
        // Same rule as dnf5's `installonly_cmp` (see the doc comment on
        // `running_kernel_evr`): the running build must never land in the
        // oldest-`excess` slice pruned here, wherever its EVR sorts. Walk
        // from oldest to newest and skip it, taking the next-oldest in its
        // place, so the pruned count still ends at `limit`.
        let to_remove: Vec<&Package> = versions
            .iter()
            .filter(|p| {
                running_kernel.as_deref()
                    != Some(format!("{}-{}", p.nevra.version, p.nevra.release).as_str())
            })
            .take(excess)
            .copied()
            .collect();
        if to_remove.is_empty() {
            continue;
        }
        let to_remove: Vec<String> = to_remove.iter().map(|p| p.nevra.to_string()).collect();
        println!(
            "installonly_limit={limit}: pruning {} old package(s):",
            to_remove.len()
        );
        for n in &to_remove {
            println!("  {n}");
        }
        vez_transaction::apply_remove(
            paths,
            &to_remove,
            false,
            &protected_packages(cli),
            cli.assume_yes,
        )?;
    }
    Ok(())
}

/// `keepcache=` support. dnf's default is to delete a package's cached `.rpm`
/// after it's installed successfully (it has done its job, and keeping it is
/// opt-in disk usage). Best-effort: a failed removal just leaves the file
/// cached, as if `keepcache=1` were set.
fn cleanup_downloaded(cli: &Cli, downloaded: &[vez_transaction::DownloadedPackage], dry_run: bool) {
    if dry_run || cli.main_conf.keepcache {
        return;
    }
    for pkg in downloaded {
        let _ = std::fs::remove_file(&pkg.rpm_path);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SyncMode {
    /// Same EVR as installed, to repair a corrupted or modified install.
    Reinstall,
    /// Highest available EVR strictly older than installed.
    Downgrade,
    /// Highest available EVR, whichever direction that is from installed.
    DistroSync,
}

/// Shared implementation for `reinstall`/`downgrade`/`distro-sync`: the same
/// installed-package matching and download/verify/apply pipeline as
/// [`upgrade`], with a different candidate-EVR rule and `rpm --replacepkgs
/// --oldpackage` so same or older EVRs aren't rejected as a no-op.
async fn sync_packages(
    cli: &Cli,
    paths: &OverlayPaths,
    names: &[String],
    dry_run: bool,
    mode: SyncMode,
) -> Result<()> {
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let (
        repo_configs,
        candidates,
        groups,
        environments,
        modules,
        _module_defaults,
        fallback_extra,
        advisories,
    ) = load_candidates(cli).await?;
    let plan = plan_sync(cli, paths, names, mode, &overlay, &candidates)?;
    let alternatives = download_alternatives(&plan.to_install, &candidates, &fallback_extra);
    release_pools((
        overlay,
        candidates,
        fallback_extra,
        groups,
        environments,
        modules,
        advisories,
    ));
    apply_sync(
        cli,
        paths,
        mode,
        plan,
        &repo_configs,
        &alternatives,
        dry_run,
    )
    .await
}

/// What [`plan_sync`] resolved: everything [`apply_sync`] needs, with no
/// reference back into the (large) candidate/overlay pools, so callers can
/// free those before the download + rpm phase.
struct SyncPlan {
    to_install: Vec<Package>,
    to_erase: Vec<Package>,
}

/// The resolution half of [`sync_packages`], working on already-loaded
/// `overlay`/`candidates`. `install` reuses its own loads here for names that
/// are already tracked instead of loading the rpmdb and every repo a second
/// time (the boot-time overlay-sync path).
fn plan_sync(
    cli: &Cli,
    paths: &OverlayPaths,
    names: &[String],
    mode: SyncMode,
    overlay: &OverlayContext,
    candidates: &[Package],
) -> Result<SyncPlan> {
    let installed_names: Vec<&str> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .map(|p| p.nevra.name.as_str())
        .collect();
    let names = &expand_name_patterns(names, &installed_names);

    let locked = vez_transaction::versionlock::list_names(paths)?;
    warn_base_only_names(
        names,
        overlay,
        match mode {
            SyncMode::Reinstall => "reinstall",
            SyncMode::Downgrade => "downgrade",
            SyncMode::DistroSync => "distro-sync",
        },
    );
    let installed: Vec<&Package> = overlay
        .overlay
        .iter()
        .filter(|pkg| names.is_empty() || names.contains(&pkg.nevra.name))
        .filter(|pkg| mode == SyncMode::Reinstall || !locked.contains(&pkg.nevra.name))
        .collect();
    if !names.is_empty() {
        for name in names {
            let in_overlay = installed.iter().any(|p| &p.nevra.name == name);
            let in_base = overlay.base.iter().any(|p| &p.nevra.name == name);
            anyhow::ensure!(in_overlay || in_base, "package '{name}' is not installed");
        }
    }

    let mut options = resolve_options(cli, paths);
    options.allow_erasing = true;
    let host_arch = detect_host_arch(cli);

    let (to_install, to_erase) = if mode == SyncMode::DistroSync {
        // dnf5's `add_distro_sync` (`SOLVER_DISTUPGRADE`): let libsolv pick
        // whatever exactly matches the enabled repos now instead of deciding
        // "highest different EVR" by hand in Rust. That also runs the pick
        // through a real dependency solve and Split mode's base-package lock
        // instead of trusting an EVR-only comparison.
        let names: Vec<String> = installed.iter().map(|p| p.nevra.name.clone()).collect();
        let plan =
            vez_resolver::resolve_distro_sync(&names, candidates, overlay, &host_arch, &options)
                .context("resolving dependencies")?;
        (plan.to_install, plan.to_erase)
    } else {
        // Reinstall/Downgrade need a specific EVR rule ("exact same build" /
        // "highest build strictly older") that libsolv's job model can't
        // express directly, so that choice stays vez's policy and is made
        // here in Rust. The install itself still goes through libsolv as a
        // pinned job (`resolve_pinned`) instead of being trusted as-is, so it
        // still gets a real Requires closure check and the base-package lock.
        //
        // (name, arch) -> candidates, in `candidates` order, so each lookup
        // below is O(1) instead of scanning every repo's packages per
        // installed package (hundreds of packages x 100k+ candidates on a
        // boot-time reinstall). `.next()`/`max_by` see the same sequence as
        // before.
        let mut by_name_arch: std::collections::HashMap<(&str, &str), Vec<&Package>> =
            std::collections::HashMap::new();
        for c in candidates {
            by_name_arch
                .entry((c.nevra.name.as_str(), c.nevra.arch.as_str()))
                .or_default()
                .push(c);
        }
        let mut targets = Vec::new();
        for inst in &installed {
            // Must match `arch` as well as `name`. A multilib package (e.g.
            // `libpng`) is installed as two `installed` entries, one per
            // arch, and a filter that ignores arch can pick the same
            // candidate for both when x86_64 and i686 share an EVR. That
            // pushes the identical NEVRA into `targets` twice, pinning the
            // same solvable through two separate jobs, and libsolv rejects it
            // as "cannot install both X and X".
            let same_name = by_name_arch
                .get(&(inst.nevra.name.as_str(), inst.nevra.arch.as_str()))
                .map(Vec::as_slice)
                .unwrap_or(&[])
                .iter()
                .copied();
            let picked = match mode {
                SyncMode::Reinstall => same_name
                    .filter(|c| {
                        c.nevra.evr().as_str().compare_evr(&inst.nevra.evr())
                            == std::cmp::Ordering::Equal
                    })
                    .next(),
                SyncMode::Downgrade => same_name
                    .filter(|c| {
                        c.nevra.evr().as_str().compare_evr(&inst.nevra.evr())
                            == std::cmp::Ordering::Less
                    })
                    .max_by(|a, b| a.nevra.evr().as_str().compare_evr(b.nevra.evr().as_str())),
                SyncMode::DistroSync => unreachable!(),
            };
            if let Some(pkg) = picked {
                targets.push(pkg.clone());
            }
        }
        if targets.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let plan =
                vez_resolver::resolve_pinned(&targets, candidates, overlay, &host_arch, &options)
                    .context("resolving dependencies")?;
            (plan.to_install, plan.to_erase)
        }
    };
    Ok(SyncPlan {
        to_install,
        to_erase,
    })
}

/// The download/apply half of [`sync_packages`]. It needs no metadata pools
/// beyond the small `alternatives` download-fallback set.
async fn apply_sync(
    cli: &Cli,
    paths: &OverlayPaths,
    mode: SyncMode,
    plan: SyncPlan,
    repo_configs: &[RepoConfig],
    alternatives: &[Package],
    dry_run: bool,
) -> Result<()> {
    let SyncPlan {
        to_install,
        to_erase,
    } = plan;
    if to_install.is_empty() {
        let verb = match mode {
            SyncMode::Reinstall => "reinstall",
            SyncMode::Downgrade => "downgrade",
            SyncMode::DistroSync => "sync",
        };
        println!("Nothing to {verb} — no matching candidate found.");
        return Ok(());
    }

    println!(
        "{} {} package(s):",
        match mode {
            SyncMode::Reinstall => "Reinstalling",
            SyncMode::Downgrade => "Downgrading",
            SyncMode::DistroSync => "Syncing",
        },
        to_install.len()
    );
    for pkg in &to_install {
        println!("  {} ({})", pkg.nevra, pkg.repo_id);
    }

    if !to_erase.is_empty() {
        println!("Erasing (would otherwise break with this transaction):");
        for pkg in &to_erase {
            println!("  {}", pkg.nevra);
        }
        let erase_names: Vec<String> = to_erase
            .iter()
            .map(|p| format!("{}.{}", p.nevra.name, p.nevra.arch))
            .collect();
        vez_transaction::apply_remove_ex(
            paths,
            &erase_names,
            dry_run,
            &protected_packages(cli),
            true,
            cli.assume_yes,
        )
        .context("erasing conflicting packages")?;
    }

    if dry_run {
        println!("Transaction test succeeded.");
        return Ok(());
    }

    let client = build_client(cli)?;
    if cli.downloadonly {
        return download_only(cli, &client, &to_install, repo_configs, alternatives).await;
    }

    if !vez_transaction::confirm_transaction_ex(cli.assume_yes, cli.assume_no, cli.default_yes)? {
        println!("Operation aborted.");
        return Ok(());
    }

    vez_transaction::import_repo_keys(&client, paths, repo_configs)
        .await
        .context("importing repo gpg keys")?;
    let downloaded = vez_transaction::download_all_ex(
        &client,
        &to_install,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        true,
        repo_configs,
        alternatives,
    )
    .await
    .context("downloading packages")?;
    let explicit_names: Vec<String> = to_install.iter().map(|p| p.nevra.name.clone()).collect();
    let downloaded = apply_install_with_signature_retry(
        &client,
        downloaded,
        &to_install,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        repo_configs,
        alternatives,
        |d| {
            vez_transaction::apply_install_ex(
                paths,
                d,
                repo_configs,
                dry_run,
                &explicit_names,
                cli.no_gpgchecks,
                true,
                setopt_noscripts(cli),
                &cli.main_conf.installonlypkgs,
                cli.assume_yes,
                true,
            )
        },
    )
    .await?;
    cleanup_downloaded(cli, &downloaded, dry_run);
    Ok(())
}

/// Removes every overlay package vez recorded as [`Reason::Dependency`] that
/// nothing installed (base or overlay) still `Requires`. Packages with no
/// recorded reason (installed before history tracking existed) count as
/// `User` and are never removed, the same way dnf treats packages it has no
/// yum/dnf history for.
fn autoremove(cli: &Cli, paths: &OverlayPaths, dry_run: bool) -> Result<()> {
    autoremove_ex(cli, paths, dry_run, None)
}

/// Every name reachable through `Requires`/`Recommends` starting from
/// `removed`, computed against `overlay` *before* removal, because the
/// removed packages' dependency edges are gone once they're erased. Feeds the
/// `scope` of `autoremove_ex`, so `clean_requirements_on_remove=` only sweeps
/// what the removed packages themselves pulled in and not unrelated orphans
/// elsewhere on the system (dnf5's `SOLVER_CLEANDEPS` has the same scope, in
/// the same solve).
fn removed_dependency_closure_names(
    removed: &[&Package],
    overlay: &OverlayContext,
) -> std::collections::HashSet<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut frontier: Vec<String> = Vec::new();
    for pkg in removed {
        for d in pkg.requires.iter().chain(pkg.recommends.iter()) {
            for leaf in vez_resolver::boolean_dep_leaf_names(&d.name) {
                if seen.insert(leaf.clone()) {
                    frontier.push(leaf);
                }
            }
        }
    }
    while let Some(name) = frontier.pop() {
        let Some(pkg) = overlay
            .overlay
            .iter()
            .chain(&overlay.base)
            .find(|p| p.nevra.name == name || p.provides.iter().any(|pr| pr.name == name))
        else {
            continue;
        };
        for d in pkg.requires.iter().chain(pkg.recommends.iter()) {
            for leaf in vez_resolver::boolean_dep_leaf_names(&d.name) {
                if seen.insert(leaf.clone()) {
                    frontier.push(leaf);
                }
            }
        }
    }
    seen
}

/// The full autoremove sweep in waves. It works out the whole removal set
/// (packages recorded as `Reason::Dependency` that nothing remaining
/// requires, over as many waves as it takes for removing one wave to orphan
/// the next) before anything is removed, instead of one pass over the
/// snapshot taken before removal. `required_names` only reflects what's
/// *still* installed after subtracting waves already picked. A single pass
/// over the original snapshot only catches the outermost leaves (e.g. steam's
/// direct deps) and leaves behind everything *those* leaves required (often
/// nearly the whole multilib dependency tree), because nothing checks them
/// again once the leaves are gone. Shared by [`autoremove_ex`] (which removes
/// the result) and `vez list --autoremove` (which only reports it).
fn compute_autoremove_candidates(
    paths: &OverlayPaths,
    overlay: &OverlayContext,
    protected_names: &[String],
    scope: Option<&std::collections::HashSet<String>>,
) -> Vec<Package> {
    let mut remaining: Vec<&Package> = overlay.overlay.iter().collect();
    let mut candidates: Vec<Package> = Vec::new();
    let reasons = history::all_reasons(paths);
    loop {
        // `d.name` can be a boolean/rich dependency expression (e.g.
        // `(python3.14dist(pyscard) < 3~~ with python3.14dist(pyscard) >=
        // 2)`) instead of a plain capability name. Expand those to their leaf
        // names so a package required only through a rich dependency doesn't
        // look orphaned.
        //
        // Weak deps (Recommends) count here too. A package installed only
        // because something `Recommends` it (dnf/vez's default; see the
        // best-effort recommends install in `vez-resolver`) is tracked as
        // `Reason::Dependency`, just like a hard-`Requires` pull. If this
        // only looked at `requires`, every Recommends-only package (mpv
        // pulled in by a codec's Recommends,
        // libvirt-daemon-kvm/-config-network/-driver-storage pulled in by
        // virt-manager's Recommends on libvirt-daemon, etc.) would look
        // unneeded on the first pass and get removed, then take *their* deps
        // with them in the next wave. That's how a `vez remove feishin`
        // removed 80 packages, including firefox/virt-manager/steam's own
        // runtime deps.
        let required_names: std::collections::HashSet<String> = overlay
            .base
            .iter()
            .chain(remaining.iter().copied())
            .flat_map(|pkg| {
                pkg.requires
                    .iter()
                    .chain(pkg.recommends.iter())
                    .flat_map(|d| vez_resolver::boolean_dep_leaf_names(&d.name))
            })
            .collect();

        let wave: Vec<&Package> = remaining
            .iter()
            .copied()
            .filter(|pkg| reasons.get(&pkg.nevra.name) == Some(&Reason::Dependency))
            .filter(|pkg| {
                !required_names.contains(pkg.nevra.name.as_str())
                    && !pkg
                        .provides
                        .iter()
                        .any(|p| required_names.contains(p.name.as_str()))
            })
            .filter(|pkg| scope.is_none_or(|s| s.contains(&pkg.nevra.name)))
            .filter(|pkg| !vez_core::name_matches_any(&pkg.nevra.name, protected_names))
            .collect();

        if wave.is_empty() {
            break;
        }
        let wave_nevras: std::collections::HashSet<&vez_core::Nevra> =
            wave.iter().map(|p| &p.nevra).collect();
        remaining.retain(|p| !wave_nevras.contains(&p.nevra));
        candidates.extend(wave.into_iter().cloned());
    }
    candidates
}

/// `scope`, when given, limits the sweep to names reachable from
/// [`removed_dependency_closure_names`]. That's how dnf5 handles
/// `clean_requirements_on_remove=`: dnf folds `SOLVER_CLEANDEPS` into the same
/// solve as the remove, so it only sweeps the removed packages' own dependency
/// subtree that's no longer needed, never an unrelated orphan that was already
/// on the system. `None` (used by the standalone `vez autoremove` command)
/// keeps the unscoped sweep of the whole system. Scoping can only shrink the
/// set the unscoped sweep would compute, never grow it, so this never removes
/// anything a full `vez autoremove` wouldn't; it just leaves unrelated orphans
/// for that explicit sweep.
fn autoremove_ex(
    cli: &Cli,
    paths: &OverlayPaths,
    dry_run: bool,
    scope: Option<&std::collections::HashSet<String>>,
) -> Result<()> {
    // `OverlayMode::Standalone` (distrobox/podman, and every image-build
    // chroot; neither has `/usr/share/rpm`, see
    // `OverlayPaths::detect`) used to refuse this sweep entirely. A package
    // inherited from a parent image layer (e.g. the kernel, installed by an
    // earlier `FROM` base stage) has no `reasons.json` entry in *this*
    // container's fresh state dir, and an older, looser version of the wave
    // filter below treated that untracked state as sweepable. During the
    // COSMIC image build, `vez remove -y google-noto-color-emoji-fonts` then
    // removed 456 packages, the kernel included. The wave filter now requires
    // a *literal* `Some(Reason::Dependency)` (recorded only when `vez`
    // itself, in this container, installed the package as a transitive
    // dependency), so an untracked inherited package reads as `None` and is
    // never a candidate. The bug is fixed where it came from, so a blanket
    // refusal by mode has nothing left to protect against. `protected_names`
    // below is the same second line of defense dnf5 relies on through its
    // `/etc/dnf/protected.d/*.conf` (vez, rpm-related tooling, and whatever
    // an image's `vez.conf` adds with `protected_packages=`) for anything
    // that must never be swept whatever the reason tracking says.
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let protected_names = protected_packages(cli);
    let candidates = compute_autoremove_candidates(paths, &overlay, &protected_names, scope);
    let candidates: Vec<&Package> = candidates.iter().collect();

    if candidates.is_empty() {
        println!("Nothing to autoremove.");
        return Ok(());
    }

    println!(
        "Removing {} unneeded dependency package(s):",
        candidates.len()
    );
    for pkg in &candidates {
        println!("  {}", pkg.nevra);
    }
    // `name.arch` instead of a bare name. A multilib dependency (e.g. steam
    // pulling in both `libnsl.x86_64` and `libnsl.i686`) gives two candidates
    // with the same name, and `rpm -e libnsl` fails as ambiguous ("specifies
    // multiple packages") instead of removing both. `rpm` accepts the
    // `name.arch` qualifier to disambiguate, like `dnf`'s NEVRA-qualified
    // erase.
    let names: Vec<String> = candidates
        .iter()
        .map(|p| format!("{}.{}", p.nevra.name, p.nevra.arch))
        .collect();
    vez_transaction::apply_remove(
        paths,
        &names,
        dry_run,
        &protected_packages(cli),
        cli.assume_yes,
    )?;
    Ok(())
}

/// Checks every installed package's `Requires` (base + overlay) against what
/// the combined installed set provides, and reports anything unmet. It's only
/// a consistency check between installed packages (rpmdb corruption, a forced
/// install, a botched removal); it doesn't compare against repo metadata the
/// way `check-upgrade` does.
fn pkg_provides(pkg: &Package, capability: &str) -> bool {
    pkg.nevra.name == capability || pkg.provides.iter().any(|d| d.name == capability)
}

fn pkg_requires(pkg: &Package, capability: &str) -> bool {
    pkg.requires.iter().any(|d| d.name == capability)
}

/// `vez provides <capability>`: reports every installed package that provides
/// it, then (if the network is available) every repo candidate too, in the
/// same two-part "Installed/Available" layout as dnf's `provides`.
async fn provides(cli: &Cli, paths: &OverlayPaths, capability: &str) -> Result<()> {
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let mut found = false;
    for pkg in overlay.base.iter().chain(&overlay.overlay) {
        if pkg_provides(pkg, capability) {
            println!("{} : installed", pkg.nevra);
            found = true;
        }
    }
    if let Ok((_, candidates, _groups, _environments, ..)) = load_candidates(cli).await {
        for pkg in &candidates {
            if pkg_provides(pkg, capability) {
                println!("{} : {}", pkg.nevra, pkg.repo_id);
                found = true;
            }
        }
    }
    if !found {
        println!("No matches found for '{capability}'.");
    }
    Ok(())
}

/// `vez advisory list/info/summary` (dnf5 alias `updateinfo`). Sorts an
/// advisory's *covered packages* against the live overlay/rpmdb view the same
/// way [`check_upgrade`] does. `--available` (the default) is packages that
/// aren't installed at that exact EVR, `--updates` is an installed package
/// with a strictly newer candidate EVR, and `--installed` is an installed
/// package at that exact EVR. An advisory counts for a bucket if *any* of its
/// covered packages does, like dnf5's collection-level semantics, since one
/// advisory often covers several subpackages of the same source build.
async fn advisory(cli: &Cli, paths: &OverlayPaths, action: &AdvisoryAction) -> Result<()> {
    let (filters, mode) = match action {
        AdvisoryAction::List { filters } => (filters, "list"),
        AdvisoryAction::Info { filters } => (filters, "info"),
        AdvisoryAction::Summary { filters } => (filters, "summary"),
    };

    let (_, candidates, _groups, _environments, _modules, _module_defaults, _fallback, advisories) =
        load_candidates(cli).await?;
    anyhow::ensure!(
        !advisories.is_empty(),
        "no advisory (updateinfo) data in enabled repos"
    );

    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let installed: Vec<&Package> = overlay.base.iter().chain(&overlay.overlay).collect();
    let installed_nevras: std::collections::HashSet<String> =
        installed.iter().map(|p| p.nevra.to_string()).collect();

    let bucket_of = |nevra_str: &str| -> Option<&'static str> {
        let pkg_nevra = vez_core::Nevra::parse_nevra(nevra_str)?;
        if installed_nevras.contains(nevra_str) {
            return Some("installed");
        }
        let is_update = installed.iter().any(|inst| {
            inst.nevra.name == pkg_nevra.name
                && inst.nevra.arch == pkg_nevra.arch
                && pkg_nevra.evr().as_str().compare_evr(&inst.nevra.evr())
                    == std::cmp::Ordering::Greater
        });
        if is_update {
            return Some("updates");
        }
        Some("available")
    };

    let want_severity = filters
        .severity
        .as_deref()
        .map(vez_repo::updateinfo::Severity::parse_cli);
    let want_kind = filters.bugfix || filters.security || filters.enhancement || filters.newpackage;
    let name_pool: Vec<&str> = candidates
        .iter()
        .map(|p| p.nevra.name.as_str())
        .chain(installed.iter().map(|p| p.nevra.name.as_str()))
        .collect();
    let want_names = expand_name_patterns(&filters.packages, &name_pool);

    let want_any_bucket = filters.installed || filters.updates || filters.all;
    let matched: Vec<(&vez_repo::Advisory, Vec<&str>)> = advisories
        .iter()
        .filter_map(|adv| {
            if !filters.advisory.is_empty() && !filters.advisory.contains(&adv.id) {
                return None;
            }
            if want_kind {
                let ok = (filters.bugfix && adv.kind == vez_repo::updateinfo::AdvisoryKind::Bugfix)
                    || (filters.security
                        && adv.kind == vez_repo::updateinfo::AdvisoryKind::Security)
                    || (filters.enhancement
                        && adv.kind == vez_repo::updateinfo::AdvisoryKind::Enhancement)
                    || (filters.newpackage
                        && adv.kind == vez_repo::updateinfo::AdvisoryKind::Newpackage);
                if !ok {
                    return None;
                }
            }
            if let Some(want) = want_severity {
                if adv.severity < want {
                    return None;
                }
            }
            let mut buckets: Vec<&str> = adv.packages.iter().filter_map(|n| bucket_of(n)).collect();
            buckets.sort_unstable();
            buckets.dedup();
            if !want_names.is_empty() {
                let covers_wanted = adv
                    .packages
                    .iter()
                    .filter_map(|n| vez_core::Nevra::parse_nevra(n))
                    .any(|n| want_names.iter().any(|w| *w == n.name));
                if !covers_wanted {
                    return None;
                }
            }
            let selected_buckets: Vec<&str> = if filters.all {
                buckets.clone()
            } else if want_any_bucket {
                buckets
                    .iter()
                    .copied()
                    .filter(|b| {
                        (*b == "installed" && filters.installed)
                            || (*b == "updates" && filters.updates)
                    })
                    .collect()
            } else {
                // Default: --available.
                buckets
                    .iter()
                    .copied()
                    .filter(|b| *b == "available")
                    .collect()
            };
            if selected_buckets.is_empty() {
                return None;
            }
            Some((adv, selected_buckets))
        })
        .collect();

    match mode {
        "summary" => {
            let mut counts: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for (adv, _) in &matched {
                *counts.entry(adv.kind.as_str()).or_default() += 1;
            }
            if counts.is_empty() {
                println!("No advisories match the given filters.");
            } else {
                for (kind, count) in &counts {
                    println!("{count:>4} {kind}");
                }
                println!("{:>4} total", matched.len());
            }
        }
        "info" => {
            if matched.is_empty() {
                println!("No advisories match the given filters.");
            }
            for (adv, _) in &matched {
                println!("Advisory ID    : {}", adv.id);
                println!("Type           : {}", adv.kind.as_str());
                println!("Severity       : {}", adv.severity.as_str());
                if !adv.issued.is_empty() {
                    println!("Issued         : {}", adv.issued);
                }
                println!("Title          : {}", adv.title);
                if !adv.description.is_empty() {
                    println!("Description    : {}", adv.description);
                }
                println!("Packages       :");
                for pkg in &adv.packages {
                    println!("  {pkg}");
                }
                println!();
            }
        }
        _ => {
            if matched.is_empty() {
                println!("No advisories match the given filters.");
            } else {
                println!("{:<24} {:<12} {:<10} Title", "Advisory", "Type", "Severity");
                for (adv, _) in &matched {
                    println!(
                        "{:<24} {:<12} {:<10} {}",
                        adv.id,
                        adv.kind.as_str(),
                        adv.severity.as_str(),
                        adv.title
                    );
                }
            }
        }
    }
    Ok(())
}

/// `vez check-upgrade`/`check-update`: the same candidate selection as
/// [`upgrade`], printed instead of applied. Always limited to the overlay,
/// even with explicit names. A base-image package can never be upgraded
/// through the overlay, so it must never be reported as having an update
/// (software centers and daemons poll this to decide what to show or offer).
///
/// This runs the real `vez_resolver::resolve_upgrade` solve (the same path
/// `vez upgrade` uses) and reports `Plan::to_upgrade`, instead of comparing
/// versions per name on its own. A separate "installed vs newest in repo"
/// diff would drift from what `vez upgrade` does. It used to list an i686
/// build whose x86_64 sibling is base-owned (and so locked across all arches
/// in Split mode; see `build_pool_locked` in `vez-solv`) even though the real
/// upgrade skips it.
async fn check_upgrade(
    cli: &Cli,
    paths: &OverlayPaths,
    names: &[String],
    json: bool,
) -> Result<()> {
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    // dnf's check-upgrade always fetches fresh metadata (unlike list/info,
    // which are fine with a stale cache). An update check that reports
    // against last week's metadata is worse than useless, so refresh whatever
    // metadata_expire= says.
    let (_, candidates, _groups, _environments, ..) = load_candidates_force_refresh(cli).await?;

    let installed_names: Vec<&str> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .map(|p| p.nevra.name.as_str())
        .collect();
    let names = &expand_name_patterns(names, &installed_names);

    let locked = vez_transaction::versionlock::list_names(paths)?;
    warn_base_only_names(names, &overlay, "check-upgrade");
    let installed: Vec<&Package> = overlay
        .overlay
        .iter()
        .filter(|pkg| names.is_empty() || names.contains(&pkg.nevra.name))
        .filter(|pkg| !locked.contains(&pkg.nevra.name))
        .collect();

    let upgrade_names: Vec<String> = installed.iter().map(|p| p.nevra.name.clone()).collect();
    let mut any = false;
    let mut updates = Vec::new();
    if !upgrade_names.is_empty() {
        let mut options = resolve_options(cli, paths);
        options.allow_erasing = cli.allowerasing;
        let host_arch = detect_host_arch(cli);
        let plan = vez_resolver::resolve_upgrade(
            &upgrade_names,
            &candidates,
            &overlay,
            &host_arch,
            &options,
        )
        .context("resolving dependencies")?;

        for newer in &plan.to_upgrade {
            // Match the installed package this upgrade replaces: same
            // name/arch when possible (the usual case), otherwise just the
            // name (libsolv can move a package to a different arch, e.g.
            // syncing a multilib sibling's EVR).
            let inst = installed
                .iter()
                .find(|p| p.nevra.name == newer.nevra.name && p.nevra.arch == newer.nevra.arch)
                .or_else(|| installed.iter().find(|p| p.nevra.name == newer.nevra.name));
            let Some(inst) = inst else { continue };

            any = true;
            if json {
                updates.push(serde_json::json!({
                    "name": inst.nevra.name,
                    "current_version": inst.nevra.evr(),
                    "version": newer.nevra.evr(),
                    "arch": newer.nevra.arch,
                    "repo": newer.repo_id,
                }));
            } else {
                println!("{} -> {} ({})", inst.nevra, newer.nevra, newer.repo_id);
            }
        }
    }

    // The self-upgradable base packages (see `SELF_UPGRADABLE_NAMES`) are not
    // in `installed` — that is overlay-only by design — but `check-upgrade`
    // must still report them, or a software centre polling it would never show
    // that vez itself can be updated.
    let host_arch = detect_host_arch(cli);
    for newer in self_upgrade_targets(names, &candidates, &overlay, &locked, &host_arch) {
        let inst = overlay
            .base
            .iter()
            .chain(&overlay.overlay)
            .filter(|p| p.nevra.name == newer.nevra.name)
            .max_by(|a, b| a.nevra.evr().as_str().compare_evr(b.nevra.evr().as_str()));
        let Some(inst) = inst else { continue };
        any = true;
        if json {
            updates.push(serde_json::json!({
                "name": inst.nevra.name,
                "current_version": inst.nevra.evr(),
                "version": newer.nevra.evr(),
                "arch": newer.nevra.arch,
                "repo": newer.repo_id,
            }));
        } else {
            println!("{} -> {} ({})", inst.nevra, newer.nevra, newer.repo_id);
        }
    }
    if json {
        println!("{}", serde_json::json!({ "updates": updates }));
    } else if !any {
        println!("Nothing to upgrade.");
    }
    Ok(())
}

/// Arguments for [`repoquery`], bundled in a struct because dnf5's
/// `repoquery` has so many independent filters and output modes that a
/// positional argument list was no longer readable.
struct RepoqueryArgs<'a> {
    pattern: Option<&'a str>,
    installed: bool,
    available: bool,
    whatprovides: Option<&'a str>,
    whatrequires: Option<&'a str>,
    whatconflicts: Option<&'a str>,
    whatobsoletes: Option<&'a str>,
    whatrecommends: Option<&'a str>,
    whatenhances: Option<&'a str>,
    whatsuggests: Option<&'a str>,
    whatsupplements: Option<&'a str>,
    recursive: bool,
    arch: Option<&'a str>,
    duplicates: bool,
    info: bool,
    queryformat: Option<&'a str>,
    requires: bool,
    provides: bool,
    conflicts: bool,
    obsoletes: bool,
    recommends: bool,
    enhances: bool,
    suggests: bool,
    supplements: bool,
    srpm: bool,
    location: bool,
    nvr: bool,
    envra: bool,
    extras: bool,
    upgrades: bool,
    querytags: bool,
}

fn pkg_conflicts(pkg: &Package, capability: &str) -> bool {
    pkg.conflicts.iter().any(|d| d.name == capability)
}

fn pkg_obsoletes(pkg: &Package, capability: &str) -> bool {
    pkg.obsoletes.iter().any(|d| d.name == capability)
}

fn pkg_recommends(pkg: &Package, capability: &str) -> bool {
    pkg.recommends.iter().any(|d| d.name == capability)
}

fn pkg_enhances(pkg: &Package, capability: &str) -> bool {
    pkg.enhances.iter().any(|d| d.name == capability)
}

fn pkg_suggests(pkg: &Package, capability: &str) -> bool {
    pkg.suggests.iter().any(|d| d.name == capability)
}

fn pkg_supplements(pkg: &Package, capability: &str) -> bool {
    pkg.supplements.iter().any(|d| d.name == capability)
}

/// `--extras`: true if no candidate in `candidates` has this installed
/// package's name, i.e. no configured repo offers it. Matched by name only
/// (not arch/EVR), like dnf's extras.
fn pkg_is_extra(pkg: &Package, candidates: &[Package]) -> bool {
    !candidates.iter().any(|c| c.nevra.name == pkg.nevra.name)
}

/// `--upgrades`: true if some same-name/same-arch candidate has a strictly
/// greater EVR than this installed package.
fn pkg_has_upgrade(pkg: &Package, candidates: &[Package]) -> bool {
    candidates.iter().any(|c| {
        c.nevra.name == pkg.nevra.name
            && c.nevra.arch == pkg.nevra.arch
            && c.nevra.evr().as_str().compare_evr(&pkg.nevra.evr()) == std::cmp::Ordering::Greater
    })
}

/// Every capability name a package could be matched against as a *provider*:
/// its own name/self-provide plus every explicit `Provides:` entry. Used to
/// grow the frontier one hop at a time for `--recursive --whatrequires`.
fn pkg_provided_names(pkg: &Package) -> impl Iterator<Item = &str> {
    std::iter::once(pkg.nevra.name.as_str()).chain(pkg.provides.iter().map(|d| d.name.as_str()))
}

/// dnf-style `--queryformat`/`--qf` substitution: replaces every `%{tag}`
/// with that field's value. Unknown tags are left as they are (rpm's
/// `--queryformat` does the same, instead of erroring on a typo).
fn apply_queryformat(fmt: &str, pkg: &Package) -> String {
    let mut out = String::with_capacity(fmt.len());
    let mut rest = fmt;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            break;
        };
        let tag = &after[..end];
        let value = match tag {
            "name" => pkg.nevra.name.clone(),
            "epoch" => pkg.nevra.epoch.to_string(),
            "version" => pkg.nevra.version.clone(),
            "release" => pkg.nevra.release.clone(),
            "evr" => pkg.nevra.evr(),
            "arch" => pkg.nevra.arch.clone(),
            "nevra" => pkg.nevra.to_string(),
            "summary" => pkg.summary.clone(),
            "repoid" => pkg.repo_id.clone(),
            "size" => pkg.download_size.to_string(),
            "installsize" => pkg.install_size.to_string(),
            "location" => pkg.location.clone(),
            other => {
                out.push_str("%{");
                out.push_str(other);
                out.push('}');
                rest = &after[end + 1..];
                continue;
            }
        };
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

async fn repoquery(cli: &Cli, paths: &OverlayPaths, args: RepoqueryArgs<'_>) -> Result<()> {
    if args.querytags {
        for tag in [
            "name",
            "epoch",
            "version",
            "release",
            "evr",
            "arch",
            "nevra",
            "summary",
            "repoid",
            "size",
            "installsize",
            "location",
        ] {
            println!("{tag}");
        }
        return Ok(());
    }

    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let installed_set: Vec<Package> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .cloned()
        .collect();
    let candidates: Vec<Package> =
        if args.available || !args.installed || args.extras || args.upgrades {
            load_candidates(cli)
                .await
                .map(|(_, c, ..)| c)
                .unwrap_or_default()
        } else {
            Vec::new()
        };

    // `--extras`/`--upgrades` compare the installed set against repo
    // candidates, which doesn't make sense on top of `--available`'s "repo
    // candidates only" pool. So they force installed-only regardless of
    // `--installed`/`--available`, like dnf5.
    let installed_only_query = args.extras || args.upgrades;
    let mut pool: Vec<Package> = Vec::new();
    if installed_only_query || args.installed || !args.available {
        pool.extend(installed_set.iter().cloned());
    }
    if !installed_only_query && (args.available || !args.installed) {
        pool.extend(candidates.iter().cloned());
    }

    // `--recursive --whatrequires`: BFS over the reverse-dependency graph.
    // Rescanning the whole pool every round is O(pool * frontier) and blows
    // up on a broad capability like `glibc` (almost everything requires it,
    // thousands of rounds). So build an index from `Requires` names to
    // requiring-package indices once up front, which makes each round
    // O(frontier * avg requirers) with direct lookups.
    let recursive_whatrequires: Option<std::collections::HashSet<usize>> = if args.recursive {
        args.whatrequires.map(|cap| {
            let mut requires_index: std::collections::HashMap<&str, Vec<usize>> =
                std::collections::HashMap::new();
            for (i, pkg) in pool.iter().enumerate() {
                for dep in &pkg.requires {
                    requires_index.entry(dep.name.as_str()).or_default().push(i);
                }
            }
            let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
            let mut frontier: Vec<String> = vec![cap.to_string()];
            loop {
                let newly_matched: Vec<usize> = frontier
                    .iter()
                    .filter_map(|f| requires_index.get(f.as_str()))
                    .flatten()
                    .copied()
                    .filter(|i| !visited.contains(i))
                    .collect::<std::collections::HashSet<usize>>()
                    .into_iter()
                    .collect();
                if newly_matched.is_empty() {
                    break;
                }
                let mut next_frontier = Vec::new();
                for &i in &newly_matched {
                    visited.insert(i);
                    next_frontier.extend(pkg_provided_names(&pool[i]).map(str::to_string));
                }
                frontier = next_frontier;
            }
            visited
        })
    } else {
        None
    };

    // `--duplicates`: only keep name+arch groups with more than one distinct
    // EVR in the matched pool (after every other filter), like dnf5's
    // "multiple builds available" report.
    let duplicate_names: Option<std::collections::HashSet<(String, String)>> = if args.duplicates {
        let mut evrs: std::collections::HashMap<
            (String, String),
            std::collections::HashSet<String>,
        > = std::collections::HashMap::new();
        for pkg in &pool {
            evrs.entry((pkg.nevra.name.clone(), pkg.nevra.arch.clone()))
                .or_default()
                .insert(pkg.nevra.evr());
        }
        Some(
            evrs.into_iter()
                .filter(|(_, set)| set.len() > 1)
                .map(|(k, _)| k)
                .collect(),
        )
    } else {
        None
    };

    // A bare pattern can use dnf's `name.arch` syntax (`vez repoquery
    // libatomic.i686`). Without this, patterns were only glob-matched against
    // the plain package name, so an exact-arch query for a real, available
    // package returned nothing (the dot suffix was treated as part of the
    // name and never matched). Only split on `.` when the suffix is an arch
    // present in the pool, so package names that contain a dot aren't
    // misparsed.
    let (pattern_name, pattern_arch): (Option<&str>, Option<&str>) = match args.pattern {
        Some(pat) => match pat.rsplit_once('.') {
            Some((base, arch)) if pool.iter().any(|p| p.nevra.arch == arch) => {
                (Some(base), Some(arch))
            }
            _ => (Some(pat), None),
        },
        None => (None, None),
    };

    let matches: Vec<&Package> = pool
        .iter()
        .enumerate()
        .filter(|(_, pkg)| pattern_name.is_none_or(|pat| glob_match(pat, &pkg.nevra.name)))
        .filter(|(_, pkg)| pattern_arch.is_none_or(|a| pkg.nevra.arch == a))
        .filter(|(_, pkg)| args.arch.is_none_or(|a| glob_match(a, &pkg.nevra.arch)))
        .filter(|(_, pkg)| args.whatprovides.is_none_or(|cap| pkg_provides(pkg, cap)))
        .filter(|(i, pkg)| match &recursive_whatrequires {
            Some(visited) => visited.contains(i),
            None => args.whatrequires.is_none_or(|cap| pkg_requires(pkg, cap)),
        })
        .filter(|(_, pkg)| args.whatconflicts.is_none_or(|cap| pkg_conflicts(pkg, cap)))
        .filter(|(_, pkg)| args.whatobsoletes.is_none_or(|cap| pkg_obsoletes(pkg, cap)))
        .filter(|(_, pkg)| {
            args.whatrecommends
                .is_none_or(|cap| pkg_recommends(pkg, cap))
        })
        .filter(|(_, pkg)| args.whatenhances.is_none_or(|cap| pkg_enhances(pkg, cap)))
        .filter(|(_, pkg)| args.whatsuggests.is_none_or(|cap| pkg_suggests(pkg, cap)))
        .filter(|(_, pkg)| {
            args.whatsupplements
                .is_none_or(|cap| pkg_supplements(pkg, cap))
        })
        .filter(|(_, pkg)| {
            duplicate_names
                .as_ref()
                .is_none_or(|dups| dups.contains(&(pkg.nevra.name.clone(), pkg.nevra.arch.clone())))
        })
        .filter(|(_, pkg)| !args.srpm || pkg.nevra.arch == "src")
        .filter(|(_, pkg)| !args.extras || pkg_is_extra(pkg, &candidates))
        .filter(|(_, pkg)| !args.upgrades || pkg_has_upgrade(pkg, &candidates))
        .map(|(_, pkg)| pkg)
        .collect();

    for pkg in matches {
        if let Some(fmt) = args.queryformat {
            println!("{}", apply_queryformat(fmt, pkg));
        } else if args.info {
            println!("Name         : {}", pkg.nevra.name);
            println!("Version      : {}", pkg.nevra.evr());
            println!("Architecture : {}", pkg.nevra.arch);
            println!(
                "Repository   : {}",
                if pkg.repo_id.is_empty() {
                    "installed"
                } else {
                    &pkg.repo_id
                }
            );
            println!("Size         : {}", vez_core::format_size(pkg.install_size));
            println!("Summary      : {}", pkg.summary);
            println!();
        } else if args.requires {
            for d in &pkg.requires {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.provides {
            for d in &pkg.provides {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.conflicts {
            for d in &pkg.conflicts {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.obsoletes {
            for d in &pkg.obsoletes {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.recommends {
            for d in &pkg.recommends {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.enhances {
            for d in &pkg.enhances {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.suggests {
            for d in &pkg.suggests {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.supplements {
            for d in &pkg.supplements {
                println!("{}: {}", pkg.nevra, d.name);
            }
        } else if args.location {
            println!("{}", pkg.location);
        } else if args.envra {
            println!(
                "{}:{}-{}-{}.{}",
                pkg.nevra.epoch,
                pkg.nevra.name,
                pkg.nevra.version,
                pkg.nevra.release,
                pkg.nevra.arch
            );
        } else if args.nvr {
            println!(
                "{}-{}-{}",
                pkg.nevra.name, pkg.nevra.version, pkg.nevra.release
            );
        } else {
            // `--nevra` is the same as the default (NEVRA is what's printed
            // without any output-mode flag). It's kept as an explicit,
            // documented flag to match dnf5's `--nevra`; it doesn't change
            // anything.
            println!("{}", pkg.nevra);
        }
    }
    Ok(())
}

/// `vez info <name>`: the installed copy (if any) first, then every matching
/// repo candidate, in the same "Installed Packages" / "Available Packages"
/// sections dnf uses.
async fn info(cli: &Cli, paths: &OverlayPaths, name: &str) -> Result<()> {
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let mut printed = false;
    for pkg in overlay.base.iter().chain(&overlay.overlay) {
        if pkg.nevra.name == name {
            println!("Name         : {}", pkg.nevra.name);
            println!("Version      : {}", pkg.nevra.evr());
            println!("Architecture : {}", pkg.nevra.arch);
            println!("Repository   : installed");
            println!("Summary      : {}", pkg.summary);
            println!();
            printed = true;
        }
    }
    if let Ok((_, candidates, _groups, _environments, ..)) = load_candidates(cli).await {
        for pkg in &candidates {
            if pkg.nevra.name == name {
                println!("Name         : {}", pkg.nevra.name);
                println!("Version      : {}", pkg.nevra.evr());
                println!("Architecture : {}", pkg.nevra.arch);
                println!("Repository   : {}", pkg.repo_id);
                println!("Summary      : {}", pkg.summary);
                println!();
                printed = true;
            }
        }
    }
    if !printed {
        println!("No package named '{name}' found.");
    }
    Ok(())
}

/// `vez leaves`: overlay packages that nothing else installed `Requires` (by
/// name or by any of its `Provides`).
fn leaves(paths: &OverlayPaths) -> Result<()> {
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let required_names: std::collections::HashSet<&str> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .flat_map(|pkg| pkg.requires.iter().map(|d| d.name.as_str()))
        .collect();

    for pkg in &overlay.overlay {
        let is_leaf = !required_names.contains(pkg.nevra.name.as_str())
            && !pkg
                .provides
                .iter()
                .any(|p| required_names.contains(p.name.as_str()));
        if is_leaf {
            println!("{}", pkg.nevra);
        }
    }
    Ok(())
}

/// Walks `dir` removing every `.rpm` file, including in every subdirectory
/// such as `repos`. Sharing that walk with the metadata cache is safe because
/// metadata files (`repomd.xml`, `primary.xml.zst`, `modules.yaml`, ...)
/// never end in `.rpm`, so this never touches them; `vez clean metadata`
/// removes the rest of `repos` itself. Returns the number removed.
fn remove_rpms_recursive(dir: &Path) -> u64 {
    let mut removed = 0u64;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            removed += remove_rpms_recursive(&path);
        } else if path.extension().is_some_and(|e| e == "rpm")
            && std::fs::remove_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// `vez clean [all|packages|metadata]`. `packages` removes downloaded `.rpm`s
/// from under `cache_dir/repos/<repo>-<hash>/packages/` (the hashed per-repo
/// cache dir that [`vez_transaction::download_all_ex`] shares with the metadata
/// cache; see its doc comment). A flat `.rpm` directly under `cache_dir` is
/// removed too, for `vez download --destdir` output left in the default cache
/// dir. `metadata` removes `cache_dir/repos` (the repo metadata cache), and
/// `all` does both.
/// Compute the plan for the declared package set against this machine.
///
/// Reads `/etc/svara/packages.toml` and the two name lists the plan needs: everything
/// installed (for "is it present", and for resolving patterns) and what vez itself installed
/// (for "is it extra"). The second is `packages.list` — the record a replay also uses — and
/// not the rpmdb, because the question is who put it there, which only vez knows.
///
/// A missing file is an empty set, not an error: every machine starts with none, and
/// `vez diff` on such a machine should say so rather than fail.
fn declared_plan(paths: &OverlayPaths) -> Result<vez_overlay::declarative::Plan> {
    let path = std::path::Path::new(vez_overlay::paths::PACKAGES_TOML);
    let declared = vez_overlay::declarative::DeclaredSet::load(path)?;

    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let installed: Vec<String> = overlay
        .base
        .iter()
        .chain(&overlay.overlay)
        .map(|p| p.nevra.name.clone())
        .collect();
    let tracked = vez_overlay::packages_list_names();

    Ok(vez_overlay::declarative::Plan::compute(
        &declared, &installed, &tracked,
    ))
}

/// Print a plan the way both `vez diff` and `vez apply --dry-run` want it.
///
/// `acting` changes only the heading and the closing line, never the content: a summary that
/// differed between the two would be a second implementation of the plan.
fn print_plan(plan: &vez_overlay::declarative::Plan, acting: bool) {
    let file = vez_overlay::paths::PACKAGES_TOML;
    if plan.install.is_empty() && plan.present.is_empty() && plan.extra.is_empty() {
        println!("{file}: declares no packages, and vez has installed none.");
        return;
    }
    if !plan.install.is_empty() {
        println!("Install ({}):", plan.install.len());
        for name in &plan.install {
            println!("  {name}");
        }
    }
    if !plan.present.is_empty() {
        println!("Already present ({}):", plan.present.len());
        for name in &plan.present {
            println!("  {name}");
        }
    }
    // Reported, never a removal. Saying "extra" rather than "to remove" is the whole policy:
    // a file that can uninstall a user's software on a mis-edit is not worth the convenience.
    if !plan.extra.is_empty() {
        println!("Installed but not declared ({}):", plan.extra.len());
        for name in &plan.extra {
            println!("  {name}");
        }
        println!("  (vez never removes these — `vez remove <name>` if you mean it)");
    }
    if plan.install.is_empty() {
        println!("\nNothing to do: this machine already matches {file}.");
    } else if acting {
        println!("\nInstalling {} package(s)...", plan.install.len());
    } else {
        println!("\nRun `sudo vez apply` to install {}.", plan.install.len());
    }
}

/// Re-apply the recorded extra set so the layer matches the deployment it is layered on.
///
/// THE CASE THIS EXISTS FOR is a base image update, not a reboot. The overlay upperdir and the
/// rpmdb both live under `/var`, so a plain restart still has the whole extra layer — the user
/// confirmed that on real hardware, and it is why this command does NOT run on every boot
/// unless the deployment moved. `bootc upgrade` changes what is underneath: `/usr` becomes the
/// new deployment while the upperdir still holds files extracted over the old one, and
/// overlayfs merges them silently. Re-applying the set is what stops an installed package
/// shadowing the new base wherever the two overlap — `/usr/lib64` sonames most of all.
///
/// It re-resolves rather than reinstalling recorded versions, deliberately: a new base means
/// new candidates, and the point is a layer consistent with what is now underneath it. Packages
/// already satisfied by the new base are skipped by the resolver's own base check, which is the
/// same rule the very first install used.
///
/// `--check` is the boot-service form: it does nothing unless the generation moved, so a machine
/// that has not updated pays nothing. The four outcomes are all separate, because "nothing to
/// replay", "already current" and "replayed" are different facts and a single message would
/// hide which one happened.
async fn replay(
    cli: &Cli,
    paths: &OverlayPaths,
    check: bool,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let state_path = std::path::Path::new(vez_overlay::paths::LAYER_STATE);
    let state = vez_overlay::state::State::load(state_path);
    let deployment = vez_overlay::state::read_deployment();
    let generation = match &deployment {
        vez_overlay::state::Deployment::Generation(g) => Some(*g),
        vez_overlay::state::Deployment::Unknown => None,
    };

    let packages = vez_overlay::packages_list_names();

    // Nothing was ever installed on top of the image, so there is no layer to restore. This is
    // every machine until it first installs something, and it must be a quiet success: a boot
    // service that reported a problem here would cry wolf on a stock install.
    if packages.is_empty() {
        println!("Nothing to replay: no packages have been installed on top of the image.");
        if !dry_run {
            // Record the generation anyway, so a later upgrade is measured from this deployment
            // rather than from whenever the state file happened to be first written.
            state.record(state_path, generation)?;
        }
        return Ok(());
    }

    // THE ONLY CASE THAT SKIPS. Note it requires `Some(false)` — a *positive* statement that the
    // layer and the deployment agree — and that is the whole safety property here:
    //
    //   `lags_deployment` returns None when there is no record of the layer ever being applied
    //   (and when /usr cannot state its generation). An earlier draft of this function treated
    //   `None` as "do not replay", which is WRONG IN THE CASE THAT MATTERS: a machine that
    //   installed packages under one deployment and then upgraded has a full `packages.list`
    //   and no state file, so `None` would mean "no replay needed" on exactly the boot where a
    //   replay is most needed — leaving the old layer shadowing the new base, silently. Absence
    //   of evidence is not evidence of being current, so anything other than a positive
    //   "they agree" falls through and replays.
    if let (Some(false), true, false) = (state.lags_deployment(&deployment), check, force) {
        println!(
            "Extra layer is current: {} package(s) applied to generation {}.",
            packages.len(),
            generation
                .map(|g| g.to_string())
                .unwrap_or_else(|| "?".into())
        );
        return Ok(());
    }

    match state.lags_deployment(&deployment) {
        Some(true) => {
            println!(
                "The deployment moved: layer applied to generation {}, running generation {}. Re-applying {} package(s).",
                state.applied_generation.map(|g| g.to_string()).unwrap_or_else(|| "?".into()),
                generation.map(|g| g.to_string()).unwrap_or_else(|| "?".into()),
                packages.len()
            );
        }
        None if state.applied_generation.is_none() => {
            // The recorded case: packages exist, but nothing says the layer was ever made to
            // match this deployment. Rewriting the layer is the safe reading; the resolver
            // skips anything the base already provides, so the cost is a no-op at worst.
            println!(
                "No record of the layer being applied to this deployment; re-applying {} package(s) to be sure.",
                packages.len()
            );
        }
        None => {
            println!(
                "Cannot read the running generation from {}; re-applying {} package(s) rather than assuming the layer is current.",
                vez_overlay::state::VERSION_JSON,
                packages.len()
            );
        }
        Some(false) => {
            println!(
                "Re-applying {} package(s) on top of the image.",
                packages.len()
            );
        }
    }

    install_ex(cli, paths, &packages, dry_run, false).await?;

    if !dry_run {
        // Only after the re-apply actually succeeded. Recording first would mark the layer
        // current even when the transaction failed, and the next boot would then skip a replay
        // that is still needed — a silent, permanent drift.
        state.record(state_path, generation)?;
    }
    Ok(())
}

fn clean(cli: &Cli, what: CleanWhat) -> Result<()> {
    let mut removed = 0u64;
    if matches!(what, CleanWhat::Packages | CleanWhat::All) {
        removed += remove_rpms_recursive(&cli.cache_dir);
    }
    if matches!(what, CleanWhat::Metadata | CleanWhat::All) {
        let repos_dir = cli.cache_dir.join("repos");
        if matches!(what, CleanWhat::All) {
            // `all` means everything, packages included.
            if repos_dir.exists() {
                std::fs::remove_dir_all(&repos_dir)
                    .with_context(|| format!("removing {}", repos_dir.display()))?;
                removed += 1;
            }
        } else {
            // Metadata only. Each per-repo dir under `repos/` holds
            // `repomd.xml`/`primary.xml.zst`/`baseurl.txt`/`comps.xml`/etc.
            // directly, plus a nested `packages/` dir with downloaded RPMs
            // (see `vez_repo::repo_cache_dir`). A blanket `remove_dir_all` on
            // the whole per-repo dir would also delete `packages/` and wipe
            // anything staged there for an offline reinstall (e.g. the
            // pre-download step of a replay) when only the metadata was
            // supposed to go.
            for entry in std::fs::read_dir(&repos_dir)
                .into_iter()
                .flatten()
                .flatten()
            {
                let repo_dir = entry.path();
                if !repo_dir.is_dir() {
                    continue;
                }
                for file in std::fs::read_dir(&repo_dir).into_iter().flatten().flatten() {
                    let path = file.path();
                    if path.is_dir() {
                        continue;
                    }
                    if std::fs::remove_file(&path).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
    }
    println!("Removed {removed} cache item(s).");
    Ok(())
}

/// `vez download`: resolves like `install` but only downloads, into `destdir`
/// (`--cache-dir` by default), and never touches the rpmdb.
async fn download(
    cli: &Cli,
    paths: &OverlayPaths,
    packages: &[String],
    destdir: Option<&Path>,
    srpm: bool,
    releasever: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(!packages.is_empty(), "no packages given");
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let (
        repo_configs,
        candidates,
        _groups,
        _environments,
        _modules,
        _module_defaults,
        fallback_extra,
        advisories,
    ) = match releasever {
        Some(rv) => {
            let mut vars = detect_vars(cli);
            vars.releasever = rv.to_string();
            load_candidates_with_vars(cli, vars, cli.refresh).await?
        }
        None => load_candidates(cli).await?,
    };
    let host_arch = detect_host_arch(cli);

    let to_install = if srpm {
        // A source package has no installable Requires closure to resolve.
        // dnf5's `--srpm` (`DownloadCommand::run`, `download.cpp`) skips
        // dependency resolution entirely and looks the name up directly with
        // `arch == "src"`. Same here: pick the newest `src`-arch candidate
        // per requested name from whatever source repo the caller enabled
        // (e.g. Fedora's `rawhide-source` through `--enablerepo`).
        let mut picked = Vec::new();
        for name in packages {
            let best = candidates
                .iter()
                .filter(|p| p.nevra.name == *name && p.nevra.arch == "src")
                .max_by(|a, b| a.nevra.evr().as_str().compare_evr(&b.nevra.evr()));
            match best {
                Some(pkg) => picked.push(pkg.clone()),
                None if cli.main_conf.skip_if_unavailable => {
                    eprintln!("warning: no source package found for '{name}'");
                }
                None => anyhow::bail!("no source package \"{name}\" available; enable its source repo (e.g. --enablerepo=*-source)"),
            }
        }
        picked
    } else {
        // Unlike `install`, `download` never touches the rpmdb, so an
        // installed package shouldn't count as "already satisfied" and get
        // skipped the way it does for `install`. Someone asking to download
        // package X wants X's RPM in the cache whether or not it's installed
        // right now (e.g. a replay filling vez's package cache from the extra
        // rpmdb before rebuilding the overlay, where every one of
        // those names *is* installed). `force_names` (the same mechanism
        // `swap`'s install half uses) makes the resolver pick a real
        // candidate instead of treating the name as already met.
        let mut options = resolve_options(cli, paths);
        options.force_names.extend(packages.iter().cloned());
        let plan = vez_resolver::resolve_ex(packages, &candidates, &overlay, &host_arch, &options)
            .context("resolving dependencies")?;
        plan.to_install
    };

    if to_install.is_empty() {
        println!("Nothing to download — every requested package is already satisfied.");
        return Ok(());
    }

    let alternatives = download_alternatives(&to_install, &candidates, &fallback_extra);
    release_pools((candidates, fallback_extra, advisories, overlay));
    let per_repo = destdir.is_none();
    let dest = destdir.unwrap_or(&cli.cache_dir);
    let client = build_client(cli)?;
    // `dest` may be a `--destdir` the caller chose, separate from
    // `cli.cache_dir`. Repo metadata (and the `baseurl.txt` the same-repo
    // mirror fallback needs) was cached under `cli.cache_dir` by
    // `load_candidates` above, not under `dest`, so that's what has to be
    // passed as the metadata root.
    let downloaded = vez_transaction::download_all_ex_with_metadata_root(
        &client,
        &to_install,
        dest,
        &cli.cache_dir,
        cli.main_conf.max_parallel_downloads,
        per_repo,
        &repo_configs,
        &alternatives,
    )
    .await
    .context("downloading packages")?;
    for d in &downloaded {
        println!("{}", d.rpm_path.display());
    }
    Ok(())
}

/// `vez reposync`: downloads every candidate package from the enabled repos
/// (filtered by `--repo`/`--repoid`) to disk, in the same file layout
/// `download`/`install` use (per-repo-id subdirectories by default;
/// `download_all_ex` does the fetching and checksum work).
async fn reposync(
    cli: &Cli,
    download_path: Option<&Path>,
    newest_only: bool,
    norepopath: bool,
) -> Result<()> {
    let (repo_configs, mut candidates, _groups, _environments, ..) = load_candidates(cli).await?;
    anyhow::ensure!(!repo_configs.is_empty(), "no enabled repos found");

    if newest_only {
        use std::collections::HashMap;
        let mut best: HashMap<(String, String), usize> = HashMap::new();
        for (i, pkg) in candidates.iter().enumerate() {
            match best.get(&(pkg.nevra.name.clone(), pkg.nevra.arch.clone())) {
                Some(&j)
                    if candidates[j]
                        .nevra
                        .evr()
                        .as_str()
                        .compare_evr(&pkg.nevra.evr())
                        .is_ge() => {}
                _ => {
                    best.insert((pkg.nevra.name.clone(), pkg.nevra.arch.clone()), i);
                }
            }
        }
        let mut keep: Vec<usize> = best.into_values().collect();
        keep.sort_unstable();
        candidates = keep.into_iter().map(|i| candidates[i].clone()).collect();
    }

    let dest = download_path.unwrap_or(&cli.cache_dir);
    let client = build_client(cli)?;
    // `&[]` on purpose, not `&repo_configs`. reposync's destination is
    // usually a mirror/export directory the user picked (`--download-path`)
    // and not vez's internal package cache, so it keeps the plain
    // `<dest>/<repo_id>/packages/` layout instead of the opaque hashed dirs
    // the real cache uses (see the doc comment on `download_all_ex`).
    let downloaded = vez_transaction::download_all_ex(
        &client,
        &candidates,
        dest,
        cli.main_conf.max_parallel_downloads,
        !norepopath,
        &[],
        &[],
    )
    .await
    .context("downloading packages")?;
    for d in &downloaded {
        println!("{}", d.rpm_path.display());
    }
    println!(
        "reposync: downloaded {} package(s) to {}",
        downloaded.len(),
        dest.display()
    );
    Ok(())
}

/// `vez repomanage <path>`, like dnf-utils' `repomanage`: scans a plain
/// directory of `.rpm` *files* (not repo metadata) and reports which are
/// "old" (all but the newest `--keep` versions of each name+arch) or, with
/// `--new`, the newest `--keep` versions themselves. Header info comes from
/// `rpm -qp` on each file directly, the same "no --dbpath needed, it just
/// reads the file's header" approach `changelog` uses for installed packages.
fn repomanage(dir: &Path, new: bool, keep: u32) -> Result<()> {
    anyhow::ensure!(dir.is_dir(), "'{}' is not a directory", dir.display());

    let mut rpm_paths = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in
            std::fs::read_dir(&d).with_context(|| format!("reading directory {}", d.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rpm") {
                rpm_paths.push(path);
            }
        }
    }

    // name, epoch:version-release, arch, path, taken from each file's own
    // header with no rpmdb involved.
    struct Entry {
        name: String,
        evr: String,
        arch: String,
        path: PathBuf,
    }
    let mut entries = Vec::new();
    for path in rpm_paths {
        let out = std::process::Command::new("rpm")
            .args([
                "-qp",
                "--qf",
                "%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}\t%{ARCH}",
                "--nosignature",
            ])
            .arg(&path)
            .output()
            .with_context(|| format!("running rpm -qp on {}", path.display()))?;
        if !out.status.success() {
            eprintln!("warning: skipping {}: rpm -qp failed", path.display());
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut parts = text.trim().splitn(3, '\t');
        let (Some(name), Some(evr), Some(arch)) = (parts.next(), parts.next(), parts.next()) else {
            eprintln!(
                "warning: skipping {}: couldn't parse rpm header",
                path.display()
            );
            continue;
        };
        entries.push(Entry {
            name: name.to_string(),
            evr: evr.to_string(),
            arch: arch.to_string(),
            path,
        });
    }

    use std::collections::HashMap;
    let mut groups: HashMap<(String, String), Vec<Entry>> = HashMap::new();
    for e in entries {
        groups
            .entry((e.name.clone(), e.arch.clone()))
            .or_default()
            .push(e);
    }

    let mut selected: Vec<PathBuf> = Vec::new();
    for group in groups.values_mut() {
        group.sort_by(|a, b| b.evr.as_str().compare_evr(a.evr.as_str()));
        let keep = keep as usize;
        let (newest, older) = if group.len() > keep {
            group.split_at(keep)
        } else {
            (group.as_slice(), &group[group.len()..])
        };
        let picked = if new { newest } else { older };
        selected.extend(picked.iter().map(|e| e.path.clone()));
    }
    selected.sort();
    for p in &selected {
        println!("{}", p.display());
    }
    Ok(())
}

/// `vez repoclosure`: checks that every candidate from the enabled repos (or
/// only the subset filtered by `--pkg`) has every `Requires` satisfiable by
/// something in the full candidate pool. See [`vez_resolver::check_closure`]
/// for the check itself.
async fn repoclosure(cli: &Cli, pkg_patterns: &[String]) -> Result<()> {
    let (repo_configs, candidates, _groups, _environments, ..) = load_candidates(cli).await?;
    anyhow::ensure!(!repo_configs.is_empty(), "no enabled repos found");
    let host_arch = detect_host_arch(cli);
    let unresolved = vez_resolver::check_closure(&candidates, pkg_patterns, &host_arch);
    if unresolved.is_empty() {
        println!("repoclosure: no unresolved dependencies found");
        return Ok(());
    }
    for (nevra, missing) in &unresolved {
        println!("package: {nevra}");
        for m in missing {
            println!("  unresolved deps:");
            println!("    {m}");
        }
    }
    anyhow::bail!(
        "repoclosure found {} package(s) with unresolved dependencies",
        unresolved.len()
    );
}

/// `vez changelog <name>...`: `rpm -q --changelog` against whichever dbpath
/// (base or overlay) has the package installed. Installed packages only, like
/// dnf's `changelog` without `--upgrades`.
fn changelog(paths: &OverlayPaths, packages: &[String]) -> Result<()> {
    let dbpaths: Vec<Option<&Path>> = match &paths.mode {
        vez_overlay::OverlayMode::Split {
            base_rpmdb,
            overlay_rpmdb,
        } => vec![Some(base_rpmdb.as_path()), Some(overlay_rpmdb.as_path())],
        vez_overlay::OverlayMode::Standalone => vec![None],
    };
    for name in packages {
        let mut found = false;
        for dbpath in &dbpaths {
            let mut cmd = std::process::Command::new("rpm");
            if let Some(p) = dbpath {
                cmd.arg("--dbpath").arg(p);
            }
            let output = cmd
                .arg("-q")
                .arg("--changelog")
                .arg(name)
                .output()
                .context("spawning rpm -q --changelog")?;
            if output.status.success() {
                found = true;
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
        }
        if !found {
            println!("{name}: not installed");
        }
    }
    Ok(())
}

/// `vez needs-restarting`: scans every readable `/proc/<pid>/maps` for a
/// mapped file whose entry ends in `(deleted)` (the kernel's marker for "this
/// mapped file no longer exists at that path", nearly always because a
/// package update replaced it under a running process) and reports the
/// affected PIDs. It doesn't try dnf's fuller "which systemd unit owns this
/// and should be restarted" classification, which needs a live systemd/D-Bus
/// connection vez has no other reason to depend on.
fn needs_restarting() -> Result<()> {
    let mut any = false;
    for entry in std::fs::read_dir("/proc")
        .context("reading /proc")?
        .flatten()
    {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let maps_path = entry.path().join("maps");
        let Ok(maps) = std::fs::read_to_string(&maps_path) else {
            continue;
        };
        let deleted: Vec<&str> = maps
            .lines()
            .filter(|l| l.ends_with("(deleted)"))
            .filter_map(|l| l.split_whitespace().last())
            .collect();
        if !deleted.is_empty() {
            any = true;
            let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            println!("{pid} : {}", comm.trim());
            for d in deleted {
                println!("    {d}");
            }
        }
    }
    if !any {
        println!("No processes need restarting.");
    }
    Ok(())
}

/// Which rpmdb(s) `check` looks at; see the `--base`/`--overlay` flags of
/// `Command::Check`. Only meaningful in Split mode. Standalone mode always
/// uses `All`, since it has no base/overlay split.
#[derive(Clone, Copy)]
enum CheckScope {
    All,
    Base,
    Overlay,
}

fn check(
    paths: &OverlayPaths,
    installonlypkgs: &[String],
    dependencies: bool,
    duplicates: bool,
    obsoleted: bool,
    scope: CheckScope,
) -> Result<()> {
    let overlay = OverlayContext::load(paths).context("loading overlay context")?;
    let all: Vec<&Package> = match (&overlay.mode, &scope) {
        (OverlayMode::Split { .. }, CheckScope::Base) => overlay.base.iter().collect(),
        (OverlayMode::Split { .. }, CheckScope::Overlay) => overlay.overlay.iter().collect(),
        _ => overlay.base.iter().chain(&overlay.overlay).collect(),
    };
    // `--base`/`--overlay` also narrow what counts as satisfied. A base
    // package's require met only by an overlay package (or the other way
    // round) should show up as missing when checking that side alone.
    // Otherwise a Split-mode `--base` check would still pass using deps that
    // `satisfied()` finds on the overlay side.
    let is_satisfied = |req: &Dependency, arch: Option<&str>| match scope {
        CheckScope::Base => overlay.satisfied_by_base(req, arch),
        CheckScope::Overlay => overlay.overlay_satisfied(req, arch),
        CheckScope::All => overlay.satisfied(req, arch),
    };

    let mut problems = 0;

    if dependencies {
        for pkg in &all {
            for req in &pkg.requires {
                if req.name.starts_with("rpmlib(") {
                    continue;
                }
                if !is_satisfied(req, Some(pkg.nevra.arch.as_str())) {
                    problems += 1;
                    println!("{}: missing require \"{}\"", pkg.nevra, req.name);
                }
            }
            for conflict in &pkg.conflicts {
                for other in &all {
                    if std::ptr::eq(*pkg, *other) || other.nevra.name == pkg.nevra.name {
                        continue;
                    }
                    if conflict.name == other.nevra.name
                        || other.provides.iter().any(|p| {
                            p.name == conflict.name && conflict.satisfied_by_evr(&other.nevra.evr())
                        })
                    {
                        problems += 1;
                        println!(
                            "{}: installed conflict \"{}\" from \"{}\"",
                            pkg.nevra, conflict.name, other.nevra
                        );
                    }
                }
            }
        }
    }

    if obsoleted {
        for pkg in &all {
            for other in &all {
                if std::ptr::eq(*pkg, *other) || other.nevra.name == pkg.nevra.name {
                    continue;
                }
                let hit = other.obsoletes.iter().any(|ob| {
                    ob.name == pkg.nevra.name
                        || pkg
                            .provides
                            .iter()
                            .any(|p| p.name == ob.name && ob.satisfied_by_evr(&pkg.nevra.evr()))
                });
                if hit {
                    problems += 1;
                    println!(
                        "{}: obsoleted by \"{}\" from \"{}\"",
                        pkg.nevra, other.nevra, other.repo_id
                    );
                }
            }
        }
    }

    if duplicates {
        let mut by_name_arch: std::collections::BTreeMap<(&str, &str), Vec<&Package>> =
            std::collections::BTreeMap::new();
        for pkg in &all {
            by_name_arch
                .entry((pkg.nevra.name.as_str(), pkg.nevra.arch.as_str()))
                .or_default()
                .push(pkg);
        }
        for ((name, _arch), pkgs) in &by_name_arch {
            if pkgs.len() < 2 || vez_core::name_matches_any(name, installonlypkgs) {
                continue;
            }
            for pkg in pkgs {
                problems += 1;
                println!("{}: duplicate with \"{}\"", pkg.nevra, name);
            }
        }
    }

    if problems == 0 {
        println!("No problems found.");
    } else {
        anyhow::bail!("{problems} problem(s) found");
    }
    Ok(())
}

/// `[commands]`/`[emitters]` from `automatic.conf`, mirroring dnf5's
/// `ConfigAutomaticCommands`/`ConfigAutomaticEmitters`. Only `stdio`/`motd`
/// emitters exist; email/D-Bus/command emitters and the
/// `[email]`/`[command]`/`[command_email]` sections aren't implemented.
/// They'd need MTA/D-Bus plumbing this codebase has no other use for, which
/// is out of proportion to what a Svara system (it has its own update
/// notifications) needs from this command.
struct AutomaticConfig {
    upgrade_type: String,
    random_sleep: u32,
    network_online_timeout: i32,
    download_updates: bool,
    apply_updates: bool,
    reboot: String,
    reboot_command: String,
    emit_via: Vec<String>,
    emit_no_updates: bool,
}

impl Default for AutomaticConfig {
    fn default() -> Self {
        Self {
            upgrade_type: "default".to_string(),
            random_sleep: 0,
            network_online_timeout: 60,
            download_updates: true,
            apply_updates: false,
            reboot: "never".to_string(),
            reboot_command: "shutdown -r +5 'Rebooting after applying package updates'".to_string(),
            emit_via: vec!["stdio".to_string()],
            emit_no_updates: false,
        }
    }
}

/// Reads `automatic.conf` from dnf5's search path (`/usr` overridden by
/// `/etc/dnf`) plus a Svara-specific `/etc/vez/automatic.conf` on top, read
/// last so it wins on any key collision. That's the same "later file wins per
/// key" layering `pre_configure()` uses in dnf5's `automatic_plugin`, without
/// the installroot/host-config indirection vez doesn't need here.
fn load_automatic_config() -> AutomaticConfig {
    let mut cfg = AutomaticConfig::default();
    for path in [
        "/usr/share/dnf5/dnf5-plugins/automatic.conf",
        "/etc/dnf/dnf5-plugins/automatic.conf",
        "/etc/dnf/automatic.conf",
        "/etc/vez/automatic.conf",
    ] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let mut section = String::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = name.trim().to_string();
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                continue;
            };
            let (key, val) = (key.trim(), val.trim());
            match (section.as_str(), key) {
                ("commands", "upgrade_type") => cfg.upgrade_type = val.to_string(),
                ("commands", "random_sleep") => {
                    cfg.random_sleep = val.parse().unwrap_or(cfg.random_sleep)
                }
                ("commands", "network_online_timeout") => {
                    cfg.network_online_timeout = val.parse().unwrap_or(cfg.network_online_timeout)
                }
                ("commands", "download_updates") => {
                    cfg.download_updates = val.eq_ignore_ascii_case("yes")
                        || val == "1"
                        || val.eq_ignore_ascii_case("true")
                }
                ("commands", "apply_updates") => {
                    cfg.apply_updates = val.eq_ignore_ascii_case("yes")
                        || val == "1"
                        || val.eq_ignore_ascii_case("true")
                }
                ("commands", "reboot") => cfg.reboot = val.to_string(),
                ("commands", "reboot_command") => cfg.reboot_command = val.to_string(),
                ("emitters", "emit_via") => {
                    cfg.emit_via = val
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }
                ("emitters", "emit_no_updates") => {
                    cfg.emit_no_updates = val.eq_ignore_ascii_case("yes")
                        || val == "1"
                        || val.eq_ignore_ascii_case("true")
                }
                _ => {}
            }
        }
    }
    cfg
}

struct AutomaticOverrides {
    timer: bool,
    download_updates: Option<bool>,
    apply_updates: Option<bool>,
}

/// Best-effort equivalent of dnf5's `wait_for_network`: tries a plain TCP
/// connect to each enabled repo's host (baseurl/mirrorlist/metalink, in that
/// order) once a second until `timeout` elapses or one succeeds. `timeout <=
/// 0` skips the check entirely, same as dnf5.
fn wait_for_network(repo_configs: &[RepoConfig], timeout: i32) {
    if timeout <= 0 {
        return;
    }
    let hosts: Vec<(String, u16)> = repo_configs
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| {
            r.base_url
                .as_deref()
                .or(r.mirrorlist.as_deref())
                .or(r.metalink.as_deref())
        })
        .filter_map(|u| reqwest::Url::parse(u).ok())
        .filter_map(|u| {
            Some((
                u.host_str()?.to_string(),
                u.port_or_known_default().unwrap_or(443),
            ))
        })
        .collect();
    if hosts.is_empty() {
        return;
    }
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(timeout.max(0) as u64);
    loop {
        for (host, port) in &hosts {
            if let Ok(mut addrs) = (host.as_str(), *port).to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if std::net::TcpStream::connect_timeout(
                        &addr,
                        std::time::Duration::from_secs(1),
                    )
                    .is_ok()
                    {
                        return;
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            eprintln!(
                "warning: no network connection detected after {timeout}s, proceeding anyway"
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// dnf-automatic/dnf5-automatic equivalent: resolve an upgrade without
/// prompting, optionally download it, optionally apply it, all driven by
/// `automatic.conf` instead of CLI flags (see the doc comment on
/// `Command::Automatic`). Meant to run from a periodic timer, not
/// interactively.
async fn automatic(
    cli: &mut Cli,
    paths: &OverlayPaths,
    overrides: AutomaticOverrides,
) -> Result<()> {
    let mut config = load_automatic_config();
    if let Some(v) = overrides.download_updates {
        config.download_updates = v;
    }
    if let Some(v) = overrides.apply_updates {
        config.apply_updates = v;
    }

    if overrides.timer && config.random_sleep > 0 {
        // No `rand` crate for one call site. A rough jitter from the
        // nanosecond clock is enough for what this is for (spreading timer
        // load across mirrors); it doesn't need to be cryptographically
        // unpredictable.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let delay = nanos % (config.random_sleep + 1);
        std::thread::sleep(std::time::Duration::from_secs(delay as u64));
    }

    let vars = detect_vars(cli);
    let repo_configs = vez_repo::load_repo_configs(&cli.repo_dir, &vars)
        .with_context(|| format!("loading repo configs from {}", cli.repo_dir.display()))?;
    wait_for_network(&repo_configs, config.network_online_timeout);

    // Non-interactive by design: a timer or cron job has no terminal to
    // prompt on, and `download_updates`/`apply_updates` already control
    // everything this command does.
    cli.assume_yes = true;
    cli.downloadonly = !config.apply_updates;

    let ran = if config.download_updates || config.apply_updates {
        let result = match config.upgrade_type.as_str() {
            "distro-sync" => sync_packages(cli, paths, &[], false, SyncMode::DistroSync).await,
            "security" => {
                let filter = AdvisoryUpgradeFilter {
                    ids: &[],
                    security: true,
                    bugfix: false,
                    enhancement: false,
                    severity: None,
                };
                upgrade(cli, paths, &[], false, &filter).await
            }
            _ => {
                let filter = AdvisoryUpgradeFilter {
                    ids: &[],
                    security: false,
                    bugfix: false,
                    enhancement: false,
                    severity: None,
                };
                upgrade(cli, paths, &[], false, &filter).await
            }
        };
        if let Err(e) = &result {
            eprintln!("Transaction failed: {e:#}");
        }
        Some(result)
    } else {
        None
    };
    let success = !matches!(ran, Some(Err(_)));

    if config.emit_no_updates || !success || ran.is_some() {
        for emitter in &config.emit_via {
            match emitter.as_str() {
                "stdio" => { /* upgrade()/sync_packages() above already printed the transaction to stdout, so there's nothing extra to emit. */ }
                "motd" => {
                    let msg = if success { "vez automatic: transaction applied successfully.\n" } else { "vez automatic: transaction failed — see logs.\n" };
                    let _ = std::fs::write("/etc/motd", msg);
                }
                other => eprintln!("warning: unknown automatic.conf emit_via emitter \"{other}\" (only stdio/motd are implemented)"),
            }
        }
    }

    if !success {
        anyhow::bail!("automatic transaction failed");
    }

    if config.apply_updates && ran.is_some() && config.reboot != "never" {
        // `when-needed` would normally only reboot if a "reboot suggested"
        // package (kernel etc.) was in the transaction. vez doesn't track
        // that classification, so it behaves like `when-changed` (reboot
        // after any applied transaction) instead of never rebooting.
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&config.reboot_command)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => anyhow::bail!("reboot command exited with status {s}"),
            Err(e) => anyhow::bail!("failed to run reboot command: {e}"),
        }
    }

    Ok(())
}

fn repo_list(cli: &Cli, all: bool) -> Result<()> {
    let vars = detect_vars(cli);
    let configs = vez_repo::load_repo_configs(&cli.repo_dir, &vars)
        .with_context(|| format!("loading repo configs from {}", cli.repo_dir.display()))?;
    for cfg in &configs {
        if cfg.enabled || all {
            println!(
                "{:<20} {}",
                cfg.id,
                if cfg.enabled { "enabled" } else { "disabled" }
            );
        }
    }
    Ok(())
}

fn repo_info(cli: &Cli, id: &str) -> Result<()> {
    let vars = detect_vars(cli);
    let configs = vez_repo::load_repo_configs(&cli.repo_dir, &vars)
        .with_context(|| format!("loading repo configs from {}", cli.repo_dir.display()))?;
    let cfg = configs
        .iter()
        .find(|c| c.id == id)
        .with_context(|| format!("no repo '{id}' found"))?;
    println!("Id           : {}", cfg.id);
    println!("Enabled      : {}", cfg.enabled);
    println!("Base URL     : {}", cfg.base_url.as_deref().unwrap_or("-"));
    println!(
        "Mirrorlist   : {}",
        cfg.mirrorlist.as_deref().unwrap_or("-")
    );
    println!("Metalink     : {}", cfg.metalink.as_deref().unwrap_or("-"));
    println!("GPG check    : {}", cfg.gpgcheck);
    println!("Metadata exp.: {}s", cfg.metadata_expire);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{self_upgrade_target, split_local_rpm_args};
    use std::path::Path;
    use vez_core::{Nevra, Package};
    use vez_overlay::OverlayContext;

    fn pkg(name: &str, evr: &str, arch: &str) -> Package {
        let (version, release) = match evr.split_once('-') {
            Some((v, r)) => (v.to_string(), r.to_string()),
            None => (evr.to_string(), "1".to_string()),
        };
        Package {
            nevra: Nevra {
                name: name.to_string(),
                epoch: 0,
                version,
                release,
                arch: arch.to_string(),
            },
            summary: String::new(),
            provides: vec![],
            requires: vec![],
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

    #[test]
    fn local_rpm_args_accept_absolute_relative_and_bare_paths() {
        // cargo runs tests from the crate dir, so work under a scratch dir
        // there so relative paths resolve without changing the process cwd.
        let dir = Path::new("target-test-local-rpm-args");
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/foo-1.0-1.x86_64.rpm"), b"").unwrap();
        let cwd = std::env::current_dir().unwrap();
        let abs = cwd.join(dir).join("sub/foo-1.0-1.x86_64.rpm");
        let expected = std::fs::canonicalize(&abs)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        let args: Vec<String> = vec![
            abs.to_string_lossy().into_owned(), // absolute
            "./target-test-local-rpm-args/sub/foo-1.0-1.x86_64.rpm".into(), // ./relative
            "target-test-local-rpm-args/sub/../sub/foo-1.0-1.x86_64.rpm".into(), // relative with ..
            "htop".into(),                      // package name
            "missing-1.0-1.x86_64.rpm".into(),  // .rpm-looking name, no such file
        ];
        let (files, names) = split_local_rpm_args(&args);
        std::fs::remove_dir_all(dir).unwrap();

        assert_eq!(files, vec![expected.clone(), expected.clone(), expected]);
        assert!(files.iter().all(|f| Path::new(f).is_absolute()));
        assert_eq!(
            names,
            vec!["htop".to_string(), "missing-1.0-1.x86_64.rpm".to_string()]
        );
    }

    #[test]
    fn self_upgrade_target_picks_a_strictly_newer_candidate() {
        let candidates = vec![
            pkg("vez", "0.1.1-1", "x86_64"),
            pkg("vez", "0.1.2-1", "x86_64"),
        ];
        let overlay = OverlayContext::for_test(vec![pkg("vez", "0.1.0-1", "x86_64")], vec![]);
        let picked =
            self_upgrade_target("vez", &candidates, &overlay, &[], "x86_64").expect("a target");
        assert_eq!(picked.nevra.version, "0.1.2");
    }

    #[test]
    fn self_upgrade_target_is_none_when_nothing_is_newer() {
        let candidates = vec![pkg("vez", "0.1.0-1", "x86_64")];
        let overlay = OverlayContext::for_test(vec![pkg("vez", "0.1.0-1", "x86_64")], vec![]);
        assert!(self_upgrade_target("vez", &candidates, &overlay, &[], "x86_64").is_none());
    }

    #[test]
    fn self_upgrade_target_respects_versionlock() {
        let candidates = vec![pkg("vez", "0.1.1-1", "x86_64")];
        let overlay = OverlayContext::for_test(vec![pkg("vez", "0.1.0-1", "x86_64")], vec![]);
        let locked = vec!["vez".to_string()];
        assert!(self_upgrade_target("vez", &candidates, &overlay, &locked, "x86_64").is_none());
    }

    #[test]
    fn self_upgrade_target_ignores_a_foreign_arch_build() {
        // A candidate that isn't the host arch and isn't noarch is not a
        // usable self-upgrade target.
        let candidates = vec![pkg("vez", "0.1.1-1", "i686")];
        let overlay = OverlayContext::for_test(vec![pkg("vez", "0.1.0-1", "x86_64")], vec![]);
        assert!(self_upgrade_target("vez", &candidates, &overlay, &[], "x86_64").is_none());

        // ...but a noarch build is.
        let candidates = vec![pkg("vez", "0.1.1-1", "noarch")];
        assert!(self_upgrade_target("vez", &candidates, &overlay, &[], "x86_64").is_some());
    }

    #[test]
    fn self_upgrade_target_is_none_when_not_installed() {
        let candidates = vec![pkg("vez", "0.1.1-1", "x86_64")];
        let overlay = OverlayContext::for_test(vec![], vec![]);
        assert!(self_upgrade_target("vez", &candidates, &overlay, &[], "x86_64").is_none());
    }

    #[test]
    fn self_upgrade_target_compares_against_an_overlay_copy_too() {
        // Once vez has been layered, the overlay copy is the baseline, so a
        // candidate must beat it, not the older base copy.
        let candidates = vec![pkg("vez", "0.1.2-1", "x86_64")];
        let overlay = OverlayContext::for_test(
            vec![pkg("vez", "0.1.0-1", "x86_64")],
            vec![pkg("vez", "0.1.1-1", "x86_64")],
        );
        let picked =
            self_upgrade_target("vez", &candidates, &overlay, &[], "x86_64").expect("a target");
        assert_eq!(picked.nevra.version, "0.1.2");

        // And a candidate equal to the overlay copy is not an upgrade.
        let candidates = vec![pkg("vez", "0.1.1-1", "x86_64")];
        assert!(self_upgrade_target("vez", &candidates, &overlay, &[], "x86_64").is_none());
    }
}
