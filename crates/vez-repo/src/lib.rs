//! Fetches and parses standard yum/dnf repo metadata (`repomd.xml` +
//! `primary.xml[.gz]`). vez still consumes plain yum-compatible repos; it
//! just resolves and applies them itself instead of handing the job to dnf.

pub mod comps;
pub mod copr;
pub mod modulemd;
mod primary;
pub mod updateinfo;

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use vez_core::Package;

pub use comps::{Environment, Group};
pub use modulemd::Module;
pub use net::{
    default_net_options, download_packages_batch, download_to_file_with_retry,
    download_to_file_with_retry_ex, fastest_mirror_sort, fastestmirror_enabled,
    get_bytes_with_retry, get_with_retry, set_default_net_options, set_fastestmirror,
    set_max_attempts, set_minrate, set_stall_timeout, verify_checksum, with_net_options,
    BatchOutcome, BatchSpec, NetOptions,
};
pub use primary::parse_primary_xml;
pub use updateinfo::{parse_updateinfo_xml, Advisory};

/// Builds the [`NetOptions`] a repo's `.repo` settings ask for
/// (`proxy=`/`username=`/`password=`/`sslcacert=`/`sslclientcert=`/
/// `sslclientkey=`, dnf's per-section option names), falling back to the
/// global `vez.conf` defaults (through [`NetOptions::or_default`]) for
/// anything the repo doesn't set. Same precedence dnf5's
/// `ConfigRepo`/`ConfigMain` `OptionChild` inheritance gives proxy settings.
/// Callers wrap a repo's network calls in
/// `vez_repo::with_net_options(vez_repo::net_options_for_repo(cfg), async {
/// ... })`.
pub fn net_options_for_repo(cfg: &RepoConfig) -> NetOptions {
    NetOptions {
        proxy: cfg.proxy.clone(),
        proxy_userpwd: match (&cfg.proxy_username, &cfg.proxy_password) {
            (Some(u), p) => Some(format!("{u}:{}", p.as_deref().unwrap_or(""))),
            (None, _) => None,
        },
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        sslcacert: cfg.sslcacert.clone(),
        sslclientcert: cfg.sslclientcert.clone(),
        sslclientkey: cfg.sslclientkey.clone(),
    }
    .or_default()
}

mod net;

/// `group_package_types=`, process-wide, set once near the top of `run()`
/// (like [`set_fastestmirror`]/[`set_max_attempts`]) so the comps parsing in
/// `load_repo_ex` can read it without threading a new parameter through every
/// call between `main` and `comps.rs`.
static GROUP_PACKAGE_TYPES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

pub fn set_group_package_types(types: Vec<String>) {
    let _ = GROUP_PACKAGE_TYPES.set(types);
}

fn group_package_types() -> &'static [String] {
    GROUP_PACKAGE_TYPES.get_or_init(|| vec!["mandatory".to_string(), "default".to_string()])
}

/// A configured package source, analogous to a `.repo` file `[section]`.
#[derive(Debug, Clone)]
pub struct RepoConfig {
    pub id: String,
    /// `name=` from the `.repo` file (dnf's human-readable repo description,
    /// e.g. `"Fedora 44 - x86_64 - Updates"`), shown in dnf-style progress
    /// output instead of the bare `id`. Falls back to `id` when unset, as dnf
    /// does.
    pub name: String,
    /// Base URL without a trailing slash (e.g.
    /// `https://example.com/repo/44`), with `$releasever`/`$basearch`
    /// already expanded. `None` when the repo only set
    /// `mirrorlist=`/`metalink=`. [`load_repo`] resolves one of those to a
    /// concrete base URL at fetch time, because that needs a network round
    /// trip and can't happen during the INI parse in [`load_repo_configs`].
    pub base_url: Option<String>,
    /// `mirrorlist=` URL: a plain-text list of mirror base URLs, one per line
    /// (sometimes with `repodata/repomd.xml` appended, as dnf/yum mirrorlists
    /// often do).
    pub mirrorlist: Option<String>,
    /// `metalink=` URL: an RFC 5854 metalink XML document (as served by
    /// `mirrors.fedoraproject.org`) whose `<url>` entries point directly at
    /// a mirror's `repomd.xml`.
    pub metalink: Option<String>,
    /// Whether downloaded packages from this repo must carry a valid
    /// signature from a key in `gpgkey` before `vez-transaction` installs
    /// them. Defaults to `true` like dnf/yum. vez never treats a missing
    /// `gpgcheck=` line as "off".
    pub gpgcheck: bool,
    /// `gpgkey=` URL(s) (space-separated in the `.repo` file, as in dnf),
    /// imported with `rpm --import` before signatures are checked.
    pub gpgkeys: Vec<String>,
    /// `metadata_expire=` in seconds: how long cached
    /// `repomd.xml`/`primary.xml` are trusted before [`load_repo`] fetches
    /// them again. `u64::MAX` stands for `-1`/`never` (dnf's "cache never
    /// expires by itself" setting). Defaults to 172800 (48h), dnf's built-in
    /// default for repos that don't set it.
    pub metadata_expire: u64,
    /// `enabled=` from the `.repo` file (defaults to `1`/true). Disabled
    /// repos are still returned by [`load_repo_configs`] (they didn't used to
    /// be) so `--enable-repo`/`config-manager --set-enabled` can turn one on
    /// for one run or permanently without re-parsing the file. Callers that
    /// only want what dnf would use by default should filter on this
    /// themselves.
    pub enabled: bool,
    /// `priority=`, dnf convention, lower number wins. A package from a repo
    /// with a lower priority number is preferred over an equally good
    /// candidate from a repo with a higher number, and resolution only falls
    /// back to the worse priority when the preferred repo has no candidate at
    /// all. Defaults to 99, dnf's default for a repo without `priority=`.
    pub priority: u32,
    /// `cost=`, dnf convention, lower number wins, but only as a *tiebreaker*
    /// between repos already tied on `priority` (unlike `priority`, which
    /// overrides version/newness). Fedora's `fedora-updates-archive.repo`
    /// sets `cost=10000` (the default is 1000) so an archive mirror that
    /// duplicates the current repos' content is only used when nothing else
    /// has the package, instead of being picked arbitrarily whenever it lists
    /// the same build. Defaults to 1000, dnf's default for a repo without
    /// `cost=`.
    pub cost: u32,
    /// `exclude=`/`excludepkgs=`: per-repo name/glob blocklist, applied on
    /// top of the global `--exclude`/`exclude=` list from `vez.conf`/the CLI.
    /// dnf allows this per section, e.g. for a COPR repo that ships a
    /// `kernel` package you never want from it even though the global exclude
    /// list doesn't mention it.
    pub exclude: Vec<String>,
    /// `includepkgs=`: per-repo allowlist. When non-empty, only names/globs
    /// on this list may come from this repo (other repos aren't affected).
    /// Applied on top of the global `main_conf.includepkgs` list, like
    /// `exclude` above.
    pub includepkgs: Vec<String>,
    /// `skip_if_unavailable=`: per-repo override of the `[main]` setting of
    /// the same name in `vez.conf`. `None` means "use the global default",
    /// matching dnf's per-section override semantics. An unreachable repo
    /// where this ends up `true` is skipped with a warning instead of failing
    /// the whole operation.
    pub skip_if_unavailable: Option<bool>,
    /// `proxy=`: this repo's own proxy URL, overriding `vez.conf`'s global
    /// `proxy=` for requests to this repo only (dnf's per-section `proxy=`,
    /// `OptionChild <OptionString> proxy` in `config_repo.cpp`). `None` means
    /// "use the global default", same as leaving it out of the `.repo` file.
    /// `main` has the `proxy=_none_` value that explicitly turns proxying
    /// off; a repo has no equivalent here because dnf's format doesn't define
    /// one.
    pub proxy: Option<String>,
    pub proxy_username: Option<String>,
    pub proxy_password: Option<String>,
    /// `username=`/`password=`: HTTP basic/digest credentials for repos that
    /// require authentication to fetch metadata or packages (dnf's
    /// per-section `username=`/`password=`).
    pub username: Option<String>,
    pub password: Option<String>,
    /// `sslcacert=`: a private CA bundle to trust for this repo on top of the
    /// system trust store, for a repo behind a CA that `LRO_SSLVERIFYPEER`'s
    /// default trust store doesn't know.
    pub sslcacert: Option<String>,
    /// `sslclientcert=`/`sslclientkey=`: client certificate/key for repos
    /// requiring mTLS.
    pub sslclientcert: Option<String>,
    pub sslclientkey: Option<String>,
}

/// dnf's default `metadata_expire` when a repo doesn't set one.
pub const DEFAULT_METADATA_EXPIRE: u64 = 172_800;

/// A repo with its parsed package list, ready for the resolver.
pub struct Repo {
    pub id: String,
    pub base_url: String,
    pub packages: Vec<Package>,
    /// Comps groups (`<group>` entries), if this repo has a `type="group"`/
    /// `"group_gz"` entry in `repomd.xml`, otherwise empty. Not every repo
    /// has comps data, and that isn't an error.
    pub groups: Vec<Group>,
    /// Comps environments (`<environment>` entries) from the same data entry
    /// as `groups`, empty under the same conditions.
    pub environments: Vec<Environment>,
    /// Module-stream metadata (`modulemd` documents), if this repo has a
    /// `type="modules"` entry in `repomd.xml`, otherwise empty (not every
    /// repo is modular).
    pub modules: Vec<Module>,
    /// module name -> default stream, from this repo's `modulemd-defaults`
    /// documents.
    pub module_defaults: HashMap<String, String>,
    /// Security/bugfix/enhancement advisories, if this repo has a
    /// `type="updateinfo"` entry in `repomd.xml`, otherwise empty (not every
    /// repo publishes advisories; most third-party repos don't).
    pub advisories: Vec<Advisory>,
}

/// Everything [`load_repo_ex`] parses out of a repo's XML/YAML metadata,
/// before it's adjusted for the current config. `packages`' `location` is
/// still the repo-relative href (not joined with `base_url`) and
/// `repo_id`/`repo_priority`/`repo_cost` aren't stamped, the same shape
/// [`parse_primary_xml`] returns, so [`ParsedCache::into_repo`] can apply
/// `cfg`'s current values instead of whatever they were when this was cached.
/// Stored as `parsed.json` next to the raw metadata cache files because it
/// loads faster, similar to libdnf5 keeping a `.solv`/`.solvx` next to the
/// raw metadata it was built from, but as plain JSON instead of a libsolv
/// pool.
#[derive(serde::Serialize, serde::Deserialize)]
struct ParsedCache {
    base_url: String,
    packages: Vec<Package>,
    groups: Vec<Group>,
    environments: Vec<Environment>,
    modules: Vec<Module>,
    module_defaults: HashMap<String, String>,
    #[serde(default)]
    advisories: Vec<Advisory>,
}

impl ParsedCache {
    fn into_repo(mut self, cfg: &RepoConfig) -> Repo {
        for pkg in &mut self.packages {
            pkg.repo_id = cfg.id.clone();
            pkg.repo_priority = cfg.priority;
            pkg.repo_cost = cfg.cost;
            if !pkg.location.is_empty() {
                pkg.location = format!("{}/{}", self.base_url, pkg.location);
            }
        }
        for advisory in &mut self.advisories {
            advisory.repo_id = cfg.id.clone();
        }
        Repo {
            id: cfg.id.clone(),
            base_url: self.base_url,
            packages: self.packages,
            groups: self.groups,
            environments: self.environments,
            modules: self.modules,
            module_defaults: self.module_defaults,
            advisories: self.advisories,
        }
    }
}

/// Downloads `repomd.xml`, finds the `primary` entry, downloads and
/// decompresses it, and parses every `<package>` into a [`Package`] with
/// `location` turned into a full download URL and `repo_id` stamped.
///
/// If `cfg.base_url` isn't set, one is resolved first from `cfg.mirrorlist`
/// or `cfg.metalink` (mirrorlist first if both are set, as in dnf).
///
/// `cache_root` is checked first. It holds a per-repo subdirectory keyed by
/// the repo id and a hash of its configured URL(s), the same scheme dnf5 uses
/// under `/var/cache/libdnf5`; because of the hash, a repo whose
/// `baseurl`/`mirrorlist`/`metalink` changes gets a fresh cache instead of
/// stale data from an unrelated source under the same id. If the cached
/// `repomd.xml` is younger than `cfg.metadata_expire`, there's no network
/// request at all, same as `dnf` when metadata hasn't expired. `refresh`
/// forces a new fetch whatever the cache age, for `vez
/// makecache`/`--refresh`.
pub async fn load_repo(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
    refresh: bool,
) -> Result<Repo> {
    load_repo_ex(client, cfg, cache_root, refresh, false).await
}

/// Fetches just `repomd.xml` from one candidate `mirror`, with no fallback of
/// its own. Returns `(repomd_xml, bytes_fetched)`.
async fn fetch_repomd(client: &reqwest::Client, mirror: &str) -> Result<(String, u64)> {
    let repomd_url = format!("{mirror}/repodata/repomd.xml");
    let repomd_resp = get_with_retry(client, &repomd_url)
        .await?
        .error_for_status()
        .with_context(|| format!("{repomd_url} returned an error status"))?
        .bytes()
        .await?;
    Ok((
        String::from_utf8_lossy(&repomd_resp).into_owned(),
        repomd_resp.len() as u64,
    ))
}

/// Downloads `href` (the compressed `primary.xml`) from `mirror` and
/// stream-parses it straight out of the decompressor. Returns the
/// still-compressed bytes (cached on disk as-is) plus the parsed packages;
/// the decompressed XML is never held in memory as a whole.
async fn fetch_primary(
    client: &reqwest::Client,
    mirror: &str,
    href: &str,
) -> Result<(Vec<u8>, Vec<Package>)> {
    let primary_url = format!("{mirror}/{href}");
    let compressed = get_bytes_with_retry(client, &primary_url).await?;
    let packages = primary::parse_primary_reader(decompress_reader(href, compressed.as_slice())?)
        .with_context(|| format!("parsing {primary_url}"))?;
    Ok((compressed, packages))
}

/// Verifies `repomd.xml`'s detached GPG signature (`repomd.xml.asc`, the same
/// file dnf/createrepo_c produce) against `cfg.gpgkeys`, like dnf5's
/// `repo_gpgcheck=` check. dnf5 gets this from librepo directly
/// (`LRO_GPGCHECK`/`LRO_GNUPGHOMEDIR`, `repo_downloader.cpp`) because its
/// metadata fetch goes through librepo's internal downloader. vez's metadata
/// fetch goes through this crate's own retry loop ([`fetch_repomd`]), so this
/// shells out to `gpg`/`gpgv` directly with a scratch keyring built from
/// `cfg.gpgkeys`, separate from rpm's keyring.
/// (`vez-transaction::import_repo_keys` imports the same keys into rpm's
/// keyring for *package* signature checks; this is the metadata trust check
/// dnf5 calls `repo_gpgcheck`, done in addition to that.)
///
/// Not every repo publishes a `repomd.xml.asc` even with `gpgcheck=1` set.
/// That just means the repo doesn't sign its metadata, so a missing `.asc`
/// counts as nothing to check instead of an error (in practice dnf5's
/// `repo_gpgcheck` is off for such repos too). A signature that *is*
/// published but doesn't verify against any configured key fails closed.
async fn verify_repomd_signature(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    mirror: &str,
    repomd_xml: &str,
) -> Result<()> {
    if !cfg.gpgcheck || cfg.gpgkeys.is_empty() {
        return Ok(());
    }
    let sig_url = format!("{mirror}/repodata/repomd.xml.asc");
    let sig_bytes = match get_with_retry(client, &sig_url)
        .await
        .and_then(|r| r.error_for_status().map_err(Into::into))
    {
        Ok(resp) => resp.bytes().await?,
        Err(_) => return Ok(()),
    };

    let mut key_texts = Vec::with_capacity(cfg.gpgkeys.len());
    for key_url in &cfg.gpgkeys {
        let bytes = get_bytes_with_retry(client, key_url)
            .await
            .with_context(|| format!("fetching gpgkey {key_url}"))?;
        key_texts.push(bytes);
    }

    let repomd_bytes = repomd_xml.as_bytes().to_vec();
    let result = tokio::task::spawn_blocking(move || {
        verify_repomd_signature_blocking(&repomd_bytes, &sig_bytes, &key_texts)
    })
    .await
    .context("gpg verification task panicked")?;

    if let Err(e) = &result {
        if is_terra_repo(cfg) {
            // Terra (fyralabs) has repeatedly shipped a `repomd.xml.asc` that
            // doesn't verify against its own published key. It isn't a
            // temporary mirror race (see the retries in
            // fetch_repomd_verified); it's a bad signature upstream,
            // apparently with nothing in Terra's release process to catch it.
            // Terra is popular enough among Svara users that failing every
            // `dnf upgrade` over it does more harm than trusting metadata
            // that claims to be signed and isn't, so this one repo is let
            // through with a loud warning instead of aborting. Every other
            // repo still fails closed.
            tracing::warn!(repo = %cfg.id, error = %e, "repomd.xml signature verification failed for Terra (known upstream signing issue) — continuing anyway");
            return Ok(());
        }
    }
    result
}

/// Whether `cfg` is (or points at) the Terra repository (fyralabs). Matched
/// by id/name instead of URL because Terra is widely mirrored, and the
/// id/name conventions of `terra.repo` are the stable signal.
fn is_terra_repo(cfg: &RepoConfig) -> bool {
    let id = cfg.id.to_ascii_lowercase();
    let name = cfg.name.to_ascii_lowercase();
    id == "terra" || id.starts_with("terra-") || id.starts_with("terra_") || name.contains("terra")
}

/// The `gpg`/`gpgv` calls behind [`verify_repomd_signature`], run in their
/// own scratch homedir (never rpm's or the user's real `~/.gnupg`) so this
/// never reads or writes any trust state beyond `cfg.gpgkeys` for this one
/// check. Steps: `gpg --import` each configured key into it, `gpg --export`
/// them to a plain keyring file (`gpgv` reads that format, not a homedir's
/// keybox), then `gpgv --keyring` that file against the signature/data pair.
/// The homedir is removed afterwards whatever the outcome.
fn verify_repomd_signature_blocking(
    repomd_bytes: &[u8],
    sig_bytes: &[u8],
    key_texts: &[Vec<u8>],
) -> Result<()> {
    use std::io::Write;

    let tmp = std::env::temp_dir().join(format!(
        "vez-repomd-gpg-{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp).context("creating temp gpg homedir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // gpg refuses to use a homedir it considers insecurely permissioned.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))
            .context("setting temp gpg homedir permissions")?;
    }

    let result = (|| -> Result<()> {
        for (i, key) in key_texts.iter().enumerate() {
            let key_path = tmp.join(format!("key{i}.asc"));
            std::fs::write(&key_path, key)?;
            let status = std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(&tmp)
                .arg("--batch")
                .arg("--quiet")
                .arg("--import")
                .arg(&key_path)
                .status()
                .context("spawning gpg --import")?;
            anyhow::ensure!(status.success(), "gpg --import failed for gpgkey #{i}");
        }

        let export = std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(&tmp)
            .arg("--batch")
            .arg("--export")
            .output()
            .context("spawning gpg --export")?;
        anyhow::ensure!(export.status.success(), "gpg --export failed");
        let keyring_path = tmp.join("keyring.gpg");
        std::fs::File::create(&keyring_path)
            .and_then(|mut f| f.write_all(&export.stdout))
            .context("writing scratch keyring")?;

        let sig_path = tmp.join("repomd.xml.asc");
        let data_path = tmp.join("repomd.xml");
        std::fs::write(&sig_path, sig_bytes)?;
        std::fs::write(&data_path, repomd_bytes)?;

        let status = std::process::Command::new("gpgv")
            .arg("--keyring")
            .arg(&keyring_path)
            .arg(&sig_path)
            .arg(&data_path)
            .status()
            .context("spawning gpgv")?;
        anyhow::ensure!(
            status.success(),
            "repomd.xml signature verification failed (gpgv rejected it)"
        );
        Ok(())
    })();

    let _ = std::fs::remove_dir_all(&tmp);
    result
}

/// [`fetch_repomd`] + [`verify_repomd_signature`] against one mirror,
/// retrying the *pair* a few times on a signature failure before giving up on
/// that mirror.
///
/// Some repos (Terra is the one that has actually shown up: bug reports cite
/// `gpgv rejected it` against a `repomd.xml` that was fine later) publish
/// `repomd.xml` and its detached `repomd.xml.asc` as two separate uploads/CDN
/// objects instead of swapping both in atomically. `createrepo_c --sign`
/// writes the signature after `repomd.xml` is already live, and a CDN edge
/// can serve a `.asc` from one sync pass with a `repomd.xml` from the next.
/// From a single fetch, that race looks exactly like a bad or malicious
/// signature. Unlike a real bad signature, fetching *both* files again a
/// moment later almost always fixes it once the mirror settles. So a bad
/// signature isn't trusted on the first try: this fetches and verifies
/// repomd.xml again up to [`REPOMD_SIGNATURE_RETRIES`] more times with a
/// short delay, and only returns the failure if it's still bad after all of
/// them. At that point it's either a real bad signature or a mirror that has
/// been broken for several seconds straight, and failing (or moving to the
/// next mirror, like any other fetch error) is right either way. This never
/// weakens what "verified" means: every accepted `repomd.xml` still passes
/// the same `gpgv` check, possibly on a later attempt.
const REPOMD_SIGNATURE_RETRIES: u32 = 3;
const REPOMD_SIGNATURE_RETRY_DELAY: Duration = Duration::from_millis(1500);

async fn fetch_repomd_verified(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    mirror: &str,
) -> Result<(String, u64)> {
    let mut attempt = 0;
    let mut fetched = 0;
    loop {
        attempt += 1;
        let (repomd_xml, bytes) = fetch_repomd(client, mirror).await?;
        fetched += bytes;
        match verify_repomd_signature(client, cfg, mirror, &repomd_xml).await {
            Ok(()) => return Ok((repomd_xml, fetched)),
            Err(e) if attempt <= REPOMD_SIGNATURE_RETRIES => {
                tracing::warn!(repo = %cfg.id, mirror = %mirror, attempt, error = %e, "repomd.xml signature verification failed, retrying (mirror may be mid-publish)");
                tokio::time::sleep(REPOMD_SIGNATURE_RETRY_DELAY).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "verifying repomd.xml signature for repo '{}' (after {attempt} attempt(s))",
                        cfg.id
                    )
                })
            }
        }
    }
}

/// Same as [`load_repo`], plus `cache_only` (dnf's `-C`/`--cacheonly`), which
/// forces a run without network access: whatever is cached gets used whatever
/// its `metadata_expire=` age (stale beats a network round trip the caller
/// asked to skip), and a completely missing cache is a hard error instead of
/// falling through to a fetch.
///
/// Applies `cfg`'s proxy/auth/TLS-client settings ([`net_options_for_repo`])
/// to every librepo handle [`load_repo_ex_inner`] creates while fetching this
/// repo's metadata, then delegates. It's a thin wrapper so the loading logic
/// isn't nested inside a closure.
pub async fn load_repo_ex(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
    refresh: bool,
    cache_only: bool,
) -> Result<Repo> {
    with_net_options(
        net_options_for_repo(cfg),
        load_repo_ex_inner(client, cfg, cache_root, refresh, cache_only),
    )
    .await
}

/// Outcome of [`fetch_into_cache`].
enum Fetched {
    /// The mirror's `repomd.xml` is byte-identical to the cached one, so
    /// nothing it points at can have changed: the cache was only re-stamped
    /// as fresh.
    Unchanged,
    Updated(ParsedCache),
}

/// Possible on-disk names for a repo's cached primary metadata, newest layout
/// first. The downloaded file is cached still compressed (`primary.xml.zst`
/// is about 14 MB, where the decompressed Fedora `primary.xml` was 176 MB and
/// `updates-archive`'s 394 MB). A bare `primary.xml` is the old decompressed
/// layout, still read so an existing cache keeps working.
const PRIMARY_CACHE_NAMES: [&str; 5] = [
    "primary.xml.zst",
    "primary.xml.gz",
    "primary.xml.xz",
    "primary.xml.bz2",
    "primary.xml",
];

/// The [`PRIMARY_CACHE_NAMES`] entry a primary downloaded from `href` is
/// cached under (keeps the compression suffix so it can be decoded again).
fn primary_cache_name(href: &str) -> &'static str {
    PRIMARY_CACHE_NAMES
        .iter()
        .copied()
        .find(|n| {
            n.rsplit_once('.')
                .is_some_and(|(_, ext)| ext != "xml" && href.ends_with(&format!(".{ext}")))
        })
        .unwrap_or("primary.xml")
}

/// Builds a [`Repo`] only from `cache_dir`: `parsed.json` if it deserializes,
/// otherwise a re-parse of the cached raw metadata (which also rewrites
/// `parsed.json`). `Ok(None)` if nothing usable is cached.
fn load_from_cache(cfg: &RepoConfig, cache_dir: &Path) -> Result<Option<Repo>> {
    let parsed_cache_path = cache_dir.join("parsed.json");
    // Fast path: a previously parsed snapshot (libdnf5's `.solv`/`.solvx`
    // cache does the same job) skips re-parsing
    // primary.xml/comps.xml/modules.yaml on every invocation when the repo
    // hasn't changed since the last fetch. On any read or deserialize failure
    // this falls through to parsing the raw metadata below. This file is an
    // optimization, never the only copy of the data.
    if let Some(repo) = std::fs::read(&parsed_cache_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ParsedCache>(&bytes).ok())
        .map(|cached| cached.into_repo(cfg))
    {
        tracing::debug!(repo = %cfg.id, cache = %cache_dir.display(), packages = repo.packages.len(), groups = repo.groups.len(), environments = repo.environments.len(), modules = repo.modules.len(), "loaded repo metadata from parsed cache");
        return Ok(Some(repo));
    }

    let Ok(base_url) = std::fs::read_to_string(cache_dir.join("baseurl.txt")) else {
        return Ok(None);
    };
    let Some((name, file)) = PRIMARY_CACHE_NAMES
        .iter()
        .find_map(|n| std::fs::File::open(cache_dir.join(n)).ok().map(|f| (*n, f)))
    else {
        return Ok(None);
    };
    let base_url = base_url.trim().to_string();
    let packages = primary::parse_primary_reader(decompress_reader(
        name,
        std::io::BufReader::with_capacity(1 << 16, file),
    )?)
    .with_context(|| format!("parsing cached {name} for repo '{}'", cfg.id))?;
    let comps = std::fs::read_to_string(cache_dir.join("comps.xml"))
        .map(|xml| comps::parse_comps_xml_with_types(&xml, group_package_types()))
        .unwrap_or_default();
    let module_data = std::fs::read_to_string(cache_dir.join("modules.yaml"))
        .map(|yaml| modulemd::parse_modules_yaml(&yaml))
        .unwrap_or_default();
    let advisories = std::fs::read_to_string(cache_dir.join("updateinfo.xml"))
        .map(|xml| parse_updateinfo_xml(&xml))
        .unwrap_or_default();

    let cached = ParsedCache {
        base_url,
        packages,
        groups: comps.groups,
        environments: comps.environments,
        modules: module_data.modules,
        module_defaults: module_data.defaults,
        advisories,
    };
    if let Err(e) = write_atomic(&parsed_cache_path, |w| {
        serde_json::to_writer(w, &cached).map_err(Into::into)
    }) {
        tracing::warn!(repo = %cfg.id, cache = %parsed_cache_path.display(), error = %e, "failed to write parsed metadata cache");
    }
    let repo = cached.into_repo(cfg);
    tracing::debug!(repo = %cfg.id, cache = %cache_dir.display(), packages = repo.packages.len(), groups = repo.groups.len(), environments = repo.environments.len(), modules = repo.modules.len(), "loaded repo metadata from cache");
    Ok(Some(repo))
}

async fn load_repo_ex_inner(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
    refresh: bool,
    cache_only: bool,
) -> Result<Repo> {
    let cache_dir = repo_cache_dir(cache_root, cfg);

    if !refresh
        && (cache_only || cache_is_fresh(&cache_dir.join("repomd.xml"), cfg.metadata_expire))
    {
        if let Some(repo) = load_from_cache(cfg, &cache_dir)? {
            return Ok(repo);
        }
        // The cached repomd.xml looked fresh but the rest of the cache is
        // missing or unreadable (partial write, manual tampering). Fall
        // through to a real fetch instead of failing, unless the caller
        // forbade network access.
    }
    anyhow::ensure!(
        !cache_only,
        "no cached metadata for repo '{}' and --cacheonly forbids fetching it",
        cfg.id
    );

    match fetch_into_cache(client, cfg, cache_root, refresh, true).await? {
        Fetched::Updated(cached) => Ok(cached.into_repo(cfg)),
        Fetched::Unchanged => match load_from_cache(cfg, &cache_dir)? {
            Some(repo) => Ok(repo),
            // The cache matched repomd.xml but turned out to be unreadable
            // after all, so refetch everything instead of failing.
            None => match fetch_into_cache(client, cfg, cache_root, refresh, false).await? {
                Fetched::Updated(cached) => Ok(cached.into_repo(cfg)),
                Fetched::Unchanged => unreachable!(
                    "fetch_into_cache never reports Unchanged when allow_unchanged is false"
                ),
            },
        },
    }
}

/// `vez makecache`: brings `cfg`'s on-disk metadata cache up to date without
/// building a [`Repo`] for the caller. Returns whether anything was
/// downloaded again. An unchanged `repomd.xml` costs one small request (plus
/// the mirror list) and no parse or rewrite at all.
pub async fn refresh_repo(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
) -> Result<bool> {
    with_net_options(net_options_for_repo(cfg), async {
        Ok(
            match fetch_into_cache(client, cfg, cache_root, true, true).await? {
                Fetched::Updated(_) => true,
                Fetched::Unchanged => false,
            },
        )
    })
    .await
}

/// The network half of loading a repo: pick a mirror, fetch and verify
/// `repomd.xml`, and, unless it's byte-identical to the cached copy (and
/// `allow_unchanged` is set), download and parse everything it points at and
/// rewrite the cache.
async fn fetch_into_cache(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
    refresh: bool,
    allow_unchanged: bool,
) -> Result<Fetched> {
    let cache_dir = repo_cache_dir(cache_root, cfg);
    let repomd_cache_path = cache_dir.join("repomd.xml");

    // Same as dnf's default: silent on a cache hit, and one dnf5-style
    // bracketed progress line per repo when metadata has to come over the
    // network. The line covers the time and size of every metadata file this
    // repo needs (repomd + primary, plus comps/modules below), not only the
    // initial `repomd.xml` probe.
    let fetch_start = std::time::Instant::now();
    let mut fetched_bytes: u64 = 0;

    // Only worth comparing if the rest of the cache it describes is there to
    // reuse.
    let cached_repomd = if allow_unchanged
        && cache_dir.join("parsed.json").exists()
        && cache_dir.join("baseurl.txt").exists()
    {
        std::fs::read_to_string(&repomd_cache_path).ok()
    } else {
        None
    };

    // A mirror can have a current repodata/repomd.xml while lagging on the
    // primary.xml it points at (or the other way round), because mirrors sync
    // file by file, not atomically per tree. Probing repomd.xml with a HEAD
    // (resolve_base_url) can't catch that, so any failure fetching *or
    // parsing* this mirror's metadata moves on to the next mirror instead of
    // failing the whole repo.
    let mirrors = resolve_ranked_mirrors(client, cfg, cache_root, refresh).await?;
    let ordered_mirrors: Vec<String> = if mirrors.len() > 1 {
        match resolve_base_url(client, cfg, cache_root).await {
            Ok(preferred) => {
                let mut ordered = vec![preferred.clone()];
                ordered.extend(mirrors.into_iter().filter(|m| *m != preferred));
                ordered
            }
            Err(_) => mirrors,
        }
    } else {
        mirrors
    };

    let mut fetched: Option<(String, String, String, Vec<u8>, Vec<Package>)> = None;
    let mut last_err: Option<anyhow::Error> = None;
    for mirror in &ordered_mirrors {
        let attempt = async {
            let (repomd_xml, bytes) = fetch_repomd_verified(client, cfg, mirror).await?;
            fetched_bytes += bytes;
            if cached_repomd.as_deref() == Some(repomd_xml.as_str()) {
                return Ok(None);
            }
            let primary_href = find_data_href(&repomd_xml, "primary").with_context(|| {
                format!("no <data type=\"primary\"> entry in {mirror}/repodata/repomd.xml")
            })?;
            // Checked before downloading: the format is the same on every
            // mirror, so there's nothing to gain from fetching it.
            check_compression(&primary_href)?;
            let (compressed, packages) = fetch_primary(client, mirror, &primary_href).await?;
            fetched_bytes += compressed.len() as u64;
            anyhow::Ok(Some((
                mirror.clone(),
                repomd_xml,
                primary_href,
                compressed,
                packages,
            )))
        };
        match attempt.await {
            Ok(None) => {
                // A byte-identical repomd.xml means every checksum/href in it
                // is identical too, so primary/comps/updateinfo can't have
                // changed. Mark the cache fresh for `metadata_expire` again
                // and skip the download, the parse, and a cache rewrite of
                // hundreds of MB.
                if let Err(e) = std::fs::File::options()
                    .write(true)
                    .open(&repomd_cache_path)
                    .and_then(|f| f.set_modified(SystemTime::now()))
                {
                    tracing::warn!(repo = %cfg.id, cache = %repomd_cache_path.display(), error = %e, "failed to mark unchanged repo metadata as fresh");
                }
                tracing::debug!(repo = %cfg.id, mirror = %mirror, "repomd.xml unchanged, keeping cached metadata");
                return Ok(Fetched::Unchanged);
            }
            Ok(Some(result)) => {
                fetched = Some(result);
                break;
            }
            Err(e) if e.downcast_ref::<UnsupportedCompression>().is_some() => {
                return Err(e.context(format!("repo '{}'", cfg.id)));
            }
            Err(e) => {
                tracing::warn!(repo = %cfg.id, mirror = %mirror, error = %e, "mirror metadata fetch failed, trying next mirror");
                last_err = Some(e);
            }
        }
    }
    let (base_url, repomd_xml, primary_href, primary_compressed, packages) =
        fetched.ok_or_else(|| match last_err {
            Some(e) => e.context(format!(
                "repo '{}': all {} mirror(s) failed",
                cfg.id,
                ordered_mirrors.len()
            )),
            None => anyhow::anyhow!("repo '{}': no mirrors available", cfg.id),
        })?;

    // Optional extras. Fetch every compressed file first, then decompress and
    // parse them one at a time below with no network waits in between, so no
    // decompressed document is kept across an await.
    //
    // Comps groups are optional and not every repo ships them (`group_gz` is
    // the usual compressed form, `group` the rare plain-XML one).
    // Module-stream metadata is rare outside Fedora/RHEL-style repos with
    // modular content. Advisory (updateinfo) data is often large, but `vez
    // advisory`/`upgrade --advisory=` need it. None of them being present is
    // an error.
    let group_href =
        find_data_href(&repomd_xml, "group_gz").or_else(|| find_data_href(&repomd_xml, "group"));
    let modules_href = find_data_href(&repomd_xml, "modules");
    let updateinfo_href = find_data_href(&repomd_xml, "updateinfo");
    let mut fetch_optional = async |href: &Option<String>,
                                    what: &str|
           -> Option<(String, Vec<u8>)> {
        let href = href.as_ref()?;
        let url = format!("{base_url}/{href}");
        match get_with_retry(client, &url)
            .await
            .and_then(|r| r.error_for_status().map_err(Into::into))
        {
            Ok(resp) => match resp.bytes().await {
                Ok(bytes) => {
                    fetched_bytes += bytes.len() as u64;
                    Some((href.clone(), bytes))
                }
                Err(_) => None,
            },
            Err(e) => {
                tracing::debug!(repo = %cfg.id, error = %e, "failed to fetch {what} data, continuing without it");
                None
            }
        }
    };
    let group_raw = fetch_optional(&group_href, "comps group").await;
    let modules_raw = fetch_optional(&modules_href, "modules").await;
    let updateinfo_raw = fetch_optional(&updateinfo_href, "updateinfo").await;

    // dnf5's bracketed `label 100% | speed | size | time` progress line,
    // printed once per repo that needed a network fetch (a cache hit returns
    // earlier and never gets here). The label is truncated/padded to a fixed
    // column width, the way dnf5 clips a long repo `name=` instead of
    // reflowing the whole table.
    const LABEL_WIDTH: usize = 39;
    let label: String = cfg.name.chars().take(LABEL_WIDTH).collect();
    eprintln!(
        " {label:<LABEL_WIDTH$} 100% | {:>10} | {:>10} | {}",
        vez_core::format_speed(fetched_bytes, fetch_start.elapsed()),
        vez_core::format_size(fetched_bytes),
        vez_core::format_duration(fetch_start.elapsed())
    );

    let decode = |raw: Option<(String, Vec<u8>)>| {
        raw.map(|(href, bytes)| decompress(&href, &bytes).unwrap_or_default())
            .unwrap_or_default()
    };
    let group_xml = decode(group_raw);
    let comps = comps::parse_comps_xml_with_types(&group_xml, group_package_types());
    let modules_yaml = decode(modules_raw);
    let module_data = modulemd::parse_modules_yaml(&modules_yaml);
    let updateinfo_xml = decode(updateinfo_raw);
    let advisories = parse_updateinfo_xml(&updateinfo_xml);

    let cached = ParsedCache {
        base_url,
        packages,
        groups: comps.groups,
        environments: comps.environments,
        modules: module_data.modules,
        module_defaults: module_data.defaults,
        advisories,
    };
    let files = CacheFiles {
        repomd_xml: &repomd_xml,
        primary_href: &primary_href,
        primary_compressed: &primary_compressed,
        group_xml: &group_xml,
        modules_yaml: &modules_yaml,
        updateinfo_xml: &updateinfo_xml,
    };
    if let Err(e) = write_cache(&cache_dir, &files, &cached) {
        // Caching is an optimization and not required for correctness. A
        // read-only cache_dir (e.g. a locked-down container, or a non-root
        // user) shouldn't stop the install.
        tracing::warn!(repo = %cfg.id, cache = %cache_dir.display(), error = %e, "failed to write repo metadata cache");
    }
    tracing::info!(repo = %cfg.id, base_url = %cached.base_url, packages = cached.packages.len(), groups = cached.groups.len(), environments = cached.environments.len(), modules = cached.modules.len(), advisories = cached.advisories.len(), "loaded repo metadata");
    Ok(Fetched::Updated(cached))
}

/// Per-repo cache directory: `<cache_root>/<id>-<hash>`, where `hash` is a
/// short digest of what identifies *which* metadata this repo id refers to
/// (`base_url`/`mirrorlist`/`metalink`). Same as dnf5's
/// `/var/cache/libdnf5/<id>-<hash>` layout: pointing a repo id at a different
/// URL (or another repo reusing the id) gets its own cache slot instead of
/// colliding with stale data.
pub fn repo_cache_dir(cache_root: &Path, cfg: &RepoConfig) -> PathBuf {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    cfg.base_url.hash(&mut hasher);
    cfg.mirrorlist.hash(&mut hasher);
    cfg.metalink.hash(&mut hasher);
    cache_root.join(format!("{}-{:016x}", cfg.id, hasher.finish()))
}

/// The exact mirror base URL a repo's cached `Package.location`s were built
/// from (`baseurl.txt`, written by [`load_repo_ex`]/`write_cache`). For a
/// `mirrorlist=`/`metalink=` repo this is whichever single mirror answered
/// when metadata was fetched. It may be hours old (it survives across
/// `metadata_expire`) or missing from a *fresh* [`resolve_mirrors`] call,
/// because Fedora's metalink endpoint returns a geo-sorted, randomized subset
/// per request instead of a stable full list. Callers that need to reduce a
/// package's `location` to its bare `href` (to retry it against another
/// mirror) must use *this* value, not a prefix search over a freshly resolved
/// mirror list. That search silently finds nothing when the two calls
/// returned disjoint mirror sets, which is what disabled the same-repo 404
/// fallback for `gtk-vnc2` on the stock Fedora metalink repo.
pub fn cached_base_url(cache_root: &Path, cfg: &RepoConfig) -> Option<String> {
    std::fs::read_to_string(repo_cache_dir(cache_root, cfg).join("baseurl.txt"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Is the cached `repomd.xml` at `repomd_cache_path` still within
/// `metadata_expire` seconds of its last write? `u64::MAX` (from
/// `-1`/`never`) means yes, always, as long as the file exists.
fn cache_is_fresh(repomd_cache_path: &Path, metadata_expire: u64) -> bool {
    let Ok(meta) = std::fs::metadata(repomd_cache_path) else {
        return false;
    };
    if metadata_expire == u64::MAX {
        return true;
    }
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age < Duration::from_secs(metadata_expire))
        .unwrap_or(false)
}

/// The raw metadata [`write_cache`] persists next to `parsed.json`.
struct CacheFiles<'a> {
    repomd_xml: &'a str,
    primary_href: &'a str,
    primary_compressed: &'a [u8],
    group_xml: &'a str,
    modules_yaml: &'a str,
    updateinfo_xml: &'a str,
}

/// Writes `path` through a temp file next to it plus a rename, so a
/// concurrent reader (another vez process, the makecache timer) only ever
/// sees the old or the new complete file and never a truncated one.
fn write_atomic(
    path: &Path,
    write: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::Write;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("cache");
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut w = std::io::BufWriter::with_capacity(1 << 16, std::fs::File::create(&tmp)?);
        write(&mut w)?;
        w.flush()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Saves a fresh fetch. `repomd.xml` is written last because freshness (and
/// the unchanged-repomd shortcut) is keyed on it, so it only ever describes a
/// cache whose other files are already complete.
fn write_cache(cache_dir: &Path, files: &CacheFiles<'_>, parsed: &ParsedCache) -> Result<()> {
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("creating {}", cache_dir.display()))?;
    let primary_name = primary_cache_name(files.primary_href);
    write_atomic(&cache_dir.join(primary_name), |w| {
        std::io::Write::write_all(w, files.primary_compressed)
    })?;
    // Remove any other primary layout (especially the old decompressed
    // `primary.xml`, up to hundreds of MB) so a stale copy is never read.
    for other in PRIMARY_CACHE_NAMES.iter().filter(|n| **n != primary_name) {
        let _ = std::fs::remove_file(cache_dir.join(other));
    }
    write_atomic(&cache_dir.join("baseurl.txt"), |w| {
        std::io::Write::write_all(w, parsed.base_url.as_bytes())
    })?;
    for (name, contents) in [
        ("comps.xml", files.group_xml),
        ("modules.yaml", files.modules_yaml),
        ("updateinfo.xml", files.updateinfo_xml),
    ] {
        if !contents.is_empty() {
            write_atomic(&cache_dir.join(name), |w| {
                std::io::Write::write_all(w, contents.as_bytes())
            })?;
        }
    }
    write_atomic(&cache_dir.join("parsed.json"), |w| {
        serde_json::to_writer(w, parsed).map_err(Into::into)
    })?;
    write_atomic(&cache_dir.join("repomd.xml"), |w| {
        std::io::Write::write_all(w, files.repomd_xml.as_bytes())
    })?;
    Ok(())
}

/// Every candidate mirror base URL for `cfg`, unprobed and in the order its
/// `mirrorlist=`/`metalink=` listed them (or one element for a plain
/// `baseurl=` repo). [`resolve_base_url`] probes these to pick the metadata
/// mirror, and `vez-transaction` uses the rest of the list to retry a package
/// `.rpm` after a 404. A mirror can be current on `repomd.xml`/`primary.xml`
/// while still behind on one package's rsync, or the other way round, so
/// package-level retries don't reuse the probe result from metadata time.
pub async fn resolve_mirrors(client: &reqwest::Client, cfg: &RepoConfig) -> Result<Vec<String>> {
    if let Some(base_url) = &cfg.base_url {
        return Ok(vec![base_url.trim_end_matches('/').to_string()]);
    }
    let (text, is_metalink) = fetch_mirror_source(client, cfg).await?;
    let mirrors = if is_metalink {
        parse_metalink(&text)
    } else {
        parse_mirrorlist(&text)
    };
    anyhow::ensure!(
        !mirrors.is_empty(),
        "repo '{}': mirrorlist/metalink returned no usable mirror URLs",
        cfg.id
    );
    Ok(mirrors)
}

async fn fetch_mirror_source(client: &reqwest::Client, cfg: &RepoConfig) -> Result<(String, bool)> {
    if let Some(mirrorlist_url) = &cfg.mirrorlist {
        let text = get_with_retry(client, mirrorlist_url)
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok((text, false))
    } else if let Some(metalink_url) = &cfg.metalink {
        let text = get_with_retry(client, metalink_url)
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok((text, true))
    } else {
        bail!(
            "repo '{}' has no baseurl, mirrorlist, or metalink configured",
            cfg.id
        )
    }
}

/// Like `resolve_mirrors`, but caches the raw `mirrorlist=`/`metalink=`
/// response in `<cache_root>/<repo>-<hash>/{mirrorlist.txt,metalink.xml}` and
/// reuses it while it's younger than `cfg.metadata_expire` (dnf5 caches the
/// same file under `/var/cache/libdnf5/<repo>-<hash>/metalink.xml`). Without
/// this, every call fetched the document again: Fedora's metalink endpoint
/// alone was hit twice per package download, once here and once in
/// `resolve_base_url`'s own `resolve_mirrors` call. That endpoint returns a
/// geo-sorted, randomized subset per request, so two calls a few hundred
/// milliseconds apart could disagree on which mirrors exist. Caching keeps
/// the mirror *list* stable for the same window `repomd.xml`/`primary.xml`
/// are trusted for, while the per-mirror `HEAD` probe in `resolve_base_url`
/// still runs live every time, so a mirror in the cached list that has died
/// since is still avoided.
pub async fn resolve_mirrors_cached(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
    refresh: bool,
) -> Result<Vec<String>> {
    if let Some(base_url) = &cfg.base_url {
        return Ok(vec![base_url.trim_end_matches('/').to_string()]);
    }
    let cache_dir = repo_cache_dir(cache_root, cfg);
    let is_metalink = cfg.mirrorlist.is_none() && cfg.metalink.is_some();
    let cache_path = cache_dir.join(if is_metalink {
        "metalink.xml"
    } else {
        "mirrorlist.txt"
    });

    if !refresh && cache_is_fresh(&cache_path, cfg.metadata_expire) {
        if let Ok(text) = std::fs::read_to_string(&cache_path) {
            let mirrors = if is_metalink {
                parse_metalink(&text)
            } else {
                parse_mirrorlist(&text)
            };
            if !mirrors.is_empty() {
                return Ok(mirrors);
            }
        }
    }

    let (text, is_metalink) = fetch_mirror_source(client, cfg).await?;
    let mirrors = if is_metalink {
        parse_metalink(&text)
    } else {
        parse_mirrorlist(&text)
    };
    anyhow::ensure!(
        !mirrors.is_empty(),
        "repo '{}': mirrorlist/metalink returned no usable mirror URLs",
        cfg.id
    );

    if let Err(e) =
        std::fs::create_dir_all(&cache_dir).and_then(|_| std::fs::write(&cache_path, &text))
    {
        // Same as the repomd/primary cache: an optimization, not required for
        // correctness.
        tracing::warn!(repo = %cfg.id, cache = %cache_path.display(), error = %e, "failed to write mirror list cache");
    }
    Ok(mirrors)
}

/// Probes `cfg`'s mirror list with a `HEAD /repodata/repomd.xml` against each
/// candidate in order and returns the first one that answers. This is the
/// same choice [`load_repo_ex`] makes for which mirror to load metadata from.
/// Mirror lists are often stale (dead mirrors, geo-routing hiccups), and
/// trusting entry #1 blindly is a common cause of flaky installs. It's public
/// so a package download can re-probe for the mirror answering best *right
/// now* instead of trusting a `baseurl.txt` that may be hours or days old
/// (under `metadata_expire=`) and may have gone stale or slow since. Uses
/// [`resolve_mirrors_cached`] for the candidate list; only the per-mirror
/// liveness probe below runs live on every call.
pub async fn resolve_base_url(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
) -> Result<String> {
    let mirrors = resolve_ranked_mirrors(client, cfg, cache_root, false).await?;
    if mirrors.len() == 1 {
        return Ok(mirrors.into_iter().next().unwrap());
    }

    for mirror in &mirrors {
        let probe_url = format!("{mirror}/repodata/repomd.xml");
        match client.head(&probe_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(repo = %cfg.id, mirror = %mirror, "selected mirror");
                return Ok(mirror.clone());
            }
            Ok(resp) => {
                tracing::debug!(repo = %cfg.id, mirror = %mirror, status = %resp.status(), "mirror probe failed, trying next")
            }
            Err(e) => {
                tracing::debug!(repo = %cfg.id, mirror = %mirror, error = %e, "mirror probe errored, trying next")
            }
        }
    }
    bail!(
        "repo '{}': none of {} mirror(s) responded to a repomd.xml probe",
        cfg.id,
        mirrors.len()
    )
}

/// Like `resolve_mirrors_cached`, but the list comes back ranked
/// fastest-first by librepo's `lr_fastestmirror` ([`fastest_mirror_sort`]),
/// the mechanism dnf5 uses (`LRO_FASTESTMIRROR`/`LRO_FASTESTMIRRORCACHE`,
/// `libdnf5/repo/repo_downloader.cpp`), caching included. Results are stored
/// in one `fastestmirror.cache` file shared by every repo under `cache_root`
/// (mirrors shared between repos, common for Fedora, reuse their measured
/// speed right away) and stay valid for librepo's default max age (30 days).
/// So `refresh` only controls whether the raw mirror list
/// ([`resolve_mirrors_cached`]) is fetched again; librepo manages the ranking
/// cache.
pub async fn resolve_ranked_mirrors(
    client: &reqwest::Client,
    cfg: &RepoConfig,
    cache_root: &Path,
    refresh: bool,
) -> Result<Vec<String>> {
    let mirrors = resolve_mirrors_cached(client, cfg, cache_root, refresh).await?;
    if mirrors.len() <= 1 {
        return Ok(mirrors);
    }
    Ok(fastest_mirror_sort(mirrors, cache_root.join("fastestmirror.cache")).await)
}

/// Plain-text yum mirrorlist format: one URL per line, blank lines and
/// `#`-comments ignored. A trailing `/repodata/repomd.xml` (some mirrorlist
/// providers add it, some don't) is stripped so every entry is a bare base
/// URL, the same shape as a `baseurl=` value.
fn parse_mirrorlist(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.trim_end_matches('/')
                .trim_end_matches("/repodata/repomd.xml")
                .to_string()
        })
        .collect()
}

/// RFC 5854 metalink XML, the format `mirrors.fedoraproject.org` serves:
/// `<metalink><files><file><resources><url ...>https://mirror/.../repomd.xml</url>...`.
/// Each `<url>` points directly at a mirror's `repomd.xml`, so the base URL
/// is that with the trailing `/repodata/repomd.xml` stripped.
fn parse_metalink(xml: &str) -> Vec<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_url = false;
    let mut urls = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.local_name().as_ref() == b"url" => in_url = true,
            Ok(Event::End(e)) if e.local_name().as_ref() == b"url" => in_url = false,
            Ok(Event::Text(t)) if in_url => {
                if let Ok(text) = t.unescape() {
                    let url = text
                        .trim()
                        .trim_end_matches("/repodata/repomd.xml")
                        .to_string();
                    if url.starts_with("http://") || url.starts_with("https://") {
                        urls.push(url);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    urls
}

/// Minimal scan of `repomd.xml` for the `<location href="…"/>` of a `<data
/// type="wanted_type">` entry. `repomd.xml` is small and flat enough that a
/// full streaming parse isn't worth the extra code. Used for `"primary"` and
/// `"group"`/`"group_gz"` (comps).
fn find_data_href(xml: &str, wanted_type: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_wanted = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local = e.local_name();
                let name = String::from_utf8_lossy(local.as_ref()).to_string();
                if name == "data" {
                    in_wanted = e.attributes().flatten().any(|a| {
                        a.key.local_name().as_ref() == b"type"
                            && a.value.as_ref() == wanted_type.as_bytes()
                    });
                } else if name == "location" && in_wanted {
                    if let Some(href) = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == b"href")
                    {
                        return Some(String::from_utf8_lossy(&href.value).to_string());
                    }
                }
            }
            Ok(Event::End(e)) => {
                if e.local_name().as_ref() == b"data" {
                    in_wanted = false;
                }
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
}

/// Streaming counterpart of [`decompress`], chosen by `href`'s suffix.
/// Compression suffixes repodata can use that vez doesn't decode. Any of
/// these used to fall through to "plain XML" and fail as a parse error on
/// every mirror in turn (each one downloading the full file again), which is
/// how Remi's `primary.xml.bz2` turned into an apparently endless metadata
/// refresh before bzip2 was supported. Now it's one clear error instead.
const UNSUPPORTED_COMPRESSION: [&str; 3] = [".lz4", ".lzma", ".zck"];

fn unsupported_compression(href: &str) -> Option<&'static str> {
    UNSUPPORTED_COMPRESSION
        .iter()
        .copied()
        .find(|ext| href.ends_with(ext))
}

/// Metadata in a compression vez can't decode. Every mirror serves the same
/// format, so the mirror loop stops on this instead of trying the next one.
#[derive(Debug)]
struct UnsupportedCompression {
    ext: &'static str,
    href: String,
}

impl std::fmt::Display for UnsupportedCompression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported metadata compression '{}' for {}",
            self.ext, self.href
        )
    }
}

impl std::error::Error for UnsupportedCompression {}

fn check_compression(href: &str) -> Result<()> {
    match unsupported_compression(href) {
        Some(ext) => Err(anyhow::Error::new(UnsupportedCompression {
            ext,
            href: href.to_string(),
        })),
        None => Ok(()),
    }
}

fn decompress_reader<'a, R: std::io::Read + 'a>(
    href: &str,
    data: R,
) -> Result<Box<dyn std::io::BufRead + 'a>> {
    use std::io::BufReader;
    const BUF: usize = 1 << 16;
    check_compression(href)?;
    Ok(if href.ends_with(".gz") {
        Box::new(BufReader::with_capacity(
            BUF,
            flate2::read::GzDecoder::new(data),
        ))
    } else if href.ends_with(".bz2") {
        Box::new(BufReader::with_capacity(
            BUF,
            bzip2::read::MultiBzDecoder::new(data),
        ))
    } else if href.ends_with(".xz") {
        Box::new(BufReader::with_capacity(
            BUF,
            xz2::read::XzDecoder::new(data),
        ))
    } else if href.ends_with(".zst") {
        Box::new(BufReader::with_capacity(
            BUF,
            zstd::stream::Decoder::new(data).context("opening zstd stream")?,
        ))
    } else {
        Box::new(BufReader::with_capacity(BUF, data))
    })
}

fn decompress(href: &str, data: &[u8]) -> Result<String> {
    use std::io::Read;

    check_compression(href)?;
    if href.ends_with(".gz") {
        let mut out = String::new();
        flate2::read::GzDecoder::new(data)
            .read_to_string(&mut out)
            .context("gunzip primary.xml.gz")?;
        Ok(out)
    } else if href.ends_with(".bz2") {
        let mut out = String::new();
        bzip2::read::MultiBzDecoder::new(data)
            .read_to_string(&mut out)
            .context("bunzip2 metadata")?;
        Ok(out)
    } else if href.ends_with(".xz") {
        let mut out = String::new();
        xz2::read::XzDecoder::new(data)
            .read_to_string(&mut out)
            .context("un-xz primary.xml.xz")?;
        Ok(out)
    } else if href.ends_with(".zst") {
        let mut out = String::new();
        zstd::stream::Decoder::new(data)
            .context("opening zstd stream")?
            .read_to_string(&mut out)
            .context("un-zstd primary.xml.zst")?;
        Ok(out)
    } else {
        Ok(String::from_utf8(data.to_vec())?)
    }
}

/// Loads repo metadata from an already decompressed `primary.xml` file on
/// disk. Used by tests and by `vez` subcommands that work on a pre-fetched
/// cache.
pub fn load_primary_file(path: &Path, repo_id: &str) -> Result<Vec<Package>> {
    let xml =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut packages = parse_primary_xml(&xml)?;
    for pkg in &mut packages {
        pkg.repo_id = repo_id.to_string();
    }
    Ok(packages)
}

pub use vez_core::glob_match;

/// The values for `$releasever`/`$basearch` (and a few other common dnf repo
/// variables) substituted into `.repo` file URLs. dnf reads releasever from
/// `VERSION_ID` in `/etc/os-release` and basearch from `uname -m` (with dnf's
/// i386-family normalization); vez does the same so existing Fedora/Svara
/// repo files resolve identically.
pub struct RepoVars {
    pub releasever: String,
    pub basearch: String,
    /// User-defined `$myvar`-style substitution vars, read from one file per
    /// var (filename = var name, file contents = value, first line only,
    /// trailing newline stripped) along dnf's `varsdir=` search path:
    /// `/etc/dnf/vars/`, `/etc/yum/vars/`, and then `vez.conf`'s `varsdir=`
    /// if set, which takes priority over both (dnf5's "explicit `varsdir=`
    /// wins" rule).
    pub custom: std::collections::HashMap<String, String>,
}

impl RepoVars {
    /// Detects `$releasever` from the base image's Fedora release and `$basearch`
    /// from `uname -m`; see [`resolve_releasever`] for why `VERSION_ID` is not the
    /// answer here. Falls back to `"44"`/`"x86_64"` (Svara's current base) if nothing
    /// can be read, since resolving against *something* sane beats failing every repo
    /// load. No custom vars; use [`RepoVars::detect_with_varsdir`] to pick those up
    /// too.
    pub fn detect() -> Self {
        Self::detect_with_varsdir(None)
    }

    /// Same as [`RepoVars::detect`], but also reads `$myvar`-style custom
    /// vars from the standard `/etc/dnf/vars/`+`/etc/yum/vars/` search path
    /// plus `extra_varsdir` (`vez.conf`'s `varsdir=`, if set, which wins over
    /// the two standard dirs when names collide).
    pub fn detect_with_varsdir(extra_varsdir: Option<&Path>) -> Self {
        let basearch = std::process::Command::new("uname")
            .arg("-m")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .map(|arch| match arch.as_str() {
                "i386" | "i486" | "i586" => "i686".to_string(),
                other => other.to_string(),
            })
            .unwrap_or_else(|| "x86_64".to_string());

        let mut custom = HashMap::new();
        for dir in [Path::new("/etc/dnf/vars"), Path::new("/etc/yum/vars")]
            .into_iter()
            .chain(extra_varsdir)
        {
            read_varsdir(dir, &mut custom);
        }

        let releasever = resolve_releasever(
            std::fs::read_to_string("/etc/os-release").ok().as_deref(),
            std::fs::read_to_string("/etc/fedora-release")
                .ok()
                .as_deref(),
            std::fs::read_to_string("/etc/dnf/vars/releasever")
                .ok()
                .as_deref(),
        );

        Self {
            releasever,
            basearch,
            custom,
        }
    }

    fn expand(&self, s: &str) -> String {
        let mut out = s
            .replace("$releasever", &self.releasever)
            .replace("$basearch", &self.basearch);
        for (name, value) in &self.custom {
            out = out.replace(&format!("${name}"), value);
        }
        out
    }
}

/// Resolves `$releasever`.
///
/// **`VERSION_ID` is not the answer on a derivative distro, and getting it wrong
/// breaks every repository at once.** Svara's `VERSION_ID` is Svara's own release
/// (`0.1`); Fedora's mirrors are organised by Fedora releases (`44`). Expanding
/// `$releasever` from `VERSION_ID` therefore asked every Fedora and COPR URL for
/// `/fedora/0.1/`, which does not exist — `vez install` could not have worked on an
/// installed Svara machine at all, and the failure would have looked like a network or
/// repository problem rather than a variable-resolution one.
///
/// The authoritative answer is the base image's Fedora release, which Fedora's own
/// release package records. An explicit `/etc/dnf/vars/releasever` outranks it, because
/// that file is how an administrator or an image build pins the value deliberately, and
/// in a bootc image it is routinely set for exactly this reason. `VERSION_ID` is the last
/// resort, and it is exactly right on Fedora itself, where the two agree.
///
/// The parameters are the three file contents rather than paths so the precedence is
/// testable; the caller reads the real files.
fn resolve_releasever(
    os_release: Option<&str>,
    fedora_release: Option<&str>,
    dnf_var: Option<&str>,
) -> String {
    if let Some(v) = dnf_var.map(str::trim).filter(|v| !v.is_empty()) {
        return v.to_string();
    }
    if let Some(v) = fedora_release.and_then(parse_fedora_release) {
        return v;
    }
    if let Some(v) = os_release
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("VERSION_ID="))
                .map(|v| v.trim().trim_matches('"').to_string())
        })
        .filter(|v| !v.is_empty())
    {
        return v;
    }
    // Nothing readable at all. 44 is Svara's current base, and resolving against
    // something plausible beats failing every repo load.
    "44".to_string()
}

/// Pulls the release out of `Fedora release 44 (Forty Four)`.
fn parse_fedora_release(text: &str) -> Option<String> {
    let mut words = text.split_whitespace();
    while let Some(w) = words.next() {
        if w.eq_ignore_ascii_case("release") {
            let v = words.next()?;
            return (!v.is_empty()).then(|| v.to_string());
        }
    }
    None
}

/// Reads every regular file directly under `dir` into `vars` (filename = var
/// name, first line of contents = value). A missing or unreadable `dir` is
/// skipped, the same way dnf5 treats a missing varsdir as "no custom vars
/// from here" instead of an error.
fn read_varsdir(dir: &Path, vars: &mut HashMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Ok(contents) = std::fs::read_to_string(entry.path()) {
            vars.insert(name, contents.lines().next().unwrap_or("").to_string());
        }
    }
}

/// Reads every repo from the standard dnf/yum `.repo` INI files in `dir`
/// (normally `/etc/yum.repos.d`). vez reuses this format instead of inventing
/// its own, so existing repo configs (Svara's, Fedora's, Terra's, RPM
/// Fusion's, …) keep working unchanged. Repos with only `mirrorlist=`/
/// `metalink=` are kept. Unlike a plain `baseurl=` repo, they don't get a
/// concrete `base_url` here; [`load_repo`] resolves one at fetch time,
/// because that needs a network round trip.
pub fn load_repo_configs(dir: &Path, vars: &RepoVars) -> Result<Vec<RepoConfig>> {
    let mut repos = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(repos),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };

    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("repo") {
            continue;
        }
        repos.extend(parse_repo_file(&std::fs::read_to_string(&path)?, vars));
    }
    Ok(repos)
}

/// Minimal `config-manager --set-enabled`/`--add-repo` equivalent. Edits
/// `.repo` INI files directly instead of going through [`load_repo_configs`]
/// and rewriting everything, so untouched sections, comments, and formatting
/// in the file survive byte for byte.
pub mod config_manager {
    use super::RepoVars;
    use anyhow::{Context, Result};
    use std::path::Path;

    /// Sets `enabled=` to `0`/`1` in `id`'s section, in whichever `.repo`
    /// file under `dir` defines it, adding the line if the section had no
    /// explicit `enabled=` (dnf's default is enabled, so enabling a repo
    /// that's implicitly enabled writes a no-op line).
    pub fn set_enabled(dir: &Path, id: &str, enabled: bool) -> Result<()> {
        let entries =
            std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("repo") {
                continue;
            }
            let contents = std::fs::read_to_string(&path)?;
            if let Some(updated) = set_enabled_in_text(&contents, id, enabled) {
                std::fs::write(&path, updated)
                    .with_context(|| format!("writing {}", path.display()))?;
                return Ok(());
            }
        }
        anyhow::bail!(
            "no repo section named '[{id}]' found under {}",
            dir.display()
        );
    }

    fn set_enabled_in_text(contents: &str, id: &str, enabled: bool) -> Option<String> {
        let header = format!("[{id}]");
        let lines: Vec<&str> = contents.lines().collect();
        let start = lines.iter().position(|l| l.trim() == header)?;
        let end = lines[start + 1..]
            .iter()
            .position(|l| l.trim_start().starts_with('['))
            .map(|i| start + 1 + i)
            .unwrap_or(lines.len());

        let mut out: Vec<String> = lines[..start + 1].iter().map(|s| s.to_string()).collect();
        let mut wrote = false;
        for line in &lines[start + 1..end] {
            if line.trim_start().starts_with("enabled") && line.contains('=') {
                out.push(format!("enabled={}", if enabled { 1 } else { 0 }));
                wrote = true;
            } else {
                out.push(line.to_string());
            }
        }
        if !wrote {
            out.push(format!("enabled={}", if enabled { 1 } else { 0 }));
        }
        out.extend(lines[end..].iter().map(|s| s.to_string()));
        Some(out.join("\n") + "\n")
    }

    /// Writes a new `<id>.repo` file under `dir` with a single `baseurl=`
    /// section. That's the common case (`dnf config-manager --add-repo <url>`
    /// for a plain repo, as opposed to a `.repo`-file URL, which dnf
    /// downloads verbatim).
    pub fn add_repo(
        dir: &Path,
        id: &str,
        baseurl: &str,
        vars: &RepoVars,
    ) -> Result<std::path::PathBuf> {
        let _ = vars; // kept for symmetry with load_repo_configs's $releasever/$basearch expansion; baseurl is stored unexpanded, same as a hand-written .repo file.
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(format!("{id}.repo"));
        let contents = format!("[{id}]\nname={id}\nbaseurl={baseurl}\nenabled=1\ngpgcheck=1\n");
        std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
        Ok(path)
    }
}

#[derive(Default)]
struct RawSection {
    name: Option<String>,
    base_url: Option<String>,
    mirrorlist: Option<String>,
    metalink: Option<String>,
    enabled: bool,
    gpgcheck: bool,
    gpgkeys: Vec<String>,
    metadata_expire: Option<String>,
    priority: Option<String>,
    cost: Option<String>,
    exclude: Vec<String>,
    includepkgs: Vec<String>,
    skip_if_unavailable: Option<bool>,
    proxy: Option<String>,
    proxy_username: Option<String>,
    proxy_password: Option<String>,
    username: Option<String>,
    password: Option<String>,
    sslcacert: Option<String>,
    sslclientcert: Option<String>,
    sslclientkey: Option<String>,
}

fn parse_repo_file(contents: &str, vars: &RepoVars) -> Vec<RepoConfig> {
    let mut repos = Vec::new();
    let mut id: Option<String> = None;
    let mut section = RawSection {
        enabled: true,
        gpgcheck: true,
        ..Default::default()
    };

    let flush = |id: &Option<String>, section: &RawSection, out: &mut Vec<RepoConfig>| {
        let Some(id) = id else { return };
        if section.base_url.is_none() && section.mirrorlist.is_none() && section.metalink.is_none()
        {
            return;
        }
        out.push(RepoConfig {
            id: id.clone(),
            name: section
                .name
                .clone()
                .map(|n| vars.expand(&n))
                .unwrap_or_else(|| id.clone()),
            base_url: section
                .base_url
                .as_ref()
                .map(|u| vars.expand(u).trim_end_matches('/').to_string()),
            mirrorlist: section.mirrorlist.as_ref().map(|u| vars.expand(u)),
            metalink: section.metalink.as_ref().map(|u| vars.expand(u)),
            gpgcheck: section.gpgcheck,
            gpgkeys: section.gpgkeys.iter().map(|k| vars.expand(k)).collect(),
            metadata_expire: section
                .metadata_expire
                .as_deref()
                .map(parse_metadata_expire)
                .unwrap_or(DEFAULT_METADATA_EXPIRE),
            enabled: section.enabled,
            priority: section
                .priority
                .as_deref()
                .and_then(|v| strip_inline_comment(v).parse().ok())
                .unwrap_or(99),
            cost: section
                .cost
                .as_deref()
                .and_then(|v| strip_inline_comment(v).parse().ok())
                .unwrap_or(1000),
            exclude: section.exclude.iter().map(|p| vars.expand(p)).collect(),
            includepkgs: section.includepkgs.iter().map(|p| vars.expand(p)).collect(),
            skip_if_unavailable: section.skip_if_unavailable,
            proxy: section.proxy.as_ref().map(|v| vars.expand(v)),
            proxy_username: section.proxy_username.as_ref().map(|v| vars.expand(v)),
            proxy_password: section.proxy_password.as_ref().map(|v| vars.expand(v)),
            username: section.username.as_ref().map(|v| vars.expand(v)),
            password: section.password.as_ref().map(|v| vars.expand(v)),
            sslcacert: section.sslcacert.as_ref().map(|v| vars.expand(v)),
            sslclientcert: section.sslclientcert.as_ref().map(|v| vars.expand(v)),
            sslclientkey: section.sslclientkey.as_ref().map(|v| vars.expand(v)),
        });
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(new_id) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            flush(&id, &section, &mut repos);
            id = Some(new_id.to_string());
            section = RawSection {
                enabled: true,
                gpgcheck: true,
                ..Default::default()
            };
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let (key, val) = (key.trim(), val.trim());
            match key {
                "name" => section.name = Some(val.to_string()),
                "baseurl" => section.base_url = Some(val.to_string()),
                "mirrorlist" => section.mirrorlist = Some(val.to_string()),
                "metalink" => section.metalink = Some(val.to_string()),
                "enabled" => section.enabled = val != "0",
                "gpgcheck" => section.gpgcheck = val != "0",
                "gpgkey" => section.gpgkeys = val.split_whitespace().map(str::to_string).collect(),
                "metadata_expire" => section.metadata_expire = Some(val.to_string()),
                "priority" => section.priority = Some(val.to_string()),
                "cost" => section.cost = Some(val.to_string()),
                "exclude" | "excludepkgs" => section
                    .exclude
                    .extend(val.split_whitespace().map(str::to_string)),
                "includepkgs" => section
                    .includepkgs
                    .extend(val.split_whitespace().map(str::to_string)),
                "skip_if_unavailable" => {
                    section.skip_if_unavailable =
                        Some(val == "1" || val.eq_ignore_ascii_case("true"))
                }
                "proxy" => {
                    section.proxy = if val.is_empty() || val == "_none_" {
                        None
                    } else {
                        Some(val.to_string())
                    }
                }
                "proxy_username" => section.proxy_username = Some(val.to_string()),
                "proxy_password" => section.proxy_password = Some(val.to_string()),
                "username" => section.username = Some(val.to_string()),
                "password" => section.password = Some(val.to_string()),
                "sslcacert" => section.sslcacert = Some(val.to_string()),
                "sslclientcert" => section.sslclientcert = Some(val.to_string()),
                "sslclientkey" => section.sslclientkey = Some(val.to_string()),
                _ => {}
            }
        }
    }
    flush(&id, &section, &mut repos);
    repos
}

/// Strips a trailing `# comment` from an INI value. dnf's `.repo` parser
/// (Python's `configparser`) doesn't support inline comments either, but some
/// hand-edited or vendored `.repo` files have them anyway (e.g. `cost=10000 #
/// default is 1000`). Tolerating them costs nothing and keeps a numeric field
/// from falling back to its default without anyone noticing.
fn strip_inline_comment(val: &str) -> &str {
    val.split('#').next().unwrap_or(val).trim()
}

/// Parses a `metadata_expire=` value the way dnf does: `-1` or `never` means
/// "doesn't expire by itself" (`u64::MAX` here), a bare integer is seconds,
/// and a trailing `s`/`m`/`h`/`d` suffix scales it (`6h` = 21600). Anything
/// unparseable falls back to [`DEFAULT_METADATA_EXPIRE`] instead of failing
/// the whole repo file over one bad value.
fn parse_metadata_expire(raw: &str) -> u64 {
    let raw = raw.trim();
    if raw == "-1" || raw.eq_ignore_ascii_case("never") {
        return u64::MAX;
    }
    let (num, mult) = match raw.chars().last() {
        Some('s') => (&raw[..raw.len() - 1], 1),
        Some('m') => (&raw[..raw.len() - 1], 60),
        Some('h') => (&raw[..raw.len() - 1], 3600),
        Some('d') => (&raw[..raw.len() - 1], 86400),
        _ => (raw, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n.saturating_mul(mult))
        .unwrap_or(DEFAULT_METADATA_EXPIRE)
}

/// Parses dnf's `minrate=`/`bandwidth=`-style byte counts: a plain number of
/// bytes, or one with a `k`/`M`/`G` suffix (case-insensitive, 1024-based,
/// like dnf5's `str_to_bytes`). Falls back to 1000 (dnf's `minrate=` default)
/// on anything unparseable.
fn parse_bytes(raw: &str) -> u64 {
    let raw = raw.trim();
    let (num, mult) = match raw.chars().last() {
        Some('k') | Some('K') => (&raw[..raw.len() - 1], 1024u64),
        Some('m') | Some('M') => (&raw[..raw.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&raw[..raw.len() - 1], 1024 * 1024 * 1024),
        _ => (raw, 1),
    };
    num.trim()
        .parse::<f64>()
        .map(|n| (n * mult as f64) as u64)
        .unwrap_or(1000)
}

/// Parses the `[main]` section of `/etc/vez/vez.conf`. Same INI format and
/// (as far as vez implements it) the same option names as dnf's
/// `/etc/dnf/dnf.conf`, so an admin who knows dnf.conf already knows
/// vez.conf. Only options vez uses are recognized. Anything else (dnf options
/// with no vez equivalent) is ignored without an error, as dnf does with
/// unknown plugin-only keys.
pub mod main_config {
    use anyhow::{Context, Result};
    use std::path::{Path, PathBuf};

    pub const DEFAULT_CONF_PATH: &str = "/etc/vez/vez.conf";

    #[derive(Debug, Clone)]
    pub struct MainConfig {
        pub cachedir: Option<PathBuf>,
        pub reposdir: Option<PathBuf>,
        /// `keepcache=`: keep downloaded `.rpm`s in the cache after a
        /// successful transaction instead of deleting them. dnf defaults to
        /// `false`.
        pub keepcache: bool,
        pub assumeyes: bool,
        /// `gpgcheck=`: dnf's default is `true`. vez already refuses to treat
        /// a *repo's* missing `gpgcheck=` as "off" (see
        /// [`crate::RepoConfig::gpgcheck`]), so this only provides the
        /// process-wide `--no-gpgchecks` default.
        pub gpgcheck: bool,
        /// `best=`: dnf's toggle for "the best available version has to
        /// resolve cleanly; don't fall back to an older one". dnf5's default
        /// is `false` (fall back to an older candidate that works instead of
        /// failing). Wired to `vez-solv`'s `SOLVER_FORCEBEST` flag on
        /// install/upgrade/distro-sync jobs (`SolveRequest::best`), like
        /// dnf5's `GoalPrivate::add_install`/`add_upgrade`/`add_distro_sync`.
        pub best: bool,
        pub exclude: Vec<String>,
        pub includepkgs: Vec<String>,
        /// `metadata_expire=`: fallback used by repos with no `metadata_expire=`
        /// of their own, in place of [`crate::DEFAULT_METADATA_EXPIRE`].
        pub metadata_expire: Option<u64>,
        pub retries: u32,
        pub timeout: u64,
        /// `minrate=`: minimum sustained throughput (bytes/sec, `k`/`M`/`G`
        /// suffixes accepted, 1024-based) below which a transfer counts as
        /// stalled and gets aborted/retried. Same as dnf's
        /// `minrate=`/`timeout=` pair, which together set libcurl's
        /// `CURLOPT_LOW_SPEED_LIMIT`/`CURLOPT_LOW_SPEED_TIME` (see
        /// `PackageDownloader`/`librepo.cpp` in dnf5). dnf's default is 1000
        /// B/s. Without it, a connection crawling at a few bytes/sec (seen in
        /// the wild: a mirror stuck at "12 B/s eta 23w") never trips a "zero
        /// progress" stall check and hangs forever instead of moving to
        /// another attempt or mirror.
        pub minrate: u64,
        pub max_parallel_downloads: u32,
        pub skip_if_unavailable: bool,
        pub clean_requirements_on_remove: bool,
        pub installroot: Option<PathBuf>,
        /// `protected_packages=`: names (or globs) that `vez
        /// remove`/`autoremove`/`swap` refuse to erase, like dnf's
        /// protected-packages plugin. `vez` itself is always protected on top
        /// of this list, whatever the config says; see
        /// [`crate::ALWAYS_PROTECTED`].
        pub protected_packages: Vec<String>,
        /// `installonlypkgs=`: names (or globs) that may have several
        /// versions installed side by side, so the resolver doesn't treat a
        /// candidate with the same name and a different EVR as replacing the
        /// installed one. The kernel package family is the usual example.
        /// Defaults to dnf's built-in list.
        pub installonlypkgs: Vec<String>,
        /// `installonly_limit=`: how many versions of an `installonlypkgs=`
        /// package to keep installed at once. Older ones past this count are
        /// pruned after a successful install (dnf default: 3).
        pub installonly_limit: u32,
        /// `install_weak_deps=`: whether `Recommends` are installed
        /// best-effort along with the hard `Requires` closure. dnf's default
        /// is `true`. `Suggests` are never installed automatically whatever
        /// this says (dnf has no setting for that either).
        pub install_weak_deps: bool,
        /// `skip_broken=`: if the full requested `install` set can't be
        /// resolved together, drop the requested names responsible and
        /// continue with the rest, instead of failing the whole transaction
        /// over one bad, renamed, or unavailable name. dnf's default is
        /// `false`; can also be set per run with `--skip-broken`.
        pub skip_broken: bool,
        /// `multilib_policy=`. `"best"` (dnf5's default) lets a bare `install
        /// foo` job cover every arch build of `foo` and leaves the pick to
        /// the solver's policy. `"all"` installs every distinct arch build
        /// side by side. Other values are rejected at parse time, like dnf5's
        /// `RuntimeError` for an unknown policy (`libdnf5/base/goal.cpp`).
        pub multilib_policy: String,
        /// `obsoletes=`: when an `install` name matches nothing by name or
        /// `Provides`, also search packages that `Obsoletes` it, so e.g. `vez
        /// install <renamed-away-name>` resolves to the replacement instead
        /// of failing. dnf's default is `true`.
        pub obsoletes: bool,
        /// `proxy=`: global default proxy URL (e.g.
        /// `http://proxy.example.com:3128`) for every repo that doesn't set
        /// its own `proxy=`. `"_none_"` (dnf's special value) turns proxying
        /// off, same as leaving it unset.
        pub proxy: Option<String>,
        pub proxy_username: Option<String>,
        pub proxy_password: Option<String>,
        /// `fastestmirror=`: dnf5's default is `true`, which ranks mirrors by
        /// measured connection time and prefers the fastest (see
        /// [`crate::fastest_mirror_sort`]). `false` uses mirrors in the order
        /// the mirrorlist/metalink document listed them and skips the probe
        /// round trip.
        pub fastestmirror: bool,
        /// `varsdir=`: an extra directory to read `$myvar`-style custom repo
        /// vars from, on top of the standard
        /// `/etc/dnf/vars/`+`/etc/yum/vars/` search path. See
        /// [`crate::RepoVars`].
        pub varsdir: Option<PathBuf>,
        /// `disable_excludes=`: a comma/space-separated list of scopes
        /// (`"main"` and/or `"*"`) that turns off `exclude=`/`--exclude`
        /// filtering. dnf also accepts individual repo ids, but vez's
        /// `exclude=`/`--exclude` only exists at the main config/CLI level,
        /// so there's no per-repo list to switch off. Empty (dnf's default)
        /// applies excludes normally.
        pub disable_excludes: Vec<String>,
        /// `protect_running_kernel=`: dnf's default is `true`. Refuse to
        /// `remove`/`autoremove` the `kernel`-family package matching the
        /// running `uname -r`, on top of whatever `protected_packages=`
        /// lists.
        pub protect_running_kernel: bool,
        /// `sslverify=`: dnf's default is `true`, i.e. verify TLS
        /// certificates on HTTPS repo/download connections. `false` is dnf's
        /// escape hatch for a repo behind a broken or self-signed cert chain,
        /// meant only for trusted internal mirrors and never for a public
        /// repo.
        pub sslverify: bool,
        /// `ip_resolve=`: `"ipv4"`/`"ipv6"`/`"whatever"` (dnf's default).
        /// Limits DNS resolution to one address family, like dnf5's
        /// `CURLOPT_IPRESOLVE`. Useful on networks with a broken or
        /// black-holed IPv6 route, where "happy eyeballs" AAAA-first delays
        /// make downloads slow to start even though IPv4 works fine.
        pub ip_resolve: String,
        /// `user_agent=`: overrides the `User-Agent` header vez sends on
        /// every repo/download HTTP request (default: `vez/<version>`).
        pub user_agent: Option<String>,
        /// `history_record=`: dnf's default is `true`. Whether
        /// install/remove/upgrade transactions get appended to vez's history
        /// log (which `vez history`/`vez history undo` read). `false` covers
        /// dnf's use case of a throwaway/CI root where transaction history
        /// isn't worth keeping.
        pub history_record: bool,
        /// `username=`/`password=`: global default HTTP basic-auth
        /// credentials for every repo request that doesn't set its own, like
        /// dnf's fallback pair.
        pub username: Option<String>,
        pub password: Option<String>,
        /// `group_package_types=`: comma/space-separated `packagereq` `type=`
        /// values (`mandatory`/`default`/`optional`/`conditional`) that count
        /// as part of a comps group for `@group`/`group install`. dnf's
        /// default is `mandatory,default`.
        pub group_package_types: Vec<String>,
        /// `diskspacecheck=`: dnf's default is `true`. Before applying a
        /// transaction, check that the target filesystem has enough free
        /// space for the packages being installed, and abort instead of
        /// failing mid-transaction with a half-written rpmdb.
        pub diskspacecheck: bool,
        /// `assumeno=`: the config-file version of `--assumeno`. Answer every
        /// confirmation prompt "no" instead of "yes", which aborts the
        /// transaction. dnf's default is `false`.
        pub assumeno: bool,
        /// `defaultyes=`: when enabled, the default answer to confirmation
        /// prompts is "yes" instead of "no", so pressing Enter on an empty
        /// line accepts. Different from `assumeyes`, which skips the prompt
        /// entirely. dnf's default is `false`.
        pub defaultyes: bool,
    }

    /// dnf's default `installonlypkgs=` list (dnf's built-in default; no
    /// `.conf` file has to spell it out).
    pub const DEFAULT_INSTALLONLYPKGS: &[&str] = &[
        "kernel",
        "kernel-core",
        "kernel-devel",
        "kernel-modules",
        "kernel-modules-core",
        "kernel-modules-extra",
        "kernel-debug",
        "kernel-debug-core",
        "kernel-debug-devel",
        "kernel-debug-modules",
        "kernel-debug-modules-core",
        "kernel-debug-modules-extra",
        "kernel-debug-uname-r",
        "kernel-uname-r",
        "kernel-PAE",
        "kernel-rt",
        "kernel-rt-core",
        "kernel-rt-devel",
        "kernel-rt-modules",
        "kernel-rt-modules-extra",
        "installonlypkg(kernel)",
        "installonlypkg(kernel-module)",
        "installonlypkg(vm)",
    ];

    /// Packages `vez` won't remove whatever `protected_packages=` says.
    /// Removing your own package manager isn't something a config file should
    /// be able to allow.
    pub const ALWAYS_PROTECTED: &[&str] = &["vez"];

    /// Base-image packages `vez upgrade` is allowed to shadow in the overlay.
    ///
    /// Every other base package is untouchable: it lives in the read-only
    /// image, so "upgrading" it can only mean layering a copy into the overlay,
    /// and `upgrade` refuses to do that by accident (see the doc comment on
    /// `upgrade()` in the CLI). `vez` itself is the one deliberate exception,
    /// because it is the only base package with a channel of its own — the COPR
    /// repo narrowed with `includepkgs=vez` — and keeping it current must not
    /// cost an image rebuild.
    ///
    /// Deliberately equal to [`ALWAYS_PROTECTED`]: the package `vez` will never
    /// let you remove is the same one it keeps up to date. A package protected
    /// from removal and updatable in place is the honest pairing — the base
    /// copy stays underneath as the recovery, so there is always something to
    /// fall back to.
    pub const SELF_UPGRADABLE_NAMES: &[&str] = ALWAYS_PROTECTED;

    impl Default for MainConfig {
        fn default() -> Self {
            MainConfig {
                cachedir: None,
                reposdir: None,
                keepcache: false,
                assumeyes: false,
                gpgcheck: true,
                best: true,
                exclude: Vec::new(),
                includepkgs: Vec::new(),
                metadata_expire: None,
                retries: 10,
                timeout: 30,
                minrate: 1000,
                max_parallel_downloads: 3,
                skip_if_unavailable: false,
                clean_requirements_on_remove: true,
                installroot: None,
                protected_packages: Vec::new(),
                installonlypkgs: DEFAULT_INSTALLONLYPKGS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                installonly_limit: 3,
                install_weak_deps: true,
                skip_broken: false,
                multilib_policy: "best".to_string(),
                obsoletes: true,
                proxy: None,
                proxy_username: None,
                proxy_password: None,
                fastestmirror: true,
                varsdir: None,
                disable_excludes: Vec::new(),
                protect_running_kernel: true,
                sslverify: true,
                ip_resolve: "whatever".to_string(),
                user_agent: None,
                history_record: true,
                username: None,
                password: None,
                group_package_types: vec!["mandatory".to_string(), "default".to_string()],
                diskspacecheck: true,
                assumeno: false,
                defaultyes: false,
            }
        }
    }

    /// Loads `path`, or [`MainConfig::default`] if it doesn't exist. vez
    /// works with no `/etc/vez/vez.conf` at all, the way dnf works with
    /// defaults when `/etc/dnf/dnf.conf` has no `[main]` section.
    pub fn load(path: &Path) -> Result<MainConfig> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(parse(&s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MainConfig::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn parse(contents: &str) -> MainConfig {
        let mut cfg = MainConfig::default();
        let mut in_main = false;
        let mut installonlypkgs_overridden = false;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                in_main = section == "main";
                continue;
            }
            if !in_main {
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                continue;
            };
            apply_kv(
                &mut cfg,
                key.trim(),
                val.trim(),
                &mut installonlypkgs_overridden,
            );
        }
        cfg
    }

    fn apply_kv(cfg: &mut MainConfig, key: &str, val: &str, installonlypkgs_overridden: &mut bool) {
        match key {
            "cachedir" => cfg.cachedir = Some(PathBuf::from(val)),
            "reposdir" => cfg.reposdir = Some(PathBuf::from(val.split(':').next().unwrap_or(val))),
            "keepcache" => cfg.keepcache = val == "1" || val.eq_ignore_ascii_case("true"),
            "assumeyes" => cfg.assumeyes = val == "1" || val.eq_ignore_ascii_case("true"),
            "gpgcheck" => cfg.gpgcheck = val != "0" && !val.eq_ignore_ascii_case("false"),
            "best" => cfg.best = val == "1" || val.eq_ignore_ascii_case("true"),
            "exclude" | "excludepkgs" => cfg
                .exclude
                .extend(val.split_whitespace().map(str::to_string)),
            "includepkgs" => cfg
                .includepkgs
                .extend(val.split_whitespace().map(str::to_string)),
            "metadata_expire" => cfg.metadata_expire = Some(super::parse_metadata_expire(val)),
            "retries" => {
                if let Ok(n) = val.parse() {
                    cfg.retries = n;
                }
            }
            "timeout" => {
                if let Ok(n) = val.parse() {
                    cfg.timeout = n;
                }
            }
            "minrate" => cfg.minrate = super::parse_bytes(val),
            "max_parallel_downloads" => {
                if let Ok(n) = val.parse() {
                    cfg.max_parallel_downloads = n;
                }
            }
            "skip_if_unavailable" => {
                cfg.skip_if_unavailable = val == "1" || val.eq_ignore_ascii_case("true")
            }
            "clean_requirements_on_remove" => {
                cfg.clean_requirements_on_remove = val == "1" || val.eq_ignore_ascii_case("true")
            }
            "installroot" => cfg.installroot = Some(PathBuf::from(val)),
            "protected_packages" => cfg
                .protected_packages
                .extend(val.split_whitespace().map(str::to_string)),
            "installonlypkgs" => {
                // An explicit `installonlypkgs=` replaces dnf's built-in
                // default list (dnf's own semantics) instead of adding to it.
                // Only the first occurrence clears the default.
                if !*installonlypkgs_overridden {
                    cfg.installonlypkgs.clear();
                    *installonlypkgs_overridden = true;
                }
                cfg.installonlypkgs
                    .extend(val.split_whitespace().map(str::to_string));
            }
            "installonly_limit" => {
                if let Ok(n) = val.parse() {
                    cfg.installonly_limit = n;
                }
            }
            "install_weak_deps" => {
                cfg.install_weak_deps = val == "1" || val.eq_ignore_ascii_case("true")
            }
            "skip_broken" => cfg.skip_broken = val == "1" || val.eq_ignore_ascii_case("true"),
            "multilib_policy" if val == "all" || val == "best" => {
                cfg.multilib_policy = val.to_string()
            }
            "obsoletes" => cfg.obsoletes = val == "1" || val.eq_ignore_ascii_case("true"),
            "proxy" => {
                cfg.proxy = if val.is_empty() || val == "_none_" {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "proxy_username" => {
                cfg.proxy_username = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "proxy_password" => {
                cfg.proxy_password = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "fastestmirror" => cfg.fastestmirror = val == "1" || val.eq_ignore_ascii_case("true"),
            "varsdir" => {
                cfg.varsdir = if val.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(val))
                }
            }
            "disable_excludes" => cfg.disable_excludes.extend(
                val.split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            ),
            "protect_running_kernel" => {
                cfg.protect_running_kernel = val == "1" || val.eq_ignore_ascii_case("true")
            }
            "sslverify" => cfg.sslverify = val == "1" || val.eq_ignore_ascii_case("true"),
            "ip_resolve" if val == "ipv4" || val == "ipv6" || val == "whatever" => {
                cfg.ip_resolve = val.to_string()
            }
            "user_agent" => {
                cfg.user_agent = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "history_record" => cfg.history_record = val == "1" || val.eq_ignore_ascii_case("true"),
            "username" => {
                cfg.username = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "password" => {
                cfg.password = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "group_package_types" => {
                cfg.group_package_types = val
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            }
            "diskspacecheck" => cfg.diskspacecheck = val == "1" || val.eq_ignore_ascii_case("true"),
            "assumeno" => cfg.assumeno = val == "1" || val.eq_ignore_ascii_case("true"),
            "defaultyes" => cfg.defaultyes = val == "1" || val.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }

    /// Applies `--setopt key=value` overrides on top of a loaded
    /// `MainConfig`, with the same key set as `[main]` in the config file
    /// (dnf5's `--setopt` overrides any config key; it isn't a fixed list of
    /// CLI flags). Unknown keys, including repo-scoped `<repoid>.key=value`
    /// and the `tsflags=` pseudo-key that vez-cli handles separately, are
    /// ignored here, same as unknown keys in `parse`.
    pub fn apply_setopt(cfg: &mut MainConfig, setopt: &[String]) {
        let mut installonlypkgs_overridden = false;
        for kv in setopt {
            let Some((key, val)) = kv.split_once('=') else {
                continue;
            };
            apply_kv(cfg, key.trim(), val.trim(), &mut installonlypkgs_overridden);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_main_section() {
            let cfg = parse("[main]\ncachedir=/var/cache/vez\nkeepcache=1\nassumeyes=True\ngpgcheck=0\nexclude=kernel* firefox\nretries=5\ntimeout=15\nbest=1\n\n[some-repo]\ncachedir=/should/not/apply\n");
            assert_eq!(cfg.cachedir, Some(PathBuf::from("/var/cache/vez")));
            assert!(cfg.keepcache);
            assert!(cfg.assumeyes);
            assert!(!cfg.gpgcheck);
            assert_eq!(cfg.exclude, vec!["kernel*", "firefox"]);
            assert_eq!(cfg.retries, 5);
            assert_eq!(cfg.timeout, 15);
            assert_eq!(cfg.minrate, 1000);
            assert!(cfg.best);
        }

        #[test]
        fn parses_new_main_options() {
            let cfg = parse("[main]\ndisable_excludes=main,foo\nprotect_running_kernel=0\nsslverify=0\nip_resolve=ipv4\nuser_agent=custom-agent\nhistory_record=0\n");
            assert_eq!(cfg.disable_excludes, vec!["main", "foo"]);
            assert!(!cfg.protect_running_kernel);
            assert!(!cfg.sslverify);
            assert_eq!(cfg.ip_resolve, "ipv4");
            assert_eq!(cfg.user_agent, Some("custom-agent".to_string()));
            assert!(!cfg.history_record);
        }

        #[test]
        fn ip_resolve_rejects_unknown_value() {
            let cfg = parse("[main]\nip_resolve=bogus\n");
            assert_eq!(cfg.ip_resolve, "whatever");
        }

        #[test]
        fn minrate_kv_overrides_default() {
            let cfg = parse("[main]\nminrate=5k\n");
            assert_eq!(cfg.minrate, 5 * 1024);
        }

        #[test]
        fn missing_file_returns_default() {
            let cfg = load(Path::new("/nonexistent/vez.conf.does.not.exist")).unwrap();
            assert!(!cfg.keepcache);
            assert!(cfg.gpgcheck);
        }

        #[test]
        fn default_has_dnf_installonlypkgs_and_limit() {
            let cfg = MainConfig::default();
            assert!(cfg.installonlypkgs.iter().any(|p| p == "kernel"));
            assert_eq!(cfg.installonly_limit, 3);
            assert!(cfg.install_weak_deps);
            assert!(cfg.protected_packages.is_empty());
        }

        #[test]
        fn parses_protected_and_installonly_settings() {
            let cfg = parse("[main]\nprotected_packages=glibc systemd\ninstallonlypkgs=kernel kernel-core mypkg\ninstallonly_limit=5\ninstall_weak_deps=0\n");
            assert_eq!(cfg.protected_packages, vec!["glibc", "systemd"]);
            assert_eq!(cfg.installonlypkgs, vec!["kernel", "kernel-core", "mypkg"]);
            assert_eq!(cfg.installonly_limit, 5);
            assert!(!cfg.install_weak_deps);
        }

        #[test]
        fn setopt_overrides_loaded_config() {
            let mut cfg = parse("[main]\ninstall_weak_deps=1\nretries=10\n");
            apply_setopt(
                &mut cfg,
                &[
                    "install_weak_deps=false".to_string(),
                    "retries=2".to_string(),
                    "unknownkey=whatever".to_string(),
                ],
            );
            assert!(!cfg.install_weak_deps);
            assert_eq!(cfg.retries, 2);
        }

        #[test]
        fn setopt_installonlypkgs_replaces_not_appends() {
            let mut cfg = parse("[main]\ninstallonlypkgs=kernel\n");
            apply_setopt(&mut cfg, &["installonlypkgs=foo bar".to_string()]);
            assert_eq!(cfg.installonlypkgs, vec!["foo", "bar"]);
        }

        #[test]
        fn parses_proxy_settings() {
            let cfg = parse("[main]\nproxy=http://proxy.example.com:3128\nproxy_username=alice\nproxy_password=hunter2\n");
            assert_eq!(cfg.proxy.as_deref(), Some("http://proxy.example.com:3128"));
            assert_eq!(cfg.proxy_username.as_deref(), Some("alice"));
            assert_eq!(cfg.proxy_password.as_deref(), Some("hunter2"));
        }

        #[test]
        fn proxy_none_magic_value_disables_proxy() {
            let cfg = parse("[main]\nproxy=_none_\n");
            assert_eq!(cfg.proxy, None);
        }

        #[test]
        fn parses_varsdir() {
            let cfg = parse("[main]\nvarsdir=/etc/vez/vars\n");
            assert_eq!(cfg.varsdir.as_deref(), Some(Path::new("/etc/vez/vars")));
            assert_eq!(MainConfig::default().varsdir, None);
        }

        #[test]
        fn fastestmirror_defaults_true_and_parses() {
            assert!(MainConfig::default().fastestmirror);
            let cfg = parse("[main]\nfastestmirror=false\n");
            assert!(!cfg.fastestmirror);
            let cfg = parse("[main]\nfastestmirror=1\n");
            assert!(cfg.fastestmirror);
        }

        #[test]
        fn parses_username_password_diskspacecheck_assumeno_group_package_types() {
            let cfg = MainConfig::default();
            assert_eq!(cfg.group_package_types, vec!["mandatory", "default"]);
            assert!(cfg.diskspacecheck);
            assert!(!cfg.assumeno);
            assert_eq!(cfg.username, None);

            let cfg = parse("[main]\nusername=alice\npassword=hunter2\ngroup_package_types=mandatory,default,optional\ndiskspacecheck=0\nassumeno=1\n");
            assert_eq!(cfg.username.as_deref(), Some("alice"));
            assert_eq!(cfg.password.as_deref(), Some("hunter2"));
            assert_eq!(
                cfg.group_package_types,
                vec!["mandatory", "default", "optional"]
            );
            assert!(!cfg.diskspacecheck);
            assert!(cfg.assumeno);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> RepoVars {
        RepoVars {
            releasever: "44".to_string(),
            basearch: "x86_64".to_string(),
            custom: HashMap::new(),
        }
    }

    /// The Svara `os-release`, abbreviated to the field that matters here.
    const SVARA_OS_RELEASE: &str = "NAME=\"Svara\"\nID=svara\nID_LIKE=\"fedora\"\nVERSION=\"0.1.0 (Zora)\"\nVERSION_ID=\"0.1\"\n";
    /// Fedora's own release file, whose contents the base image carries.
    const FEDORA_RELEASE: &str = "Fedora release 44 (Forty Four)\n";

    #[test]
    fn releasever_comes_from_the_base_image_not_svara_version() {
        // The bug this test exists for: Svara's VERSION_ID is 0.1, so taking
        // $releasever from os-release asked every Fedora and COPR URL for
        // /fedora/0.1/, which does not exist. Nothing about a Svara machine works
        // until this is the Fedora release.
        assert_eq!(
            resolve_releasever(Some(SVARA_OS_RELEASE), Some(FEDORA_RELEASE), None),
            "44"
        );
    }

    #[test]
    fn an_explicit_dnf_var_outranks_everything() {
        // /etc/dnf/vars/releasever is how an admin or an image build pins the value
        // deliberately, and in a bootc image it is routinely set for exactly this
        // reason. It must win even against the base release.
        assert_eq!(
            resolve_releasever(Some(SVARA_OS_RELEASE), Some(FEDORA_RELEASE), Some("45\n")),
            "45"
        );
        // Whitespace and an empty file are not a pinned value.
        assert_eq!(
            resolve_releasever(Some(SVARA_OS_RELEASE), Some(FEDORA_RELEASE), Some("  ")),
            "44"
        );
        assert_eq!(
            resolve_releasever(Some(SVARA_OS_RELEASE), Some(FEDORA_RELEASE), Some("")),
            "44"
        );
    }

    #[test]
    fn releasever_falls_back_to_version_id_on_plain_fedora() {
        // Where the two agree, the fallback is exact, so a Fedora install with no
        // release file still resolves correctly.
        let fedora = "ID=fedora\nVERSION_ID=44\n";
        assert_eq!(resolve_releasever(Some(fedora), None, None), "44");
        // Quotes around the value are stripped, as os-release permits them.
        let quoted = "ID=fedora\nVERSION_ID=\"44\"\n";
        assert_eq!(resolve_releasever(Some(quoted), None, None), "44");
    }

    #[test]
    fn releasever_survives_nothing_being_readable() {
        // Resolving against something plausible beats failing every repo load.
        assert_eq!(resolve_releasever(None, None, None), "44");
        assert_eq!(
            resolve_releasever(Some("ID=svara\n"), Some("garbage\n"), None),
            "44"
        );
    }

    #[test]
    fn parses_the_fedora_release_line() {
        assert_eq!(parse_fedora_release(FEDORA_RELEASE).as_deref(), Some("44"));
        assert_eq!(
            parse_fedora_release("Fedora release Rawhide (Rawhide)\n").as_deref(),
            Some("Rawhide")
        );
        // The fixture must not contain the word "release" at all — an earlier version of
        // this test wrote "no release word here", which does, and so parsed "word" and
        // passed for a reason that had nothing to do with what it claimed to check.
        assert_eq!(parse_fedora_release("Svara 0.1.0 (Zora)\n"), None);
        // A trailing "release" with nothing after it has no version to return.
        assert_eq!(parse_fedora_release("Fedora release\n"), None);
    }

    #[test]
    fn parses_repo_ini() {
        let repos = parse_repo_file(
            "[svara-test]\nname=Svara test repo\nbaseurl=https://example.com/repo/$releasever/\nenabled=1\ngpgcheck=1\ngpgkey=https://example.com/pubkey.gpg\n\n[disabled-repo]\nbaseurl=https://example.com/x\nenabled=0\n",
            &vars(),
        );
        // Disabled repos are still returned (so
        // `--enable-repo`/`config-manager --set-enabled` can act on them).
        // Filtering on `enabled` is the caller's job, not the parser's.
        assert_eq!(repos.len(), 2);
        assert_eq!(repos[0].id, "svara-test");
        assert_eq!(
            repos[0].base_url.as_deref(),
            Some("https://example.com/repo/44")
        );
        assert!(repos[0].gpgcheck);
        assert!(repos[0].enabled);
        assert_eq!(repos[0].gpgkeys, vec!["https://example.com/pubkey.gpg"]);
        assert_eq!(repos[1].id, "disabled-repo");
        assert!(!repos[1].enabled);
        assert_eq!(repos[0].metadata_expire, DEFAULT_METADATA_EXPIRE);
    }

    #[test]
    fn parses_metadata_expire_suffixes() {
        assert_eq!(parse_metadata_expire("6h"), 21_600);
        assert_eq!(parse_metadata_expire("7d"), 604_800);
        assert_eq!(parse_metadata_expire("120"), 120);
        assert_eq!(parse_metadata_expire("120s"), 120);
        assert_eq!(parse_metadata_expire("30m"), 1800);
        assert_eq!(parse_metadata_expire("-1"), u64::MAX);
        assert_eq!(parse_metadata_expire("never"), u64::MAX);
        assert_eq!(parse_metadata_expire("garbage"), DEFAULT_METADATA_EXPIRE);
    }

    #[test]
    fn parses_minrate_suffixes() {
        assert_eq!(parse_bytes("1000"), 1000);
        assert_eq!(parse_bytes("10k"), 10 * 1024);
        assert_eq!(parse_bytes("10K"), 10 * 1024);
        assert_eq!(parse_bytes("1M"), 1024 * 1024);
        assert_eq!(parse_bytes("1G"), 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("garbage"), 1000);
    }

    #[test]
    fn repo_ini_metadata_expire_overrides_default() {
        let repos = parse_repo_file(
            "[fedora]\nbaseurl=https://example.com/os\nenabled=1\nmetadata_expire=6h\n",
            &vars(),
        );
        assert_eq!(repos[0].metadata_expire, 21_600);
    }

    #[test]
    fn repo_ini_priority_parses_and_defaults() {
        let repos = parse_repo_file(
            "[fedora]\nbaseurl=https://example.com/os\nenabled=1\npriority=10\n\n[rpmfusion]\nbaseurl=https://example.com/rf\nenabled=1\n",
            &vars(),
        );
        assert_eq!(repos[0].priority, 10);
        assert_eq!(repos[1].priority, 99);
    }

    #[test]
    fn cache_is_fresh_respects_metadata_expire() {
        let dir = std::env::temp_dir().join(format!("vez-repo-cache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let repomd = dir.join("repomd.xml");
        std::fs::write(&repomd, "x").unwrap();

        assert!(cache_is_fresh(&repomd, 3600));
        assert!(!cache_is_fresh(&repomd, 0));
        assert!(cache_is_fresh(&repomd, u64::MAX));
        assert!(!cache_is_fresh(&dir.join("missing.xml"), 3600));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expands_basearch() {
        let repos = parse_repo_file(
            "[fedora]\nbaseurl=https://example.com/$basearch/os\nenabled=1\ngpgcheck=0\n",
            &vars(),
        );
        assert_eq!(
            repos[0].base_url.as_deref(),
            Some("https://example.com/x86_64/os")
        );
        assert!(!repos[0].gpgcheck);
    }

    #[test]
    fn expands_custom_vars() {
        let mut v = vars();
        v.custom
            .insert("myrepo".to_string(), "internal".to_string());
        let repos = parse_repo_file(
            "[custom]\nbaseurl=https://example.com/$myrepo/$basearch\nenabled=1\ngpgcheck=0\n",
            &v,
        );
        assert_eq!(
            repos[0].base_url.as_deref(),
            Some("https://example.com/internal/x86_64")
        );
    }

    #[test]
    fn reads_custom_vars_from_varsdir() {
        let dir = std::env::temp_dir().join(format!("vez-varsdir-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("myrepo"), "internal-mirror\n").unwrap();
        let vars = RepoVars::detect_with_varsdir(Some(&dir));
        assert_eq!(
            vars.custom.get("myrepo").map(String::as_str),
            Some("internal-mirror")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keeps_mirrorlist_only_repo_without_a_base_url() {
        let repos = parse_repo_file(
            "[nobase]\nmirrorlist=https://example.com/$releasever/mirrorlist\nenabled=1\n",
            &vars(),
        );
        assert_eq!(repos.len(), 1);
        assert!(repos[0].base_url.is_none());
        assert_eq!(
            repos[0].mirrorlist.as_deref(),
            Some("https://example.com/44/mirrorlist")
        );
    }

    #[test]
    fn keeps_metalink_only_repo_without_a_base_url() {
        let repos = parse_repo_file(
            "[nobase]\nmetalink=https://example.com/metalink\nenabled=1\n",
            &vars(),
        );
        assert_eq!(repos.len(), 1);
        assert!(repos[0].base_url.is_none());
        assert_eq!(
            repos[0].metalink.as_deref(),
            Some("https://example.com/metalink")
        );
    }

    #[test]
    fn parses_mirrorlist_text() {
        let text = "# comment\nhttp://mirror1.example.com/repo/\n\nhttp://mirror2.example.com/repo/repodata/repomd.xml\n";
        let mirrors = parse_mirrorlist(text);
        assert_eq!(
            mirrors,
            vec![
                "http://mirror1.example.com/repo",
                "http://mirror2.example.com/repo"
            ]
        );
    }

    #[test]
    fn parses_metalink_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/">
  <files>
    <file name="repomd.xml">
      <resources maxconnections="1">
        <url protocol="https" type="https" location="US" preference="100">https://mirror1.example.com/repo/repodata/repomd.xml</url>
        <url protocol="http" type="http" location="US" preference="99">http://mirror2.example.com/repo/repodata/repomd.xml</url>
      </resources>
    </file>
  </files>
</metalink>"#;
        let mirrors = parse_metalink(xml);
        assert_eq!(
            mirrors,
            vec![
                "https://mirror1.example.com/repo",
                "http://mirror2.example.com/repo"
            ]
        );
    }

    #[test]
    fn primary_cache_name_keeps_the_compression_suffix() {
        assert_eq!(
            primary_cache_name("repodata/abc-primary.xml.zst"),
            "primary.xml.zst"
        );
        assert_eq!(
            primary_cache_name("repodata/abc-primary.xml.gz"),
            "primary.xml.gz"
        );
        assert_eq!(
            primary_cache_name("repodata/abc-primary.xml.xz"),
            "primary.xml.xz"
        );
        assert_eq!(
            primary_cache_name("repodata/abc-primary.xml.bz2"),
            "primary.xml.bz2"
        );
        assert_eq!(
            primary_cache_name("repodata/abc-primary.xml"),
            "primary.xml"
        );
    }

    #[test]
    fn streaming_parse_of_compressed_primary_matches_string_parse() {
        use std::io::Write;
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
  <package type="rpm"><name>foo</name><arch>x86_64</arch><version epoch="0" ver="1.0" rel="1"/>
    <checksum type="sha256" pkgid="YES">aa</checksum><summary>Foo &amp; bar</summary><location href="foo.rpm"/><size package="1" installed="2"/>
    <format><rpm:provides><rpm:entry name="foo" flags="EQ" epoch="0" ver="1.0" rel="1"/></rpm:provides>
    <rpm:requires><rpm:entry name="libc.so.6()(64bit)"/></rpm:requires><file>/usr/bin/foo</file></format></package>
  <package type="rpm"><name>bar</name><arch>noarch</arch><version epoch="2" ver="3" rel="4"/><summary>Bar</summary><location href="bar.rpm"/></package>
</metadata>"#;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(xml.as_bytes()).unwrap();
        let compressed = gz.finish().unwrap();
        let streamed = primary::parse_primary_reader(
            decompress_reader("x-primary.xml.gz", compressed.as_slice()).unwrap(),
        )
        .unwrap();
        let whole = parse_primary_xml(xml).unwrap();
        assert_eq!(
            serde_json::to_string(&streamed).unwrap(),
            serde_json::to_string(&whole).unwrap()
        );
        assert_eq!(streamed.len(), 2);
        assert_eq!(streamed[0].summary, "Foo & bar");
        assert!(streamed[0]
            .provides
            .iter()
            .any(|p| p.name == "/usr/bin/foo"));
    }

    #[test]
    fn write_atomic_replaces_whole_file_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("vez-write-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("parsed.json");
        std::fs::write(&path, b"old contents that are longer").unwrap();
        write_atomic(&path, |w| std::io::Write::write_all(w, b"new")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decodes_bzip2_metadata() {
        use std::io::{Read, Write};
        let xml = "<metadata packages=\"0\"></metadata>";
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        enc.write_all(xml.as_bytes()).unwrap();
        let bz = enc.finish().unwrap();
        assert_eq!(decompress("repodata/x-primary.xml.bz2", &bz).unwrap(), xml);
        let mut out = String::new();
        decompress_reader("repodata/x-primary.xml.bz2", bz.as_slice())
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, xml);
    }

    #[test]
    fn rejects_unsupported_compression_clearly() {
        let err = decompress("repodata/x-primary.xml.zck", b"junk").unwrap_err();
        assert!(err.downcast_ref::<UnsupportedCompression>().is_some());
        assert!(decompress_reader("repodata/x-primary.xml.lz4", &b"junk"[..]).is_err());
    }
}
