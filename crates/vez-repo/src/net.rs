//! A retrying `GET`, shared by every crate that talks to a repo or mirror
//! over HTTP (`vez-repo` itself, the downloads and gpg-key fetch in
//! `vez-transaction`, `vez-repo::copr`).
//!
//! Plain `reqwest` never retries a failed `send()`, which made `vez` much
//! more fragile than dnf/libdnf (default `retries=10`) against the error we
//! actually saw: "connection closed before message completed" from a pooled
//! keep-alive connection the remote end had already closed when `reqwest`
//! tried to reuse it. That's a common, harmless race in HTTP connection
//! pooling and doesn't mean the mirror or network is down. One retry after a
//! short backoff clears it in practice.
//!
//! Every transfer here goes through [`vez_librepo`] (real librepo, the C
//! library dnf5 links) instead of hand-rolled curl calls. This module only
//! owns the retry loop, the `.part`-file/resume bookkeeping, and checksum
//! verification around it, the same split `libdnf5`'s `repo_downloader.cpp`
//! has on top of its librepo calls.

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

const DEFAULT_MAX_ATTEMPTS: u32 = 4;
const DEFAULT_STALL_TIMEOUT_SECS: u32 = 30;

/// Process-wide attempt count, set once from `vez.conf`'s `retries=` (dnf's
/// default is 10) through [`set_max_attempts`]. Every crate that calls
/// [`get_with_retry`] (`vez-repo` itself, the downloads and gpg-key fetch in
/// `vez-transaction`, `vez-repo::copr`) shares this one setting so `retries=`
/// doesn't have to be threaded through every signature.
static MAX_ATTEMPTS: AtomicU32 = AtomicU32::new(DEFAULT_MAX_ATTEMPTS);

/// Process-wide stall timeout in seconds, set once from `vez.conf`'s
/// `timeout=` through [`set_stall_timeout`]. It applies per chunk in
/// [`get_bytes_with_retry`] instead of as a whole-request `reqwest` timeout,
/// so a large package isn't killed just for taking a while. Only a connection
/// that has been silent this long gets aborted.
static STALL_TIMEOUT_SECS: AtomicU32 = AtomicU32::new(DEFAULT_STALL_TIMEOUT_SECS);

/// Process-wide `minrate=` (bytes/sec), set once from `vez.conf` through
/// [`set_minrate`]. Defaults to dnf's `minrate=` default of 1000 B/s. It maps
/// to librepo's `LRO_LOWSPEEDLIMIT`/`LRO_LOWSPEEDTIME` pair (dnf5's
/// `librepo.cpp` sets the same two options): a transfer averaging below
/// `minrate` bytes/sec over a `timeout`-second window counts as stalled, even
/// if it isn't completely silent. `0` turns the throughput check off.
static MINRATE: AtomicU64 = AtomicU64::new(1000);

/// Process-wide `fastestmirror=` toggle, set once from `vez.conf` through
/// [`set_fastestmirror`]. dnf5 defaults to `true`. When `false`,
/// [`fastest_mirror_sort`] skips its connect-time race and mirrors are used
/// in the order the mirrorlist/metalink document listed them.
static FASTEST_MIRROR: AtomicBool = AtomicBool::new(true);

/// Sets the [`FASTEST_MIRROR`] toggle. Call once at startup after loading
/// `vez.conf`.
pub fn set_fastestmirror(enabled: bool) {
    FASTEST_MIRROR.store(enabled, Ordering::Relaxed);
}

/// Proxy/auth/TLS-client settings applied to every librepo handle created
/// while in scope. This is the per-repo/per-call counterpart of `vez.conf`'s
/// global `proxy=`/`proxy_username=`/`proxy_password=` (already parsed into
/// `MainConfig`, see `vez-cli/src/main.rs`) plus the per-section `.repo`
/// options dnf supports: `proxy=`/`username=`/`password=`/`sslcacert=`/
/// `sslclientcert=`/`sslclientkey=` (`RepoConfig`). Same model as dnf5:
/// `librepo.cpp` sets these six `LRO_*` options from `ConfigRepo`, which
/// falls back to `ConfigMain`'s global proxy when a repo doesn't set its own
/// (`OptionChild` inheritance in `config_repo.cpp`).
#[derive(Clone, Default, Debug)]
pub struct NetOptions {
    pub proxy: Option<String>,
    /// `"user:pass"`, already combined, the format `LRO_PROXYUSERPWD`
    /// expects.
    pub proxy_userpwd: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub sslcacert: Option<String>,
    pub sslclientcert: Option<String>,
    pub sslclientkey: Option<String>,
}

impl NetOptions {
    /// Fills any field left `None` here from `default_net_options()`, the
    /// global (`vez.conf`) fallback a repo-level [`NetOptions`] inherits when
    /// it doesn't set a value. Same precedence dnf5's `OptionChild<T>` gives
    /// `ConfigRepo` over `ConfigMain`.
    pub fn or_default(self) -> NetOptions {
        let def = default_net_options();
        NetOptions {
            proxy: self.proxy.or(def.proxy),
            proxy_userpwd: self.proxy_userpwd.or(def.proxy_userpwd),
            username: self.username.or(def.username),
            password: self.password.or(def.password),
            sslcacert: self.sslcacert.or(def.sslcacert),
            sslclientcert: self.sslclientcert.or(def.sslclientcert),
            sslclientkey: self.sslclientkey.or(def.sslclientkey),
        }
    }
}

static DEFAULT_NET_OPTIONS: std::sync::OnceLock<std::sync::RwLock<NetOptions>> =
    std::sync::OnceLock::new();

fn default_net_options_lock() -> &'static std::sync::RwLock<NetOptions> {
    DEFAULT_NET_OPTIONS.get_or_init(|| std::sync::RwLock::new(NetOptions::default()))
}

/// Sets the process-wide default [`NetOptions`]. Call once at startup with
/// `vez.conf`'s `[main]` proxy settings, like [`set_fastestmirror`] and the
/// others. Per-repo overrides (see [`with_net_options`]) still fall back to
/// this through [`NetOptions::or_default`].
pub fn set_default_net_options(opts: NetOptions) {
    *default_net_options_lock().write().unwrap() = opts;
}

pub fn default_net_options() -> NetOptions {
    default_net_options_lock().read().unwrap().clone()
}

tokio::task_local! {
    /// The [`NetOptions`] in effect for librepo handles created by the
    /// current async task, set through [`with_net_options`].
    /// [`current_net_options`] uses `try_with` instead of `with` because most
    /// call sites never set an override and should fall back to
    /// [`default_net_options`].
    static NET_OPTIONS: NetOptions;
}

/// Runs `fut` with `opts` as the effective [`NetOptions`] for every librepo
/// handle it creates, directly or through any `vez-repo` network call.
/// [`load_repo`](crate::load_repo) and `vez-transaction`'s package downloads
/// use this to apply a repo's `proxy=`/`username=`/`sslclientcert=` etc.
/// without threading a `NetOptions` parameter through every function in
/// between. It's task-local instead of thread-local so it survives `.await`
/// points in the same task (a `tokio` worker thread can switch to an
/// unrelated task between polls, which would break a thread-local). Each
/// `spawn_blocking` closure that builds a handle captures it by value, since
/// the blocking thread can't read the task-local.
pub async fn with_net_options<F: std::future::Future>(opts: NetOptions, fut: F) -> F::Output {
    NET_OPTIONS.scope(opts, fut).await
}

fn current_net_options() -> NetOptions {
    NET_OPTIONS
        .try_with(|o| o.clone())
        .unwrap_or_else(|_| default_net_options())
}

/// Reads the current [`FASTEST_MIRROR`] toggle.
pub fn fastestmirror_enabled() -> bool {
    FASTEST_MIRROR.load(Ordering::Relaxed)
}

/// Sets the attempt count [`get_with_retry`] uses from now on. Call once at
/// startup after loading `vez.conf`. `retries=0` would mean "never try at
/// all", which makes no sense as a retry count, so it's floored at 1.
pub fn set_max_attempts(retries: u32) {
    MAX_ATTEMPTS.store(retries.max(1), Ordering::Relaxed);
}

/// Sets the per-chunk stall timeout [`get_bytes_with_retry`] uses from now
/// on. Call once at startup after loading `vez.conf`. `timeout=0` would mean
/// "abort unless a chunk is already buffered", which is never useful, so it's
/// floored at 1.
pub fn set_stall_timeout(secs: u64) {
    STALL_TIMEOUT_SECS.store((secs.max(1)).min(u32::MAX as u64) as u32, Ordering::Relaxed);
}

/// Sets the [`MINRATE`] throughput floor used by [`get_bytes_with_retry`] and
/// [`download_to_file_with_retry_ex`] from now on. Call once at startup after
/// loading `vez.conf`.
pub fn set_minrate(bytes_per_sec: u64) {
    MINRATE.store(bytes_per_sec, Ordering::Relaxed);
}

/// A fully buffered HTTP response from [`get_with_retry`]; it isn't a
/// `reqwest::Response`. Metadata, mirrorlist, and GPG-key fetches go through
/// librepo (like the package downloads in [`download_to_file_with_retry_ex`]
/// and like dnf5; see that function's doc comment). librepo only has a
/// synchronous API, so this runs inside `spawn_blocking` and returns a body
/// that's already fully read instead of a streaming response object.
/// `bytes()`/`text()` are still `async fn` only so existing call sites
/// (written against `reqwest::Response`) can keep their `.await`.
pub struct HttpResponse {
    pub status: u32,
    body: Vec<u8>,
}

impl HttpResponse {
    /// Same contract as `reqwest::Response::error_for_status`: turns a
    /// >=400 status into an `Err`, otherwise passes `self` through
    /// unchanged.
    pub fn error_for_status(self) -> Result<Self> {
        if self.status >= 400 {
            anyhow::bail!(HttpStatusError {
                status: self.status
            });
        }
        Ok(self)
    }

    pub async fn bytes(self) -> Result<Vec<u8>> {
        Ok(self.body)
    }

    pub async fn text(self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.body).into_owned())
    }
}

fn new_handle(
    stall_timeout_secs: u64,
    minrate: u64,
    net_opts: &NetOptions,
) -> Result<vez_librepo::Handle> {
    let handle = vez_librepo::Handle::new(
        concat!("vez/", env!("CARGO_PKG_VERSION")),
        30,
        minrate,
        stall_timeout_secs,
    )
    .context("initializing librepo handle")?;
    handle.set_proxy(net_opts.proxy.as_deref(), net_opts.proxy_userpwd.as_deref())?;
    handle.set_credentials(net_opts.username.as_deref(), net_opts.password.as_deref())?;
    handle.set_tls_client(
        net_opts.sslcacert.as_deref(),
        net_opts.sslclientcert.as_deref(),
        net_opts.sslclientkey.as_deref(),
    )?;
    Ok(handle)
}

/// Ranks `mirrors` fastest-first with librepo's `lr_fastestmirror` (a real
/// TCP connect-time race per mirror,
/// [`vez_librepo::Handle::fastest_mirror_sort`]), the same mechanism dnf5
/// uses (`LRO_FASTESTMIRROR`/`LRO_FASTESTMIRRORCACHE` in
/// `libdnf5/repo/repo_downloader.cpp`). `cache_path` should be one path
/// shared by every repo (dnf5 uses `<basecachedir>/fastestmirror.cache`, not
/// a file per repo), so a mirror measured once helps every repo that shares
/// it, and results last for `LRO_FASTESTMIRRORMAXAGE` (30 days, librepo's
/// default, which this crate doesn't override). On any failure it returns
/// `mirrors` unchanged; the download doesn't need the ranking to succeed.
pub async fn fastest_mirror_sort(
    mirrors: Vec<String>,
    cache_path: std::path::PathBuf,
) -> Vec<String> {
    if mirrors.len() <= 1 || !fastestmirror_enabled() {
        return mirrors;
    }
    let original = mirrors.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
        let handle =
            vez_librepo::Handle::new(concat!("vez/", env!("CARGO_PKG_VERSION")), 30, 0, 30)
                .context("initializing librepo handle")?;
        handle
            .set_fastestmirror(true, cache_path.to_str())
            .context("setting LRO_FASTESTMIRROR")?;
        handle.fastest_mirror_sort(&mirrors)
    })
    .await;
    match result {
        Ok(Ok(ranked)) => ranked,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "fastest-mirror ranking failed, using unranked mirror order");
            original
        }
        Err(e) => {
            tracing::debug!(error = %e, "fastest-mirror ranking task panicked, using unranked mirror order");
            original
        }
    }
}

/// A librepo failure turned into an HTTP-style status when librepo's `GError`
/// message names one (see [`vez_librepo::parse_http_status`]). That lets the
/// shared retry loop below keep its permanent-vs-transient split (4xx other
/// than 429 is permanent, everything else transient) without caring that it's
/// librepo underneath and not curl.
fn classify_librepo_error(e: anyhow::Error) -> anyhow::Error {
    let msg = e.to_string();
    match vez_librepo::parse_http_status(&msg) {
        Some(status) => anyhow::Error::new(HttpStatusError { status }).context(msg),
        None => e,
    }
}

/// One single-stream librepo `GET url` attempt that buffers the whole body in
/// memory. The documents this is used for (repomd.xml, compressed
/// primary.xml, a PEM-armored key) are small enough that streaming to disk
/// like package downloads would only add complexity. librepo has no
/// write-to-buffer mode and its fd-based API needs a real seekable read+write
/// file descriptor, so this downloads to a private temp file and reads it
/// back.
fn fetch_bytes_blocking(
    url: &str,
    stall_timeout_secs: u64,
    minrate: u64,
    net_opts: &NetOptions,
) -> Result<(u32, Vec<u8>)> {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::io::AsRawFd;

    let handle = new_handle(stall_timeout_secs, minrate, net_opts)?;
    let path = std::env::temp_dir().join(format!(
        "vez-librepo-fetch-{}-{:x}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    // librepo `fdopen()`s the fd itself, which needs read+write access
    // whichever way the data flows. Write-only fails with EINVAL (checked
    // against this librepo build).
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .context("creating temp file for download")?;
    let result = handle.fetch_to_fd(url, file.as_raw_fd());
    let outcome = match result {
        Ok(()) => {
            file.seek(SeekFrom::Start(0))?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            // librepo's `lr_download_url` fails the whole call on a bad HTTP
            // status instead of returning it for the caller to inspect
            // (libcurl's `response_code()`, which this replaced, did return
            // it), so a successful call here always means 2xx.
            Ok((200, buf))
        }
        Err(e) => Err(classify_librepo_error(e)),
    };
    drop(file);
    let _ = std::fs::remove_file(&path);
    outcome
}

/// Shared retry loop behind [`get_with_retry`] and [`get_bytes_with_retry`].
/// Transport-level failures (connect error, a mid-transfer stall below
/// `minrate`, etc.) are retried with exponential backoff. A completed
/// transfer, even with a >=400 status, returns right away on that attempt,
/// except for 5xx/429. Those are treated as transient and retried like a
/// transport error: a mirror returning 503/429 now can easily succeed on the
/// next attempt, while a definitive 404/403 won't.
async fn fetch_with_retry(url: &str) -> Result<HttpResponse> {
    let max_attempts = MAX_ATTEMPTS.load(Ordering::Relaxed);
    let stall_timeout_secs = STALL_TIMEOUT_SECS.load(Ordering::Relaxed) as u64;
    let minrate = MINRATE.load(Ordering::Relaxed);
    let net_opts = current_net_options();
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=max_attempts {
        let url_owned = url.to_string();
        let net_opts = net_opts.clone();
        let result = tokio::task::spawn_blocking(move || {
            fetch_bytes_blocking(&url_owned, stall_timeout_secs, minrate, &net_opts)
        })
        .await
        .context("fetch task panicked")?;
        match result {
            Ok((status, body)) => return Ok(HttpResponse { status, body }),
            Err(e) => {
                let retryable_status = e
                    .downcast_ref::<HttpStatusError>()
                    .is_some_and(|he| he.status >= 500 || he.status == 429);
                let is_permanent = e
                    .downcast_ref::<HttpStatusError>()
                    .is_some_and(|he| (400..500).contains(&he.status) && he.status != 429);
                if is_permanent {
                    if let Some(he) = e.downcast_ref::<HttpStatusError>() {
                        return Ok(HttpResponse {
                            status: he.status,
                            body: Vec::new(),
                        });
                    }
                }
                if attempt < max_attempts {
                    tracing::debug!(url, attempt, error = %e, retryable_status, "request failed, retrying");
                    tokio::time::sleep(Duration::from_millis(200 * 2u64.pow(attempt - 1))).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
        .with_context(|| format!("fetching {url} (after {max_attempts} attempts)"))
}

/// `GET url`, retrying transient connect/request errors and 5xx/429 statuses
/// with a short exponential backoff. Other HTTP error statuses aren't
/// retried; callers still call `.error_for_status()` themselves. Returns the
/// first success or definitive-status response, or the last error wrapped
/// with `url` for context. `client` is accepted but unused, so existing
/// callers don't have to drop the argument; see the doc comment on
/// [`HttpResponse`] for why this no longer goes through `reqwest`.
pub async fn get_with_retry(_client: &reqwest::Client, url: &str) -> Result<HttpResponse> {
    fetch_with_retry(url).await
}

/// `GET url` and read the whole body, retrying the *whole* request+body cycle
/// on failure (not just connect/headers). Same as [`get_with_retry`], plus an
/// immediate, unretried failure on any >=400 status: a mirror that's missing
/// a file it advertised won't stop 404ing between attempt 1 and attempt 10,
/// so there's no point spending every attempt's backoff on it. (5xx/429 are
/// already retried inside [`fetch_with_retry`] before this sees them.)
/// `client` is accepted but unused; see [`get_with_retry`].
pub async fn get_bytes_with_retry(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    get_with_retry(client, url)
        .await?
        .error_for_status()
        .with_context(|| format!("fetching {url}"))?
        .bytes()
        .await
}

/// Downloads `url` to `dest`, streaming to disk instead of buffering in
/// memory (unlike [`get_bytes_with_retry`]). Same as
/// [`download_to_file_with_retry_ex`] with no progress reporting and no
/// expected checksum.
///
/// An earlier version shelled out to the real `wget` binary per package for
/// its Content-Length check (the approach `rakurpm`, Svara's other
/// package-download tool, uses). That cost a cold TCP+TLS handshake per
/// package, which showed up as long pauses during "Downloading Packages:" on
/// any transaction with more than a couple dozen packages.
///
/// Writes go to `dest` with a `.part` suffix and are only renamed onto `dest`
/// once complete. Found in podman testing with an interrupted (killed
/// mid-transfer) `vez install rocm`: the caller's cache logic treats "file
/// exists at `dest`" as "already downloaded, skip it", so writing straight to
/// the final path left a truncated RPM that looked cached forever and failed
/// signature verification on every later run instead of being retried.
pub async fn download_to_file_with_retry(
    client: &reqwest::Client,
    url: &str,
    dest: &std::path::Path,
) -> Result<()> {
    download_to_file_with_retry_ex(client, url, dest, None, None).await
}

/// Digest algorithms `primary.xml`'s `<checksum type="...">` can name.
/// Current `createrepo_c` emits `sha256`; `sha1`/`md5` are kept for older or
/// third-party repos that still use them (the same set librepo accepts).
fn digest_hex(algo: &str, bytes: &[u8]) -> Option<String> {
    use sha2::Digest as _;
    match algo {
        "sha256" => Some(hex::encode(sha2::Sha256::digest(bytes))),
        "sha512" => Some(hex::encode(sha2::Sha512::digest(bytes))),
        "sha1" => {
            use sha1::Digest as _;
            Some(hex::encode(sha1::Sha1::digest(bytes)))
        }
        "md5" => {
            use md5::Digest as _;
            Some(hex::encode(md5::Md5::digest(bytes)))
        }
        _ => None,
    }
}

/// Verifies `path`'s bytes against a `(type, hex)` checksum from primary.xml.
/// dnf5/librepo do the same integrity check on every downloaded package
/// through the checksum arguments of `lr_packagetarget_new_v3`. It's separate
/// from GPG signature verification, which many repos/packages skip with
/// `gpgcheck=0`. An unrecognized algorithm name means "can't verify, don't
/// block on it" instead of a hard error; the checksum types Fedora repos emit
/// are all covered above.
pub async fn verify_checksum(
    path: &std::path::Path,
    checksum_type: &str,
    expected_hex: &str,
) -> Result<()> {
    if checksum_type.is_empty() || expected_hex.is_empty() {
        return Ok(());
    }
    let algo = checksum_type.to_ascii_lowercase();
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {} for checksum verification", path.display()))?;
    let Some(actual) = digest_hex(&algo, &bytes) else {
        return Ok(());
    };
    if !actual.eq_ignore_ascii_case(expected_hex) {
        anyhow::bail!(
            "checksum mismatch for {}: expected {algo}:{expected_hex}, got {algo}:{actual}",
            path.display()
        );
    }
    Ok(())
}

/// An HTTP status for a transfer librepo didn't fail by itself in a way that
/// returns a real status code (only bad statuses do, and then only through
/// [`vez_librepo::parse_http_status`] scraping the error message). Rebuilt by
/// hand after every attempt so the retry loop can tell a permanent 404/403
/// from a transient network failure, the same split `get_bytes_with_retry`
/// makes for `reqwest::Error`.
#[derive(Debug)]
struct HttpStatusError {
    status: u32,
}

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server returned HTTP {}", self.status)
    }
}

impl std::error::Error for HttpStatusError {}

/// One single-stream attempt at downloading `url` into `part`, resuming from
/// whatever bytes are already on disk at `part` (written by an earlier
/// attempt of the same call; see the caller's doc comment). Runs on a
/// blocking thread because librepo's handle/target API is synchronous.
///
/// It's one sequential stream on purpose, not a download split into parallel
/// `Range` requests. dnf5 does the same: librepo (`downloader.c`) opens one
/// transfer per file and parallelizes *across* files (through
/// `LRO_MAXPARALLELDOWNLOADS`), never splitting one file into concurrent
/// ranges. Splitting a file assumes every range comes back with identical,
/// consistent bytes, which is a real risk with a load-balanced mirror/CDN
/// over a lossy or degraded link, where different ranges can hit different
/// backend nodes. One stream per file, like librepo, avoids that entirely,
/// and `verify_checksum` after each attempt is the remaining safety net.
///
/// The handle options follow librepo's defaults, which dnf5 also sets
/// (`libdnf5/repo/librepo.cpp`): 30s connect timeout, TLS verification on,
/// and `LRO_LOWSPEEDLIMIT`/`LRO_LOWSPEEDTIME` from `vez.conf`'s
/// `minrate=`/`timeout=` (dnf's settings for the same two options), so
/// librepo detects and aborts a stalled transfer itself.
fn download_single_attempt_blocking(
    url: &str,
    part: &std::path::Path,
    stall_timeout_secs: u64,
    minrate: u64,
    progress: Option<std::sync::Arc<AtomicU64>>,
    net_opts: &NetOptions,
) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let resume_from = std::fs::metadata(part).map(|m| m.len()).unwrap_or(0);
    // librepo `fdopen()`s the fd itself, which needs read+write access
    // whichever way the data flows. Write-only fails with EINVAL (checked
    // against this librepo build).
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(part)
        .with_context(|| format!("opening {}", part.display()))?;

    let handle = new_handle(stall_timeout_secs, minrate, net_opts)?;
    let resume = resume_from > 0;
    handle
        .download_target(url, file.as_raw_fd(), resume, 0, progress)
        .map_err(classify_librepo_error)
}

/// `progress`, if given, is set to the total bytes downloaded so far
/// (including anything already on disk from an earlier attempt of this call)
/// as the transfer runs. A caller can poll it from a separate ticker task to
/// print a live "X% done" line. Before this, every download went silent until
/// 100%, which on a large file from a slow mirror looked exactly like a hang.
/// It's reset to 0 at the start of the call and then left alone across
/// retries, since each retry resumes where the last one stopped; see
/// [`download_single_attempt_blocking`].
///
/// Writes go to `dest` with a `.part` suffix and are only renamed onto `dest`
/// once complete and checksum-verified. Found in podman testing with an
/// interrupted (killed mid-transfer) `vez install rocm`: the caller's cache
/// logic treats "file exists at `dest`" as "already downloaded, skip it", so
/// writing straight to the final path left a truncated RPM that looked cached
/// forever and failed signature verification on every later run instead of
/// being retried. A `.part` file left over from a *previous, separate* call
/// (a crashed or killed process) isn't trusted for resume: this call didn't
/// see it being written, so it's truncated at the start.
pub async fn download_to_file_with_retry_ex(
    _client: &reqwest::Client,
    url: &str,
    dest: &std::path::Path,
    progress: Option<std::sync::Arc<AtomicU64>>,
    expected_checksum: Option<(&str, &str)>,
) -> Result<()> {
    let part = dest.with_extension(match dest.extension() {
        Some(ext) => format!("{}.part", ext.to_string_lossy()),
        None => "part".to_string(),
    });
    let max_attempts = MAX_ATTEMPTS.load(Ordering::Relaxed);
    let stall_timeout_secs = STALL_TIMEOUT_SECS.load(Ordering::Relaxed) as u64;
    let minrate = MINRATE.load(Ordering::Relaxed);
    let net_opts = current_net_options();

    let _ = tokio::fs::remove_file(&part).await;
    if let Some(p) = &progress {
        p.store(0, Ordering::Relaxed);
    }

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=max_attempts {
        let url_owned = url.to_string();
        let part_owned = part.clone();
        let progress_clone = progress.clone();
        let net_opts = net_opts.clone();
        let result = tokio::task::spawn_blocking(move || {
            download_single_attempt_blocking(
                &url_owned,
                &part_owned,
                stall_timeout_secs,
                minrate,
                progress_clone,
                &net_opts,
            )
        })
        .await
        .context("download task panicked")?;

        match result {
            Ok(()) => {
                if let Some((ty, hex)) = expected_checksum {
                    if let Err(e) = verify_checksum(&part, ty, hex).await {
                        // Wrong bytes on disk. A corrupt partial can't be
                        // resumed, so the next attempt starts clean.
                        let _ = tokio::fs::remove_file(&part).await;
                        if let Some(p) = &progress {
                            p.store(0, Ordering::Relaxed);
                        }
                        if attempt < max_attempts {
                            tracing::debug!(url, attempt, error = %e, "checksum mismatch, retrying");
                            tokio::time::sleep(Duration::from_millis(200 * 2u64.pow(attempt - 1)))
                                .await;
                        }
                        last_err = Some(e);
                        continue;
                    }
                }
                tokio::fs::rename(&part, dest).await.with_context(|| {
                    format!("renaming {} to {}", part.display(), dest.display())
                })?;
                return Ok(());
            }
            Err(e) => {
                // Same reasoning as get_bytes_with_retry: a definitive HTTP
                // client error means this exact URL will never succeed no
                // matter how often it's retried. We don't retry here even for
                // archive-style single-host repos known to lag their own
                // metadata; the per-package mirror-cycling loop in
                // `download_all_ex` handles that case. This function only
                // sees one URL at a time, so retrying here would spend
                // several seconds on a dead mirror instead of moving to the
                // next one. dnf5/librepo do the same: cycle through the whole
                // mirror set quickly and only back off after every mirror has
                // failed.
                let is_permanent = e
                    .downcast_ref::<HttpStatusError>()
                    .is_some_and(|he| (400..500).contains(&he.status) && he.status != 429);
                if is_permanent {
                    let _ = tokio::fs::remove_file(&part).await;
                    return Err(e).with_context(|| format!("fetching {url}"));
                }
                // Transient failure. Leave the `.part` file on disk so the
                // next attempt resumes from its current offset instead of
                // restarting the transfer.
                if attempt < max_attempts {
                    tracing::debug!(url, attempt, error = %e, "download failed, retrying");
                    tokio::time::sleep(Duration::from_millis(200 * 2u64.pow(attempt - 1))).await;
                }
                last_err = Some(e);
            }
        }
    }
    let _ = tokio::fs::remove_file(&part).await;
    Err(last_err.unwrap())
        .with_context(|| format!("fetching {url} (after {max_attempts} attempts)"))
}

/// One package to fetch as part of a [`download_packages_batch`] call.
pub struct BatchSpec {
    /// Repo-relative href. librepo combines it with `urls` (the repo's ranked
    /// mirror list); this crate doesn't.
    pub relative_url: String,
    /// Final destination path. librepo writes and resumes into a sibling
    /// `.part` file, and this function renames it onto `dest` once librepo
    /// reports that target as `Successful`/`Alreadyexists`, like every other
    /// download path here.
    pub dest: std::path::PathBuf,
    pub checksum_type: String,
    pub checksum: String,
    pub expected_size: i64,
    pub progress: Option<std::sync::Arc<AtomicU64>>,
    /// Overrides the batch's shared `urls` list for this one target
    /// (`LrPackageTarget::base_url`). Used for a package whose href can't be
    /// resolved against the repo's ranked mirror list, so it still gets a
    /// real librepo download (from a single mirror) instead of being dropped
    /// from the batch.
    pub base_url: Option<String>,
}

/// One package's outcome from [`download_packages_batch`].
pub struct BatchOutcome {
    pub ok: bool,
    pub error: Option<String>,
}

/// Downloads every package in `specs` from one repo with a single
/// `lr_download_packages` call: librepo's batch downloader, parallel and with
/// mirror failover across `urls` (the repo's ranked mirror list). dnf5's
/// `PackageDownloader::download()` uses the same entry point per repo.
/// librepo verifies checksums itself (each target carries its own
/// `checksum_type`/`checksum`), unlike the single-target path above, which
/// verifies afterwards.
///
/// Every target writes to a `.part` sibling of its `dest` (resumed if one is
/// already on disk, e.g. from an earlier failed batch) and is renamed onto
/// `dest` only once librepo reports it `Successful`. A failed target's
/// `.part` file stays in place so the next batch or round resumes it instead
/// of starting from zero.
pub async fn download_packages_batch(
    urls: Vec<String>,
    specs: Vec<BatchSpec>,
    max_parallel: u64,
) -> Result<Vec<BatchOutcome>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let stall_timeout_secs = STALL_TIMEOUT_SECS.load(Ordering::Relaxed) as u64;
    let minrate = MINRATE.load(Ordering::Relaxed);
    let net_opts = current_net_options();

    let parts: Vec<std::path::PathBuf> = specs
        .iter()
        .map(|s| {
            s.dest.with_extension(match s.dest.extension() {
                Some(ext) => format!("{}.part", ext.to_string_lossy()),
                None => "part".to_string(),
            })
        })
        .collect();

    let lr_specs: Vec<vez_librepo::PackageSpec> = specs
        .iter()
        .zip(&parts)
        .map(|(s, part)| {
            let resume = part.exists();
            vez_librepo::PackageSpec {
                relative_url: s.relative_url.clone(),
                dest: part.to_string_lossy().into_owned(),
                checksum_type: s.checksum_type.clone(),
                checksum: s.checksum.clone(),
                expected_size: s.expected_size,
                base_url: s.base_url.clone(),
                resume,
                progress: s.progress.clone(),
            }
        })
        .collect();

    let results =
        tokio::task::spawn_blocking(move || -> Result<Vec<vez_librepo::PackageResult>> {
            let handle = new_handle(stall_timeout_secs, minrate, &net_opts)?;
            handle.set_urls(&urls).context("setting LRO_URLS")?;
            handle
                .set_max_parallel(max_parallel.max(1))
                .context("setting LRO_MAXPARALLELDOWNLOADS")?;
            handle.download_packages(&lr_specs, false)
        })
        .await
        .context("batch download task panicked")??;

    let mut out = Vec::with_capacity(results.len());
    for ((spec, part), result) in specs.iter().zip(&parts).zip(results) {
        if result.ok {
            tokio::fs::rename(part, &spec.dest).await.with_context(|| {
                format!("renaming {} to {}", part.display(), spec.dest.display())
            })?;
            out.push(BatchOutcome {
                ok: true,
                error: None,
            });
        } else {
            out.push(BatchOutcome {
                ok: false,
                error: result.error,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    #[tokio::test]
    async fn checksum_matches() {
        let dir = std::env::temp_dir().join(format!("vez-checksum-test-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("pkg.rpm");
        tokio::fs::write(&path, b"hello world").await.unwrap();
        // sha256("hello world")
        verify_checksum(
            &path,
            "sha256",
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn checksum_mismatch_rejected() {
        let dir = std::env::temp_dir().join(format!("vez-checksum-test2-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("pkg.rpm");
        tokio::fs::write(&path, b"hello world").await.unwrap();
        let err = verify_checksum(
            &path,
            "sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await;
        assert!(err.is_err());
    }
}
