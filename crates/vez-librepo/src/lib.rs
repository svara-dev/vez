//! Safe Rust wrapper around librepo's `LrHandle`/`LrDownloadTarget` C API.
//! dnf5 links the same library (`libdnf5/repo/librepo.hpp`,
//! `repo_downloader.cpp`) for repo metadata and package downloads, so using
//! it here makes `vez`'s downloader behave like dnf5's instead of imitating
//! it with hand-rolled curl calls.
//!
//! This layer is kept thin. One [`Handle`] wraps an `LrHandle*` configured
//! with the timeout/TLS/user-agent options `vez-repo` needs, with two
//! download primitives on top: [`Handle::fetch_to_fd`] (single shot, no
//! resume; matches `lr_download_url`) and [`Handle::download_target`]
//! (resumable, with a progress callback; matches the
//! `LrDownloadTarget`/`lr_download_target` API dnf5 uses for packages). Retry
//! loops, exponential backoff, `.part` file handling, and checksum
//! verification stay in `vez-repo::net`; librepo only does the transfer.
mod sys;

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::os::raw::c_double;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Wraps a GLib `GError**` out-param for one FFI call, turns a non-NULL
/// result into an `anyhow::Error`, and frees it either way. Every `sys::`
/// call in this module goes through here so a `GError` never leaks and every
/// failure path gets checked. Like all GLib-style APIs, librepo only sets
/// `err` when the call reports failure, never on success.
struct ErrSlot(*mut sys::GError);

impl ErrSlot {
    fn new() -> Self {
        ErrSlot(std::ptr::null_mut())
    }

    fn as_out_param(&mut self) -> *mut *mut sys::GError {
        &mut self.0
    }

    /// `ok` is the `gboolean` librepo returned from the call this slot was
    /// passed to. Consumes `self` either way. On success there's nothing to
    /// free (librepo didn't set `err`); on failure the message is copied out
    /// before the `GError` is freed.
    fn check(mut self, ok: sys::gboolean, what: &str) -> Result<()> {
        if ok != 0 && self.0.is_null() {
            return Ok(());
        }
        if self.0.is_null() {
            bail!("{what} failed (no error detail from librepo)");
        }
        let msg = unsafe {
            let m = (*self.0).message;
            if m.is_null() {
                "unknown error".to_string()
            } else {
                std::ffi::CStr::from_ptr(m).to_string_lossy().into_owned()
            }
        };
        let code = unsafe { (*self.0).code };
        unsafe { sys::g_error_free(self.0) };
        self.0 = std::ptr::null_mut();
        bail!("{what}: {msg} (librepo error code {code})")
    }
}

impl Drop for ErrSlot {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::g_error_free(self.0) };
        }
    }
}

/// A best-effort HTTP status parsed out of a librepo `GError` message.
/// librepo's public API doesn't return the raw status code the way libcurl's
/// `CURLINFO_RESPONSE_CODE` does. It folds a bad status into `LRE_BADSTATUS`,
/// and only the message names the code (librepo's `curl.c`/`downloader.c`
/// format these as `"Status code: NNN for <url>"`). Callers that need to tell
/// a permanent 4xx from a transient 5xx/429 (see the retry loop in
/// `vez-repo::net`) parse it from the message. `None` means "couldn't tell,
/// treat as transient".
pub fn parse_http_status(message: &str) -> Option<u32> {
    let lower = message.to_ascii_lowercase();
    let idx = lower.find("status code")?;
    let rest = &message[idx..];
    let digits_start = rest.find(|c: char| c.is_ascii_digit())?;
    let digits: String = rest[digits_start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// One configured librepo handle. Not `Sync` or shared between threads:
/// `LrHandle` isn't documented as safe for concurrent use, so `vez-repo::net`
/// creates a new [`Handle`] per blocking download task (the same lifetime the
/// `curl::easy::Easy` it replaced had).
pub struct Handle(*mut sys::LrHandle);

impl Handle {
    pub fn new(
        useragent: &str,
        connect_timeout_secs: u64,
        low_speed_limit: u64,
        low_speed_time_secs: u64,
    ) -> Result<Self> {
        let raw = unsafe { sys::lr_handle_init() };
        if raw.is_null() {
            bail!("lr_handle_init failed (out of memory)");
        }
        let handle = Handle(raw);
        handle
            .setopt_str(sys::LrHandleOption::Useragent, useragent)
            .context("setting LRO_USERAGENT")?;
        handle
            .setopt_long(
                sys::LrHandleOption::Connecttimeout,
                connect_timeout_secs.min(i64::MAX as u64) as i64,
            )
            .context("setting LRO_CONNECTTIMEOUT")?;
        handle
            .setopt_long(
                sys::LrHandleOption::Lowspeedlimit,
                low_speed_limit.min(i64::MAX as u64) as i64,
            )
            .context("setting LRO_LOWSPEEDLIMIT")?;
        handle
            .setopt_long(
                sys::LrHandleOption::Lowspeedtime,
                low_speed_time_secs.max(1).min(i64::MAX as u64) as i64,
            )
            .context("setting LRO_LOWSPEEDTIME")?;
        handle
            .setopt_long(sys::LrHandleOption::Sslverifypeer, 1)
            .context("setting LRO_SSLVERIFYPEER")?;
        handle
            .setopt_long(sys::LrHandleOption::Sslverifyhost, 1)
            .context("setting LRO_SSLVERIFYHOST")?;
        Ok(handle)
    }

    fn setopt_long(&self, opt: sys::LrHandleOption, value: i64) -> Result<()> {
        let mut err = ErrSlot::new();
        // LRO_* "(long)" options take a real C `long` in the varargs slot. On
        // this platform (LP64) that's 64-bit, i.e. `i64`.
        let ok = unsafe {
            sys::lr_handle_setopt(
                self.0,
                err.as_out_param(),
                opt,
                value as std::os::raw::c_long,
            )
        };
        err.check(ok, "lr_handle_setopt")
    }

    fn setopt_str(&self, opt: sys::LrHandleOption, value: &str) -> Result<()> {
        let cstr = CString::new(value).context("option value contains an interior NUL")?;
        let mut err = ErrSlot::new();
        let ok = unsafe { sys::lr_handle_setopt(self.0, err.as_out_param(), opt, cstr.as_ptr()) };
        err.check(ok, "lr_handle_setopt")
    }

    /// Sets `LRO_URLS` (a `NULL`-terminated `char **`), the option dnf5's
    /// `RepoDownloader` sets from its resolved mirror list before handing a
    /// repo's packages to `lr_download_packages`. Once set, every
    /// `LrPackageTarget` built from this handle with a null `base_url`
    /// resolves its `relative_url` against *this* list, and librepo does the
    /// mirror cycling and failover for the whole batch (not caller-side Rust
    /// code).
    pub fn set_urls(&self, urls: &[String]) -> Result<()> {
        let cstrs: Vec<CString> = urls
            .iter()
            .map(|u| CString::new(u.as_str()).context("url contains an interior NUL"))
            .collect::<Result<_>>()?;
        let mut ptrs: Vec<*const c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        {
            let mut err = ErrSlot::new();
            let ok = unsafe {
                sys::lr_handle_setopt(
                    self.0,
                    err.as_out_param(),
                    sys::LrHandleOption::Urls,
                    ptrs.as_ptr(),
                )
            };
            err.check(ok, "lr_handle_setopt(LRO_URLS)")?;
        }
        // `LRO_REPOTYPE` is a C enum, so it's promoted to `c_int` in the
        // varargs slot (the other options this crate sets are `c_long`).
        // `lr_download_packages` won't resolve targets against `LRO_URLS`
        // without it; see the `LR_YUMREPO` doc comment in `sys.rs`.
        let mut err = ErrSlot::new();
        let ok = unsafe {
            sys::lr_handle_setopt(
                self.0,
                err.as_out_param(),
                sys::LrHandleOption::Repotype,
                sys::LR_YUMREPO,
            )
        };
        err.check(ok, "lr_handle_setopt(LRO_REPOTYPE)")
    }

    /// Single-shot download of `url` into the open file descriptor `fd`, with
    /// no resume. Matches `lr_download_url`, librepo's own wrapper for the
    /// same job. `fd` stays open and owned by the caller; librepo doesn't
    /// take ownership.
    pub fn fetch_to_fd(&self, url: &str, fd: RawFd) -> Result<()> {
        let curl = CString::new(url).context("url contains an interior NUL")?;
        let mut err = ErrSlot::new();
        let ok = unsafe { sys::lr_download_url(self.0, curl.as_ptr(), fd, err.as_out_param()) };
        err.check(ok, &format!("downloading {url}"))
    }

    /// Downloads `url` into `fd`, resuming from `fd`'s current write offset
    /// when `resume` is set (librepo finds the offset by seeking `fd`
    /// itself), and reports progress through `progress` as the transfer runs
    /// (bytes so far, including anything already on disk from an earlier
    /// attempt). Matches the `LrDownloadTarget`/`lr_download_target` API dnf5
    /// uses for package downloads. This is the fuller sibling of
    /// [`Handle::fetch_to_fd`], needed for resume and progress, which
    /// `lr_download_url` doesn't expose.
    pub fn download_target(
        &self,
        url: &str,
        fd: RawFd,
        resume: bool,
        expected_size: i64,
        progress: Option<Arc<AtomicU64>>,
    ) -> Result<()> {
        let curl = CString::new(url).context("url contains an interior NUL")?;

        // `clientp` for the progress trampoline: a raw pointer into the
        // `Arc`'s allocation, kept alive on this function's stack for the
        // whole (synchronous) download call below.
        let cb_data = progress
            .as_ref()
            .map(|p| Arc::as_ptr(p) as *mut std::ffi::c_void)
            .unwrap_or(std::ptr::null_mut());
        let cb: sys::LrProgressCb = if progress.is_some() {
            Some(progress_trampoline)
        } else {
            None
        };

        let target = unsafe {
            sys::lr_downloadtarget_new(
                self.0,
                curl.as_ptr(),
                std::ptr::null(),
                fd,
                std::ptr::null(),
                std::ptr::null_mut(),
                expected_size,
                resume as sys::gboolean,
                cb,
                cb_data,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                0,
            )
        };
        if target.is_null() {
            bail!("lr_downloadtarget_new failed (out of memory)");
        }

        let mut err = ErrSlot::new();
        let ok = unsafe { sys::lr_download_target(target, err.as_out_param()) };
        let target_err = unsafe { (*target).err };
        let target_rcode = unsafe { (*target).rcode };
        let extra = if !target_err.is_null() {
            Some(unsafe {
                std::ffi::CStr::from_ptr(target_err)
                    .to_string_lossy()
                    .into_owned()
            })
        } else {
            None
        };
        unsafe { sys::lr_downloadtarget_free(target) };

        err.check(ok, &format!("downloading {url}"))?;
        if target_rcode != sys::LRE_OK {
            let msg = extra.unwrap_or_else(|| format!("librepo error code {target_rcode}"));
            bail!("downloading {url}: {msg}");
        }
        Ok(())
    }

    /// Sets `LRO_PROXY`/`LRO_PROXYUSERPWD`, matching how dnf5's `librepo.cpp`
    /// handles `proxy=`/`proxy_username=`+`proxy_password=`
    /// (`config_repo.cpp`). `proxy` is a full URL (`http://host:port`,
    /// `socks5://host:port`, ...); `userpwd`, if given, is `"user:pass"`.
    /// Passing `None` for either leaves that option unset on the handle.
    pub fn set_proxy(&self, proxy: Option<&str>, userpwd: Option<&str>) -> Result<()> {
        if let Some(p) = proxy {
            self.setopt_str(sys::LrHandleOption::Proxy, p)
                .context("setting LRO_PROXY")?;
        }
        if let Some(up) = userpwd {
            self.setopt_str(sys::LrHandleOption::Proxyuserpwd, up)
                .context("setting LRO_PROXYUSERPWD")?;
        }
        Ok(())
    }

    /// Sets `LRO_USERNAME`/`LRO_PASSWORD`: HTTP basic/digest credentials for
    /// repos that require authentication. Matches dnf5's `librepo.cpp`
    /// handling of `username=`/`password=` (`config_repo.cpp`).
    pub fn set_credentials(&self, username: Option<&str>, password: Option<&str>) -> Result<()> {
        if let Some(u) = username {
            self.setopt_str(sys::LrHandleOption::Username, u)
                .context("setting LRO_USERNAME")?;
        }
        if let Some(p) = password {
            self.setopt_str(sys::LrHandleOption::Password, p)
                .context("setting LRO_PASSWORD")?;
        }
        Ok(())
    }

    /// Sets `LRO_SSLCACERT`/`LRO_SSLCLIENTCERT`/`LRO_SSLCLIENTKEY`: a private
    /// CA bundle and/or client certificate and key for repos behind mTLS or a
    /// non-public CA. Matches dnf5's `librepo.cpp` handling of
    /// `sslcacert=`/`sslclientcert=`/`sslclientkey=` (`config_repo.cpp`). The
    /// three paths are independent and any of them may be `None`.
    pub fn set_tls_client(
        &self,
        cacert: Option<&str>,
        clientcert: Option<&str>,
        clientkey: Option<&str>,
    ) -> Result<()> {
        if let Some(c) = cacert {
            self.setopt_str(sys::LrHandleOption::Sslcacert, c)
                .context("setting LRO_SSLCACERT")?;
        }
        if let Some(c) = clientcert {
            self.setopt_str(sys::LrHandleOption::Sslclientcert, c)
                .context("setting LRO_SSLCLIENTCERT")?;
        }
        if let Some(k) = clientkey {
            self.setopt_str(sys::LrHandleOption::Sslclientkey, k)
                .context("setting LRO_SSLCLIENTKEY")?;
        }
        Ok(())
    }

    /// Sets `LRO_FASTESTMIRROR`/`LRO_FASTESTMIRRORCACHE`: librepo's
    /// mirror-speed sorting (a plain TCP connect-time race per mirror, cached
    /// per host in `cache_path`) for whatever mirror list this handle has
    /// through `LRO_URLS`/`LRO_MIRRORLISTURL`/`LRO_METALINKURL`. dnf5's
    /// `RepoDownloader::common_handle_setup` (`repo_downloader.cpp`) points
    /// `LRO_FASTESTMIRRORCACHE` at one `fastestmirror.cache` file under the
    /// *base* cachedir, shared by every repo, so `cache_path` should be that
    /// shared path here as well. `LRO_FASTESTMIRRORMAXAGE` stays at librepo's
    /// default (30 days, `LRO_FASTESTMIRRORMAXAGE_DEFAULT`).
    pub fn set_fastestmirror(&self, enabled: bool, cache_path: Option<&str>) -> Result<()> {
        self.setopt_long(sys::LrHandleOption::Fastestmirror, enabled as i64)
            .context("setting LRO_FASTESTMIRROR")?;
        if enabled {
            if let Some(path) = cache_path {
                self.setopt_str(sys::LrHandleOption::Fastestmirrorcache, path)
                    .context("setting LRO_FASTESTMIRRORCACHE")?;
            }
        }
        Ok(())
    }

    /// Sorts `urls` fastest-first with librepo's `lr_fastestmirror`: a real
    /// TCP connect-time race per mirror
    /// (`LrFastestMirror::plain_connect_time`), cached in whatever
    /// `LRO_FASTESTMIRRORCACHE` path this handle has (see
    /// [`Handle::set_fastestmirror`]) and reused for
    /// `LRO_FASTESTMIRRORMAXAGE` (30 days by default). dnf5 uses the same
    /// function for mirror ranking. Calling it directly (instead of only
    /// through `LRO_URLS` + `lr_download_packages`) lets `vez-repo` rank a
    /// mirror list before choosing where to fetch metadata from, the way
    /// dnf5's `RepoDownloader` ranks once when resolving metadata and reuses
    /// that order for later package downloads.
    ///
    /// On any failure it returns `urls` unchanged, in the original order. A
    /// bad probe shouldn't block a download that would work against an
    /// unranked list.
    pub fn fastest_mirror_sort(&self, urls: &[String]) -> Result<Vec<String>> {
        if urls.len() <= 1 {
            return Ok(urls.to_vec());
        }
        let cstrs: Vec<CString> = urls
            .iter()
            .map(|u| CString::new(u.as_str()).context("url contains an interior NUL"))
            .collect::<Result<_>>()?;
        let mut list: *mut sys::GSList = std::ptr::null_mut();
        for c in cstrs.iter().rev() {
            list = unsafe { sys::g_slist_prepend(list, c.as_ptr() as *mut c_void) };
        }

        let mut err = ErrSlot::new();
        let ok = unsafe { sys::lr_fastestmirror(self.0, &mut list, err.as_out_param()) };

        let mut out = Vec::with_capacity(urls.len());
        if ok != 0 {
            let mut node = list;
            while !node.is_null() {
                let data = unsafe { (*node).data } as *const c_char;
                if !data.is_null() {
                    out.push(
                        unsafe { std::ffi::CStr::from_ptr(data) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                node = unsafe { (*node).next };
            }
        }
        unsafe { sys::g_slist_free(list) };
        err.check(ok, "lr_fastestmirror")?;
        if out.len() != urls.len() {
            bail!(
                "lr_fastestmirror returned {} url(s), expected {}",
                out.len(),
                urls.len()
            );
        }
        Ok(out)
    }

    /// Sets `LRO_MAXPARALLELDOWNLOADS`. Matches
    /// `main.get_max_parallel_downloads_option()` in dnf5's
    /// `RepoDownloader::get_cached_handle`
    /// (`libdnf5/repo/repo_downloader.cpp`). Set once per handle before
    /// batch-downloading packages with it.
    pub fn set_max_parallel(&self, n: u64) -> Result<()> {
        self.setopt_long(
            sys::LrHandleOption::Maxparalleldownloads,
            n.min(i64::MAX as u64) as i64,
        )
        .context("setting LRO_MAXPARALLELDOWNLOADS")
    }

    /// Batch-downloads every target in `specs` with one
    /// `lr_download_packages` call. That's librepo's parallel package
    /// downloader with mirror failover (bounded by
    /// `LRO_MAXPARALLELDOWNLOADS`, see [`Handle::set_max_parallel`]), and the
    /// same entry point dnf5's `PackageDownloader::download()`
    /// (`libdnf5/repo/package_downloader.cpp`) uses: one `LrPackageTarget`
    /// per package from `lr_packagetarget_new_v3`, batched into a `GSList`,
    /// and one `lr_download_packages` call for the set. Looping over
    /// single-target `download_target` calls from our own code would lose
    /// librepo's mirror failover and its shared low-speed/timeout enforcement
    /// across the batch.
    pub fn download_packages(
        &self,
        specs: &[PackageSpec],
        fail_fast: bool,
    ) -> Result<Vec<PackageResult>> {
        if specs.is_empty() {
            return Ok(Vec::new());
        }

        // Every C string and per-target state has to outlive the
        // `lr_download_packages` call below, because librepo keeps these
        // pointers (as `cbdata` and as target fields) until the call returns.
        // `states` is a `Vec<Box<_>>` so each element's heap address stays
        // put even as the Vec grows.
        let mut states: Vec<Box<TargetState>> = Vec::with_capacity(specs.len());
        let mut url_cstrs = Vec::with_capacity(specs.len());
        let mut dest_cstrs = Vec::with_capacity(specs.len());
        let mut checksum_cstrs = Vec::with_capacity(specs.len());
        let mut base_cstrs = Vec::with_capacity(specs.len());
        let mut lr_targets: Vec<*mut sys::LrPackageTarget> = Vec::with_capacity(specs.len());

        let mut build_err: Option<anyhow::Error> = None;
        for spec in specs {
            let url = match CString::new(spec.relative_url.as_str()) {
                Ok(v) => v,
                Err(e) => {
                    build_err = Some(e.into());
                    break;
                }
            };
            let dest = match CString::new(spec.dest.as_str()) {
                Ok(v) => v,
                Err(e) => {
                    build_err = Some(e.into());
                    break;
                }
            };
            let checksum = if spec.checksum.is_empty() {
                None
            } else {
                match CString::new(spec.checksum.as_str()) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        build_err = Some(e.into());
                        break;
                    }
                }
            };
            let base = match spec.base_url.as_deref().map(CString::new).transpose() {
                Ok(v) => v,
                Err(e) => {
                    build_err = Some(e.into());
                    break;
                }
            };

            let state = Box::new(TargetState {
                progress: spec.progress.clone(),
                ok: false,
                already_exists: false,
                error: None,
            });
            let state_ptr = state.as_ref() as *const TargetState as *mut c_void;

            let mut err = ErrSlot::new();
            let target = unsafe {
                sys::lr_packagetarget_new_v3(
                    self.0,
                    url.as_ptr(),
                    dest.as_ptr(),
                    checksum_type_from_str(&spec.checksum_type),
                    checksum
                        .as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(std::ptr::null()),
                    spec.expected_size,
                    base.as_ref()
                        .map(|c| c.as_ptr())
                        .unwrap_or(std::ptr::null()),
                    spec.resume as sys::gboolean,
                    if spec.progress.is_some() {
                        Some(pkg_progress_trampoline)
                    } else {
                        None
                    },
                    state_ptr,
                    Some(pkg_end_trampoline),
                    None,
                    0,
                    0,
                    err.as_out_param(),
                )
            };
            if target.is_null() {
                build_err = Some(err.check(0, "lr_packagetarget_new_v3").unwrap_err());
                break;
            }

            lr_targets.push(target);
            states.push(state);
            url_cstrs.push(url);
            dest_cstrs.push(dest);
            checksum_cstrs.push(checksum);
            base_cstrs.push(base);
        }

        if let Some(e) = build_err {
            for target in &lr_targets {
                unsafe { sys::lr_packagetarget_free(*target) };
            }
            return Err(e);
        }

        // Build the GSList. dnf5 prepends back to front for the same reason:
        // prepending is O(1) per node and appending to a GSList's tail is
        // O(n).
        let mut list: *mut sys::GSList = std::ptr::null_mut();
        for target in lr_targets.iter().rev() {
            list = unsafe { sys::g_slist_prepend(list, *target as *mut c_void) };
        }

        let flags = if fail_fast {
            sys::LR_PACKAGEDOWNLOAD_FAILFAST
        } else {
            0
        };
        let mut err = ErrSlot::new();
        let ok = unsafe { sys::lr_download_packages(list, flags, err.as_out_param()) };

        unsafe { sys::g_slist_free(list) };
        for target in &lr_targets {
            unsafe { sys::lr_packagetarget_free(*target) };
        }

        // From librepo's docs (package_downloader.h): in non-failfast mode
        // FALSE only comes back for a function-level error. Per-target
        // failures go through the end callback (already captured in `states`)
        // and don't affect this return value. So FALSE here is always a hard
        // error, like dnf5's `if (!lr_download_packages(...)) throw`.
        err.check(ok, "lr_download_packages")?;

        Ok(states
            .into_iter()
            .map(|s| PackageResult {
                ok: s.ok,
                already_exists: s.already_exists,
                error: s.error,
            })
            .collect())
    }
}

/// One package to download, passed to [`Handle::download_packages`].
pub struct PackageSpec {
    /// Repo-relative package location. librepo combines it with the handle's
    /// configured mirrors/baseurl, same as `LrPackageTarget::relative_url`.
    pub relative_url: String,
    /// Destination filename (full path), matching `LrPackageTarget::dest`.
    pub dest: String,
    /// Checksum algorithm name (`"sha256"`, `"sha1"`, ...), case-insensitive.
    /// Empty means unknown, so no check.
    pub checksum_type: String,
    pub checksum: String,
    pub expected_size: i64,
    pub base_url: Option<String>,
    pub resume: bool,
    /// Optional live byte-progress counter, ticked from
    /// [`pkg_progress_trampoline`] the same way [`Handle::download_target`]
    /// ticks its single-target counter.
    pub progress: Option<Arc<AtomicU64>>,
}

/// Per-target outcome from [`Handle::download_packages`], filled in by
/// librepo's `LrEndCb`. Mirrors the three-way split of dnf5's
/// `DownloadCallbacks::TransferStatus` (success / already exists / error).
pub struct PackageResult {
    pub ok: bool,
    pub already_exists: bool,
    pub error: Option<String>,
}

struct TargetState {
    progress: Option<Arc<AtomicU64>>,
    ok: bool,
    already_exists: bool,
    error: Option<String>,
}

fn checksum_type_from_str(s: &str) -> sys::LrChecksumType {
    match s.to_ascii_lowercase().as_str() {
        "md5" => sys::LrChecksumType::Md5,
        "sha1" | "sha" => sys::LrChecksumType::Sha1,
        "sha224" => sys::LrChecksumType::Sha224,
        "sha256" => sys::LrChecksumType::Sha256,
        "sha384" => sys::LrChecksumType::Sha384,
        "sha512" => sys::LrChecksumType::Sha512,
        _ => sys::LrChecksumType::Unknown,
    }
}

extern "C" fn pkg_progress_trampoline(
    clientp: *mut c_void,
    _total_to_download: c_double,
    now_downloaded: c_double,
) -> c_int {
    if !clientp.is_null() {
        let state = unsafe { &mut *(clientp as *mut TargetState) };
        if let Some(p) = &state.progress {
            p.store(now_downloaded.max(0.0) as u64, Ordering::Relaxed);
        }
    }
    0 // LR_CB_OK
}

extern "C" fn pkg_end_trampoline(
    clientp: *mut c_void,
    status: sys::LrTransferStatus,
    msg: *const c_char,
) -> c_int {
    if !clientp.is_null() {
        let state = unsafe { &mut *(clientp as *mut TargetState) };
        match status {
            sys::LrTransferStatus::Successful => state.ok = true,
            sys::LrTransferStatus::Alreadyexists => {
                state.ok = true;
                state.already_exists = true;
            }
            sys::LrTransferStatus::Error => {
                state.ok = false;
                state.error = Some(if msg.is_null() {
                    "unknown error".to_string()
                } else {
                    unsafe { std::ffi::CStr::from_ptr(msg) }
                        .to_string_lossy()
                        .into_owned()
                });
            }
        }
    }
    0 // LR_CB_OK
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::lr_handle_free(self.0) };
        }
    }
}

extern "C" fn progress_trampoline(
    clientp: *mut std::ffi::c_void,
    _total_to_download: std::os::raw::c_double,
    now_downloaded: std::os::raw::c_double,
) -> std::os::raw::c_int {
    if !clientp.is_null() {
        let atomic = unsafe { &*(clientp as *const AtomicU64) };
        atomic.store(now_downloaded.max(0.0) as u64, Ordering::Relaxed);
    }
    0 // LR_CB_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_new_and_drop() {
        let h = Handle::new("vez-librepo-test/0", 5, 0, 5).unwrap();
        drop(h);
    }

    #[test]
    fn fetch_local_file() {
        let dir = std::env::temp_dir().join(format!("vez-librepo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.txt");
        std::fs::write(&src, b"hello librepo").unwrap();

        let h = Handle::new("vez-librepo-test/0", 5, 0, 5).unwrap();
        let dest = dir.join("dest.txt");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&dest)
            .unwrap();
        use std::os::unix::io::AsRawFd;
        h.fetch_to_fd(&format!("file://{}", src.display()), file.as_raw_fd())
            .unwrap();
        drop(file);
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello librepo");
    }

    #[test]
    fn download_target_https() {
        let dir = std::env::temp_dir().join(format!("vez-librepo-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("example.html");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&dest)
            .unwrap();
        use std::os::unix::io::AsRawFd;
        let h = Handle::new("vez-librepo-test/0", 10, 0, 10).unwrap();
        let progress = Arc::new(AtomicU64::new(0));
        h.download_target(
            "https://example.com/",
            file.as_raw_fd(),
            false,
            0,
            Some(progress.clone()),
        )
        .unwrap();
        drop(file);
        let body = std::fs::read(&dest).unwrap();
        assert!(!body.is_empty());
        assert!(progress.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn parse_status_from_message() {
        assert_eq!(
            parse_http_status("Status code: 404 for http://example.com/x"),
            Some(404)
        );
        assert_eq!(parse_http_status("some other failure"), None);
    }
}
