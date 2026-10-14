//! Live-HTTP test of the *same-repo* mirror fallback in `download_all_ex`.
//! When the mirror chosen for a `mirrorlist=`/`metalink=` repo 404s on one
//! package file, the download should retry the same `href` on the rest of
//! that repo's mirrorlist instead of failing the transaction. This reproduces
//! a real Fedora case: `ix-denver.mm.fcix.net` 404ed on
//! `Box2D-2.4.2-7.fc44.x86_64.rpm` while its own `primary.xml` still listed
//! it. Also covers the fix in `vez-repo/src/net.rs`: a definitive 404 has to
//! fail fast instead of running through every configured retry's exponential
//! backoff before the mirror-swap loop gets a turn.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use vez_core::{Nevra, Package};
use vez_repo::RepoConfig;

/// Minimal HTTP server: answers every request it accepts with `status_line` +
/// `body`. `count` is a lower bound on how many requests it must be ready
/// for, not an exact quota. librepo's mirror-speed ranking
/// (`lr_fastestmirror`, added after this test was first written) makes its
/// own TCP connect probes to each mirror before `download_all_ex` gets there,
/// on top of whatever this crate's HTTP client does, so a test can't pin down
/// the exact connection count. It accepts forever instead, and tolerates a
/// probe that connects and disconnects without finishing a request (the
/// `write_all` error is ignored instead of unwrapped).
fn spawn_server(count: usize, status_line: &'static str, body: &'static [u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if stream.write_all(response.as_bytes()).is_err() {
                continue;
            }
            let _ = stream.write_all(body);
        }
    });
    let _ = count;
    format!("http://{addr}")
}

/// Serves a fixed body to every request (used for the `mirrorlist=` text
/// endpoint). `resolve_mirrors` is only called once per download here, but
/// leaving the count open avoids a flaky hang if that ever changes.
fn spawn_static_server(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn pkg(name: &str, location: String) -> Package {
    Package {
        nevra: Nevra {
            name: name.to_string(),
            epoch: 0,
            version: "2.4.2".to_string(),
            release: "7.fc44".to_string(),
            arch: "x86_64".to_string(),
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
        location,
        repo_id: "fedora".to_string(),
        repo_priority: 99,
        repo_cost: 1000,
        install_size: 0,
        download_size: 0,
        vendor: String::new(),
        checksum_type: String::new(),
        checksum: String::new(),
    }
}

fn repo_cfg(id: &str, mirrorlist_url: String) -> RepoConfig {
    RepoConfig {
        id: id.to_string(),
        name: id.to_string(),
        base_url: None,
        mirrorlist: Some(mirrorlist_url),
        metalink: None,
        gpgcheck: false,
        gpgkeys: vec![],
        metadata_expire: vez_repo::DEFAULT_METADATA_EXPIRE,
        enabled: true,
        priority: 99,
        cost: 1000,
        exclude: vec![],
        includepkgs: vec![],
        skip_if_unavailable: None,
        proxy: None,
        proxy_username: None,
        proxy_password: None,
        username: None,
        password: None,
        sslcacert: None,
        sslclientcert: None,
        sslclientkey: None,
    }
}

/// Reproduces the real `ix-denver.mm.fcix.net` Box2D 404. The repo's
/// mirrorlist has two mirrors, the package's `location` points at the first
/// (which 404s on this one file), and the second mirror has it. The download
/// must still succeed by falling through to the second mirror.
#[tokio::test]
async fn falls_back_to_the_next_mirror_in_the_same_repos_mirrorlist_on_404() {
    // Use a high retry count, like a user's `retries=10` in vez.conf. This is
    // what makes the fast-fail-on-404 fix in vez-repo/src/net.rs matter:
    // without it, this one dead mirror would burn about 10 attempts of
    // exponential backoff before the mirror-swap loop below got a turn.
    vez_repo::set_max_attempts(10);

    // `download_all_ex` also ranks mirrors fastest-first with librepo's
    // `lr_fastestmirror` (`resolve_ranked_mirrors` ->
    // `vez_repo::fastest_mirror_sort`, real TCP connect-time probes, the same
    // mechanism dnf5 uses). It then re-probes for the current best mirror
    // with `resolve_base_url` (a `HEAD` per mirror, in ranked order, stopping
    // at the first success) before fetching, and the fetch goes through
    // `ripget`, which sends its own `Range: bytes=0-0` metadata probe before
    // the data connection. How many connections each mirror gets from all
    // that is an implementation detail this test doesn't pin down (see
    // `spawn_server`). What it checks is that the dead mirror's 404 doesn't
    // stop the live mirror from being found and used.
    let dead_mirror = spawn_server(2, "HTTP/1.1 404 Not Found", b"not found");
    let alive_mirror = spawn_server(4, "HTTP/1.1 200 OK", b"fake Box2D rpm bytes");
    let mirrorlist_body: &'static str =
        Box::leak(format!("{dead_mirror}\n{alive_mirror}\n").into_boxed_str());
    let mirrorlist_url = spawn_static_server(mirrorlist_body);

    let cfg = repo_cfg("fedora", mirrorlist_url);
    let href = "Everything/x86_64/os/Packages/b/Box2D-2.4.2-7.fc44.x86_64.rpm";
    let package = pkg("Box2D", format!("{dead_mirror}/{href}"));

    let tmp = tempdir();
    let client = reqwest::Client::new();

    let start = Instant::now();
    let result = vez_transaction::download_all_ex(
        &client,
        &[package],
        &tmp,
        1,
        false,
        std::slice::from_ref(&cfg),
        &[],
    )
    .await
    .expect("should fall back to the alive mirror");
    let elapsed = start.elapsed();

    assert_eq!(result.len(), 1);
    assert!(result[0].rpm_path.exists());
    assert_eq!(
        std::fs::read(&result[0].rpm_path).unwrap(),
        b"fake Box2D rpm bytes"
    );

    // One dead-mirror 404 plus one successful retry must finish almost at
    // once. Before the fast-fail fix, a definitive 404 was retried
    // `max_attempts` times with `200ms * 2^attempt` backoff; at `retries=10`
    // that alone took well over a minute before the mirror-swap loop tried
    // the second mirror.
    assert!(elapsed < Duration::from_secs(5), "mirror fallback took {elapsed:?}, the dead mirror's 404 should fail fast instead of exhausting its retry budget");
}

/// Reproduces the real `gtk-vnc2` bug. `location` was built against a mirror
/// (`baseurl.txt`, from a metadata fetch that may be hours old) that isn't in
/// a *fresh* `resolve_mirrors` result. Fedora's metalink endpoint returns a
/// geo-sorted, randomized subset per request, so two calls can list different
/// mirrors. Before the fix, prefix-matching `location` against the fresh list
/// found nothing, no fallback URLs were added, and the download failed on the
/// stale mirror's 404 with no retry.
#[tokio::test]
async fn falls_back_even_when_the_used_mirror_is_absent_from_a_fresh_resolve() {
    vez_repo::set_max_attempts(10);

    // `stale_mirror` is only ever the original location's mirror. The fresh
    // metalink never mentions it, so it's tried after the (correctly
    // preferred) live mirror and is never reached once that one succeeds.
    // `alive_mirror` is the *only* mirror in the fresh resolve, so
    // `resolve_ranked_mirrors` and `resolve_base_url` both return early
    // without probing (`mirrors.len() <= 1`). Its connections are only
    // `ripget`'s `Range: bytes=0-0` probe plus the real fetch.
    let stale_mirror = spawn_server(1, "HTTP/1.1 404 Not Found", b"not found");
    let alive_mirror = spawn_server(2, "HTTP/1.1 200 OK", b"fake gtk-vnc2 rpm bytes");
    // The *fresh* metalink response only mentions `alive_mirror` and never
    // lists `stale_mirror`, simulating a geo/randomized re-resolve that
    // disagrees with the mirror `baseurl.txt` was cached from.
    let metalink_body: &'static str = Box::leak(
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/">
<files><file name="repomd.xml">
<resources>
<url protocol="http" type="http" location="US" preference="100">{alive_mirror}/repodata/repomd.xml</url>
</resources>
</file></files>
</metalink>"#
        )
        .into_boxed_str(),
    );
    let metalink_url = spawn_static_server(metalink_body);

    let cfg = RepoConfig {
        id: "fedora".to_string(),
        name: "fedora".to_string(),
        base_url: None,
        mirrorlist: None,
        metalink: Some(metalink_url),
        gpgcheck: false,
        gpgkeys: vec![],
        metadata_expire: vez_repo::DEFAULT_METADATA_EXPIRE,
        enabled: true,
        priority: 99,
        cost: 1000,
        exclude: vec![],
        includepkgs: vec![],
        skip_if_unavailable: None,
        proxy: None,
        proxy_username: None,
        proxy_password: None,
        username: None,
        password: None,
        sslcacert: None,
        sslclientcert: None,
        sslclientkey: None,
    };

    let href = "Everything/x86_64/os/Packages/g/gtk-vnc2-1.5.0-4.fc44.x86_64.rpm";
    let package = pkg("gtk-vnc2", format!("{stale_mirror}/{href}"));

    let tmp = tempdir();
    // Simulate a metadata cache written against `stale_mirror` earlier on.
    // That's what `load_repo_ex` would have left on disk before this mirror
    // went dead for this one file.
    let cache_root = tmp.join("repos");
    let cache_dir = vez_repo::repo_cache_dir(&cache_root, &cfg);
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(cache_dir.join("baseurl.txt"), &stale_mirror).unwrap();

    let client = reqwest::Client::new();
    let result = vez_transaction::download_all_ex(
        &client,
        &[package],
        &tmp,
        1,
        false,
        std::slice::from_ref(&cfg),
        &[],
    )
    .await
    .expect("should fall back despite the mirror mismatch");

    assert_eq!(result.len(), 1);
    assert_eq!(
        std::fs::read(&result[0].rpm_path).unwrap(),
        b"fake gtk-vnc2 rpm bytes"
    );
}

fn tempdir() -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("vez-mirror-fallback-test-{}", std::process::id()))
        .join(uniqueish());
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn uniqueish() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}
