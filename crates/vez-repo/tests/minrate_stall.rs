//! Live check that a connection trickling well below `minrate=` bytes/sec
//! gets treated as stalled and aborted instead of waited on forever. A mirror
//! crawling at a few bytes/sec ("12 B/s eta 23w", seen in the wild) used to
//! hang indefinitely because the stall check only caught zero progress. Uses
//! a real local TCP server sending a few bytes a second, so this exercises
//! the `tokio::select!`/interval watchdogs in `vez_repo::net` and not only
//! the `parse_bytes` helper.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

/// Accepts one connection, sends a `Content-Length` header for `body_len`
/// bytes, then trickles `per_tick` bytes every second until the client gives
/// up and closes. The transfer never completes, so a success here would mean
/// the stall watchdog never fired.
fn spawn_trickle_server(body_len: usize, per_tick: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let header =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n");
        if stream.write_all(header.as_bytes()).is_err() {
            return;
        }
        loop {
            if stream.write_all(&vec![b'x'; per_tick]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn get_bytes_with_retry_aborts_on_sub_minrate_throughput() {
    // 1 attempt (fail fast instead of retrying the same dead trickle 4x), a
    // 2s stall window, and a 1000 B/s floor. The server sends 5 B/s, far
    // below the floor, so the first stall check should trip.
    vez_repo::set_max_attempts(1);
    vez_repo::set_stall_timeout(2);
    vez_repo::set_minrate(1000);

    let url = spawn_trickle_server(2_000_000, 5);
    let client = reqwest::Client::new();

    let start = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        vez_repo::get_bytes_with_retry(&client, &url),
    )
    .await;
    let elapsed = start.elapsed();

    // Must return before our outer 10s test timeout, and must be an error: a
    // trickle this slow will never finish 2 MiB.
    let result = result.expect("stall watchdog never fired — hung past the outer test timeout");
    assert!(
        result.is_err(),
        "expected a stall error, got a successful download"
    );
    assert!(
        elapsed < Duration::from_secs(6),
        "took {elapsed:?} to detect the stall, expected ~2s"
    );
}

#[tokio::test]
async fn download_to_file_with_retry_ex_aborts_on_sub_minrate_throughput() {
    vez_repo::set_max_attempts(1);
    vez_repo::set_stall_timeout(2);
    vez_repo::set_minrate(1000);

    let url = spawn_trickle_server(2_000_000, 5);
    let client = reqwest::Client::new();
    let dir = std::env::temp_dir().join(format!("vez-minrate-test-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let dest = dir.join("pkg.rpm");

    let start = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(15),
        vez_repo::download_to_file_with_retry_ex(&client, &url, &dest, None, None),
    )
    .await;
    let elapsed = start.elapsed();

    let result = result.expect("stall watchdog never fired — hung past the outer test timeout");
    assert!(
        result.is_err(),
        "expected a stall error, got a successful download"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "took {elapsed:?} to detect the stall, expected a few seconds"
    );
}
