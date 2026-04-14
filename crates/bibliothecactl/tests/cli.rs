//! End-to-end CLI test: spawns the bibliothecad gRPC control server
//! in-process on a tempdir Unix socket, then drives the *built*
//! `bibliothecactl` binary against it via `std::process::Command`.
//!
//! This exercises the actual clap argument parser, the tonic UDS
//! connector glue in `main.rs`, and the output formatting — none of
//! which the in-process gRPC tests can reach.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::task::JoinHandle;

struct Daemon {
    _tmp: TempDir,
    socket: PathBuf,
    handle: JoinHandle<anyhow::Result<()>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn_daemon() -> Daemon {
    let tmp = TempDir::new().unwrap();
    let socket = tmp.path().join("ctl.sock");
    let root = tmp.path().join("sv");
    let backend = Arc::new(MemoryBackend::new(&root));
    let dyn_backend: Arc<dyn SubvolumeBackend> = backend;
    let store = Store::open_in_memory().unwrap();
    let svc = BibliothecaService::new(store, dyn_backend);

    let socket_for_server = socket.clone();
    let handle =
        tokio::spawn(
            async move { bibliothecad::control::serve(svc, None, socket_for_server).await },
        );

    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(socket.exists(), "daemon never bound {}", socket.display());

    Daemon {
        _tmp: tmp,
        socket,
        handle,
    }
}

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

async fn run_ctl(socket: &Path, args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_bibliothecactl");
    let out = Command::new(bin)
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .await
        .expect("spawn bibliothecactl");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Helper: pull the first tab-separated column off a line of stdout.
fn first_col(s: &str) -> &str {
    s.trim().split('\t').next().unwrap_or("").trim()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn help_runs_without_daemon() {
    // `--help` should short-circuit before any RPC attempt, so no
    // daemon needs to be running for this to succeed.
    let tmp = TempDir::new().unwrap();
    let fake_socket = tmp.path().join("nope.sock");
    let out = run_ctl(&fake_socket, &["--help"]).await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("user"));
    assert!(out.stdout.contains("subvolume"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_lifecycle_via_cli() {
    let d = spawn_daemon().await;

    let create = run_ctl(
        &d.socket,
        &[
            "user",
            "create",
            "alice",
            "--password",
            "pw",
            "--display",
            "Alice",
        ],
    )
    .await;
    assert_eq!(create.code, 0, "stderr: {}", create.stderr);
    let uid = first_col(&create.stdout).to_string();
    assert!(!uid.is_empty(), "expected uid in: {:?}", create.stdout);

    let list = run_ctl(&d.socket, &["user", "list"]).await;
    assert_eq!(list.code, 0);
    assert!(list.stdout.contains("alice"));
    assert!(list.stdout.contains("Alice"));
    assert!(list.stdout.contains(&uid));

    let del = run_ctl(&d.socket, &["user", "delete", &uid]).await;
    assert_eq!(del.code, 0, "stderr: {}", del.stderr);

    let list = run_ctl(&d.socket, &["user", "list"]).await;
    assert_eq!(list.code, 0);
    assert!(!list.stdout.contains("alice"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_and_subvolume_flow_via_cli() {
    let d = spawn_daemon().await;

    let u = run_ctl(&d.socket, &["user", "create", "alice", "--password", "pw"]).await;
    assert_eq!(u.code, 0, "stderr: {}", u.stderr);
    let uid = first_col(&u.stdout).to_string();

    let g = run_ctl(
        &d.socket,
        &["group", "create", "staff", "--description", "internal"],
    )
    .await;
    assert_eq!(g.code, 0, "stderr: {}", g.stderr);
    let gid = first_col(&g.stdout).to_string();

    let add = run_ctl(&d.socket, &["group", "add", &uid, &gid]).await;
    assert_eq!(add.code, 0, "stderr: {}", add.stderr);

    let gl = run_ctl(&d.socket, &["group", "list"]).await;
    assert_eq!(gl.code, 0);
    assert!(gl.stdout.contains("staff"));
    assert!(gl.stdout.contains("internal"));

    let sv = run_ctl(
        &d.socket,
        &[
            "subvolume",
            "create",
            "photos",
            "--owner",
            &uid,
            "--quota",
            "4096",
        ],
    )
    .await;
    assert_eq!(sv.code, 0, "stderr: {}", sv.stderr);
    let sid = first_col(&sv.stdout).to_string();
    // Subvolume stdout is "<id>\t<name>\t<mount>"
    assert!(sv.stdout.contains("photos"), "{:?}", sv.stdout);

    let list = run_ctl(&d.socket, &["subvolume", "list"]).await;
    assert_eq!(list.code, 0);
    assert!(list.stdout.contains(&sid));
    assert!(list.stdout.contains("photos"));

    let filtered = run_ctl(&d.socket, &["subvolume", "list", "--owner", &uid]).await;
    assert_eq!(filtered.code, 0);
    assert!(filtered.stdout.contains("photos"));

    let qota = run_ctl(&d.socket, &["subvolume", "quota", &sid, "8192"]).await;
    assert_eq!(qota.code, 0, "stderr: {}", qota.stderr);

    let del = run_ctl(&d.socket, &["subvolume", "delete", &sid]).await;
    assert_eq!(del.code, 0, "stderr: {}", del.stderr);

    let list = run_ctl(&d.socket, &["subvolume", "list"]).await;
    assert_eq!(list.code, 0);
    assert!(!list.stdout.contains("photos"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reports_not_found_via_nonzero_exit() {
    let d = spawn_daemon().await;
    // Nonsense UUID — tonic returns InvalidArgument or NotFound.
    let out = run_ctl(
        &d.socket,
        &["user", "delete", "00000000-0000-0000-0000-000000000000"],
    )
    .await;
    assert_ne!(
        out.code, 0,
        "expected failure exit, got stdout={:?}",
        out.stdout
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_fails_cleanly_when_socket_missing() {
    let tmp = TempDir::new().unwrap();
    let out = run_ctl(&tmp.path().join("nope.sock"), &["user", "list"]).await;
    assert_ne!(out.code, 0);
    assert!(!out.stderr.is_empty(), "expected some diagnostic on stderr");
}
