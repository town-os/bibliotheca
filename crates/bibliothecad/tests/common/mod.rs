//! Shared harness for bibliothecad integration tests.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bibliotheca_core::backend::SubvolumeBackend;
use bibliotheca_core::service::BibliothecaService;
use bibliotheca_core::store::Store;
use bibliotheca_core::testing::MemoryBackend;
use bibliotheca_proto::v1::identity_client::IdentityClient;
use bibliotheca_proto::v1::ipfs_client::IpfsClient;
use bibliotheca_proto::v1::storage_client::StorageClient;
use hyper_util::rt::TokioIo;
use tempfile::TempDir;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

#[allow(dead_code)] // individual tests pick the fields they need
pub struct Harness {
    pub tmp: TempDir,
    pub socket: PathBuf,
    pub svc: BibliothecaService,
    pub backend: Arc<MemoryBackend>,
    pub server: JoinHandle<anyhow::Result<()>>,
    pub channel: Channel,
}

impl Harness {
    pub async fn new() -> Self {
        let tmp = TempDir::new().expect("tmp");
        let root = tmp.path().join("sv");
        let socket = tmp.path().join("ctl.sock");

        let backend = Arc::new(MemoryBackend::new(&root));
        let dyn_backend: Arc<dyn SubvolumeBackend> = backend.clone();
        let store = Store::open_in_memory().expect("store");
        let svc = BibliothecaService::new(store, dyn_backend);

        let svc_for_server = svc.clone();
        let socket_for_server = socket.clone();
        let server = tokio::spawn(async move {
            bibliothecad::control::serve(svc_for_server, None, None, socket_for_server).await
        });

        // Wait until the socket appears, with a hard ceiling so a
        // regression doesn't wedge CI.
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(socket.exists(), "server never bound {}", socket.display());

        let socket_for_conn = socket.clone();
        let channel = Endpoint::try_from("http://[::]:0")
            .unwrap()
            .connect_with_connector(service_fn(move |_: Uri| {
                let s = socket_for_conn.clone();
                async move {
                    let stream = UnixStream::connect(s).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .expect("connect");

        Self {
            tmp,
            socket,
            svc,
            backend,
            server,
            channel,
        }
    }

    pub fn identity(&self) -> IdentityClient<Channel> {
        IdentityClient::new(self.channel.clone())
    }
    pub fn storage(&self) -> StorageClient<Channel> {
        StorageClient::new(self.channel.clone())
    }
    pub fn ipfs(&self) -> IpfsClient<Channel> {
        IpfsClient::new(self.channel.clone())
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}
