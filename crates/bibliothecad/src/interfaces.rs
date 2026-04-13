//! Interface configuration loading + spawn helpers.

use std::path::Path;

use bibliotheca_core::service::BibliothecaService;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InterfaceFile {
    #[serde(default)]
    pub http: Option<HttpEntry>,
    #[serde(default)]
    pub s3: Option<ListenEntry>,
    #[serde(default)]
    pub solid: Option<SolidEntry>,
    #[serde(default)]
    pub dropbox: Option<ListenEntry>,
    #[serde(default)]
    pub nextcloud: Option<ListenEntry>,
    #[serde(default)]
    pub gcs: Option<ListenEntry>,
    #[serde(default)]
    pub icloud: Option<ICloudEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEntry {
    /// Opt-in by default — must be explicitly true.
    #[serde(default)]
    pub enabled: bool,
    pub listen: String,
    #[serde(default)]
    pub allow_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenEntry {
    #[serde(default)]
    pub enabled: bool,
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidEntry {
    #[serde(default)]
    pub enabled: bool,
    pub listen: String,
    pub base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ICloudEntry {
    #[serde(default)]
    pub enabled: bool,
    pub listen: String,
    pub container: String,
}

pub fn load(path: Option<&Path>) -> anyhow::Result<InterfaceFile> {
    let Some(path) = path else {
        return Ok(InterfaceFile::default());
    };
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn spawn_enabled(svc: BibliothecaService, ifaces: &InterfaceFile) {
    if let Some(http) = &ifaces.http {
        if http.enabled {
            let svc = svc.clone();
            let listen = http.listen.clone();
            let allow_public = http.allow_public;
            tokio::spawn(async move {
                let addr = match listen.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, listen = %listen, "invalid http listen");
                        return;
                    }
                };
                if let Err(e) = bibliotheca_http::start(
                    svc,
                    bibliotheca_http::HttpConfig {
                        listen: addr,
                        allow_public,
                    },
                )
                .await
                {
                    warn!(error = %e, "http interface exited");
                }
            });
        } else {
            info!("http interface present but disabled (default)");
        }
    }

    if let Some(cfg) = &ifaces.s3 {
        if cfg.enabled {
            spawn_listen(svc.clone(), &cfg.listen, "s3", |svc, addr| async move {
                bibliotheca_s3::start(
                    svc,
                    bibliotheca_s3::S3Config {
                        listen: addr,
                        region: "bibliotheca".into(),
                    },
                )
                .await
            });
        }
    }

    if let Some(cfg) = &ifaces.solid {
        if cfg.enabled {
            let svc = svc.clone();
            let listen = cfg.listen.clone();
            let base_url = cfg.base_url.clone();
            tokio::spawn(async move {
                let addr = match listen.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "invalid solid listen");
                        return;
                    }
                };
                if let Err(e) =
                    bibliotheca_solid::start(svc, bibliotheca_solid::SolidConfig { listen: addr, base_url })
                        .await
                {
                    warn!(error = %e, "solid interface exited");
                }
            });
        }
    }

    if let Some(cfg) = &ifaces.dropbox {
        if cfg.enabled {
            spawn_listen(svc.clone(), &cfg.listen, "dropbox", |svc, addr| async move {
                bibliotheca_dropbox::start(svc, bibliotheca_dropbox::DropboxConfig { listen: addr }).await
            });
        }
    }

    if let Some(cfg) = &ifaces.nextcloud {
        if cfg.enabled {
            spawn_listen(svc.clone(), &cfg.listen, "nextcloud", |svc, addr| async move {
                bibliotheca_nextcloud::start(
                    svc,
                    bibliotheca_nextcloud::NextcloudConfig { listen: addr },
                )
                .await
            });
        }
    }

    if let Some(cfg) = &ifaces.gcs {
        if cfg.enabled {
            spawn_listen(svc.clone(), &cfg.listen, "gcs", |svc, addr| async move {
                bibliotheca_gcs::start(svc, bibliotheca_gcs::GcsConfig { listen: addr }).await
            });
        }
    }

    if let Some(cfg) = &ifaces.icloud {
        if cfg.enabled {
            let svc = svc.clone();
            let listen = cfg.listen.clone();
            let container = cfg.container.clone();
            tokio::spawn(async move {
                let addr = match listen.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "invalid icloud listen");
                        return;
                    }
                };
                if let Err(e) = bibliotheca_icloud::start(
                    svc,
                    bibliotheca_icloud::ICloudConfig {
                        listen: addr,
                        container,
                    },
                )
                .await
                {
                    warn!(error = %e, "icloud interface exited");
                }
            });
        }
    }
}

fn spawn_listen<F, Fut>(svc: BibliothecaService, listen: &str, name: &'static str, f: F)
where
    F: FnOnce(BibliothecaService, std::net::SocketAddr) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
    let listen = listen.to_string();
    tokio::spawn(async move {
        let addr = match listen.parse() {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, name, "invalid listen");
                return;
            }
        };
        if let Err(e) = f(svc, addr).await {
            warn!(error = %e, name, "interface exited");
        }
    });
}
