//! `bibliothecactl` — administrative CLI that talks to bibliothecad over its
//! Unix-domain gRPC socket.

use std::path::PathBuf;

use bibliotheca_proto::v1::anisette_admin_client::AnisetteAdminClient;
use bibliotheca_proto::v1::identity_client::IdentityClient;
use bibliotheca_proto::v1::storage_client::StorageClient;
use bibliotheca_proto::v1::sync_admin_client::SyncAdminClient;
use bibliotheca_proto::v1::{
    self as pb, AddUserToGroupRequest, CreateGroupRequest, CreateSubvolumeRequest,
    CreateUserRequest, DeleteSubvolumeRequest, DeleteUserRequest, ListGroupsRequest,
    ListSubvolumesRequest, ListUsersRequest, SetQuotaRequest,
};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

#[derive(Debug, Parser)]
#[command(name = "bibliothecactl", version, about = "Bibliotheca control client")]
struct Args {
    #[arg(
        long,
        env = "BIBLIOTHECA_SOCKET",
        default_value = "/run/bibliotheca/control.sock"
    )]
    socket: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Identity management.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    Subvolume {
        #[command(subcommand)]
        cmd: SubvolumeCmd,
    },
    /// Sync connector mounts.
    Sync {
        #[command(subcommand)]
        cmd: SyncCmd,
    },
    /// Embedded anisette proxy.
    Anisette {
        #[command(subcommand)]
        cmd: AnisetteCmd,
    },
}

#[derive(Debug, Subcommand)]
enum AnisetteCmd {
    /// Print the proxy's current state: upstreams, call counts,
    /// last success timestamp, cached-until.
    Status,
    /// Clear the cached OTP and upstream backoff state so the next
    /// request hits upstream fresh.
    Reset,
    /// Register a new upstream anisette peer at runtime.
    AddPeer { url: String },
    /// Remove a previously-added upstream.
    RemovePeer { url: String },
    /// Print the current list of upstream URLs.
    ListPeers,
}

#[derive(Debug, Subcommand)]
enum UserCmd {
    Create {
        name: String,
        #[arg(long)]
        display: Option<String>,
        #[arg(long)]
        password: String,
    },
    List,
    Delete {
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum GroupCmd {
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    List,
    Add {
        user_id: String,
        group_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum SubvolumeCmd {
    Create {
        name: String,
        #[arg(long)]
        owner: String,
        #[arg(long, default_value_t = 0)]
        quota: u64,
    },
    List {
        #[arg(long)]
        owner: Option<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        force: bool,
    },
    Quota {
        id: String,
        bytes: u64,
    },
}

#[derive(Debug, Subcommand)]
enum SyncCmd {
    /// Mount management.
    Mount {
        #[command(subcommand)]
        cmd: SyncMountCmd,
    },
    /// Submit a two-factor code for a mount blocked on 2FA auth
    /// (iCloud, typically).
    Twofactor {
        #[command(subcommand)]
        cmd: SyncTwofactorCmd,
    },
    /// Tail sync events over a server-streaming RPC.
    Events {
        #[command(subcommand)]
        cmd: SyncEventsCmd,
    },
    /// Rotate the master encryption key for credentials at rest.
    Secret {
        #[command(subcommand)]
        cmd: SyncSecretCmd,
    },
}

#[derive(Debug, Subcommand)]
enum SyncMountCmd {
    /// Create a new mount. Credentials are read from a file (JSON)
    /// to keep them out of the process command line.
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        kind: String,
        #[arg(long, default_value = "pull")]
        direction: String,
        #[arg(long)]
        owner: String,
        #[arg(long, default_value_t = 0)]
        quota_bytes: u64,
        #[arg(long, default_value_t = 300)]
        interval_secs: u32,
        /// Path to a JSON file describing the credentials to use.
        /// Shape matches the CredentialBlob enum — e.g.
        /// `{"kind":"basic","username":"alice","password":"hunter2"}`.
        #[arg(long)]
        credentials_file: PathBuf,
        /// Repeatable `--config key=val`.
        #[arg(long = "config", value_parser = parse_kv)]
        config: Vec<(String, String)>,
    },
    List,
    Get {
        id_or_name: String,
    },
    SetQuota {
        id: String,
        bytes: u64,
    },
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
    Trigger {
        id: String,
    },
    Delete {
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum SyncTwofactorCmd {
    Submit { id: String, code: String },
}

#[derive(Debug, Subcommand)]
enum SyncEventsCmd {
    Tail {
        #[arg(long)]
        mount: Option<String>,
        #[arg(long, default_value_t = 0)]
        since_unix: i64,
    },
}

#[derive(Debug, Subcommand)]
enum SyncSecretCmd {
    Rotate {
        #[arg(long)]
        hex: String,
    },
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected key=value, got: {s}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Args::parse();
    let socket = args.socket.clone();

    // tonic requires a URI even for unix sockets — the actual connect
    // happens via the connector below.
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                let stream = UnixStream::connect(socket).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;

    match args.command {
        Cmd::User { cmd } => {
            let mut client = IdentityClient::new(channel);
            match cmd {
                UserCmd::Create {
                    name,
                    display,
                    password,
                } => {
                    let display_name = display.unwrap_or_else(|| name.clone());
                    let resp = client
                        .create_user(CreateUserRequest {
                            name,
                            display_name,
                            password,
                        })
                        .await?;
                    let u = resp.into_inner();
                    println!("{}\t{}", u.id, u.name);
                }
                UserCmd::List => {
                    let resp = client
                        .list_users(ListUsersRequest {
                            limit: 0,
                            offset: 0,
                        })
                        .await?;
                    for u in resp.into_inner().users {
                        println!("{}\t{}\t{}", u.id, u.name, u.display_name);
                    }
                }
                UserCmd::Delete { id } => {
                    client.delete_user(DeleteUserRequest { id }).await?;
                }
            }
        }
        Cmd::Group { cmd } => {
            let mut client = IdentityClient::new(channel);
            match cmd {
                GroupCmd::Create { name, description } => {
                    let resp = client
                        .create_group(CreateGroupRequest { name, description })
                        .await?;
                    let g = resp.into_inner();
                    println!("{}\t{}", g.id, g.name);
                }
                GroupCmd::List => {
                    let resp = client
                        .list_groups(ListGroupsRequest {
                            limit: 0,
                            offset: 0,
                        })
                        .await?;
                    for g in resp.into_inner().groups {
                        println!("{}\t{}\t{}", g.id, g.name, g.description);
                    }
                }
                GroupCmd::Add { user_id, group_id } => {
                    client
                        .add_user_to_group(AddUserToGroupRequest { user_id, group_id })
                        .await?;
                }
            }
        }
        Cmd::Anisette { cmd } => {
            let mut client = AnisetteAdminClient::new(channel);
            match cmd {
                AnisetteCmd::Status => {
                    let s = client.status(()).await?.into_inner();
                    if !s.enabled {
                        println!("anisette\tdisabled");
                    } else {
                        println!(
                            "kind\t{kind}\nlisten\t{listen}\nlast_success_at\t{last}\ncached_until\t{cached}",
                            kind = s.kind,
                            listen = s.listen,
                            last = s.last_success_at,
                            cached = s.cached_until
                        );
                        for u in s.upstreams {
                            println!(
                                "upstream\t{url}\tok={ok}\terr={err}\t{last}",
                                url = u.url,
                                ok = u.ok_count,
                                err = u.err_count,
                                last = u.last_error
                            );
                        }
                    }
                }
                AnisetteCmd::Reset => {
                    client.reset(()).await?;
                }
                AnisetteCmd::AddPeer { url } => {
                    client.add_peer(pb::AnisettePeerRequest { url }).await?;
                }
                AnisetteCmd::RemovePeer { url } => {
                    client.remove_peer(pb::AnisettePeerRequest { url }).await?;
                }
                AnisetteCmd::ListPeers => {
                    let resp = client.list_peers(()).await?.into_inner();
                    for u in resp.urls {
                        println!("{u}");
                    }
                }
            }
        }
        Cmd::Sync { cmd } => {
            let mut client = SyncAdminClient::new(channel);
            match cmd {
                SyncCmd::Mount { cmd } => run_sync_mount_cmd(&mut client, cmd).await?,
                SyncCmd::Twofactor { cmd } => match cmd {
                    SyncTwofactorCmd::Submit { id, code } => {
                        client
                            .submit_two_factor_code(pb::SubmitTwoFactorCodeRequest { id, code })
                            .await?;
                    }
                },
                SyncCmd::Events { cmd } => match cmd {
                    SyncEventsCmd::Tail { mount, since_unix } => {
                        let req = pb::TailEventsRequest {
                            mount_id: mount.unwrap_or_default(),
                            since_unix,
                        };
                        let mut stream = client.tail_events(req).await?.into_inner();
                        while let Some(msg) = stream.next().await {
                            match msg {
                                Ok(ev) => {
                                    let ts = ev.ts.map(|t| t.seconds).unwrap_or(0);
                                    println!(
                                        "{ts}\t{level}\t{kind}\t{mount}\t{msg}",
                                        level = ev.level,
                                        kind = ev.kind,
                                        mount = ev.mount_id,
                                        msg = ev.message
                                    );
                                }
                                Err(e) => {
                                    eprintln!("stream error: {e}");
                                    break;
                                }
                            }
                        }
                    }
                },
                SyncCmd::Secret { cmd } => match cmd {
                    SyncSecretCmd::Rotate { hex } => {
                        client
                            .rotate_secret_key(pb::RotateSecretKeyRequest { new_hex_key: hex })
                            .await?;
                    }
                },
            }
        }
        Cmd::Subvolume { cmd } => {
            let mut client = StorageClient::new(channel);
            match cmd {
                SubvolumeCmd::Create { name, owner, quota } => {
                    let resp = client
                        .create_subvolume(CreateSubvolumeRequest {
                            name,
                            owner_user_id: owner,
                            quota_bytes: quota,
                            acl: None,
                        })
                        .await?;
                    let sv = resp.into_inner();
                    println!("{}\t{}\t{}", sv.id, sv.name, sv.mount_path);
                }
                SubvolumeCmd::List { owner } => {
                    let resp = client
                        .list_subvolumes(ListSubvolumesRequest {
                            owner_user_id: owner.unwrap_or_default(),
                            limit: 0,
                            offset: 0,
                        })
                        .await?;
                    for sv in resp.into_inner().subvolumes {
                        println!("{}\t{}\t{}", sv.id, sv.name, sv.mount_path);
                    }
                }
                SubvolumeCmd::Delete { id, force } => {
                    client
                        .delete_subvolume(DeleteSubvolumeRequest { id, force })
                        .await?;
                }
                SubvolumeCmd::Quota { id, bytes } => {
                    client
                        .set_quota(SetQuotaRequest {
                            id,
                            quota_bytes: bytes,
                        })
                        .await?;
                }
            }
        }
    }

    Ok(())
}

fn print_mount(m: &pb::SyncMount) {
    let kind = pb::SyncConnectorKind::try_from(m.kind)
        .map(|k| k.as_str_name().to_string())
        .unwrap_or_else(|_| m.kind.to_string());
    let dir = pb::SyncDirection::try_from(m.direction)
        .map(|d| d.as_str_name().to_string())
        .unwrap_or_else(|_| m.direction.to_string());
    let paused = if m.paused { "paused" } else { "active" };
    println!(
        "{id}\t{name}\t{kind}\t{dir}\t{quota}\t{paused}\t{err}",
        id = m.id,
        name = m.name,
        kind = kind,
        dir = dir,
        quota = m.quota_bytes,
        paused = paused,
        err = m.last_error,
    );
}

async fn run_sync_mount_cmd(
    client: &mut SyncAdminClient<tonic::transport::Channel>,
    cmd: SyncMountCmd,
) -> anyhow::Result<()> {
    match cmd {
        SyncMountCmd::Create {
            name,
            kind,
            direction,
            owner,
            quota_bytes,
            interval_secs,
            credentials_file,
            config,
        } => {
            let kind_pb = match kind.as_str() {
                "icloud" | "icloud_photos" => pb::SyncConnectorKind::SyncConnectorIcloudPhotos,
                "dropbox" => pb::SyncConnectorKind::SyncConnectorDropbox,
                "nextcloud" | "webdav" => pb::SyncConnectorKind::SyncConnectorNextcloud,
                "solid" => pb::SyncConnectorKind::SyncConnectorSolid,
                "gphotos" | "google_photos" => pb::SyncConnectorKind::SyncConnectorGooglePhotos,
                "ipfs" => pb::SyncConnectorKind::SyncConnectorIpfs,
                other => anyhow::bail!("unknown kind: {other}"),
            };
            let direction_pb = match direction.as_str() {
                "pull" => pb::SyncDirection::Pull,
                "push" => pb::SyncDirection::Push,
                "both" => pb::SyncDirection::Both,
                other => anyhow::bail!("unknown direction: {other}"),
            };
            let raw = std::fs::read(&credentials_file)?;
            let blob: serde_json::Value = serde_json::from_slice(&raw)?;
            let credentials = creds_from_json(&blob)?;
            let config_map: std::collections::HashMap<String, String> =
                config.into_iter().collect();
            let req = pb::CreateMountRequest {
                name,
                kind: kind_pb as i32,
                direction: direction_pb as i32,
                quota_bytes,
                interval_secs,
                owner_user_id: owner,
                config: config_map,
                credentials: Some(credentials),
            };
            let resp = client.create_mount(req).await?;
            print_mount(&resp.into_inner());
        }
        SyncMountCmd::List => {
            let resp = client.list_mounts(()).await?;
            for m in resp.into_inner().mounts {
                print_mount(&m);
            }
        }
        SyncMountCmd::Get { id_or_name } => {
            let resp = client.get_mount(pb::GetMountRequest { id_or_name }).await?;
            print_mount(&resp.into_inner());
        }
        SyncMountCmd::SetQuota { id, bytes } => {
            let resp = client
                .update_mount(pb::UpdateMountRequest {
                    id,
                    interval_secs: None,
                    direction: None,
                    quota_bytes: Some(bytes),
                })
                .await?;
            print_mount(&resp.into_inner());
        }
        SyncMountCmd::Pause { id } => {
            let resp = client.pause(pb::MountIdRequest { id }).await?;
            print_mount(&resp.into_inner());
        }
        SyncMountCmd::Resume { id } => {
            let resp = client.resume(pb::MountIdRequest { id }).await?;
            print_mount(&resp.into_inner());
        }
        SyncMountCmd::Trigger { id } => {
            client.trigger_sync(pb::MountIdRequest { id }).await?;
        }
        SyncMountCmd::Delete { id } => {
            client.delete_mount(pb::DeleteMountRequest { id }).await?;
        }
    }
    Ok(())
}

fn creds_from_json(v: &serde_json::Value) -> anyhow::Result<pb::create_mount_request::Credentials> {
    let kind = v
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| anyhow::anyhow!("credentials file missing 'kind' field"))?;
    Ok(match kind {
        "basic" => pb::create_mount_request::Credentials::Basic(pb::BasicCredentials {
            username: v["username"].as_str().unwrap_or("").to_string(),
            password: v["password"].as_str().unwrap_or("").to_string(),
        }),
        "token" => pb::create_mount_request::Credentials::Token(pb::TokenCredentials {
            token: v["token"].as_str().unwrap_or("").to_string(),
            refresh_token: v["refresh_token"].as_str().unwrap_or("").to_string(),
            expires_at: v["expires_at"].as_i64().unwrap_or(0),
        }),
        "oauth2" => pb::create_mount_request::Credentials::Oauth2(pb::OAuth2Credentials {
            access_token: v["access_token"].as_str().unwrap_or("").to_string(),
            refresh_token: v["refresh_token"].as_str().unwrap_or("").to_string(),
            expires_at: v["expires_at"].as_i64().unwrap_or(0),
            client_id: v["client_id"].as_str().unwrap_or("").to_string(),
            client_secret: v["client_secret"].as_str().unwrap_or("").to_string(),
            token_url: v["token_url"].as_str().unwrap_or("").to_string(),
        }),
        "icloud" => pb::create_mount_request::Credentials::Icloud(pb::ICloudCredentials {
            apple_id: v["apple_id"].as_str().unwrap_or("").to_string(),
            password: v["password"].as_str().unwrap_or("").to_string(),
            anisette_url: v["anisette_url"].as_str().unwrap_or("").to_string(),
        }),
        "ipfs" => pb::create_mount_request::Credentials::Ipfs(pb::IpfsCredentials {
            api_url: v["api_url"].as_str().unwrap_or("").to_string(),
            auth_header: v["auth_header"].as_str().unwrap_or("").to_string(),
        }),
        other => anyhow::bail!("unknown credentials kind: {other}"),
    })
}
