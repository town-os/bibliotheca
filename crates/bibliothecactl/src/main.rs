//! `bibliothecactl` — administrative CLI that talks to bibliothecad over its
//! Unix-domain gRPC socket.

use std::path::PathBuf;

use bibliotheca_config::BibliothecaConfig;
use bibliotheca_oauth::{run_flow, BrokerParams};
use bibliotheca_proto::v1::anisette_admin_client::AnisetteAdminClient;
use bibliotheca_proto::v1::archives_client::ArchivesClient;
use bibliotheca_proto::v1::identity_client::IdentityClient;
use bibliotheca_proto::v1::sharing_client::SharingClient;
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

    /// Path to a bibliotheca config file. Used by subcommands that
    /// need to know about OAuth provider profiles, share defaults,
    /// etc. Falls back to `/etc/bibliotheca/bibliotheca.yml` if the
    /// default exists, otherwise to built-in defaults.
    #[arg(long, env = "BIBLIOTHECA_CONFIG")]
    config: Option<PathBuf>,

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
    /// Share-link (unguessable URL) management.
    Share {
        #[command(subcommand)]
        cmd: ShareCmd,
    },
    /// Per-subvolume archival (snapshots or tarballs).
    Archive {
        #[command(subcommand)]
        cmd: ArchiveCmd,
    },
    /// Embedded anisette proxy.
    Anisette {
        #[command(subcommand)]
        cmd: AnisetteCmd,
    },
}

#[derive(Debug, Subcommand)]
enum ArchiveCmd {
    /// Create an archive (snapshot or tarball) for a subvolume.
    Create {
        #[arg(long)]
        subvolume: String,
        #[arg(long)]
        name: String,
        /// Archive kind. "snapshot" is zero-copy via btrfs;
        /// "tarball" streams every file into a single .tar under
        /// `archive.root`. Empty → daemon default.
        #[arg(long, default_value = "")]
        kind: String,
        /// Retention window in days. 0 = use daemon default.
        #[arg(long, default_value_t = 0)]
        retention_days: u64,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long)]
        owner: Option<String>,
    },
    List {
        #[arg(long)]
        subvolume: Option<String>,
    },
    Get {
        id: String,
    },
    Delete {
        id: String,
        #[arg(long)]
        force: bool,
    },
    Verify {
        id: String,
    },
    Restore {
        id: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        overwrite: bool,
    },
    Manifest {
        id: String,
    },
    PolicySet {
        #[arg(long)]
        subvolume: String,
        #[arg(long)]
        kind: String,
        #[arg(long, default_value_t = 0)]
        retention_days: u64,
        #[arg(long, default_value_t = 86400)]
        interval_secs: u64,
        #[arg(long, default_value_t = 1)]
        min_age_days: u64,
        #[arg(long, default_value_t = true)]
        enabled: bool,
    },
    PolicyGet {
        subvolume: String,
    },
    PolicyDelete {
        subvolume: String,
    },
    PolicyList,
    LifecycleRun,
}

#[derive(Debug, Subcommand)]
enum ShareCmd {
    /// Mint a new share token for a subvolume (and optionally a
    /// single key inside it).
    Create {
        #[arg(long)]
        subvolume: String,
        #[arg(long)]
        owner: String,
        /// Optional pinned key. Omit for a whole-subvolume share.
        #[arg(long)]
        key: Option<String>,
        /// Seconds the share should live. 0 = use daemon default.
        #[arg(long, default_value_t = 0)]
        ttl_secs: u64,
        /// Maximum number of successful uses. 0 = use daemon default
        /// (which in turn defaults to unlimited).
        #[arg(long, default_value_t = 0)]
        use_limit: u64,
        #[arg(long, default_value = "")]
        note: String,
    },
    List {
        /// Restrict listing to one subvolume (id or name).
        #[arg(long)]
        subvolume: Option<String>,
    },
    Get {
        id_or_token: String,
    },
    Revoke {
        id: String,
    },
    Delete {
        id: String,
    },
    Events {
        id: String,
        #[arg(long, default_value_t = 100)]
        limit: u32,
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
    /// Three-legged OAuth broker: runs the authorize + code exchange
    /// flow locally and uploads the resulting refresh token to the
    /// daemon. Operators do this once per provider account before
    /// creating a mount.
    Oauth {
        #[command(subcommand)]
        cmd: SyncOauthCmd,
    },
}

#[derive(Debug, Subcommand)]
enum SyncMountCmd {
    /// Create a new mount. Credentials are read from a file (JSON)
    /// to keep them out of the process command line, or reused from
    /// a previous `sync oauth run` that returned a credentials id.
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
        /// Mutually exclusive with `--existing-credentials-id`.
        #[arg(long, conflicts_with = "existing_credentials_id")]
        credentials_file: Option<PathBuf>,
        /// Reuse an existing encrypted credentials row — e.g. one
        /// returned by `bibliothecactl sync oauth run`. Mutually
        /// exclusive with `--credentials-file`.
        #[arg(long)]
        existing_credentials_id: Option<String>,
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

#[derive(Debug, Subcommand)]
enum SyncOauthCmd {
    /// Run the three-legged OAuth flow for the named provider
    /// (e.g. `dropbox`, `gphotos`) and upload the resulting refresh
    /// token to the daemon. Prints the new credentials id on
    /// success — pass it to `sync mount create
    /// --existing-credentials-id <id>`.
    Run {
        /// Provider profile name as it appears in the
        /// `oauth.providers` map of the bibliotheca config file.
        #[arg(long)]
        provider: String,
        /// Additional scopes to request on top of whatever the
        /// provider profile already declares. Repeatable.
        #[arg(long = "scope")]
        scopes: Vec<String>,
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
    let config_path = args.config.clone();

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
                SyncCmd::Oauth { cmd } => {
                    run_sync_oauth_cmd(&mut client, config_path.as_deref(), cmd).await?
                }
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
        Cmd::Share { cmd } => {
            let mut client = SharingClient::new(channel);
            run_share_cmd(&mut client, cmd).await?;
        }
        Cmd::Archive { cmd } => {
            let mut client = ArchivesClient::new(channel);
            run_archive_cmd(&mut client, cmd).await?;
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
            existing_credentials_id,
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
            let (credentials, existing_id) = match (credentials_file, existing_credentials_id) {
                (Some(path), None) => {
                    let raw = std::fs::read(&path)?;
                    let blob: serde_json::Value = serde_json::from_slice(&raw)?;
                    (Some(creds_from_json(&blob)?), String::new())
                }
                (None, Some(id)) => (None, id),
                (Some(_), Some(_)) => anyhow::bail!(
                    "pass exactly one of --credentials-file or --existing-credentials-id"
                ),
                (None, None) => {
                    anyhow::bail!("pass one of --credentials-file or --existing-credentials-id")
                }
            };
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
                existing_credentials_id: existing_id,
                credentials,
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

async fn run_sync_oauth_cmd(
    client: &mut SyncAdminClient<tonic::transport::Channel>,
    config_path: Option<&std::path::Path>,
    cmd: SyncOauthCmd,
) -> anyhow::Result<()> {
    match cmd {
        SyncOauthCmd::Run { provider, scopes } => {
            let cfg = BibliothecaConfig::load_or_default(config_path)?;
            let outcome = run_flow(
                BrokerParams {
                    oauth: &cfg.oauth,
                    provider: &provider,
                    extra_scopes: scopes,
                },
                |url| {
                    println!("open this URL in a browser to approve the flow:");
                    println!("{url}");
                },
            )
            .await?;
            let req = pb::StoreOAuthCredentialsRequest {
                credentials: Some(pb::OAuth2Credentials {
                    access_token: outcome.access_token,
                    refresh_token: outcome.refresh_token,
                    expires_at: outcome.expires_at,
                    client_id: outcome.client_id,
                    client_secret: outcome.client_secret,
                    token_url: outcome.token_url,
                }),
            };
            let resp = client.store_o_auth_credentials(req).await?;
            let id = resp.into_inner().credentials_id;
            println!("credentials id:\t{id}");
            println!("pass `--existing-credentials-id {id}` to `sync mount create` to bind it.");
        }
    }
    Ok(())
}

fn print_share_grant(g: &pb::ShareGrant) {
    let exp = if g.expires_at == 0 {
        "never".to_string()
    } else {
        g.expires_at.to_string()
    };
    let uses = if g.use_limit == 0 {
        format!("{}/∞", g.uses)
    } else {
        format!("{}/{}", g.uses, g.use_limit)
    };
    let state = if g.revoked { "revoked" } else { "active" };
    let key = if g.key.is_empty() {
        "<subvolume>".to_string()
    } else {
        g.key.clone()
    };
    println!(
        "{id}\t{key}\t{state}\t{uses}\t{exp}\t{token}",
        id = g.id,
        key = key,
        state = state,
        uses = uses,
        exp = exp,
        token = g.token,
    );
}

async fn run_share_cmd(
    client: &mut SharingClient<tonic::transport::Channel>,
    cmd: ShareCmd,
) -> anyhow::Result<()> {
    match cmd {
        ShareCmd::Create {
            subvolume,
            owner,
            key,
            ttl_secs,
            use_limit,
            note,
        } => {
            let resp = client
                .create(pb::CreateShareRequest {
                    subvolume_id: subvolume,
                    created_by: owner,
                    key: key.unwrap_or_default(),
                    ttl_secs,
                    use_limit,
                    note,
                })
                .await?;
            let inner = resp.into_inner();
            if let Some(g) = &inner.grant {
                print_share_grant(g);
            }
            if !inner.url.is_empty() {
                println!("url:\t{}", inner.url);
            }
        }
        ShareCmd::List { subvolume } => {
            let resp = client
                .list(pb::ListSharesRequest {
                    subvolume_id: subvolume.unwrap_or_default(),
                })
                .await?;
            for g in resp.into_inner().grants {
                print_share_grant(&g);
            }
        }
        ShareCmd::Get { id_or_token } => {
            let g = client
                .get(pb::GetShareRequest { id_or_token })
                .await?
                .into_inner();
            print_share_grant(&g);
        }
        ShareCmd::Revoke { id } => {
            client.revoke(pb::RevokeShareRequest { id }).await?;
        }
        ShareCmd::Delete { id } => {
            client.delete(pb::DeleteShareRequest { id }).await?;
        }
        ShareCmd::Events { id, limit } => {
            let resp = client
                .list_events(pb::ListShareEventsRequest { id, limit })
                .await?;
            for ev in resp.into_inner().events {
                let ts = ev.ts.map(|t| t.seconds).unwrap_or(0);
                println!(
                    "{ts}\t{action}\t{status}\t{ip}\t{key}",
                    action = ev.action,
                    status = ev.status,
                    ip = ev.remote_ip,
                    key = ev.key,
                );
            }
        }
    }
    Ok(())
}

fn print_archive(a: &pb::Archive) {
    let exp = if a.expires_at == 0 {
        "never".to_string()
    } else {
        a.expires_at.to_string()
    };
    println!(
        "{id}\t{name}\t{kind}\t{size}\t{count}\t{exp}\t{sv}",
        id = a.id,
        name = a.name,
        kind = a.kind,
        size = a.size_bytes,
        count = a.object_count,
        exp = exp,
        sv = a.subvolume_id,
    );
}

fn print_policy(p: &pb::SubvolumePolicy) {
    let retention = if p.retention_days == 0 {
        "forever".to_string()
    } else {
        format!("{}d", p.retention_days)
    };
    println!(
        "{sv}\t{kind}\tretention={ret}\tinterval={intv}s\tmin_age={min}d\tenabled={enabled}",
        sv = p.subvolume_id,
        kind = p.kind,
        ret = retention,
        intv = p.archive_interval_secs,
        min = p.min_age_days,
        enabled = p.enabled,
    );
}

async fn run_archive_cmd(
    client: &mut ArchivesClient<tonic::transport::Channel>,
    cmd: ArchiveCmd,
) -> anyhow::Result<()> {
    match cmd {
        ArchiveCmd::Create {
            subvolume,
            name,
            kind,
            retention_days,
            note,
            owner,
        } => {
            let resp = client
                .create_archive(pb::CreateArchiveRequest {
                    subvolume_id: subvolume,
                    name,
                    kind,
                    retention_days,
                    note,
                    created_by: owner.unwrap_or_default(),
                })
                .await?
                .into_inner();
            print_archive(&resp);
        }
        ArchiveCmd::List { subvolume } => {
            let resp = client
                .list_archives(pb::ListArchivesRequest {
                    subvolume_id: subvolume.unwrap_or_default(),
                })
                .await?
                .into_inner();
            for a in resp.archives {
                print_archive(&a);
            }
        }
        ArchiveCmd::Get { id } => {
            let a = client
                .get_archive(pb::GetArchiveRequest { id })
                .await?
                .into_inner();
            print_archive(&a);
        }
        ArchiveCmd::Delete { id, force } => {
            client
                .delete_archive(pb::DeleteArchiveRequest { id, force })
                .await?;
        }
        ArchiveCmd::Verify { id } => {
            let r = client
                .verify_archive(pb::VerifyArchiveRequest { id })
                .await?
                .into_inner();
            println!(
                "archive={id}\tok={ok}\ttotal={total}\tchecked={checked}\tmismatches={mm}\tmissing={miss}",
                id = r.archive_id,
                ok = r.ok,
                total = r.total,
                checked = r.checked,
                mm = r.mismatches.len(),
                miss = r.missing.len(),
            );
            for m in r.mismatches {
                println!("mismatch\t{m}");
            }
            for m in r.missing {
                println!("missing\t{m}");
            }
        }
        ArchiveCmd::Restore {
            id,
            target,
            overwrite,
        } => {
            let r = client
                .restore_archive(pb::RestoreArchiveRequest {
                    id,
                    target_subvolume_id: target,
                    overwrite,
                })
                .await?
                .into_inner();
            println!("restored\t{}", r.restored);
        }
        ArchiveCmd::Manifest { id } => {
            let r = client
                .get_manifest(pb::ArchiveManifestRequest { id })
                .await?
                .into_inner();
            for e in r.entries {
                println!("{}\t{}\t{}", e.sha256, e.size, e.key);
            }
        }
        ArchiveCmd::PolicySet {
            subvolume,
            kind,
            retention_days,
            interval_secs,
            min_age_days,
            enabled,
        } => {
            let r = client
                .set_policy(pb::SetSubvolumePolicyRequest {
                    policy: Some(pb::SubvolumePolicy {
                        subvolume_id: subvolume,
                        kind,
                        retention_days,
                        archive_interval_secs: interval_secs,
                        min_age_days,
                        enabled,
                        last_run_at: 0,
                    }),
                })
                .await?
                .into_inner();
            print_policy(&r);
        }
        ArchiveCmd::PolicyGet { subvolume } => {
            let r = client
                .get_policy(pb::GetSubvolumePolicyRequest {
                    subvolume_id: subvolume,
                })
                .await?
                .into_inner();
            print_policy(&r);
        }
        ArchiveCmd::PolicyDelete { subvolume } => {
            client
                .delete_policy(pb::DeleteSubvolumePolicyRequest {
                    subvolume_id: subvolume,
                })
                .await?;
        }
        ArchiveCmd::PolicyList => {
            let r = client.list_policies(()).await?.into_inner();
            for p in r.policies {
                print_policy(&p);
            }
        }
        ArchiveCmd::LifecycleRun => {
            client.run_lifecycle_once(()).await?;
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
