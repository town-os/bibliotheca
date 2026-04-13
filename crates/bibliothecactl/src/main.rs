//! `bibliothecactl` — administrative CLI that talks to bibliothecad over its
//! Unix-domain gRPC socket.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use hyper_util::rt::TokioIo;
use bibliotheca_proto::v1::identity_client::IdentityClient;
use bibliotheca_proto::v1::storage_client::StorageClient;
use bibliotheca_proto::v1::{
    AddUserToGroupRequest, CreateGroupRequest, CreateSubvolumeRequest, CreateUserRequest,
    DeleteSubvolumeRequest, DeleteUserRequest, ListGroupsRequest, ListSubvolumesRequest,
    ListUsersRequest, SetQuotaRequest,
};
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

#[derive(Debug, Parser)]
#[command(name = "bibliothecactl", version, about = "Bibliotheca control client")]
struct Args {
    #[arg(long, env = "BIBLIOTHECA_SOCKET", default_value = "/run/bibliotheca/control.sock")]
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
                    client.delete_subvolume(DeleteSubvolumeRequest { id, force }).await?;
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
