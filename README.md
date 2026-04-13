# bibliotheca

Object storage for [town-os]. Rust, controlled over a local gRPC socket,
backed by btrfs subvolumes, with multiple data-plane interfaces hung off
a single user / group / ACL model.

[town-os]: https://gitea.com/town-os/town-os

## Layout

```
bibliotheca/
├── proto/bibliotheca/v1/control.proto   # gRPC schema
└── crates/
    ├── bibliotheca-proto       # tonic-generated bindings
    ├── bibliotheca-core        # users, groups, ACL, sqlite store, service
    ├── bibliotheca-btrfs       # SubvolumeBackend implementation
    ├── bibliotheca-ipfs        # Kubo client + ingest helpers
    ├── bibliotheca-http        # authenticated HTTP (opt-in by default)
    ├── bibliotheca-s3          # S3 v2/v4 compat
    ├── bibliotheca-solid       # Solid pods (LDP + WAC)
    ├── bibliotheca-dropbox     # Dropbox v2 API surface
    ├── bibliotheca-nextcloud   # Nextcloud WebDAV + OCS
    ├── bibliotheca-gcs         # Google Cloud Storage JSON API
    ├── bibliotheca-icloud      # iCloud / CloudKit Web Services
    ├── bibliothecad            # the daemon binary
    └── bibliothecactl          # admin CLI talking to the daemon socket
```

## Architecture

There are two planes:

**Control plane.** `bibliothecad` listens on a Unix domain socket
(`/run/bibliotheca/control.sock` by default) and serves the gRPC services
defined in `proto/bibliotheca/v1/control.proto`:

- `bibliotheca.v1.Identity` — users, groups, group membership.
- `bibliotheca.v1.Storage`  — subvolumes, ACLs, snapshots, quotas.
- `bibliotheca.v1.Interfaces` — view and (eventually) toggle data-plane
  interfaces.
- `bibliotheca.v1.Ipfs` — pin / unpin / import / export against a Kubo node.

There is no network auth on the control socket. Access is gated by
filesystem permissions on the socket itself, the same model town-os uses
for its other privileged daemons.

**Data plane.** Each interface crate spins up its own listener and
shares a single `BibliothecaService` handle. ACL evaluation happens in
`bibliotheca-core::acl`; data-plane crates ask the service whether
`(subvolume, principal, permission)` is allowed and stream bytes to or
from the subvolume mount path on success.

### Btrfs integration

`bibliotheca-btrfs::BtrfsBackend` shells out to the `btrfs` binary for
`subvolume create`, `subvolume delete`, `subvolume snapshot`, and
`qgroup limit`. It mirrors the surface area of the Go
`BtrFSController` already in town-os
(`town-os/src/storage/btrfs.go`) so the two daemons can coexist on the
same data filesystem without stepping on each other.

Subvolumes are placed under `BIBLIOTHECA_ROOT` (default
`/var/lib/bibliotheca/subvolumes`), one directory per subvolume. Snapshots
live under `<root>/.snapshots/<subvolume>/<name>`. Quotas use
`btrfs qgroup limit`, so the host filesystem must have quotas enabled
(`btrfs quota enable`); town-os does this at provisioning time.

### Identity, groups, and ACLs

A user is `(uuid, name, display_name, password_hash)`. Groups are
`(uuid, name, description)` and have a many-to-many table to users.
Both are persisted in a single sqlite database (`BIBLIOTHECA_DB`, default
`/var/lib/bibliotheca/bibliotheca.db`), with the same WAL settings town-os uses
elsewhere.

Each subvolume carries an `Acl`: a list of entries, each binding a
`Principal` (`User`, `Group`, or `Public`) to a set of `Permission`s
(`Read`, `Write`, `List`, `Delete`, `Admin`). Owners always pass the
permission check; everything else falls through ACL evaluation. The
default ACL for a brand-new subvolume is `owner-only Admin`.

`Principal::Public` only matters when the HTTP interface is enabled
**and** the operator has explicitly added a `Public` ACL entry. That
double opt-in is the spec requirement: HTTP is off by default, and even
when on it never serves anonymous requests unless the ACL explicitly
says so.

### Interface enablement

Interfaces are configured via a JSON file passed with `--interfaces`.
Anything missing from the file (or with `enabled: false`) stays off. The
HTTP interface is the only one that defaults to off even when present;
the others were not specified as opt-in but you should treat them the
same way for any deployment that exposes them on a public network.

```json
{
  "http":      { "enabled": false, "listen": "127.0.0.1:8443", "allow_public": false },
  "s3":        { "enabled": true,  "listen": "127.0.0.1:9000" },
  "solid":     { "enabled": false, "listen": "127.0.0.1:8444", "base_url": "https://bibliotheca.local" },
  "dropbox":   { "enabled": false, "listen": "127.0.0.1:8445" },
  "nextcloud": { "enabled": false, "listen": "127.0.0.1:8446" },
  "gcs":       { "enabled": false, "listen": "127.0.0.1:8447" },
  "icloud":    { "enabled": false, "listen": "127.0.0.1:8448", "container": "iCloud.com.example" }
}
```

### IPFS

`bibliotheca-ipfs` does not embed a node. It talks to a local Kubo
(go-ipfs) RPC API at `http://127.0.0.1:5001`, exposing the same five
operations (pin, unpin, import, export, list pins) as both an in-process
helper and the `bibliotheca.v1.Ipfs` gRPC service. Bytes are materialized
into the target subvolume by way of the same ACL / mount-path machinery
the other interfaces use, so an IPFS export respects per-subvolume
quotas exactly the way an HTTP PUT does.

## Build

```sh
cargo check --workspace
cargo build --release -p bibliothecad -p bibliothecactl
```

The build needs `protoc` for `tonic-build`. On Manjaro / Arch:
`sudo pacman -S protobuf`.

## Run

```sh
sudo bibliothecad \
  --socket /run/bibliotheca/control.sock \
  --db /var/lib/bibliotheca/bibliotheca.db \
  --root /var/lib/bibliotheca/subvolumes \
  --interfaces /etc/bibliotheca/interfaces.json
```

```sh
bibliothecactl user create alice --password hunter2
bibliothecactl group create staff
bibliothecactl group add <user-id> <group-id>
bibliothecactl subvolume create photos --owner <user-id> --quota 10737418240
bibliothecactl subvolume list
```

## Status

Control plane (gRPC), identity, groups, ACL evaluation, sqlite store,
btrfs backend wiring, daemon orchestration, and CLI are real and
buildable. Each data-plane interface crate is wired into the daemon and
shares the core `BibliothecaService`, but the protocol-specific handlers are
deliberately stubbed — search for `TODO(spec)` in the interface crates
for the extension points. The intent is to flesh those out incrementally
without touching the control plane or the storage layer.
