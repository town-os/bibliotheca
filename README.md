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
    ├── bibliotheca-photos      # Google Photos Library API
    ├── bibliotheca-admin       # HTML admin panel (indexed browsing)
    ├── bibliotheca-sync-core   # client-side connector trait, supervisor, state,
    │                           #   conflict resolver, town-os storage procurement
    ├── bibliotheca-sync-ipfs       # IPFS sync connector
    ├── bibliotheca-sync-dropbox    # Dropbox sync connector
    ├── bibliotheca-sync-nextcloud  # Nextcloud / WebDAV sync connector
    ├── bibliotheca-sync-solid      # Solid / LDP sync connector
    ├── bibliotheca-sync-gphotos    # Google Photos sync connector
    ├── bibliotheca-sync-icloud     # iCloud Photos sync connector (pyicloud port)
    ├── bibliotheca-anisette    # client-side anisette proxy for sync-icloud
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
  "icloud":    { "enabled": false, "listen": "127.0.0.1:8448", "container": "iCloud.com.example" },
  "photos":    { "enabled": false, "listen": "127.0.0.1:8449", "library": "photos" },
  "admin":     { "enabled": false, "listen": "127.0.0.1:8787", "admin_group": "admins" }
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

### Sync connectors

Every server-side transport has a client-side twin. A `sync-*` crate
takes a remote service and mirrors its contents into a local
subvolume, which every existing transport can then re-serve. Mounts
are created via the control plane (`SyncAdmin.CreateMount`) and
managed at runtime with `bibliothecactl sync mount …`. Each mount
owns exactly one subvolume, procured on demand through the town-os
systemcontroller (`POST /storage/create`) so storage allocation
goes through the same path as the rest of town-os. Quotas are a
first-class, editable field: set at create time, updatable via
`bibliothecactl sync mount set-quota`, enforced by `DataStore::put`,
resized on the town-os side via `POST /storage/modify`.

Six connector kinds ship today: `ipfs`, `dropbox`, `nextcloud`
(WebDAV), `solid`, `gphotos`, `icloud`. Each has its own
encryption-at-rest credential blob in `sync_credentials` (AES-GCM-256
with a master key from `BIBLIOTHECA_SECRET_KEY` or
`--sync-secret-key-file`), its own incremental cursor in
`sync_mounts.cursor_blob`, and its own integration test against a
mock server. Direction can be `pull`, `push`, or `both`; bidirectional
mounts stash conflict losers to `.conflicts/<unix_ts>/<key>` inside
the subvolume and emit a `conflict` event over the supervisor's
`SyncAdmin.TailEvents` stream.

### Anisette proxy

`sync-icloud` needs Apple's device attestation headers on every
`idmsa.apple.com` request. Those headers are produced by Apple's
`CoreADI` library, which only runs on Apple hardware, so the actual
producer must live somewhere the operator owns.

`bibliotheca-anisette` is a **client-side proxy** that forwards
`POST /v3/get_anisette_data` to one or more operator-controlled
upstream producers — typically a peer bibliotheca node reachable
over a VPN and resolved via private DNS. It never forwards to
community or third-party providers. Features on top of a single
upstream:

- round-robin failover across multiple peers
- per-upstream health tracking with exponential backoff
- short-TTL response caching (Apple's OTPs are valid for ~30 s)
- dynamic peer management via gRPC (`AnisetteAdmin.AddPeer`,
  `RemovePeer`, `ListPeers`) and
  `bibliothecactl anisette {add-peer,remove-peer,list-peers}`
- optional mDNS/Bonjour discovery of peers advertising
  `_bibliotheca-anisette._tcp.local.` (build with the `mdns`
  feature on `bibliothecad`)

The proxy is off by default. Enable it by passing at least one
upstream URL or the mDNS flag on the daemon command line:

```sh
bibliothecad \
  --anisette-listen 127.0.0.1:6969 \
  --anisette-upstream https://anisette.iphone.tailnet.ts.net \
  --anisette-upstream https://anisette.mac-mini.tailnet.ts.net \
  --anisette-cache-ttl-secs 20
```

With the proxy up, `sync-icloud` mounts set their credential
blob's `anisette_url` to `http://127.0.0.1:6969` and never see the
upstream directly.

#### Peer options

What actually *produces* anisette data is out of scope for
`bibliotheca-anisette` — the operator runs one or more producer
nodes inside their trust boundary. A realistic option we may ship
later: an iPhone app that wraps the native `AOSKit.framework`
anisette APIs and serves them over HTTP on a Bonjour-advertised
local socket, so the phone itself becomes a first-class peer.
Wiring is already in place today: the iPhone (or anything else)
just needs to speak the `POST /v3/get_anisette_data` shape, and
the proxy will discover it via mDNS or accept it via `add-peer`.

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
buildable. Every data-plane interface now implements the object CRUD
surface its protocol expects, sharing a single ACL-checked
`bibliotheca-core::data::DataStore` helper so path-traversal and
permission enforcement live in one place. Each transport ships with an
end-to-end integration test that drives it over a real TCP socket.

- `bibliotheca-http` — Basic auth, GET/HEAD/PUT/DELETE/LIST; `Public`
  ACL entries honoured only when `allow_public = true`.
- `bibliotheca-s3` — ListBuckets, CreateBucket, ListObjectsV2,
  Put/Get/Head/Delete Object. Auth: HTTP Basic or a minimal
  `AWS4-HMAC-SHA256 Credential=...` parser paired with a
  `X-Amz-Bibliotheca-Secret` header.
- `bibliotheca-solid` — LDP verbs (GET/HEAD/PUT/POST/DELETE/OPTIONS)
  with Turtle directory listings, `Slug` header, and the double opt-in
  `Public` ACL path from the HTTP interface.
- `bibliotheca-dropbox` — `/2/files/{list_folder,upload,download,
  delete_v2,get_metadata}` with `Authorization: Bearer
  <base64(user:pass)>`.
- `bibliotheca-nextcloud` — WebDAV (GET/HEAD/PUT/DELETE/MKCOL/
  PROPFIND/OPTIONS) under `/remote.php/dav/files/<user>/…` plus a
  minimal OCS shares envelope.
- `bibliotheca-gcs` — JSON API for bucket and object CRUD, including
  `?alt=media` downloads and `/upload/storage/v1` uploads, with Bearer
  auth matching the Dropbox transport.
- `bibliotheca-icloud` — CloudKit Web Services shape:
  `records/query`, `records/lookup`, `records/modify` (create/delete),
  and `assets/upload` + asset download.
- `bibliotheca-photos` — Google Photos Library API subset: raw
  upload → upload-token → `mediaItems/batchCreate` two-step flow,
  album create/list/get, mediaItems list/search/get, and byte
  download. Albums are top-level directories inside a configurable
  "library" subvolume (default `photos`); media items are files.
  Note: Google's `:verb` convention is served at `/verb` here
  because axum's matchit treats mid-segment `:` as a path
  parameter.
- `bibliotheca-ipfs` — real Kubo HTTP RPC client (`pin add`, `pin rm`,
  `pin ls`, `add`, `cat`), in addition to the existing `IpfsService`
  orchestration layer that handles ACLs and path-traversal guards.
- `bibliotheca-admin` — HTML admin panel with indexed directory
  browsing, file download, and read-only user/group/subvolume views.
  Access is gated by membership in a configurable admin group
  (default `admins`), and operations bypass subvolume ACLs — they
  still go through the same `data::resolve_key` traversal guard the
  other transports use. Disabled by default; bootstrap with
  `bibliothecactl group create admins && bibliothecactl group add
  admins <user-id>`.

The daemon wiring and interface-enablement file are unchanged — see
`crates/bibliothecad/src/interfaces.rs`. Adding a new transport still
means writing one crate, implementing the protocol's verbs in terms of
`DataStore`, and adding a `Listen*` entry to `interfaces.json`.
