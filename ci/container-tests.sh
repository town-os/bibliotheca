#!/usr/bin/env bash
#
# Run the bibliotheca workspace test suite against a REAL btrfs filesystem,
# fully isolated inside a throwaway container.
#
# `make test` runs every transport harness against the in-memory `MemoryBackend`
# fake. This script sets BIBLIOTHECA_REAL_BTRFS_ROOT to a loopback btrfs mount,
# which flips `bibliotheca_btrfs::testing::test_backend` over to a real
# `BtrfsBackend` — so the same harnesses now create real `btrfs subvolume`s and
# stream bytes onto them. It also runs the `#[ignore]`-gated real-btrfs backend
# test (subvolume create/delete + quota + snapshot + byte round-trip).
#
# The host filesystem is never touched: the repo is bind-mounted read-only and
# copied into the container, all btrfs operations happen inside a loopback image.
#
# Requirements: podman (or docker) able to run --privileged and mount a loopback
# filesystem. Rootless engines generally cannot loop-mount, so this defaults to
# `sudo podman`. Override with CONTAINER_ENGINE, the image with TEST_IMAGE, and
# the loopback size with BTRFS_IMG_SIZE.
#
#   ./ci/container-tests.sh
#   CONTAINER_ENGINE="sudo docker" TEST_IMAGE=docker.io/library/rust:1-trixie ./ci/container-tests.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${TEST_IMAGE:-docker.io/library/rust:1-bookworm}"
ENGINE="${CONTAINER_ENGINE:-sudo podman}"
IMG_SIZE="${BTRFS_IMG_SIZE:-3G}"

echo ">> repo:   $REPO_ROOT"
echo ">> image:  $IMAGE"
echo ">> engine: $ENGINE"
echo ">> btrfs image size: $IMG_SIZE"

# Named volumes cache the crate registry and the build target across runs so
# repeats don't re-download or recompile from scratch.
#
# This host is memory-constrained, and linking the workspace's debug test
# binaries in parallel can OOM the linker ("ld: Input/output error"). So we
# strip debug info (RUSTFLAGS) and cap build parallelism (CARGO_BUILD_JOBS).
exec $ENGINE run --rm --privileged \
  -v "$REPO_ROOT":/src:ro \
  -v bibliotheca-cargo-registry:/usr/local/cargo/registry \
  -v bibliotheca-cargo-target:/work/target \
  -e BTRFS_IMG_SIZE="$IMG_SIZE" \
  -e CARGO_TERM_COLOR=always \
  -e RUSTFLAGS="${RUSTFLAGS:--C debuginfo=0}" \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  "$IMAGE" bash -euo pipefail -c '
    step() { printf "\n\033[1;36m== %s ==\033[0m\n" "$*"; }

    step "install btrfs-progs + build prerequisites"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq btrfs-progs pkg-config libssl-dev >/dev/null
    btrfs --version

    step "create a loopback btrfs filesystem at /mnt/btrfs"
    truncate -s "$BTRFS_IMG_SIZE" /img
    mkfs.btrfs -q /img
    mkdir -p /mnt/btrfs
    mount -o loop /img /mnt/btrfs
    stat -f -c "fstype=%T" /mnt/btrfs   # must print btrfs
    btrfs quota enable /mnt/btrfs
    export BIBLIOTHECA_REAL_BTRFS_ROOT=/mnt/btrfs

    step "copy source out of the read-only mount (excluding target/ and .git)"
    mkdir -p /work
    tar -C /src --exclude=./target --exclude=./.git -cf - . | tar -C /work -xf -
    cd /work
    export CARGO_TARGET_DIR=/work/target

    step "workspace suite against REAL btrfs (every transport harness)"
    cargo test --workspace --features bibliotheca-core/test-support

    step "dedicated real-btrfs backend test (create/delete + quota + snapshot)"
    cargo test -p bibliotheca-btrfs --test backend -- --ignored

    printf "\n\033[1;32mALL GREEN on real btrfs\033[0m\n"
  '
