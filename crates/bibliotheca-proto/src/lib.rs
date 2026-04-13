//! Generated protobuf + tonic bindings for the Bibliotheca control plane.
//!
//! See `proto/bibliotheca/v1/control.proto` for the source of truth.

#![allow(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]

pub mod v1 {
    tonic::include_proto!("bibliotheca.v1");
}

pub use v1::*;
