//! Public surface of the daemon crate so integration tests (and
//! anything else that wants to embed bibliothecad in-process) can
//! reach the control-plane server and interface loader without going
//! through the binary entrypoint.

// `tonic::Status` is ~176 bytes, and every tonic service method
// returns `Result<T, Status>` by contract. Boxing it everywhere would
// be viral and gain us nothing, so we turn off the lint here.
#![allow(clippy::result_large_err)]

pub mod control;
pub mod interfaces;
pub mod sync;
