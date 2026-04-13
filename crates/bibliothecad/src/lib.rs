//! Public surface of the daemon crate so integration tests (and
//! anything else that wants to embed bibliothecad in-process) can
//! reach the control-plane server and interface loader without going
//! through the binary entrypoint.

pub mod control;
pub mod interfaces;
