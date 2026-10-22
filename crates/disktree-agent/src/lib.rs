//! `disktree-agent`: disktree's scanner on another machine.
//!
//! A small headless binary built from `disktree-core` alone runs where the
//! disk is, usually started over `ssh -T host disktree-agent serve`, and
//! does the real walk there at local disk speed. It speaks a framed
//! protocol on stdin and stdout ([`protocol`]); [`Client`] is the other
//! end, shaped like the local scan, space and removal calls so the app can
//! put either behind one source.
//!
//! The removal guards run on the agent: it plans what it is asked to
//! remove against its own mounts and home directory, and refuses what its
//! own plan blocks. The client's plan is never trusted.

pub mod client;
pub mod protocol;
pub mod serve;
pub mod tree_codec;
pub mod wire;

pub use client::{Client, RemoteRemoval, RemoteScan, Transfer};
pub use protocol::{Hello, PROTOCOL, PathInfo, SpaceReport};
pub use serve::serve;
