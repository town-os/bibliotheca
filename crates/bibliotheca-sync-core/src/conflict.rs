//! Conflict resolution for bidirectional sync.

use crate::mount::Direction;

/// The outcome of resolving a single (remote, local) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Bytes are identical already; record the sync and move on.
    SkipIdentical,
    /// Overwrite local with remote bytes (pull or remote-newer).
    TakeRemote,
    /// Overwrite remote with local bytes (push or local-newer).
    TakeLocal,
    /// Both sides diverged: stash the local copy under
    /// `.conflicts/<ts>/` and then apply the remote.
    StashAndTakeRemote,
    /// Both sides diverged: stash the remote copy under
    /// `.conflicts/<ts>/` and then apply the local.
    StashAndTakeLocal,
}

/// Hashes / mtimes needed to run the resolver.
#[derive(Debug, Clone)]
pub struct Inputs<'a> {
    pub direction: Direction,
    pub remote_hash: Option<&'a str>,
    pub local_hash: Option<&'a str>,
    pub remote_mtime: i64,
    pub local_mtime: i64,
    pub baseline_remote_hash: Option<&'a str>,
    pub baseline_local_hash: Option<&'a str>,
}

pub struct Resolver;

impl Resolver {
    pub fn resolve(input: Inputs<'_>) -> Resolution {
        // Content-identical short-circuit.
        if let (Some(a), Some(b)) = (input.remote_hash, input.local_hash) {
            if a == b {
                return Resolution::SkipIdentical;
            }
        }
        match input.direction {
            Direction::Pull => Resolution::TakeRemote,
            Direction::Push => Resolution::TakeLocal,
            Direction::Both => {
                let remote_changed = input.remote_hash != input.baseline_remote_hash;
                let local_changed = input.local_hash != input.baseline_local_hash;
                match (remote_changed, local_changed) {
                    (true, false) => Resolution::TakeRemote,
                    (false, true) => Resolution::TakeLocal,
                    (false, false) => Resolution::SkipIdentical,
                    (true, true) => {
                        if input.remote_mtime >= input.local_mtime {
                            Resolution::StashAndTakeRemote
                        } else {
                            Resolution::StashAndTakeLocal
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Inputs<'static> {
        Inputs {
            direction: Direction::Both,
            remote_hash: Some("r"),
            local_hash: Some("l"),
            remote_mtime: 0,
            local_mtime: 0,
            baseline_remote_hash: Some("r"),
            baseline_local_hash: Some("l"),
        }
    }

    #[test]
    fn identical_is_skipped() {
        let mut i = base();
        i.remote_hash = Some("x");
        i.local_hash = Some("x");
        assert_eq!(Resolver::resolve(i), Resolution::SkipIdentical);
    }

    #[test]
    fn pull_always_remote() {
        let mut i = base();
        i.direction = Direction::Pull;
        assert_eq!(Resolver::resolve(i), Resolution::TakeRemote);
    }

    #[test]
    fn push_always_local() {
        let mut i = base();
        i.direction = Direction::Push;
        assert_eq!(Resolver::resolve(i), Resolution::TakeLocal);
    }

    #[test]
    fn both_only_remote_changed() {
        let i = Inputs {
            direction: Direction::Both,
            remote_hash: Some("r2"),
            local_hash: Some("l"),
            baseline_remote_hash: Some("r"),
            baseline_local_hash: Some("l"),
            remote_mtime: 5,
            local_mtime: 3,
        };
        assert_eq!(Resolver::resolve(i), Resolution::TakeRemote);
    }

    #[test]
    fn both_only_local_changed() {
        let i = Inputs {
            direction: Direction::Both,
            remote_hash: Some("r"),
            local_hash: Some("l2"),
            baseline_remote_hash: Some("r"),
            baseline_local_hash: Some("l"),
            remote_mtime: 3,
            local_mtime: 5,
        };
        assert_eq!(Resolver::resolve(i), Resolution::TakeLocal);
    }

    #[test]
    fn both_diverged_newer_remote_wins() {
        let i = Inputs {
            direction: Direction::Both,
            remote_hash: Some("r2"),
            local_hash: Some("l2"),
            baseline_remote_hash: Some("r"),
            baseline_local_hash: Some("l"),
            remote_mtime: 10,
            local_mtime: 5,
        };
        assert_eq!(Resolver::resolve(i), Resolution::StashAndTakeRemote);
    }

    #[test]
    fn both_diverged_newer_local_wins() {
        let i = Inputs {
            direction: Direction::Both,
            remote_hash: Some("r2"),
            local_hash: Some("l2"),
            baseline_remote_hash: Some("r"),
            baseline_local_hash: Some("l"),
            remote_mtime: 5,
            local_mtime: 10,
        };
        assert_eq!(Resolver::resolve(i), Resolution::StashAndTakeLocal);
    }
}
