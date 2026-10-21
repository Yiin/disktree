//! Where the scanned disk is: the one door from the app to a filesystem.
//!
//! Every read of the disk being explored and every change to it goes through
//! [`Source`], so a disk on another machine needs one new arm per method and
//! no change in the screens. Methods take and return plain data, never a
//! handle that only works on this machine.
//!
//! What a source provides, `local only` marking what has no meaning for a
//! disk on another machine:
//!
//! * the scan: start one at a root, optionally reusing a known subtree
//!   ([`Source::scan`]); read its progress, take its tree, cancel it
//!   ([`SourceScan`]);
//! * free space, the mount source and the volume root of a path
//!   ([`Source::space`], [`Source::device`], [`Source::volume_root`]);
//! * the volumes the picker lists ([`Source::volumes_besides`]);
//! * the home directory, which the removal guards and `~` are about
//!   ([`Source::home`]);
//! * the root as given on the command line: canonical, and a directory
//!   ([`Source::canonical`], [`Source::is_dir`]);
//! * whether a path is still there ([`Source::exists`]);
//! * the removal plan, whose guards run where the disk is
//!   ([`Source::plan`]), and the removal itself ([`Source::remove`],
//!   [`SourceRemoval`]); which trash it uses ([`Source::trash_backend`]);
//! * what git knows about a checkout ([`Source::git_state`]);
//! * the mount table primed before the first plan
//!   ([`Source::prime_mount_points`]);
//! * whether a whole NTFS drive can be read from its file table
//!   ([`Source::file_table_readable`]);
//! * local only: Full Disk Access and administrator rights, which are about
//!   this process ([`Source::full_disk_access`], [`Source::administrator`]),
//!   restarting as administrator, revealing a path in the file manager, and
//!   choosing a folder with the system picker. These check
//!   [`Source::is_local`].
//!
//! Desktop-side, not part of a source: the clipboard, the saved delete list
//! (a file the user picks on this machine), the power settings file and the
//! appearance settings.

use std::io;
use std::path::{Path, PathBuf};

use disktree_core::removal::{
    Plan, RemovalEvent, RemovalHandle, RemovalMode, Target, TrashBackend,
};
use disktree_core::scan::{Known, ScanHandle, ScanOptions, ScanSnapshot};
use disktree_core::space::{SpaceInfo, Volume};
use disktree_core::tree::Node;

use crate::git::GitState;

/// The machine whose disk is explored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// This machine, through `disktree-core` directly.
    Local,
}

impl Source {
    /// Whether the disk is this machine's, so a file manager, a folder
    /// picker or a restart here would act on it.
    pub const fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    /// The machine, as a notice names it.
    pub const fn name(&self) -> &str {
        match self {
            Self::Local => "this machine",
        }
    }

    /// The window title for `shown`, the directory on screen as displayed.
    pub fn title(&self, shown: &str) -> String {
        match self {
            Self::Local => format!("disktree · {shown}"),
        }
    }

    /// The home directory of whoever the scan runs as.
    pub fn home(&self) -> Option<PathBuf> {
        match self {
            Self::Local => std::env::home_dir(),
        }
    }

    /// `root` in the form a widening walk recognises again, or as given
    /// when it cannot be resolved. Through dunce, so Windows gets
    /// `C:\Users\…` rather than the `\\?\C:\…` form nothing else is written
    /// in.
    pub fn canonical(&self, root: PathBuf) -> PathBuf {
        match self {
            Self::Local => dunce::canonicalize(&root).unwrap_or(root),
        }
    }

    /// Whether `path` is a directory, following links.
    pub fn is_dir(&self, path: &Path) -> io::Result<bool> {
        match self {
            Self::Local => Ok(std::fs::metadata(path)?.is_dir()),
        }
    }

    /// Whether anything is at `path`, without following a link.
    pub fn exists(&self, path: &Path) -> bool {
        match self {
            Self::Local => std::fs::symlink_metadata(path).is_ok(),
        }
    }

    /// Start walking `root`, reusing `known` where the walk reaches it.
    pub fn scan(
        &self,
        root: PathBuf,
        options: ScanOptions,
        known: Option<Known>,
    ) -> SourceScan {
        match self {
            Self::Local => {
                SourceScan::Local(ScanHandle::spawn_with(root, options, known))
            }
        }
    }

    /// Free space on the volume holding `path`, `None` when unreadable.
    pub fn space(&self, path: &Path) -> Option<SpaceInfo> {
        match self {
            Self::Local => disktree_core::space::space_info(path).ok(),
        }
    }

    /// The device `path` is mounted from.
    pub fn device(&self, path: &Path) -> Option<String> {
        match self {
            Self::Local => disktree_core::space::device_for(path),
        }
    }

    /// The top of the volume `path` lives on: what "Whole disk" scans.
    pub fn volume_root(&self, path: &Path) -> Option<PathBuf> {
        match self {
            Self::Local => disktree_core::space::volume_root_for(path),
        }
    }

    /// Every volume the picker offers while `root` is scanned: the mounted
    /// volumes, plus the one holding `root` when the table missed it, less
    /// `root` itself. Slow on removable and network media; call it off the
    /// UI thread.
    pub fn volumes_besides(&self, root: &Path) -> Vec<Volume> {
        let mut volumes = match self {
            Self::Local => disktree_core::space::volumes(),
        };
        if let Some(point) = self.volume_root(root)
            && !volumes.iter().any(|volume| volume.point == point)
        {
            volumes.push(Volume {
                device: self.device(&point),
                space: self.space(&point),
                point,
            });
        }
        volumes.retain(|volume| volume.point != root);
        volumes
    }

    /// Whether `root` is a whole NTFS drive an administrator reads from its
    /// file table. `false` off Windows.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where the core stub is; Windows asks the system"
    )]
    pub fn file_table_readable(&self, root: &Path) -> bool {
        match self {
            Self::Local => disktree_core::access::file_table_readable(root),
        }
    }

    /// Read the mount table now, so the first plan does not wait on it.
    pub fn prime_mount_points(&self) {
        match self {
            Self::Local => disktree_core::removal::prime_mount_points(),
        }
    }

    /// The trash removals in trash mode go to.
    pub fn trash_backend(&self) -> TrashBackend {
        match self {
            Self::Local => disktree_core::removal::detect_trash_backend(),
        }
    }

    /// What removing `targets` under `root` would do, with every guard
    /// applied where the disk is.
    pub fn plan(&self, targets: &[Target], root: &Path) -> Plan {
        match self {
            Self::Local => disktree_core::removal::plan(targets, root),
        }
    }

    /// Carry out `plan` on a worker.
    pub fn remove(&self, plan: Plan, mode: RemovalMode) -> SourceRemoval {
        match self {
            Self::Local => {
                SourceRemoval::Local(disktree_core::removal::spawn(plan, mode))
            }
        }
    }

    /// What git knows about `path`, `None` when it is not a checkout.
    pub fn git_state(&self, path: &Path) -> Option<GitState> {
        match self {
            Self::Local => crate::git::state(path),
        }
    }

    /// Whether macOS lets this process read everything under `home`.
    /// Local only: `None` off macOS and for another machine.
    pub fn full_disk_access(&self, home: &Path) -> Option<bool> {
        match self {
            Self::Local => disktree_core::access::full_disk_access(home),
        }
    }

    /// Whether this process is an administrator. Local only: `None` off
    /// Windows and for another machine.
    #[allow(
        clippy::missing_const_for_fn,
        reason = "const only where the core stub is; Windows asks the system"
    )]
    pub fn administrator(&self) -> Option<bool> {
        match self {
            Self::Local => disktree_core::access::administrator(),
        }
    }
}

/// A scan in flight, wherever it runs.
#[derive(Debug)]
pub enum SourceScan {
    Local(ScanHandle),
}

impl SourceScan {
    /// The counters as they stand.
    pub fn progress(&self) -> ScanSnapshot {
        match self {
            Self::Local(scan) => scan.progress.snapshot(),
        }
    }

    /// Take the finished tree, if the walk is done.
    pub fn poll(&self) -> Option<io::Result<Node>> {
        match self {
            Self::Local(scan) => scan.poll(),
        }
    }

    /// Abandon the walk.
    pub fn cancel(&self) {
        match self {
            Self::Local(scan) => scan.cancel(),
        }
    }
}

/// A removal in flight, wherever it runs.
#[derive(Debug)]
pub enum SourceRemoval {
    Local(RemovalHandle),
}

impl SourceRemoval {
    /// Take the next event, if one has arrived.
    pub fn poll(&self) -> Option<RemovalEvent> {
        match self {
            Self::Local(run) => run.poll(),
        }
    }

    /// Stop after the item in progress.
    pub fn cancel(&self) {
        match self {
            Self::Local(run) => run.cancel(),
        }
    }
}
