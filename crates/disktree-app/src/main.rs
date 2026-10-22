//! `disktree`: find what is eating a volume, mark it, and remove it.
//!
//! The window opens on a treemap of the scanned root — the home directory
//! unless another path is given — with a breadcrumb bar, a selection line, and a
//! live free-space meter. Marking is non-destructive until the review screen
//! is confirmed.

// A window, not a console program: on Windows, opening it from Explorer or
// the Start menu should not bring a console window along. `main` attaches to
// the console of a terminal it was started from, so `--help` and errors still
// reach one. Ignored elsewhere.
#![windows_subsystem = "windows"]

mod app_menu;
mod appearance;
mod marks;
mod palette;
mod power;
mod remote;
mod source;
mod state;
#[cfg(test)]
mod tests;
mod treemap_view;
mod ui;
mod views;
mod widgets;

use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::{
    io::IsTerminal as _,
    os::unix::process::CommandExt as _,
    process::{Command, Stdio},
};

use anyhow::{Context as _, Result};
use disktree_core::scan::ScanOptions;
use gpui_kit::{AppContext as _, WindowOptions, px, size};
use remote::{Ask, Reach, Remote};
use source::Source;
use state::Disktree;

/// What the command line asked for.
#[derive(Debug)]
enum Invocation {
    /// Open the window.
    Window(Args),
    /// Print [`USAGE`].
    Help,
    /// Print [`version_line`].
    Version,
}

/// What the window needs from the command line.
#[derive(Debug)]
struct Args {
    source: Source,
    /// Empty for another machine, whose root is known once it answers.
    root: PathBuf,
    options: ScanOptions,
    depth: u32,
    power: Option<power::PowerEfficiency>,
}

const USAGE: &str = "\
disktree — a treemap of what is using your disk

usage: disktree [OPTIONS] [PATH]
       disktree [OPTIONS] HOST[:PATH]

arguments:
  PATH              directory to scan (default: the home directory)
  HOST[:PATH]       scan another machine over ssh, as scp names it: a
                    ':' before any '/' means HOST:PATH, and a bare word
                    that is no local path is a HOST. PATH there defaults
                    to the real disk on SparkOS, else the home directory;
                    a relative one starts in that home directory. Write
                    ./NAME for a local folder named like a host.

The window opens on a treemap of the root, largest first. Space marks the
selected tile, Enter opens it, c reviews the marked list, ? lists every key.

options:
  -a, --apparent-size   measure apparent length instead of allocated blocks
  -l, --follow-links    follow symlinks
  -H, --no-hidden       skip dotfiles and dot-directories
  -D, --disk            scan the whole disk the home directory is on
      --sudo            on a HOST, scan as root through sudo -n, which must
                        not ask for a password there
  -X, --cross-filesystems
                        also measure other disks, network shares and pseudo
                        filesystems mounted below PATH (off by default)
  -d, --depth N         how many levels to draw at once (1-6, default 3)
      --power-efficiency PRESET
                        miser, balanced (default), aggressive, drain-my-battery
      --scan-threads N  fixed scan workers, capped by available CPU count
      --adaptive-threads
                        experimental adaptive admission (opt-in)
      --fixed-threads   disable adaptive admission and CPU governor
      --thread-throughput-percent N
                        retain this percent of sampled initial throughput (80)
      --thread-system-cpu-percent N
                        best-effort host CPU budget; 0 disables it (80)
      --metric files    rank by file count instead of bytes
  -h, --help            show this help
  -V, --version         print the version, the commit this binary was built
                        from, and the agent it carries
";

/// One line: the crate version, the commit this binary was built from, and
/// the build id of the agent embedded in it. `build.rs` stamps the last two.
fn version_line() -> String {
    format!(
        "disktree {} (commit {}, agent {})",
        env!("CARGO_PKG_VERSION"),
        env!("DISKTREE_COMMIT"),
        env!("DISKTREE_EMBEDDED_AGENT"),
    )
}

fn main() -> Result<()> {
    #[cfg(windows)]
    console::attach();
    let outcome = run();
    #[cfg(windows)]
    console::detach();
    outcome
}

fn run() -> Result<()> {
    let saved = power::settings_path()
        .map_or_else(
            || Ok(power::PowerEfficiency::default()),
            |path| power::load(&path),
        )
        .unwrap_or_else(|error| {
            eprintln!("Cannot load Power Efficiency: {error}; using Balanced");
            power::PowerEfficiency::default()
        });
    // These answer on the command line and never open a window, so they go
    // before the macOS re-exec: a detached child could not print them.
    let args = match parse_args_with_power(std::env::args_os().skip(1), saved)?
    {
        Invocation::Window(args) => args,
        Invocation::Help => {
            println!("{USAGE}");
            return Ok(());
        }
        Invocation::Version => {
            println!("{}", version_line());
            return Ok(());
        }
    };

    // When the app executable is reached through the command-line symlink,
    // cmux sends SIGTERM to its foreground process group as AppKit takes
    // focus. Spawn once into a separate group before AppKit starts. Restrict
    // this to interactive cmux sessions so scripts retain normal foreground
    // lifetime; the marker prevents the child from spawning recursively.
    #[cfg(target_os = "macos")]
    if std::io::stdin().is_terminal()
        && std::env::var_os("CMUX_SURFACE_ID").is_some()
        && std::env::var_os("DISKTREE_CMUX_DETACHED").is_none()
    {
        Command::new(std::env::current_exe().context("find disktree")?)
            .args(std::env::args_os().skip(1))
            .env("DISKTREE_CMUX_DETACHED", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Zero makes the child the leader of a new process group.
            .process_group(0)
            .spawn()
            .context("start disktree")?;
        return Ok(());
    }

    let root = args.root.clone();
    let depth = args.depth;
    let title_root = root.clone();

    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            gpui_omarchy::init(cx);
            app_menu::install(cx);
            let home = std::env::home_dir();
            let native_look = appearance::follows_system(home.as_deref());
            if native_look {
                appearance::apply(cx.window_appearance(), cx);
            }
            let options = args.options.clone();
            let root_for_app = root.clone();
            let window = cx
                .open_window(
                    WindowOptions {
                        window_bounds: Some(gpui_kit::WindowBounds::Windowed(
                            gpui_kit::Bounds::new(
                                gpui_kit::point(px(120.), px(90.)),
                                size(px(1440.), px(900.)),
                            ),
                        )),
                        titlebar: Some(gpui_kit::TitlebarOptions {
                            title: Some(
                                args.source
                                    .title(&marks::display_path(
                                        &title_root,
                                        args.source.home().as_deref(),
                                    ))
                                    .into(),
                            ),
                            ..Default::default()
                        }),
                        // Wayland app id. Hyprland reports it as the window
                        // class, and the desktop entry's StartupWMClass and
                        // the documented window rule both match `disktree`.
                        // Left unset, the class is empty and that rule never
                        // matches.
                        app_id: Some("disktree".to_owned()),
                        // Below this the treemap stops being readable, so ask
                        // the compositor not to go there.
                        window_min_size: Some(size(px(900.), px(600.))),
                        ..Default::default()
                    },
                    move |window, cx| {
                        if native_look {
                            appearance::follow(window);
                        }
                        cx.new(|cx| {
                            let mut app = Disktree::with_source(
                                args.source.clone(),
                                root_for_app.clone(),
                                options.clone(),
                                depth,
                                cx,
                            );
                            app.power_choice = args.power;
                            app
                        })
                    },
                )
                .expect("open the disktree window");

            // The treemap owns the keyboard from the first frame; there is no
            // text field to focus first.
            let _ = window.update(cx, |this, window, cx| {
                let focus = this.focus.clone();
                window.focus(&focus, cx);
            });
            cx.activate(true);
        });
    Ok(())
}

/// Read the command line, program name already skipped, and insist on a
/// window: what most tests are about.
#[cfg(test)]
fn parse_args(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Args> {
    match parse_args_with_power(args, power::PowerEfficiency::default())? {
        Invocation::Window(args) => Ok(args),
        other => panic!("not a window: {other:?}"),
    }
}

fn parse_args_with_power(
    mut args: impl Iterator<Item = std::ffi::OsString>,
    preset: power::PowerEfficiency,
) -> Result<Invocation> {
    let mut root: Option<std::ffi::OsString> = None;
    let mut sudo = false;
    let mut options = ScanOptions {
        threads: preset.policy(power::cpu_threads()),
        ..ScanOptions::default()
    };
    let mut power = Some(preset);
    let mut depth = 3_u32;
    let mut disk = false;
    // `std::env::args` panics on a name that is not Unicode, and a path is
    // any name: a restart as administrator hands the root back exactly as
    // it was, so the caller passes `args_os`.
    let text = |value: Option<std::ffi::OsString>, need: &str| {
        value
            .and_then(|value| value.into_string().ok())
            .with_context(|| need.to_owned())
    };

    while let Some(arg) = args.next() {
        match arg.to_str().unwrap_or_default() {
            // Answered before anything asks about a path: the parser must
            // not open a window, or fail, to answer them.
            "-h" | "--help" => return Ok(Invocation::Help),
            "-V" | "--version" => return Ok(Invocation::Version),
            "-a" | "--apparent-size" => options.apparent_size = true,
            "-l" | "--follow-links" => options.follow_links = true,
            "-H" | "--no-hidden" => options.include_hidden = false,
            // Staying on one volume is the default; the flag is kept so
            // old invocations still work.
            "-x" | "--one-filesystem" => options.one_filesystem = true,
            "-X" | "--cross-filesystems" => options.one_filesystem = false,
            "-D" | "--disk" => disk = true,
            "--sudo" => sudo = true,
            "-d" | "--depth" => {
                let value = text(args.next(), "--depth needs a number")?;
                depth = value.parse().context("--depth needs a number")?;
                anyhow::ensure!(
                    (1..=6).contains(&depth),
                    "--depth must be 1 to 6"
                );
            }
            "--power-efficiency" => {
                let value =
                    text(args.next(), "--power-efficiency needs a preset")?;
                let preset = power::PowerEfficiency::parse(&value)
                    .context("unknown Power Efficiency preset")?;
                options.threads = preset.policy(power::cpu_threads());
                power = Some(preset);
            }
            "--scan-threads" => {
                power = None;
                let value = text(args.next(), "--scan-threads needs a number")?;
                options.threads.max_threads = value
                    .parse()
                    .context("--scan-threads needs a positive integer")?;
                anyhow::ensure!(
                    options.threads.max_threads > 0,
                    "--scan-threads must be positive"
                );
            }
            "--fixed-threads" => {
                options.threads.adaptive = false;
                power = None;
            }
            "--adaptive-threads" => {
                options.threads.adaptive = true;
                options.threads.system_cpu_limit = Some(0.80);
                power = None;
            }
            "--thread-throughput-percent" => {
                let value = text(
                    args.next(),
                    "--thread-throughput-percent needs a number",
                )?;
                let percent: u8 = value
                    .parse()
                    .context("throughput percent must be 1 to 100")?;
                anyhow::ensure!(
                    (1..=100).contains(&percent),
                    "throughput percent must be 1 to 100"
                );
                options.threads.retained_throughput =
                    f64::from(percent) / 100.0;
            }
            "--thread-system-cpu-percent" => {
                let value = text(
                    args.next(),
                    "--thread-system-cpu-percent needs a number",
                )?;
                let percent: u8 =
                    value.parse().context("CPU percent must be 0 to 100")?;
                anyhow::ensure!(percent <= 100, "CPU percent must be 0 to 100");
                options.threads.system_cpu_limit =
                    (percent > 0).then(|| f64::from(percent) / 100.0);
            }
            "--metric" => {
                let value = text(args.next(), "--metric needs a value")?;
                options.metric = match value.as_str() {
                    "files" => disktree_core::tree::Metric::Files,
                    "bytes" | "size" => disktree_core::tree::Metric::Bytes,
                    other => anyhow::bail!(
                        "unknown metric {other}; try bytes or files"
                    ),
                };
            }
            // Launch Services added a process serial number when opening an
            // app from Finder until OS X 10.9, and some launchers still do.
            other if other.starts_with("-psn_") => {}
            other if other.starts_with('-') => {
                anyhow::bail!("unknown option {other}\n\n{USAGE}");
            }
            _ => {
                anyhow::ensure!(root.is_none(), "only one path can be scanned");
                root = Some(arg);
            }
        }
    }

    // A link counts as there even when it leads nowhere: it is a local
    // name, and a dangling one is a local error, not a host.
    let place =
        root.map(|root| place(root, |path| path.symlink_metadata().is_ok()));
    if let Some(Place::Remote { host, path, bare }) = place.clone() {
        anyhow::ensure!(
            !(disk && path.is_some()),
            "--disk and a PATH cannot be combined"
        );
        let ask = match path {
            Some(path) if remote::names_a_user(&path) => anyhow::bail!(
                "{host}:{}: ~user is not supported; give the full path",
                path.display()
            ),
            Some(path) => Ask::Path(path),
            None if disk => Ask::Disk,
            None => Ask::Default,
        };
        let mut remote = Remote::new(host, Reach::Ssh { sudo }, ask);
        remote.bare = bare;
        return Ok(Invocation::Window(Args {
            source: Source::Remote(std::sync::Arc::new(remote)),
            root: PathBuf::new(),
            options,
            depth: depth.clamp(1, 6),
            power,
        }));
    }
    anyhow::ensure!(
        !sudo,
        "--sudo is for another machine (disktree HOST --sudo); here, run \
         disktree itself as root"
    );
    let root = place.map(|place| match place {
        Place::Local(path) => path,
        Place::Remote { .. } => unreachable!("handled above"),
    });
    anyhow::ensure!(
        !(disk && root.is_some()),
        "--disk and a PATH cannot be combined"
    );
    let source = Source::Local;
    let home = source.home();
    let root = match root {
        _ if disk => home
            .as_deref()
            .and_then(|home| source.volume_root(home))
            .unwrap_or_else(|| PathBuf::from("/")),
        Some(root) => root,
        None => home.context("no path given and no home directory")?,
    };
    // Store the depth as the initial view setting rather than a scan option: it
    // is a display choice the run-time `[` and `]` keys also change.
    // Canonical, so a later widening recognises this tree in the wider walk.
    let root = source.canonical(root);
    let is_dir = source
        .is_dir(&root)
        .with_context(|| format!("cannot read {}", root.display()))?;
    anyhow::ensure!(is_dir, "{} is not a directory", root.display());

    Ok(Invocation::Window(Args {
        source,
        root,
        options,
        depth: depth.clamp(1, 6),
        power,
    }))
}

/// Where the root argument points: here, or at another machine.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Place {
    Local(PathBuf),
    /// `path` is `None` for `host` and `host:`: the default root there.
    /// `bare` when the word had no `:`, and is a host only because no
    /// local path has that name.
    Remote {
        host: String,
        path: Option<PathBuf>,
        bare: bool,
    },
}

/// scp's rule, after one of its own: a path that `exists` here is local,
/// whatever it holds. Then a `:` before any `/` makes `host:path`, with
/// `[address]:path` for an IPv6 address; a bare word with no `/` is a
/// host; everything else is a local path, so `./spark-1` is the folder.
fn place(arg: std::ffi::OsString, exists: impl Fn(&Path) -> bool) -> Place {
    let Some(text) = arg.to_str() else {
        return Place::Local(PathBuf::from(arg));
    };
    if exists(Path::new(text)) {
        return Place::Local(PathBuf::from(arg));
    }
    let remote = |host: &str, path: &str, bare: bool| Place::Remote {
        host: host.to_owned(),
        path: (!path.is_empty()).then(|| PathBuf::from(path)),
        bare,
    };
    // `[fe80::1]:path` and `me@[fe80::1]:path`: the colons inside the
    // brackets are the address's. ssh takes the address without them.
    if let Some((user, rest)) = bracketed(text)
        && let Some((address, after)) = rest.split_once(']')
        && let Some(path) = after
            .strip_prefix(':')
            .or_else(|| after.is_empty().then_some(""))
    {
        return remote(&format!("{user}{address}"), path, false);
    }
    let separator = |c: char| c == '/' || (cfg!(windows) && c == '\\');
    let slash = text.find(separator).unwrap_or(text.len());
    if let Some(colon) = text[..slash].find(':') {
        let (host, path) = (&text[..colon], &text[colon + 1..]);
        // `C:\Users` is a drive on Windows, not a host named C.
        let drive = cfg!(windows) && host.len() == 1;
        if !host.is_empty() && !drive {
            return remote(host, path, false);
        }
    }
    let bare = slash == text.len() && !matches!(text, "" | "." | ".." | "~");
    if bare {
        return remote(text, "", true);
    }
    Place::Local(PathBuf::from(arg))
}

/// `text` split after `user@[` or `[`, when it starts with either.
fn bracketed(text: &str) -> Option<(&str, &str)> {
    let open = text.find('[')?;
    let user = &text[..open];
    (user.is_empty()
        || (user.ends_with('@')
            && !user[..user.len() - 1].contains(['/', ':', '@'])))
    .then(|| (user, &text[open + 1..]))
}

/// The console of the terminal disktree was started from, if any: a
/// windowed program on Windows gets none of its own.
#[cfg(windows)]
mod console {
    #![allow(
        unsafe_code,
        reason = "two Win32 calls that take no pointers to get wrong"
    )]

    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, FreeConsole,
    };

    /// Borrow the parent's console so printed text reaches it. Does
    /// nothing when started from Explorer, which has none.
    pub fn attach() {
        // SAFETY: takes a process id by value, and failure only means
        // there was no console to attach to.
        unsafe {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }

    /// Let go of it again, so the shell redraws its prompt.
    pub fn detach() {
        // SAFETY: no arguments; a process without a console is left as is.
        unsafe {
            FreeConsole();
        }
    }
}

#[cfg(test)]
mod argument_tests {
    use super::*;

    fn arguments(extra: &[&str]) -> impl Iterator<Item = std::ffi::OsString> {
        extra
            .iter()
            .copied()
            .chain(std::iter::once("."))
            .map(std::ffi::OsString::from)
    }

    /// Parse with a saved preset, insisting on a window.
    fn saved_args(list: &[&str], preset: power::PowerEfficiency) -> Args {
        match parse_args_with_power(arguments(list), preset).expect("parses") {
            Invocation::Window(args) => args,
            other => panic!("not a window: {other:?}"),
        }
    }

    #[test]
    fn adaptive_budget_and_fixed_override_are_explicit() {
        let args = parse_args(arguments(&[])).expect("defaults");
        assert_eq!(
            args.options.threads.max_threads,
            4.min(power::cpu_threads())
        );
        assert!(!args.options.threads.adaptive);
        let args = parse_args(arguments(&[
            "--scan-threads",
            "4",
            "--fixed-threads",
            "--thread-throughput-percent",
            "85",
            "--thread-system-cpu-percent",
            "0",
        ]))
        .expect("custom");
        assert_eq!(args.options.threads.max_threads, 4);
        assert!(!args.options.threads.adaptive);
        assert!(
            (args.options.threads.retained_throughput - 0.85).abs()
                < f64::EPSILON
        );
        assert_eq!(args.options.threads.system_cpu_limit, None);
    }

    #[test]
    fn saved_power_is_loaded_before_cli_overrides() {
        use power::PowerEfficiency as Power;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("power-efficiency");
        power::save(&path, Power::Miser).expect("save");
        let saved = power::load(&path).expect("load");
        let args = saved_args(&[], saved);
        assert_eq!(args.power, Some(Power::Miser));
        assert_eq!(
            args.options.threads.max_threads,
            2.min(power::cpu_threads())
        );
        let args =
            saved_args(&["--power-efficiency", "drain-my-battery"], saved);
        assert_eq!(args.power, Some(Power::DrainMyBattery));
        assert_eq!(args.options.threads.max_threads, power::cpu_threads());
        let args =
            saved_args(&["--scan-threads", "8", "--adaptive-threads"], saved);
        assert!(args.power.is_none());
        assert!(args.options.threads.adaptive);
        assert_eq!(args.options.threads.max_threads, 8);
        assert_eq!(power::load(&path).expect("unchanged"), saved);
        assert!(
            parse_args(arguments(&["--power-efficiency", "invalid"])).is_err()
        );
    }

    // APFS rejects these filename bytes; Linux filesystems permit them.
    #[cfg(target_os = "linux")]
    #[test]
    fn worker_options_preserve_a_non_unicode_root() {
        use std::os::unix::ffi::OsStringExt as _;

        let temp = tempfile::TempDir::new().expect("tempdir");
        let root = temp
            .path()
            .join(std::ffi::OsString::from_vec(vec![b'r', 0xff]));
        std::fs::create_dir(&root).expect("directory");
        let args = parse_args(
            [
                std::ffi::OsString::from("--scan-threads"),
                std::ffi::OsString::from("4"),
                root.clone().into_os_string(),
            ]
            .into_iter(),
        )
        .expect("native path");
        assert_eq!(args.root, dunce::canonicalize(root).expect("root"));
        assert_eq!(args.options.threads.max_threads, 4);
    }

    #[test]
    fn a_host_is_named_the_way_scp_names_one() {
        let remote = |host: &str, path: Option<&str>| Place::Remote {
            host: host.into(),
            path: path.map(PathBuf::from),
            bare: false,
        };
        let bare = |host: &str| Place::Remote {
            host: host.into(),
            path: None,
            bare: true,
        };
        let local = |path: &str| Place::Local(PathBuf::from(path));
        // What is here: a folder, a folder with a colon in its name, and
        // a link that leads nowhere.
        let here = |path: &Path| {
            ["projects", "backup:2024", "dangling"]
                .iter()
                .any(|name| path == Path::new(name))
        };
        for (arg, expected) in [
            ("spark-1", bare("spark-1")),
            ("me@spark-1", bare("me@spark-1")),
            ("spark-1:", remote("spark-1", None)),
            // The home directory there, as scp spells it.
            ("spark-1:~", remote("spark-1", Some("~"))),
            ("spark-1:~/models", remote("spark-1", Some("~/models"))),
            // An IPv6 address, bracketed so its colons are not a path's.
            ("[fe80::1]:/srv", remote("fe80::1", Some("/srv"))),
            ("me@[fe80::1]:models", remote("me@fe80::1", Some("models"))),
            ("[fe80::1]", remote("fe80::1", None)),
            ("[fe80::1]:", remote("fe80::1", None)),
            // Local paths win: one with a colon, and a dangling link.
            ("backup:2024", local("backup:2024")),
            ("dangling", local("dangling")),
            (
                "spark-1:/srv/models",
                remote("spark-1", Some("/srv/models")),
            ),
            ("spark-1:models", remote("spark-1", Some("models"))),
            // A ':' after a '/' is part of a local name.
            ("./spark-1", local("./spark-1")),
            ("dir/a:b", local("dir/a:b")),
            ("/abs/path", local("/abs/path")),
            // A local folder named like a host stays local.
            ("projects", local("projects")),
            (".", local(".")),
            ("..", local("..")),
        ] {
            assert_eq!(place(arg.into(), here), expected, "{arg}");
        }
    }

    #[test]
    fn a_host_on_the_command_line_makes_a_remote_source() {
        let args = |list: &[&str]| {
            parse_args(list.iter().copied().map(std::ffi::OsString::from))
        };
        let parsed = args(&["--sudo", "spark-1:/srv"]).expect("remote");
        let Source::Remote(remote) = &parsed.source else {
            panic!("not remote: {parsed:?}");
        };
        assert_eq!(remote.host, "spark-1");
        assert_eq!(remote.reach, Reach::Ssh { sudo: true });
        assert_eq!(remote.ask, Ask::Path(PathBuf::from("/srv")));
        assert!(parsed.root.as_os_str().is_empty(), "known once connected");

        let disk = args(&["-D", "spark-1"]).expect("remote disk");
        let Source::Remote(remote) = &disk.source else {
            panic!("not remote: {disk:?}");
        };
        assert_eq!(remote.ask, Ask::Disk);
        assert_eq!(remote.reach, Reach::Ssh { sudo: false });

        assert!(args(&["-D", "spark-1:/srv"]).is_err());
        // scp reads `~other` as that user's home; disktree does not guess.
        for path in ["spark-1:~other/x", "spark-1:~other"] {
            let error = args(&[path]).expect_err(path).to_string();
            assert!(error.contains("~user is not supported"), "{error}");
        }
        let mine = args(&["spark-1:~/x"]).expect("own home");
        let Source::Remote(remote) = &mine.source else {
            panic!("not remote: {mine:?}");
        };
        assert_eq!(remote.ask, Ask::Path(PathBuf::from("~/x")));
        assert!(args(&["--sudo", "."]).is_err(), "sudo is for a host");
        let here = args(&["."]).expect("local");
        assert!(here.source.is_local());
    }

    #[test]
    fn help_and_version_answer_before_any_path() {
        let parse = |list: &[&str]| {
            parse_args_with_power(
                list.iter().copied().map(std::ffi::OsString::from),
                power::PowerEfficiency::default(),
            )
        };
        assert!(matches!(parse(&["-h"]), Ok(Invocation::Help)));
        assert!(matches!(parse(&["--help"]), Ok(Invocation::Help)));
        assert!(matches!(parse(&["-V"]), Ok(Invocation::Version)));
        assert!(matches!(parse(&["--version"]), Ok(Invocation::Version)));
        // They need no path, and options after them are not read.
        assert!(matches!(
            parse(&["--version", "/no/such/path"]),
            Ok(Invocation::Version)
        ));
        // Before them, an unknown option is still an error.
        assert!(parse(&["--nope", "--version"]).is_err());
    }

    #[test]
    fn the_version_line_names_the_build() {
        let line = version_line();
        assert_eq!(line.lines().count(), 1, "{line}");
        assert!(
            line.starts_with(concat!(
                "disktree ",
                env!("CARGO_PKG_VERSION"),
                " (commit "
            )),
            "{line}"
        );
        let commit = env!("DISKTREE_COMMIT");
        let sha = commit.strip_suffix("-dirty").unwrap_or(commit);
        assert!(
            sha == "unknown"
                || (sha.len() == 7
                    && sha.chars().all(|c| c.is_ascii_hexdigit())),
            "commit {commit}"
        );
        // A source id is 16 lowercase hex digits. The two phrases are the
        // cases of no agent, and of agents the build has no record of.
        let agent = env!("DISKTREE_EMBEDDED_AGENT");
        assert!(
            matches!(agent, "no agent" | "unknown agent")
                || (agent.len() == 16
                    && agent.chars().all(|c| c.is_ascii_hexdigit())),
            "agent {agent}"
        );
        assert!(line.ends_with(&format!("agent {agent})")), "{line}");
    }

    #[test]
    fn invalid_worker_budgets_are_rejected() {
        for extra in [
            vec!["--scan-threads", "0"],
            vec!["--scan-threads", "-1"],
            vec!["--thread-throughput-percent", "0"],
            vec!["--thread-throughput-percent", "101"],
            vec!["--thread-system-cpu-percent", "101"],
        ] {
            assert!(parse_args(arguments(&extra)).is_err());
        }
    }
}
