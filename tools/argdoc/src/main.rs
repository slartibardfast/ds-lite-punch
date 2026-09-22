//! argdoc — the CLI authoring tool for ds-lite-punch.
//!
//! One clap definition of the command line lives here, and two files come out
//! of it: the help text the daemon prints (`src/help.txt`) and the manual page
//! (`deploy/man/ds-lite-punch.8`). The manual's ENVIRONMENT, FILES, LOG EVENTS,
//! LIMITS and SEE ALSO sections come from `src/man-sections.roff`, appended so
//! that a regeneration keeps them.
//!
//! The daemon links nothing from here. `src/main.rs` carries the help text with
//! `include_str!`, and a test in that crate compares this definition's flags
//! with the ones the real parser accepts, which is what keeps the two in step.
//!
//! Run it with an explicit target, because the crate tree's `.cargo/config.toml`
//! sends every cargo command to musl:
//!
//! ```text
//! cargo run --manifest-path tools/argdoc/Cargo.toml --target x86_64-unknown-linux-gnu
//! ```

use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, Command};

/// The repository root, resolved from this crate's manifest directory so the
/// tool can be run from anywhere.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve the repository root")
}

/// The shipping crate's version, read from its manifest so the help text, the
/// manual page and `--version` cannot disagree with the artifact.
fn crate_version(root: &Path) -> String {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml"))
        .expect("read the shipping crate's manifest");
    for line in manifest.lines() {
        if let Some(rest) = line.strip_prefix("version = ") {
            return rest.trim().trim_matches('"').to_string();
        }
    }
    panic!("no version line in the shipping crate's manifest");
}

/// The command line, mirrored flag for flag from `parse_args_from` in
/// `src/main.rs`.
fn cli(version: &str) -> Command {
    Command::new("ds-lite-punch")
        .version(version.to_string())
        // The daemon prints this text itself, for `-h` and `--help` alike, so
        // clap's own help flag would add a note about a short form that does
        // not exist. The flag below takes its place.
        .disable_help_flag(true)
        .override_usage(
            "ds-lite-punch --static-map R=ip:port [OPTIONS]\n       \
             ds-lite-punch --bind ip:port --target ip:port [OPTIONS]",
        )
        .about(
            "CGNAT-aware UDP relay for a ds-lite line: hold the carrier's mapping \
             and forward inbound traffic to a br-lan target.",
        )
        .long_about(
            "The daemon keeps one external mapping alive on a ds-lite line by writing \
             to it, learns the mapping's external address and port with STUN, and \
             forwards inbound UDP and TCP to a target on the local network with the \
             peer's source address preserved. It answers UPnP IGD, PCP and NAT-PMP on \
             the LAN, and it can report on the carrier's filtering from outside the line.",
        )
        .arg(
            Arg::new("static-map")
                .long("static-map")
                .value_name("R=IP:PORT")
                .action(ArgAction::Append)
                .help("Hold the mapping for slot port R. Repeatable, one entry per instance.")
                .long_help(
                    "Hold the mapping for slot port R, forwarding inbound datagrams to \
                     ip:port on the local network. Repeatable, one entry per instance. \
                     Either this or the legacy --bind/--target pair is required.",
                ),
        )
        .arg(
            Arg::new("bind")
                .long("bind")
                .value_name("IP:PORT")
                .help("Legacy single-map form: the relay socket on the CGNAT-facing address.")
                .long_help(
                    "Legacy single-map form: the relay socket on the CGNAT-facing address, \
                     which is the tuple the carrier maps. Requires --target.",
                ),
        )
        .arg(
            Arg::new("target")
                .long("target")
                .value_name("IP:PORT")
                .help("Legacy single-map form: the endpoint inbound datagrams go to.")
                .long_help(
                    "Legacy single-map form: the local endpoint inbound datagrams are \
                     forwarded to, with the peer's source address preserved. Requires --bind.",
                ),
        )
        .arg(
            Arg::new("stun")
                .long("stun")
                .value_name("HOST:PORT,...")
                .help("STUN servers to read and refresh the mapping, comma-separated.")
                .long_help(
                    "STUN servers, comma-separated as host:port, tried in order and rotated \
                     when one falls silent. Default: \
                     stun.l.google.com:19302,stun.cloudflare.com:3478.",
                ),
        )
        .arg(
            Arg::new("interval")
                .long("interval")
                .value_name("SECS")
                .help("Seconds between the STUN writes that keep the mapping alive.")
                .long_help(
                    "Seconds between the STUN writes that keep the mapping alive. The writes \
                     are what the carrier sees, so this is the cadence the mapping's lifetime \
                     depends on. Default 2, minimum 1.",
                ),
        )
        .arg(
            Arg::new("gateway")
                .long("gateway")
                .value_name("IP")
                .help("Next hop used to route STUN out the line that holds the mapping.")
                .long_help(
                    "Next hop used to route STUN out the line that holds the mapping. Without \
                     it the default route wins and STUN reports the wrong nat. Default \
                     192.168.0.1.",
                ),
        )
        .arg(
            Arg::new("state-dir")
                .long("state-dir")
                .value_name("PATH")
                .help("Directory for the live state: the tuple, the leases and the stores.")
                .long_help(
                    "Directory for the live state: the learned external tuple, the facade's \
                     leases, and the DeviceProtection store. It is expected to be on a \
                     temporary filesystem, so its contents do not survive a reboot. Default \
                     /run/ds-lite-punch.",
                ),
        )
        .arg(
            Arg::new("slot-port-range")
                .long("slot-port-range")
                .value_name("LO-HI")
                .help("Port range the slot engine allocates from.")
                .long_help(
                    "Port range the slot engine allocates from, written LO-HI. Ports in it \
                     must not overlap the relay socket. Default 30000-39999.",
                ),
        )
        .arg(
            Arg::new("max-slots")
                .long("max-slots")
                .value_name("N")
                .help("Maximum concurrent slots.")
                .long_help("Maximum concurrent slots. Default 32."),
        )
        .arg(
            Arg::new("max-maps-per-client")
                .long("max-maps-per-client")
                .value_name("N")
                .help("Maximum mappings one client may hold.")
                .long_help("Maximum mappings one client may hold at a time. Default 16."),
        )
        .arg(
            Arg::new("gc-grace-factor")
                .long("gc-grace-factor")
                .value_name("N")
                .help("Grace multiple applied to a slot's lifetime before collection.")
                .long_help(
                    "Grace multiple applied to a slot's lifetime before it is collected. \
                     Default 3.",
                ),
        )
        .arg(
            Arg::new("max-rescues")
                .long("max-rescues")
                .value_name("N")
                .help("Maximum rescue attempts before a slot is abandoned.")
                .long_help("Maximum rescue attempts before a slot is abandoned. Default 8."),
        )
        .arg(
            Arg::new("observation")
                .long("observation")
                .action(ArgAction::SetTrue)
                .help("Report what the hold would act on, and change nothing.")
                .long_help(
                    "Report the named devices' live flows and touch nothing. This is the \
                     stage a new device is admitted from, before --hold arms the arm.",
                ),
        )
        .arg(
            Arg::new("allowlist")
                .long("allowlist")
                .value_name("PATH")
                .help("File of IPv4 addresses, one per line, naming the devices the hold acts for.")
                .long_help(
                    "File of IPv4 addresses, one per line, with # for comments. These are the \
                     devices the hold acts for. The list is a budget as well as an admission: \
                     a held flow costs about half a packet a second at the default cadence. \
                     The path is read at startup, so a typo fails the start.",
                ),
        )
        .arg(
            Arg::new("hold")
                .long("hold")
                .action(ArgAction::SetTrue)
                .help("Hold the named devices' flows instead of only reporting them.")
                .long_help(
                    "Hold the named devices' flows: the RFC conntrack lifetimes, plus the \
                     daemon's own writes to keep them alive. Without this flag the allowlist \
                     is reported on and nothing is touched.",
                ),
        )
        .arg(
            Arg::new("cdc")
                .long("cdc")
                .value_name("proc|nft|aya")
                .help("How conntrack entries are removed.")
                .long_help(
                    "How conntrack entries are removed: proc, nft, or aya. The nft backend is \
                     the default and the one this line is measured with.",
                ),
        )
        .arg(
            Arg::new("pcp")
                .long("pcp")
                .action(ArgAction::SetTrue)
                .help("Answer PCP and NAT-PMP on UDP 5351, on the local network.")
                .long_help(
                    "Answer PCP (RFC 6887) and NAT-PMP (RFC 6886) on UDP 5351, on the local \
                     network only, riding the same slot engine as the UPnP facade. Off by \
                     default.",
                ),
        )
        .arg(
            Arg::new("pcp-peer")
                .long("pcp-peer")
                .action(ArgAction::SetTrue)
                .help("Answer the PCP PEER opcode with the mapping's own tuple.")
                .long_help(
                    "Answer the PCP PEER opcode with the mapping's own tuple. The datapath is \
                     endpoint-independent, so that opcode installs nothing and is otherwise \
                     refused.",
                ),
        )
        .arg(
            Arg::new("upnp-port")
                .long("upnp-port")
                .value_name("N")
                .help("Port the UPnP IGD facade serves on.")
                .long_help("Port the UPnP IGD facade serves on. Default 49152."),
        )
        .arg(
            Arg::new("lan-ip")
                .long("lan-ip")
                .value_name("IP")
                .help("Local address the facade binds and SSDP joins.")
                .long_help(
                    "Local address the facade binds its HTTP service to and joins the SSDP \
                     group on. Default 192.168.21.1.",
                ),
        )
        .arg(
            Arg::new("upnp-name")
                .long("upnp-name")
                .value_name("NAME")
                .help("Friendly name the facade reports.")
                .long_help(
                    "Friendly name the facade reports in its device description. Default \
                     `ds-lite-punch IGD`.",
                ),
        )
        .arg(
            Arg::new("no-upnp")
                .long("no-upnp")
                .action(ArgAction::SetTrue)
                .help("Turn the UPnP IGD facade off.")
                .long_help(
                    "Turn the UPnP IGD facade off. Use it when another device on the local \
                     network already answers SSDP.",
                ),
        )
        .arg(
            Arg::new("carrier-probe")
                .long("carrier-probe")
                .action(ArgAction::SetTrue)
                .help("Count the cooperating helper's probe and raise carrier-silent when it stops.")
                .long_help(
                    "Count the cooperating helper's marked probe, and raise carrier-silent \
                     after the configured number of intervals with none. Arming this obliges \
                     the helper to run, because a helper that stopped and a carrier that \
                     stopped look the same to the counter.",
                ),
        )
        .arg(
            Arg::new("carrier-probe-interval")
                .long("carrier-probe-interval")
                .value_name("SECS")
                .help("Seconds expected between the helper's probes.")
                .long_help("Seconds expected between the helper's probes. Default 900."),
        )
        .arg(
            Arg::new("carrier-probe-misses")
                .long("carrier-probe-misses")
                .value_name("N")
                .help("Intervals of silence that raise carrier-silent.")
                .long_help("Intervals of silence that raise carrier-silent. Default 3."),
        )
        .arg(
            Arg::new("carrier-probe-poll")
                .long("carrier-probe-poll")
                .value_name("SECS")
                .help("Seconds between readings of the counter.")
                .long_help("Seconds between readings of the counter's value. Default 5."),
        )
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help("Print this text and exit."),
        )
        .arg(
            Arg::new("ct-probe")
                .long("ct-probe")
                .action(ArgAction::SetTrue)
                .hide(true)
                .help("Diagnostic: bisect the conntrack-delete encoding, then exit."),
        )
        .after_long_help(
            "EXIT STATUS\n  \
             0   the daemon ran, or --help or --version was printed\n  \
             2   the command line was rejected, and the message says why\n\n\
             ENVIRONMENT\n  \
             The procd service reads /etc/ds-lite-punch.env and turns its keys into \
             the flags above. The key-by-key mapping is in the manual page's \
             ENVIRONMENT section, which also names the three keys only the service \
             reads.\n\n\
             SEE ALSO\n  \
             man 8 ds-lite-punch, /etc/ds-lite-punch.env",
        )
}

fn main() -> std::io::Result<()> {
    let root = repo_root();
    let version = crate_version(&root);
    let cmd = cli(&version);

    let mut help = cmd.clone().render_long_help().to_string();
    if !help.ends_with('\n') {
        help.push('\n');
    }
    let help_path = root.join("src/help.txt");
    std::fs::write(&help_path, &help)?;

    let mut man = Vec::new();
    clap_mangen::Man::new(cmd)
        .section("8")
        .manual("System Manager's Manual")
        .source(format!("ds-lite-punch {}", version))
        .render(&mut man)?;
    man.extend_from_slice(include_bytes!("man-sections.roff"));
    let man_path = root.join("deploy/man/ds-lite-punch.8");
    if let Some(dir) = man_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&man_path, &man)?;

    println!("wrote {}", help_path.display());
    println!("wrote {}", man_path.display());
    Ok(())
}