//! hy2tui — Hysteria2 full-system VPN (TUN) with a btop-like terminal UI.

mod app;
mod core;
mod dns;
mod traffic;
mod download;
mod embedded;
mod mixed;
mod split;
mod net;
mod store;
mod ui;
mod uri;

use anyhow::{bail, Result};
use std::io::Write;
use std::os::unix::process::CommandExt;
use store::{is_root, Paths, Store};

const HELP: &str = "\
hy2tui — Hysteria2 VPN in your terminal (TUN mode, all traffic)

USAGE
  hy2tui                   open the TUI (asks for sudo when TUN mode is on)
  hy2tui connect [N]       open the TUI and connect to profile N (default: last used)
  hy2tui --proxy-only      switch to proxy-only mode (no root): browsers use
                           SOCKS5/HTTP 127.0.0.1:2080, nothing else changes
  hy2tui add [LINK…]       add hy2:// links (no args = read clipboard)
  hy2tui list              list profiles
  hy2tui install-core [-j N] [--proxy URL] [--force] [--embedded]
                           download/update the hysteria core: parallel streams,
                           continues after a broken connection or Ctrl-C;
                           --embedded = use the core built into hy2tui (offline)
  hy2tui reset             clean up after crashes / a closed CyberVPN: DNS,
                           leftover TUN devices and routes (also runs automatically)
  hy2tui help

Config: ~/.config/hy2tui/config.toml
";

/// TUN, routes and resolv.conf need root: re-run ourselves through sudo,
/// keeping the environment (Wayland/X11 clipboard variables).
fn elevate() -> Result<()> {
    if is_root() {
        return Ok(());
    }
    eprintln!("hy2tui needs root for TUN mode — asking sudo…");
    let exe = std::env::current_exe()?;
    let err = std::process::Command::new("sudo")
        .arg("-E")
        .arg(exe)
        .args(std::env::args_os().skip(1))
        .exec();
    bail!("cannot run sudo: {err}")
}

fn ensure_core(paths: &Paths, store: &Store) -> Result<Option<std::path::PathBuf>> {
    if let Some(p) = core::find_core(paths, &store.settings) {
        return Ok(Some(p));
    }
    // built-in core: no network needed
    if let Some(v) = embedded::version() {
        match embedded::extract(paths) {
            Ok(p) => {
                eprintln!("Using the built-in hysteria core {v}");
                return Ok(Some(p));
            }
            Err(e) => eprintln!("built-in core: {e:#}"),
        }
    }
    print!("Hysteria core not found. Download the official one from GitHub now? [Y/n] ");
    std::io::stdout().flush()?;
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    if ans.trim().is_empty() || ans.trim().eq_ignore_ascii_case("y") {
        match core::install_core(paths, &core::InstallOpts::default()) {
            Ok(p) => return Ok(Some(p)),
            Err(e) => eprintln!("install failed: {e:#}"),
        }
    }
    Ok(None)
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths::detect();
    match args.first().map(String::as_str) {
        Some("help") | Some("-h") | Some("--help") => print!("{HELP}"),
        Some("add") => {
            let text = if args.len() > 1 {
                args[1..].join(" ")
            } else {
                net::read_clipboard().ok_or_else(|| anyhow::anyhow!("clipboard empty/unavailable; pass the link as an argument"))?
            };
            let mut store = Store::load(&paths)?;
            let (ok, bad) = store.add_from_text(&text);
            if !ok.is_empty() { store.save(&paths)?; }
            for n in &ok { println!("added: {n}"); }
            for e in &bad { eprintln!("skipped: {e}"); }
            if ok.is_empty() { bail!("no valid hy2:// link found"); }
        }
        Some("list") => {
            let store = Store::load(&paths)?;
            for (i, p) in store.profiles.iter().enumerate() {
                let addr = uri::Hy2Uri::parse(&p.uri).map(|u| format!("{}:{}", u.host, u.ports)).unwrap_or_else(|e| e.to_string());
                println!("{:>2}  {:<40} {}", i + 1, p.name, addr);
            }
            if store.profiles.is_empty() { println!("no profiles — copy a hy2:// link and run: hy2tui add"); }
        }
        Some("install-core") => {
            let mut o = core::InstallOpts::default();
            let mut it = args[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "-j" | "--jobs" => o.jobs = it.next().and_then(|v| v.parse().ok()).ok_or_else(|| anyhow::anyhow!("-j needs a number"))?,
                    "--proxy" => o.proxy = Some(it.next().cloned().ok_or_else(|| anyhow::anyhow!("--proxy needs a URL"))?),
                    "--base" => o.base = it.next().cloned().ok_or_else(|| anyhow::anyhow!("--base needs a URL"))?,
                    "-f" | "--force" => o.force = true,
                    "--embedded" => {
                        let p = embedded::extract(&paths)?;
                        println!("built-in core {} installed: {}", embedded::version().unwrap_or("?"), p.display());
                        return Ok(());
                    }
                    x => bail!("unknown option {x}"),
                }
            }
            if let Err(e) = core::install_core(&paths, &o) {
                if let Some(v) = embedded::version() {
                    bail!("{e:#}\n\nDownload failed. This hy2tui has the core {v} built in — install it with:\n  hy2tui install-core --embedded");
                }
                return Err(e);
            }
        }
        Some("restore") | Some("reset") => {
            elevate()?;
            let store = Store::load(&paths).unwrap_or_default();
            let log = net::network_reset(&store.settings.tun_name);
            if log.is_empty() {
                println!("network is clean — nothing to reset");
            }
            for l in log {
                println!("{l}");
            }
        }
        Some("connect") | Some("--proxy-only") | None => {
            let mut store = Store::load(&paths)?;
            if args.iter().any(|a| a == "--proxy-only") {
                store.settings.tun = false;
                if store.settings.proxy.trim().is_empty() {
                    store.settings.proxy = "127.0.0.1:2080".into();
                }
                store.save(&paths)?;
                eprintln!("proxy-only mode: SOCKS5/HTTP on {} (saved; press m in hy2tui to change)", store.settings.proxy);
            }
            // only TUN needs root; proxy-only runs as your user
            if store.settings.tun {
                elevate()?;
            }
            let auto = if args.first().map(String::as_str) == Some("connect") {
                match args.get(1).and_then(|n| n.parse::<usize>().ok()) {
                    Some(n) if n >= 1 => Some(n - 1),
                    _ => store.last_used.or(Some(0)),
                }
            } else {
                None
            };
            let core = ensure_core(&paths, &store)?;
            app::run(paths, store, core, auto)?;
        }
        Some(other) => {
            eprint!("unknown command '{other}'\n\n{HELP}");
            std::process::exit(2);
        }
    }
    Ok(())
}
