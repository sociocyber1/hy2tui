//! The Hysteria 2 core (official Go binary by apernet): find / download /
//! verify it, write its client config, run it and stream its JSON logs.

use crate::store::{Paths, Profile, Settings};
use crate::uri::Hy2Uri;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;

pub const RELEASES_BASE: &str = "https://github.com/apernet/hysteria/releases";
pub const RUN_DIR: &str = "/run/hy2tui";

// ---------------------------------------------------------------- locating

pub fn find_core(paths: &Paths, s: &Settings) -> Option<PathBuf> {
    if !s.core_path.is_empty() {
        let p = PathBuf::from(&s.core_path);
        return p.is_file().then_some(p);
    }
    let own = paths.data_dir.join("bin/hysteria");
    if own.is_file() {
        return Some(own);
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .chain(["/usr/bin".into(), "/usr/local/bin".into()])
            .map(|d| d.join("hysteria"))
            .find(|p| p.is_file())
    })
}

pub fn core_version(core: &Path) -> String {
    Command::new(core)
        .arg("version")
        .env("HYSTERIA_DISABLE_UPDATE_CHECK", "true")
        .stdin(Stdio::null())
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.trim().strip_prefix("Version:").map(|v| v.trim().to_string()))
        })
        .unwrap_or_else(|| "?".into())
}

// ---------------------------------------------------------------- install

/// x86-64-v3 (AVX2/BMI2/FMA) CPUs can use the faster "-avx" build.
fn cpu_is_v3() -> bool {
    let info = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let flags = info.lines().find(|l| l.starts_with("flags")).unwrap_or("");
    ["avx2", "bmi2", "fma", "movbe"].iter().all(|f| flags.split_whitespace().any(|x| x == *f))
}

pub fn asset_name() -> Result<String> {
    Ok(match std::env::consts::ARCH {
        "x86_64" if cpu_is_v3() => "hysteria-linux-amd64-avx",
        "x86_64" => "hysteria-linux-amd64",
        "aarch64" => "hysteria-linux-arm64",
        "arm" => "hysteria-linux-arm",
        a => bail!("no prebuilt hysteria core for CPU '{a}'"),
    }
    .to_string())
}

fn sha256_file(p: &Path) -> Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

pub struct InstallOpts {
    pub jobs: usize,
    pub proxy: Option<String>,
    /// Release page base; override for a mirror. Default: GitHub.
    pub base: String,
    pub force: bool,
}

impl Default for InstallOpts {
    fn default() -> Self {
        Self { jobs: 8, proxy: None, base: RELEASES_BASE.into(), force: false }
    }
}

/// Download the latest core: parallel async streams, resumable after any
/// interruption, SHA-256 checked against the release's hashes.txt.
pub fn install_core(paths: &Paths, o: &InstallOpts) -> Result<PathBuf> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(install_core_async(paths, o))
}

async fn install_core_async(paths: &Paths, o: &InstallOpts) -> Result<PathBuf> {
    use crate::download::{self, Opts};
    let asset = asset_name()?;
    let dl = Opts { jobs: o.jobs, proxy: o.proxy.clone() };
    let base = o.base.trim_end_matches('/');

    // latest/download/<asset> redirects to download/<tag>/<asset>: learn the tag
    let latest = format!("{base}/latest/download/{asset}");
    let nr = download::client(&dl, false)?;
    let r = download::resolve(&nr, &latest).await.context("cannot reach the release server (try --proxy)")?;
    let tag = r
        .hops
        .iter()
        .find_map(|h| {
            let rest = h.split("/releases/download/").nth(1)?;
            let t = rest.strip_suffix(&format!("/{asset}"))?;
            (t != "latest").then(|| percent_encoding::percent_decode_str(t).decode_utf8_lossy().into_owned())
        })
        .unwrap_or_else(|| "latest".into());
    let version = tag.rsplit('/').next().unwrap_or(&tag).to_string();
    println!("latest core: {version}  ({asset})");

    let bin_dir = paths.data_dir.join("bin");
    paths.mkdir(&bin_dir, 0o755)?;
    let dest = bin_dir.join("hysteria");
    if dest.is_file() && !o.force && core_version(&dest) == version {
        println!("already up to date: {}", dest.display());
        return Ok(dest);
    }

    let url = if tag == "latest" { latest.clone() } else { format!("{base}/download/{tag}/{asset}") };
    let tmp = bin_dir.join("hysteria.download");
    let owner = |p: &Path| paths.give_back(p);
    download::download(&url, &tmp, &format!("{tag}/{asset}"), &dl, &owner).await?;

    let hashes_url = if tag == "latest" { format!("{base}/latest/download/hashes.txt") } else { format!("{base}/download/{tag}/hashes.txt") };
    let fc = download::client(&dl, true)?;
    let mut hashes = String::new();
    for i in 1..=5 {
        match download::fetch_text(&fc, &hashes_url).await {
            Ok(t) => { hashes = t; break; }
            Err(e) => { eprintln!("hashes.txt: {e:#} (retry {i}/5)"); tokio::time::sleep(std::time::Duration::from_secs(2 * i)).await; }
        }
    }
    let want = hashes
        .lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            let (h, f) = (it.next()?, it.next()?);
            (f.rsplit('/').next() == Some(asset.as_str())).then(|| h.to_lowercase())
        })
        .context("could not get hashes.txt — run again")?;
    let got = sha256_file(&tmp)?;
    if got != want {
        let _ = fs::remove_file(&tmp);
        bail!("SHA-256 mismatch — file deleted, run again for a fresh download");
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, &dest)?;
    paths.give_back(&dest);
    println!("core {version} installed: {} (sha256 ok)", dest.display());
    Ok(dest)
}

// ---------------------------------------------------------------- config

pub const LAN_V4: &[&str] = &[
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "224.0.0.0/4", "255.255.255.255/32",
];
pub const LAN_V6: &[&str] = &["fc00::/7", "fe80::/10", "ff00::/8"];

/// Build the hysteria client config. JSON is valid YAML, so it is written
/// as config.yaml and every string is safely quoted.
/// `proxy_ports`: internal (socks5, http) listener ports for the mixed proxy.
pub fn build_config(p: &Profile, u: &Hy2Uri, s: &Settings, server_ips: &[IpAddr], proxy_ports: Option<(u16, u16)>) -> Value {
    // Connect to the resolved IP (SNI keeps the hostname). This way the core
    // never needs DNS to reconnect, even after we point DNS into the tunnel.
    let server = match server_ips.iter().find(|i| i.is_ipv4()).or(server_ips.first()) {
        Some(ip) => u.server_with(&ip.to_string()),
        None => u.server_with(&u.host),
    };

    let mut tls = Map::new();
    tls.insert("sni".into(), json!(u.sni_or_host()));
    tls.insert("insecure".into(), json!(u.insecure));
    if let Some(pin) = &u.pin_sha256 {
        tls.insert("pinSHA256".into(), json!(pin));
    }

    let mut v4_ex: Vec<String> = vec![];
    let mut v6_ex: Vec<String> = vec![];
    for ip in server_ips {
        match ip {
            IpAddr::V4(a) => v4_ex.push(format!("{a}/32")),
            IpAddr::V6(a) => v6_ex.push(format!("{a}/128")),
        }
    }
    if s.bypass_lan {
        v4_ex.extend(LAN_V4.iter().map(|x| x.to_string()));
        v6_ex.extend(LAN_V6.iter().map(|x| x.to_string()));
    }
    for e in &s.exclude {
        if e.contains(':') { v6_ex.push(e.clone()) } else { v4_ex.push(e.clone()) }
    }

    let mut cfg = Map::new();
    cfg.insert("server".into(), json!(server));
    cfg.insert("auth".into(), json!(u.auth));
    cfg.insert("tls".into(), Value::Object(tls));
    if let Some(t) = &u.obfs {
        let mut inner = Map::new();
        if let Some(pw) = &u.obfs_password {
            inner.insert("password".into(), json!(pw));
        }
        cfg.insert("obfs".into(), json!({ "type": t, t.as_str(): Value::Object(inner) }));
    }
    if p.up_mbps.is_some() || p.down_mbps.is_some() {
        let mut bw = Map::new();
        if let Some(up) = p.up_mbps {
            bw.insert("up".into(), json!(format!("{up} mbps")));
        }
        if let Some(d) = p.down_mbps {
            bw.insert("down".into(), json!(format!("{d} mbps")));
        }
        cfg.insert("bandwidth".into(), Value::Object(bw));
    }
    cfg.insert("fastOpen".into(), json!(s.fast_open));
    if let Some((socks, http)) = proxy_ports {
        cfg.insert("socks5".into(), json!({ "listen": format!("127.0.0.1:{socks}") }));
        cfg.insert("http".into(), json!({ "listen": format!("127.0.0.1:{http}") }));
    }
    if !s.tun {
        return Value::Object(cfg);
    }
    cfg.insert(
        "tun".into(),
        json!({
            "name": s.tun_name,
            "mtu": s.mtu,
            "timeout": "5m",
            "address": { "ipv4": "100.100.100.101/30", "ipv6": "2001::ffff:ffff:ffff:fff1/126" },
            "route": {
                "ipv4": ["0.0.0.0/0"],
                "ipv6": ["2000::/3"],
                "ipv4Exclude": v4_ex,
                "ipv6Exclude": v6_ex,
            }
        }),
    );
    Value::Object(cfg)
}

/// Root: /run/hy2tui. Proxy-only as a normal user: $XDG_RUNTIME_DIR/hy2tui.
fn run_dir() -> PathBuf {
    if crate::store::is_root() {
        return PathBuf::from(RUN_DIR);
    }
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("hy2tui-{}", unsafe { libc::getuid() })))
        .join("hy2tui")
}

pub fn write_config(cfg: &Value) -> Result<PathBuf> {
    let dir = run_dir();
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let path = dir.join("client.yaml");
    let _ = fs::remove_file(&path);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(serde_json::to_string_pretty(cfg)?.as_bytes())?;
    Ok(path)
}

// ---------------------------------------------------------------- process

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level { Debug, Info, Warn, Error }

#[derive(Debug, Clone)]
pub struct LogLine {
    pub time: String,
    pub level: Level,
    pub msg: String,
    pub fields: String,
    /// raw "count" field from "connected to server"
    pub count: Option<u64>,
}

pub fn now_hms() -> String {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            if it.peek() == Some(&'[') {
                it.next();
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() { break; }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn parse_log(line: &str) -> LogLine {
    let time = now_hms();
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(line) {
        let level = match m.get("level").and_then(|v| v.as_str()).unwrap_or("info") {
            "debug" => Level::Debug,
            "warn" => Level::Warn,
            "error" | "fatal" | "panic" | "dpanic" => Level::Error,
            _ => Level::Info,
        };
        let msg = m.get("msg").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let count = m.get("count").and_then(|v| v.as_u64());
        let fields = m
            .iter()
            .filter(|(k, _)| !matches!(k.as_str(), "level" | "ts" | "msg" | "logger" | "caller"))
            .map(|(k, v)| match v {
                Value::String(s) => format!("{k}={s}"),
                o => format!("{k}={o}"),
            })
            .collect::<Vec<_>>()
            .join(" ");
        return LogLine { time, level, msg, fields, count };
    }
    LogLine { time, level: Level::Info, msg: strip_ansi(line), fields: String::new(), count: None }
}

pub fn app_log(level: Level, msg: impl Into<String>) -> LogLine {
    LogLine { time: now_hms(), level, msg: msg.into(), fields: String::new(), count: None }
}

pub fn spawn(core: &Path, cfg: &Path, tx: Sender<LogLine>) -> Result<Child> {
    let mut cmd = Command::new(core);
    cmd.args(["client", "-c"])
        .arg(cfg)
        .env("HYSTERIA_LOG_FORMAT", "json")
        .env("HYSTERIA_LOG_LEVEL", "debug") // debug = per-connection TUN events
        .env("HYSTERIA_DISABLE_UPDATE_CHECK", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // If hy2tui dies for any reason, the kernel kills the core too.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
            Ok(())
        });
    }
    let mut child = cmd.spawn().with_context(|| format!("cannot start {}", core.display()))?;
    for stream in [
        child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
        child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if !line.trim().is_empty() && tx.send(parse_log(&line)).is_err() {
                    break;
                }
            }
        });
    }
    Ok(child)
}

/// SIGTERM, wait up to 3 s, then SIGKILL.
pub fn stop(child: &mut Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    for _ in 0..30 {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_shape() {
        let u = Hy2Uri::parse("hy2://pw@vpn.example.com:45765?obfs=salamander&obfs-password=ob&sni=vpn.example.com#t").unwrap();
        let p = Profile { name: "t".into(), uri: String::new(), up_mbps: Some(50), down_mbps: Some(200) };
        let ips: Vec<IpAddr> = vec!["203.0.113.7".parse().unwrap()];
        let c = build_config(&p, &u, &Settings::default(), &ips, Some((31001, 31002)));
        assert_eq!(c["socks5"]["listen"], "127.0.0.1:31001");
        assert_eq!(c["http"]["listen"], "127.0.0.1:31002");
        let no_tun = build_config(&p, &u, &Settings { tun: false, ..Settings::default() }, &ips, Some((1, 2)));
        assert!(no_tun.get("tun").is_none());
        assert_eq!(c["server"], "203.0.113.7:45765");
        assert_eq!(c["tls"]["sni"], "vpn.example.com");
        assert_eq!(c["obfs"]["type"], "salamander");
        assert_eq!(c["obfs"]["salamander"]["password"], "ob");
        assert_eq!(c["bandwidth"]["down"], "200 mbps");
        let ex = c["tun"]["route"]["ipv4Exclude"].as_array().unwrap();
        assert_eq!(ex[0], "203.0.113.7/32");
        assert!(ex.iter().any(|x| x == "192.168.0.0/16"));
    }

    #[test]
    fn json_logs() {
        let l = parse_log(r#"{"level":"info","ts":1.5,"msg":"connected to server","addr":"1.2.3.4:1","udpEnabled":true,"count":2}"#);
        assert_eq!(l.msg, "connected to server");
        assert_eq!(l.count, Some(2));
        assert!(l.fields.contains("udpEnabled=true"));
        let l = parse_log("\x1b[31mFATAL\x1b[0m boom");
        assert_eq!(l.msg, "FATAL boom");
    }
}
