//! System side: server resolving, TUN counters, DNS override with safe
//! restore, sysctl tuning, and small probes (latency, exit IP).

use anyhow::{Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

pub fn resolve(host: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let mut ips: Vec<IpAddr> = (host, 443)
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {host}"))?
        .map(|a| a.ip())
        .collect();
    ips.sort_by_key(|i| !i.is_ipv4()); // IPv4 first
    ips.dedup();
    Ok(ips)
}

// ---------------------------------------------------------------- sysctl

fn sysctl_read(key: &str) -> Option<String> {
    fs::read_to_string(format!("/proc/sys/{}", key.replace('.', "/"))).ok().map(|s| s.trim().to_string())
}
fn sysctl_write(key: &str, v: &str) -> bool {
    fs::write(format!("/proc/sys/{}", key.replace('.', "/")), v).is_ok()
}

/// Returns (log messages, values to restore on disconnect).
pub fn tune_sysctl() -> (Vec<String>, Vec<(String, String)>) {
    let mut log = vec![];
    let mut restore = vec![];
    // QUIC needs big UDP buffers; the Linux default (~208 KiB) caps speed.
    const BUF: u64 = 16 * 1024 * 1024;
    for key in ["net.core.rmem_max", "net.core.wmem_max"] {
        if let Some(cur) = sysctl_read(key).and_then(|v| v.parse::<u64>().ok()) {
            if cur < BUF && sysctl_write(key, &BUF.to_string()) {
                log.push(format!("{key}: {cur} → {BUF} (faster QUIC)"));
            }
        }
    }
    // Hysteria docs: TUN on Linux may need loose reverse-path filtering.
    for key in ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"] {
        if let Some(cur) = sysctl_read(key) {
            if cur != "2" && sysctl_write(key, "2") {
                restore.push((key.to_string(), cur));
            }
        }
    }
    (log, restore)
}

pub fn restore_sysctl(vals: &[(String, String)]) {
    for (k, v) in vals {
        sysctl_write(k, v);
    }
}

// ---------------------------------------------------------------- DNS

const RESOLV: &str = "/etc/resolv.conf";
const STATE_DIR: &str = "/var/lib/hy2tui";
const MARK: &str = "# hy2tui: temporary, restored on disconnect";

fn bak_file() -> std::path::PathBuf { Path::new(STATE_DIR).join("resolv.conf.bak") }
fn link_file() -> std::path::PathBuf { Path::new(STATE_DIR).join("resolv.conf.link") }

/// Points /etc/resolv.conf at DNS servers reached through the tunnel.
/// The original file (or symlink) is saved in /var/lib/hy2tui and put back
/// on drop — and on the next start if hy2tui was killed.
pub struct DnsGuard {
    content: String,
    active: bool,
}

impl DnsGuard {
    pub fn apply(servers: &[String]) -> Result<Self> {
        fs::create_dir_all(STATE_DIR)?;
        if !bak_file().exists() && !link_file().exists() {
            let meta = fs::symlink_metadata(RESOLV);
            match meta {
                Ok(m) if m.file_type().is_symlink() => {
                    let target = fs::read_link(RESOLV)?;
                    fs::write(link_file(), target.as_os_str().as_encoded_bytes())?;
                }
                Ok(_) => {
                    fs::copy(RESOLV, bak_file())?;
                }
                Err(_) => {
                    fs::write(bak_file(), "")?;
                }
            }
        }
        let mut content = format!("{MARK}\n");
        for s in servers {
            content.push_str(&format!("nameserver {s}\n"));
        }
        content.push_str("options timeout:2 attempts:2\n");
        let g = DnsGuard { content, active: true };
        g.write()?;
        Ok(g)
    }

    fn write(&self) -> Result<()> {
        if fs::symlink_metadata(RESOLV).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            fs::remove_file(RESOLV)?;
        }
        let tmp = format!("{RESOLV}.hy2tui");
        fs::write(&tmp, &self.content)?;
        fs::rename(&tmp, RESOLV)?;
        Ok(())
    }

    /// NetworkManager/dhcpcd may rewrite resolv.conf; put ours back.
    pub fn ensure(&self) -> bool {
        if !self.active {
            return false;
        }
        let cur = fs::read_to_string(RESOLV).unwrap_or_default();
        if cur != self.content {
            return self.write().is_ok();
        }
        false
    }

    pub fn restore(&mut self) {
        if self.active {
            let _ = restore_dns_backup();
            self.active = false;
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Put the saved resolv.conf back if a backup exists. Returns true if restored.
pub fn restore_dns_backup() -> Result<bool> {
    if link_file().exists() {
        let target = fs::read_to_string(link_file())?;
        let _ = fs::remove_file(RESOLV);
        std::os::unix::fs::symlink(target.trim_end_matches('\n'), RESOLV)?;
        fs::remove_file(link_file())?;
        Ok(true)
    } else if bak_file().exists() {
        let data = fs::read(bak_file())?;
        let tmp = format!("{RESOLV}.hy2tui");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, RESOLV)?;
        fs::remove_file(bak_file())?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ---------------------------------------------------------------- probes

/// Open host:port directly, or through our SOCKS5 proxy when `via` is set
/// (proxy-only mode: the probe must go through the tunnel, not around it).
fn open(host: &str, port: u16, via: Option<SocketAddr>, timeout: Duration) -> Result<TcpStream> {
    match via {
        Some(px) => Ok(crate::mixed::socks5_connect(px, host, port, timeout)?),
        None => {
            let addr = (host, port).to_socket_addrs()?.find(|a| a.is_ipv4()).context("no IPv4 address")?;
            Ok(TcpStream::connect_timeout(&addr, timeout)?)
        }
    }
}

fn http_get(host: &str, path: &str, via: Option<SocketAddr>, timeout: Duration) -> Result<(Duration, String)> {
    let t0 = Instant::now();
    let mut s = open(host, 80, via, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: hy2tui\r\nConnection: close\r\n\r\n")?;
    let mut first = [0u8; 1];
    s.read_exact(&mut first)?;
    let ttfb = t0.elapsed();
    let mut rest = Vec::new();
    let _ = s.take(64 * 1024).read_to_end(&mut rest);
    let mut all = vec![first[0]];
    all.extend(rest);
    Ok((ttfb, String::from_utf8_lossy(&all).into_owned()))
}

/// Round-trip through the tunnel: time to first byte of an HTTP reply
/// from 1.1.1.1 (TCP connect alone would be answered locally by the TUN stack).
pub fn latency_ms(via: Option<SocketAddr>) -> Option<u64> {
    http_get("1.1.1.1", "/", via, Duration::from_secs(5)).ok().map(|(d, _)| d.as_millis() as u64)
}

/// Exit IP + location as seen by the internet.
pub fn public_ip(via: Option<SocketAddr>) -> Option<String> {
    let (_, resp) = http_get("ip-api.com", "/json/?fields=query,country,city", via, Duration::from_secs(8)).ok()?;
    let (_, body) = resp.split_once("\r\n\r\n")?;
    let v: serde_json::Value = serde_json::from_str(&body[body.find('{')?..=body.rfind('}')?]).ok()?;
    let g = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let (ip, country, city) = (g("query"), g("country"), g("city"));
    if ip.is_empty() {
        return None;
    }
    Some(match (country.is_empty(), city.is_empty()) {
        (true, _) => ip.to_string(),
        (false, true) => format!("{ip}  {country}"),
        _ => format!("{ip}  {country}, {city}"),
    })
}

// ---------------------------------------------------------------- process stats

pub struct ProcSample {
    pub cpu_ticks: u64,
    pub rss_kb: u64,
}

pub fn proc_sample(pid: u32) -> Option<ProcSample> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = after.split_whitespace().collect();
    // fields after ")" start at index 3 (state); utime=14, stime=15 → idx 11, 12
    let cpu_ticks = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0);
    Some(ProcSample { cpu_ticks, rss_kb })
}

pub fn clk_tck() -> f64 {
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as f64 } else { 100.0 }
}

// ---------------------------------------------------------------- clipboard

/// Read the system clipboard (Wayland, then X11). Under `sudo -E` the
/// user's WAYLAND_DISPLAY / DISPLAY are kept, so this works as root too.
pub fn read_clipboard() -> Option<String> {
    use std::process::{Command, Stdio};
    let mut tries: Vec<(&str, Vec<&str>)> = vec![];
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        tries.push(("wl-paste", vec!["--no-newline"]));
    }
    if std::env::var_os("DISPLAY").is_some() {
        tries.push(("xclip", vec!["-selection", "clipboard", "-o"]));
        tries.push(("xsel", vec!["-b", "-o"]));
    }
    for (cmd, args) in tries {
        if let Ok(o) = Command::new(cmd).args(&args).stdin(Stdio::null()).stderr(Stdio::null()).output() {
            if o.status.success() && !o.stdout.is_empty() {
                return Some(String::from_utf8_lossy(&o.stdout).into_owned());
            }
        }
    }
    None
}

// ---------------------------------------------------------------- TUN preflight

/// Other VPN cores that also take over routing in TUN mode. Two of them at
/// once share the same routing table (2022) and break each other.
const CORES: &[&str] = &["hysteria", "sing-box", "nekobox_core", "nekoray_core", "xray", "v2ray"];

/// Running VPN cores (pid, name), except `except_pid`.
pub fn running_cores(except_pid: Option<u32>) -> Vec<(u32, String)> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        if Some(pid) == except_pid {
            continue;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        let comm = comm.trim();
        if CORES.contains(&comm) {
            out.push((pid, comm.to_string()));
        }
    }
    out
}

fn ip(args: &[&str]) -> Option<String> {
    let o = std::process::Command::new("ip").args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Describe the first running VPN core, if any.
pub fn other_core() -> Option<String> {
    running_cores(None).first().map(|(pid, name)| {
        let who = match name.as_str() {
            "hysteria" => "another hysteria core (hy2tui or CyberVPN?)",
            "sing-box" | "nekobox_core" | "nekoray_core" => "nekoray / sing-box",
            _ => "another VPN core",
        };
        format!("{who} is running (pid {pid})")
    })
}

/// Remove TUN devices and policy-routing leftovers (sing-tun uses table 2022).
fn cleanup_routes(tuns: &[&str], log: &mut Vec<String>) {
    let n = crate::split::Bypass::cleanup_all();
    if n > 0 {
        log.push(format!("removed {n} leftover notToVPN rules"));
    }
    for t in tuns {
        if std::path::Path::new("/sys/class/net").join(t).exists() {
            log.push(format!("removed leftover TUN device {t}"));
            let _ = ip(&["link", "delete", t]);
        }
    }
    for fam in ["-4", "-6"] {
        if let Some(rules) = ip(&[fam, "rule", "show"]) {
            for line in rules.lines().filter(|l| l.contains("lookup 2022") || l.contains("table 2022")) {
                if let Some(pref) = line.split(':').next().map(str::trim) {
                    if ip(&[fam, "rule", "del", "pref", pref]).is_some() {
                        log.push(format!("removed leftover ip {fam} rule {pref}"));
                    }
                }
            }
        }
        let _ = ip(&[fam, "route", "flush", "table", "2022"]);
    }
}

/// DNS backups of CyberVPN and hy2tui. The other app's first: its backup may
/// hold our temporary file, ours holds the real original — so it wins last.
const DNS_STATE: [&str; 2] = ["/var/lib/cybervpn", "/var/lib/hy2tui"];
const DNS_MARKS: [&str; 2] = ["# hy2tui:", "# CyberVPN:"];

fn reset_dns(log: &mut Vec<String>) {
    let dirs: Vec<&Path> = DNS_STATE.iter().map(Path::new).collect();
    reset_dns_in(Path::new(RESOLV), &dirs, log);
}

fn reset_dns_in(resolv: &Path, dirs: &[&Path], log: &mut Vec<String>) {
    let tmp = resolv.with_extension("hy2tui-tmp");
    for dir in dirs {
        let link = dir.join("resolv.conf.link");
        let bak = dir.join("resolv.conf.bak");
        if let Ok(target) = fs::read_to_string(&link) {
            let _ = fs::remove_file(resolv);
            if std::os::unix::fs::symlink(target.trim_end_matches('\n'), resolv).is_ok() {
                log.push(format!("DNS restored from {} (symlink → {})", dir.display(), target.trim()));
            }
            let _ = fs::remove_file(&link);
        }
        if let Ok(data) = fs::read_to_string(&bak) {
            if DNS_MARKS.iter().any(|m| data.starts_with(m)) {
                // a VPN's temporary file, not the user's original
            } else {
                if fs::write(&tmp, &data).is_ok() && fs::rename(&tmp, resolv).is_ok() {
                    log.push(format!("DNS restored from {}", dir.display()));
                }
            }
            let _ = fs::remove_file(&bak);
        }
    }
    // still pointing at a VPN's DNS forwarder that is not running?
    let cur = fs::read_to_string(resolv).unwrap_or_default();
    if DNS_MARKS.iter().any(|m| cur.starts_with(m)) {
        let text = "# reset by hy2tui (the original was not found)\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        if fs::write(&tmp, text).is_ok() && fs::rename(&tmp, resolv).is_ok() {
            log.push("DNS was left pointing at a stopped VPN — set to 1.1.1.1 / 8.8.8.8".into());
        }
    }
}

/// Bring networking back to normal after crashes or another VPN app
/// (CyberVPN) that was closed: DNS, TUN devices, policy routes.
/// Does nothing while any VPN core is running. Needs root.
pub fn network_reset(own_tun: &str) -> Vec<String> {
    let mut log = vec![];
    if let Some(who) = other_core() {
        log.push(format!("network reset skipped: {who}"));
        return log;
    }
    reset_dns(&mut log);
    cleanup_routes(&[own_tun, "hytun", "cybervpn"], &mut log);
    log
}

/// Before starting TUN mode: refuse if another core owns the routes, and
/// clean up what a crashed session (or a closed CyberVPN) left behind.
pub fn tun_preflight(own_tun: &str, other_tuns: &[&str]) -> anyhow::Result<Vec<String>> {
    if let Some(who) = other_core() {
        anyhow::bail!("{who}. Two TUN VPNs at once break each other's routes — turn it off first (or use proxy-only mode)");
    }
    let mut log = vec![];
    let mut tuns = vec![own_tun];
    tuns.extend_from_slice(other_tuns);
    cleanup_routes(&tuns, &mut log);
    Ok(log)
}

#[cfg(test)]
mod reset_tests {
    use super::*;

    /// hy2tui on → CyberVPN on (backs up hy2tui's temporary file) → both
    /// killed. The reset must end with the user's real original.
    #[test]
    fn dns_reset_after_hy2tui_and_cybervpn() {
        let d = std::env::temp_dir().join(format!("hy2-reset-{}", std::process::id()));
        let (cv, hy) = (d.join("cybervpn"), d.join("hy2tui"));
        fs::create_dir_all(&cv).unwrap();
        fs::create_dir_all(&hy).unwrap();
        let resolv = d.join("resolv.conf");
        fs::write(&resolv, "# CyberVPN: temporary\nnameserver 127.0.53.53\n").unwrap();
        fs::write(cv.join("resolv.conf.bak"), "# hy2tui: temporary\nnameserver 127.0.53.53\n").unwrap();
        fs::write(hy.join("resolv.conf.bak"), "nameserver 192.168.1.1\n").unwrap();
        let mut log = vec![];
        reset_dns_in(&resolv, &[&cv, &hy], &mut log);
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 192.168.1.1\n");
        assert!(!cv.join("resolv.conf.bak").exists() && !hy.join("resolv.conf.bak").exists());

        // no original anywhere, file still points at a dead forwarder → public DNS
        fs::write(&resolv, "# hy2tui: temporary\nnameserver 127.0.53.53\n").unwrap();
        reset_dns_in(&resolv, &[&cv, &hy], &mut log);
        assert!(fs::read_to_string(&resolv).unwrap().contains("nameserver 1.1.1.1"));

        // normal file, no backups → untouched
        fs::write(&resolv, "nameserver 10.0.0.1\n").unwrap();
        let mut log2 = vec![];
        reset_dns_in(&resolv, &[&cv, &hy], &mut log2);
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 10.0.0.1\n");
        assert!(log2.is_empty());
        let _ = fs::remove_dir_all(d);
    }
}
