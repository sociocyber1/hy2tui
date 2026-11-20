//! Profiles + settings, stored in ~/.config/hy2tui/config.toml (mode 600).
//! When run through sudo, files go to the *real* user's home and are chowned back.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub uri: String,
    /// Brutal congestion control: set to your real line speed (Mbit/s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Full-system VPN through a TUN device (needs root).
    pub tun: bool,
    /// Local mixed SOCKS5+HTTP proxy for browsers, e.g. "127.0.0.1:2080".
    /// Empty = off. Works without root.
    pub proxy: String,
    /// Replace /etc/resolv.conf with these servers while connected
    /// (queries then go through the tunnel — no ISP DNS poisoning / leaks).
    pub override_dns: bool,
    pub dns: Vec<String>,
    /// Keep LAN / private ranges outside the tunnel.
    pub bypass_lan: bool,
    pub tun_name: String,
    pub mtu: u32,
    /// Raise UDP socket buffers (QUIC speed) and relax rp_filter for TUN.
    pub tune_sysctl: bool,
    /// Hysteria fastOpen: saves one round-trip per new connection.
    pub fast_open: bool,
    pub auto_reconnect: bool,
    /// Extra CIDRs that must NOT go through the VPN.
    pub exclude: Vec<String>,
    /// notToVPN: domains/zones that bypass the tunnel (TUN mode). Off by default.
    pub not_to_vpn: bool,
    /// e.g. "ru", "рф", "kz" (whole zones) or "gosuslugi.ru" (one domain)
    pub not_to_vpn_domains: Vec<String>,
    /// DNS used for notToVPN names (reached outside the tunnel)
    pub direct_dns: Vec<String>,
    /// Path to the hysteria core; empty = auto.
    pub core_path: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            tun: true,
            proxy: "127.0.0.1:2080".into(),
            override_dns: true,
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            bypass_lan: true,
            tun_name: "hytun".into(),
            mtu: 1500,
            tune_sysctl: true,
            fast_open: true,
            auto_reconnect: true,
            exclude: vec![],
            not_to_vpn: false,
            not_to_vpn_domains: ["ru", "рф", "su", "by", "kz", "ua"].iter().map(|s| s.to_string()).collect(),
            direct_dns: vec!["77.88.8.8".into(), "77.88.8.1".into()],
            core_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Store {
    pub last_used: Option<usize>,
    pub settings: Settings,
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    /// uid/gid to chown created files to (when running via sudo)
    pub owner: Option<(u32, u32)>,
}

fn home_of(user: &str) -> Option<PathBuf> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[0] == user).then(|| PathBuf::from(f[5]))
    })
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

impl Paths {
    pub fn detect() -> Self {
        let sudo_user = std::env::var("SUDO_USER").ok().filter(|u| u != "root");
        let home = sudo_user
            .as_deref()
            .and_then(home_of)
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/root"));
        let owner = if is_root() && sudo_user.is_some() {
            let uid = std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
            let gid = std::env::var("SUDO_GID").ok().and_then(|v| v.parse().ok());
            uid.zip(gid)
        } else {
            None
        };
        let config_dir = home.join(".config/hy2tui");
        Paths {
            config_file: config_dir.join("config.toml"),
            config_dir,
            data_dir: home.join(".local/share/hy2tui"),
            owner,
        }
    }

    pub fn give_back(&self, p: &Path) {
        if let Some((u, g)) = self.owner {
            let _ = std::os::unix::fs::chown(p, Some(u), Some(g));
        }
    }

    /// mkdir -p, chowning every directory we create.
    pub fn mkdir(&self, dir: &Path, mode: u32) -> Result<()> {
        let mut missing = vec![];
        let mut d = dir.to_path_buf();
        while !d.exists() {
            missing.push(d.clone());
            if !d.pop() {
                break;
            }
        }
        for m in missing.iter().rev() {
            fs::create_dir(m).with_context(|| format!("mkdir {}", m.display()))?;
            let _ = fs::set_permissions(m, fs::Permissions::from_mode(mode));
            self.give_back(m);
        }
        Ok(())
    }
}

impl Store {
    pub fn load(paths: &Paths) -> Result<Self> {
        match fs::read_to_string(&paths.config_file) {
            Ok(s) => toml::from_str(&s)
                .with_context(|| format!("cannot parse {}", paths.config_file.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        paths.mkdir(&paths.config_dir, 0o700)?;
        let tmp = paths.config_file.with_extension("toml.tmp");
        let text = format!(
            "# hy2tui config. Edit while hy2tui is closed.\n# Settings are documented in README.md\n\n{}",
            toml::to_string_pretty(self)?
        );
        {
            let mut f = fs::File::create(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        paths.give_back(&tmp);
        fs::rename(&tmp, &paths.config_file)?;
        Ok(())
    }

    /// Add parsed links; returns (added, errors).
    pub fn add_from_text(&mut self, text: &str) -> (Vec<String>, Vec<String>) {
        let mut ok = vec![];
        let mut bad = vec![];
        for r in crate::uri::extract_all(text) {
            match r {
                Ok(u) => {
                    let raw = text
                        .split_whitespace()
                        .find(|t| crate::uri::Hy2Uri::parse(t).ok().as_ref() == Some(&u))
                        .unwrap_or_default()
                        .to_string();
                    if let Some(p) = self.profiles.iter_mut().find(|p| p.uri == raw) {
                        p.name = u.name.clone(); // duplicate: just refresh name
                        ok.push(format!("{} (already existed)", u.name));
                    } else {
                        self.profiles.push(Profile { name: u.name.clone(), uri: raw, up_mbps: None, down_mbps: None });
                        ok.push(u.name);
                    }
                }
                Err((_, e)) => bad.push(e),
            }
        }
        (ok, bad)
    }
}
