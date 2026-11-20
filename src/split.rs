//! notToVPN — split tunneling by domain, for TUN mode.
//!
//! The TUN core can only exclude IP ranges, so this works at the DNS level:
//! our DNS forwarder resolves names from the list *directly* (outside the
//! tunnel), and before answering the app it adds a policy rule
//! `ip rule add to <ip> lookup main pref 8765`. That rule is checked before
//! the TUN rules (9000+), so traffic to those IPs goes straight out.
//! Everything else — including all other DNS — stays in the tunnel.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

/// Rule priority used for bypass rules (before sing-tun's 9000+).
pub const PREF: &str = "8765";

/// Zones offered as presets in the UI (label, zone).
#[allow(dead_code)]
pub const PRESETS: &[(&str, &str)] = &[
    (".ru", "ru"), (".рф", "рф"), (".su", "su"), (".by", "by"), (".kz", "kz"),
    (".ua", "ua"), (".uz", "uz"), (".am", "am"), (".ge", "ge"), (".md", "md"),
];

pub struct Bypass {
    patterns: Vec<String>,
    pub direct_dns: Vec<SocketAddr>,
    added: Mutex<HashSet<IpAddr>>,
}

/// "*.Example.RU." / ".рф" / "https://x.ru/path" → "example.ru" / "xn--p1ai"
pub fn normalize(d: &str) -> Option<String> {
    let d = d.trim().trim_start_matches("https://").trim_start_matches("http://");
    let d = d.split('/').next().unwrap_or("").trim_start_matches("*.").trim_matches('.').to_lowercase();
    if d.is_empty() {
        return None;
    }
    idna::domain_to_ascii(&d).ok().filter(|x| !x.is_empty())
}

fn ip(args: &[&str]) -> bool {
    std::process::Command::new("ip").args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

impl Bypass {
    pub fn new(domains: &[String], direct_dns: &[String]) -> Self {
        let mut patterns: Vec<String> = domains.iter().filter_map(|d| normalize(d)).collect();
        patterns.sort();
        patterns.dedup();
        let direct_dns = direct_dns.iter().filter_map(|s| s.trim().parse::<IpAddr>().ok()).map(|ip| SocketAddr::new(ip, 53)).collect();
        Bypass { patterns, direct_dns, added: Mutex::new(HashSet::new()) }
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// name is a listed domain, or inside a listed zone.
    pub fn matches(&self, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_lowercase();
        let n = idna::domain_to_ascii(&n).unwrap_or(n);
        self.patterns.iter().any(|p| n == *p || (n.len() > p.len() && n.ends_with(p.as_str()) && n.as_bytes()[n.len() - p.len() - 1] == b'.'))
    }

    /// Route these IPs outside the tunnel. Returns the newly added ones.
    pub fn add_ips(&self, ips: &[IpAddr]) -> Vec<IpAddr> {
        let mut out = vec![];
        let mut set = self.added.lock().unwrap();
        for a in ips {
            if a.is_loopback() || a.is_unspecified() || !set.insert(*a) {
                continue;
            }
            let (fam, cidr) = match a {
                IpAddr::V4(v) => ("-4", format!("{v}/32")),
                IpAddr::V6(v) => ("-6", format!("{v}/128")),
            };
            if ip(&[fam, "rule", "add", "to", &cidr, "lookup", "main", "pref", PREF]) {
                out.push(*a);
            } else {
                set.remove(a);
            }
        }
        out
    }

    pub fn count(&self) -> usize {
        self.added.lock().unwrap().len()
    }

    /// Remove every bypass rule (also leftovers of a crashed session).
    pub fn cleanup_all() -> usize {
        let mut n = 0;
        for fam in ["-4", "-6"] {
            // each `del pref` removes one rule; loop until none is left
            for _ in 0..100_000 {
                if !ip(&[fam, "rule", "del", "pref", PREF]) {
                    break;
                }
                n += 1;
            }
        }
        n
    }
}

impl Drop for Bypass {
    fn drop(&mut self) {
        Self::cleanup_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_and_domain_matching() {
        let b = Bypass::new(&["ru".into(), ".рф".into(), "*.Example.COM".into(), "https://vk.com/feed".into()], &["77.88.8.8".into()]);
        assert!(b.matches("yandex.ru"));
        assert!(b.matches("mail.yandex.ru."));
        assert!(b.matches("ru"));
        assert!(!b.matches("guru"));          // not the .ru zone
        assert!(!b.matches("ru.example.org"));
        assert!(b.matches("госуслуги.рф"));   // IDN → punycode
        assert!(b.matches("xn--p1ai"));
        assert!(b.matches("www.example.com"));
        assert!(b.matches("vk.com"));
        assert!(!b.matches("notvk.com"));
        assert_eq!(b.direct_dns.len(), 1);
        std::mem::forget(b); // don't touch real ip rules in tests
    }

    /// Real `ip rule` round trip (needs root): cargo test -- --ignored split
    #[test]
    #[ignore]
    fn real_rules_roundtrip() {
        let show = || String::from_utf8_lossy(&std::process::Command::new("ip").args(["rule", "show"]).output().unwrap().stdout).into_owned();
        let b = Bypass::new(&["ru".into()], &[]);
        let added = b.add_ips(&["203.0.113.99".parse().unwrap(), "203.0.113.99".parse().unwrap()]);
        assert_eq!(added.len(), 1, "duplicates are added once");
        let rules = show();
        println!("{rules}");
        assert!(rules.contains("8765:") && rules.contains("203.0.113.99"));
        drop(b); // Drop removes them
        assert!(!show().contains("203.0.113.99"));
    }
}
