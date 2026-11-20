//! Parser for `hysteria2://` / `hy2://` share links.
//! Format: hysteria2://[auth@]host[:ports]/?key=value&...#name

use anyhow::{bail, Context, Result};
use percent_encoding::percent_decode_str;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hy2Uri {
    pub auth: String,
    pub host: String,
    /// "443", "45765", or port-hopping form like "123,5000-6000"
    pub ports: String,
    pub obfs: Option<String>,
    pub obfs_password: Option<String>,
    pub sni: Option<String>,
    pub insecure: bool,
    pub pin_sha256: Option<String>,
    pub name: String,
}

fn dec(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

impl Hy2Uri {
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        let lower = s.to_ascii_lowercase();
        let rest = if lower.starts_with("hysteria2://") {
            &s["hysteria2://".len()..]
        } else if lower.starts_with("hy2://") {
            &s["hy2://".len()..]
        } else {
            bail!("not a hysteria2:// or hy2:// link");
        };

        let (rest, frag) = match rest.split_once('#') {
            Some((a, b)) => (a, Some(dec(b))),
            None => (rest, None),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((a, b)) => (a, b),
            None => (rest, ""),
        };
        let authority = rest.split('/').next().unwrap_or("");
        if authority.is_empty() {
            bail!("missing server address");
        }
        let (auth, hostport) = match authority.rsplit_once('@') {
            Some((a, h)) => (dec(a), h),
            None => (String::new(), authority),
        };

        let (host, ports) = if let Some(h) = hostport.strip_prefix('[') {
            let (h6, after) = h.split_once(']').context("bad IPv6 address")?;
            let p = after.strip_prefix(':').unwrap_or("");
            (h6.to_string(), p.to_string())
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h.to_string(), p.to_string()),
                None => (hostport.to_string(), String::new()),
            }
        };
        if host.is_empty() {
            bail!("missing host");
        }
        let ports = if ports.is_empty() { "443".to_string() } else { ports };
        if !ports.chars().all(|c| c.is_ascii_digit() || c == ',' || c == '-') {
            bail!("bad port: {ports}");
        }

        let mut u = Hy2Uri {
            auth,
            name: frag.filter(|f| !f.trim().is_empty()).unwrap_or_else(|| host.clone()),
            host,
            ports,
            obfs: None,
            obfs_password: None,
            sni: None,
            insecure: false,
            pin_sha256: None,
        };
        for kv in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let v = dec(v);
            match k {
                "obfs" => u.obfs = Some(v).filter(|x| !x.is_empty() && x != "none"),
                "obfs-password" => u.obfs_password = Some(v),
                "sni" | "peer" => u.sni = Some(v).filter(|x| !x.is_empty()),
                "insecure" | "allowInsecure" => u.insecure = v == "1" || v == "true",
                "pinSHA256" => u.pin_sha256 = Some(v).filter(|x| !x.is_empty()),
                _ => {}
            }
        }
        Ok(u)
    }

    /// The server address with the given host (or IP) substituted.
    pub fn server_with(&self, host: &str) -> String {
        if host.contains(':') {
            format!("[{host}]:{}", self.ports)
        } else {
            format!("{host}:{}", self.ports)
        }
    }

    pub fn sni_or_host(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }
}

/// Find all hy2 links in a block of pasted text (one per line or space-separated).
pub fn extract_all(text: &str) -> Vec<Result<Hy2Uri, (String, String)>> {
    text.split_whitespace()
        .filter(|t| {
            let l = t.to_ascii_lowercase();
            l.starts_with("hy2://") || l.starts_with("hysteria2://")
        })
        .map(|t| Hy2Uri::parse(t).map_err(|e| (t.to_string(), e.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_link() {
        let u = Hy2Uri::parse(
            "hy2://secretpass@vpn.example.com:45765?obfs=salamander&obfs-password=obfspw&sni=vpn.example.com#my%20server%20(NL)",
        )
        .unwrap();
        assert_eq!(u.auth, "secretpass");
        assert_eq!(u.host, "vpn.example.com");
        assert_eq!(u.ports, "45765");
        assert_eq!(u.obfs.as_deref(), Some("salamander"));
        assert_eq!(u.obfs_password.as_deref(), Some("obfspw"));
        assert_eq!(u.sni.as_deref(), Some("vpn.example.com"));
        assert_eq!(u.name, "my server (NL)");
        assert!(!u.insecure);
    }

    #[test]
    fn defaults_and_hopping() {
        let u = Hy2Uri::parse("hysteria2://user:pa%40ss@1.2.3.4:123,5000-6000/?insecure=1").unwrap();
        assert_eq!(u.auth, "user:pa@ss");
        assert_eq!(u.ports, "123,5000-6000");
        assert!(u.insecure);
        assert_eq!(u.name, "1.2.3.4");
        let u = Hy2Uri::parse("hy2://pw@example.org").unwrap();
        assert_eq!(u.ports, "443");
        let u = Hy2Uri::parse("hy2://pw@[2001:db8::1]:8443?sni=x.org").unwrap();
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.server_with(&u.host), "[2001:db8::1]:8443");
    }

    #[test]
    fn rejects_garbage() {
        assert!(Hy2Uri::parse("vless://x@y:1").is_err());
        assert!(Hy2Uri::parse("hy2://pw@host:12a").is_err());
        let all = extract_all("junk\nhy2://a@b:1#x  hy2://c@d:2\n");
        assert_eq!(all.len(), 2);
    }
}
