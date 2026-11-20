//! Live connection table built from the core's TUN events, enriched with
//! domain names (from our DNS forwarder) and the app that opened them.

use crate::core::{now_hms, LogLine};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::time::Instant;

const MAX_CONNS: usize = 3000;
const MAX_DNS_MAP: usize = 50_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Proto { Tcp, Udp }

#[derive(Clone)]
pub struct Conn {
    pub proto: Proto,
    /// "tun", "socks" or "http"
    pub via: &'static str,
    pub src: String,
    pub dst: Option<String>,
    pub domain: Option<String>,
    pub app: Option<String>,
    pub app_tried: bool,
    pub time: String,
    pub opened: Instant,
    pub closed: Option<Instant>,
    pub error: Option<String>,
}

impl Conn {
    pub fn is_open(&self) -> bool { self.closed.is_none() }
}

#[derive(Default)]
pub struct Traffic {
    pub conns: VecDeque<Conn>,
    pub total_tcp: u64,
    pub total_udp: u64,
    pub errors: u64,
    ip_names: HashMap<IpAddr, String>,
    ip_order: VecDeque<IpAddr>,
    /// domain → number of connections
    pub domain_hits: HashMap<String, u64>,
    /// new connections per sample (for the "conn/s" graph)
    pub new_since_sample: u64,
}

fn host_of(addr: &str) -> Option<IpAddr> {
    let h = addr.rsplit_once(':')?.0.trim_start_matches('[').trim_end_matches(']');
    h.parse().ok()
}

/// Host part of "host:port" or of a URL, when it is a name (not an IP).
fn name_of(addr: &str) -> Option<String> {
    let a = addr.split("://").last().unwrap_or(addr);
    let hostport = a.split('/').next().unwrap_or(a);
    let host = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => hostport,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty() && host.parse::<IpAddr>().is_err()).then(|| host.to_string())
}

fn field<'a>(fields: &'a str, key: &str) -> Option<&'a str> {
    fields.split(' ').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

impl Traffic {
    pub fn learn_dns(&mut self, name: &str, ips: &[IpAddr]) {
        for ip in ips {
            if self.ip_names.insert(*ip, name.to_string()).is_none() {
                self.ip_order.push_back(*ip);
                if self.ip_order.len() > MAX_DNS_MAP {
                    if let Some(old) = self.ip_order.pop_front() {
                        self.ip_names.remove(&old);
                    }
                }
            }
        }
        // late DNS answer: name connections that are still unnamed
        for c in self.conns.iter_mut().rev().take(200) {
            if c.domain.is_none() {
                if let Some(ip) = c.dst.as_deref().and_then(host_of) {
                    if ips.contains(&ip) {
                        c.domain = Some(name.to_string());
                    }
                }
            }
        }
    }

    /// Feed a core log line. Returns true if it was a TUN connection event
    /// (those go to the connections tab, not to the main log).
    pub fn on_log(&mut self, l: &LogLine) -> bool {
        let f = l.fields.as_str();
        match l.msg.as_str() {
            "TUN TCP request" | "SOCKS5 TCP request" | "HTTP CONNECT request" | "HTTP request" => {
                let via = via_of(&l.msg);
                let dst = field(f, "reqAddr").or_else(|| field(f, "reqURL")).map(str::to_string);
                let domain = dst.as_deref().and_then(name_of).or_else(|| {
                    dst.as_deref().and_then(host_of).and_then(|ip| self.ip_names.get(&ip).cloned())
                });
                let key = domain.clone().or_else(|| dst.as_deref().and_then(host_of).map(|ip| ip.to_string()));
                if let Some(k) = key {
                    *self.domain_hits.entry(k).or_default() += 1;
                }
                self.push(Conn {
                    proto: Proto::Tcp, via,
                    src: field(f, "addr").unwrap_or("").to_string(),
                    dst, domain, app: None, app_tried: false,
                    time: now_hms(), opened: Instant::now(), closed: None, error: None,
                });
                self.total_tcp += 1;
                true
            }
            "TUN UDP request" | "SOCKS5 UDP request" => {
                self.push(Conn {
                    proto: Proto::Udp, via: via_of(&l.msg),
                    src: field(f, "addr").unwrap_or("").to_string(),
                    dst: None, domain: None, app: None, app_tried: false,
                    time: now_hms(), opened: Instant::now(), closed: None, error: None,
                });
                self.total_udp += 1;
                true
            }
            "TUN TCP closed" | "TUN TCP error" | "TUN UDP closed" | "TUN UDP error"
            | "SOCKS5 TCP closed" | "SOCKS5 TCP error" | "SOCKS5 UDP closed" | "SOCKS5 UDP error"
            | "HTTP CONNECT closed" | "HTTP CONNECT error" | "HTTP closed" | "HTTP error" => {
                let proto = if l.msg.contains("UDP") { Proto::Udp } else { Proto::Tcp };
                let via = via_of(&l.msg);
                let src = field(f, "addr").unwrap_or("");
                let err = l.msg.ends_with("error").then(|| field(f, "error").unwrap_or("error").to_string());
                if err.is_some() {
                    self.errors += 1;
                }
                if let Some(c) = self.conns.iter_mut().rev().find(|c| c.proto == proto && c.via == via && c.is_open() && c.src == src) {
                    c.closed = Some(Instant::now());
                    c.error = err;
                }
                true
            }
            m if m.starts_with("TUN ") || m.starts_with("SOCKS5 ") || m.starts_with("HTTP ") => true,
            _ => false,
        }
    }

    fn push(&mut self, c: Conn) {
        self.new_since_sample += 1;
        self.conns.push_back(c);
        while self.conns.len() > MAX_CONNS {
            // drop the oldest closed one first
            if let Some(i) = self.conns.iter().position(|c| !c.is_open()) {
                self.conns.remove(i);
            } else {
                self.conns.pop_front();
            }
        }
    }

    pub fn open_count(&self) -> (usize, usize) {
        self.conns.iter().filter(|c| c.is_open()).fold((0, 0), |(t, u), c| match c.proto {
            Proto::Tcp => (t + 1, u),
            Proto::Udp => (t, u + 1),
        })
    }

    pub fn top_domains(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.domain_hits.iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Source ports of open connections whose app is not known yet.
    pub fn pending_app_ports(&mut self) -> Vec<u16> {
        let mut out = vec![];
        for c in self.conns.iter_mut().rev().take(300) {
            if !c.app_tried && c.is_open() {
                c.app_tried = true;
                if let Some(p) = c.src.rsplit_once(':').and_then(|(_, p)| p.parse().ok()) {
                    out.push(p);
                }
            }
        }
        out
    }

    pub fn set_apps(&mut self, apps: &HashMap<u16, String>) {
        for c in self.conns.iter_mut().rev().take(300) {
            if c.app.is_none() {
                if let Some(p) = c.src.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()) {
                    if let Some(a) = apps.get(&p) {
                        c.app = Some(a.clone());
                    }
                }
            }
        }
    }
}

fn via_of(msg: &str) -> &'static str {
    if msg.starts_with("SOCKS5") { "socks" } else if msg.starts_with("HTTP") { "http" } else { "tun" }
}

// ---------------------------------------------------------------- apps

/// Map local ports → process name (like `ss -p`): /proc/net/{tcp,udp}
/// gives socket inodes, /proc/<pid>/fd tells which process owns them.
pub fn apps_for_ports(ports: &[u16]) -> HashMap<u16, String> {
    let mut inode_port: HashMap<u64, u16> = HashMap::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"] {
        let Ok(s) = fs::read_to_string(f) else { continue };
        for line in s.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            let Some(port) = cols[1].rsplit_once(':').and_then(|(_, p)| u16::from_str_radix(p, 16).ok()) else { continue };
            if ports.contains(&port) {
                if let Ok(inode) = cols[9].parse::<u64>() {
                    if inode != 0 {
                        inode_port.insert(inode, port);
                    }
                }
            }
        }
    }
    let mut out = HashMap::new();
    if inode_port.is_empty() {
        return out;
    }
    let Ok(procs) = fs::read_dir("/proc") else { return out };
    for p in procs.flatten() {
        let name = p.file_name();
        let Some(pid) = name.to_str().filter(|s| s.bytes().all(|b| b.is_ascii_digit())) else { continue };
        let Ok(fds) = fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else { continue };
            let l = link.to_string_lossy();
            if let Some(ino) = l.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')).and_then(|x| x.parse::<u64>().ok()) {
                if let Some(port) = inode_port.get(&ino) {
                    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string();
                    out.insert(*port, comm);
                }
            }
        }
        if out.len() == inode_port.len() {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------- packets

#[derive(Default, Clone, Copy)]
pub struct IfStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub errors: u64,
    pub dropped: u64,
}

pub fn if_stats(name: &str) -> Option<IfStats> {
    let base = std::path::Path::new("/sys/class/net").join(name).join("statistics");
    let rd = |f: &str| fs::read_to_string(base.join(f)).ok()?.trim().parse::<u64>().ok();
    Some(IfStats {
        rx_bytes: rd("rx_bytes")?,
        tx_bytes: rd("tx_bytes")?,
        rx_packets: rd("rx_packets")?,
        tx_packets: rd("tx_packets")?,
        errors: rd("rx_errors").unwrap_or(0) + rd("tx_errors").unwrap_or(0),
        dropped: rd("rx_dropped").unwrap_or(0) + rd("tx_dropped").unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::parse_log;

    #[test]
    fn tracks_connections_with_domains() {
        let mut t = Traffic::default();
        t.learn_dns("github.com", &["140.82.121.4".parse().unwrap()]);
        let ev = parse_log(r#"{"level":"debug","msg":"TUN TCP request","addr":"100.100.100.101:40000","reqAddr":"140.82.121.4:443"}"#);
        assert!(t.on_log(&ev));
        assert_eq!(t.conns[0].domain.as_deref(), Some("github.com"));
        assert_eq!(t.open_count(), (1, 0));
        let ev = parse_log(r#"{"level":"debug","msg":"TUN TCP closed","addr":"100.100.100.101:40000","reqAddr":"140.82.121.4:443"}"#);
        assert!(t.on_log(&ev));
        assert_eq!(t.open_count(), (0, 0));
        assert_eq!(t.top_domains(5)[0], ("github.com".to_string(), 1));
        assert!(!t.on_log(&parse_log(r#"{"level":"info","msg":"connected to server"}"#)));
        // browser through the proxy: domain comes straight from reqAddr / reqURL
        t.on_log(&parse_log(r#"{"level":"debug","msg":"SOCKS5 TCP request","addr":"127.0.0.1:5000","reqAddr":"www.youtube.com:443"}"#));
        t.on_log(&parse_log(r#"{"level":"debug","msg":"HTTP request","addr":"127.0.0.1:5001","reqURL":"http://example.org/index.html"}"#));
        let c: Vec<_> = t.conns.iter().rev().take(2).collect();
        assert_eq!((c[0].via, c[0].domain.as_deref()), ("http", Some("example.org")));
        assert_eq!((c[1].via, c[1].domain.as_deref()), ("socks", Some("www.youtube.com")));
        t.on_log(&parse_log(r#"{"level":"debug","msg":"SOCKS5 TCP closed","addr":"127.0.0.1:5000","reqAddr":"www.youtube.com:443"}"#));
        assert_eq!(t.open_count(), (1, 0));
    }

    #[test]
    fn finds_app_by_port() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let port = c.local_addr().unwrap().port();
        let apps = apps_for_ports(&[port]);
        let me = fs::read_to_string("/proc/self/comm").unwrap().trim().to_string();
        assert_eq!(apps.get(&port), Some(&me));
    }
}
