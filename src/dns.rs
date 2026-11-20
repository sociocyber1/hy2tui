//! Tiny DNS forwarder on 127.0.53.53:53 (UDP + TCP).
//! Every query is forwarded to the configured upstream servers — through
//! the tunnel — and reported to the UI: domain, type, answers, time. The
//! answers give an IP → domain map, so connections can be shown by name.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const LISTEN_IP: &str = "127.0.53.53";

#[derive(Debug, Clone)]
pub struct DnsEvent {
    pub time: String,
    pub name: String,
    pub qtype: String,
    pub ips: Vec<IpAddr>,
    pub cname: Option<String>,
    pub ms: u64,
    pub status: String, // NOERROR / NXDOMAIN / TIMEOUT / …
    pub tcp: bool,
    /// resolved outside the tunnel (notToVPN list)
    pub direct: bool,
}

// ---------------------------------------------------------------- parsing

fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = vec![];
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

fn u16_at(m: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(p)?, *m.get(p + 1)?]))
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(), 28 => "AAAA".into(), 5 => "CNAME".into(), 15 => "MX".into(),
        16 => "TXT".into(), 33 => "SRV".into(), 65 => "HTTPS".into(), 64 => "SVCB".into(),
        12 => "PTR".into(), 2 => "NS".into(), 6 => "SOA".into(), x => format!("T{x}"),
    }
}

/// (name, qtype) of the first question.
pub fn parse_query(m: &[u8]) -> Option<(String, String)> {
    if m.len() < 12 || u16_at(m, 4)? == 0 {
        return None;
    }
    let (name, p) = read_name(m, 12)?;
    Some((name, qtype_name(u16_at(m, p)?)))
}

/// (rcode name, A/AAAA answers, first CNAME target)
pub fn parse_answer(m: &[u8]) -> Option<(String, Vec<IpAddr>, Option<String>)> {
    if m.len() < 12 {
        return None;
    }
    let rcode = match m[3] & 0x0F {
        0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 5 => "REFUSED", _ => "ERROR",
    }
    .to_string();
    let qd = u16_at(m, 4)?;
    let an = u16_at(m, 6)?;
    let mut p = 12;
    for _ in 0..qd {
        p = read_name(m, p)?.1 + 4;
    }
    let mut ips = vec![];
    let mut cname = None;
    for _ in 0..an {
        p = read_name(m, p)?.1;
        let t = u16_at(m, p)?;
        let rdlen = u16_at(m, p + 8)? as usize;
        let rd = p + 10;
        match (t, rdlen) {
            (1, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(m[rd], m[rd + 1], m[rd + 2], m[rd + 3]))),
            (28, 16) => {
                let b: [u8; 16] = m.get(rd..rd + 16)?.try_into().ok()?;
                ips.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
            (5, _) if cname.is_none() => cname = read_name(m, rd).map(|x| x.0),
            _ => {}
        }
        p = rd + rdlen;
    }
    Some((rcode, ips, cname))
}

// ---------------------------------------------------------------- server

pub struct DnsServer {
    stop: Arc<AtomicBool>,
    /// tunnel DNS servers, in priority order (hot-swappable)
    ups: Arc<std::sync::RwLock<Vec<SocketAddr>>>,
}

/// Well-known resolvers: name → IPs (for quick adding).
pub const PRESETS: &[(&str, &[&str])] = &[
    ("cloudflare", &["1.1.1.1", "1.0.0.1"]),
    ("google", &["8.8.8.8", "8.8.4.4"]),
    ("quad9", &["9.9.9.9", "149.112.112.112"]),
    ("adguard", &["94.140.14.14", "94.140.15.15"]),
    ("opendns", &["208.67.222.222", "208.67.220.220"]),
];

pub const DEFAULT_SERVERS: &[&str] = &["1.1.1.1", "8.8.8.8"];

/// Friendly name of a known resolver IP.
pub fn provider_of(ip: &str) -> &'static str {
    PRESETS.iter().find(|(_, ips)| ips.contains(&ip)).map(|(n, _)| *n).unwrap_or("")
}

/// A query for `name` (type A).
pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// Round-trip time of one DNS server (asks for example.com).
pub fn probe(server: &str) -> Option<u64> {
    let ip: IpAddr = server.parse().ok()?;
    let t0 = Instant::now();
    ask_udp(&build_query("example.com", 0x4242), &[SocketAddr::new(ip, 53)])?;
    Some(t0.elapsed().as_millis() as u64)
}

impl DnsServer {
    /// Replace the tunnel DNS servers while running (order = priority).
    pub fn set_upstreams(&self, servers: &[String]) {
        let v = upstreams(servers);
        if !v.is_empty() {
            *self.ups.write().unwrap() = v;
        }
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn upstreams(list: &[String]) -> Vec<SocketAddr> {
    list.iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

fn ask_udp(q: &[u8], ups: &[SocketAddr]) -> Option<Vec<u8>> {
    for up in ups {
        let bind = if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(s) = UdpSocket::bind(bind) else { continue };
        let _ = s.set_read_timeout(Some(Duration::from_millis(2500)));
        if s.connect(up).is_err() || s.send(q).is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = s.recv(&mut buf) {
            buf.truncate(n);
            return Some(buf);
        }
    }
    None
}

fn ask_tcp(q: &[u8], ups: &[SocketAddr]) -> Option<Vec<u8>> {
    for up in ups {
        let Ok(mut s) = TcpStream::connect_timeout(up, Duration::from_secs(3)) else { continue };
        let _ = s.set_read_timeout(Some(Duration::from_secs(4)));
        let mut out = (q.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(q);
        if s.write_all(&out).is_err() {
            continue;
        }
        let mut len = [0u8; 2];
        if s.read_exact(&mut len).is_err() {
            continue;
        }
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        if s.read_exact(&mut buf).is_ok() {
            return Some(buf);
        }
    }
    None
}

fn report(tx: &Sender<DnsEvent>, q: &[u8], ans: Option<&[u8]>, t0: Instant, tcp: bool, direct: bool) {
    let Some((name, qtype)) = parse_query(q) else { return };
    let (status, ips, cname) = match ans.and_then(parse_answer) {
        Some(a) => a,
        None => ("TIMEOUT".into(), vec![], None),
    };
    let _ = tx.send(DnsEvent {
        time: crate::core::now_hms(),
        name, qtype, ips, cname, status, tcp, direct,
        ms: t0.elapsed().as_millis() as u64,
    });
}

/// Resolve through the tunnel, or directly for notToVPN names (and route
/// the answer's IPs outside the tunnel before the app sees them).
fn resolve(q: &[u8], ups: &[SocketAddr], bypass: Option<&crate::split::Bypass>, tcp: bool) -> (Option<Vec<u8>>, bool) {
    let ask = |servers: &[SocketAddr]| if tcp { ask_tcp(q, servers).or_else(|| ask_udp(q, servers)) } else { ask_udp(q, servers).or_else(|| ask_tcp(q, servers)) };
    if let Some(b) = bypass {
        if let Some((name, _)) = parse_query(q) {
            if b.matches(&name) && !b.direct_dns.is_empty() {
                let ans = ask(&b.direct_dns);
                if let Some(a) = &ans {
                    if let Some((_, ips, _)) = parse_answer(a) {
                        b.add_ips(&ips);
                    }
                }
                return (ans, true);
            }
        }
    }
    (ask(ups), false)
}

impl DnsServer {
    pub fn start(servers: &[String], tx: Sender<DnsEvent>, bypass: Option<std::sync::Arc<crate::split::Bypass>>) -> std::io::Result<Self> {
        let first = upstreams(servers);
        if first.is_empty() {
            return Err(std::io::Error::other("no upstream DNS IPs"));
        }
        let ups = Arc::new(std::sync::RwLock::new(first));
        let addr: SocketAddr = format!("{LISTEN_IP}:53").parse().unwrap();
        let udp = UdpSocket::bind(addr)?;
        udp.set_read_timeout(Some(Duration::from_millis(300)))?;
        let tcp = TcpListener::bind(addr)?;
        tcp.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        if let Some(b) = &bypass {
            // the forwarder's own queries to the direct DNS must not enter the tunnel
            let ips: Vec<IpAddr> = b.direct_dns.iter().map(|a| a.ip()).collect();
            b.add_ips(&ips);
        }

        {
            let (stop, ups, tx, bypass) = (stop.clone(), ups.clone(), tx.clone(), bypass.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, from)) = udp.recv_from(&mut buf) else { continue };
                    let q = buf[..n].to_vec();
                    let (ups, tx, bypass) = (ups.clone(), tx.clone(), bypass.clone());
                    let Ok(sock) = udp.try_clone() else { continue };
                    std::thread::spawn(move || {
                        let t0 = Instant::now();
                        let list = ups.read().unwrap().clone();
                        let (ans, direct) = resolve(&q, &list, bypass.as_deref(), false);
                        if let Some(a) = &ans {
                            let _ = sock.send_to(a, from);
                        }
                        report(&tx, &q, ans.as_deref(), t0, false, direct);
                    });
                }
            });
        }
        {
            let (stop, ups) = (stop.clone(), ups.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match tcp.accept() {
                        Ok((mut c, _)) => {
                            let (ups, tx, bypass) = (ups.clone(), tx.clone(), bypass.clone());
                            std::thread::spawn(move || {
                                let _ = c.set_nonblocking(false);
                                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                                let mut len = [0u8; 2];
                                if c.read_exact(&mut len).is_err() { return; }
                                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                                if c.read_exact(&mut q).is_err() { return; }
                                let t0 = Instant::now();
                                let list = ups.read().unwrap().clone();
                                let (ans, direct) = resolve(&q, &list, bypass.as_deref(), true);
                                if let Some(a) = &ans {
                                    let mut out = (a.len() as u16).to_be_bytes().to_vec();
                                    out.extend_from_slice(a);
                                    let _ = c.write_all(&out);
                                }
                                report(&tx, &q, ans.as_deref(), t0, true, direct);
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(100)),
                    }
                }
            });
        }
        Ok(DnsServer { stop, ups })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // query for example.com A, id 0x1234
    fn query() -> Vec<u8> {
        build_query("example.com", 0x1234)
    }

    #[test]
    fn parses_query_and_answer() {
        let q = query();
        assert_eq!(parse_query(&q), Some(("example.com".into(), "A".into())));
        let mut a = q.clone();
        a[2] = 0x81; a[3] = 0x80; a[7] = 2; // QR, ANCOUNT=2
        // CNAME example.com → www.example.com (compressed)
        a.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, b'w', b'w', b'w', 0xC0, 12]);
        // A 93.184.216.34
        a.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let (rc, ips, cn) = parse_answer(&a).unwrap();
        assert_eq!(rc, "NOERROR");
        assert_eq!(ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        assert_eq!(cn.as_deref(), Some("www.example.com"));
    }

    #[test]
    #[ignore] // needs real internet DNS: cargo test -- --ignored
    fn forwards_real_query() {
        // live test through the local network (skipped if offline)
        let (tx, rx) = std::sync::mpsc::channel();
        let ups = upstreams(&["1.1.1.1".into(), "8.8.8.8".into()]);
        let q = query();
        let t0 = Instant::now();
        let ans = ask_udp(&q, &ups).or_else(|| ask_tcp(&q, &ups));
        if ans.is_none() { eprintln!("offline: skipped"); return; }
        report(&tx, &q, ans.as_deref(), t0, false, false);
        let ev = rx.recv().unwrap();
        assert_eq!(ev.name, "example.com");
        assert_eq!(ev.status, "NOERROR");
    }

    #[test]
    #[ignore] // binds 127.0.53.53:53 (root) and needs an upstream resolver
    fn server_end_to_end() {
        let (tx, rx) = std::sync::mpsc::channel();
        let _srv = DnsServer::start(&["1.1.1.1".into()], tx, None).expect("bind");
        // UDP
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.send_to(&query(), format!("{LISTEN_IP}:53")).unwrap();
        let mut buf = [0u8; 1500];
        let n = c.recv(&mut buf).expect("udp answer");
        assert_eq!(&buf[..2], &[0x12, 0x34]);
        let ev = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        println!("udp event: {} {} {} {}ms", ev.name, ev.qtype, ev.status, ev.ms);
        assert!(n > 12 && ev.name == "example.com" && !ev.tcp);
        // TCP
        let mut t = TcpStream::connect(format!("{LISTEN_IP}:53")).unwrap();
        t.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        let q = query();
        let mut out = (q.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&q);
        t.write_all(&out).unwrap();
        let mut len = [0u8; 2];
        t.read_exact(&mut len).expect("tcp answer");
        let ev = rx.recv_timeout(Duration::from_secs(6)).unwrap();
        println!("tcp event: {} {} {} {}ms", ev.name, ev.qtype, ev.status, ev.ms);
        assert!(ev.tcp);
    }
}
