//! Tiny DNS forwarder on 127.0.53.53:53 (UDP + TCP).
//! Every query is forwarded to the configured upstream servers — through
//! the tunnel — and reported to the UI: domain, type, answers, time. The
//! answers give an IP → domain map, so connections can be shown by name.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock};
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
    /// answer AAAA queries with "no IPv6 address" (server has no IPv6)
    no_aaaa: Arc<AtomicBool>,
}

/// Well-known resolvers: name → IPs (for quick adding).
/// All of these answer plain DNS on port 53 (what the forwarder speaks).
/// LibreDNS and Mullvad DNS are DoH/DoT-only, so they can't be used here.
pub const PRESETS: &[(&str, &[&str])] = &[
    ("cloudflare", &["1.1.1.1", "1.0.0.1"]),
    ("google", &["8.8.8.8", "8.8.4.4"]),
    // non-profit, no logging of IPs
    ("quad9", &["9.9.9.9", "149.112.112.112"]),
    // privacy-focused, no logs, no filtering (xTom, Germany)
    ("dnssb", &["185.222.222.222", "45.11.45.11"]),
    // free, uncensored, no logging (Denmark)
    ("uncensored", &["91.239.100.100", "89.233.43.71"]),
    // EU public resolver, unfiltered variant
    ("dns4eu", &["86.54.11.100", "86.54.11.200"]),
    // blocks ads and trackers
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

/// Round-trip time of one DNS server: best of 3 lookups (UDP, then TCP if
/// UDP gets nothing), so one lost packet doesn't spoil the result.
pub fn probe(server: &str) -> Option<u64> {
    let ip: IpAddr = server.parse().ok()?;
    let up = [SocketAddr::new(ip, 53)];
    let mut best: Option<u64> = None;
    for (i, name) in ["example.com", "wikipedia.org", "example.org"].iter().enumerate() {
        let q = build_query(name, 0x4240 + i as u16);
        let t0 = Instant::now();
        if ask_udp(&q, &up).or_else(|| ask_tcp(&q, &up)).is_some() {
            let ms = t0.elapsed().as_millis() as u64;
            best = Some(best.map_or(ms, |b| b.min(ms)));
        }
    }
    best
}

/// Test every preset (first address of each) at once: (provider, ip, ms).
pub fn bench_presets() -> Vec<(String, String, Option<u64>)> {
    let hs: Vec<_> = PRESETS
        .iter()
        .map(|(name, ips)| {
            let (name, ip) = (name.to_string(), ips[0].to_string());
            std::thread::spawn(move || {
                let t = probe(&ip);
                (name, ip, t)
            })
        })
        .collect();
    let mut v: Vec<_> = hs.into_iter().filter_map(|h| h.join().ok()).collect();
    v.sort_by_key(|(_, _, t)| t.unwrap_or(u64::MAX));
    v
}

/// Reply to `q` with NOERROR and no answers ("this name has no address of
/// that type"). Apps then use IPv4 right away instead of trying IPv6.
pub fn empty_reply(q: &[u8]) -> Option<Vec<u8>> {
    if q.len() < 12 || u16_at(q, 4)? != 1 {
        return None;
    }
    let end = read_name(q, 12)?.1 + 4;
    if end > q.len() {
        return None;
    }
    let mut r = q[..end].to_vec();
    r[2] = 0x80 | (q[2] & 0x01); // QR, keep RD
    r[3] = 0x80; // RA, NOERROR
    for b in &mut r[6..12] {
        *b = 0;
    }
    Some(r)
}

/// Does IPv6 work through the tunnel? Asks public resolvers over TCP:
/// Some(true) = yes, Some(false) = IPv4 works but IPv6 doesn't,
/// None = can't tell (IPv4 is down too).
pub fn ipv6_works() -> Option<bool> {
    let q = build_query("example.com", 0x6666);
    let v6: Vec<SocketAddr> = ["[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"].iter().map(|a| a.parse().unwrap()).collect();
    if ask_tcp(&q, &v6).is_some() {
        return Some(true);
    }
    let v4: Vec<SocketAddr> = ["1.1.1.1:53", "8.8.8.8:53"].iter().map(|a| a.parse().unwrap()).collect();
    ask_tcp(&q, &v4).map(|_| false)
}

impl DnsServer {
    /// Allow (true) or filter (false) IPv6 answers.
    pub fn set_ipv6(&self, on: bool) {
        self.no_aaaa.store(!on, Ordering::Relaxed);
    }

    pub fn ipv6_on(&self) -> bool {
        !self.no_aaaa.load(Ordering::Relaxed)
    }

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

// ---------------------------------------------------------------- fast path
//
// Why: through the tunnel a single UDP packet can get lost, and asking the
// servers one after another with long waits made lookups take 5–13 s.
// Now: answers are cached (by TTL); a query goes to the first server over
// UDP *and* over a kept-open TCP connection at once, the other servers join
// after 300 ms, and the first good answer wins (usually one round-trip).

const CACHE_MAX: usize = 4096;

struct CacheEntry {
    until: Instant,
    msg: Vec<u8>,
}

fn cache() -> &'static Mutex<HashMap<(String, u16, bool), CacheEntry>> {
    static C: OnceLock<Mutex<HashMap<(String, u16, bool), CacheEntry>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// (lower-case name, qtype) of the question.
fn cache_key(q: &[u8]) -> Option<(String, u16)> {
    if q.len() < 12 || u16_at(q, 4)? != 1 {
        return None;
    }
    let (name, p) = read_name(q, 12)?;
    Some((name.to_ascii_lowercase(), u16_at(q, p)?))
}

/// Smallest TTL among the answers (or a short default for "no data").
fn ttl_of(m: &[u8]) -> Option<u32> {
    let qd = u16_at(m, 4)?;
    let an = u16_at(m, 6)?;
    let mut p = 12;
    for _ in 0..qd {
        p = read_name(m, p)?.1 + 4;
    }
    let mut ttl = u32::MAX;
    for _ in 0..an {
        p = read_name(m, p)?.1;
        let t = u32::from_be_bytes(m.get(p + 4..p + 8)?.try_into().ok()?);
        ttl = ttl.min(t);
        p += 10 + u16_at(m, p + 8)? as usize;
    }
    Some(if an == 0 { 60 } else { ttl })
}

fn cache_get(q: &[u8], direct: bool) -> Option<Vec<u8>> {
    let (name, t) = cache_key(q)?;
    let c = cache().lock().unwrap();
    let e = c.get(&(name, t, direct))?;
    if e.until <= Instant::now() {
        return None;
    }
    let mut m = e.msg.clone();
    m[0] = q[0]; // the asker's query id
    m[1] = q[1];
    Some(m)
}

fn cache_put(q: &[u8], a: &[u8], direct: bool) {
    let rcode = a.get(3).map(|b| b & 0x0F).unwrap_or(2);
    if rcode != 0 && rcode != 3 {
        return; // don't remember SERVFAIL & co
    }
    let (Some((name, t)), Some(ttl)) = (cache_key(q), ttl_of(a)) else { return };
    let ttl = ttl.clamp(10, 1800);
    let mut c = cache().lock().unwrap();
    if c.len() >= CACHE_MAX {
        let now = Instant::now();
        c.retain(|_, e| e.until > now);
        if c.len() >= CACHE_MAX {
            c.clear();
        }
    }
    c.insert((name, t, direct), CacheEntry { until: Instant::now() + Duration::from_secs(ttl as u64), msg: a.to_vec() });
}

/// A kept-open DNS-over-TCP connection; many queries share it (pipelined,
/// matched by query id). Through the tunnel this is a reliable QUIC stream.
struct TcpPipe {
    w: Mutex<TcpStream>,
    pending: Mutex<HashMap<u16, (u16, Sender<Vec<u8>>)>>,
    next: AtomicU16,
    dead: AtomicBool,
}

impl TcpPipe {
    fn connect(up: SocketAddr) -> std::io::Result<Arc<Self>> {
        let s = TcpStream::connect_timeout(&up, Duration::from_secs(3))?;
        let _ = s.set_nodelay(true);
        let mut r = s.try_clone()?;
        let pipe = Arc::new(TcpPipe { w: Mutex::new(s), pending: Default::default(), next: AtomicU16::new(1), dead: AtomicBool::new(false) });
        let p2 = pipe.clone();
        std::thread::spawn(move || {
            loop {
                let mut len = [0u8; 2];
                if r.read_exact(&mut len).is_err() {
                    break;
                }
                let mut m = vec![0u8; u16::from_be_bytes(len) as usize];
                if m.len() < 2 || r.read_exact(&mut m).is_err() {
                    break;
                }
                let id = u16::from_be_bytes([m[0], m[1]]);
                if let Some((orig, tx)) = p2.pending.lock().unwrap().remove(&id) {
                    m[..2].copy_from_slice(&orig.to_be_bytes());
                    let _ = tx.send(m);
                }
            }
            p2.dead.store(true, Ordering::Relaxed);
            p2.pending.lock().unwrap().clear();
        });
        Ok(pipe)
    }

    fn ask(&self, q: &[u8], tx: Sender<Vec<u8>>) -> bool {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let orig = u16::from_be_bytes([q[0], q[1]]);
        self.pending.lock().unwrap().insert(id, (orig, tx));
        let mut out = Vec::with_capacity(q.len() + 2);
        out.extend_from_slice(&(q.len() as u16).to_be_bytes());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&q[2..]);
        let ok = self.w.lock().unwrap().write_all(&out).is_ok();
        if !ok {
            self.dead.store(true, Ordering::Relaxed);
            self.pending.lock().unwrap().remove(&id);
        }
        ok
    }
}

fn pipe_for(up: SocketAddr) -> Option<Arc<TcpPipe>> {
    static P: OnceLock<Mutex<HashMap<SocketAddr, Arc<TcpPipe>>>> = OnceLock::new();
    let pool = P.get_or_init(Default::default);
    if let Some(p) = pool.lock().unwrap().get(&up) {
        if !p.dead.load(Ordering::Relaxed) {
            return Some(p.clone());
        }
    }
    let p = TcpPipe::connect(up).ok()?;
    pool.lock().unwrap().insert(up, p.clone());
    Some(p)
}

/// UDP with one resend (a lost packet costs 700 ms, not seconds).
fn udp_try(q: &[u8], up: SocketAddr) -> Option<Vec<u8>> {
    let s = UdpSocket::bind(if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    s.connect(up).ok()?;
    let mut buf = vec![0u8; 4096];
    for wait in [700u64, 1500] {
        s.send(q).ok()?;
        let _ = s.set_read_timeout(Some(Duration::from_millis(wait)));
        if let Ok(n) = s.recv(&mut buf) {
            if n >= 12 && buf[..2] == q[..2] {
                buf.truncate(n);
                return Some(buf);
            }
        }
    }
    None
}

/// Ask the servers in parallel; first good answer wins.
fn race(q: &[u8], ups: &[SocketAddr]) -> Option<Vec<u8>> {
    if ups.is_empty() || q.len() < 12 {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let launch = |up: SocketAddr| {
        let (q1, t1) = (q.to_vec(), tx.clone());
        std::thread::spawn(move || {
            if let Some(a) = udp_try(&q1, up) {
                let _ = t1.send(a);
            }
        });
        let (q2, t2) = (q.to_vec(), tx.clone());
        std::thread::spawn(move || {
            if let Some(p) = pipe_for(up) {
                if !p.ask(&q2, t2.clone()) {
                    // stale connection: one fresh try
                    if let Some(p) = pipe_for(up) {
                        p.ask(&q2, t2);
                    }
                }
            }
        });
    };
    let deadline = Instant::now() + Duration::from_millis(4500);
    let mut fallback = None;
    let wait_one = |until: Instant, fallback: &mut Option<Vec<u8>>| -> Option<Vec<u8>> {
        while let Some(left) = until.checked_duration_since(Instant::now()) {
            match rx.recv_timeout(left) {
                Ok(a) => {
                    let rc = a[3] & 0x0F;
                    if rc == 0 || rc == 3 {
                        return Some(a);
                    }
                    fallback.get_or_insert(a); // SERVFAIL etc.: maybe another server knows better
                }
                Err(_) => return None,
            }
        }
        None
    };
    launch(ups[0]);
    if let Some(a) = wait_one(Instant::now() + Duration::from_millis(300), &mut fallback) {
        return Some(a);
    }
    for up in &ups[1..] {
        launch(*up);
    }
    wait_one(deadline, &mut fallback).or(fallback)
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
fn resolve(q: &[u8], ups: &[SocketAddr], bypass: Option<&crate::split::Bypass>, _tcp: bool, no_aaaa: bool) -> (Option<Vec<u8>>, bool) {
    if no_aaaa && q.len() > 12 {
        if let Some((_, t)) = parse_query(q) {
            if t == "AAAA" {
                return (empty_reply(q), false);
            }
        }
    }
    let direct = bypass.is_some_and(|b| parse_query(q).is_some_and(|(n, _)| b.matches(&n) && !b.direct_dns.is_empty()));
    if let Some(hit) = cache_get(q, direct) {
        if let Some(b) = bypass.filter(|_| direct) {
            if let Some((_, ips, _)) = parse_answer(&hit) {
                b.add_ips(&ips); // already routed; re-adds only if rules were reset
            }
        }
        return (Some(hit), direct);
    }
    let ask = |servers: &[SocketAddr]| {
        let a = race(q, servers);
        if let Some(a) = &a {
            cache_put(q, a, direct);
        }
        a
    };
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
    /// `ipv6`: start with IPv6 answers allowed (can be changed with `set_ipv6`).
    pub fn start(servers: &[String], tx: Sender<DnsEvent>, bypass: Option<std::sync::Arc<crate::split::Bypass>>, ipv6: bool) -> std::io::Result<Self> {
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
        let no_aaaa = Arc::new(AtomicBool::new(!ipv6));
        if let Some(b) = &bypass {
            // the forwarder's own queries to the direct DNS must not enter the tunnel
            let ips: Vec<IpAddr> = b.direct_dns.iter().map(|a| a.ip()).collect();
            b.add_ips(&ips);
        }

        {
            let (stop, ups, tx, bypass, no_aaaa) = (stop.clone(), ups.clone(), tx.clone(), bypass.clone(), no_aaaa.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, from)) = udp.recv_from(&mut buf) else { continue };
                    let q = buf[..n].to_vec();
                    let (ups, tx, bypass, na) = (ups.clone(), tx.clone(), bypass.clone(), no_aaaa.load(Ordering::Relaxed));
                    let Ok(sock) = udp.try_clone() else { continue };
                    std::thread::spawn(move || {
                        let t0 = Instant::now();
                        let list = ups.read().unwrap().clone();
                        let (ans, direct) = resolve(&q, &list, bypass.as_deref(), false, na);
                        if let Some(a) = &ans {
                            let _ = sock.send_to(a, from);
                        }
                        report(&tx, &q, ans.as_deref(), t0, false, direct);
                    });
                }
            });
        }
        {
            let (stop, ups, no_aaaa) = (stop.clone(), ups.clone(), no_aaaa.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match tcp.accept() {
                        Ok((mut c, _)) => {
                            let (ups, tx, bypass, na) = (ups.clone(), tx.clone(), bypass.clone(), no_aaaa.load(Ordering::Relaxed));
                            std::thread::spawn(move || {
                                let _ = c.set_nonblocking(false);
                                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                                let mut len = [0u8; 2];
                                if c.read_exact(&mut len).is_err() { return; }
                                let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                                if c.read_exact(&mut q).is_err() { return; }
                                let t0 = Instant::now();
                                let list = ups.read().unwrap().clone();
                                let (ans, direct) = resolve(&q, &list, bypass.as_deref(), true, na);
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
        Ok(DnsServer { stop, ups, no_aaaa })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// answer = query + one A record 10.1.2.3 (ttl 300)
    fn fake_answer(q: &[u8]) -> Vec<u8> {
        let mut a = empty_reply(q).unwrap();
        a[7] = 1; // ancount
        a.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 10, 1, 2, 3]);
        a
    }

    #[test]
    fn race_survives_lost_udp_and_caches() {
        // upstream whose UDP is a black hole, but TCP answers
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        let tcp = TcpListener::bind(("127.0.0.1", port)).unwrap();
        std::thread::spawn(move || {
            for c in tcp.incoming() {
                let mut c = c.unwrap();
                std::thread::spawn(move || loop {
                    let mut len = [0u8; 2];
                    if c.read_exact(&mut len).is_err() { return; }
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    if c.read_exact(&mut q).is_err() { return; }
                    let a = fake_answer(&q);
                    let mut out = (a.len() as u16).to_be_bytes().to_vec();
                    out.extend_from_slice(&a);
                    if c.write_all(&out).is_err() { return; }
                });
            }
        });
        let up: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let q = build_query("race.test", 0x7777);
        let t0 = Instant::now();
        let a = race(&q, &[up]).expect("answer over TCP");
        assert!(t0.elapsed() < Duration::from_millis(600), "took {:?}", t0.elapsed());
        assert_eq!(&a[..2], &[0x77, 0x77]);
        assert_eq!(parse_answer(&a).unwrap().1, vec!["10.1.2.3".parse::<IpAddr>().unwrap()]);
        // pipelined: many at once over the same connection
        let hs: Vec<_> = (0..20u16).map(|i| std::thread::spawn(move || race(&build_query(&format!("n{i}.test"), 100 + i), &[up]))).collect();
        for (i, h) in hs.into_iter().enumerate() {
            let a = h.join().unwrap().unwrap();
            assert_eq!(u16::from_be_bytes([a[0], a[1]]), 100 + i as u16);
        }
        // cache: same name, other id → instant, id rewritten
        cache_put(&q, &a, false);
        let q2 = build_query("RACE.test", 0x1234);
        let hit = cache_get(&q2, false).unwrap();
        assert_eq!(&hit[..2], &[0x12, 0x34]);
        assert!(cache_get(&q2, true).is_none());
        drop(udp);
    }

    #[test]
    fn empty_aaaa_reply() {
        let mut q = build_query("youtube.com", 0x0102);
        let n = q.len();
        q[n - 3] = 28; // AAAA
        q.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]); // EDNS OPT
        q[11] = 1; // arcount 1
        let r = empty_reply(&q).unwrap();
        assert_eq!(&r[..2], &[1, 2]);
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(&r[6..12], &[0; 6]);
        assert_eq!(r.len(), n);
        let (st, ips, _) = parse_answer(&r).unwrap();
        assert_eq!(st, "NOERROR");
        assert!(ips.is_empty());
        assert_eq!(parse_query(&r).unwrap().1, "AAAA");
        // the forwarder answers AAAA itself when IPv6 is hidden (no upstream needed)
        let (ans, direct) = resolve(&q, &[], None, false, true);
        assert_eq!(ans.unwrap(), r);
        assert!(!direct);
    }

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
        let _srv = DnsServer::start(&["1.1.1.1".into()], tx, None, true).expect("bind");
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
