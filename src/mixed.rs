//! Mixed proxy port (like nekoray's): one local port, e.g. 127.0.0.1:2080,
//! that speaks both SOCKS5 and HTTP. The first byte decides:
//! 0x05 → hysteria's SOCKS5 listener, anything else → hysteria's HTTP
//! listener. Bytes are relayed as-is, so all protocol work (CONNECT, UDP
//! ASSOCIATE, remote DNS) is done by the official core.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A free local port for the core's internal listeners.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

#[derive(Default)]
pub struct Counters {
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub active: AtomicUsize,
    pub total: AtomicU64,
    /// relay-side local port → browser's port (to find which app connected)
    pub ports: Mutex<HashMap<u16, u16>>,
}

pub struct MixedProxy {
    stop: Arc<AtomicBool>,
    pub c: Arc<Counters>,
    pub listen: SocketAddr,
}

impl Drop for MixedProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn relay(mut from: TcpStream, mut to: TcpStream, ctr: Arc<Counters>, upload: bool) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
                let c = if upload { &ctr.up } else { &ctr.down };
                c.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
    let _ = from.shutdown(Shutdown::Read);
}

fn handle(client: TcpStream, socks: u16, http: u16, ctr: Arc<Counters>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(15)));
    let mut first = [0u8; 1];
    let Ok(1) = client.peek(&mut first) else { return };
    let _ = client.set_read_timeout(None);
    let port = if first[0] == 0x05 { socks } else { http };
    // the core may still be starting: retry briefly
    let mut up = None;
    for _ in 0..20 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            up = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let Some(up) = up else { return };
    let _ = up.set_nodelay(true);
    let relay_port = up.local_addr().map(|a| a.port()).unwrap_or(0);
    let client_port = client.peer_addr().map(|a| a.port()).unwrap_or(0);
    ctr.ports.lock().unwrap().insert(relay_port, client_port);
    ctr.active.fetch_add(1, Ordering::Relaxed);
    ctr.total.fetch_add(1, Ordering::Relaxed);

    let (c2, u2) = match (client.try_clone(), up.try_clone()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return,
    };
    let ctr2 = ctr.clone();
    let t = std::thread::spawn(move || relay(c2, u2, ctr2, true));
    relay(up, client, ctr.clone(), false);
    let _ = t.join();
    ctr.active.fetch_sub(1, Ordering::Relaxed);
    ctr.ports.lock().unwrap().remove(&relay_port);
}

impl MixedProxy {
    pub fn start(listen: &str, socks: u16, http: u16) -> std::io::Result<Self> {
        let l = TcpListener::bind(listen)?;
        let addr = l.local_addr()?;
        l.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let c = Arc::new(Counters::default());
        {
            let (stop, c) = (stop.clone(), c.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match l.accept() {
                        Ok((s, _)) => {
                            let _ = s.set_nonblocking(false);
                            let c = c.clone();
                            std::thread::spawn(move || handle(s, socks, http, c));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(15)),
                    }
                }
            });
        }
        Ok(MixedProxy { stop, c, listen: addr })
    }
}

/// Open a TCP stream to host:port through a SOCKS5 proxy (no auth).
pub fn socks5_connect(proxy: SocketAddr, host: &str, port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    use std::io::{Error, ErrorKind};
    let mut s = TcpStream::connect_timeout(&proxy, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(Error::new(ErrorKind::Other, "socks5: auth rejected"));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h)?;
    if h[1] != 0 {
        return Err(Error::new(ErrorKind::Other, format!("socks5: connect failed ({})", h[1])));
    }
    let skip = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize + 2
        }
        _ => return Err(Error::new(ErrorKind::Other, "socks5: bad reply")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake "core": SOCKS5 port answers "S", HTTP port answers "H".
    fn fake(tag: char) -> u16 {
        let tag = tag as u8;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut b = [0u8; 1];
                    if s.read_exact(&mut b).is_ok() {
                        let _ = s.write_all(&[tag, b[0]]);
                    }
                });
            }
        });
        p
    }

    #[test]
    fn routes_by_first_byte_and_counts() {
        let (sp, hp) = (fake('S'), fake('H'));
        let px = MixedProxy::start("127.0.0.1:0", sp, hp).unwrap();
        for (first, want) in [(0x05u8, b'S'), (b'C', b'H'), (b'G', b'H')] {
            let mut c = TcpStream::connect(px.listen).unwrap();
            c.write_all(&[first]).unwrap();
            let mut r = [0u8; 2];
            c.read_exact(&mut r).unwrap();
            assert_eq!(r, [want, first]);
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(px.c.total.load(Ordering::Relaxed), 3);
        assert_eq!(px.c.up.load(Ordering::Relaxed), 3);
        assert_eq!(px.c.down.load(Ordering::Relaxed), 6);
    }

    /// Minimal SOCKS5 server standing in for the core's listener.
    fn fake_socks5() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut c = c;
                    let mut g = [0u8; 3];
                    c.read_exact(&mut g).unwrap();
                    c.write_all(&[5, 0]).unwrap();
                    let mut h = [0u8; 5];
                    c.read_exact(&mut h).unwrap();
                    let mut host = vec![0u8; h[4] as usize + 2];
                    c.read_exact(&mut host).unwrap();
                    let port = u16::from_be_bytes([host[host.len() - 2], host[host.len() - 1]]);
                    let name = String::from_utf8_lossy(&host[..host.len() - 2]).to_string();
                    assert_eq!(name, "web.test");
                    let up = TcpStream::connect(("127.0.0.1", port)).unwrap();
                    c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    let (c2, u2) = (c.try_clone().unwrap(), up.try_clone().unwrap());
                    std::thread::spawn(move || { let _ = std::io::copy(&mut &c2, &mut &u2); });
                    let _ = std::io::copy(&mut &up, &mut &c);
                    let _ = c.shutdown(Shutdown::Write);
                });
            }
        });
        p
    }

    #[test]
    fn socks5_through_mixed_port_end_to_end() {
        // a tiny web server
        let web = TcpListener::bind("127.0.0.1:0").unwrap();
        let wp = web.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in web.incoming().flatten() {
                let mut s = s;
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
            }
        });
        let px = MixedProxy::start("127.0.0.1:0", fake_socks5(), fake('H')).unwrap();
        let mut s = socks5_connect(px.listen, "web.test", wp, Duration::from_secs(3)).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: web.test\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(out.ends_with("hello"), "{out}");
    }
}
