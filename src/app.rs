//! Application state, connection supervisor and the event loop.

use crate::core::{self, app_log, Level, LogLine};
use crate::dns::{DnsEvent, DnsServer};
use crate::traffic::{self, Traffic};
use crate::net::{self, DnsGuard};
use crate::store::{Paths, Profile, Store};
use crate::uri::Hy2Uri;
use crate::ui;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const HIST: usize = 600; // samples kept (500 ms each → 5 min)
const SAMPLE_EVERY: Duration = Duration::from_millis(500);
const LOG_MAX: usize = 500;
const DNS_MAX: usize = 2000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab { Overview, Connections, Dns, Log }

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Overview, Tab::Connections, Tab::Dns, Tab::Log];
    pub fn idx(self) -> usize { Tab::ALL.iter().position(|t| *t == self).unwrap() }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen { Profiles, Dashboard }

#[derive(Clone, PartialEq, Eq)]
pub enum Status { Disconnected, Connecting, Connected, Reconnecting(u32), Failed(String) }

#[derive(Clone)]
pub enum InputKind { AddUri, Bandwidth(usize), Rename(usize), NotToVpn }

pub enum Popup {
    None,
    /// DNS server manager: selection, text being added, reset armed
    Dns { sel: usize, adding: Option<String>, reset_armed: bool },
    Input { kind: InputKind, title: String, hint: String, buf: String },
    Confirm { text: String, idx: usize },
    Help,
}

pub struct Session {
    pub profile: Profile,
    pub uri: Hy2Uri,
    pub server_ips: Vec<IpAddr>,
    pub cfg_path: PathBuf,
    pub child: Option<Child>,
    pub started: Instant,
    pub connected_at: Option<Instant>,
    pub restarts: u32,
    pub reconnects: u64,
    pub next_restart: Option<Instant>,
    pub dns: Option<DnsGuard>,
    pub dns_server: Option<DnsServer>,
    pub mixed: Option<crate::mixed::MixedProxy>,
    pub bypass: Option<Arc<crate::split::Bypass>>,
    pub sysctl_restore: Vec<(String, String)>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            core::stop(&mut c);
        }
        if let Some(mut d) = self.dns.take() {
            d.restore();
        }
        if self.bypass.take().is_some() {
            crate::split::Bypass::cleanup_all();
        }
        self.dns_server.take();
        net::restore_sysctl(&self.sysctl_restore);
        let _ = std::fs::remove_file(&self.cfg_path);
    }
}

#[derive(Default)]
pub struct Stats {
    pub down: VecDeque<f64>, // bytes/s
    pub up: VecDeque<f64>,
    pub down_now: f64,
    pub up_now: f64,
    pub down_peak: f64,
    pub up_peak: f64,
    pub down_total: u64,
    pub up_total: u64,
    last: Option<(traffic::IfStats, Instant)>,
    last_proxy: Option<(u64, u64, Instant)>,
    pub rx_pps: VecDeque<u64>,
    pub tx_pps: VecDeque<u64>,
    pub rx_pps_now: u64,
    pub tx_pps_now: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub if_errors: u64,
    pub if_dropped: u64,
    pub conn_rate: VecDeque<u64>,
    pub dns_queries: u64,
    pub dns_fail: u64,
    pub dns_ms_sum: u64,
    pub lat: VecDeque<u64>,
    pub latency: Option<u64>,
    pub lat_fail: u32,
    pub public_ip: Option<String>,
    pub cpu: f64,
    pub rss_kb: u64,
    last_cpu: Option<(u64, Instant)>,
}

enum Probe { Latency(Option<u64>), Ip(Option<String>), Apps(std::collections::HashMap<u16, String>), DnsTimes(Vec<(String, Option<u64>)>), Ipv6(Option<bool>), DnsBench(Vec<(String, String, Option<u64>)>) }

pub struct App {
    pub paths: Paths,
    pub store: Store,
    pub core_path: Option<PathBuf>,
    pub core_version: String,
    pub screen: Screen,
    pub popup: Popup,
    pub sel: usize,
    pub status: Status,
    pub session: Option<Session>,
    pub stats: Stats,
    pub logs: VecDeque<LogLine>,
    pub log_scroll: usize,
    pub toast: Option<(String, bool, Instant)>,
    pub quit: bool,
    pub tab: Tab,
    pub traffic: Traffic,
    pub dns_log: VecDeque<DnsEvent>,
    pub conn_scroll: usize,
    pub dns_scroll: usize,
    pub only_open: bool,
    /// animation state
    pub frame: u64,
    pub flow_down: f64,
    pub flow_up: f64,
    pub disp_down: f64,
    pub disp_up: f64,
    dns_tx: Sender<DnsEvent>,
    dns_rx: Receiver<DnsEvent>,
    probing_apps: bool,
    /// measured round-trip per DNS server (D → t)
    pub dns_times: std::collections::HashMap<String, Option<u64>>,
    pub dns_probing: bool,
    /// all presets tested (D → b): (provider, ip, ms), fastest first
    pub dns_bench: Vec<(String, String, Option<u64>)>,
    pub dns_benching: bool,
    auto_repaired: bool,
    last_proxy_addr: String,
    last_apps: Instant,
    log_tx: Sender<LogLine>,
    log_rx: Receiver<LogLine>,
    probe_tx: Sender<Probe>,
    probe_rx: Receiver<Probe>,
    probing_lat: bool,
    probing_ip: bool,
    last_lat: Option<Instant>,
    last_ip: Option<Instant>,
    last_sample: Instant,
    last_dns_check: Instant,
    clk: f64,
}

impl App {
    pub fn new(paths: Paths, store: Store, core_path: Option<PathBuf>) -> Self {
        let (log_tx, log_rx) = channel();
        let (probe_tx, probe_rx) = channel();
        let (dns_tx, dns_rx) = channel();
        let core_version = core_path.as_deref().map(core::core_version).unwrap_or_else(|| "not found".into());
        let last_proxy_addr = if store.settings.proxy.trim().is_empty() { "127.0.0.1:2080".to_string() } else { store.settings.proxy.trim().to_string() };
        let sel = store.last_used.unwrap_or(0).min(store.profiles.len().saturating_sub(1));
        App {
            paths, store, core_path, core_version,
            screen: Screen::Profiles, popup: Popup::None, sel,
            status: Status::Disconnected, session: None, stats: Stats::default(),
            logs: VecDeque::new(), log_scroll: 0, toast: None, quit: false,
            tab: Tab::Overview, traffic: Traffic::default(), dns_log: VecDeque::new(),
            conn_scroll: 0, dns_scroll: 0, only_open: false,
            frame: 0, flow_down: 0.0, flow_up: 0.0, disp_down: 0.0, disp_up: 0.0,
            dns_tx, dns_rx, probing_apps: false, dns_times: Default::default(), dns_probing: false, dns_bench: vec![], dns_benching: false, auto_repaired: false, last_proxy_addr, last_apps: Instant::now(),
            log_tx, log_rx, probe_tx, probe_rx,
            probing_lat: false, probing_ip: false, last_lat: None, last_ip: None,
            last_sample: Instant::now(), last_dns_check: Instant::now(), clk: net::clk_tck(),
        }
    }

    pub fn log(&mut self, level: Level, msg: impl Into<String>) {
        self.push_log(app_log(level, msg));
    }
    #[cfg(test)]
    pub fn push_test_log(&mut self, l: LogLine) { self.push_log(l) }
    fn push_log(&mut self, l: LogLine) {
        self.logs.push_back(l);
        while self.logs.len() > LOG_MAX {
            self.logs.pop_front();
        }
    }
    pub fn toast(&mut self, msg: impl Into<String>, err: bool) {
        self.toast = Some((msg.into(), err, Instant::now()));
    }
    fn save(&mut self) {
        if let Err(e) = self.store.save(&self.paths) {
            self.toast(format!("save failed: {e}"), true);
        }
    }

    // ------------------------------------------------------------ profiles

    pub fn add_text(&mut self, text: &str) {
        let (ok, bad) = self.store.add_from_text(text);
        if !ok.is_empty() {
            self.save();
            self.sel = self.store.profiles.len() - 1;
            self.toast(format!("Added: {}", ok.join(", ")), false);
        } else if let Some(e) = bad.first() {
            self.toast(format!("Not a valid hy2:// link: {e}"), true);
        } else {
            self.toast("Clipboard has no hy2:// / hysteria2:// link", true);
        }
    }

    // ------------------------------------------------------------ connect

    pub fn connect(&mut self, idx: usize) {
        self.disconnect();
        let Some(core_path) = self.core_path.clone() else {
            self.toast("Hysteria core not found — run: hy2tui install-core", true);
            return;
        };
        let Some(profile) = self.store.profiles.get(idx).cloned() else { return };
        let uri = match Hy2Uri::parse(&profile.uri) {
            Ok(u) => u,
            Err(e) => return self.toast(format!("Bad link: {e}"), true),
        };
        // Resolve now, before DNS is redirected into the tunnel.
        let server_ips = match net::resolve(&uri.host) {
            Ok(v) if !v.is_empty() => v,
            Ok(_) | Err(_) => {
                self.toast(format!("Cannot resolve {} — check internet", uri.host), true);
                return;
            }
        };
        let s = self.store.settings.clone();
        let want_proxy = !s.proxy.trim().is_empty();
        if !s.tun && !want_proxy {
            return self.toast("Both TUN and the proxy are off — press [m] to choose a mode", true);
        }
        if s.tun && !crate::store::is_root() {
            return self.toast("TUN mode needs root: restart with sudo hy2tui — or press [m] for proxy-only (no root)", true);
        }
        let mut pre_log = vec![];
        if s.tun {
            match net::tun_preflight(&s.tun_name, &["cybervpn"]) {
                Ok(l) => pre_log = l,
                Err(e) => return self.toast(format!("{e:#}"), true),
            }
        }
        // mixed SOCKS5+HTTP port for browsers
        let mut mixed = None;
        let mut proxy_ports = None;
        if want_proxy {
            let (sp, hp) = (crate::mixed::free_port(), crate::mixed::free_port());
            match crate::mixed::MixedProxy::start(s.proxy.trim(), sp, hp) {
                Ok(m) => {
                    mixed = Some(m);
                    proxy_ports = Some((sp, hp));
                }
                Err(e) => {
                    return self.toast(format!("Cannot open proxy {}: {e} (is nekoray still running?)", s.proxy.trim()), true);
                }
            }
        }
        let cfg = core::build_config(&profile, &uri, &s, &server_ips, proxy_ports);
        let cfg_path = match core::write_config(&cfg) {
            Ok(p) => p,
            Err(e) => return self.toast(format!("Cannot write core config: {e}"), true),
        };

        self.logs.clear();
        self.stats = Stats::default();
        self.traffic = Traffic::default();
        self.dns_log.clear();
        self.tab = Tab::Overview;
        self.log(Level::Info, format!(
            "connecting to {} → {} (sni {})",
            uri.server_with(&uri.host),
            server_ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
            uri.sni_or_host()
        ));
        match (profile.up_mbps, profile.down_mbps) {
            (None, None) => self.log(Level::Warn, "bandwidth not set → BBR congestion control. Press [b] on the profile to set your line speed (Brutal)."),
            (u, d) => self.log(Level::Info, format!("bandwidth up {:?} / down {:?} Mbit/s (Brutal)", u, d)),
        }

        for m in pre_log {
            self.log(Level::Warn, m);
        }
        if let Some(m) = &mixed {
            self.log(Level::Info, format!("browser proxy ready: SOCKS5 + HTTP on {}", m.listen));
        }
        if !s.tun {
            self.log(Level::Info, "proxy-only mode: no TUN, routes and DNS unchanged — only apps using the proxy go through the VPN");
        }
        let mut sysctl_restore = vec![];
        if s.tune_sysctl && crate::store::is_root() {
            let (msgs, restore) = net::tune_sysctl();
            for m in msgs {
                self.log(Level::Info, m);
            }
            sysctl_restore = restore;
        }

        let child = match core::spawn(&core_path, &cfg_path, self.log_tx.clone()) {
            Ok(c) => c,
            Err(e) => {
                net::restore_sysctl(&sysctl_restore);
                return self.toast(format!("{e:#}"), true);
            }
        };

        let mut dns_server = None;
        let mut bypass = None;
        if s.not_to_vpn {
            if !s.tun {
                self.log(Level::Warn, "notToVPN works in TUN mode only (proxy users choose per app)");
            } else if !s.override_dns {
                self.log(Level::Warn, "notToVPN needs \"override_dns = true\" (it works through hy2tui's DNS)");
            } else {
                let b = Arc::new(crate::split::Bypass::new(&s.not_to_vpn_domains, &s.direct_dns));
                self.log(Level::Info, format!("notToVPN: {} go direct (DNS {})", b.patterns().join(", "), s.direct_dns.join(", ")));
                bypass = Some(b);
            }
        }
        let dns = if s.tun && s.override_dns {
            // our forwarder logs every query and maps IPs → domains
            let servers = match DnsServer::start(&s.dns, self.dns_tx.clone(), bypass.clone(), s.ipv6 == "on") {
                Ok(srv) => {
                    dns_server = Some(srv);
                    vec![crate::dns::LISTEN_IP.to_string()]
                }
                Err(e) => {
                    self.log(Level::Warn, format!("DNS logger unavailable ({e}); using {} directly", s.dns.join(", ")));
                    s.dns.clone()
                }
            };
            match DnsGuard::apply(&servers) {
                Ok(g) => {
                    self.log(Level::Info, format!("DNS → {} (through tunnel){}", s.dns.join(", "),
                        if dns_server.is_some() { ", queries logged" } else { "" }));
                    Some(g)
                }
                Err(e) => {
                    self.log(Level::Warn, format!("DNS override failed: {e}"));
                    None
                }
            }
        } else {
            None
        };

        self.session = Some(Session {
            profile, uri, server_ips, cfg_path, child: Some(child),
            started: Instant::now(), connected_at: None, restarts: 0, reconnects: 0,
            next_restart: None, dns, dns_server, mixed, bypass, sysctl_restore,
        });
        self.status = Status::Connecting;
        self.screen = Screen::Dashboard;
        self.store.last_used = Some(idx);
        self.save();
    }

    /// First connect failure: tear the session down, reset leftover network
    /// state (DNS, TUN devices, routes — e.g. after CyberVPN was closed) and
    /// try once more, like `hy2tui reset` + reconnect by hand.
    fn auto_repair(&mut self) {
        let Some(idx) = self.store.last_used else { return };
        self.auto_repaired = true;
        self.disconnect();
        let mut msgs = vec!["could not reach the server — resetting network state and retrying".to_string()];
        if crate::store::is_root() {
            msgs.extend(net::network_reset(&self.store.settings.tun_name));
        }
        self.connect(idx); // clears the log, so add the messages after
        for m in msgs {
            self.log(Level::Warn, m);
        }
        self.toast("Connection failed — network reset, retrying…", false);
    }

    pub fn disconnect(&mut self) {
        if self.session.take().is_some() {
            self.log(Level::Info, "disconnected; DNS and routes restored");
            self.toast("Disconnected", false);
        }
        self.status = Status::Disconnected;
    }

    // ------------------------------------------------------------ periodic

    pub fn tick(&mut self) {
        let mut repair = false;
        // core logs
        while let Ok(l) = self.log_rx.try_recv() {
            if l.msg == "connected to server" {
                if let Some(sess) = &mut self.session {
                    if sess.connected_at.is_none() {
                        sess.connected_at = Some(Instant::now());
                    }
                    sess.reconnects = l.count.unwrap_or(1).saturating_sub(1);
                    sess.restarts = 0;
                }
                self.status = Status::Connected;
                self.auto_repaired = false;
                self.last_ip = None; // refresh exit IP now
                // does the server have IPv6? if not, hide IPv6 addresses
                if self.store.settings.ipv6 == "auto" && self.session.as_ref().is_some_and(|s| s.dns_server.is_some()) {
                    let tx = self.probe_tx.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(800));
                        let _ = tx.send(Probe::Ipv6(crate::dns::ipv6_works()));
                    });
                }
            }
            if self.traffic.on_log(&l) {
                continue; // connection event → connections tab
            }
            if l.msg == "failed to initialize client" && self.session.is_some() && !self.auto_repaired {
                repair = true;
            }
            if l.level == Level::Debug {
                continue; // other debug noise
            }
            if l.level == Level::Error {
                self.toast(format!("core: {} {}", l.msg, l.fields), true);
            }
            self.push_log(l);
        }
        if repair {
            self.auto_repair();
        }
        // DNS queries
        while let Ok(ev) = self.dns_rx.try_recv() {
            self.stats.dns_queries += 1;
            self.stats.dns_ms_sum += ev.ms;
            if ev.status != "NOERROR" { self.stats.dns_fail += 1; }
            if !ev.ips.is_empty() { self.traffic.learn_dns(&ev.name, &ev.ips); }
            self.dns_log.push_back(ev);
            if self.dns_log.len() > DNS_MAX { self.dns_log.pop_front(); }
        }
        // probes
        while let Ok(p) = self.probe_rx.try_recv() {
            match p {
                Probe::Latency(v) => {
                    self.probing_lat = false;
                    self.stats.latency = v;
                    match v {
                        Some(ms) => {
                            self.stats.lat_fail = 0;
                            self.stats.lat.push_back(ms);
                            if self.stats.lat.len() > 120 {
                                self.stats.lat.pop_front();
                            }
                        }
                        None => self.stats.lat_fail += 1,
                    }
                }
                Probe::Ip(v) => {
                    self.probing_ip = false;
                    if v.is_some() {
                        self.stats.public_ip = v;
                    }
                }
                Probe::Apps(m) => {
                    self.probing_apps = false;
                    self.traffic.set_apps(&m);
                }
                Probe::DnsTimes(v) => {
                    self.dns_probing = false;
                    self.dns_times.extend(v);
                }
                Probe::DnsBench(v) => {
                    self.dns_benching = false;
                    for (_, ip, t) in &v {
                        self.dns_times.insert(ip.clone(), *t);
                    }
                    self.dns_bench = v;
                }
                Probe::Ipv6(v) => {
                    let Some(srv) = self.session.as_ref().and_then(|s| s.dns_server.as_ref()) else { continue };
                    match v {
                        Some(true) => {
                            if !srv.ipv6_on() {
                                srv.set_ipv6(true);
                                self.log(Level::Info, "IPv6 works through the server — IPv6 enabled");
                            }
                        }
                        Some(false) => {
                            srv.set_ipv6(false);
                            self.log(Level::Info, "server has no IPv6 — sites use IPv4 (IPv6 addresses hidden, nothing leaks)");
                        }
                        None => {}
                    }
                }
            }
        }

        self.supervise();

        if self.last_sample.elapsed() >= SAMPLE_EVERY {
            self.last_sample = Instant::now();
            self.sample();
        }

        if self.last_dns_check.elapsed() >= Duration::from_secs(3) {
            self.last_dns_check = Instant::now();
            let fixed = self.session.as_ref().and_then(|s| s.dns.as_ref()).map(|d| d.ensure()).unwrap_or(false);
            if fixed {
                self.log(Level::Warn, "resolv.conf was rewritten by the system — DNS override re-applied");
            }
        }

        // animations
        self.frame = self.frame.wrapping_add(1);
        self.disp_down += (self.stats.down_now - self.disp_down) * 0.35;
        self.disp_up += (self.stats.up_now - self.disp_up) * 0.35;
        let speed = |b: f64| if b < 512.0 { 0.0 } else { 0.25 + (b / 1024.0).log10().max(0.0) * 0.35 };
        self.flow_down += speed(self.disp_down);
        self.flow_up += speed(self.disp_up);

        // which app owns new connections (once a second, in background)
        if !self.probing_apps && self.last_apps.elapsed() >= Duration::from_secs(1) {
            self.last_apps = Instant::now();
            let ports = self.traffic.pending_app_ports();
            if !ports.is_empty() {
                self.probing_apps = true;
                // proxy connections: the core sees our relay socket; look up the browser's port instead
                let map: std::collections::HashMap<u16, u16> = self
                    .session
                    .as_ref()
                    .and_then(|s| s.mixed.as_ref())
                    .map(|m| m.c.ports.lock().unwrap().clone())
                    .unwrap_or_default();
                let tx = self.probe_tx.clone();
                std::thread::spawn(move || {
                    let real: Vec<u16> = ports.iter().map(|p| *map.get(p).unwrap_or(p)).collect();
                    let found = traffic::apps_for_ports(&real);
                    let back = ports
                        .iter()
                        .filter_map(|p| found.get(map.get(p).unwrap_or(p)).map(|a| (*p, a.clone())))
                        .collect();
                    let _ = tx.send(Probe::Apps(back));
                });
            }
        }

        if let Some((_, _, t)) = &self.toast {
            if t.elapsed() > Duration::from_secs(6) {
                self.toast = None;
            }
        }
    }

    /// Watch the core process; restart it with backoff if it dies.
    fn supervise(&mut self) {
        let auto = self.store.settings.auto_reconnect;
        let core_path = self.core_path.clone();
        let tx = self.log_tx.clone();
        let mut new_status = None;
        let mut msgs: Vec<(Level, String)> = vec![];
        if let Some(sess) = &mut self.session {
            if let Some(child) = &mut sess.child {
                if let Ok(Some(st)) = child.try_wait() {
                    sess.child = None;
                    sess.connected_at = None;
                    msgs.push((Level::Error, format!("core exited ({st})")));
                    if auto {
                        sess.restarts += 1;
                        let delay = (2u64 << sess.restarts.min(4)).min(30);
                        sess.next_restart = Some(Instant::now() + Duration::from_secs(delay));
                        msgs.push((Level::Warn, format!("restarting in {delay}s (attempt {})", sess.restarts)));
                        new_status = Some(Status::Reconnecting(sess.restarts));
                    } else {
                        new_status = Some(Status::Failed("core stopped".into()));
                    }
                }
            } else if let (Some(t), Some(core)) = (sess.next_restart, core_path) {
                if Instant::now() >= t {
                    sess.next_restart = None;
                    match core::spawn(&core, &sess.cfg_path, tx) {
                        Ok(c) => {
                            sess.child = Some(c);
                            new_status = Some(Status::Reconnecting(sess.restarts));
                        }
                        Err(e) => {
                            sess.restarts += 1;
                            sess.next_restart = Some(Instant::now() + Duration::from_secs(10));
                            msgs.push((Level::Error, format!("{e:#}")));
                        }
                    }
                }
            }
        }
        for (l, m) in msgs {
            self.log(l, m);
        }
        if let Some(s) = new_status {
            self.status = s;
        }
    }

    fn sample(&mut self) {
        let Some(sess) = &self.session else { return };
        let tun = self.store.settings.tun_name.clone();
        let now = Instant::now();
        let st = &mut self.stats;
        if let Some(cur) = traffic::if_stats(&tun) {
            if let Some((l, lt)) = st.last {
                let dt = now.duration_since(lt).as_secs_f64().max(0.001);
                // counters reset when the core recreates the TUN device
                let d = |a: u64, b: u64| if a >= b { a - b } else { a };
                let (drx, dtx) = (d(cur.rx_bytes, l.rx_bytes), d(cur.tx_bytes, l.tx_bytes));
                let (prx, ptx) = (d(cur.rx_packets, l.rx_packets), d(cur.tx_packets, l.tx_packets));
                st.down_total += drx;
                st.up_total += dtx;
                st.rx_packets += prx;
                st.tx_packets += ptx;
                st.down_now = drx as f64 / dt;
                st.up_now = dtx as f64 / dt;
                st.rx_pps_now = (prx as f64 / dt) as u64;
                st.tx_pps_now = (ptx as f64 / dt) as u64;
            }
            st.if_errors = cur.errors;
            st.if_dropped = cur.dropped;
            st.last = Some((cur, now));
        } else {
            st.down_now = 0.0;
            st.up_now = 0.0;
            st.rx_pps_now = 0;
            st.tx_pps_now = 0;
            st.last = None;
        }
        // browser proxy traffic does not pass the TUN device: add it
        if let Some(m) = &sess.mixed {
            use std::sync::atomic::Ordering::Relaxed;
            let (d, u) = (m.c.down.load(Relaxed), m.c.up.load(Relaxed));
            if let Some((ld, lu, lt)) = st.last_proxy {
                let dt = now.duration_since(lt).as_secs_f64().max(0.001);
                st.down_total += d - ld;
                st.up_total += u - lu;
                st.down_now += (d - ld) as f64 / dt;
                st.up_now += (u - lu) as f64 / dt;
            }
            st.last_proxy = Some((d, u, now));
        }
        st.rx_pps.push_back(st.rx_pps_now);
        st.tx_pps.push_back(st.tx_pps_now);
        st.conn_rate.push_back(std::mem::take(&mut self.traffic.new_since_sample));
        while st.rx_pps.len() > HIST { st.rx_pps.pop_front(); st.tx_pps.pop_front(); }
        while st.conn_rate.len() > HIST { st.conn_rate.pop_front(); }
        st.down_peak = st.down_peak.max(st.down_now);
        st.up_peak = st.up_peak.max(st.up_now);
        st.down.push_back(st.down_now);
        st.up.push_back(st.up_now);
        while st.down.len() > HIST {
            st.down.pop_front();
            st.up.pop_front();
        }

        if let Some(pid) = sess.child.as_ref().map(|c| c.id()) {
            if let Some(ps) = net::proc_sample(pid) {
                if let Some((lt, lw)) = st.last_cpu {
                    let dt = now.duration_since(lw).as_secs_f64().max(0.001);
                    st.cpu = (ps.cpu_ticks.saturating_sub(lt)) as f64 / self.clk / dt * 100.0;
                }
                st.last_cpu = Some((ps.cpu_ticks, now));
                st.rss_kb = ps.rss_kb;
            }
        }

        let connected = self.status == Status::Connected;
        let via = if self.store.settings.tun { None } else { sess.mixed.as_ref().map(|m| m.listen) };
        if connected && !self.probing_lat && self.last_lat.is_none_or(|t| t.elapsed() >= Duration::from_secs(3)) {
            self.probing_lat = true;
            self.last_lat = Some(now);
            let tx = self.probe_tx.clone();
            std::thread::spawn(move || { let _ = tx.send(Probe::Latency(net::latency_ms(via))); });
        }
        if connected && !self.probing_ip && self.last_ip.is_none_or(|t| t.elapsed() >= Duration::from_secs(120)) {
            self.probing_ip = true;
            self.last_ip = Some(now);
            let tx = self.probe_tx.clone();
            std::thread::spawn(move || { let _ = tx.send(Probe::Ip(net::public_ip(via))); });
        }
    }

    // ------------------------------------------------------------ input

    pub fn on_paste(&mut self, text: String) {
        match &mut self.popup {
            Popup::Input { buf, .. } => buf.push_str(text.trim()),
            _ => self.add_text(&text),
        }
    }

    pub fn on_key(&mut self, k: KeyEvent) {
        if k.kind != KeyEventKind::Press {
            return;
        }
        if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('q')) {
            self.quit = true;
            return;
        }
        // popups first
        match std::mem::replace(&mut self.popup, Popup::None) {
            Popup::Help => return,
            Popup::Dns { sel, adding, reset_armed } => {
                self.key_dns(k, sel, adding, reset_armed);
                return;
            }
            Popup::Confirm { text, idx } => {
                match k.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        let name = self.store.profiles.remove(idx).name;
                        if self.store.last_used == Some(idx) { self.store.last_used = None; }
                        self.sel = self.sel.min(self.store.profiles.len().saturating_sub(1));
                        self.save();
                        self.toast(format!("Deleted {name}"), false);
                    }
                    KeyCode::Char('n') | KeyCode::Esc => {}
                    _ => self.popup = Popup::Confirm { text, idx },
                }
                return;
            }
            Popup::Input { kind, title, hint, mut buf } => {
                match k.code {
                    KeyCode::Esc => {}
                    KeyCode::Enter => self.submit_input(kind, buf),
                    KeyCode::Backspace => { buf.pop(); self.popup = Popup::Input { kind, title, hint, buf }; }
                    KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.popup = Popup::Input { kind, title, hint, buf: String::new() };
                    }
                    KeyCode::Char('v') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if let Some(c) = net::read_clipboard() { buf.push_str(c.trim()); }
                        self.popup = Popup::Input { kind, title, hint, buf };
                    }
                    KeyCode::Char(c) => { buf.push(c); self.popup = Popup::Input { kind, title, hint, buf }; }
                    _ => self.popup = Popup::Input { kind, title, hint, buf },
                }
                return;
            }
            Popup::None => {}
        }

        // global keys
        match k.code {
            KeyCode::Char('q') => { self.quit = true; return; }
            KeyCode::Char('?') | KeyCode::F(1) => { self.popup = Popup::Help; return; }
            KeyCode::Tab => {
                self.screen = if self.screen == Screen::Profiles { Screen::Dashboard } else { Screen::Profiles };
                return;
            }
            _ => {}
        }

        match self.screen {
            Screen::Profiles => self.key_profiles(k),
            Screen::Dashboard => self.key_dashboard(k),
        }
    }

    fn key_profiles(&mut self, k: KeyEvent) {
        let n = self.store.profiles.len();
        match k.code {
            KeyCode::Up | KeyCode::Char('k') => self.sel = self.sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => if n > 0 { self.sel = (self.sel + 1).min(n - 1) },
            KeyCode::Home | KeyCode::Char('g') => self.sel = 0,
            KeyCode::End | KeyCode::Char('G') => self.sel = n.saturating_sub(1),
            KeyCode::Enter | KeyCode::Char('c') => if n > 0 { self.connect(self.sel) },
            KeyCode::Char('x') => self.disconnect(),
            KeyCode::Char('D') => self.popup = Popup::Dns { sel: 0, adding: None, reset_armed: false },
            KeyCode::Char('v') | KeyCode::Char('p') => match net::read_clipboard() {
                Some(t) => self.add_text(&t),
                None => self.toast("Clipboard tool not available (install wl-clipboard) — use Ctrl+Shift+V or [a]", true),
            },
            KeyCode::Char('m') => {
                // cycle: TUN + proxy → proxy only → TUN only → …
                let st = &mut self.store.settings;
                if !st.proxy.trim().is_empty() {
                    self.last_proxy_addr = st.proxy.trim().to_string();
                }
                let (tun, proxy) = match (st.tun, !st.proxy.trim().is_empty()) {
                    (true, true) => (false, true),
                    (false, _) => (true, false),
                    (true, false) => (true, true),
                };
                st.tun = tun;
                st.proxy = if proxy { self.last_proxy_addr.clone() } else { String::new() };
                let msg = match (tun, proxy) {
                    (true, true) => format!("Mode: TUN (whole system) + browser proxy {}", self.last_proxy_addr),
                    (false, _) => format!("Mode: proxy only on {} — no root needed", self.last_proxy_addr),
                    _ => "Mode: TUN only (no browser proxy)".to_string(),
                };
                self.save();
                self.toast(msg + " — reconnect to apply", false);
            }
            KeyCode::Char('N') => {
                let st = &mut self.store.settings;
                st.not_to_vpn = !st.not_to_vpn;
                let msg = if st.not_to_vpn {
                    format!("notToVPN on: {} bypass the tunnel — reconnect to apply", st.not_to_vpn_domains.join(", "))
                } else {
                    "notToVPN off: everything goes through the tunnel — reconnect to apply".to_string()
                };
                self.save();
                self.toast(msg, false);
            }
            KeyCode::Char('n') => {
                self.popup = Popup::Input {
                    kind: InputKind::NotToVpn,
                    title: " notToVPN — domains & zones outside the tunnel ".into(),
                    hint: "comma-separated: zones (ru, рф, kz, ua) or domains (gosuslugi.ru). [N] turns it on/off".into(),
                    buf: self.store.settings.not_to_vpn_domains.join(", "),
                };
            }
            KeyCode::Char('a') => {
                self.popup = Popup::Input {
                    kind: InputKind::AddUri,
                    title: " Add profile ".into(),
                    hint: "Paste a hy2:// link (Ctrl+Shift+V or Ctrl+V), Enter to save, Esc to cancel".into(),
                    buf: String::new(),
                }
            }
            KeyCode::Char('b') if n > 0 => {
                let p = &self.store.profiles[self.sel];
                let cur = match (p.up_mbps, p.down_mbps) {
                    (Some(u), Some(d)) => format!("{u} {d}"),
                    _ => String::new(),
                };
                self.popup = Popup::Input {
                    kind: InputKind::Bandwidth(self.sel),
                    title: " Bandwidth (Mbit/s) ".into(),
                    hint: "\"UP DOWN\", e.g. \"50 200\" = your real line speed. Empty = auto (BBR)".into(),
                    buf: cur,
                };
            }
            KeyCode::Char('r') if n > 0 => {
                self.popup = Popup::Input {
                    kind: InputKind::Rename(self.sel),
                    title: " Rename ".into(),
                    hint: "New name, Enter to save".into(),
                    buf: self.store.profiles[self.sel].name.clone(),
                }
            }
            KeyCode::Char('d') | KeyCode::Delete if n > 0 => {
                self.popup = Popup::Confirm {
                    text: format!("Delete \"{}\"?  [y/N]", self.store.profiles[self.sel].name),
                    idx: self.sel,
                }
            }
            _ => {}
        }
    }

    fn key_dashboard(&mut self, k: KeyEvent) {
        let scroll = |v: &mut usize, d: i64, max: usize| *v = (*v as i64 + d).clamp(0, max as i64) as usize;
        match k.code {
            KeyCode::Char('x') | KeyCode::Char('d') => self.disconnect(),
            KeyCode::Char('D') => self.popup = Popup::Dns { sel: 0, adding: None, reset_armed: false },
            KeyCode::Char('r') => if let Some(i) = self.store.last_used { self.connect(i) },
            KeyCode::Char('i') => self.last_ip = None,
            KeyCode::Char('1') => self.tab = Tab::Overview,
            KeyCode::Char('2') => self.tab = Tab::Connections,
            KeyCode::Char('3') => self.tab = Tab::Dns,
            KeyCode::Char('4') => self.tab = Tab::Log,
            KeyCode::Right | KeyCode::Char('l') => self.tab = Tab::ALL[(self.tab.idx() + 1) % 4],
            KeyCode::Left | KeyCode::Char('h') => self.tab = Tab::ALL[(self.tab.idx() + 3) % 4],
            KeyCode::Char('o') => { self.only_open = !self.only_open; self.conn_scroll = 0; }
            KeyCode::Char('C') => match self.tab {
                Tab::Dns => { self.dns_log.clear(); self.dns_scroll = 0; }
                Tab::Connections => { self.traffic.conns.retain(|c| c.is_open()); self.conn_scroll = 0; }
                _ => { self.logs.clear(); self.log_scroll = 0; }
            },
            KeyCode::Up | KeyCode::Char('k') | KeyCode::PageUp => {
                let d = if k.code == KeyCode::PageUp { 15 } else { 1 };
                match self.tab {
                    Tab::Connections => scroll(&mut self.conn_scroll, d, self.traffic.conns.len()),
                    Tab::Dns => scroll(&mut self.dns_scroll, d, self.dns_log.len()),
                    _ => scroll(&mut self.log_scroll, d, self.logs.len()),
                }
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::PageDown => {
                let d = if k.code == KeyCode::PageDown { -15 } else { -1 };
                match self.tab {
                    Tab::Connections => scroll(&mut self.conn_scroll, d, self.traffic.conns.len()),
                    Tab::Dns => scroll(&mut self.dns_scroll, d, self.dns_log.len()),
                    _ => scroll(&mut self.log_scroll, d, self.logs.len()),
                }
            }
            KeyCode::End => { self.conn_scroll = 0; self.dns_scroll = 0; self.log_scroll = 0; }
            KeyCode::Esc => self.screen = Screen::Profiles,
            _ => {}
        }
    }

    /// Save the DNS list and hand it to the running forwarder (no reconnect needed).
    fn apply_dns(&mut self) {
        self.save();
        let list = self.store.settings.dns.clone();
        let live = self.session.as_ref().and_then(|s| s.dns_server.as_ref()).map(|srv| srv.set_upstreams(&list)).is_some();
        if live {
            self.log(Level::Info, format!("DNS servers now: {} (applied live)", list.join(" → ")));
        }
    }

    fn key_dns(&mut self, k: KeyEvent, mut sel: usize, adding: Option<String>, reset_armed: bool) {
        // typing a new server
        if let Some(mut buf) = adding {
            match k.code {
                KeyCode::Esc => {}
                KeyCode::Enter => {
                    let mut added = vec![];
                    let mut bad = vec![];
                    for tok in buf.split([',', ' ', ';']).map(str::trim).filter(|t| !t.is_empty()) {
                        let lower = tok.to_lowercase();
                        if let Some((_, ips)) = crate::dns::PRESETS.iter().find(|(n, _)| *n == lower) {
                            added.extend(ips.iter().map(|s| s.to_string()));
                        } else if tok.parse::<std::net::IpAddr>().is_ok() {
                            added.push(tok.to_string());
                        } else {
                            bad.push(tok.to_string());
                        }
                    }
                    let list = &mut self.store.settings.dns;
                    let mut n = 0;
                    for a in added {
                        if !list.contains(&a) {
                            list.push(a);
                            n += 1;
                        }
                    }
                    if !bad.is_empty() {
                        self.toast(format!("not an IP address or known provider: {}", bad.join(", ")), true);
                    } else if n > 0 {
                        self.toast(format!("added {n} DNS server(s) at the end — move them up with K"), false);
                    }
                    if n > 0 {
                        sel = self.store.settings.dns.len() - 1;
                        self.apply_dns();
                    }
                }
                KeyCode::Backspace => {
                    buf.pop();
                    self.popup = Popup::Dns { sel, adding: Some(buf), reset_armed: false };
                    return;
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                    self.popup = Popup::Dns { sel, adding: Some(buf), reset_armed: false };
                    return;
                }
                _ => {
                    self.popup = Popup::Dns { sel, adding: Some(buf), reset_armed: false };
                    return;
                }
            }
            self.popup = Popup::Dns { sel, adding: None, reset_armed: false };
            return;
        }
        let n = self.store.settings.dns.len();
        let shift = k.modifiers.contains(KeyModifiers::SHIFT);
        let mut keep = true;
        let mut armed = false;
        match k.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => keep = false,
            KeyCode::Up if shift => self.dns_move(&mut sel, -1),
            KeyCode::Down if shift => self.dns_move(&mut sel, 1),
            KeyCode::Char('K') | KeyCode::Char('+') => self.dns_move(&mut sel, -1),
            KeyCode::Char('J') | KeyCode::Char('-') => self.dns_move(&mut sel, 1),
            KeyCode::Up | KeyCode::Char('k') => sel = sel.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => sel = (sel + 1).min(n.saturating_sub(1)),
            KeyCode::Char('a') | KeyCode::Insert => {
                self.popup = Popup::Dns { sel, adding: Some(String::new()), reset_armed: false };
                return;
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if n <= 1 {
                    self.toast("at least one DNS server is needed — add another first, or reset with r", true);
                } else if sel < n {
                    let gone = self.store.settings.dns.remove(sel);
                    sel = sel.min(self.store.settings.dns.len() - 1);
                    self.apply_dns();
                    self.toast(format!("removed {gone}"), false);
                }
            }
            KeyCode::Char('r') => {
                if reset_armed {
                    self.store.settings.dns = crate::dns::DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect();
                    sel = 0;
                    self.apply_dns();
                    self.toast(format!("DNS servers reset to defaults: {}", crate::dns::DEFAULT_SERVERS.join(", ")), false);
                } else {
                    armed = true;
                    self.toast("press r again to reset DNS servers to defaults (1.1.1.1, 8.8.8.8)", false);
                }
            }
            KeyCode::Char('b') => {
                if !self.dns_benching {
                    self.dns_benching = true;
                    let tx = self.probe_tx.clone();
                    std::thread::spawn(move || { let _ = tx.send(Probe::DnsBench(crate::dns::bench_presets())); });
                }
            }
            KeyCode::Char('f') => {
                // the two fastest answering providers, both their addresses ordered by speed
                let best: Vec<String> = self.dns_bench.iter().filter(|(_, _, t)| t.is_some()).take(2).map(|(_, ip, _)| ip.clone()).collect();
                if best.is_empty() {
                    self.toast("press b first to test the providers", true);
                } else {
                    self.store.settings.dns = best.clone();
                    sel = 0;
                    self.apply_dns();
                    self.toast(format!("using the fastest: {}", best.join(" → ")), false);
                }
            }
            KeyCode::Char('t') => {
                if !self.dns_probing {
                    self.dns_probing = true;
                    let list = self.store.settings.dns.clone();
                    let tx = self.probe_tx.clone();
                    std::thread::spawn(move || {
                        let handles: Vec<_> = list.into_iter().map(|s| std::thread::spawn(move || { let t = crate::dns::probe(&s); (s, t) })).collect();
                        let res = handles.into_iter().filter_map(|h| h.join().ok()).collect();
                        let _ = tx.send(Probe::DnsTimes(res));
                    });
                }
            }
            _ => {}
        }
        if keep {
            self.popup = Popup::Dns { sel, adding: None, reset_armed: armed };
        }
    }

    fn dns_move(&mut self, sel: &mut usize, dir: i32) {
        let list = &mut self.store.settings.dns;
        let to = *sel as i32 + dir;
        if to < 0 || to as usize >= list.len() {
            return;
        }
        list.swap(*sel, to as usize);
        *sel = to as usize;
        self.apply_dns();
    }

    fn submit_input(&mut self, kind: InputKind, buf: String) {
        match kind {
            InputKind::AddUri => self.add_text(&buf),
            InputKind::NotToVpn => {
                let list: Vec<String> = buf
                    .split([',', ' ', ';', '\n'])
                    .filter_map(crate::split::normalize)
                    .map(|d| idna::domain_to_unicode(&d).0)
                    .collect();
                let n = list.len();
                self.store.settings.not_to_vpn_domains = list;
                self.save();
                let state = if self.store.settings.not_to_vpn { "on" } else { "off — press N to turn on" };
                self.toast(format!("notToVPN: {n} entries saved ({state}); reconnect to apply"), false);
            }
            InputKind::Rename(i) => {
                let name = buf.trim();
                if !name.is_empty() {
                    self.store.profiles[i].name = name.to_string();
                    self.save();
                }
            }
            InputKind::Bandwidth(i) => {
                let nums: Vec<u32> = buf
                    .split(|c: char| !c.is_ascii_digit())
                    .filter_map(|x| x.parse().ok())
                    .filter(|x| *x > 0)
                    .collect();
                let p = &mut self.store.profiles[i];
                match nums.as_slice() {
                    [] => { p.up_mbps = None; p.down_mbps = None; }
                    [both] => { p.up_mbps = Some(*both); p.down_mbps = Some(*both); }
                    [u, d, ..] => { p.up_mbps = Some(*u); p.down_mbps = Some(*d); }
                }
                let msg = match (p.up_mbps, p.down_mbps) {
                    (Some(u), Some(d)) => format!("Bandwidth ↑{u} ↓{d} Mbit/s — reconnect to apply"),
                    _ => "Bandwidth: auto (BBR)".into(),
                };
                self.save();
                self.toast(msg, false);
            }
        }
    }
}

// ---------------------------------------------------------------- run loop

pub fn run(paths: Paths, store: Store, core_path: Option<PathBuf>, autoconnect: Option<usize>) -> Result<()> {
    let term_flag = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&term_flag))?;
    }

    let mut app = App::new(paths, store, core_path);
    // start from a clean network: leftovers of crashes or of a closed CyberVPN
    if crate::store::is_root() {
        let tun = app.store.settings.tun_name.clone();
        for m in net::network_reset(&tun) {
            app.log(Level::Warn, m);
        }
    }
    if app.core_path.is_none() {
        app.toast("Hysteria core not found — quit and run: hy2tui install-core", true);
    }
    if app.store.profiles.is_empty() {
        app.toast("No profiles yet: copy a hy2:// link and press [v]", false);
    }

    let mut terminal = ui::setup_terminal()?;
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ui::restore_terminal_raw();
        prev_hook(info);
    }));

    if let Some(i) = autoconnect {
        if i < app.store.profiles.len() {
            app.sel = i;
            app.connect(i);
        }
    }

    let res = (|| -> Result<()> {
        while !app.quit && !term_flag.load(Ordering::Relaxed) {
            app.tick();
            terminal.draw(|f| ui::draw(f, &app))?;
            if event::poll(Duration::from_millis(70))? {
                match event::read()? {
                    Event::Key(k) => app.on_key(k),
                    Event::Paste(t) => app.on_paste(t),
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    app.disconnect(); // kills core, restores DNS + sysctl
    ui::restore_terminal(&mut terminal)?;
    res
}
