//! Rendering (ratatui). Layout and colours are modelled on btop.

use crate::app::{App, Popup, Screen, Status, Tab};
use crate::core::Level;
use crate::uri::Hy2Uri;
use anyhow::Result;
use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols::Marker,
    text::{Line, Span},
    widgets::{
        Axis, Block, BorderType, Cell, Chart, Clear, Dataset, GraphType, List, ListItem, ListState,
        Paragraph, Row, Sparkline, Table, Wrap,
    },
    Frame, Terminal,
};
use std::io::Stdout;

pub type Term = Terminal<CrosstermBackend<Stdout>>;

// btop-ish palette
const BORDER: Color = Color::Rgb(88, 91, 112);
const TITLE: Color = Color::Rgb(137, 180, 250);
const DIM: Color = Color::Rgb(127, 132, 156);
const TEXT: Color = Color::Rgb(205, 214, 244);
const DOWN: Color = Color::Rgb(166, 227, 161);
const UP: Color = Color::Rgb(245, 194, 231);
const WARN: Color = Color::Rgb(249, 226, 175);
const ERR: Color = Color::Rgb(243, 139, 168);
const ACCENT: Color = Color::Rgb(203, 166, 247);
const SEL_BG: Color = Color::Rgb(49, 50, 68);

pub fn setup_terminal() -> Result<Term> {
    enable_raw_mode()?;
    let mut out = std::io::stdout();
    execute!(out, EnterAlternateScreen, EnableBracketedPaste)?;
    let mut t = Terminal::new(CrosstermBackend::new(out))?;
    t.clear()?;
    Ok(t)
}

pub fn restore_terminal(t: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(t.backend_mut(), DisableBracketedPaste, LeaveAlternateScreen)?;
    t.show_cursor()?;
    Ok(())
}

pub fn restore_terminal_raw() {
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
}

fn panel(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(BORDER))
        .title(Line::from(vec![
            Span::styled("┤ ", Style::new().fg(BORDER)),
            Span::styled(title.to_string(), Style::new().fg(TITLE).bold()),
            Span::styled(" ├", Style::new().fg(BORDER)),
        ]))
}

pub fn fmt_bytes(b: f64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{v:.0} {}", U[i]) } else { format!("{v:.1} {}", U[i]) }
}

pub fn fmt_rate(bps: f64) -> String {
    format!("{}/s", fmt_bytes(bps))
}

fn fmt_mbit(bps: f64) -> String {
    let m = bps * 8.0 / 1_000_000.0;
    if m >= 100.0 { format!("{m:.0} Mbit/s") } else { format!("{m:.1} Mbit/s") }
}

fn fmt_dur(s: u64) -> String {
    let (h, m, sec) = (s / 3600, (s / 60) % 60, s % 60);
    if h >= 24 { format!("{}d {:02}:{:02}:{:02}", h / 24, h % 24, m, sec) } else { format!("{h:02}:{m:02}:{sec:02}") }
}

fn status_span(st: &Status, frame: u64) -> Span<'static> {
    let spin = SPIN[(frame % 10) as usize];
    let beat = if frame % 12 < 6 { "●" } else { "◉" };
    match st {
        Status::Disconnected => Span::styled(" ○ DISCONNECTED ", Style::new().fg(DIM).bold()),
        Status::Connecting => Span::styled(format!(" {spin} CONNECTING "), Style::new().fg(Color::Black).bg(WARN).bold()),
        Status::Connected => Span::styled(format!(" {beat} CONNECTED "), Style::new().fg(Color::Black).bg(DOWN).bold()),
        Status::Reconnecting(n) => Span::styled(format!(" {spin} RECONNECTING #{n} "), Style::new().fg(Color::Black).bg(WARN).bold()),
        Status::Failed(_) => Span::styled(" ✕ FAILED ", Style::new().fg(Color::Black).bg(ERR).bold()),
    }
}

pub fn draw(f: &mut Frame, app: &App) {
    let [header, body, footer] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(5), Constraint::Length(1)]).areas(f.area());
    draw_header(f, header, app);
    match app.screen {
        Screen::Profiles => draw_profiles(f, body, app),
        Screen::Dashboard => draw_dashboard(f, body, app),
    }
    draw_footer(f, footer, app);
    draw_popup(f, app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![
        Span::styled(" hy2tui ", Style::new().fg(Color::Black).bg(ACCENT).bold()),
        Span::raw(" "),
        status_span(&app.status, app.frame),
    ];
    if let Some(s) = &app.session {
        spans.push(Span::styled(format!("  {}", s.profile.name), Style::new().fg(TEXT).bold()));
        if let Some(t) = s.connected_at {
            spans.push(Span::styled(format!("  ⏱ {}", fmt_dur(t.elapsed().as_secs())), Style::new().fg(DIM)));
        }
        if app.status == Status::Connected {
            spans.push(Span::styled(format!("  ▼ {}", fmt_rate(app.disp_down)), Style::new().fg(DOWN)));
            spans.push(Span::styled(format!("  ▲ {}", fmt_rate(app.disp_up)), Style::new().fg(UP)));
        }
    }
    let right = Span::styled(format!("core {} ", app.core_version), Style::new().fg(DIM));
    let w = right.width() as u16;
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    if area.width > w + 40 {
        f.render_widget(Paragraph::new(right).alignment(Alignment::Right), area);
    }
}

fn key(k: &str, label: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!(" {k} "), Style::new().fg(Color::Black).bg(TITLE).bold()),
        Span::styled(format!(" {label}  "), Style::new().fg(DIM)),
    ]
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    if let Some((msg, err, _)) = &app.toast {
        let st = if *err { Style::new().fg(Color::Black).bg(ERR) } else { Style::new().fg(Color::Black).bg(DOWN) };
        f.render_widget(Paragraph::new(Span::styled(format!(" {msg} "), st.bold())), area);
        return;
    }
    let mut s: Vec<Span> = vec![];
    match app.screen {
        Screen::Profiles => {
            for (k, l) in [("⏎", "connect"), ("v", "paste link"), ("a", "add"), ("b", "bandwidth"),
                           ("m", "mode"), ("D", "DNS"), ("r", "rename"), ("d", "delete"), ("x", "disconnect"), ("Tab", "dashboard"), ("q", "quit")] {
                s.extend(key(k, l));
            }
        }
        Screen::Dashboard => {
            let mut keys = vec![("1-4", "tabs"), ("x", "disconnect"), ("r", "reconnect")];
            match app.tab {
                Tab::Overview => keys.push(("i", "refresh IP")),
                Tab::Connections => { keys.push(("↑↓", "scroll")); keys.push(("o", "open only")); keys.push(("C", "clear closed")); }
                Tab::Dns | Tab::Log => { keys.push(("↑↓", "scroll")); keys.push(("C", "clear")); }
            }
            keys.extend([("Tab", "profiles"), ("?", "help"), ("q", "quit")]);
            for (k, l) in keys {
                s.extend(key(k, l));
            }
        }
    }
    f.render_widget(Paragraph::new(Line::from(s)), area);
}

// ---------------------------------------------------------------- profiles

fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n <= 4 { "••••".into() } else { format!("{}••••••", s.chars().take(3).collect::<String>()) }
}

fn draw_profiles(f: &mut Frame, area: Rect, app: &App) {
    let [left, right] = Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).areas(area);

    let active = app.session.as_ref().map(|s| s.profile.uri.clone());
    let items: Vec<ListItem> = app
        .store
        .profiles
        .iter()
        .map(|p| {
            let u = Hy2Uri::parse(&p.uri).ok();
            let is_active = active.as_deref() == Some(p.uri.as_str());
            let dot = if is_active { Span::styled("● ", Style::new().fg(DOWN)) } else { Span::styled("  ", Style::new()) };
            let addr = u.as_ref().map(|u| format!("{}:{}", u.host, u.ports)).unwrap_or_else(|| "invalid link".into());
            let bw = match (p.up_mbps, p.down_mbps) {
                (Some(a), Some(b)) => format!(" ↑{a} ↓{b}"),
                _ => String::new(),
            };
            ListItem::new(vec![
                Line::from(vec![dot, Span::styled(p.name.clone(), Style::new().fg(TEXT).bold())]),
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(addr, Style::new().fg(DIM)),
                    Span::styled(bw, Style::new().fg(ACCENT)),
                ]),
            ])
        })
        .collect();

    let title = format!("profiles ({})", app.store.profiles.len());
    if items.is_empty() {
        let p = Paragraph::new(vec![
            Line::raw(""),
            Line::styled("  No profiles yet.", Style::new().fg(TEXT).bold()),
            Line::raw(""),
            Line::styled("  1. Copy your hy2:// link", Style::new().fg(DIM)),
            Line::styled("  2. Press  v  (or Ctrl+Shift+V)", Style::new().fg(DIM)),
            Line::styled("  3. Press  Enter  to connect", Style::new().fg(DIM)),
        ])
        .block(panel(&title));
        f.render_widget(p, left);
    } else {
        let list = List::new(items)
            .block(panel(&title))
            .highlight_style(Style::new().bg(SEL_BG))
            .highlight_symbol("▌");
        let mut st = ListState::default().with_selected(Some(app.sel));
        f.render_stateful_widget(list, left, &mut st);
    }

    // details of selected profile
    let mut lines: Vec<Line> = vec![];
    if let Some(p) = app.store.profiles.get(app.sel) {
        match Hy2Uri::parse(&p.uri) {
            Ok(u) => {
                let kv = |k: &str, v: String| {
                    Line::from(vec![
                        Span::styled(format!(" {k:<11}"), Style::new().fg(DIM)),
                        Span::styled(v, Style::new().fg(TEXT)),
                    ])
                };
                lines.push(kv("name", p.name.clone()));
                lines.push(kv("server", u.host.clone()));
                lines.push(kv("port(s)", u.ports.clone()));
                lines.push(kv("auth", mask(&u.auth)));
                lines.push(kv("sni", u.sni_or_host().to_string()));
                lines.push(kv("obfs", match &u.obfs {
                    Some(o) => format!("{o} ({})", mask(u.obfs_password.as_deref().unwrap_or(""))),
                    None => "none".into(),
                }));
                lines.push(kv("tls verify", if u.insecure { "OFF (insecure)".into() } else { "on".into() }));
                if u.pin_sha256.is_some() {
                    lines.push(kv("pinned", "sha256".into()));
                }
                lines.push(kv("bandwidth", match (p.up_mbps, p.down_mbps) {
                    (Some(a), Some(b)) => format!("↑ {a}  ↓ {b} Mbit/s  (Brutal)"),
                    _ => "auto (BBR) — press b to set".into(),
                }));
            }
            Err(e) => lines.push(Line::styled(format!(" invalid link: {e}"), Style::new().fg(ERR))),
        }
    }
    let s = &app.store.settings;
    lines.push(Line::raw(""));
    lines.push(Line::styled(" settings", Style::new().fg(TITLE).bold()));
    let flag = |b: bool| if b { "on" } else { "off" };
    let mode = match (s.tun, !s.proxy.trim().is_empty()) {
        (true, true) => format!("TUN (whole system) + browser proxy {}", s.proxy.trim()),
        (true, false) => "TUN (whole system)".to_string(),
        (false, true) => format!("proxy only {} — no root", s.proxy.trim()),
        (false, false) => "nothing enabled — press m".to_string(),
    };
    lines.push(Line::from(vec![
        Span::styled(" mode       ", Style::new().fg(DIM)),
        Span::styled(mode, Style::new().fg(ACCENT).bold()),
        Span::styled("  [m]", Style::new().fg(DIM)),
    ]));
    let ntv = if s.not_to_vpn {
        format!("on — {}", s.not_to_vpn_domains.join(", "))
    } else {
        "off".to_string()
    };
    lines.push(Line::from(vec![
        Span::styled(" notToVPN   ", Style::new().fg(DIM)),
        Span::styled(ntv, Style::new().fg(if s.not_to_vpn { DOWN } else { DIM })),
        Span::styled("  [n] edit  [N] on/off", Style::new().fg(DIM)),
    ]));
    lines.push(Line::styled(
        format!(" TUN {} mtu {}   bypass LAN {}   fastOpen {}", s.tun_name, s.mtu, flag(s.bypass_lan), flag(s.fast_open)),
        Style::new().fg(DIM),
    ));
    lines.push(Line::from(vec![
        Span::styled(" DNS        ", Style::new().fg(DIM)),
        Span::styled(if s.override_dns { s.dns.join(" → ") } else { "system".into() }, Style::new().fg(TEXT)),
        Span::styled("  [D]", Style::new().fg(DIM)),
    ]));
    lines.push(Line::styled(format!(" sysctl tuning {}", flag(s.tune_sysctl)), Style::new().fg(DIM)));
    lines.push(Line::styled(format!(" {}", app.paths.config_file.display()), Style::new().fg(DIM).italic()));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel("details")), right);
}

// ---------------------------------------------------------------- dashboard

const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn tabs_line(app: &App) -> Line<'static> {
    let (open_t, open_u) = app.traffic.open_count();
    let names = [
        "Overview".to_string(),
        format!("Connections {}", open_t + open_u),
        format!("DNS {}", app.dns_log.len()),
        "Log".to_string(),
    ];
    let mut spans = vec![Span::raw(" ")];
    for (i, n) in names.iter().enumerate() {
        let sel = app.tab.idx() == i;
        let st = if sel { Style::new().fg(Color::Black).bg(ACCENT).bold() } else { Style::new().fg(DIM) };
        spans.push(Span::styled(format!(" {} ", i + 1), if sel { st } else { Style::new().fg(TITLE).bold() }));
        spans.push(Span::styled(format!("{n} "), st));
        spans.push(Span::raw("  "));
    }
    Line::from(spans)
}

fn draw_dashboard(f: &mut Frame, area: Rect, app: &App) {
    let Some(sess) = &app.session else {
        let pulse = ["·", "•", "●", "•"][(app.frame / 4 % 4) as usize];
        let p = Paragraph::new(vec![
            Line::raw(""),
            Line::styled(format!("{pulse}  Not connected  {pulse}"), Style::new().fg(TEXT).bold()),
            Line::styled("Tab → profiles, Enter → connect", Style::new().fg(DIM)),
        ])
        .alignment(Alignment::Center)
        .block(panel("dashboard"));
        f.render_widget(p, area);
        return;
    };
    let [tabs, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(3)]).areas(area);
    f.render_widget(Paragraph::new(tabs_line(app)), tabs);

    if sess.connected_at.is_none() && app.tab == Tab::Overview {
        let [anim, rest] = Layout::vertical([Constraint::Length(9), Constraint::Min(3)]).areas(body);
        draw_connecting(f, anim, app);
        draw_logs(f, rest, app);
        return;
    }
    match app.tab {
        Tab::Overview => draw_overview(f, body, app),
        Tab::Connections => draw_conn_table(f, body, app),
        Tab::Dns => draw_dns_table(f, body, app),
        Tab::Log => draw_logs(f, body, app),
    }
}

/// "you ──●──── server" with a packet travelling back and forth.
fn draw_connecting(f: &mut Frame, area: Rect, app: &App) {
    let Some(s) = &app.session else { return };
    let block = panel("establishing tunnel");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let w = inner.width.saturating_sub(24).max(10) as usize;
    let t = (app.frame % (2 * w as u64)) as usize;
    let pos = if t < w { t } else { 2 * w - t - 1 };
    let mut path = String::new();
    for i in 0..w {
        path.push(if i == pos { '◆' } else if (i + app.frame as usize / 2).is_multiple_of(3) { '┄' } else { '─' });
    }
    let spin = SPIN[(app.frame % 10) as usize];
    let what = match &app.status {
        Status::Reconnecting(n) => format!("reconnecting, attempt {n}"),
        _ => "connecting".into(),
    };
    let lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled("   ◉ you ", Style::new().fg(TEXT).bold()),
            Span::styled(path, Style::new().fg(ACCENT)),
            Span::styled(" ◎ server", Style::new().fg(TEXT).bold()),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(format!("   {spin} "), Style::new().fg(WARN).bold()),
            Span::styled(format!("{what} to {}:{}", s.uri.host, s.uri.ports), Style::new().fg(TEXT)),
            Span::styled(format!("   {}s", s.started.elapsed().as_secs()), Style::new().fg(DIM)),
        ]),
        Line::styled(
            format!("     QUIC + {} obfs · sni {}", s.uri.obfs.as_deref().unwrap_or("no"), s.uri.sni_or_host()),
            Style::new().fg(DIM),
        ),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_overview(f: &mut Frame, area: Rect, app: &App) {
    let [net, flow, mid, bottom] = Layout::vertical([
        Constraint::Percentage(40),
        Constraint::Length(4),
        Constraint::Length(9),
        Constraint::Min(5),
    ])
    .areas(area);
    draw_net(f, net, app);
    draw_flow(f, flow, app);
    let [pk, lat, ses] = Layout::horizontal([Constraint::Ratio(1, 3), Constraint::Ratio(1, 3), Constraint::Ratio(1, 3)]).areas(mid);
    draw_packets(f, pk, app);
    draw_latency(f, lat, app);
    draw_sessions(f, ses, app);
    let [live, top] = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(bottom);
    draw_live(f, live, app);
    draw_top(f, top, app);
}

fn graph(f: &mut Frame, area: Rect, data: &std::collections::VecDeque<f64>, color: Color, label: &str, now: f64) {
    let width = (area.width as usize * 2).max(2); // braille: 2 columns per cell
    let n = data.len().min(width);
    let pts: Vec<(f64, f64)> = data
        .iter()
        .skip(data.len() - n)
        .enumerate()
        .map(|(i, v)| ((width - n + i) as f64, *v))
        .collect();
    let max = pts.iter().map(|p| p.1).fold(0.0f64, f64::max).max(16.0 * 1024.0) * 1.15;
    let ds = Dataset::default()
        .marker(Marker::Braille)
        .graph_type(GraphType::Bar)
        .style(Style::new().fg(color))
        .data(&pts);
    let chart = Chart::new(vec![ds])
        .x_axis(Axis::default().bounds([0.0, width as f64]))
        .y_axis(Axis::default().bounds([0.0, max]));
    f.render_widget(chart, area);
    let tag = Line::from(vec![
        Span::styled(format!(" {label} "), Style::new().fg(color).bold()),
        Span::styled(format!("{} ", fmt_rate(now)), Style::new().fg(TEXT)),
        Span::styled(format!("max {} ", fmt_rate(max / 1.15)), Style::new().fg(DIM)),
    ]);
    f.render_widget(Paragraph::new(tag), Rect { height: 1, ..area });
}

fn draw_net(f: &mut Frame, area: Rect, app: &App) {
    let st = &app.stats;
    let block = panel(&format!("net · {}", app.store.settings.tun_name));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [graphs, side] = Layout::horizontal([Constraint::Min(20), Constraint::Length(28)]).areas(inner);
    let [g1, g2] = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(graphs);
    graph(f, g1, &st.down, DOWN, "▼ download", app.disp_down);
    graph(f, g2, &st.up, UP, "▲ upload", app.disp_up);

    let big = |arrow: &str, v: f64, c: Color| {
        Line::from(vec![
            Span::styled(format!(" {arrow} "), Style::new().fg(c).bold()),
            Span::styled(fmt_rate(v), Style::new().fg(c).bold()),
        ])
    };
    let small = |k: &str, v: String| {
        Line::from(vec![Span::styled(format!("   {k:<6}"), Style::new().fg(DIM)), Span::styled(v, Style::new().fg(TEXT))])
    };
    let lines = vec![
        big("▼", app.disp_down, DOWN),
        small("", fmt_mbit(app.disp_down)),
        small("peak", fmt_rate(st.down_peak)),
        small("total", fmt_bytes(st.down_total as f64)),
        Line::raw(""),
        big("▲", app.disp_up, UP),
        small("", fmt_mbit(app.disp_up)),
        small("peak", fmt_rate(st.up_peak)),
        small("total", fmt_bytes(st.up_total as f64)),
    ];
    let sideblock = Block::new().borders(ratatui::widgets::Borders::LEFT).border_style(Style::new().fg(BORDER));
    f.render_widget(Paragraph::new(lines).block(sideblock), side);
}

/// Animated data flow: arrows move faster when there is more traffic.
fn draw_flow(f: &mut Frame, area: Rect, app: &App) {
    let block = panel("flow");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let exit = app
        .stats
        .public_ip
        .as_deref()
        .and_then(|s| s.split_once("  ").map(|x| x.1.to_string()))
        .unwrap_or_else(|| "server".into());
    let ip = app.session.as_ref().and_then(|s| s.server_ips.first()).map(|i| format!(" {i}")).unwrap_or_default();
    let exit = format!("{exit}{ip}");
    let label_w = 8usize;
    let right = format!(" ◎ {}", exit);
    let w = (inner.width as usize).saturating_sub(label_w + right.chars().count() + 2).max(6);
    let lane = |offset: f64, rev: bool, active: bool, c: Color| -> Span<'static> {
        let off = offset as usize;
        let s: String = (0..w)
            .map(|i| {
                let k = if rev { (i + off) % 6 } else { (w - i + off) % 6 };
                if !active { '┄' } else if k == 0 { if rev { '◂' } else { '▸' } } else if k == 1 { '━' } else { '─' }
            })
            .collect();
        Span::styled(s, Style::new().fg(if active { c } else { BORDER }))
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(" ◉ you   ", Style::new().fg(TEXT).bold()),
            lane(app.flow_up, false, app.disp_up > 512.0, UP),
            Span::styled(right.clone(), Style::new().fg(TEXT).bold()),
        ]),
        Line::from(vec![
            Span::styled("         ", Style::new()),
            lane(app.flow_down, true, app.disp_down > 512.0, DOWN),
            Span::styled(format!("  ▼ {}", fmt_rate(app.disp_down)), Style::new().fg(DOWN)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn spark_line(data: &std::collections::VecDeque<u64>, w: usize) -> Vec<u64> {
    data.iter().rev().take(w).rev().copied().collect()
}

fn kvline(k: &str, v: String, c: Color) -> Line<'static> {
    Line::from(vec![Span::styled(format!(" {k:<9}"), Style::new().fg(DIM)), Span::styled(v, Style::new().fg(c))])
}

fn fmt_num(n: u64) -> String {
    if n >= 1_000_000 { format!("{:.1}M", n as f64 / 1e6) } else if n >= 10_000 { format!("{:.1}k", n as f64 / 1e3) } else { n.to_string() }
}

fn draw_packets(f: &mut Frame, area: Rect, app: &App) {
    let st = &app.stats;
    let block = panel("packets");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [txt, s1, s2] = Layout::vertical([Constraint::Length(3), Constraint::Length(2), Constraint::Min(1)]).areas(inner);
    let errc = if st.if_errors + st.if_dropped > 0 { WARN } else { TEXT };
    f.render_widget(
        Paragraph::new(vec![
            kvline("▼ in", format!("{}/s  Σ {}", fmt_num(st.rx_pps_now), fmt_num(st.rx_packets)), DOWN),
            kvline("▲ out", format!("{}/s  Σ {}", fmt_num(st.tx_pps_now), fmt_num(st.tx_packets)), UP),
            kvline("err/drop", format!("{} / {}", st.if_errors, st.if_dropped), errc),
        ]),
        txt,
    );
    let w = inner.width as usize;
    f.render_widget(Sparkline::default().data(spark_line(&st.rx_pps, w)).style(Style::new().fg(DOWN)), s1);
    f.render_widget(Sparkline::default().data(spark_line(&st.tx_pps, w)).style(Style::new().fg(UP)), s2);
}

fn draw_latency(f: &mut Frame, area: Rect, app: &App) {
    let Some(s) = &app.session else { return };
    let st = &app.stats;
    let (lat_txt, lat_col) = match st.latency {
        Some(ms) if ms < 150 => (format!("{ms} ms"), DOWN),
        Some(ms) if ms < 400 => (format!("{ms} ms"), WARN),
        Some(ms) => (format!("{ms} ms"), ERR),
        None if st.lat_fail > 0 => ("timeout".into(), ERR),
        None => ("…".into(), DIM),
    };
    let block = panel("latency · core");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [txt, sp] = Layout::vertical([Constraint::Length(4), Constraint::Min(1)]).areas(inner);
    let (mn, mx) = st.lat.iter().fold((u64::MAX, 0), |(a, b), &v| (a.min(v), b.max(v)));
    let jitter = if st.lat.len() > 1 { format!("  min {mn} max {mx}") } else { String::new() };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" rtt      ", Style::new().fg(DIM)),
                Span::styled(lat_txt, Style::new().fg(lat_col).bold()),
                Span::styled(jitter, Style::new().fg(DIM)),
            ]),
            kvline("cpu/mem", format!("{:.1}%  {}", st.cpu, fmt_bytes(st.rss_kb as f64 * 1024.0)), TEXT),
            kvline("reconn.", format!("{} quic · {} core", s.reconnects, s.restarts), TEXT),
            kvline("exit", st.public_ip.clone().unwrap_or_else(|| "…".into()), ACCENT),
        ]),
        txt,
    );
    f.render_widget(Sparkline::default().data(spark_line(&st.lat, sp.width as usize)).style(Style::new().fg(lat_col)), sp);
}

fn draw_sessions(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.traffic;
    let st = &app.stats;
    let (ot, ou) = t.open_count();
    let block = panel("sessions");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [txt, sp] = Layout::vertical([Constraint::Length(4), Constraint::Min(1)]).areas(inner);
    let avg = st.dns_ms_sum.checked_div(st.dns_queries).unwrap_or(0);
    let new_s: u64 = st.conn_rate.iter().rev().take(2).sum();
    f.render_widget(
        Paragraph::new(vec![
            kvline("open", format!("{ot} tcp · {ou} udp   +{new_s}/s"), TEXT),
            kvline("total", format!("{} tcp · {} udp", fmt_num(t.total_tcp), fmt_num(t.total_udp)), TEXT),
            kvline("errors", t.errors.to_string(), if t.errors > 0 { WARN } else { TEXT }),
            match app.session.as_ref().and_then(|s| s.mixed.as_ref()) {
                Some(m) => kvline("proxy", format!("{} · {} active · {} total", m.listen,
                    m.c.active.load(std::sync::atomic::Ordering::Relaxed),
                    m.c.total.load(std::sync::atomic::Ordering::Relaxed)), ACCENT),
                None => match app.session.as_ref().and_then(|s| s.bypass.as_ref()) {
                    Some(b) => kvline("direct", format!("{} IPs outside the tunnel (notToVPN)", b.count()), DOWN),
                    None => kvline("dns", format!("{} q · {} ms avg · {} fail", fmt_num(st.dns_queries), avg, st.dns_fail), TEXT),
                },
            },
        ]),
        txt,
    );
    f.render_widget(Sparkline::default().data(spark_line(&st.conn_rate, sp.width as usize)).style(Style::new().fg(TITLE)), sp);
}

fn conn_dest(app: &App, c: &crate::traffic::Conn) -> (String, String) {
    let dst = c.dst.clone().unwrap_or_else(|| "(udp session)".into());
    let name = c.domain.clone().unwrap_or_default();
    let _ = app;
    (dst, name)
}

fn draw_live(f: &mut Frame, area: Rect, app: &App) {
    let h = area.height.saturating_sub(2) as usize;
    let w = area.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = app
        .traffic
        .conns
        .iter()
        .rev()
        .take(h)
        .map(|c| {
            let (dot, dc) = match (c.is_open(), &c.error) {
                (true, _) => ("●", DOWN),
                (false, Some(_)) => ("✕", ERR),
                (false, None) => ("○", DIM),
            };
            let fresh = c.opened.elapsed().as_millis() < 1200;
            let (dst, name) = conn_dest(app, c);
            let who = if name.is_empty() { dst.clone() } else { format!("{name}  {dst}") };
            let app_s = c.app.clone().unwrap_or_default();
            let mut s = vec![
                Span::styled(format!(" {dot} "), Style::new().fg(dc)),
                Span::styled(format!("{} ", c.time), Style::new().fg(DIM)),
                Span::styled(format!("{:<5}", match (c.via, c.proto) { ("socks", _) => "SOCK", ("http", _) => "HTTP", (_, crate::traffic::Proto::Tcp) => "TCP", _ => "UDP" }), Style::new().fg(TITLE)),
                Span::styled(format!("{app_s:<12.12} "), Style::new().fg(ACCENT)),
            ];
            let rest = w.saturating_sub(30);
            let who: String = who.chars().take(rest).collect();
            s.push(Span::styled(who, if fresh { Style::new().fg(Color::White).bold() } else { Style::new().fg(TEXT) }));
            Line::from(s)
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(panel("live connections")), area);
}

fn draw_top(f: &mut Frame, area: Rect, app: &App) {
    let h = area.height.saturating_sub(2) as usize;
    let w = area.width.saturating_sub(2) as usize;
    let top = app.traffic.top_domains(h);
    let max = top.first().map(|x| x.1).unwrap_or(1).max(1);
    let bar_w = (w / 3).max(4);
    let name_w = w.saturating_sub(bar_w + 7);
    let lines: Vec<Line> = top
        .iter()
        .map(|(d, n)| {
            let filled = ((*n as f64 / max as f64) * bar_w as f64).ceil() as usize;
            let name: String = if d.chars().count() > name_w {
                let tail: String = d.chars().rev().take(name_w.saturating_sub(1)).collect::<Vec<_>>().into_iter().rev().collect();
                format!("…{tail}")
            } else {
                d.clone()
            };
            Line::from(vec![
                Span::styled(format!(" {name:<name_w$} "), Style::new().fg(TEXT)),
                Span::styled("▆".repeat(filled), Style::new().fg(ACCENT)),
                Span::styled("▁".repeat(bar_w - filled.min(bar_w)), Style::new().fg(BORDER)),
                Span::styled(format!(" {n:>3}"), Style::new().fg(DIM)),
            ])
        })
        .collect();
    let body = if lines.is_empty() { vec![Line::styled(" waiting for traffic…", Style::new().fg(DIM))] } else { lines };
    f.render_widget(Paragraph::new(body).block(panel("top destinations")), area);
}

fn draw_conn_table(f: &mut Frame, area: Rect, app: &App) {
    let rows_h = area.height.saturating_sub(3) as usize;
    let list: Vec<&crate::traffic::Conn> =
        app.traffic.conns.iter().rev().filter(|c| !app.only_open || c.is_open()).collect();
    let rows: Vec<Row> = list
        .iter()
        .skip(app.conn_scroll)
        .take(rows_h)
        .map(|c| {
            let (state, sc) = match (c.is_open(), &c.error) {
                (true, _) => ("● open".to_string(), DOWN),
                (false, Some(e)) => (format!("✕ {}", e.chars().take(24).collect::<String>()), ERR),
                (false, None) => ("○ closed".to_string(), DIM),
            };
            let dur = c.closed.unwrap_or_else(std::time::Instant::now).duration_since(c.opened).as_secs();
            let (dst, name) = conn_dest(app, c);
            Row::new(vec![
                Cell::from(c.time.clone()).style(Style::new().fg(DIM)),
                Cell::from(match (c.via, c.proto) { ("socks", _) => "SOCK", ("http", _) => "HTTP", (_, crate::traffic::Proto::Tcp) => "TCP", _ => "UDP" }).style(Style::new().fg(TITLE)),
                Cell::from(c.app.clone().unwrap_or_else(|| "·".into())).style(Style::new().fg(ACCENT)),
                Cell::from(dst).style(Style::new().fg(TEXT)),
                Cell::from(name).style(Style::new().fg(Color::White)),
                Cell::from(fmt_dur(dur)).style(Style::new().fg(DIM)),
                Cell::from(state).style(Style::new().fg(sc)),
            ])
        })
        .collect();
    let (ot, ou) = app.traffic.open_count();
    let title = format!(
        "connections · {} open ({ot} tcp, {ou} udp) · {}{}",
        ot + ou,
        if app.only_open { "open only [o]" } else { "all [o]" },
        if app.conn_scroll > 0 { format!(" · ↑{}", app.conn_scroll) } else { String::new() }
    );
    let t = Table::new(
        rows,
        [
            Constraint::Length(8), Constraint::Length(5), Constraint::Length(14), Constraint::Length(24),
            Constraint::Min(16), Constraint::Length(8), Constraint::Length(26),
        ],
    )
    .header(
        Row::new(["time", "", "app", "destination", "domain", "dur", "state"])
            .style(Style::new().fg(DIM).add_modifier(Modifier::UNDERLINED)),
    )
    .block(panel(&title));
    f.render_widget(t, area);
}

fn draw_dns_table(f: &mut Frame, area: Rect, app: &App) {
    let rows_h = area.height.saturating_sub(3) as usize;
    let rows: Vec<Row> = app
        .dns_log
        .iter()
        .rev()
        .skip(app.dns_scroll)
        .take(rows_h)
        .map(|e| {
            let sc = if e.status == "NOERROR" { DOWN } else if e.status == "NXDOMAIN" { WARN } else { ERR };
            let ans = if !e.ips.is_empty() {
                let mut a = e.ips.iter().take(2).map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
                if e.ips.len() > 2 { a.push_str(&format!(" +{}", e.ips.len() - 2)); }
                a
            } else if let Some(c) = &e.cname {
                format!("→ {c}")
            } else {
                "—".into()
            };
            let msc = if e.ms < 80 { DOWN } else if e.ms < 300 { WARN } else { ERR };
            Row::new(vec![
                Cell::from(e.time.clone()).style(Style::new().fg(DIM)),
                Cell::from(format!("{:>4}ms", e.ms)).style(Style::new().fg(msc)),
                Cell::from(if e.direct { format!("{}⇢", e.qtype) } else if e.tcp { format!("{}/t", e.qtype) } else { e.qtype.clone() })
                    .style(Style::new().fg(if e.direct { DOWN } else { TITLE })),
                Cell::from(e.name.clone()).style(Style::new().fg(Color::White)),
                Cell::from(ans).style(Style::new().fg(TEXT)),
                Cell::from(e.status.clone()).style(Style::new().fg(sc)),
            ])
        })
        .collect();
    let st = &app.stats;
    let avg = st.dns_ms_sum.checked_div(st.dns_queries).unwrap_or(0);
    let title = format!("dns · {} queries · avg {avg} ms · {} failed{}", st.dns_queries, st.dns_fail,
        if app.dns_scroll > 0 { format!(" · ↑{}", app.dns_scroll) } else { String::new() });
    let t = Table::new(
        rows,
        [Constraint::Length(8), Constraint::Length(7), Constraint::Length(7), Constraint::Min(20), Constraint::Length(36), Constraint::Length(9)],
    )
    .header(Row::new(["time", "rtt", "type", "domain", "answer", "status"]).style(Style::new().fg(DIM).add_modifier(Modifier::UNDERLINED)))
    .block(panel(&title));
    if app.dns_log.is_empty() {
        let msg = if app.session.as_ref().map(|s| s.dns_server.is_some()).unwrap_or(false) {
            " no DNS queries yet"
        } else {
            " DNS logging is off (override_dns = false in config)"
        };
        f.render_widget(Paragraph::new(Line::styled(msg, Style::new().fg(DIM))).block(panel("dns")), area);
    } else {
        f.render_widget(t, area);
    }
}

fn draw_logs(f: &mut Frame, area: Rect, app: &App) {
    let h = area.height.saturating_sub(2) as usize;
    let total = app.logs.len();
    let end = total.saturating_sub(app.log_scroll);
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = app
        .logs
        .iter()
        .skip(start)
        .take(end - start)
        .map(|l| {
            let (tag, c) = match l.level {
                Level::Debug => ("DBG", DIM),
                Level::Info => ("INF", TITLE),
                Level::Warn => ("WRN", WARN),
                Level::Error => ("ERR", ERR),
            };
            Line::from(vec![
                Span::styled(format!(" {} ", l.time), Style::new().fg(DIM)),
                Span::styled(format!("{tag} "), Style::new().fg(c).bold()),
                Span::styled(l.msg.clone(), Style::new().fg(TEXT)),
                Span::styled(if l.fields.is_empty() { String::new() } else { format!("  {}", l.fields) }, Style::new().fg(DIM)),
            ])
        })
        .collect();
    let title = if app.log_scroll > 0 { format!("log  (↑{} — End to follow)", app.log_scroll) } else { "log".into() };
    f.render_widget(Paragraph::new(lines).block(panel(&title)), area);
}

// ---------------------------------------------------------------- popups

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(2));
    let h = h.min(area.height.saturating_sub(2));
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

fn draw_popup(f: &mut Frame, app: &App) {
    match &app.popup {
        Popup::None => {}
        Popup::Input { title, hint, buf, .. } => {
            let r = centered(f.area(), 90, 7);
            f.render_widget(Clear, r);
            let inner_w = r.width.saturating_sub(4) as usize;
            let chars: Vec<char> = buf.chars().collect();
            let shown: String = chars.iter().skip(chars.len().saturating_sub(inner_w.saturating_sub(1))).collect();
            let p = Paragraph::new(vec![
                Line::styled(hint.clone(), Style::new().fg(DIM)),
                Line::raw(""),
                Line::from(vec![
                    Span::styled(shown, Style::new().fg(TEXT)),
                    Span::styled("█", Style::new().fg(ACCENT).add_modifier(Modifier::SLOW_BLINK)),
                ]),
            ])
            .block(panel(title.trim()).border_style(Style::new().fg(ACCENT)));
            f.render_widget(p, r);
        }
        Popup::Dns { sel, adding, reset_armed } => {
            let list = &app.store.settings.dns;
            let h = (list.len() as u16 + 12).min(f.area().height.saturating_sub(2));
            let r = centered(f.area(), 70, h);
            f.render_widget(Clear, r);
            let mut lines = vec![
                Line::styled(" Order = priority: the first server is asked first, the next one if it fails.", Style::new().fg(DIM)),
                Line::raw(""),
            ];
            for (i, ip) in list.iter().enumerate() {
                let selected = i == *sel;
                let ms = match app.dns_times.get(ip) {
                    Some(Some(ms)) => Span::styled(format!("{ms:>5} ms"), Style::new().fg(if *ms < 80 { DOWN } else if *ms < 250 { WARN } else { ERR })),
                    Some(None) => Span::styled("  no answer", Style::new().fg(ERR)),
                    None => Span::raw(""),
                };
                let mark = if selected { "▶" } else { " " };
                let st = if selected { Style::new().fg(Color::Black).bg(TITLE).bold() } else { Style::new().fg(TEXT) };
                lines.push(Line::from(vec![
                    Span::styled(format!(" {mark} {}. ", i + 1), Style::new().fg(DIM)),
                    Span::styled(format!(" {ip:<18} "), st),
                    Span::styled(format!(" {:<11}", crate::dns::provider_of(ip)), Style::new().fg(DIM)),
                    ms,
                    if i == 0 { Span::styled("  primary", Style::new().fg(ACCENT)) } else { Span::raw("") },
                ]));
            }
            lines.push(Line::raw(""));
            if let Some(buf) = adding {
                lines.push(Line::from(vec![
                    Span::styled(" add: ", Style::new().fg(ACCENT).bold()),
                    Span::styled(buf.clone(), Style::new().fg(TEXT)),
                    Span::styled("█", Style::new().fg(ACCENT)),
                ]));
                lines.push(Line::styled(" IP address(es) or: cloudflare, google, quad9, adguard, opendns — Enter to add", Style::new().fg(DIM)));
            } else {
                let k = |key: &str, l: &str| vec![Span::styled(format!(" {key} "), Style::new().fg(Color::Black).bg(TITLE).bold()), Span::styled(format!(" {l} "), Style::new().fg(DIM))];
                let mut l1 = vec![];
                for (a, b) in [("a", "add"), ("d", "delete"), ("K/J", "priority ↑↓"), ("t", "speed test")] { l1.extend(k(a, b)); }
                let mut l2 = vec![];
                for (a, b) in [("r r", "reset to defaults"), ("Esc", "close")] { l2.extend(k(a, b)); }
                lines.push(Line::from(l1));
                lines.push(Line::from(l2));
                if *reset_armed {
                    lines.push(Line::styled(" press r again to reset to 1.1.1.1, 8.8.8.8", Style::new().fg(WARN).bold()));
                }
            }
            let live = app.session.as_ref().is_some_and(|s| s.dns_server.is_some());
            let title = if live { "DNS servers — changes apply live" } else { "DNS servers — saved for next runs" };
            f.render_widget(Paragraph::new(lines).block(panel(title).border_style(Style::new().fg(ACCENT))), r);
        }
        Popup::Confirm { text, .. } => {
            let r = centered(f.area(), (text.chars().count() as u16 + 6).max(30), 3);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(Span::styled(text.clone(), Style::new().fg(TEXT).bold()))
                    .alignment(Alignment::Center)
                    .block(panel("confirm").border_style(Style::new().fg(ERR))),
                r,
            );
        }
        Popup::Help => {
            let r = centered(f.area(), 74, 27);
            f.render_widget(Clear, r);
            let h = |k: &str, d: &str| {
                Line::from(vec![Span::styled(format!("  {k:<16}"), Style::new().fg(TITLE).bold()), Span::styled(d.to_string(), Style::new().fg(TEXT))])
            };
            let lines = vec![
                Line::styled(" profiles", Style::new().fg(ACCENT).bold()),
                h("Enter / c", "connect selected profile (full-system VPN)"),
                h("v / p", "add link(s) from system clipboard"),
                h("Ctrl+Shift+V", "paste anywhere — links are added instantly"),
                h("a", "add by typing / pasting into a box"),
                h("m", "mode: TUN+proxy / proxy only / TUN only"),
                h("n / N", "notToVPN list: edit / turn on-off"),
                h("D", "DNS servers: add, delete, priority, reset"),
                h("b", "bandwidth up/down Mbit/s (Brutal = faster)"),
                h("r / d", "rename / delete"),
                Line::raw(""),
                Line::styled(" dashboard", Style::new().fg(ACCENT).bold()),
                h("1 2 3 4 / ← →", "overview · connections · DNS · log"),
                h("o", "connections: only open / all"),
                h("x", "disconnect (DNS + routes restored)"),
                h("r", "reconnect"),
                h("i", "refresh exit IP"),
                h("↑ ↓ PgUp/Dn End", "scroll current table / follow"),
                h("C", "clear current table"),
                Line::raw(""),
                h("Tab", "switch screen"),
                h("q / Ctrl+C", "quit (always disconnects cleanly)"),
                Line::raw(""),
                Line::styled("  any key closes this help", Style::new().fg(DIM)),
            ];
            f.render_widget(Paragraph::new(lines).block(panel("help").border_style(Style::new().fg(ACCENT))), r);
        }
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use crate::app::{App, Screen, Session, Status, Tab};
    use crate::store::{Paths, Profile, Store};
    use ratatui::backend::TestBackend;
    use std::time::{Duration, Instant};

    fn dump(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn demo() -> App {
        let mut store = Store::default();
        store.profiles.push(Profile {
            name: "lab (Netherlands)".into(),
            uri: "hy2://secretpass@vpn.example.com:45765?obfs=salamander&obfs-password=obfspw&sni=vpn.example.com#lab".into(),
            up_mbps: Some(50),
            down_mbps: Some(200),
        });
        store.profiles.push(Profile { name: "backup".into(), uri: "hy2://pw@203.0.113.9:443".into(), up_mbps: None, down_mbps: None });
        App::new(Paths::detect(), store, None)
    }

    #[test]
    #[ignore]
    fn show_screens() {
        let mut app = demo();
        println!("{}\n", dump(&app, 120, 24));
        let p = app.store.profiles[0].clone();
        app.session = Some(Session {
            uri: crate::uri::Hy2Uri::parse(&p.uri).unwrap(),
            profile: p,
            server_ips: vec!["203.0.113.7".parse().unwrap()],
            cfg_path: "/nonexistent".into(),
            child: None,
            started: Instant::now() - Duration::from_secs(3725),
            connected_at: Some(Instant::now() - Duration::from_secs(3720)),
            restarts: 0, reconnects: 1, next_restart: None, dns: None, dns_server: None, mixed: None, bypass: None, sysctl_restore: vec![],
        });
        app.status = Status::Connected;
        app.screen = Screen::Dashboard;
        for i in 0..400 {
            let x = i as f64 / 9.0;
            app.stats.down.push_back((x.sin().abs() * 9.0 + (i % 17) as f64 * 0.3) * 1024.0 * 1024.0);
            app.stats.up.push_back(((x * 0.7).cos().abs() * 1.5) * 1024.0 * 1024.0);
        }
        app.stats.down_now = 8.4 * 1024.0 * 1024.0; app.stats.up_now = 1.1 * 1024.0 * 1024.0;
        app.stats.down_peak = 11.2 * 1024.0 * 1024.0; app.stats.up_peak = 2.0 * 1024.0 * 1024.0;
        app.stats.down_total = 3_400_000_000; app.stats.up_total = 220_000_000;
        app.stats.latency = Some(96); app.stats.cpu = 7.5; app.stats.rss_kb = 41_000;
        app.stats.lat.extend([90, 95, 120, 96, 101, 93, 96, 140, 98, 96]);
        app.stats.public_ip = Some("203.0.113.7  Netherlands, Amsterdam".into());
        app.log(crate::core::Level::Info, "DNS → 1.1.1.1, 8.8.8.8 (through tunnel), queries logged");
        app.push_test_log(crate::core::parse_log(r#"{"level":"info","msg":"connected to server","addr":"203.0.113.7:45765","udpEnabled":true,"count":2}"#));
        let names = [("github.com","140.82.121.4"),("www.youtube.com","142.250.74.14"),("api.telegram.org","149.154.167.220"),("rr3---sn-4g5e6nsz.googlevideo.com","173.194.18.40"),("discord.com","162.159.137.232")];
        for (i,(n,ip)) in names.iter().enumerate() {
            app.dns_log.push_back(crate::dns::DnsEvent{ time:"09:58:0".to_string()+&i.to_string(), name:n.to_string(), qtype:"A".into(), ips:vec![ip.parse().unwrap()], cname:None, ms: 40+i as u64*37, status:"NOERROR".into(), tcp: i==3, direct: i==2 });
            app.traffic.learn_dns(n, &[ip.parse().unwrap()]);
        }
        app.dns_log.push_back(crate::dns::DnsEvent{ time:"09:58:09".into(), name:"nonexistent.example".into(), qtype:"AAAA".into(), ips:vec![], cname:None, ms: 120, status:"NXDOMAIN".into(), tcp:false, direct:false });
        for (i, (_, ip)) in names.iter().cycle().take(14).enumerate() {
            let ev = format!(r#"{{"level":"debug","msg":"TUN TCP request","addr":"100.100.100.101:{}","reqAddr":"{}:443"}}"#, 40000+i, ip);
            app.traffic.on_log(&crate::core::parse_log(&ev));
            if i % 3 == 0 {
                let ev = format!(r#"{{"level":"debug","msg":"TUN TCP closed","addr":"100.100.100.101:{}","reqAddr":"{}:443"}}"#, 40000+i, ip);
                app.traffic.on_log(&crate::core::parse_log(&ev));
            }
        }
        app.traffic.on_log(&crate::core::parse_log(r#"{"level":"warn","msg":"TUN TCP error","addr":"100.100.100.101:40013","reqAddr":"162.159.137.232:443","error":"connection reset"}"#));
        app.traffic.on_log(&crate::core::parse_log(r#"{"level":"debug","msg":"TUN UDP request","addr":"100.100.100.101:5353"}"#));
        let apps: std::collections::HashMap<u16,String> = (0..14u16).map(|i| (40000+i, ["firefox","telegram-deskto","curl","mpv"][i as usize % 4].to_string())).collect();
        app.traffic.set_apps(&apps);
        for i in 0..300u64 { app.stats.rx_pps.push_back(800 + (i*37)%900); app.stats.tx_pps.push_back(300+(i*13)%400); app.stats.conn_rate.push_back((i*7)%5); }
        app.stats.rx_pps_now = 1340; app.stats.tx_pps_now = 512; app.stats.rx_packets = 2_340_000; app.stats.tx_packets = 910_000;
        app.stats.dns_queries = 6; app.stats.dns_ms_sum = 6*95; app.stats.dns_fail = 1;
        app.disp_down = app.stats.down_now; app.disp_up = app.stats.up_now; app.flow_down = 7.0; app.flow_up = 3.0; app.frame = 30;
        for t in [Tab::Overview, Tab::Connections, Tab::Dns] {
            app.tab = t;
            println!("{}\n", dump(&app, 130, 44));
        }
        // connecting animation
        if let Some(s) = &mut app.session { s.connected_at = None; }
        app.status = Status::Connecting; app.tab = Tab::Overview;
        println!("{}", dump(&app, 130, 16));
        app.session = None; // avoid Drop side effects mattering
    }
}
