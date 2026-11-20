//! Fast, resumable downloader (tokio + reqwest).
//!
//! * The file is cut into chunks; N async streams take chunks from a shared
//!   queue (a fast connection simply takes more chunks).
//! * Bytes are written straight into a preallocated `.part` file at their
//!   offset; per-chunk progress is saved to `.state` twice a second.
//!   Ctrl-C, a dead connection or a reboot → run again → continues.
//! * A stream that receives nothing for 20 s is dropped and its chunk
//!   continues on a new connection. If the whole network is down, it waits
//!   (2 s … 30 s back-off) and resumes when the network is back.

use anyhow::{bail, Context, Result};
use reqwest::{header, Client, StatusCode};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const IDLE: Duration = Duration::from_secs(20);
const MIN_CHUNK: u64 = 512 * 1024;
const MAX_IDLE_ROUNDS: u32 = 60; // ~25 min without a single byte → give up (rerun continues)

pub struct Opts {
    pub jobs: usize,
    pub proxy: Option<String>,
}

pub fn client(opts: &Opts, follow: bool) -> Result<Client> {
    let mut b = Client::builder()
        .user_agent("hy2tui")
        .connect_timeout(Duration::from_secs(15))
        .tcp_keepalive(Duration::from_secs(15))
        .redirect(if follow { reqwest::redirect::Policy::limited(10) } else { reqwest::redirect::Policy::none() });
    if let Some(p) = &opts.proxy {
        b = b.proxy(reqwest::Proxy::all(p).context("bad --proxy URL")?);
    }
    Ok(b.build()?)
}

/// Where a URL finally points, and its size.
pub struct Resolved {
    pub url: String,
    pub hops: Vec<String>,
    pub size: Option<u64>,
    pub ranges: bool,
}

/// Walk redirects by hand (so we can see versioned GitHub URLs) and probe
/// the final URL with `Range: bytes=0-0`.
pub async fn resolve(c: &Client, url: &str) -> Result<Resolved> {
    let mut cur = reqwest::Url::parse(url)?;
    let mut hops = vec![];
    for _ in 0..10 {
        let r = c.get(cur.clone()).header(header::RANGE, "bytes=0-0").send().await?;
        if r.status().is_redirection() {
            let loc = r.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).context("redirect without Location")?;
            cur = cur.join(loc)?;
            hops.push(cur.to_string());
            continue;
        }
        let st = r.status();
        let h = r.headers();
        return match st {
            StatusCode::PARTIAL_CONTENT => {
                let size = h
                    .get(header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.rsplit('/').next()?.parse().ok());
                Ok(Resolved { url: cur.to_string(), hops, size, ranges: size.is_some() })
            }
            StatusCode::OK => Ok(Resolved { url: cur.to_string(), hops, size: r.content_length(), ranges: false }),
            s => bail!("{s} for {cur}"),
        };
    }
    bail!("too many redirects")
}

pub async fn fetch_text(c: &Client, url: &str) -> Result<String> {
    let r = c.get(url).send().await?.error_for_status()?;
    Ok(r.text().await?)
}

// ---------------------------------------------------------------- state

struct Shared {
    file: File,
    total: u64,
    chunk: u64,
    done: Vec<AtomicU64>,
    url: Mutex<String>,
    expired: AtomicBool,
    last_err: Mutex<String>,
}

impl Shared {
    fn nchunks(&self) -> usize { self.done.len() }
    fn chunk_len(&self, i: usize) -> u64 {
        let s = i as u64 * self.chunk;
        (s + self.chunk).min(self.total) - s
    }
    fn missing(&self) -> Vec<usize> {
        (0..self.nchunks()).filter(|&i| self.done[i].load(Ordering::Relaxed) < self.chunk_len(i)).collect()
    }
    fn have(&self) -> u64 { self.done.iter().map(|d| d.load(Ordering::Relaxed)).sum() }
}

fn state_header(key: &str, total: u64, chunk: u64) -> String {
    format!("hy2tui-dl v1 {key} {total} {chunk}")
}

/// Save progress: flush data to disk first, so the state never claims
/// bytes that are not really written.
fn save_state(sh: &Shared, state: &Path, key: &str) {
    let _ = sh.file.sync_data();
    let mut s = state_header(key, sh.total, sh.chunk);
    for d in &sh.done {
        s.push('\n');
        s.push_str(&d.load(Ordering::Relaxed).to_string());
    }
    let tmp = state.with_extension("state.tmp");
    if fs::write(&tmp, s).is_ok() {
        let _ = fs::rename(&tmp, state);
    }
}

fn load_state(state: &Path, key: &str, total: u64, chunk: u64, n: usize) -> Option<Vec<u64>> {
    let s = fs::read_to_string(state).ok()?;
    let mut lines = s.lines();
    if lines.next()? != state_header(key, total, chunk) {
        return None;
    }
    let v: Vec<u64> = lines.filter_map(|l| l.trim().parse().ok()).collect();
    (v.len() == n).then_some(v)
}

// ---------------------------------------------------------------- progress

fn human(b: f64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let (mut v, mut i) = (b, 0);
    while v >= 1024.0 && i < 3 { v /= 1024.0; i += 1; }
    format!("{v:.1} {}", U[i])
}

fn bar(frac: f64, w: usize) -> String {
    let cells = frac.clamp(0.0, 1.0) * w as f64;
    let full = cells.floor() as usize;
    let parts = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
    let p = ((cells - full as f64) * 8.0) as usize;
    let mut s = "█".repeat(full);
    if full < w { s.push_str(parts[p.min(7)]); }
    let len = s.chars().count();
    s + &" ".repeat(w.saturating_sub(len))
}

// ---------------------------------------------------------------- download

async fn fetch_chunk(c: &Client, sh: &Shared, i: usize) -> Result<()> {
    let len = sh.chunk_len(i);
    let have = sh.done[i].load(Ordering::Relaxed);
    if have >= len { return Ok(()); }
    let start = i as u64 * sh.chunk + have;
    let end = i as u64 * sh.chunk + len - 1;
    let url = sh.url.lock().unwrap().clone();
    let mut r = tokio::time::timeout(IDLE, c.get(&url).header(header::RANGE, format!("bytes={start}-{end}")).send())
        .await
        .context("no answer in 20 s")??;
    match r.status() {
        StatusCode::PARTIAL_CONTENT => {}
        s if s == StatusCode::FORBIDDEN || s == StatusCode::NOT_FOUND || s == StatusCode::GONE => {
            sh.expired.store(true, Ordering::Relaxed); // signed CDN link expired
            bail!("{s}");
        }
        s => bail!("unexpected {s}"),
    }
    let mut pos = start;
    while pos <= end {
        let Some(bytes) = tokio::time::timeout(IDLE, r.chunk()).await.context("stalled 20 s")?? else { break };
        let take = (bytes.len() as u64).min(end + 1 - pos) as usize;
        sh.file.write_all_at(&bytes[..take], pos)?;
        pos += take as u64;
        sh.done[i].fetch_add(take as u64, Ordering::Relaxed);
    }
    if pos <= end { bail!("connection closed early"); }
    Ok(())
}

/// Download `url` to `dest` (atomically renamed when complete).
/// `key` identifies the content (e.g. version + asset): progress is only
/// reused for the same key.
pub async fn download(url: &str, dest: &Path, key: &str, opts: &Opts, owner: &dyn Fn(&Path)) -> Result<()> {
    let c = client(opts, true)?;
    let c_noredir = client(opts, false)?;
    let mut res = resolve_retry(&c_noredir, url).await?;
    let part: PathBuf = dest.with_extension("part");
    let state: PathBuf = dest.with_extension("state");

    let Some(total) = res.size.filter(|_| res.ranges) else {
        eprintln!("server does not support ranges — single stream, no resume");
        let bytes = c.get(&res.url).send().await?.error_for_status()?.bytes().await?;
        fs::write(&part, &bytes)?;
        fs::rename(&part, dest)?;
        return Ok(());
    };

    let jobs = opts.jobs.clamp(1, 64);
    let chunk = (total / (jobs as u64 * 4)).max(MIN_CHUNK);
    let n = total.div_ceil(chunk) as usize;

    let saved = (fs::metadata(&part).map(|m| m.len()).ok() == Some(total))
        .then(|| load_state(&state, key, total, chunk, n))
        .flatten();
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&part)?;
    owner(&part);
    let done: Vec<AtomicU64> = match &saved {
        Some(v) => v.iter().enumerate().map(|(i, x)| AtomicU64::new((*x).min((i as u64 * chunk + chunk).min(total) - i as u64 * chunk))).collect(),
        None => {
            file.set_len(0)?;
            file.set_len(total)?;
            (0..n).map(|_| AtomicU64::new(0)).collect()
        }
    };
    let sh = Arc::new(Shared {
        file, total, chunk, done,
        url: Mutex::new(res.url.clone()),
        expired: AtomicBool::new(false),
        last_err: Mutex::new(String::new()),
    });
    let have0 = sh.have();
    if have0 > 0 {
        eprintln!("resuming: {} of {} already downloaded", human(have0 as f64), human(total as f64));
    }
    eprintln!("downloading {} with {jobs} streams ({n} chunks)", human(total as f64));
    save_state(&sh, &state, key);
    owner(&state);

    // progress + periodic state save
    let stop = Arc::new(AtomicBool::new(false));
    let ticker = {
        let (sh, stop, state, key) = (sh.clone(), stop.clone(), state.clone(), key.to_string());
        let tty = std::io::stderr().is_terminal();
        tokio::spawn(async move {
            let t0 = Instant::now();
            let mut last = (sh.have(), Instant::now());
            let mut speed = 0.0f64;
            let mut n = 0u32;
            while !stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(250)).await;
                n += 1;
                let have = sh.have();
                let dt = last.1.elapsed().as_secs_f64().max(0.001);
                let inst = (have - last.0.min(have)) as f64 / dt;
                speed = if speed == 0.0 { inst } else { speed * 0.8 + inst * 0.2 };
                last = (have, Instant::now());
                if n.is_multiple_of(2) { save_state(&sh, &state, &key); }
                if tty {
                    let frac = have as f64 / sh.total as f64;
                    let eta = if speed > 1.0 { format!("{:.0}s", (sh.total - have) as f64 / speed) } else { "…".into() };
                    eprint!(
                        "\r  {} {:5.1}%  {:>10} / {:<10} {:>11}/s  eta {:<6} {:>5.0}s ",
                        bar(frac, 28), frac * 100.0, human(have as f64), human(sh.total as f64), human(speed), eta,
                        t0.elapsed().as_secs_f64()
                    );
                    let _ = std::io::stderr().flush();
                }
            }
        })
    };

    let run = async {
        let mut idle_rounds = 0u32;
        let mut backoff = 2u64;
        loop {
            let missing = sh.missing();
            if missing.is_empty() { return Ok::<(), anyhow::Error>(()); }
            if sh.expired.swap(false, Ordering::Relaxed) || idle_rounds > 0 {
                if let Ok(r) = resolve(&c_noredir, url).await {
                    *sh.url.lock().unwrap() = r.url.clone();
                    res = r;
                }
            }
            let before = sh.have();
            let queue = Arc::new(Mutex::new(VecDeque::from(missing)));
            let mut tasks = vec![];
            for _ in 0..jobs {
                let (c, sh, q) = (c.clone(), sh.clone(), queue.clone());
                tasks.push(tokio::spawn(async move {
                    loop {
                        let Some(i) = q.lock().unwrap().pop_front() else { break };
                        if let Err(e) = fetch_chunk(&c, &sh, i).await {
                            *sh.last_err.lock().unwrap() = format!("{e:#}");
                            // retried in the next round, on a fresh connection
                        }
                    }
                }));
            }
            for t in tasks { let _ = t.await; }
            if sh.missing().is_empty() { return Ok(()); }

            if sh.have() > before { idle_rounds = 0; backoff = 2; } else {
                idle_rounds += 1;
                backoff = (backoff * 2).min(30);
                if idle_rounds > MAX_IDLE_ROUNDS {
                    bail!("network unavailable for too long");
                }
            }
            let err = sh.last_err.lock().unwrap().clone();
            eprintln!("\n  connection problem: {}", err.chars().take(90).collect::<String>());
            let wait = if idle_rounds == 0 { 1 } else { backoff };
            eprintln!("  continuing in {wait}s from {} (nothing is lost)", human(sh.have() as f64));
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
    };

    let outcome = tokio::select! {
        r = run => r,
        _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("interrupted")),
    };
    stop.store(true, Ordering::Relaxed);
    let _ = ticker.await;
    save_state(&sh, &state, key);
    eprintln!();

    match outcome {
        Ok(()) => {
            sh.file.sync_all()?;
            fs::rename(&part, dest)?;
            let _ = fs::remove_file(&state);
            Ok(())
        }
        Err(e) => bail!(
            "{e:#}. Downloaded {} of {} is saved — run the same command again to continue.",
            human(sh.have() as f64),
            human(total as f64)
        ),
    }
}

async fn resolve_retry(c: &Client, url: &str) -> Result<Resolved> {
    let mut wait = 2;
    for attempt in 1..=8 {
        match resolve(c, url).await {
            Ok(r) => return Ok(r),
            Err(e) => {
                eprintln!("cannot reach server ({e:#}); retry {attempt}/8 in {wait}s");
                tokio::time::sleep(Duration::from_secs(wait)).await;
                wait = (wait * 2).min(30);
            }
        }
    }
    bail!("server unreachable — check the internet or use --proxy")
}
