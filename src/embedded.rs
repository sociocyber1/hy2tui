//! The official hysteria core, embedded in the hy2tui binary (xz-compressed),
//! so no download is needed — useful where GitHub is blocked.
//! Unpacked once to ~/.local/share/hy2tui/bin/hysteria and SHA-256 checked.

use crate::store::Paths;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;

#[cfg(all(embedded_core, target_arch = "x86_64"))]
const DATA: &[(&str, &[u8])] = &[
    ("hysteria-linux-amd64-avx", include_bytes!("../vendor/hysteria-linux-amd64-avx.xz")),
    ("hysteria-linux-amd64", include_bytes!("../vendor/hysteria-linux-amd64.xz")),
];
#[cfg(all(embedded_core, target_arch = "aarch64"))]
const DATA: &[(&str, &[u8])] = &[("hysteria-linux-arm64", include_bytes!("../vendor/hysteria-linux-arm64.xz"))];
#[cfg(not(embedded_core))]
const DATA: &[(&str, &[u8])] = &[];

#[cfg(embedded_core)]
const VERSION: &str = include_str!("../vendor/VERSION");
#[cfg(not(embedded_core))]
const VERSION: &str = "";
#[cfg(embedded_core)]
const SUMS: &str = include_str!("../vendor/SHA256SUMS");
#[cfg(not(embedded_core))]
const SUMS: &str = "";

pub fn version() -> Option<&'static str> {
    (!DATA.is_empty()).then(|| VERSION.trim())
}

fn sha256_of(r: &mut impl Read) -> Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

/// Unpack the embedded core for this CPU into the data dir.
pub fn extract(paths: &Paths) -> Result<PathBuf> {
    if DATA.is_empty() {
        bail!("this hy2tui build has no embedded core");
    }
    let want_asset = crate::core::asset_name()?;
    let (asset, data) = DATA
        .iter()
        .find(|(n, _)| *n == want_asset)
        .or_else(|| DATA.last())
        .context("no embedded core for this CPU")?;
    let want = SUMS
        .lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            let (h, f) = (it.next()?, it.next()?);
            (f == *asset).then(|| h.to_lowercase())
        })
        .context("embedded checksum missing")?;

    let bin_dir = paths.data_dir.join("bin");
    paths.mkdir(&bin_dir, 0o755)?;
    let dest = bin_dir.join("hysteria");
    if let Ok(mut f) = fs::File::open(&dest) {
        if sha256_of(&mut f)? == want {
            return Ok(dest); // already unpacked
        }
    }
    let tmp = bin_dir.join("hysteria.unpack");
    {
        let mut out = BufWriter::new(fs::File::create(&tmp)?);
        lzma_rs::xz_decompress(&mut std::io::Cursor::new(*data), &mut out).context("embedded core is corrupt")?;
        out.flush()?;
    }
    if sha256_of(&mut fs::File::open(&tmp)?)? != want {
        let _ = fs::remove_file(&tmp);
        bail!("embedded core failed the SHA-256 check");
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, &dest)?;
    paths.give_back(&dest);
    Ok(dest)
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(embedded_core)]
    fn embedded_core_unpacks_and_matches_checksum() {
        let dir = std::env::temp_dir().join(format!("hy2tui-emb-{}", std::process::id()));
        let paths = crate::store::Paths {
            config_dir: dir.join("cfg"),
            config_file: dir.join("cfg/config.toml"),
            data_dir: dir.join("data"),
            owner: None,
        };
        let p = super::extract(&paths).expect("extract");
        assert!(p.metadata().unwrap().len() > 10_000_000);
        // second call: already unpacked, checksum still matches
        assert_eq!(super::extract(&paths).unwrap(), p);
        let _ = std::fs::remove_dir_all(dir);
    }
}
