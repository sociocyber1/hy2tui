// Embed the hysteria core from vendor/ (xz-compressed) when it is present
// for the target CPU. Without vendor files hy2tui still builds and falls
// back to downloading the core.
use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(embedded_core)");
    println!("cargo::rerun-if-changed=vendor");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let needed: &[&str] = match (os.as_str(), arch.as_str()) {
        ("linux", "x86_64") => &["hysteria-linux-amd64.xz", "hysteria-linux-amd64-avx.xz"],
        ("linux", "aarch64") => &["hysteria-linux-arm64.xz"],
        _ => &[],
    };
    let ok = !needed.is_empty()
        && needed.iter().all(|f| Path::new("vendor").join(f).is_file())
        && Path::new("vendor/SHA256SUMS").is_file()
        && Path::new("vendor/VERSION").is_file();
    if ok {
        println!("cargo::rustc-cfg=embedded_core");
    } else {
        println!("cargo::warning=hysteria core NOT embedded (vendor/ files missing) — it will be downloaded at runtime");
    }
}
