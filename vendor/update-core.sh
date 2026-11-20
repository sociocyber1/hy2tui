#!/bin/sh
# Refresh the hysteria core embedded into hy2tui (run where GitHub is reachable,
# or set PROXY=socks5h://127.0.0.1:1080). Then: cargo build --release
set -e
cd "$(dirname "$0")"
B=https://github.com/apernet/hysteria/releases/latest/download
C="curl -fL --retry 10 --retry-all-errors -C - ${PROXY:+--proxy $PROXY}"
$C -o hashes.txt "$B/hashes.txt"
VER=$(curl -fsSI ${PROXY:+--proxy $PROXY} "$B/hashes.txt" | grep -io 'download/app/v[0-9.]*' | head -1 | sed 's#.*/##')
: > SHA256SUMS
for a in hysteria-linux-amd64 hysteria-linux-amd64-avx hysteria-linux-arm64; do
  $C -o "$a" "$B/$a"
  want=$(grep " build/$a\$" hashes.txt | cut -d' ' -f1)
  [ "$(sha256sum "$a" | cut -d' ' -f1)" = "$want" ] || { echo "checksum mismatch: $a"; exit 1; }
  echo "$want  $a" >> SHA256SUMS
  xz -9e -f "$a"
done
echo "${VER:-unknown}" > VERSION
rm -f hashes.txt
echo "embedded core updated to $(cat VERSION)"
