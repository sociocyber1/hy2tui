First release of **hy2tui**: a fast terminal Hysteria2 VPN client for Linux.

### Download
- `hy2tui-linux-x86_64`: a single binary. The hysteria core v2.14.0 is built in, so no GitHub access is needed.

```bash
chmod +x hy2tui-linux-x86_64 && sudo install -m755 hy2tui-linux-x86_64 /usr/local/bin/hy2tui
hy2tui add 'hy2://…'   # or press v in the app to paste from the clipboard
hy2tui                 # asks for sudo for TUN mode
```

### Features
- Whole-system VPN (TUN) with DNS through the tunnel and a btop-style live dashboard (speed, packets, connections by IP/domain, DNS log)
- Local SOCKS5 + HTTP proxy for browsers on `127.0.0.1:2080`
- **notToVPN**: zones/domains (.ru, .kz, …) that go direct, with no leaks for everything else
- **DNS manager** (`D`): your own servers, priority order, speed test, reset to defaults
- **IPv6 auto-check**: if the server has no IPv6, IPv6 is hidden so sites don't stall (fixes `curl: (52) Empty reply from server`)
- Automatic network repair after crashes or other VPN apps; `hy2tui reset`
- Resumable, parallel download for core updates

Check the binary: `sha256sum -c hy2tui-linux-x86_64.sha256`
