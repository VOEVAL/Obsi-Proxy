<div align="center">

# Obsi Proxy

**Global proxy manager for Obsidian**

Route all network traffic through HTTP or SOCKS5 proxy — with one-click toggling, connection checking, and persistent settings.

[![Obsidian Downloads](https://img.shields.io/badge/Obsidian-Plugin-purple?logo=obsidian&logoColor=white)](https://obsidian.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

---

## Features

- **Global traffic routing** — All Obsidian network requests (Sync, plugins, themes, API calls) go through your proxy
- **HTTP & SOCKS5 support** — Switch between proxy types instantly
- **Proxy authentication** — Optional username/password fields
- **On-the-fly toggle** — Enable or disable proxy without restarting Obsidian
- **Connection checker** — Verify your proxy works by checking your outgoing IP via `ipify.org`
- **Emergency kill switch** — One-click disable when proxy goes down
- **Persistent state** — Proxy settings survive Obsidian restarts

## How It Works

Obsidian runs on Electron, which is built on Chromium. Chromium exposes a `session` API that controls network routing for the entire renderer process.

When you enable the proxy, the plugin calls:

```js
session.defaultSession.setProxy({ proxyRules: "http=user:pass@host:port;https=..." })
```

This tells Chromium to route **all new TCP connections** through the specified proxy server. No request hooks, no interceptor hacks — just the native Chromium proxy engine.

## Installation

### From Release (Recommended)

1. Download `main.js`, `manifest.json`, and `styles.css` from the [latest release](../../releases)
2. Copy them into your vault: `.obsidian/plugins/global-proxy/`
3. Restart Obsidian → **Settings → Community Plugins → Enable "Global Proxy"**

### From Source

```bash
git clone https://github.com/VOEVAL/obsi-proxy.git
cd obsi-proxy
npm install
npm run build
```

Then copy `main.js`, `manifest.json`, and `styles.css` to `.obsidian/plugins/global-proxy/` in your vault.

## Usage

1. Open **Settings → Community Plugins → Global Proxy**
2. Enter your proxy **Host** and **Port**
3. Select **Proxy Type** (HTTP or SOCKS5)
4. Add **Username/Password** if your proxy requires auth
5. Toggle **Enable Proxy** ON
6. Click **Check Connection** to verify — you'll see your outgoing IP in a modal

If something goes wrong, hit **Emergency Disable** to instantly restore direct connection.

## Settings Reference

| Setting | Description | Default |
|---|---|---|
| Enable Proxy | Toggle proxy on/off without restart | OFF |
| Proxy Type | HTTP or SOCKS5 | HTTP |
| Host | IP address or hostname of proxy server | — |
| Port | Port number of proxy server | — |
| Username | Proxy auth username (optional) | — |
| Password | Proxy auth password (optional) | — |

## Security Notice

> Obsidian is a local application. When you enable a proxy, **all** network traffic — including Obsidian Sync data — flows through the proxy server. Only use proxy servers you trust.

## Development

```bash
# Watch mode (auto-rebuild on file changes)
npm run dev

# Production build
npm run build
```

## License

[MIT](LICENSE)
