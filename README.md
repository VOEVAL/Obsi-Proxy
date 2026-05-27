<div align="center">

# Obsi Proxy

**Convenient proxy configuration for Obsidian**

Route all Obsidian and plugin traffic through HTTP or SOCKS5 proxies — with multi-proxy support, connection checking, and complete coverage.

[![Obsidian Downloads](https://img.shields.io/badge/Obsidian-Plugin-purple?logo=obsidian&logoColor=white)](https://obsidian.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.0-green.svg)](https://github.com/VOEVAL/Obsi-Proxy/releases)

</div>

---

## Features

- **Complete traffic routing** — Covers both Chromium network stack AND Node.js environment variables
- **All sessions coverage** — Applies proxy to every Electron session (default, BrowserWindows, partitions)
- **Periodic refresh** — Re-applies proxy every 30s to catch new windows/webviews
- **Multi-proxy support** — Save multiple proxy servers and switch between them instantly
- **HTTP & SOCKS5** — Choose the proxy type for each entry
- **Proxy authentication** — Optional username/password per proxy
- **On-the-fly toggle** — Enable or disable proxy without restarting Obsidian
- **Connection checker** — Verify any proxy works, even before enabling it
- **Emergency kill switch** — One-click disable when proxy goes down
- **Diagnostics** — Built-in diagnostic tool to troubleshoot proxy issues
- **Persistent state** — Proxy settings survive Obsidian restarts

## How It Works

Obsidian runs on Electron, which combines Chromium (renderer) and Node.js (main process). Network requests can originate from **two different stacks**:

### 1. Chromium Network Stack (renderer process)
- `fetch()`, `XMLHttpRequest`, `<img src>`, webviews
- Obsidian's `requestUrl()` API (used by most plugins)
- Obsidian Sync, theme/plugin downloads
- **Controlled by:** `session.setProxy({ mode: 'fixed_servers', proxyRules: '...' })`

### 2. Node.js Network Stack (main process)
- `require('http')`, `require('https')` direct calls
- Libraries like axios, node-fetch, got
- **Controlled by:** `process.env` variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`)

### Dual-level coverage

Obsi Proxy applies proxy rules at **both levels** simultaneously:

```
┌─────────────────────────────────────────────┐
│           Obsidian + All Plugins             │
├──────────────┬──────────────────────────────┤
│  Chromium    │  Node.js                     │
│  requests    │  requests                    │
│      ↓       │      ↓                       │
│  session.    │  process.env                 │
│  setProxy()  │  HTTP_PROXY / HTTPS_PROXY    │
│      ↓       │      ↓                       │
├──────────────┴──────────────────────────────┤
│              Proxy Server                    │
└─────────────────────────────────────────────┘
```

Additionally, the proxy is applied to **all Electron sessions** (not just `defaultSession`):
- All open BrowserWindows
- Common partitions (`persist:obsidian`, `persist:sync`, etc.)
- A periodic refresh every 30s catches new windows created after proxy was enabled

## Installation

### From Release (Recommended)

1. Download `main.js`, `manifest.json`, and `styles.css` from the [latest release](../../releases)
2. Copy them into your vault: `.obsidian/plugins/obsi-proxy/`
3. Restart Obsidian → **Settings → Community Plugins → Enable "Obsi Proxy"**

### From Source

```bash
git clone https://github.com/VOEVAL/Obsi-Proxy.git
cd Obsi-Proxy
npm install
npm run build
```

Then copy `main.js`, `manifest.json`, and `styles.css` to `.obsidian/plugins/obsi-proxy/` in your vault.

## Usage

1. Open **Settings → Community Plugins → Obsi Proxy**
2. Click **"+ Add Proxy"** and enter your proxy details (host, port, type, auth)
3. Click on a proxy in the list to **select** it as active
4. Toggle **Enable Proxy** ON
5. Click **"Check"** on any proxy to verify it works — even before enabling it
6. If something goes wrong, hit **Emergency Disable** to instantly restore direct connection
7. If a plugin still doesn't work, click **"Run Diagnostics"** to check session access and env vars

### Multi-Proxy

You can save as many proxies as you want. Click any proxy in the list to select it as the active one. When you switch, the proxy rules update immediately — no restart needed.

The **Check** button works on any saved proxy, regardless of whether it's currently active. It temporarily applies the proxy, runs the connectivity test, then reverts to your previous state.

### Diagnostics

The built-in diagnostics tool shows:
- Whether Electron APIs are accessible
- How many sessions were discovered
- The resolved proxy for each session (`session.resolveProxy()`)
- Current environment variable values (passwords masked)
- Plugin state

## Settings Reference

| Setting | Description | Default |
|---|---|---|
| Enable Proxy | Route all traffic through the selected proxy | OFF |
| Proxy List | Saved proxies — click to select, Check/Edit/Delete | — |
| Add Proxy | Create a new proxy entry (name, type, host, port, auth) | — |
| Emergency Disable | Instantly clear all proxy rules | — |
| Run Diagnostics | Check Electron session access and proxy state | — |

## Security Notice

> Obsidian is a local application. When you enable a proxy, **all** network traffic — including Obsidian Sync data and requests from every installed plugin — flows through the proxy server. Only use proxy servers you trust.

## Development

```bash
# Watch mode (auto-rebuild on file changes)
npm run dev

# Production build
npm run build
```

## License

[MIT](LICENSE)
