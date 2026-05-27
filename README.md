<div align="center">

# Obsi Proxy

**Convenient proxy configuration for Obsidian**

Route all Obsidian and plugin traffic through HTTP or SOCKS5 proxies — with multi-proxy support, connection checking, and one-click toggle.

[![Obsidian Downloads](https://img.shields.io/badge/Obsidian-Plugin-purple?logo=obsidian&logoColor=white)](https://obsidian.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/VOEVAL/Obsi-Proxy/releases)

</div>

---

## Features

- **Full traffic routing** — All network requests from Obsidian core **and every installed plugin** go through your proxy
- **Multi-proxy support** — Save multiple proxy servers and switch between them instantly
- **HTTP & SOCKS5** — Choose the proxy type for each entry
- **Proxy authentication** — Optional username/password per proxy
- **On-the-fly toggle** — Enable or disable proxy without restarting Obsidian
- **Connection checker** — Verify any proxy works by checking your outgoing IP, **even when the proxy is not currently active**
- **Emergency kill switch** — One-click disable when proxy goes down
- **Persistent state** — Proxy settings survive Obsidian restarts

## How It Works

Obsidian runs on Electron, which is built on Chromium. Chromium's network stack has a built-in proxy resolver that controls routing for **ALL** connections from the renderer process — including every installed plugin.

When you enable a proxy, Obsi Proxy calls:

```js
session.defaultSession.setProxy({ proxyRules: "http=user:pass@host:port;https=..." })
```

This tells Chromium to route **all new TCP connections** through the specified proxy server. No request hooks, no interceptor hacks — just the native Chromium proxy engine.

Every plugin that uses `requestUrl()`, `fetch()`, `XMLHttpRequest`, or any network call goes through the same Chromium network stack, so they all respect the proxy rules.

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

### Multi-Proxy

You can save as many proxies as you want. Click any proxy in the list to select it as the active one. When you switch, the proxy rules update immediately — no restart needed.

The **Check** button works on any saved proxy, regardless of whether it's currently active. It temporarily applies the proxy, runs the connectivity test, then reverts to your previous state.

## Settings Reference

| Setting | Description | Default |
|---|---|---|
| Enable Proxy | Route all traffic through the selected proxy | OFF |
| Proxy List | Saved proxies — click to select, Check/Edit/Delete | — |
| Add Proxy | Create a new proxy entry (name, type, host, port, auth) | — |
| Emergency Disable | Instantly clear all proxy rules | — |

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
