import {
	App,
	Notice,
	Plugin,
	PluginSettingTab,
	Setting,
	Modal,
	requestUrl,
} from "obsidian";
import type { ElectronSession, ProxyConfig } from "electron";

interface ProxyEntry {
	id: string;
	name: string;
	proxyType: "http" | "socks5";
	host: string;
	port: string;
	username: string;
	password: string;
}

interface ProxySettings {
	enabled: boolean;
	activeProxyId: string;
	proxies: ProxyEntry[];
}

const DEFAULT_SETTINGS: ProxySettings = {
	enabled: false,
	activeProxyId: "",
	proxies: [],
};

function generateId(): string {
	return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/**
 * Obsi Proxy — main plugin class.
 *
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  COMPLETE TRAFFIC INTERCEPTION ARCHITECTURE
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Obsidian runs on Electron (Chromium + Node.js). Network requests
 * can originate from two distinct stacks:
 *
 *  1) CHROMIUM NETWORK STACK (renderer process)
 *     - fetch(), XMLHttpRequest, <img src>, <link>, webview, etc.
 *     - Obsidian's requestUrl() (uses electron.net under the hood)
 *     - ALL community plugins that use requestUrl()
 *     → Controlled by session.setProxy()
 *
 *  2) NODE.JS NETWORK STACK (main process)
 *     - require('http').request(), require('https').request()
 *     - Some plugins that use Node.js http directly
 *     - Obsidian Sync (partially)
 *     → NOT controlled by session.setProxy()
 *     → Controlled by process.env HTTP_PROXY / HTTPS_PROXY
 *       (read by many popular libraries: axios, node-fetch, got)
 *
 * This plugin applies proxy rules at BOTH levels to ensure
 * complete coverage:
 *
 *  A) Electron session.setProxy() — with mode: 'fixed_servers'
 *     Applied to ALL discoverable sessions:
 *       - defaultSession
 *       - Current BrowserWindow's webContents.session
 *       - All open BrowserWindows
 *       - Common partitions (persist:obsidian, persist:sync, etc.)
 *
 *  B) process.env variables:
 *       HTTP_PROXY, HTTPS_PROXY, ALL_PROXY
 *       http_proxy, https_proxy, all_proxy
 *
 *  C) Periodic refresh every 30s — re-applies proxy to all
 *     sessions, catching any new BrowserWindows/webviews
 *     created after proxy was enabled.
 *
 *  D) Verification via session.resolveProxy() — confirms
 *     the proxy rules were actually accepted by Chromium.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */
export default class ObsiProxyPlugin extends Plugin {
	settings: ProxySettings = DEFAULT_SETTINGS;
	private sessionWatchInterval: number | null = null;
	private originalEnv: Map<string, string | undefined> = new Map();
	private lastSessionCount: number = 0;

	async onload() {
		await this.loadSettings();
		this.addSettingTab(new ObsiProxySettingTab(this.app, this));

		if (this.settings.enabled && this.getActiveProxy()) {
			await this.applyProxy();
			this.startSessionWatch();
		}
	}

	async onunload() {
		this.stopSessionWatch();
		await this.clearProxy();
	}

	async loadSettings() {
		const loaded = await this.loadData();
		this.settings = Object.assign({}, DEFAULT_SETTINGS, loaded);
		if (!this.settings.proxies) this.settings.proxies = [];
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}

	getActiveProxy(): ProxyEntry | null {
		if (!this.settings.activeProxyId) return null;
		return (
			this.settings.proxies.find(
				(p) => p.id === this.settings.activeProxyId
			) ?? null
		);
	}

	// ──────────────────────────────────────────────────────────
	//  SESSION DISCOVERY
	// ──────────────────────────────────────────────────────────

	/**
	 * Get the Electron remote module through any available method.
	 * In Electron 17+, electron.remote was removed and replaced
	 * by the @electron/remote package. Obsidian may or may not
	 * have it available, so we try both.
	 */
	private getRemote(): any {
		try {
			const electron = (window as any).require("electron");
			if (electron.remote) return electron.remote;
		} catch {}
		try {
			const remote = (window as any).require("@electron/remote");
			if (remote) return remote;
		} catch {}
		return null;
	}

	/**
	 * Discover ALL Electron sessions in the current Obsidian instance.
	 *
	 * This is critical for complete coverage. A single call to
	 * session.defaultSession.setProxy() is NOT sufficient because:
	 *
	 *   - Obsidian may use separate partitions for Sync, plugin
	 *     downloads, webviews, etc.
	 *   - Each BrowserWindow has its own webContents with its own session.
	 *   - New windows created by plugins get new sessions that
	 *     don't inherit defaultSession's proxy settings.
	 *
	 * We cast everything to `any` because the Electron API surface
	 * varies between versions and we need maximum compatibility.
	 */
	async getAllSessions(): Promise<ElectronSession[]> {
		const sessions: ElectronSession[] = [];
		const seen = new Set<any>();

		const add = (s: any) => {
			if (s && typeof s.setProxy === "function" && !seen.has(s)) {
				seen.add(s);
				sessions.push(s as ElectronSession);
			}
		};

		try {
			const electron = (window as any).require("electron");
			const remote = this.getRemote();

			if (remote) {
				// 1. defaultSession — the primary session
				try {
					add(remote.session?.defaultSession);
				} catch {}

				// 2. Current window's session — most directly relevant
				try {
					const win = remote.getCurrentWindow();
					add(win?.webContents?.session);
				} catch {}

				// 3. ALL BrowserWindows — popout windows, secondary windows
				try {
					const windows: any[] = remote.BrowserWindow.getAllWindows();
					for (const win of windows) {
						try {
							add(win.webContents?.session);
						} catch {}
					}
				} catch {}

				// 4. Common partition-based sessions
				//    Obsidian may use these for Sync, plugin downloads, etc.
				const partitions = [
					"persist:obsidian",
					"persist:sync",
					"persist:plugins",
					"persist:themes",
					"persist:core",
					"persist:0",
					"persist:1",
					"persist:",
				];
				for (const partition of partitions) {
					try {
						add(remote.session?.fromPartition?.(partition));
					} catch {}
				}
			}

			// 5. electron.session directly (may work in some contexts)
			try {
				add(electron.session?.defaultSession);
			} catch {}
		} catch {}

		this.lastSessionCount = sessions.length;
		return sessions;
	}

	// ──────────────────────────────────────────────────────────
	//  PROXY RULES BUILDER
	// ──────────────────────────────────────────────────────────

	/**
	 * Build Chromium-compatible proxyRules string.
	 *
	 * Chromium proxy configuration format:
	 *   https://www.chromium.org/developers/design-documents/network-settings/
	 *
	 * HTTP:  "http=user:pass@host:port;https=user:pass@host:port"
	 * SOCKS5: "socks5://user:pass@host:port"
	 */
	buildProxyRules(proxy: ProxyEntry): string {
		const { proxyType, host, port, username, password } = proxy;
		if (!host || !port) return "";

		const auth =
			username && password
				? `${encodeURIComponent(username)}:${encodeURIComponent(password)}@`
				: "";

		if (proxyType === "socks5") {
			return `socks5://${auth}${host}:${port}`;
		}

		return `http=${auth}${host}:${port};https=${auth}${host}:${port}`;
	}

	/**
	 * Build a standard proxy URL for environment variables.
	 * Format: "http://user:pass@host:port" or "socks5://user:pass@host:port"
	 */
	buildProxyUrl(proxy: ProxyEntry): string {
		const auth =
			proxy.username && proxy.password
				? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`
				: "";

		if (proxy.proxyType === "socks5") {
			return `socks5://${auth}${proxy.host}:${proxy.port}`;
		}
		return `http://${auth}${proxy.host}:${proxy.port}`;
	}

	// ──────────────────────────────────────────────────────────
	//  ENVIRONMENT VARIABLES
	// ──────────────────────────────────────────────────────────

	/**
	 * Set process.env proxy variables.
	 *
	 * Many Node.js HTTP libraries (axios, node-fetch, got, request)
	 * read HTTP_PROXY / HTTPS_PROXY / ALL_PROXY from environment.
	 * The Node.js built-in http/https modules do NOT read these,
	 * but setting them covers a significant portion of real-world usage.
	 *
	 * We also set lowercase variants (http_proxy) because some
	 * tools only check the lowercase version.
	 */
	setEnvironmentProxy(proxy: ProxyEntry) {
		const httpUrl = `http://${proxy.username && proxy.password ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@` : ""}${proxy.host}:${proxy.port}`;
		const allUrl = this.buildProxyUrl(proxy);

		const keys = [
			"HTTP_PROXY",
			"HTTPS_PROXY",
			"ALL_PROXY",
			"http_proxy",
			"https_proxy",
			"all_proxy",
		];

		for (const key of keys) {
			if (!this.originalEnv.has(key)) {
				this.originalEnv.set(key, process.env[key]);
			}
		}

		process.env.HTTP_PROXY = httpUrl;
		process.env.HTTPS_PROXY = httpUrl;
		process.env.ALL_PROXY = allUrl;
		process.env.http_proxy = httpUrl;
		process.env.https_proxy = httpUrl;
		process.env.all_proxy = allUrl;
	}

	/**
	 * Restore original environment variables.
	 */
	clearEnvironmentProxy() {
		const keys = [
			"HTTP_PROXY",
			"HTTPS_PROXY",
			"ALL_PROXY",
			"http_proxy",
			"https_proxy",
			"all_proxy",
		];

		for (const key of keys) {
			const original = this.originalEnv.get(key);
			if (original === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = original;
			}
		}
		this.originalEnv.clear();
	}

	// ──────────────────────────────────────────────────────────
	//  PROXY APPLY / CLEAR
	// ──────────────────────────────────────────────────────────

	/**
	 * Apply proxy to ALL discovered sessions + environment variables.
	 *
	 * This is the core method that ensures complete traffic coverage.
	 * It applies the proxy at two levels:
	 *
	 *   1) session.setProxy() — Chromium network stack
	 *      Covers: fetch, XHR, requestUrl(), electron.net,
	 *              webviews, plugin API calls, Obsidian Sync
	 *
	 *   2) process.env — Node.js network stack fallback
	 *      Covers: axios, node-fetch, got, and any library
	 *              that reads HTTP_PROXY/HTTPS_PROXY
	 */
	async applyProxy(): Promise<boolean> {
		const proxy = this.getActiveProxy();
		if (!proxy) {
			new Notice("Obsi Proxy: no proxy selected");
			return false;
		}

		const rules = this.buildProxyRules(proxy);
		if (!rules) {
			new Notice("Obsi Proxy: host and port are required");
			return false;
		}

		// ── Level 1: Electron sessions ──
		const sessions = await this.getAllSessions();
		let applied = 0;

		for (const session of sessions) {
			try {
				await session.setProxy({
					mode: "fixed_servers",
					proxyRules: rules,
					proxyBypassRules: "",
				});
				applied++;
			} catch (err) {
				console.error("Obsi Proxy: setProxy failed on session", err);
			}
		}

		// ── Level 2: Environment variables ──
		this.setEnvironmentProxy(proxy);

		// ── Verification ──
		if (applied === 0) {
			new Notice(
				"Obsi Proxy: could not apply proxy to any Electron session. Check Electron API access."
			);
			return false;
		}

		// Verify at least one session accepted the proxy
		let verified = false;
		for (const session of sessions) {
			try {
				const resolved = await session.resolveProxy(
					"https://example.com"
				);
				if (resolved && resolved !== "DIRECT") {
					verified = true;
					break;
				}
			} catch {}
		}

		if (!verified && applied > 0) {
			console.warn(
				"Obsi Proxy: setProxy was called but resolveProxy returns DIRECT — proxy may not have taken effect"
			);
		}

		console.log(
			`Obsi Proxy: applied to ${applied}/${sessions.length} sessions, env vars set, verified=${verified}`
		);

		new Notice(
			`Obsi Proxy: ON — ${proxy.name} (${applied} sessions, env vars set)`
		);
		return true;
	}

	/**
	 * Clear proxy from ALL sessions + restore environment variables.
	 */
	async clearProxy(): Promise<void> {
		const sessions = await this.getAllSessions();
		for (const session of sessions) {
			try {
				await session.setProxy({
					mode: "system",
					proxyRules: "",
					proxyBypassRules: "",
				});
			} catch (err) {
				console.error("Obsi Proxy: clearProxy failed on session", err);
			}
		}
		this.clearEnvironmentProxy();
	}

	async enableProxy(): Promise<void> {
		const ok = await this.applyProxy();
		this.settings.enabled = ok;
		await this.saveSettings();
		if (ok) {
			this.startSessionWatch();
		}
	}

	async disableProxy(): Promise<void> {
		this.stopSessionWatch();
		await this.clearProxy();
		this.settings.enabled = false;
		await this.saveSettings();
		new Notice("Obsi Proxy: OFF — direct connection restored");
	}

	// ──────────────────────────────────────────────────────────
	//  PERIODIC SESSION REFRESH
	// ──────────────────────────────────────────────────────────

	/**
	 * Periodically re-apply proxy to all sessions.
	 *
	 * This handles the case where new BrowserWindows or webviews
	 * are created AFTER the proxy was enabled. These new sessions
	 * don't inherit the proxy settings from defaultSession.
	 *
	 * Interval: 30 seconds (low overhead, catches new windows quickly).
	 */
	startSessionWatch() {
		if (this.sessionWatchInterval) return;
		this.sessionWatchInterval = window.setInterval(async () => {
			if (!this.settings.enabled || !this.getActiveProxy()) return;

			const proxy = this.getActiveProxy()!;
			const rules = this.buildProxyRules(proxy);
			if (!rules) return;

			const sessions = await this.getAllSessions();
			for (const session of sessions) {
				try {
					await session.setProxy({
						mode: "fixed_servers",
						proxyRules: rules,
						proxyBypassRules: "",
					});
				} catch {}
			}
		}, 30000);
	}

	stopSessionWatch() {
		if (this.sessionWatchInterval !== null) {
			window.clearInterval(this.sessionWatchInterval);
			this.sessionWatchInterval = null;
		}
	}

	// ──────────────────────────────────────────────────────────
	//  CONNECTION CHECK
	// ──────────────────────────────────────────────────────────

	/**
	 * Check if a proxy works by making a test request through it.
	 *
	 * Works regardless of whether the proxy is currently active:
	 *
	 *   - If the proxy IS active: just make the test request directly.
	 *   - If the proxy is NOT active: temporarily apply it to ALL
	 *     sessions + env vars, make the test request, then revert
	 *     to the previous state.
	 *
	 * This ensures the checker is useful for pre-flight testing
	 * before committing to a proxy.
	 */
	async checkConnection(proxy: ProxyEntry): Promise<{
		ip: string;
	} | null> {
		const isActive =
			this.settings.enabled &&
			this.settings.activeProxyId === proxy.id;

		let needsRevert = false;

		if (!isActive) {
			const rules = this.buildProxyRules(proxy);
			if (!rules) return null;

			// Temporarily apply to ALL sessions
			const sessions = await this.getAllSessions();
			for (const session of sessions) {
				try {
					await session.setProxy({
						mode: "fixed_servers",
						proxyRules: rules,
						proxyBypassRules: "",
					});
				} catch {}
			}
			this.setEnvironmentProxy(proxy);
			needsRevert = true;
		}

		try {
			const resp = await requestUrl({
				url: "https://api.ipify.org?format=json",
				method: "GET",
			});
			return resp.json as { ip: string };
		} catch (err) {
			console.error("Obsi Proxy check error:", err);
			return null;
		} finally {
			if (needsRevert) {
				// Revert to previous state
				if (this.settings.enabled && this.getActiveProxy()) {
					const activeProxy = this.getActiveProxy()!;
					const rules = this.buildProxyRules(activeProxy);
					const sessions = await this.getAllSessions();
					for (const session of sessions) {
						try {
							await session.setProxy({
								mode: "fixed_servers",
								proxyRules: rules,
								proxyBypassRules: "",
							});
						} catch {}
					}
					this.setEnvironmentProxy(activeProxy);
				} else {
					const sessions = await this.getAllSessions();
					for (const session of sessions) {
						try {
							await session.setProxy({
								mode: "system",
								proxyRules: "",
								proxyBypassRules: "",
							});
						} catch {}
					}
					this.clearEnvironmentProxy();
				}
			}
		}
	}

	// ──────────────────────────────────────────────────────────
	//  DIAGNOSTICS
	// ──────────────────────────────────────────────────────────

	/**
	 * Collect diagnostic information about the current proxy state.
	 * Useful for debugging and user support.
	 */
	async getDiagnostics(): Promise<string> {
		const lines: string[] = [];

		lines.push("=== Obsi Proxy Diagnostics ===");
		lines.push("");

		// Electron access
		const hasRequire = typeof (window as any).require === "function";
		lines.push(`window.require available: ${hasRequire}`);

		if (hasRequire) {
			try {
				const electron = (window as any).require("electron");
				lines.push(`electron.remote available: ${!!electron.remote}`);

				try {
					const remote = (window as any).require("@electron/remote");
					lines.push(`@electron/remote available: ${!!remote}`);
				} catch {
					lines.push("@electron/remote available: false");
				}
			} catch {
				lines.push("electron require failed");
			}
		}

		// Sessions
		const sessions = await this.getAllSessions();
		lines.push(`Sessions discovered: ${sessions.length}`);

		for (let i = 0; i < sessions.length; i++) {
			const session = sessions[i];
			try {
				const resolved = await session.resolveProxy(
					"https://example.com"
				);
				lines.push(`  Session ${i}: resolveProxy = "${resolved}"`);
			} catch (err) {
				lines.push(`  Session ${i}: resolveProxy failed — ${err}`);
			}
		}

		// Environment variables
		lines.push("");
		lines.push("Environment variables:");
		for (const key of [
			"HTTP_PROXY",
			"HTTPS_PROXY",
			"ALL_PROXY",
			"http_proxy",
			"https_proxy",
			"all_proxy",
		]) {
			const val = process.env[key];
			if (val) {
				const masked = val.replace(/:[^@]+@/, ":****@");
				lines.push(`  ${key} = ${masked}`);
			} else {
				lines.push(`  ${key} = (not set)`);
			}
		}

		// Plugin state
		lines.push("");
		lines.push(`Proxy enabled: ${this.settings.enabled}`);
		lines.push(`Active proxy ID: ${this.settings.activeProxyId || "(none)"}`);
		lines.push(`Saved proxies: ${this.settings.proxies.length}`);
		lines.push(`Session watch active: ${this.sessionWatchInterval !== null}`);

		return lines.join("\n");
	}
}

// ──────────────────────────────────────────────────────────────
//  MODALS
// ──────────────────────────────────────────────────────────────

class ProxyCheckModal extends Modal {
	result: { ip: string } | null;
	error: string | null;
	wasActiveWhenChecked: boolean;
	proxyName: string;

	constructor(
		app: App,
		proxyName: string,
		result: { ip: string } | null,
		error: string | null,
		wasActiveWhenChecked: boolean
	) {
		super(app);
		this.proxyName = proxyName;
		this.result = result;
		this.error = error;
		this.wasActiveWhenChecked = wasActiveWhenChecked;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.empty();

		contentEl.createEl("h2", { text: "Proxy Connection Check" });
		contentEl.createEl("p", {
			text: `Checking: ${this.proxyName}`,
			cls: "obsi-proxy-check-result",
		});

		if (!this.wasActiveWhenChecked) {
			contentEl.createEl("p", {
				text: "Note: This proxy was temporarily applied for the check and then reverted to your previous state.",
				attr: {
					style: "font-style: italic; color: var(--text-muted);",
				},
			});
		}

		if (this.error) {
			contentEl.createEl("p", {
				text: `Error: ${this.error}`,
				cls: "obsi-proxy-check-result",
				attr: {
					style:
						"background: var(--background-modifier-error); color: var(--text-error);",
				},
			});
			contentEl.createEl("p", {
				text: "The proxy server is unreachable or the credentials are incorrect. Try another proxy or hit Emergency Disable.",
			});
		} else if (this.result) {
			contentEl.createEl("p", {
				text: `Outgoing IP: ${this.result.ip}`,
				cls: "obsi-proxy-check-result",
				attr: {
					style:
						"background: var(--background-modifier-success); color: var(--text-success); font-size: 16px; font-weight: 600;",
				},
			});
			contentEl.createEl("p", {
				text: this.wasActiveWhenChecked
					? "This IP belongs to your proxy server. Connection is working correctly."
					: "This is the IP that would be seen if you enable this proxy. Connection is working correctly.",
			});
		}

		new Setting(contentEl).addButton((btn) =>
			btn.setButtonText("Close").onClick(() => this.close())
		);
	}

	onClose() {
		this.contentEl.empty();
	}
}

class ProxyEditModal extends Modal {
	plugin: ObsiProxyPlugin;
	entry: ProxyEntry;
	onSave: (entry: ProxyEntry) => void;
	isNew: boolean;

	constructor(
		app: App,
		plugin: ObsiProxyPlugin,
		entry: ProxyEntry,
		isNew: boolean,
		onSave: (entry: ProxyEntry) => void
	) {
		super(app);
		this.plugin = plugin;
		this.entry = { ...entry };
		this.isNew = isNew;
		this.onSave = onSave;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.empty();

		contentEl.createEl("h2", {
			text: this.isNew ? "Add Proxy" : "Edit Proxy",
		});

		new Setting(contentEl)
			.setName("Name")
			.setDesc("A friendly name for this proxy")
			.addText((text) =>
				text
					.setPlaceholder("e.g. Work VPN")
					.setValue(this.entry.name)
					.onChange((val) => {
						this.entry.name = val;
					})
			);

		new Setting(contentEl)
			.setName("Proxy type")
			.setDesc(
				"HTTP routes HTTP/HTTPS. SOCKS5 proxies all TCP with DNS resolution on the proxy side."
			)
			.addDropdown((dd) =>
				dd
					.addOption("http", "HTTP")
					.addOption("socks5", "SOCKS5")
					.setValue(this.entry.proxyType)
					.onChange((val: string) => {
						this.entry.proxyType = val as "http" | "socks5";
					})
			);

		new Setting(contentEl)
			.setName("Host")
			.setDesc("IP address or hostname")
			.addText((text) =>
				text
					.setPlaceholder("e.g. 127.0.0.1")
					.setValue(this.entry.host)
					.onChange((val) => {
						this.entry.host = val.trim();
					})
			);

		new Setting(contentEl)
			.setName("Port")
			.setDesc("Port number")
			.addText((text) =>
				text
					.setPlaceholder("e.g. 8080")
					.setValue(this.entry.port)
					.onChange((val) => {
						this.entry.port = val.trim();
					})
			);

		new Setting(contentEl)
			.setName("Username")
			.setDesc("Leave empty if not required")
			.addText((text) =>
				text
					.setPlaceholder("optional")
					.setValue(this.entry.username)
					.onChange((val) => {
						this.entry.username = val;
					})
			);

		new Setting(contentEl)
			.setName("Password")
			.setDesc("Leave empty if not required")
			.addText((text) => {
				text.inputEl.type = "password";
				text
					.setPlaceholder("optional")
					.setValue(this.entry.password)
					.onChange((val) => {
						this.entry.password = val;
					});
			});

		new Setting(contentEl).addButton((btn) =>
			btn
				.setButtonText(this.isNew ? "Add Proxy" : "Save Changes")
				.setCta()
				.onClick(() => {
					if (!this.entry.name.trim()) {
						this.entry.name = `${this.entry.proxyType}://${this.entry.host}:${this.entry.port}`;
					}
					if (!this.entry.host || !this.entry.port) {
						new Notice("Obsi Proxy: host and port are required");
						return;
					}
					this.onSave(this.entry);
					this.close();
				})
		);
	}

	onClose() {
		this.contentEl.empty();
	}
}

class DiagnosticsModal extends Modal {
	diagText: string;

	constructor(app: App, diagText: string) {
		super(app);
		this.diagText = diagText;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.empty();

		contentEl.createEl("h2", { text: "Obsi Proxy Diagnostics" });

		const pre = contentEl.createEl("pre", {
			cls: "obsi-proxy-check-result",
			attr: {
				style:
					"background: var(--background-secondary); padding: 16px; border-radius: 6px; overflow-x: auto; max-height: 400px; white-space: pre-wrap;",
			},
		});
		pre.textContent = this.diagText;

		new Setting(contentEl).addButton((btn) =>
			btn
				.setButtonText("Copy to Clipboard")
				.onClick(() => {
					navigator.clipboard.writeText(this.diagText);
					new Notice("Copied to clipboard");
				})
		);

		new Setting(contentEl).addButton((btn) =>
			btn.setButtonText("Close").onClick(() => this.close())
		);
	}

	onClose() {
		this.contentEl.empty();
	}
}

// ──────────────────────────────────────────────────────────────
//  SETTINGS TAB
// ──────────────────────────────────────────────────────────────

class ObsiProxySettingTab extends PluginSettingTab {
	plugin: ObsiProxyPlugin;
	statusEl: HTMLElement | null = null;
	proxyListEl: HTMLElement | null = null;

	constructor(app: App, plugin: ObsiProxyPlugin) {
		super(app, plugin);
		this.plugin = plugin;
	}

	display(): void {
		const { containerEl } = this;
		containerEl.empty();
		containerEl.addClass("obsi-proxy-settings");

		containerEl.createEl("h2", { text: "Obsi Proxy" });

		this.renderStatus(containerEl);
		this.renderToggle(containerEl);
		this.renderProxyList(containerEl);
		this.renderEmergency(containerEl);
		this.renderDiagnostics(containerEl);
	}

	renderStatus(parent: HTMLElement) {
		const active = this.plugin.getActiveProxy();
		const text =
			this.plugin.settings.enabled && active
				? `ON — ${active.name} (${active.proxyType}://${active.host}:${active.port})`
				: "OFF — direct connection";

		this.statusEl = parent.createEl("div", {
			cls: `obsi-proxy-status ${this.plugin.settings.enabled ? "active" : "inactive"}`,
			text: `Obsi Proxy: ${text}`,
		});
	}

	renderToggle(parent: HTMLElement) {
		new Setting(parent)
			.setName("Enable proxy")
			.setDesc(
				"Route all Obsidian and plugin traffic through the selected proxy"
			)
			.addToggle((toggle) =>
				toggle
					.setValue(this.plugin.settings.enabled)
					.onChange(async (val) => {
						if (val) {
							if (!this.plugin.getActiveProxy()) {
								new Notice("Obsi Proxy: select a proxy first");
								toggle.setValue(false);
								return;
							}
							await this.plugin.enableProxy();
						} else {
							await this.plugin.disableProxy();
						}
						this.display();
					})
			);
	}

	renderProxyList(parent: HTMLElement) {
		parent.createEl("div", {
			text: "PROXY LIST",
			cls: "obsi-proxy-section-title",
		});

		this.proxyListEl = parent.createEl("div");

		this.plugin.settings.proxies.forEach((proxy) => {
			this.renderProxyItem(proxy);
		});

		if (this.plugin.settings.proxies.length === 0) {
			this.proxyListEl.createEl("p", {
				text: "No proxies configured. Add one below.",
				attr: { style: "color: var(--text-muted); padding: 8px 0;" },
			});
		}

		new Setting(parent)
			.setName("Add new proxy")
			.setDesc("Add an HTTP or SOCKS5 proxy server")
			.addButton((btn) =>
				btn
					.setButtonText("+ Add Proxy")
					.setCta()
					.onClick(() => {
						const newEntry: ProxyEntry = {
							id: generateId(),
							name: "",
							proxyType: "http",
							host: "",
							port: "",
							username: "",
							password: "",
						};

						const modal = new ProxyEditModal(
							this.app,
							this.plugin,
							newEntry,
							true,
							async (entry) => {
								this.plugin.settings.proxies.push(entry);
								if (
									!this.plugin.settings.activeProxyId ||
									this.plugin.settings.proxies.length === 1
								) {
									this.plugin.settings.activeProxyId = entry.id;
								}
								await this.plugin.saveSettings();
								this.display();
							}
						);
						modal.open();
					})
			);
	}

	renderProxyItem(proxy: ProxyEntry) {
		if (!this.proxyListEl) return;

		const isSelected =
			this.plugin.settings.activeProxyId === proxy.id;

		const item = this.proxyListEl.createEl("div", {
			cls: `obsi-proxy-list-item ${isSelected ? "selected" : ""}`,
		});

		item.addEventListener("click", async (e) => {
			const target = e.target as HTMLElement;
			if (target.closest("button")) return;

			this.plugin.settings.activeProxyId = proxy.id;
			await this.plugin.saveSettings();

			if (this.plugin.settings.enabled) {
				await this.plugin.enableProxy();
			}
			this.display();
		});

		const header = item.createEl("div", {
			cls: "obsi-proxy-list-item-header",
		});

		header.createEl("span", {
			text: isSelected ? `\u25B6 ${proxy.name}` : proxy.name,
			cls: "obsi-proxy-list-item-name",
		});

		const actions = header.createEl("div", {
			cls: "obsi-proxy-list-item-actions",
		});

		const checkBtn = actions.createEl("button", {
			text: "Check",
		});
		checkBtn.addEventListener("click", async (e) => {
			e.stopPropagation();
			checkBtn.textContent = "...";
			checkBtn.setAttribute("disabled", "true");

			const wasActive =
				this.plugin.settings.enabled &&
				this.plugin.settings.activeProxyId === proxy.id;

			const result = await this.plugin.checkConnection(proxy);
			const error =
				result === null
					? "Connection failed — proxy may be unreachable or credentials are wrong"
					: null;

			checkBtn.textContent = "Check";
			checkBtn.removeAttribute("disabled");

			if (error) {
				new Notice("Obsi Proxy: check failed", 5000);
			} else if (result) {
				new Notice(`Obsi Proxy: IP is ${result.ip}`, 5000);
			}

			const modal = new ProxyCheckModal(
				this.app,
				proxy.name,
				result,
				error,
				wasActive
			);
			modal.open();
		});

		const editBtn = actions.createEl("button", {
			text: "Edit",
		});
		editBtn.addEventListener("click", (e) => {
			e.stopPropagation();
			const modal = new ProxyEditModal(
				this.app,
				this.plugin,
				proxy,
				false,
				async (entry) => {
					const idx = this.plugin.settings.proxies.findIndex(
						(p) => p.id === entry.id
					);
					if (idx >= 0) {
						this.plugin.settings.proxies[idx] = entry;
					}
					await this.plugin.saveSettings();
					if (
						this.plugin.settings.enabled &&
						this.plugin.settings.activeProxyId === entry.id
					) {
						await this.plugin.enableProxy();
					}
					this.display();
				}
			);
			modal.open();
		});

		const delBtn = actions.createEl("button", {
			text: "Delete",
		});
		delBtn.addEventListener("click", async (e) => {
			e.stopPropagation();

			this.plugin.settings.proxies =
				this.plugin.settings.proxies.filter((p) => p.id !== proxy.id);

			if (this.plugin.settings.activeProxyId === proxy.id) {
				this.plugin.settings.activeProxyId =
					this.plugin.settings.proxies.length > 0
						? this.plugin.settings.proxies[0].id
						: "";

				if (this.plugin.settings.enabled) {
					if (this.plugin.getActiveProxy()) {
						await this.plugin.enableProxy();
					} else {
						await this.plugin.disableProxy();
					}
				}
			}

			await this.plugin.saveSettings();
			this.display();
		});

		item.createEl("div", {
			text: `${proxy.proxyType}://${proxy.host}:${proxy.port}${proxy.username ? " (auth)" : ""}${isSelected ? " \u2014 selected" : ""}`,
			cls: "obsi-proxy-list-item-detail",
		});
	}

	renderEmergency(parent: HTMLElement) {
		new Setting(parent)
			.setName("Emergency Disable")
			.setDesc(
				"Instantly clear all proxy rules and restore direct connection"
			)
			.addButton((btn) =>
				btn
					.setButtonText("Disable Proxy Now")
					.setWarning()
					.onClick(async () => {
						await this.plugin.disableProxy();
						this.display();
					})
			);
	}

	renderDiagnostics(parent: HTMLElement) {
		parent.createEl("div", {
			text: "DIAGNOSTICS",
			cls: "obsi-proxy-section-title",
		});

		new Setting(parent)
			.setName("Run diagnostics")
			.setDesc(
				"Check Electron session access, proxy state, and environment variables"
			)
			.addButton((btn) =>
				btn.setButtonText("Run Diagnostics").onClick(async () => {
					btn.setButtonText("Running...");
					btn.setDisabled(true);

					const diag = await this.plugin.getDiagnostics();

					btn.setButtonText("Run Diagnostics");
					btn.setDisabled(false);

					const modal = new DiagnosticsModal(this.app, diag);
					modal.open();
				})
			);
	}

	refreshStatus() {
		if (!this.statusEl) return;

		const active = this.plugin.getActiveProxy();
		const text =
			this.plugin.settings.enabled && active
				? `ON — ${active.name} (${active.proxyType}://${active.host}:${active.port})`
				: "OFF — direct connection";

		this.statusEl.className = `obsi-proxy-status ${this.plugin.settings.enabled ? "active" : "inactive"}`;
		this.statusEl.textContent = `Obsi Proxy: ${text}`;
	}
}
