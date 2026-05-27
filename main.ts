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
 * Three critical layers for proxy to work on ALL Obsidian + plugin traffic:
 *
 *  A) session.setProxy() with mode: 'fixed_servers'
 *     - Applied to EVERY Electron session we can find
 *     - Covers Chromium network stack (fetch, XHR, requestUrl, webviews)
 *     - Credentials embedded in proxyRules URL (http://user:pass@host:port)
 *
 *  B) session.on('login') handler
 *     - When proxy sends 407 Proxy Auth Required, Chromium fires
 *       the 'login' event. Without a handler, Chromium silently
 *       drops the connection or shows an invisible dialog.
 *     - Our handler checks authInfo.isProxy and provides credentials.
 *     - This is ESSENTIAL for proxy auth to work reliably.
 *
 *  C) process.env variables
 *     - HTTP_PROXY, HTTPS_PROXY, ALL_PROXY (+ lowercase)
 *     - Covers Node.js stack: axios, node-fetch, got, etc.
 *     - For SOCKS5: only ALL_PROXY uses socks5:// scheme
 *       (HTTP_PROXY with socks5:// confuses most libraries)
 *
 *  D) Periodic refresh every 30s — catches new BrowserWindows
 *
 *  E) Verification via session.resolveProxy() after setProxy
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */
export default class ObsiProxyPlugin extends Plugin {
	settings: ProxySettings = DEFAULT_SETTINGS;
	private sessionWatchInterval: number | null = null;
	private originalEnv: Map<string, string | undefined> = new Map();
	private lastSessionCount: number = 0;
	private loginHandler: ((...args: any[]) => void) | null = null;

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
	 * Discover ALL Electron sessions.
	 *
	 * Critical: Obsidian uses separate sessions for Sync, plugin
	 * downloads, webviews, etc. Applying proxy only to defaultSession
	 * is NOT enough — other sessions bypass the proxy entirely.
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
				try { add(remote.session?.defaultSession); } catch {}

				try {
					const win = remote.getCurrentWindow();
					add(win?.webContents?.session);
				} catch {}

				try {
					const windows: any[] = remote.BrowserWindow.getAllWindows();
					for (const win of windows) {
						try { add(win.webContents?.session); } catch {}
					}
				} catch {}

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
					try { add(remote.session?.fromPartition?.(partition)); } catch {}
				}
			}

			try { add(electron.session?.defaultSession); } catch {}
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
	 * ─── CRITICAL FORMAT NOTE ───
	 *
	 * When credentials are present, the proxy URL MUST include the
	 * scheme prefix (http://) explicitly. Without it, Chromium's
	 * parser misinterprets the string:
	 *
	 *   WRONG: "http=user:pass@host:port"
	 *     → Chromium sees "http=" as traffic type, then tries to
	 *       parse "user:pass@host:port" as host:port
	 *     → Result: host="user", port="pass@host..." → GARBAGE
	 *
	 *   CORRECT: "http=http://user:pass@host:port"
	 *     → Chromium sees "http=" as traffic type, then parses
	 *       "http://user:pass@host:port" as a URL with scheme
	 *     → Result: correct extraction of user, pass, host, port
	 *
	 * Chromium proxy config format:
	 *   proxy-rule = [ traffic-type "=" ] [ scheme "://" ] [ user ":" pass "@" ] host [ ":" port ]
	 *   traffic-type = "http" | "https" | "ftp"
	 *   scheme = "http" | "https" | "socks4" | "socks5" | "direct"
	 *
	 * Example for HTTP proxy with auth:
	 *   "http=http://user:pass@host:port;https=http://user:pass@host:port"
	 *
	 * Example for SOCKS5 proxy with auth:
	 *   "socks5://user:pass@host:port"
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

		if (username && password) {
			return `http=http://${auth}${host}:${port};https=http://${auth}${host}:${port}`;
		}

		return `http=${host}:${port};https=${host}:${port}`;
	}

	// ──────────────────────────────────────────────────────────
	//  LOGIN HANDLER (PROXY AUTH)
	// ──────────────────────────────────────────────────────────

	/**
	 * Create a login handler for session.on('login').
	 *
	 * When a proxy sends 407 Proxy Authentication Required,
	 * Chromium fires the 'login' event. Without a handler:
	 *   - Chromium shows an invisible auth dialog in Electron
	 *   - The request silently fails
	 *   - The user sees "connection error" with no explanation
	 *
	 * With this handler:
	 *   - We detect authInfo.isProxy (proxy auth challenge)
	 *   - We provide the username/password via callback()
	 *   - The proxy connection succeeds
	 *
	 * This is ESSENTIAL for proxies that require authentication.
	 * Even if credentials are in proxyRules, Chromium may still
	 * fire the 'login' event in some cases.
	 */
	private createLoginHandler(proxy: ProxyEntry): (...args: any[]) => void {
		return (
			event: any,
			_webContents: any,
			_request: any,
			authInfo: any,
			callback: any
		) => {
			if (authInfo?.isProxy && proxy.username && proxy.password) {
				event.preventDefault();
				callback(proxy.username, proxy.password);
			}
		};
	}

	/**
	 * Register login handler on all discovered sessions.
	 * Remove old handler first to prevent duplicates.
	 */
	private async registerLoginHandlers(proxy: ProxyEntry): Promise<void> {
		await this.unregisterLoginHandlers();
		this.loginHandler = this.createLoginHandler(proxy);
		const sessions = await this.getAllSessions();
		for (const session of sessions) {
			try {
				session.on("login", this.loginHandler);
			} catch {}
		}
	}

	/**
	 * Remove login handler from all sessions.
	 */
	private async unregisterLoginHandlers(): Promise<void> {
		if (!this.loginHandler) return;
		const sessions = await this.getAllSessions();
		for (const session of sessions) {
			try {
				session.removeListener("login", this.loginHandler);
			} catch {}
		}
		this.loginHandler = null;
	}

	// ──────────────────────────────────────────────────────────
	//  ENVIRONMENT VARIABLES
	// ──────────────────────────────────────────────────────────

	/**
	 * Set process.env proxy variables.
	 *
	 * For HTTP proxy:
	 *   HTTP_PROXY=http://user:pass@host:port
	 *   HTTPS_PROXY=http://user:pass@host:port
	 *   ALL_PROXY=http://user:pass@host:port
	 *
	 * For SOCKS5 proxy:
	 *   HTTP_PROXY=socks5://user:pass@host:port  (for libs that support it)
	 *   HTTPS_PROXY=socks5://user:pass@host:port
	 *   ALL_PROXY=socks5://user:pass@host:port
	 *
	 * Note: Most HTTP libraries (axios, node-fetch) only understand
	 * http:// scheme in HTTP_PROXY. For SOCKS5, they need
	 * socks-proxy-agent or similar. ALL_PROXY with socks5:// is
	 * the standard fallback for SOCKS5-aware libraries (got, etc.)
	 */
	setEnvironmentProxy(proxy: ProxyEntry) {
		const auth =
			proxy.username && proxy.password
				? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`
				: "";

		let httpUrl: string;
		let allUrl: string;

		if (proxy.proxyType === "socks5") {
			httpUrl = `socks5://${auth}${proxy.host}:${proxy.port}`;
			allUrl = `socks5://${auth}${proxy.host}:${proxy.port}`;
		} else {
			httpUrl = `http://${auth}${proxy.host}:${proxy.port}`;
			allUrl = `http://${auth}${proxy.host}:${proxy.port}`;
		}

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
	 * Apply proxy to ALL discovered sessions + env vars + login handler.
	 *
	 * Three-layer approach:
	 *   1) session.setProxy({ mode: 'fixed_servers', proxyRules })
	 *   2) session.on('login', handler) — for 407 proxy auth
	 *   3) process.env — for Node.js stack
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

		// ── Layer 1: setProxy on all sessions ──
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

		// ── Layer 2: login handler for proxy auth ──
		await this.registerLoginHandlers(proxy);

		// ── Layer 3: environment variables ──
		this.setEnvironmentProxy(proxy);

		// ── Verification ──
		if (applied === 0) {
			new Notice(
				"Obsi Proxy: could not apply proxy to any Electron session. Run Diagnostics for details."
			);
			return false;
		}

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
			`Obsi Proxy: applied to ${applied}/${sessions.length} sessions, login handler registered, env vars set, verified=${verified}`
		);
		console.log(`Obsi Proxy: proxyRules = "${rules}"`);

		new Notice(
			`Obsi Proxy: ON — ${proxy.name} (${applied} sessions${verified ? ", verified" : ""})`
		);
		return true;
	}

	/**
	 * Clear proxy from ALL sessions + restore env + remove login handler.
	 */
	async clearProxy(): Promise<void> {
		await this.unregisterLoginHandlers();

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
	 * Re-apply proxy + login handler every 30s to catch new sessions.
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

				if (this.loginHandler) {
					try {
						session.removeListener("login", this.loginHandler);
						session.on("login", this.loginHandler);
					} catch {}
				}
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
	 * Check proxy by making a test request.
	 * Works even when proxy is NOT currently active:
	 *   1. Temporarily apply proxy to ALL sessions + env vars
	 *   2. Wait 500ms for Chromium to update proxy config
	 *   3. Make test request to ipify.org
	 *   4. Revert to previous state
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

			if (proxy.username && proxy.password) {
				const handler = this.createLoginHandler(proxy);
				for (const session of sessions) {
					try { session.on("login", handler); } catch {}
				}
			}

			this.setEnvironmentProxy(proxy);
			needsRevert = true;

			await new Promise((resolve) => setTimeout(resolve, 500));
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
				if (this.settings.enabled && this.getActiveProxy()) {
					const activeProxy = this.getActiveProxy()!;
					const activeRules = this.buildProxyRules(activeProxy);
					const sessions = await this.getAllSessions();
					for (const session of sessions) {
						try {
							await session.setProxy({
								mode: "fixed_servers",
								proxyRules: activeRules,
								proxyBypassRules: "",
							});
						} catch {}
					}
					await this.registerLoginHandlers(activeProxy);
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
					await this.unregisterLoginHandlers();
					this.clearEnvironmentProxy();
				}
			}
		}
	}

	// ──────────────────────────────────────────────────────────
	//  DIAGNOSTICS
	// ──────────────────────────────────────────────────────────

	async getDiagnostics(): Promise<string> {
		const lines: string[] = [];

		lines.push("=== Obsi Proxy Diagnostics ===");
		lines.push("");

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

		lines.push("");
		lines.push(`Proxy enabled: ${this.settings.enabled}`);
		lines.push(`Active proxy ID: ${this.settings.activeProxyId || "(none)"}`);
		lines.push(`Saved proxies: ${this.settings.proxies.length}`);
		lines.push(`Session watch active: ${this.sessionWatchInterval !== null}`);
		lines.push(`Login handler registered: ${this.loginHandler !== null}`);

		const active = this.getActiveProxy();
		if (active) {
			lines.push("");
			lines.push("Active proxy details:");
			lines.push(`  Name: ${active.name}`);
			lines.push(`  Type: ${active.proxyType}`);
			lines.push(`  Host: ${active.host}`);
			lines.push(`  Port: ${active.port}`);
			lines.push(`  Has auth: ${!!(active.username && active.password)}`);
			lines.push(`  proxyRules: "${this.buildProxyRules(active)}"`);
		}

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
				"HTTP routes HTTP/HTTPS traffic through HTTP CONNECT. SOCKS5 proxies all TCP with DNS on the proxy side."
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
			.setDesc("IP address or hostname of the proxy server")
			.addText((text) =>
				text
					.setPlaceholder("e.g. 167.148.96.23")
					.setValue(this.entry.host)
					.onChange((val) => {
						this.entry.host = val.trim();
					})
			);

		new Setting(contentEl)
			.setName("Port")
			.setDesc("Port number of the proxy server")
			.addText((text) =>
				text
					.setPlaceholder("e.g. 47866")
					.setValue(this.entry.port)
					.onChange((val) => {
						this.entry.port = val.trim();
					})
			);

		new Setting(contentEl)
			.setName("Username")
			.setDesc("Leave empty if proxy does not require authentication")
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
			.setDesc("Leave empty if proxy does not require authentication")
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
