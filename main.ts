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
// @ts-ignore — bundled by esbuild, no type declarations
import { HttpsProxyAgent } from "https-proxy-agent";
// @ts-ignore — bundled by esbuild, no type declarations
import { SocksProxyAgent } from "socks-proxy-agent";

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
 *  FOUR-LAYER TRAFFIC INTERCEPTION ARCHITECTURE
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Obsidian runs on Electron (Chromium + Node.js). Plugins can
 * make network requests through two COMPLETELY SEPARATE stacks:
 *
 *  STACK 1: Chromium (renderer browser APIs)
 *    - fetch(), XMLHttpRequest, browser WebSocket
 *    - Obsidian's requestUrl()
 *    - Webviews, <img src>, CSS url()
 *    → Controlled by session.setProxy()
 *
 *  STACK 2: Node.js (built-in modules)
 *    - require('http').request(), require('https').request()
 *    - Used internally by: node-telegram-bot-api, axios,
 *      node-fetch, got, and MANY other npm packages
 *    → NOT controlled by session.setProxy()
 *    → NOT controlled by HTTP_PROXY env vars
 *      (Node.js built-in http/https do NOT read env vars!)
 *    → Controlled ONLY by replacing http.globalAgent
 *      and https.globalAgent with a proxy-aware agent
 *
 * This plugin applies proxy at FOUR layers:
 *
 *  A) session.setProxy({ mode: 'fixed_servers' })
 *     - Chromium network stack
 *     - All sessions: defaultSession, BrowserWindows, partitions
 *
 *  B) session.on('login') handler
 *     - 407 Proxy Auth Required responses
 *     - Chromium fires 'login' event, we provide credentials
 *
 *  C) http.globalAgent / https.globalAgent replacement
 *     - Node.js http/https module
 *     - Uses HttpsProxyAgent or SocksProxyAgent
 *     - This is the ONLY way to make node-telegram-bot-api
 *       and other Node.js-based libraries go through proxy
 *     - Original agents saved and restored on disable
 *
 *  D) process.env variables
 *     - HTTP_PROXY, HTTPS_PROXY, ALL_PROXY
 *     - Covers libraries that explicitly read env vars
 *       (axios with proxy config, got, node-fetch v3+)
 *     - Does NOT cover Node.js built-in http/https!
 *
 *  E) Periodic refresh every 30s
 *     - Re-applies all layers to catch new sessions
 *
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */
export default class ObsiProxyPlugin extends Plugin {
	settings: ProxySettings = DEFAULT_SETTINGS;
	private sessionWatchInterval: number | null = null;
	private originalEnv: Map<string, string | undefined> = new Map();
	private lastSessionCount: number = 0;
	private loginHandler: ((...args: any[]) => void) | null = null;

	// ── Node.js globalAgent backup ──
	private originalHttpAgent: any = null;
	private originalHttpsAgent: any = null;

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
	 * When credentials are present, the proxy URL MUST include
	 * the scheme prefix (http://) explicitly:
	 *
	 *   CORRECT: "http=http://user:pass@host:port;https=http://user:pass@host:port"
	 *   WRONG:   "http=user:pass@host:port;https=user:pass@host:port"
	 *            → Chromium misparses: host="user", port="pass@host..."
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

	/**
	 * Build a proxy URL for agent/env usage.
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
	//  LOGIN HANDLER (PROXY AUTH)
	// ──────────────────────────────────────────────────────────

	/**
	 * session.on('login') handler — critical for proxy auth.
	 *
	 * When proxy sends 407 Proxy Auth Required, Chromium fires
	 * the 'login' event. Without a handler, the connection is
	 * silently dropped. With our handler, we provide credentials.
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

	private async registerLoginHandlers(proxy: ProxyEntry): Promise<void> {
		await this.unregisterLoginHandlers();
		this.loginHandler = this.createLoginHandler(proxy);
		const sessions = await this.getAllSessions();
		for (const session of sessions) {
			try { session.on("login", this.loginHandler); } catch {}
		}
	}

	private async unregisterLoginHandlers(): Promise<void> {
		if (!this.loginHandler) return;
		const sessions = await this.getAllSessions();
		for (const session of sessions) {
			try { session.removeListener("login", this.loginHandler); } catch {}
		}
		this.loginHandler = null;
	}

	// ──────────────────────────────────────────────────────────
	//  NODE.JS GLOBAL AGENT PATCH
	// ──────────────────────────────────────────────────────────

	/**
	 * Replace http.globalAgent and https.globalAgent with proxy agents.
	 *
	 * ─── WHY THIS IS NECESSARY ───
	 *
	 * Node.js built-in http/https modules do NOT read HTTP_PROXY
	 * or HTTPS_PROXY environment variables. When a plugin like
	 * obsidian-telegram-sync uses node-telegram-bot-api (which
	 * internally calls require('https').request()), the request
	 * goes DIRECTLY to the target, ignoring all proxy settings.
	 *
	 * The ONLY way to make Node.js http/https go through a proxy
	 * is to replace their globalAgent with a proxy-aware agent:
	 *
	 *   http.globalAgent = new HttpsProxyAgent(proxyUrl)
	 *   https.globalAgent = new HttpsProxyAgent(proxyUrl)
	 *
	 * This intercepts ALL http/https requests made by ANY code
	 * in the process, including:
	 *   - node-telegram-bot-api (Telegram bot long polling)
	 *   - axios (when no explicit agent is specified)
	 *   - node-fetch (when no explicit agent is specified)
	 *   - Any other library using Node.js http/https
	 *
	 * For SOCKS5 proxy, we use SocksProxyAgent which implements
	 * the SOCKS5 handshake before establishing the TCP tunnel.
	 *
	 * We save the original agents and restore them on disable.
	 */
	private setGlobalProxyAgent(proxy: ProxyEntry): void {
		const proxyUrl = this.buildProxyUrl(proxy);
		const nodeHttp = require("http");
		const nodeHttps = require("https");

		if (!this.originalHttpAgent) {
			this.originalHttpAgent = nodeHttp.globalAgent;
		}
		if (!this.originalHttpsAgent) {
			this.originalHttpsAgent = nodeHttps.globalAgent;
		}

		if (proxy.proxyType === "socks5") {
			const agent = new SocksProxyAgent(proxyUrl);
			nodeHttp.globalAgent = agent;
			nodeHttps.globalAgent = agent;
		} else {
			const agent = new HttpsProxyAgent(proxyUrl);
			nodeHttp.globalAgent = agent;
			nodeHttps.globalAgent = agent;
		}

		console.log(`Obsi Proxy: globalAgent set to ${proxyUrl.replace(/:[^@]+@/, ":****@")}`);
	}

	/**
	 * Restore original http/https globalAgents.
	 */
	private clearGlobalProxyAgent(): void {
		const nodeHttp = require("http");
		const nodeHttps = require("https");
		if (this.originalHttpAgent) {
			nodeHttp.globalAgent = this.originalHttpAgent;
			this.originalHttpAgent = null;
		}
		if (this.originalHttpsAgent) {
			nodeHttps.globalAgent = this.originalHttpsAgent;
			this.originalHttpsAgent = null;
		}
		console.log("Obsi Proxy: globalAgent restored to original");
	}

	// ──────────────────────────────────────────────────────────
	//  ENVIRONMENT VARIABLES
	// ──────────────────────────────────────────────────────────

	setEnvironmentProxy(proxy: ProxyEntry) {
		const proxyUrl = this.buildProxyUrl(proxy);

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

		process.env.HTTP_PROXY = proxyUrl;
		process.env.HTTPS_PROXY = proxyUrl;
		process.env.ALL_PROXY = proxyUrl;
		process.env.http_proxy = proxyUrl;
		process.env.https_proxy = proxyUrl;
		process.env.all_proxy = proxyUrl;
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
	 * Apply proxy at ALL four layers.
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

		// ── Layer 1: Chromium session.setProxy ──
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

		// ── Layer 2: session.on('login') for 407 auth ──
		await this.registerLoginHandlers(proxy);

		// ── Layer 3: Node.js globalAgent replacement ──
		// This is what makes node-telegram-bot-api work through proxy!
		this.setGlobalProxyAgent(proxy);

		// ── Layer 4: Environment variables ──
		this.setEnvironmentProxy(proxy);

		// ── Verification ──
		if (applied === 0) {
			new Notice(
				"Obsi Proxy: could not apply proxy to any Electron session. Run Diagnostics."
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

		console.log(
			`Obsi Proxy: applied to ${applied}/${sessions.length} sessions, globalAgent patched, env vars set, verified=${verified}`
		);
		console.log(`Obsi Proxy: proxyRules = "${rules}"`);

		new Notice(
			`Obsi Proxy: ON — ${proxy.name} (${applied} sessions + Node.js patched${verified ? ", verified" : ""})`
		);
		return true;
	}

	/**
	 * Clear proxy at ALL four layers.
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

		this.clearGlobalProxyAgent();
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

			this.setGlobalProxyAgent(proxy);
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
					this.setGlobalProxyAgent(activeProxy);
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
					this.clearGlobalProxyAgent();
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
				const resolved = await session.resolveProxy("https://example.com");
				lines.push(`  Session ${i}: resolveProxy = "${resolved}"`);
			} catch (err) {
				lines.push(`  Session ${i}: resolveProxy failed — ${err}`);
			}
		}

		lines.push("");
		lines.push("Environment variables:");
		for (const key of [
			"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
			"http_proxy", "https_proxy", "all_proxy",
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

		lines.push("");
		lines.push("Node.js globalAgent:");
		const nodeHttp = require("http");
		const nodeHttps = require("https");
		lines.push(`  http.globalAgent type: ${nodeHttp.globalAgent.constructor.name}`);
		lines.push(`  https.globalAgent type: ${nodeHttps.globalAgent.constructor.name}`);
		lines.push(`  Original http agent saved: ${this.originalHttpAgent !== null}`);
		lines.push(`  Original https agent saved: ${this.originalHttpsAgent !== null}`);

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
			lines.push(`  proxyUrl: "${this.buildProxyUrl(active).replace(/:[^@]+@/, ":****@")}"`);
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
				text: "Note: This proxy was temporarily applied for the check and then reverted.",
				attr: { style: "font-style: italic; color: var(--text-muted);" },
			});
		}

		if (this.error) {
			contentEl.createEl("p", {
				text: `Error: ${this.error}`,
				cls: "obsi-proxy-check-result",
				attr: {
					style: "background: var(--background-modifier-error); color: var(--text-error);",
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
					style: "background: var(--background-modifier-success); color: var(--text-success); font-size: 16px; font-weight: 600;",
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

		contentEl.createEl("h2", { text: this.isNew ? "Add Proxy" : "Edit Proxy" });

		new Setting(contentEl)
			.setName("Name")
			.setDesc("A friendly name for this proxy")
			.addText((text) =>
				text.setPlaceholder("e.g. Work VPN").setValue(this.entry.name).onChange((val) => {
					this.entry.name = val;
				})
			);

		new Setting(contentEl)
			.setName("Proxy type")
			.setDesc("HTTP routes HTTP/HTTPS. SOCKS5 proxies all TCP with DNS on the proxy side.")
			.addDropdown((dd) =>
				dd.addOption("http", "HTTP").addOption("socks5", "SOCKS5").setValue(this.entry.proxyType).onChange((val: string) => {
					this.entry.proxyType = val as "http" | "socks5";
				})
			);

		new Setting(contentEl)
			.setName("Host")
			.setDesc("IP address or hostname of the proxy server")
			.addText((text) =>
				text.setPlaceholder("e.g. 167.148.96.23").setValue(this.entry.host).onChange((val) => {
					this.entry.host = val.trim();
				})
			);

		new Setting(contentEl)
			.setName("Port")
			.setDesc("Port number of the proxy server")
			.addText((text) =>
				text.setPlaceholder("e.g. 47866").setValue(this.entry.port).onChange((val) => {
					this.entry.port = val.trim();
				})
			);

		new Setting(contentEl)
			.setName("Username")
			.setDesc("Leave empty if proxy does not require authentication")
			.addText((text) =>
				text.setPlaceholder("optional").setValue(this.entry.username).onChange((val) => {
					this.entry.username = val;
				})
			);

		new Setting(contentEl)
			.setName("Password")
			.setDesc("Leave empty if proxy does not require authentication")
			.addText((text) => {
				text.inputEl.type = "password";
				text.setPlaceholder("optional").setValue(this.entry.password).onChange((val) => {
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
			btn.setButtonText("Copy to Clipboard").onClick(() => {
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
			.setDesc("Route all Obsidian and plugin traffic through the selected proxy (Chromium + Node.js)")
			.addToggle((toggle) =>
				toggle.setValue(this.plugin.settings.enabled).onChange(async (val) => {
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
				btn.setButtonText("+ Add Proxy").setCta().onClick(() => {
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
						this.app, this.plugin, newEntry, true,
						async (entry) => {
							this.plugin.settings.proxies.push(entry);
							if (!this.plugin.settings.activeProxyId || this.plugin.settings.proxies.length === 1) {
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

		const isSelected = this.plugin.settings.activeProxyId === proxy.id;

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

		const header = item.createEl("div", { cls: "obsi-proxy-list-item-header" });
		header.createEl("span", {
			text: isSelected ? `\u25B6 ${proxy.name}` : proxy.name,
			cls: "obsi-proxy-list-item-name",
		});

		const actions = header.createEl("div", { cls: "obsi-proxy-list-item-actions" });

		const checkBtn = actions.createEl("button", { text: "Check" });
		checkBtn.addEventListener("click", async (e) => {
			e.stopPropagation();
			checkBtn.textContent = "...";
			checkBtn.setAttribute("disabled", "true");

			const wasActive =
				this.plugin.settings.enabled && this.plugin.settings.activeProxyId === proxy.id;

			const result = await this.plugin.checkConnection(proxy);
			const error = result === null
				? "Connection failed — proxy may be unreachable or credentials are wrong"
				: null;

			checkBtn.textContent = "Check";
			checkBtn.removeAttribute("disabled");

			if (error) {
				new Notice("Obsi Proxy: check failed", 5000);
			} else if (result) {
				new Notice(`Obsi Proxy: IP is ${result.ip}`, 5000);
			}

			const modal = new ProxyCheckModal(this.app, proxy.name, result, error, wasActive);
			modal.open();
		});

		const editBtn = actions.createEl("button", { text: "Edit" });
		editBtn.addEventListener("click", (e) => {
			e.stopPropagation();
			const modal = new ProxyEditModal(this.app, this.plugin, proxy, false,
				async (entry) => {
					const idx = this.plugin.settings.proxies.findIndex((p) => p.id === entry.id);
					if (idx >= 0) {
						this.plugin.settings.proxies[idx] = entry;
					}
					await this.plugin.saveSettings();
					if (this.plugin.settings.enabled && this.plugin.settings.activeProxyId === entry.id) {
						await this.plugin.enableProxy();
					}
					this.display();
				}
			);
			modal.open();
		});

		const delBtn = actions.createEl("button", { text: "Delete" });
		delBtn.addEventListener("click", async (e) => {
			e.stopPropagation();
			this.plugin.settings.proxies = this.plugin.settings.proxies.filter((p) => p.id !== proxy.id);
			if (this.plugin.settings.activeProxyId === proxy.id) {
				this.plugin.settings.activeProxyId =
					this.plugin.settings.proxies.length > 0 ? this.plugin.settings.proxies[0].id : "";
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
			.setDesc("Instantly clear all proxy rules and restore direct connection")
			.addButton((btn) =>
				btn.setButtonText("Disable Proxy Now").setWarning().onClick(async () => {
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
			.setDesc("Check Electron session access, Node.js agent type, proxy state, and environment variables")
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
