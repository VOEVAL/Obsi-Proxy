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
// @ts-ignore
import { HttpsProxyAgent } from "https-proxy-agent";
// @ts-ignore
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
 *  FIVE-LAYER TRAFFIC INTERCEPTION
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 *  Layer 1: session.setProxy() — Chromium stack
 *    Covers: fetch, XHR, requestUrl, browser WebSocket, webviews
 *    Critical: must VERIFY with resolveProxy() after each call
 *    Tries multiple config formats until one works
 *    Calls closeAllConnections() to flush old connections
 *
 *  Layer 2: session.on('login') — 407 proxy auth
 *
 *  Layer 3: http/https.globalAgent — Node.js stack
 *    Covers: require('https').request(), node-telegram-bot-api, axios
 *    Uses HttpsProxyAgent or SocksProxyAgent
 *
 *  Layer 4: process.env — libraries that read env vars
 *
 *  Layer 5: Periodic refresh every 15s
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */
export default class ObsiProxyPlugin extends Plugin {
	settings: ProxySettings = DEFAULT_SETTINGS;
	private sessionWatchInterval: number | null = null;
	private originalEnv: Map<string, string | undefined> = new Map();
	private loginHandler: ((...args: any[]) => void) | null = null;
	private originalHttpAgent: any = null;
	private originalHttpsAgent: any = null;
	private lastApplyLog: string = "";

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
		return this.settings.proxies.find((p) => p.id === this.settings.activeProxyId) ?? null;
	}

	// ──────────────────────────────────────────────────────────
	//  SESSION DISCOVERY
	// ──────────────────────────────────────────────────────────

	private getRemote(): any {
		try {
			const e = (window as any).require("electron");
			if (e?.remote) return e.remote;
		} catch {}
		try {
			const r = (window as any).require("@electron/remote");
			if (r) return r;
		} catch {}
		return null;
	}

	/**
	 * Get the single most important session: the one used by the
	 * current BrowserWindow for ALL its network requests.
	 */
	private getPrimarySession(): ElectronSession | null {
		const remote = this.getRemote();
		if (!remote) return null;

		// Priority: current window's session > defaultSession
		try {
			const win = remote.getCurrentWindow();
			const s = win?.webContents?.session;
			if (s && typeof s.setProxy === "function") return s;
		} catch {}

		try {
			const s = remote.session?.defaultSession;
			if (s && typeof s.setProxy === "function") return s;
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
		}

		try {
			const e = (window as any).require("electron");
			try { add(e.session?.defaultSession); } catch {}
		} catch {}

		return sessions;
	}

	// ──────────────────────────────────────────────────────────
	//  PROXY RULES BUILDER
	// ──────────────────────────────────────────────────────────

	/**
	 * Generate multiple proxyRules formats to try.
	 *
	 * Different Electron/Chromium versions parse proxyRules differently.
	 * We try formats from most explicit to simplest, and use whichever
	 * one makes resolveProxy() return a non-DIRECT result.
	 */
	buildProxyRulesFormats(proxy: ProxyEntry): string[] {
		const { host, port } = proxy;
		if (!host || !port) return [];

		/**
		 * Deep test proved: this Chromium version does NOT support
		 * credentials in proxyRules. Only the bare host:port format
		 * makes resolveProxy() return non-DIRECT.
		 *
		 * Auth MUST go through session.on('login') handler instead.
		 *
		 * We still try credential formats as fallback for other
		 * Chromium versions, but put the working format first.
		 */

		if (proxy.proxyType === "socks5") {
			return [
				// Format 1 (best): no creds — works on ALL Chromium versions
				`socks5://${host}:${port}`,
				// Format 2: with creds — may work on newer Chromium
				...(proxy.username && proxy.password
					? [`socks5://${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@${host}:${port}`]
					: []),
			];
		}

		const formats: string[] = [];

		// Format 1 (best): traffic-type + host:port, NO credentials
		// This is the ONLY format that works on most Electron versions
		formats.push(`http=${host}:${port};https=${host}:${port}`);

		// Format 2: single host:port without traffic-type
		formats.push(`${host}:${port}`);

		// Format 3: with creds in URL (may work on some Chromium versions)
		if (proxy.username && proxy.password) {
			const auth = `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`;
			formats.push(`http=http://${auth}${host}:${port};https=http://${auth}${host}:${port}`);
			formats.push(`http://${auth}${host}:${port}`);
		}

		return formats;
	}

	buildProxyUrl(proxy: ProxyEntry): string {
		const auth = proxy.username && proxy.password
			? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`
			: "";
		if (proxy.proxyType === "socks5") {
			return `socks5://${auth}${proxy.host}:${proxy.port}`;
		}
		return `http://${auth}${proxy.host}:${proxy.port}`;
	}

	// ──────────────────────────────────────────────────────────
	//  LOGIN HANDLER
	// ──────────────────────────────────────────────────────────

	private createLoginHandler(proxy: ProxyEntry): (...args: any[]) => void {
		return (event: any, webContents: any, request: any, authInfo: any, callback: any) => {
			console.log("Obsi Proxy: login event fired", {
				isProxy: authInfo?.isProxy,
				scheme: authInfo?.scheme,
				host: authInfo?.host,
				port: authInfo?.port,
				realm: authInfo?.realm,
			});

			if (proxy.username && proxy.password) {
				event.preventDefault();
				callback(proxy.username, proxy.password);
			}
		};
	}

	private async registerLoginHandlers(proxy: ProxyEntry): Promise<void> {
		await this.unregisterLoginHandlers();
		this.loginHandler = this.createLoginHandler(proxy);

		// Register on sessions
		const sessions = await this.getAllSessions();
		for (const s of sessions) {
			try { s.on("login", this.loginHandler); } catch {}
		}

		// Also register on webContents — some Electron versions
		// fire the 'login' event on webContents instead of session
		const remote = this.getRemote();
		if (remote) {
			try {
				const windows: any[] = remote.BrowserWindow.getAllWindows();
				for (const win of windows) {
					try { win.webContents?.on("login", this.loginHandler); } catch {}
				}
			} catch {}
			try {
				const win = remote.getCurrentWindow();
				try { win?.webContents?.on("login", this.loginHandler); } catch {}
			} catch {}
		}
	}

	private async unregisterLoginHandlers(): Promise<void> {
		if (!this.loginHandler) return;

		const sessions = await this.getAllSessions();
		for (const s of sessions) {
			try { s.removeListener("login", this.loginHandler); } catch {}
		}

		const remote = this.getRemote();
		if (remote) {
			try {
				const windows: any[] = remote.BrowserWindow.getAllWindows();
				for (const win of windows) {
					try { win.webContents?.removeListener("login", this.loginHandler); } catch {}
				}
			} catch {}
			try {
				const win = remote.getCurrentWindow();
				try { win?.webContents?.removeListener("login", this.loginHandler); } catch {}
			} catch {}
		}

		this.loginHandler = null;
	}

	// ──────────────────────────────────────────────────────────
	//  NODE.JS GLOBAL AGENT
	// ──────────────────────────────────────────────────────────

	private setGlobalProxyAgent(proxy: ProxyEntry): void {
		const proxyUrl = this.buildProxyUrl(proxy);
		const nodeHttp = require("http");
		const nodeHttps = require("https");

		if (!this.originalHttpAgent) this.originalHttpAgent = nodeHttp.globalAgent;
		if (!this.originalHttpsAgent) this.originalHttpsAgent = nodeHttps.globalAgent;

		if (proxy.proxyType === "socks5") {
			const agent = new SocksProxyAgent(proxyUrl);
			nodeHttp.globalAgent = agent;
			nodeHttps.globalAgent = agent;
		} else {
			const agent = new HttpsProxyAgent(proxyUrl);
			nodeHttp.globalAgent = agent;
			nodeHttps.globalAgent = agent;
		}
	}

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
	}

	// ──────────────────────────────────────────────────────────
	//  ENVIRONMENT VARIABLES
	// ──────────────────────────────────────────────────────────

	setEnvironmentProxy(proxy: ProxyEntry) {
		const proxyUrl = this.buildProxyUrl(proxy);
		const keys = ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"];
		for (const key of keys) {
			if (!this.originalEnv.has(key)) this.originalEnv.set(key, process.env[key]);
		}
		for (const key of keys) {
			const upper = key.toUpperCase();
			process.env[upper] = proxyUrl;
			if (key !== upper) process.env[key] = proxyUrl;
		}
	}

	clearEnvironmentProxy() {
		const keys = ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"];
		for (const key of keys) {
			const original = this.originalEnv.get(key);
			if (original === undefined) { delete process.env[key]; }
			else { process.env[key] = original; }
		}
		this.originalEnv.clear();
	}

	// ──────────────────────────────────────────────────────────
	//  SESSION SET PROXY — WITH VERIFICATION
	// ──────────────────────────────────────────────────────────

	/**
	 * Try to set proxy on a session and verify it worked.
	 *
	 * This is the critical fix: we try MULTIPLE config formats
	 * because different Electron/Chromium versions parse
	 * proxyRules differently. After each attempt, we verify
	 * with resolveProxy(). If it returns DIRECT, the format
	 * didn't work and we try the next one.
	 *
	 * We also try WITH and WITHOUT the `mode` parameter,
	 * because some Electron versions ignore mode while
	 * others require it.
	 */
	private async setProxyWithVerify(
		session: ElectronSession,
		proxy: ProxyEntry
	): Promise<boolean> {
		const formats = this.buildProxyRulesFormats(proxy);
		const modeOptions: (string | undefined)[] = ["fixed_servers", undefined, "system", "direct"];

		for (const mode of modeOptions) {
			for (const rules of formats) {
				try {
					const config: any = {
						proxyRules: rules,
						proxyBypassRules: "",
					};
					if (mode) config.mode = mode;

					await session.setProxy(config);

					// Verify immediately
					const resolved = await session.resolveProxy("https://example.com");
					if (resolved && resolved !== "DIRECT") {
						console.log(
							`Obsi Proxy: setProxy WORKED with mode=${mode}, rules="${rules}" → resolved="${resolved}"`
						);
						this.lastApplyLog = `SUCCESS: mode=${mode}, rules="${rules}", resolved="${resolved}"`;

						// Close existing connections so new ones use proxy
						try {
							if ((session as any).closeAllConnections) {
								await (session as any).closeAllConnections();
							}
						} catch {}

						return true;
					}
				} catch (err) {
					// Try next combination
				}
			}
		}

		console.warn("Obsi Proxy: ALL setProxy formats failed — resolveProxy still returns DIRECT");
		this.lastApplyLog = "FAILED: all format/mode combinations tried, resolveProxy still DIRECT";
		return false;
	}

	// ──────────────────────────────────────────────────────────
	//  PROXY APPLY / CLEAR
	// ──────────────────────────────────────────────────────────

	async applyProxy(): Promise<boolean> {
		const proxy = this.getActiveProxy();
		if (!proxy) {
			new Notice("Obsi Proxy: no proxy selected");
			return false;
		}

		const formats = this.buildProxyRulesFormats(proxy);
		if (formats.length === 0) {
			new Notice("Obsi Proxy: host and port are required");
			return false;
		}

		// ── Layer 1: Chromium session.setProxy with verification ──
		let anyVerified = false;
		const sessions = await this.getAllSessions();
		const verifiedSessions: ElectronSession[] = [];

		for (const session of sessions) {
			const ok = await this.setProxyWithVerify(session, proxy);
			if (ok) {
				anyVerified = true;
				verifiedSessions.push(session);
			}
		}

		// If no session verified, try the primary session with extra force
		if (!anyVerified) {
			const primary = this.getPrimarySession();
			if (primary) {
				const ok = await this.setProxyWithVerify(primary, proxy);
				if (ok) {
					anyVerified = true;
					verifiedSessions.push(primary);
				}
			}
		}

		// ── Layer 2: Login handler ──
		await this.registerLoginHandlers(proxy);

		// ── Layer 3: Node.js globalAgent ──
		this.setGlobalProxyAgent(proxy);

		// ── Layer 4: Environment variables ──
		this.setEnvironmentProxy(proxy);

		// Report
		if (!anyVerified) {
			new Notice(
				"Obsi Proxy: WARNING — session.setProxy could not be verified. Chromium traffic may not go through proxy. Run Diagnostics for details.",
				8000
			);
			console.error("Obsi Proxy: session.setProxy verification failed on ALL sessions");
			console.error(`Obsi Proxy: last attempt log: ${this.lastApplyLog}`);
			// Still return true — the other layers (globalAgent, env) are active
			return true;
		}

		new Notice(
			`Obsi Proxy: ON — ${proxy.name} (verified on ${verifiedSessions.length} sessions + Node.js patched)`,
			5000
		);
		return true;
	}

	async clearProxy(): Promise<void> {
		await this.unregisterLoginHandlers();

		const sessions = await this.getAllSessions();
		for (const s of sessions) {
			try {
				await s.setProxy({ mode: "system", proxyRules: "", proxyBypassRules: "" });
			} catch {}
			try {
				if ((s as any).closeAllConnections) await (s as any).closeAllConnections();
			} catch {}
		}

		this.clearGlobalProxyAgent();
		this.clearEnvironmentProxy();
	}

	async enableProxy(): Promise<void> {
		const ok = await this.applyProxy();
		this.settings.enabled = true;
		await this.saveSettings();
		if (ok) this.startSessionWatch();
	}

	async disableProxy(): Promise<void> {
		this.stopSessionWatch();
		await this.clearProxy();
		this.settings.enabled = false;
		await this.saveSettings();
		new Notice("Obsi Proxy: OFF — direct connection restored");
	}

	// ──────────────────────────────────────────────────────────
	//  PERIODIC REFRESH
	// ──────────────────────────────────────────────────────────

	startSessionWatch() {
		if (this.sessionWatchInterval) return;
		this.sessionWatchInterval = window.setInterval(async () => {
			if (!this.settings.enabled || !this.getActiveProxy()) return;
			const proxy = this.getActiveProxy()!;
			const sessions = await this.getAllSessions();
			for (const s of sessions) {
				try {
					// Re-verify: if proxy was lost, re-apply
					const resolved = await s.resolveProxy("https://example.com");
					if (!resolved || resolved === "DIRECT") {
						await this.setProxyWithVerify(s, proxy);
					}
				} catch {}
				if (this.loginHandler) {
					try { s.removeListener("login", this.loginHandler); s.on("login", this.loginHandler); } catch {}
				}
			}
		}, 15000);
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

	async checkConnection(proxy: ProxyEntry): Promise<{ ip: string } | null> {
		const isActive = this.settings.enabled && this.settings.activeProxyId === proxy.id;
		let needsRevert = false;

		if (!isActive) {
			const sessions = await this.getAllSessions();
			for (const s of sessions) {
				try { await this.setProxyWithVerify(s, proxy); } catch {}
			}
			if (proxy.username && proxy.password) {
				const handler = this.createLoginHandler(proxy);
				for (const s of sessions) {
					try { s.on("login", handler); } catch {}
				}
			}
			this.setGlobalProxyAgent(proxy);
			this.setEnvironmentProxy(proxy);
			needsRevert = true;
			await new Promise((r) => setTimeout(r, 500));
		}

		try {
			const resp = await requestUrl({ url: "https://api.ipify.org?format=json", method: "GET" });
			return resp.json as { ip: string };
		} catch (err) {
			console.error("Obsi Proxy check error:", err);
			return null;
		} finally {
			if (needsRevert) {
				if (this.settings.enabled && this.getActiveProxy()) {
					const ap = this.getActiveProxy()!;
					const sessions = await this.getAllSessions();
					for (const s of sessions) {
						try { await this.setProxyWithVerify(s, ap); } catch {}
					}
					await this.registerLoginHandlers(ap);
					this.setGlobalProxyAgent(ap);
					this.setEnvironmentProxy(ap);
				} else {
					await this.clearProxy();
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
				const e = (window as any).require("electron");
				lines.push(`electron.remote available: ${!!e.remote}`);
				try {
					const r = (window as any).require("@electron/remote");
					lines.push(`@electron/remote available: ${!!r}`);
				} catch { lines.push("@electron/remote available: false"); }
			} catch { lines.push("electron require failed"); }
		}

		const sessions = await this.getAllSessions();
		lines.push(`Sessions discovered: ${sessions.length}`);

		for (let i = 0; i < sessions.length; i++) {
			const s = sessions[i];
			try {
				const resolved = await s.resolveProxy("https://example.com");
				lines.push(`  Session ${i}: resolveProxy = "${resolved}"`);
			} catch (err) { lines.push(`  Session ${i}: resolveProxy failed — ${err}`); }
		}

		const primary = this.getPrimarySession();
		lines.push(`Primary session available: ${!!primary}`);
		if (primary) {
			try {
				const resolved = await primary.resolveProxy("https://example.com");
				lines.push(`  Primary session resolveProxy = "${resolved}"`);
			} catch {}
		}

		lines.push("");
		lines.push("Node.js globalAgent:");
		const nodeHttp = require("http");
		const nodeHttps = require("https");
		lines.push(`  http.globalAgent type: ${nodeHttp.globalAgent.constructor.name}`);
		lines.push(`  https.globalAgent type: ${nodeHttps.globalAgent.constructor.name}`);
		lines.push(`  Original http agent saved: ${this.originalHttpAgent !== null}`);
		lines.push(`  Original https agent saved: ${this.originalHttpsAgent !== null}`);

		lines.push("");
		lines.push("Environment variables:");
		for (const key of ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"]) {
			const val = process.env[key];
			lines.push(`  ${key} = ${val ? val.replace(/:[^@]+@/, ":****@") : "(not set)"}`);
		}

		lines.push("");
		lines.push(`Proxy enabled: ${this.settings.enabled}`);
		lines.push(`Active proxy ID: ${this.settings.activeProxyId || "(none)"}`);
		lines.push(`Session watch active: ${this.sessionWatchInterval !== null}`);
		lines.push(`Login handler registered: ${this.loginHandler !== null}`);
		lines.push(`Last apply log: ${this.lastApplyLog || "(none)"}`);

		// ── Real connectivity test ──
		lines.push("");
		lines.push("=== Real Connectivity Test ===");
		const activeProxy = this.getActiveProxy();
		if (activeProxy) {
			// Test 1: Node.js stack via globalAgent
			lines.push("");
			lines.push("Test 1: Node.js https.request (globalAgent)...");
			try {
				const nodeHttps = require("https");
				const testResult = await new Promise<string>((resolve, reject) => {
					const timeout = setTimeout(() => reject(new Error("timeout 10s")), 10000);
					const req = nodeHttps.get("https://api.ipify.org?format=json", (res: any) => {
						let data = "";
						res.on("data", (chunk: any) => { data += chunk; });
						res.on("end", () => { clearTimeout(timeout); resolve(data); });
					});
					req.on("error", (err: any) => { clearTimeout(timeout); reject(err); });
				});
				const json = JSON.parse(testResult);
				lines.push(`  ✓ Node.js test OK — outgoing IP: ${json.ip}`);
			} catch (err: any) {
				lines.push(`  ✗ Node.js test FAILED — ${err.message ?? err}`);
			}

			// Test 2: Chromium stack via requestUrl
			lines.push("");
			lines.push("Test 2: Chromium requestUrl (session proxy)...");
			try {
				const resp = await requestUrl({
					url: "https://api.ipify.org?format=json",
					method: "GET",
				});
				const json = resp.json as { ip: string };
				lines.push(`  ✓ Chromium test OK — outgoing IP: ${json.ip}`);
			} catch (err: any) {
				lines.push(`  ✗ Chromium test FAILED — ${err.message ?? err}`);
				lines.push(`  (This likely means proxy auth (407) is not being handled)`);
			}

			// Test 3: Direct request WITHOUT proxy (for comparison)
			lines.push("");
			lines.push("Test 3: Direct request (no proxy) for IP comparison...");
			try {
				const savedEnabled = this.settings.enabled;
				// Temporarily clear proxy for this test
				const nodeHttp = require("http");
				const nodeHttps = require("https");
				const savedAgent = nodeHttps.globalAgent;
				nodeHttps.globalAgent = this.originalHttpsAgent || new nodeHttps.Agent();

				const sessions = await this.getAllSessions();
				for (const s of sessions) {
					try { await s.setProxy({ mode: "direct", proxyRules: "", proxyBypassRules: "" }); } catch {}
				}

				const resp = await requestUrl({ url: "https://api.ipify.org?format=json", method: "GET" });
				const json = resp.json as { ip: string };
				lines.push(`  ✓ Direct IP: ${json.ip}`);

				// Restore proxy
				nodeHttps.globalAgent = savedAgent;
				if (savedEnabled && activeProxy) {
					for (const s of sessions) {
						try { await this.setProxyWithVerify(s, activeProxy); } catch {}
					}
				}
			} catch (err: any) {
				lines.push(`  ✗ Direct test FAILED — ${err.message ?? err}`);
			}
		}
		const active = this.getActiveProxy();
		if (active) {
			lines.push("");
			lines.push("Active proxy details:");
			lines.push(`  Name: ${active.name}`);
			lines.push(`  Type: ${active.proxyType}`);
			lines.push(`  Host: ${active.host}`);
			lines.push(`  Port: ${active.port}`);
			lines.push(`  Has auth: ${!!(active.username && active.password)}`);
			lines.push(`  proxyUrl: "${this.buildProxyUrl(active).replace(/:[^@]+@/, ":****@")}"`);
			const formats = this.buildProxyRulesFormats(active);
			lines.push(`  proxyRules formats to try:`);
			for (let i = 0; i < formats.length; i++) {
				const f = formats[i].replace(/:[^@]+@/, ":****@");
				lines.push(`    ${i + 1}. "${f}"`);
			}
		}

		return lines.join("\n");
	}

	/**
	 * Deep test: try setProxy with every format on the primary session
	 * and report which ones make resolveProxy return non-DIRECT.
	 */
	async getDeepProxyTest(proxy: ProxyEntry): Promise<string> {
		const lines: string[] = [];
		lines.push("=== Obsi Proxy Deep Test ===");
		lines.push("");

		const session = this.getPrimarySession();
		if (!session) {
			lines.push("ERROR: No primary session available!");
			return lines.join("\n");
		}

		const formats = this.buildProxyRulesFormats(proxy);
		const modes: (string | undefined)[] = ["fixed_servers", undefined, "system"];

		for (const mode of modes) {
			for (let fi = 0; fi < formats.length; fi++) {
				const rules = formats[fi];
				const masked = rules.replace(/:[^@]+@/, ":****@");
				const label = `mode=${mode ?? "(none)"}, format=${fi + 1}`;

				try {
					const config: any = { proxyRules: rules, proxyBypassRules: "" };
					if (mode) config.mode = mode;
					await session.setProxy(config);

					const resolved = await session.resolveProxy("https://example.com");

					if (resolved && resolved !== "DIRECT") {
						lines.push(`✓ ${label}: WORKED → resolved="${resolved}"`);
						lines.push(`  rules: "${masked}"`);
					} else {
						lines.push(`✗ ${label}: DIRECT (rules: "${masked}")`);
					}
				} catch (err) {
					lines.push(`✗ ${label}: ERROR — ${err}`);
				}
			}
		}

		// Reset to current proxy state
		if (this.settings.enabled && this.getActiveProxy()) {
			await this.setProxyWithVerify(session, this.getActiveProxy()!);
		} else {
			try { await session.setProxy({ mode: "system", proxyRules: "", proxyBypassRules: "" }); } catch {}
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

	constructor(app: App, proxyName: string, result: { ip: string } | null, error: string | null, wasActive: boolean) {
		super(app);
		this.proxyName = proxyName;
		this.result = result;
		this.error = error;
		this.wasActiveWhenChecked = wasActive;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.empty();
		contentEl.createEl("h2", { text: "Proxy Connection Check" });
		contentEl.createEl("p", { text: `Checking: ${this.proxyName}`, cls: "obsi-proxy-check-result" });
		if (!this.wasActiveWhenChecked) {
			contentEl.createEl("p", {
				text: "Note: This proxy was temporarily applied for the check and then reverted.",
				attr: { style: "font-style: italic; color: var(--text-muted);" },
			});
		}
		if (this.error) {
			contentEl.createEl("p", { text: `Error: ${this.error}`, cls: "obsi-proxy-check-result",
				attr: { style: "background: var(--background-modifier-error); color: var(--text-error);" } });
			contentEl.createEl("p", { text: "The proxy server is unreachable or credentials are wrong." });
		} else if (this.result) {
			contentEl.createEl("p", { text: `Outgoing IP: ${this.result.ip}`, cls: "obsi-proxy-check-result",
				attr: { style: "background: var(--background-modifier-success); color: var(--text-success); font-size: 16px; font-weight: 600;" } });
			contentEl.createEl("p", {
				text: this.wasActiveWhenChecked
					? "This IP belongs to your proxy server. Connection is working correctly."
					: "This is the IP that would be seen if you enable this proxy." });
		}
		new Setting(contentEl).addButton((btn) => btn.setButtonText("Close").onClick(() => this.close()));
	}

	onClose() { this.contentEl.empty(); }
}

class ProxyEditModal extends Modal {
	plugin: ObsiProxyPlugin;
	entry: ProxyEntry;
	onSave: (entry: ProxyEntry) => void;
	isNew: boolean;

	constructor(app: App, plugin: ObsiProxyPlugin, entry: ProxyEntry, isNew: boolean, onSave: (e: ProxyEntry) => void) {
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

		new Setting(contentEl).setName("Name").setDesc("A friendly name").addText((t) =>
			t.setPlaceholder("e.g. Work VPN").setValue(this.entry.name).onChange((v) => { this.entry.name = v; }));

		new Setting(contentEl).setName("Proxy type").setDesc("HTTP or SOCKS5").addDropdown((dd) =>
			dd.addOption("http","HTTP").addOption("socks5","SOCKS5").setValue(this.entry.proxyType).onChange((v) => { this.entry.proxyType = v as "http"|"socks5"; }));

		new Setting(contentEl).setName("Host").setDesc("IP or hostname").addText((t) =>
			t.setPlaceholder("e.g. 167.148.96.23").setValue(this.entry.host).onChange((v) => { this.entry.host = v.trim(); }));

		new Setting(contentEl).setName("Port").setDesc("Port number").addText((t) =>
			t.setPlaceholder("e.g. 47866").setValue(this.entry.port).onChange((v) => { this.entry.port = v.trim(); }));

		new Setting(contentEl).setName("Username").setDesc("Optional").addText((t) =>
			t.setPlaceholder("optional").setValue(this.entry.username).onChange((v) => { this.entry.username = v; }));

		new Setting(contentEl).setName("Password").setDesc("Optional").addText((t) => {
			t.inputEl.type = "password";
			t.setPlaceholder("optional").setValue(this.entry.password).onChange((v) => { this.entry.password = v; });
		});

		new Setting(contentEl).addButton((btn) =>
			btn.setButtonText(this.isNew ? "Add Proxy" : "Save Changes").setCta().onClick(() => {
				if (!this.entry.name.trim()) this.entry.name = `${this.entry.proxyType}://${this.entry.host}:${this.entry.port}`;
				if (!this.entry.host || !this.entry.port) { new Notice("Obsi Proxy: host and port required"); return; }
				this.onSave(this.entry);
				this.close();
			}));
	}

	onClose() { this.contentEl.empty(); }
}

class DiagnosticsModal extends Modal {
	diagText: string;
	constructor(app: App, diagText: string) { super(app); this.diagText = diagText; }
	onOpen() {
		const { contentEl } = this;
		contentEl.empty();
		contentEl.createEl("h2", { text: "Obsi Proxy Diagnostics" });
		const pre = contentEl.createEl("pre", { cls: "obsi-proxy-check-result",
			attr: { style: "background: var(--background-secondary); padding: 16px; border-radius: 6px; overflow-x: auto; max-height: 500px; white-space: pre-wrap;" } });
		pre.textContent = this.diagText;
		new Setting(contentEl).addButton((btn) => btn.setButtonText("Copy to Clipboard").onClick(() => {
			navigator.clipboard.writeText(this.diagText); new Notice("Copied"); }));
		new Setting(contentEl).addButton((btn) => btn.setButtonText("Close").onClick(() => this.close()));
	}
	onClose() { this.contentEl.empty(); }
}

// ──────────────────────────────────────────────────────────────
//  SETTINGS TAB
// ──────────────────────────────────────────────────────────────

class ObsiProxySettingTab extends PluginSettingTab {
	plugin: ObsiProxyPlugin;
	statusEl: HTMLElement | null = null;
	proxyListEl: HTMLElement | null = null;

	constructor(app: App, plugin: ObsiProxyPlugin) { super(app, plugin); this.plugin = plugin; }

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
		const text = this.plugin.settings.enabled && active
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
			.setDesc("Route all Obsidian and plugin traffic through the selected proxy")
			.addToggle((toggle) => toggle.setValue(this.plugin.settings.enabled).onChange(async (val) => {
				if (val) {
					if (!this.plugin.getActiveProxy()) { new Notice("Obsi Proxy: select a proxy first"); toggle.setValue(false); return; }
					await this.plugin.enableProxy();
				} else { await this.plugin.disableProxy(); }
				this.display();
			}));
	}

	renderProxyList(parent: HTMLElement) {
		parent.createEl("div", { text: "PROXY LIST", cls: "obsi-proxy-section-title" });
		this.proxyListEl = parent.createEl("div");
		this.plugin.settings.proxies.forEach((p) => this.renderProxyItem(p));
		if (this.plugin.settings.proxies.length === 0) {
			this.proxyListEl.createEl("p", { text: "No proxies configured. Add one below.",
				attr: { style: "color: var(--text-muted); padding: 8px 0;" } });
		}
		new Setting(parent).setName("Add new proxy").addButton((btn) =>
			btn.setButtonText("+ Add Proxy").setCta().onClick(() => {
				const entry: ProxyEntry = { id: generateId(), name: "", proxyType: "http", host: "", port: "", username: "", password: "" };
				new ProxyEditModal(this.app, this.plugin, entry, true, async (e) => {
					this.plugin.settings.proxies.push(e);
					if (!this.plugin.settings.activeProxyId || this.plugin.settings.proxies.length === 1) this.plugin.settings.activeProxyId = e.id;
					await this.plugin.saveSettings(); this.display();
				}).open();
			}));
	}

	renderProxyItem(proxy: ProxyEntry) {
		if (!this.proxyListEl) return;
		const isSelected = this.plugin.settings.activeProxyId === proxy.id;
		const item = this.proxyListEl.createEl("div", { cls: `obsi-proxy-list-item ${isSelected ? "selected" : ""}` });

		item.addEventListener("click", async (e) => {
			if ((e.target as HTMLElement).closest("button")) return;
			this.plugin.settings.activeProxyId = proxy.id;
			await this.plugin.saveSettings();
			if (this.plugin.settings.enabled) await this.plugin.enableProxy();
			this.display();
		});

		const header = item.createEl("div", { cls: "obsi-proxy-list-item-header" });
		header.createEl("span", { text: isSelected ? `\u25B6 ${proxy.name}` : proxy.name, cls: "obsi-proxy-list-item-name" });
		const actions = header.createEl("div", { cls: "obsi-proxy-list-item-actions" });

		const checkBtn = actions.createEl("button", { text: "Check" });
		checkBtn.addEventListener("click", async (e) => {
			e.stopPropagation();
			checkBtn.textContent = "..."; checkBtn.setAttribute("disabled", "true");
			const wasActive = this.plugin.settings.enabled && this.plugin.settings.activeProxyId === proxy.id;
			const result = await this.plugin.checkConnection(proxy);
			const error = result === null ? "Connection failed" : null;
			checkBtn.textContent = "Check"; checkBtn.removeAttribute("disabled");
			if (error) new Notice("Obsi Proxy: check failed", 5000);
			else if (result) new Notice(`Obsi Proxy: IP is ${result.ip}`, 5000);
			new ProxyCheckModal(this.app, proxy.name, result, error, wasActive).open();
		});

		const editBtn = actions.createEl("button", { text: "Edit" });
		editBtn.addEventListener("click", (e) => {
			e.stopPropagation();
			new ProxyEditModal(this.app, this.plugin, proxy, false, async (entry) => {
				const idx = this.plugin.settings.proxies.findIndex((p) => p.id === entry.id);
				if (idx >= 0) this.plugin.settings.proxies[idx] = entry;
				await this.plugin.saveSettings();
				if (this.plugin.settings.enabled && this.plugin.settings.activeProxyId === entry.id) await this.plugin.enableProxy();
				this.display();
			}).open();
		});

		const delBtn = actions.createEl("button", { text: "Delete" });
		delBtn.addEventListener("click", async (e) => {
			e.stopPropagation();
			this.plugin.settings.proxies = this.plugin.settings.proxies.filter((p) => p.id !== proxy.id);
			if (this.plugin.settings.activeProxyId === proxy.id) {
				this.plugin.settings.activeProxyId = this.plugin.settings.proxies.length > 0 ? this.plugin.settings.proxies[0].id : "";
				if (this.plugin.settings.enabled) {
					if (this.plugin.getActiveProxy()) await this.plugin.enableProxy();
					else await this.plugin.disableProxy();
				}
			}
			await this.plugin.saveSettings(); this.display();
		});

		item.createEl("div", {
			text: `${proxy.proxyType}://${proxy.host}:${proxy.port}${proxy.username ? " (auth)" : ""}${isSelected ? " — selected" : ""}`,
			cls: "obsi-proxy-list-item-detail",
		});
	}

	renderEmergency(parent: HTMLElement) {
		new Setting(parent).setName("Emergency Disable")
			.setDesc("Instantly clear all proxy rules and restore direct connection")
			.addButton((btn) => btn.setButtonText("Disable Proxy Now").setWarning().onClick(async () => {
				await this.plugin.disableProxy(); this.display();
			}));
	}

	renderDiagnostics(parent: HTMLElement) {
		parent.createEl("div", { text: "DIAGNOSTICS", cls: "obsi-proxy-section-title" });

		new Setting(parent).setName("Run diagnostics")
			.setDesc("Check session access, proxy state, agents, and env vars")
			.addButton((btn) => btn.setButtonText("Run Diagnostics").onClick(async () => {
				btn.setButtonText("Running..."); btn.setDisabled(true);
				const diag = await this.plugin.getDiagnostics();
				btn.setButtonText("Run Diagnostics"); btn.setDisabled(false);
				new DiagnosticsModal(this.app, diag).open();
			}));

		new Setting(parent).setName("Deep proxy test")
			.setDesc("Try ALL proxyRules formats on the primary session and report which ones work")
			.addButton((btn) => btn.setButtonText("Run Deep Test").onClick(async () => {
				const proxy = this.plugin.getActiveProxy();
				if (!proxy) { new Notice("Obsi Proxy: select a proxy first"); return; }
				btn.setButtonText("Testing..."); btn.setDisabled(true);
				const result = await this.plugin.getDeepProxyTest(proxy);
				btn.setButtonText("Run Deep Test"); btn.setDisabled(false);
				new DiagnosticsModal(this.app, result).open();
			}));
	}

	refreshStatus() {
		if (!this.statusEl) return;
		const active = this.plugin.getActiveProxy();
		const text = this.plugin.settings.enabled && active
			? `ON — ${active.name} (${active.proxyType}://${active.host}:${active.port})`
			: "OFF — direct connection";
		this.statusEl.className = `obsi-proxy-status ${this.plugin.settings.enabled ? "active" : "inactive"}`;
		this.statusEl.textContent = `Obsi Proxy: ${text}`;
	}
}
