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

export default class ObsiProxyPlugin extends Plugin {
	settings: ProxySettings = DEFAULT_SETTINGS;
	private sessionWatchInterval: number | null = null;
	private originalEnv: Map<string, string | undefined> = new Map();
	private loginHandler: ((...args: any[]) => void) | null = null;
	private authRequiredHandler: ((...args: any[]) => any) | null = null;
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

	private getPrimarySession(): ElectronSession | null {
		const remote = this.getRemote();
		if (!remote) return null;
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

	buildProxyRulesFormats(proxy: ProxyEntry): string[] {
		const { host, port } = proxy;
		if (!host || !port) return [];

		if (proxy.proxyType === "socks5") {
			return [
				`socks5://${host}:${port}`,
				...(proxy.username && proxy.password
					? [`socks5://${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@${host}:${port}`]
					: []),
			];
		}

		const formats: string[] = [];
		formats.push(`http=${host}:${port};https=${host}:${port}`);
		formats.push(`${host}:${port}`);
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
	//  PROXY AUTH HANDLERS — TRIPLE APPROACH
	// ──────────────────────────────────────────────────────────

	/**
	 * Approach 1: session.on('login')
	 * Fired when proxy sends 407 challenge.
	 * NO isProxy check — provide creds for ANY auth challenge.
	 */
	private createLoginHandler(proxy: ProxyEntry): (...args: any[]) => void {
		return (event: any, _webContents: any, _request: any, authInfo: any, callback: any) => {
			console.log("Obsi Proxy: session.on('login') fired", authInfo);
			if (proxy.username && proxy.password) {
				event.preventDefault();
				callback(proxy.username, proxy.password);
			}
		};
	}

	/**
	 * Approach 2: webContents.on('login')
	 * Some Electron versions fire login on webContents, not session.
	 */
	private createWebContentsLoginHandler(proxy: ProxyEntry): (...args: any[]) => void {
		return (event: any, _request: any, authInfo: any, callback: any) => {
			console.log("Obsi Proxy: webContents.on('login') fired", authInfo);
			if (proxy.username && proxy.password) {
				event.preventDefault();
				callback(proxy.username, proxy.password);
			}
		};
	}

	/**
	 * Approach 3: webRequest.onAuthRequired
	 * The most reliable Electron API for handling auth.
	 * Returns { authCredentials } object instead of using callback.
	 */
	private createAuthRequiredHandler(proxy: ProxyEntry): (...args: any[]) => any {
		return (details: any, _callback: any) => {
			console.log("Obsi Proxy: webRequest.onAuthRequired fired", {
				url: details.url,
				isProxy: details.isProxy,
				authChallenges: details.authChallenges,
			});
			if (proxy.username && proxy.password) {
				return {
					authCredentials: {
						username: proxy.username,
						password: proxy.password,
					},
				};
			}
			return {};
		};
	}

	private async registerAuthHandlers(proxy: ProxyEntry): Promise<void> {
		await this.unregisterAuthHandlers();

		// Approach 1: session.on('login')
		this.loginHandler = this.createLoginHandler(proxy);
		const sessions = await this.getAllSessions();
		for (const s of sessions) {
			try { s.on("login", this.loginHandler); } catch {}
		}

		// Approach 2: webContents.on('login')
		const wcHandler = this.createWebContentsLoginHandler(proxy);
		const remote = this.getRemote();
		if (remote) {
			try {
				const windows: any[] = remote.BrowserWindow.getAllWindows();
				for (const win of windows) {
					try { win.webContents?.on("login", wcHandler); } catch {}
				}
				try {
					const win = remote.getCurrentWindow();
					win?.webContents?.on("login", wcHandler);
				} catch {}
			} catch {}
		}

		// Approach 3: webRequest.onAuthRequired
		this.authRequiredHandler = this.createAuthRequiredHandler(proxy);
		for (const s of sessions) {
			try {
				const wr = (s as any).webRequest;
				if (wr?.onAuthRequired) {
					wr.onAuthRequired(this.authRequiredHandler);
				}
			} catch {}
		}
	}

	private async unregisterAuthHandlers(): Promise<void> {
		if (this.loginHandler) {
			const sessions = await this.getAllSessions();
			for (const s of sessions) {
				try { s.removeListener("login", this.loginHandler); } catch {}
			}
			this.loginHandler = null;
		}

		if (this.authRequiredHandler) {
			const sessions = await this.getAllSessions();
			for (const s of sessions) {
				try {
					const wr = (s as any).webRequest;
					if (wr?.onAuthRequired) {
						wr.onAuthRequired(null as any);
					}
				} catch {}
			}
			this.authRequiredHandler = null;
		}
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
		if (this.originalHttpAgent) { nodeHttp.globalAgent = this.originalHttpAgent; this.originalHttpAgent = null; }
		if (this.originalHttpsAgent) { nodeHttps.globalAgent = this.originalHttpsAgent; this.originalHttpsAgent = null; }
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
			process.env[key.toUpperCase()] = proxyUrl;
			if (key !== key.toUpperCase()) process.env[key] = proxyUrl;
		}
	}

	clearEnvironmentProxy() {
		const keys = ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"];
		for (const key of keys) {
			const o = this.originalEnv.get(key);
			if (o === undefined) delete process.env[key];
			else process.env[key] = o;
		}
		this.originalEnv.clear();
	}

	// ──────────────────────────────────────────────────────────
	//  SESSION SET PROXY — WITH VERIFICATION
	// ──────────────────────────────────────────────────────────

	private async setProxyWithVerify(session: ElectronSession, proxy: ProxyEntry): Promise<boolean> {
		const formats = this.buildProxyRulesFormats(proxy);
		const modeOptions: (string | undefined)[] = ["fixed_servers", undefined];

		for (const mode of modeOptions) {
			for (const rules of formats) {
				try {
					const config: any = { proxyRules: rules, proxyBypassRules: "" };
					if (mode) config.mode = mode;
					await session.setProxy(config);

					const resolved = await session.resolveProxy("https://example.com");
					if (resolved && resolved !== "DIRECT") {
						console.log(`Obsi Proxy: setProxy OK — mode=${mode}, rules="${rules}" → "${resolved}"`);
						this.lastApplyLog = `OK: mode=${mode}, rules="${rules}", resolved="${resolved}"`;
						return true;
					}
				} catch {}
			}
		}
		console.warn("Obsi Proxy: setProxy failed on session");
		this.lastApplyLog = "FAILED: all formats returned DIRECT";
		return false;
	}

	// ──────────────────────────────────────────────────────────
	//  PROXY APPLY / CLEAR
	// ──────────────────────────────────────────────────────────

	async applyProxy(): Promise<boolean> {
		const proxy = this.getActiveProxy();
		if (!proxy) { new Notice("Obsi Proxy: no proxy selected"); return false; }
		if (this.buildProxyRulesFormats(proxy).length === 0) { new Notice("Obsi Proxy: host and port required"); return false; }

		// CRITICAL: Register auth handlers BEFORE setProxy
		// so they're ready when the first proxied request triggers 407
		await this.registerAuthHandlers(proxy);

		// Layer 1: session.setProxy
		let anyVerified = false;
		const sessions = await this.getAllSessions();
		for (const session of sessions) {
			if (await this.setProxyWithVerify(session, proxy)) anyVerified = true;
		}
		if (!anyVerified) {
			const primary = this.getPrimarySession();
			if (primary && await this.setProxyWithVerify(primary, proxy)) anyVerified = true;
		}

		// Layer 3: Node.js globalAgent
		this.setGlobalProxyAgent(proxy);

		// Layer 4: env vars
		this.setEnvironmentProxy(proxy);

		new Notice(
			`Obsi Proxy: ON — ${proxy.name}${anyVerified ? " (verified)" : " (unverified)"} + auth handlers + Node.js patched`,
			5000
		);
		return true;
	}

	async clearProxy(): Promise<void> {
		await this.unregisterAuthHandlers();
		const sessions = await this.getAllSessions();
		for (const s of sessions) {
			try { await s.setProxy({ mode: "system", proxyRules: "", proxyBypassRules: "" }); } catch {}
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

	startSessionWatch() {
		if (this.sessionWatchInterval) return;
		this.sessionWatchInterval = window.setInterval(async () => {
			if (!this.settings.enabled || !this.getActiveProxy()) return;
			const proxy = this.getActiveProxy()!;
			const sessions = await this.getAllSessions();
			for (const s of sessions) {
				try {
					const resolved = await s.resolveProxy("https://example.com");
					if (!resolved || resolved === "DIRECT") await this.setProxyWithVerify(s, proxy);
				} catch {}
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
			await this.registerAuthHandlers(proxy);
			const sessions = await this.getAllSessions();
			for (const s of sessions) { try { await this.setProxyWithVerify(s, proxy); } catch {} }
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
					await this.registerAuthHandlers(ap);
					const sessions = await this.getAllSessions();
					for (const s of sessions) { try { await this.setProxyWithVerify(s, ap); } catch {} }
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
		const L: string[] = [];
		L.push("=== Obsi Proxy Diagnostics ===");
		L.push("");

		const hasReq = typeof (window as any).require === "function";
		L.push(`window.require available: ${hasReq}`);

		if (hasReq) {
			try {
				const e = (window as any).require("electron");
				L.push(`electron.remote available: ${!!e.remote}`);
				try {
					const p = e.remote?.app?.getVersion?.();
					if (p) L.push(`Electron version: ${p}`);
				} catch {}
				try {
					const r = (window as any).require("@electron/remote");
					L.push(`@electron/remote available: ${!!r}`);
					try {
						const v = r.app?.getVersion?.();
						if (v) L.push(`Electron version (remote): ${v}`);
					} catch {}
				} catch { L.push("@electron/remote available: false"); }
			} catch { L.push("electron require failed"); }
		}

		const sessions = await this.getAllSessions();
		L.push(`Sessions discovered: ${sessions.length}`);
		for (let i = 0; i < sessions.length; i++) {
			try {
				const r = await sessions[i].resolveProxy("https://example.com");
				L.push(`  Session ${i}: resolveProxy = "${r}"`);
			} catch (e) { L.push(`  Session ${i}: resolveProxy error — ${e}`); }
		}

		L.push("");
		L.push("Node.js globalAgent:");
		const nH = require("http");
		const nS = require("https");
		L.push(`  http.globalAgent: ${nH.globalAgent.constructor.name}`);
		L.push(`  https.globalAgent: ${nS.globalAgent.constructor.name}`);

		L.push("");
		L.push("Environment:");
		for (const k of ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"]) {
			const v = process.env[k];
			L.push(`  ${k} = ${v ? v.replace(/:[^@]+@/, ":****@") : "(not set)"}`);
		}

		L.push("");
		L.push(`Enabled: ${this.settings.enabled}`);
		L.push(`Login handler: ${this.loginHandler !== null}`);
		L.push(`AuthRequired handler: ${this.authRequiredHandler !== null}`);
		L.push(`Watch active: ${this.sessionWatchInterval !== null}`);
		L.push(`Last apply: ${this.lastApplyLog || "(none)"}`);

		// ── REAL CONNECTIVITY TESTS ──
		const active = this.getActiveProxy();
		if (active) {
			L.push("");
			L.push("=== Real Connectivity Tests ===");

			// Test 1: Node.js https.get (globalAgent handles auth)
			L.push("");
			L.push("Test 1: Node.js https.get via globalAgent...");
			try {
				const result = await new Promise<string>((resolve, reject) => {
					const t = setTimeout(() => reject(new Error("timeout 10s")), 10000);
					const req = nS.get("https://api.ipify.org?format=json", (res: any) => {
						let d = ""; res.on("data", (c: any) => d += c);
						res.on("end", () => { clearTimeout(t); resolve(d); });
					});
					req.on("error", (e: any) => { clearTimeout(t); reject(e); });
				});
				const j = JSON.parse(result);
				L.push(`  OK — IP: ${j.ip}`);
			} catch (e: any) {
				L.push(`  FAIL — ${e.message ?? e}`);
			}

			// Test 2: Obsidian requestUrl (Chromium stack + onAuthRequired)
			L.push("");
			L.push("Test 2: Obsidian requestUrl via Chromium...");
			try {
				const resp = await requestUrl({ url: "https://api.ipify.org?format=json", method: "GET" });
				L.push(`  OK — IP: ${(resp.json as any).ip}`);
			} catch (e: any) {
				L.push(`  FAIL — ${e.message ?? e}`);
				L.push(`  → Proxy auth (407) is likely NOT being handled by Chromium`);
				L.push(`  → Check console for "Obsi Proxy: onAuthRequired/login fired" messages`);
			}

			// Test 3: Direct (no proxy)
			L.push("");
			L.push("Test 3: Direct request (no proxy)...");
			try {
				const savedAgent = nS.globalAgent;
				nS.globalAgent = this.originalHttpsAgent || new nS.Agent();
				for (const s of sessions) {
					try { await s.setProxy({ mode: "direct", proxyRules: "", proxyBypassRules: "" }); } catch {}
				}
				const resp = await requestUrl({ url: "https://api.ipify.org?format=json", method: "GET" });
				L.push(`  Direct IP: ${(resp.json as any).ip}`);
				nS.globalAgent = savedAgent;
				for (const s of sessions) {
					try { await this.setProxyWithVerify(s, active); } catch {}
				}
			} catch (e: any) {
				L.push(`  FAIL — ${e.message ?? e}`);
			}

			L.push("");
			L.push("Proxy details:");
			L.push(`  Type: ${active.proxyType}`);
			L.push(`  Host: ${active.host}:${active.port}`);
			L.push(`  Auth: ${!!(active.username && active.password)}`);
		}

		return L.join("\n");
	}

	async getDeepProxyTest(proxy: ProxyEntry): Promise<string> {
		const L: string[] = [];
		L.push("=== Deep Proxy Test ===");
		const session = this.getPrimarySession();
		if (!session) { L.push("ERROR: No primary session"); return L.join("\n"); }

		const formats = this.buildProxyRulesFormats(proxy);
		const modes: (string | undefined)[] = ["fixed_servers", undefined, "system"];

		for (const mode of modes) {
			for (let fi = 0; fi < formats.length; fi++) {
				const rules = formats[fi];
				const masked = rules.replace(/:[^@]+@/, ":****@");
				const label = `mode=${mode ?? "(none)"}, format=${fi + 1}`;
				try {
					const cfg: any = { proxyRules: rules, proxyBypassRules: "" };
					if (mode) cfg.mode = mode;
					await session.setProxy(cfg);
					const r = await session.resolveProxy("https://example.com");
					if (r && r !== "DIRECT") {
						L.push(`✓ ${label}: "${r}" (rules: "${masked}")`);
					} else {
						L.push(`✗ ${label}: DIRECT (rules: "${masked}")`);
					}
				} catch (e) { L.push(`✗ ${label}: ERROR — ${e}`); }
			}
		}

		// Also test: does onAuthRequired exist on this session?
		L.push("");
		L.push("API availability:");
		L.push(`  session.on: ${typeof session.on === "function"}`);
		L.push(`  session.webRequest: ${!!(session as any).webRequest}`);
		L.push(`  session.webRequest.onAuthRequired: ${typeof (session as any).webRequest?.onAuthRequired === "function"}`);
		L.push(`  session.closeAllConnections: ${typeof (session as any).closeAllConnections === "function"}`);

		if (this.settings.enabled && this.getActiveProxy()) {
			await this.setProxyWithVerify(session, this.getActiveProxy()!);
		} else {
			try { await session.setProxy({ mode: "system", proxyRules: "", proxyBypassRules: "" }); } catch {}
		}
		return L.join("\n");
	}
}

// ──────────────────────────────────────────────────────────────
//  MODALS
// ──────────────────────────────────────────────────────────────

class ProxyCheckModal extends Modal {
	result: { ip: string } | null; error: string | null; wasActive: boolean; name: string;
	constructor(app: App, name: string, r: { ip: string } | null, e: string | null, w: boolean) {
		super(app); this.name = name; this.result = r; this.error = e; this.wasActive = w;
	}
	onOpen() {
		const { contentEl } = this; contentEl.empty();
		contentEl.createEl("h2", { text: "Proxy Connection Check" });
		contentEl.createEl("p", { text: `Checking: ${this.name}` });
		if (!this.wasActive) contentEl.createEl("p", { text: "Temporarily applied for this check.", attr: { style: "font-style: italic; color: var(--text-muted);" } });
		if (this.error) {
			contentEl.createEl("p", { text: `Error: ${this.error}`, attr: { style: "background: var(--background-modifier-error); color: var(--text-error); padding: 8px; border-radius: 4px;" } });
		} else if (this.result) {
			contentEl.createEl("p", { text: `Outgoing IP: ${this.result.ip}`, attr: { style: "background: var(--background-modifier-success); color: var(--text-success); padding: 8px; border-radius: 4px; font-size: 16px; font-weight: 600;" } });
		}
		new Setting(contentEl).addButton((b) => b.setButtonText("Close").onClick(() => this.close()));
	}
	onClose() { this.contentEl.empty(); }
}

class ProxyEditModal extends Modal {
	plugin: ObsiProxyPlugin; entry: ProxyEntry; isNew: boolean; onSave: (e: ProxyEntry) => void;
	constructor(app: App, plugin: ObsiProxyPlugin, entry: ProxyEntry, isNew: boolean, onSave: (e: ProxyEntry) => void) {
		super(app); this.plugin = plugin; this.entry = { ...entry }; this.isNew = isNew; this.onSave = onSave;
	}
	onOpen() {
		const { contentEl } = this; contentEl.empty();
		contentEl.createEl("h2", { text: this.isNew ? "Add Proxy" : "Edit Proxy" });
		new Setting(contentEl).setName("Name").addText((t) => t.setValue(this.entry.name).onChange((v) => this.entry.name = v));
		new Setting(contentEl).setName("Type").addDropdown((d) => d.addOption("http","HTTP").addOption("socks5","SOCKS5").setValue(this.entry.proxyType).onChange((v) => this.entry.proxyType = v as any));
		new Setting(contentEl).setName("Host").addText((t) => t.setPlaceholder("167.148.96.23").setValue(this.entry.host).onChange((v) => this.entry.host = v.trim()));
		new Setting(contentEl).setName("Port").addText((t) => t.setPlaceholder("47866").setValue(this.entry.port).onChange((v) => this.entry.port = v.trim()));
		new Setting(contentEl).setName("Username").addText((t) => t.setValue(this.entry.username).onChange((v) => this.entry.username = v));
		new Setting(contentEl).setName("Password").addText((t) => { t.inputEl.type = "password"; t.setValue(this.entry.password).onChange((v) => this.entry.password = v); });
		new Setting(contentEl).addButton((b) => b.setButtonText(this.isNew ? "Add" : "Save").setCta().onClick(() => {
			if (!this.entry.name.trim()) this.entry.name = `${this.entry.proxyType}://${this.entry.host}:${this.entry.port}`;
			if (!this.entry.host || !this.entry.port) { new Notice("Host and port required"); return; }
			this.onSave(this.entry); this.close();
		}));
	}
	onClose() { this.contentEl.empty(); }
}

class DiagnosticsModal extends Modal {
	text: string;
	constructor(app: App, t: string) { super(app); this.text = t; }
	onOpen() {
		const { contentEl } = this; contentEl.empty();
		contentEl.createEl("h2", { text: "Obsi Proxy Diagnostics" });
		const pre = contentEl.createEl("pre", { attr: { style: "background: var(--background-secondary); padding: 16px; border-radius: 6px; overflow-x: auto; max-height: 500px; white-space: pre-wrap; font-size: 12px;" } });
		pre.textContent = this.text;
		new Setting(contentEl).addButton((b) => b.setButtonText("Copy").onClick(() => { navigator.clipboard.writeText(this.text); new Notice("Copied"); }));
		new Setting(contentEl).addButton((b) => b.setButtonText("Close").onClick(() => this.close()));
	}
	onClose() { this.contentEl.empty(); }
}

// ──────────────────────────────────────────────────────────────
//  SETTINGS TAB
// ──────────────────────────────────────────────────────────────

class ObsiProxySettingTab extends PluginSettingTab {
	plugin: ObsiProxyPlugin; statusEl: HTMLElement | null = null; listEl: HTMLElement | null = null;
	constructor(app: App, plugin: ObsiProxyPlugin) { super(app, plugin); this.plugin = plugin; }

	display() {
		const { containerEl } = this; containerEl.empty(); containerEl.addClass("obsi-proxy-settings");
		containerEl.createEl("h2", { text: "Obsi Proxy" });
		const a = this.plugin.getActiveProxy();
		this.statusEl = containerEl.createEl("div", {
			cls: `obsi-proxy-status ${this.plugin.settings.enabled ? "active" : "inactive"}`,
			text: `Obsi Proxy: ${this.plugin.settings.enabled && a ? `ON — ${a.name}` : "OFF"}`,
		});

		new Setting(containerEl).setName("Enable proxy").addToggle((t) => t.setValue(this.plugin.settings.enabled).onChange(async (v) => {
			if (v) { if (!this.plugin.getActiveProxy()) { new Notice("Select a proxy first"); t.setValue(false); return; } await this.plugin.enableProxy(); }
			else await this.plugin.disableProxy();
			this.display();
		}));

		containerEl.createEl("div", { text: "PROXY LIST", cls: "obsi-proxy-section-title" });
		this.listEl = containerEl.createEl("div");
		this.plugin.settings.proxies.forEach((p) => this.renderItem(p));
		if (!this.plugin.settings.proxies.length) this.listEl.createEl("p", { text: "No proxies. Add one below.", attr: { style: "color: var(--text-muted);" } });
		new Setting(containerEl).addButton((b) => b.setButtonText("+ Add Proxy").setCta().onClick(() => {
			new ProxyEditModal(this.app, this.plugin, { id: generateId(), name: "", proxyType: "http", host: "", port: "", username: "", password: "" }, true, async (e) => {
				this.plugin.settings.proxies.push(e);
				if (!this.plugin.settings.activeProxyId || this.plugin.settings.proxies.length === 1) this.plugin.settings.activeProxyId = e.id;
				await this.plugin.saveSettings(); this.display();
			}).open();
		}));

		new Setting(containerEl).setName("Emergency Disable").addButton((b) => b.setButtonText("Disable Now").setWarning().onClick(async () => { await this.plugin.disableProxy(); this.display(); }));

		containerEl.createEl("div", { text: "DIAGNOSTICS", cls: "obsi-proxy-section-title" });
		new Setting(containerEl).setName("Run diagnostics").addButton((b) => b.setButtonText("Run").onClick(async () => {
			b.setButtonText("..."); b.setDisabled(true);
			new DiagnosticsModal(this.app, await this.plugin.getDiagnostics()).open();
			b.setButtonText("Run"); b.setDisabled(false);
		}));
		new Setting(containerEl).setName("Deep proxy test").addButton((b) => b.setButtonText("Run").onClick(async () => {
			const p = this.plugin.getActiveProxy();
			if (!p) { new Notice("Select proxy first"); return; }
			b.setButtonText("..."); b.setDisabled(true);
			new DiagnosticsModal(this.app, await this.plugin.getDeepProxyTest(p)).open();
			b.setButtonText("Run"); b.setDisabled(false);
		}));
	}

	renderItem(proxy: ProxyEntry) {
		if (!this.listEl) return;
		const sel = this.plugin.settings.activeProxyId === proxy.id;
		const item = this.listEl.createEl("div", { cls: `obsi-proxy-list-item ${sel ? "selected" : ""}` });
		item.addEventListener("click", async (e) => { if ((e.target as HTMLElement).closest("button")) return; this.plugin.settings.activeProxyId = proxy.id; await this.plugin.saveSettings(); if (this.plugin.settings.enabled) await this.plugin.enableProxy(); this.display(); });

		const hdr = item.createEl("div", { cls: "obsi-proxy-list-item-header" });
		hdr.createEl("span", { text: sel ? `▶ ${proxy.name}` : proxy.name, cls: "obsi-proxy-list-item-name" });
		const acts = hdr.createEl("div", { cls: "obsi-proxy-list-item-actions" });

		acts.createEl("button", { text: "Check" }).addEventListener("click", async (e) => {
			e.stopPropagation();
			const r = await this.plugin.checkConnection(proxy);
			if (r) new Notice(`IP: ${r.ip}`, 5000); else new Notice("Check failed", 5000);
			new ProxyCheckModal(this.app, proxy.name, r, r ? null : "Failed", this.plugin.settings.enabled && sel).open();
		});
		acts.createEl("button", { text: "Edit" }).addEventListener("click", (e) => {
			e.stopPropagation();
			new ProxyEditModal(this.app, this.plugin, proxy, false, async (en) => {
				const i = this.plugin.settings.proxies.findIndex((p) => p.id === en.id);
				if (i >= 0) this.plugin.settings.proxies[i] = en;
				await this.plugin.saveSettings();
				if (this.plugin.settings.enabled && this.plugin.settings.activeProxyId === en.id) await this.plugin.enableProxy();
				this.display();
			}).open();
		});
		acts.createEl("button", { text: "Del" }).addEventListener("click", async (e) => {
			e.stopPropagation();
			this.plugin.settings.proxies = this.plugin.settings.proxies.filter((p) => p.id !== proxy.id);
			if (this.plugin.settings.activeProxyId === proxy.id) {
				this.plugin.settings.activeProxyId = this.plugin.settings.proxies[0]?.id ?? "";
				if (this.plugin.settings.enabled) { if (this.plugin.getActiveProxy()) await this.plugin.enableProxy(); else await this.plugin.disableProxy(); }
			}
			await this.plugin.saveSettings(); this.display();
		});

		item.createEl("div", { text: `${proxy.proxyType}://${proxy.host}:${proxy.port}${proxy.username ? " (auth)" : ""}${sel ? " — selected" : ""}`, cls: "obsi-proxy-list-item-detail" });
	}
}
