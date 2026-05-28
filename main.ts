import {
	App,
	Notice,
	Plugin,
	PluginSettingTab,
	Setting,
	Modal,
	requestUrl,
} from "obsidian";
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
	private originalHttpAgent: any = null;
	private originalHttpsAgent: any = null;
	private lastApplyLog: string = "";
	private lastLoginEventInfo: string = "(never fired)";

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
		try { const e = (window as any).require("electron"); if (e?.remote) return e.remote; } catch {}
		try { const r = (window as any).require("@electron/remote"); if (r) return r; } catch {}
		return null;
	}

	private getPrimarySession(): any | null {
		const remote = this.getRemote();
		if (!remote) return null;
		try { const w = remote.getCurrentWindow(); const s = w?.webContents?.session; if (s?.setProxy) return s; } catch {}
		try { const s = remote.session?.defaultSession; if (s?.setProxy) return s; } catch {}
		return null;
	}

	async getAllSessions(): Promise<any[]> {
		const sessions: any[] = [];
		const seen = new Set<any>();
		const add = (s: any) => { if (s?.setProxy && !seen.has(s)) { seen.add(s); sessions.push(s); } };
		const remote = this.getRemote();
		if (remote) {
			try { add(remote.session?.defaultSession); } catch {}
			try { add(remote.getCurrentWindow()?.webContents?.session); } catch {}
			try { for (const w of remote.BrowserWindow.getAllWindows() ?? []) { try { add(w.webContents?.session); } catch {} } } catch {}
		}
		return sessions;
	}

	buildProxyRules(proxy: ProxyEntry): string {
		const { host, port } = proxy;
		if (!host || !port) return "";
		if (proxy.proxyType === "socks5") return `socks5://${host}:${port}`;
		return `http=${host}:${port};https=${host}:${port}`;
	}

	buildProxyUrl(proxy: ProxyEntry): string {
		const auth = proxy.username && proxy.password ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@` : "";
		if (proxy.proxyType === "socks5") return `socks5://${auth}${proxy.host}:${proxy.port}`;
		return `http://${auth}${proxy.host}:${proxy.port}`;
	}

	// ──────────────────────────────────────────────────────────
	//  AUTH — session.on('login') with logging
	// ──────────────────────────────────────────────────────────

	private async registerLoginHandler(proxy: ProxyEntry): Promise<void> {
		await this.unregisterLoginHandler();
		this.lastLoginEventInfo = "(waiting for login event...)";

		this.loginHandler = (event: any, webContents: any, request: any, authInfo: any, callback: any) => {
			this.lastLoginEventInfo = `FIRED! isProxy=${authInfo?.isProxy} scheme=${authInfo?.scheme} host=${authInfo?.host} port=${authInfo?.port} realm=${authInfo?.realm}`;

			if (proxy.username && proxy.password) {
				event.preventDefault();
				callback(proxy.username, proxy.password);
			}
		};

		const sessions = await this.getAllSessions();
		for (const s of sessions) {
			try { s.on("login", this.loginHandler); } catch {}
		}

		// Also on webContents
		const remote = this.getRemote();
		if (remote) {
			try { for (const w of remote.BrowserWindow.getAllWindows() ?? []) { try { w.webContents?.on("login", this.loginHandler); } catch {} } } catch {}
			try { remote.getCurrentWindow()?.webContents?.on("login", this.loginHandler); } catch {}
		}
	}

	private async unregisterLoginHandler(): Promise<void> {
		if (!this.loginHandler) return;
		const sessions = await this.getAllSessions();
		for (const s of sessions) { try { s.removeListener("login", this.loginHandler); } catch {} }
		const remote = this.getRemote();
		if (remote) {
			try { for (const w of remote.BrowserWindow.getAllWindows() ?? []) { try { w.webContents?.removeListener("login", this.loginHandler); } catch {} } } catch {}
			try { remote.getCurrentWindow()?.webContents?.removeListener("login", this.loginHandler); } catch {}
		}
		this.loginHandler = null;
	}

	// ──────────────────────────────────────────────────────────
	//  NODE.JS GLOBAL AGENT
	// ──────────────────────────────────────────────────────────

	private setGlobalProxyAgent(proxy: ProxyEntry): void {
		const proxyUrl = this.buildProxyUrl(proxy);
		const nH = require("http");
		const nS = require("https");
		if (!this.originalHttpAgent) this.originalHttpAgent = nH.globalAgent;
		if (!this.originalHttpsAgent) this.originalHttpsAgent = nS.globalAgent;
		const agent = proxy.proxyType === "socks5" ? new SocksProxyAgent(proxyUrl) : new HttpsProxyAgent(proxyUrl);
		nH.globalAgent = agent;
		nS.globalAgent = agent;
	}

	private clearGlobalProxyAgent(): void {
		const nH = require("http");
		const nS = require("https");
		if (this.originalHttpAgent) { nH.globalAgent = this.originalHttpAgent; this.originalHttpAgent = null; }
		if (this.originalHttpsAgent) { nS.globalAgent = this.originalHttpsAgent; this.originalHttpsAgent = null; }
	}

	setEnvironmentProxy(proxy: ProxyEntry) {
		const u = this.buildProxyUrl(proxy);
		for (const k of ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"]) {
			if (!this.originalEnv.has(k)) this.originalEnv.set(k, process.env[k]);
			process.env[k] = u;
		}
	}

	clearEnvironmentProxy() {
		for (const k of ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"]) {
			const o = this.originalEnv.get(k);
			if (o === undefined) delete process.env[k]; else process.env[k] = o;
		}
		this.originalEnv.clear();
	}

	// ──────────────────────────────────────────────────────────
	//  APPLY / CLEAR
	// ──────────────────────────────────────────────────────────

	async applyProxy(): Promise<boolean> {
		const proxy = this.getActiveProxy();
		if (!proxy) { new Notice("Obsi Proxy: no proxy selected"); return false; }
		const rules = this.buildProxyRules(proxy);
		if (!rules) { new Notice("Obsi Proxy: host and port required"); return false; }

		// AUTH BEFORE setProxy — handler must be ready
		await this.registerLoginHandler(proxy);

		// setProxy on all sessions
		let verified = 0;
		const sessions = await this.getAllSessions();
		for (const s of sessions) {
			try {
				await s.setProxy({ mode: "fixed_servers", proxyRules: rules, proxyBypassRules: "" });
				const r = await s.resolveProxy("https://example.com");
				if (r && r !== "DIRECT") verified++;
			} catch {}
		}

		this.setGlobalProxyAgent(proxy);
		this.setEnvironmentProxy(proxy);

		this.lastApplyLog = `setProxy: ${verified}/${sessions.length} sessions verified, proxyRules="${rules}"`;
		new Notice(`Obsi Proxy: ON — ${proxy.name} (${verified} sessions + Node.js)`, 5000);
		return true;
	}

	async clearProxy(): Promise<void> {
		await this.unregisterLoginHandler();
		for (const s of await this.getAllSessions()) {
			try { await s.setProxy({ mode: "system", proxyRules: "", proxyBypassRules: "" }); } catch {}
		}
		this.clearGlobalProxyAgent();
		this.clearEnvironmentProxy();
	}

	async enableProxy(): Promise<void> {
		await this.applyProxy();
		this.settings.enabled = true;
		await this.saveSettings();
		this.startSessionWatch();
	}

	async disableProxy(): Promise<void> {
		this.stopSessionWatch();
		await this.clearProxy();
		this.settings.enabled = false;
		await this.saveSettings();
		new Notice("Obsi Proxy: OFF");
	}

	startSessionWatch() {
		if (this.sessionWatchInterval) return;
		this.sessionWatchInterval = window.setInterval(async () => {
			if (!this.settings.enabled || !this.getActiveProxy()) return;
			const proxy = this.getActiveProxy()!;
			const rules = this.buildProxyRules(proxy);
			for (const s of await this.getAllSessions()) {
				try {
					const r = await s.resolveProxy("https://example.com");
					if (!r || r === "DIRECT") {
						await s.setProxy({ mode: "fixed_servers", proxyRules: rules, proxyBypassRules: "" });
					}
				} catch {}
			}
		}, 15000);
	}

	stopSessionWatch() {
		if (this.sessionWatchInterval !== null) { window.clearInterval(this.sessionWatchInterval); this.sessionWatchInterval = null; }
	}

	async checkConnection(proxy: ProxyEntry): Promise<{ ip: string } | null> {
		const isActive = this.settings.enabled && this.settings.activeProxyId === proxy.id;
		let revert = false;

		if (!isActive) {
			await this.registerLoginHandler(proxy);
			const rules = this.buildProxyRules(proxy);
			for (const s of await this.getAllSessions()) {
				try { await s.setProxy({ mode: "fixed_servers", proxyRules: rules, proxyBypassRules: "" }); } catch {}
			}
			this.setGlobalProxyAgent(proxy);
			this.setEnvironmentProxy(proxy);
			revert = true;
			await new Promise((r) => setTimeout(r, 500));
		}

		try {
			const resp = await requestUrl({ url: "https://api.ipify.org?format=json", method: "GET" });
			return resp.json as { ip: string };
		} catch { return null; }
		finally {
			if (revert) {
				if (this.settings.enabled && this.getActiveProxy()) {
					const ap = this.getActiveProxy()!;
					await this.registerLoginHandler(ap);
					const rules = this.buildProxyRules(ap);
					for (const s of await this.getAllSessions()) {
						try { await s.setProxy({ mode: "fixed_servers", proxyRules: rules, proxyBypassRules: "" }); } catch {}
					}
					this.setGlobalProxyAgent(ap);
					this.setEnvironmentProxy(ap);
				} else { await this.clearProxy(); }
			}
		}
	}

	// ──────────────────────────────────────────────────────────
	//  DIAGNOSTICS — WITH REAL HTTP TESTS
	// ──────────────────────────────────────────────────────────

	async getDiagnostics(): Promise<string> {
		const L: string[] = [];
		L.push("=== Obsi Proxy Diagnostics ===\n");

		try {
			const remote = this.getRemote();
			if (remote) {
				try { L.push(`Electron version: ${remote.app?.getVersion?.() ?? "unknown"}`); } catch {}
			}
		} catch {}

		L.push(`Login handler: ${this.loginHandler !== null}`);
		L.push(`Last login event: ${this.lastLoginEventInfo}`);
		L.push(`Apply log: ${this.lastApplyLog || "(none)"}`);

		const sessions = await this.getAllSessions();
		L.push(`Sessions: ${sessions.length}`);
		for (let i = 0; i < sessions.length; i++) {
			try {
				const r = await sessions[i].resolveProxy("https://example.com");
				L.push(`  #${i}: ${r}`);
			} catch (e) { L.push(`  #${i}: error — ${e}`); }
		}

		const nH = require("http"), nS = require("https");
		L.push(`\nNode.js: http.globalAgent = ${nH.globalAgent.constructor.name}, https.globalAgent = ${nS.globalAgent.constructor.name}`);

		L.push("\nEnv:");
		for (const k of ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"]) {
			const v = process.env[k];
			L.push(`  ${k} = ${v ? v.replace(/:[^@]+@/, ":****@") : "(not set)"}`);
		}

		const proxy = this.getActiveProxy();
		if (proxy) {
			L.push(`\nProxy: ${proxy.proxyType}://${proxy.host}:${proxy.port} auth=${!!(proxy.username && proxy.password)}`);

			// ── REAL TESTS ──
			L.push("\n=== Real HTTP Tests ===");

			// Test 1: Node.js
			L.push("\n1) Node.js https.get (globalAgent handles auth)...");
			try {
				const data = await new Promise<string>((res, rej) => {
					const t = setTimeout(() => rej(new Error("timeout")), 10000);
					nS.get("https://api.ipify.org?format=json", (r: any) => {
						let d = ""; r.on("data", (c: any) => d += c); r.on("end", () => { clearTimeout(t); res(d); });
					}).on("error", (e: any) => { clearTimeout(t); rej(e); });
				});
				L.push(`  OK — IP: ${(JSON.parse(data)).ip}`);
			} catch (e: any) { L.push(`  FAIL — ${e.message ?? e}`); }

			// Test 2: requestUrl (Chromium)
			L.push("\n2) Obsidian requestUrl (Chromium + session.on('login'))...");
			try {
				const r = await requestUrl({ url: "https://api.ipify.org?format=json", method: "GET" });
				L.push(`  OK — IP: ${(r.json as any).ip}`);
			} catch (e: any) {
				L.push(`  FAIL — ${e.message ?? e}`);
				L.push(`  Login event status: ${this.lastLoginEventInfo}`);
			}
		}

		return L.join("\n");
	}

	/**
	 * Deep test that makes REAL requests, not just resolveProxy.
	 */
	async getDeepProxyTest(proxy: ProxyEntry): Promise<string> {
		const L: string[] = [];
		L.push("=== Deep Proxy Test ===\n");

		const session = this.getPrimarySession();
		if (!session) { L.push("No primary session!"); return L.join("\n"); }

		// Phase 1: resolveProxy test (existing)
		L.push("--- Phase 1: resolveProxy ---");
		const rules = this.buildProxyRules(proxy);
		const modes = ["fixed_servers", undefined];
		for (const mode of modes) {
			try {
				const cfg: any = { proxyRules: rules, proxyBypassRules: "" };
				if (mode) cfg.mode = mode;
				await session.setProxy(cfg);
				const r = await session.resolveProxy("https://example.com");
				L.push(`  mode=${mode ?? "(none)"}: ${r}`);
			} catch (e: any) { L.push(`  mode=${mode ?? "(none)"}: ERROR ${e.message}`); }
		}

		// Phase 2: session.on('login') test
		L.push("\n--- Phase 2: session.on('login') ---");
		L.push(`  Registering login handler with user=${proxy.username ? "YES" : "NO"} pass=${proxy.password ? "YES" : "NO"}`);

		let loginFired = false;
		const testHandler = (event: any, wc: any, req: any, authInfo: any, callback: any) => {
			loginFired = true;
			L.push(`  LOGIN EVENT: isProxy=${authInfo?.isProxy} scheme=${authInfo?.scheme} host=${authInfo?.host} port=${authInfo?.port} realm=${authInfo?.realm}`);
			if (proxy.username && proxy.password) {
				event.preventDefault();
				callback(proxy.username, proxy.password);
			}
		};

		try { session.on("login", testHandler); } catch (e: any) { L.push(`  session.on('login') FAILED: ${e.message}`); }

		// Also webContents
		let wcLoginFired = false;
		const wcHandler = (event: any, req: any, authInfo: any, callback: any) => {
			wcLoginFired = true;
			L.push(`  WC LOGIN EVENT: isProxy=${authInfo?.isProxy} scheme=${authInfo?.scheme} host=${authInfo?.host} port=${authInfo?.port}`);
			if (proxy.username && proxy.password) {
				event.preventDefault();
				callback(proxy.username, proxy.password);
			}
		};
		const remote = this.getRemote();
		let webContents: any = null;
		if (remote) {
			try {
				webContents = remote.getCurrentWindow()?.webContents;
				if (webContents) {
					try { webContents.on("login", wcHandler); } catch (e: any) { L.push(`  webContents.on('login') FAILED: ${e.message}`); }
				}
			} catch {}
		}

		// Set proxy
		try { await session.setProxy({ mode: "fixed_servers", proxyRules: rules, proxyBypassRules: "" }); } catch {}
		const r = await session.resolveProxy("https://example.com");
		L.push(`  resolveProxy after setProxy: ${r}`);

		// Phase 3: REAL request
		L.push("\n--- Phase 3: Real requestUrl() ---");
		try {
			const resp = await requestUrl({ url: "https://api.ipify.org?format=json", method: "GET" });
			L.push(`  OK — IP: ${(resp.json as any).ip}`);
		} catch (e: any) {
			L.push(`  FAIL — ${e.message ?? e}`);
		}

		L.push(`\n--- Phase 4: Login event results ---`);
		L.push(`  session.on('login') fired: ${loginFired}`);
		L.push(`  webContents.on('login') fired: ${wcLoginFired}`);
		if (!loginFired && !wcLoginFired) {
			L.push(`  NO login event fired!`);
			L.push(`  This means Chromium did NOT send a 407 challenge.`);
			L.push(`  Possible reasons:`);
			L.push(`    - Proxy doesn't require auth (try without username/password)`);
			L.push(`    - Proxy is unreachable (connection times out)`);
			L.push(`    - Auth is handled differently by this Electron version`);
		}

		// Phase 5: Node.js test
		L.push("\n--- Phase 5: Node.js https.get (globalAgent) ---");
		const nS = require("https");
		this.setGlobalProxyAgent(proxy);
		try {
			const data = await new Promise<string>((res, rej) => {
				const t = setTimeout(() => rej(new Error("timeout")), 10000);
				nS.get("https://api.ipify.org?format=json", (r: any) => {
					let d = ""; r.on("data", (c: any) => d += c); r.on("end", () => { clearTimeout(t); res(d); });
				}).on("error", (e: any) => { clearTimeout(t); rej(e); });
			});
			L.push(`  OK — IP: ${(JSON.parse(data)).ip}`);
		} catch (e: any) { L.push(`  FAIL — ${e.message ?? e}`); }

		// Cleanup
		try { session.removeListener("login", testHandler); } catch {}
		try { webContents?.removeListener("login", wcHandler); } catch {}

		// Restore
		if (this.settings.enabled && this.getActiveProxy()) {
			await this.applyProxy();
		} else {
			await this.clearProxy();
		}

		return L.join("\n");
	}
}

// MODALS

class ProxyCheckModal extends Modal {
	r: { ip: string } | null; e: string | null; w: boolean; n: string;
	constructor(app: App, n: string, r: { ip: string } | null, e: string | null, w: boolean) { super(app); this.n = n; this.r = r; this.e = e; this.w = w; }
	onOpen() {
		const { contentEl } = this; contentEl.empty();
		contentEl.createEl("h2", { text: "Connection Check" });
		if (!this.w) contentEl.createEl("p", { text: "Temporarily applied for this check.", attr: { style: "font-style: italic; color: var(--text-muted);" } });
		if (this.e) contentEl.createEl("p", { text: `Error: ${this.e}`, attr: { style: "background: var(--background-modifier-error); color: var(--text-error); padding: 8px; border-radius: 4px;" } });
		else if (this.r) contentEl.createEl("p", { text: `IP: ${this.r.ip}`, attr: { style: "background: var(--background-modifier-success); color: var(--text-success); padding: 8px; border-radius: 4px; font-size: 16px; font-weight: 600;" } });
		new Setting(contentEl).addButton((b) => b.setButtonText("Close").onClick(() => this.close()));
	}
	onClose() { this.contentEl.empty(); }
}

class ProxyEditModal extends Modal {
	plugin: ObsiProxyPlugin; entry: ProxyEntry; isNew: boolean; onSave: (e: ProxyEntry) => void;
	constructor(app: App, p: ObsiProxyPlugin, e: ProxyEntry, n: boolean, s: (e: ProxyEntry) => void) { super(app); this.plugin = p; this.entry = { ...e }; this.isNew = n; this.onSave = s; }
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

class DiagModal extends Modal {
	t: string;
	constructor(app: App, t: string) { super(app); this.t = t; }
	onOpen() {
		const { contentEl } = this; contentEl.empty();
		contentEl.createEl("h2", { text: "Obsi Proxy" });
		const pre = contentEl.createEl("pre", { attr: { style: "background: var(--background-secondary); padding: 16px; border-radius: 6px; overflow: auto; max-height: 500px; white-space: pre-wrap; font-size: 12px;" } });
		pre.textContent = this.t;
		new Setting(contentEl).addButton((b) => b.setButtonText("Copy").onClick(() => { navigator.clipboard.writeText(this.t); new Notice("Copied"); }));
		new Setting(contentEl).addButton((b) => b.setButtonText("Close").onClick(() => this.close()));
	}
	onClose() { this.contentEl.empty(); }
}

// SETTINGS TAB

class ObsiProxySettingTab extends PluginSettingTab {
	plugin: ObsiProxyPlugin; statusEl: HTMLElement | null = null; listEl: HTMLElement | null = null;
	constructor(app: App, p: ObsiProxyPlugin) { super(app, p); this.plugin = p; }

	display() {
		const { containerEl: c } = this; c.empty(); c.addClass("obsi-proxy-settings");
		c.createEl("h2", { text: "Obsi Proxy" });
		const a = this.plugin.getActiveProxy();
		this.statusEl = c.createEl("div", {
			cls: `obsi-proxy-status ${this.plugin.settings.enabled ? "active" : "inactive"}`,
			text: this.plugin.settings.enabled && a ? `ON — ${a.name}` : "OFF",
		});

		new Setting(c).setName("Enable proxy").addToggle((t) => t.setValue(this.plugin.settings.enabled).onChange(async (v) => {
			if (v) { if (!this.plugin.getActiveProxy()) { new Notice("Select a proxy first"); t.setValue(false); return; } await this.plugin.enableProxy(); }
			else await this.plugin.disableProxy();
			this.display();
		}));

		c.createEl("div", { text: "PROXY LIST", cls: "obsi-proxy-section-title" });
		this.listEl = c.createEl("div");
		this.plugin.settings.proxies.forEach((p) => this.item(p));
		if (!this.plugin.settings.proxies.length) this.listEl.createEl("p", { text: "No proxies. Add one below.", attr: { style: "color: var(--text-muted);" } });
		new Setting(c).addButton((b) => b.setButtonText("+ Add Proxy").setCta().onClick(() => {
			new ProxyEditModal(this.app, this.plugin, { id: generateId(), name: "", proxyType: "http", host: "", port: "", username: "", password: "" }, true, async (e) => {
				this.plugin.settings.proxies.push(e);
				if (!this.plugin.settings.activeProxyId || this.plugin.settings.proxies.length === 1) this.plugin.settings.activeProxyId = e.id;
				await this.plugin.saveSettings(); this.display();
			}).open();
		}));

		new Setting(c).setName("Emergency Disable").addButton((b) => b.setButtonText("Disable Now").setWarning().onClick(async () => { await this.plugin.disableProxy(); this.display(); }));

		c.createEl("div", { text: "DIAGNOSTICS", cls: "obsi-proxy-section-title" });
		new Setting(c).setName("Diagnostics").setDesc("Full report with real HTTP tests").addButton((b) => b.setButtonText("Run").onClick(async () => {
			b.setButtonText("..."); b.setDisabled(true);
			new DiagModal(this.app, await this.plugin.getDiagnostics()).open();
			b.setButtonText("Run"); b.setDisabled(false);
		}));
		new Setting(c).setName("Deep test").setDesc("5-phase test: resolveProxy + login events + real requests").addButton((b) => b.setButtonText("Run").onClick(async () => {
			const p = this.plugin.getActiveProxy();
			if (!p) { new Notice("Select a proxy first"); return; }
			b.setButtonText("..."); b.setDisabled(true);
			new DiagModal(this.app, await this.plugin.getDeepProxyTest(p)).open();
			b.setButtonText("Run"); b.setDisabled(false);
		}));
	}

	item(proxy: ProxyEntry) {
		if (!this.listEl) return;
		const sel = this.plugin.settings.activeProxyId === proxy.id;
		const el = this.listEl.createEl("div", { cls: `obsi-proxy-list-item ${sel ? "selected" : ""}` });
		el.addEventListener("click", async (e) => { if ((e.target as HTMLElement).closest("button")) return; this.plugin.settings.activeProxyId = proxy.id; await this.plugin.saveSettings(); if (this.plugin.settings.enabled) await this.plugin.enableProxy(); this.display(); });

		const hdr = el.createEl("div", { cls: "obsi-proxy-list-item-header" });
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

		el.createEl("div", { text: `${proxy.proxyType}://${proxy.host}:${proxy.port}${proxy.username ? " (auth)" : ""}${sel ? " — selected" : ""}`, cls: "obsi-proxy-list-item-detail" });
	}
}
