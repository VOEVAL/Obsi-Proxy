import {
	App,
	Notice,
	Plugin,
	PluginSettingTab,
	Setting,
	Modal,
	requestUrl,
	ButtonComponent,
} from "obsidian";
import type { ElectronSession } from "electron";

/**
 * Single proxy configuration entry.
 * Each entry is a unique proxy server the user has saved.
 */
interface ProxyEntry {
	id: string;
	name: string;
	proxyType: "http" | "socks5";
	host: string;
	port: string;
	username: string;
	password: string;
}

/**
 * Plugin settings — persisted in data.json.
 *
 * - enabled:      whether proxy is currently active
 * - activeProxyId: ID of the selected proxy entry
 * - proxies:      list of all saved proxy configurations
 */
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

/**
 * Generate a unique ID for new proxy entries.
 */
function generateId(): string {
	return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/**
 * Main plugin class — Obsi Proxy.
 *
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  HOW TRAFFIC INTERCEPTION WORKS
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Obsidian runs on Electron, which is built on Chromium.
 * Chromium's network stack has a built-in proxy resolver that
 * controls routing for ALL HTTP/HTTPS/TCP connections made by
 * the renderer process.
 *
 * When we call:
 *
 *   session.defaultSession.setProxy({ proxyRules })
 *
 * Chromium immediately updates its proxy configuration. Every
 * new network request from the renderer — including requests
 * made by:
 *   - Obsidian core (Sync, updates, image loading, PDF viewer)
 *   - ALL installed community plugins (any plugin that uses
 *     requestUrl, fetch, XMLHttpRequest, or any net request)
 *   - The internal webview used for external links
 *
 * — will be routed through the specified proxy server.
 *
 * This works because ALL of these go through Chromium's
 * network stack, which respects the session-level proxy rules.
 * There is no way for a plugin to bypass this unless it opens
 * a separate Node.js net.Socket (which no Obsidian plugin does).
 *
 * proxyRules format for HTTP:
 *   "http=host:port;https=host:port"
 *
 * proxyRules format for SOCKS5:
 *   "socks5://host:port"
 *   (Chromium resolves DNS through the SOCKS5 proxy)
 *
 * With credentials:
 *   "http://user:pass@host:port;https=user:pass@host:port"
 *   "socks5://user:pass@host:port"
 *
 * setProxy takes effect immediately for NEW connections.
 * Existing keep-alive connections may keep their old route
 * until they close and reconnect.
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */
export default class ObsiProxyPlugin extends Plugin {
	settings: ProxySettings = DEFAULT_SETTINGS;

	async onload() {
		await this.loadSettings();
		this.addSettingTab(new ObsiProxySettingTab(this.app, this));

		if (this.settings.enabled && this.getActiveProxy()) {
			await this.applyProxy();
		}
	}

	async onunload() {
		await this.clearProxy();
	}

	async loadSettings() {
		const loaded = await this.loadData();
		this.settings = Object.assign({}, DEFAULT_SETTINGS, loaded);
		if (!this.settings.proxies) {
			this.settings.proxies = [];
		}
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

	/**
	 * Build a Chromium-compatible proxyRules string from a ProxyEntry.
	 *
	 * Chromium docs:
	 *   https://www.chromium.org/developers/design-documents/network-settings/
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
	 * Get the Electron session object.
	 *
	 * Obsidian gives us access to Electron via:
	 *   (window as any).require('electron')
	 *
	 * We need defaultSession from either remote.session
	 * or directly from electron.session (depends on
	 * Electron version and contextIsolation settings).
	 */
	getSession(): ElectronSession | null {
		try {
			const electron = (window as any).require("electron");
			return (
				electron.remote?.session?.defaultSession ??
				electron.session?.defaultSession ??
				null
			);
		} catch {
			return null;
		}
	}

	/**
	 * Apply proxy rules to the Electron session.
	 *
	 * This is the core call that makes ALL Obsidian + plugin traffic
	 * go through the proxy. After this call, every new HTTP/HTTPS/TCP
	 * connection from the renderer process will be routed through the
	 * specified proxy server.
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

		const session = this.getSession();
		if (!session) {
			new Notice("Obsi Proxy: cannot access Electron session");
			return false;
		}

		try {
			await session.setProxy({
				proxyRules: rules,
				proxyBypassRules: "",
			});
			new Notice(
				`Obsi Proxy: ON — ${proxy.name} (${proxy.proxyType}://${proxy.host}:${proxy.port})`
			);
			return true;
		} catch (err) {
			console.error("Obsi Proxy apply error:", err);
			new Notice(
				`Obsi Proxy: error — ${err.message ?? err}`
			);
			return false;
		}
	}

	/**
	 * Clear proxy rules — all traffic returns to direct connection.
	 */
	async clearProxy(): Promise<void> {
		const session = this.getSession();
		if (!session) return;

		try {
			await session.setProxy({
				proxyRules: "",
				proxyBypassRules: "",
			});
		} catch (err) {
			console.error("Obsi Proxy clear error:", err);
		}
	}

	async enableProxy(): Promise<void> {
		const ok = await this.applyProxy();
		this.settings.enabled = ok;
		await this.saveSettings();
	}

	async disableProxy(): Promise<void> {
		await this.clearProxy();
		this.settings.enabled = false;
		await this.saveSettings();
		new Notice("Obsi Proxy: OFF — direct connection restored");
	}

	/**
	 * Apply a specific proxy (by entry) to the session.
	 * Used for temporarily checking a proxy that isn't currently active.
	 */
	async applySpecificProxy(proxy: ProxyEntry): Promise<boolean> {
		const rules = this.buildProxyRules(proxy);
		if (!rules) return false;

		const session = this.getSession();
		if (!session) return false;

		try {
			await session.setProxy({
				proxyRules: rules,
				proxyBypassRules: "",
			});
			return true;
		} catch {
			return false;
		}
	}

	/**
	 * Connection check.
	 *
	 * If proxy is enabled and this is the active proxy — just check directly.
	 * If proxy is NOT enabled — temporarily apply the proxy, check, then
	 * revert to the previous state (either direct or previous active proxy).
	 *
	 * This ensures the checker works regardless of whether the proxy
	 * is currently connected or not.
	 */
	async checkConnection(proxy: ProxyEntry): Promise<{
		ip: string;
	} | null> {
		const isActive =
			this.settings.enabled &&
			this.settings.activeProxyId === proxy.id;

		let needsRevert = false;

		if (!isActive) {
			const applied = await this.applySpecificProxy(proxy);
			if (!applied) return null;
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
				if (this.settings.enabled && this.getActiveProxy()) {
					await this.applyProxy();
				} else {
					await this.clearProxy();
				}
			}
		}
	}
}

/**
 * Modal for displaying proxy check results.
 */
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
		contentEl.addClass("obsi-proxy-check-modal");

		contentEl.createEl("h2", { text: "Proxy Connection Check" });
		contentEl.createEl("p", {
			text: `Checking: ${this.proxyName}`,
			cls: "obsi-proxy-check-result",
		});

		if (!this.wasActiveWhenChecked) {
			contentEl.createEl("p", {
				text: "Note: Proxy was not active. It was temporarily applied for this check and then reverted.",
				attr: { style: "font-style: italic; color: var(--text-muted);" },
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
				text: "The proxy server is unreachable or the credentials are incorrect. You can try another proxy or hit Emergency Disable.",
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
			if (this.wasActiveWhenChecked) {
				contentEl.createEl("p", {
					text: "This IP belongs to your proxy server. Connection is working correctly.",
				});
			} else {
				contentEl.createEl("p", {
					text: "This is the IP that would be seen if you enable this proxy. Connection is working correctly.",
				});
			}
		}

		new Setting(contentEl).addButton((btn) =>
			btn.setButtonText("Close").onClick(() => this.close())
		);
	}

	onClose() {
		this.contentEl.empty();
	}
}

/**
 * Modal for adding or editing a proxy entry.
 */
class ProxyEditModal extends Modal {
	plugin: ObsiProxyPlugin;
	entry: ProxyEntry;
	onSave: (entry: ProxyEntry) => void;
	isNew: boolean;

	nameInput: HTMLInputElement;
	typeSelect: HTMLSelectElement;
	hostInput: HTMLInputElement;
	portInput: HTMLInputElement;
	usernameInput: HTMLInputElement;
	passwordInput: HTMLInputElement;

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
			.addText((text) => {
				text
					.setPlaceholder("e.g. Work VPN")
					.setValue(this.entry.name)
					.onChange((val) => {
						this.entry.name = val;
					});
				this.nameInput = text.inputEl;
			});

		new Setting(contentEl)
			.setName("Proxy type")
			.setDesc("HTTP routes HTTP/HTTPS. SOCKS5 proxies all TCP with DNS on the proxy side.")
			.addDropdown((dd) => {
				dd
					.addOption("http", "HTTP")
					.addOption("socks5", "SOCKS5")
					.setValue(this.entry.proxyType)
					.onChange((val: string) => {
						this.entry.proxyType = val as "http" | "socks5";
					});
				this.typeSelect = dd.selectEl;
			});

		new Setting(contentEl)
			.setName("Host")
			.setDesc("IP address or hostname")
			.addText((text) => {
				text
					.setPlaceholder("e.g. 127.0.0.1")
					.setValue(this.entry.host)
					.onChange((val) => {
						this.entry.host = val.trim();
					});
				this.hostInput = text.inputEl;
			});

		new Setting(contentEl)
			.setName("Port")
			.setDesc("Port number")
			.addText((text) => {
				text
					.setPlaceholder("e.g. 8080")
					.setValue(this.entry.port)
					.onChange((val) => {
						this.entry.port = val.trim();
					});
				this.portInput = text.inputEl;
			});

		new Setting(contentEl)
			.setName("Username")
			.setDesc("Leave empty if not required")
			.addText((text) => {
				text
					.setPlaceholder("optional")
					.setValue(this.entry.username)
					.onChange((val) => {
						this.entry.username = val;
					});
				this.usernameInput = text.inputEl;
			});

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
				this.passwordInput = text.inputEl;
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

/**
 * Settings tab — the main UI for Obsi Proxy.
 */
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
						this.refreshStatus();
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
			text: isSelected ? `> ${proxy.name}` : proxy.name,
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

			this.plugin.settings.proxies = this.plugin.settings.proxies.filter(
				(p) => p.id !== proxy.id
			);

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
			text: `${proxy.proxyType}://${proxy.host}:${proxy.port}${proxy.username ? " (auth)" : ""}${isSelected ? " — selected" : ""}`,
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
