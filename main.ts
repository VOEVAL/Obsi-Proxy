import { App, Notice, Plugin, PluginSettingTab, Setting, Modal, requestUrl } from "obsidian";
import type { ElectronSession } from "electron";

/**
 * Plugin settings interface.
 * All fields are persisted in data.json and survive Obsidian restarts.
 */
interface ProxySettings {
	enabled: boolean;
	proxyType: "http" | "socks5";
	host: string;
	port: string;
	username: string;
	password: string;
}

const DEFAULT_SETTINGS: ProxySettings = {
	enabled: false,
	proxyType: "http",
	host: "",
	port: "",
	username: "",
	password: "",
};

/**
 * Main plugin class.
 *
 * Traffic interception mechanism:
 * ────────────────────────────────
 * Obsidian runs on Electron. Electron exposes a `session` object that
 * governs all network requests from the renderer process.
 *
 * When we call session.defaultSession.setProxy({ proxyRules }),
 * Chromium (Electron's engine) begins routing **all** HTTP/HTTPS
 * requests through the specified proxy server. This includes:
 *   - Obsidian Sync
 *   - Theme and plugin updates
 *   - requestUrl() calls
 *   - Built-in PDF and image viewers fetching remote resources
 *
 * proxyRules format for HTTP:
 *   "http=host:port;https=host:port"
 *
 * proxyRules format for SOCKS5:
 *   "socks5://host:port"  (Chromium understands the socks5:// scheme)
 *
 * If credentials are provided, they are embedded in the URL:
 *   "http://user:pass@host:port"
 *   "socks5://user:pass@host:port"
 *
 * Important: setProxy takes effect immediately for all *new* connections.
 * Existing keep-alive connections may retain their previous route.
 */
export default class ProxyPlugin extends Plugin {
	settings: ProxySettings = DEFAULT_SETTINGS;

	async onload() {
		await this.loadSettings();
		this.addSettingTab(new ProxySettingTab(this.app, this));

		/**
		 * On startup, check if proxy was enabled previously.
		 * If so, apply settings automatically so the user doesn't
		 * lose configuration after restarting Obsidian.
		 */
		if (this.settings.enabled) {
			await this.applyProxy();
		}
	}

	async onunload() {
		/**
		 * When the plugin is unloaded (deactivation / Obsidian close),
		 * clear proxy rules to avoid leaving the system in a modified state.
		 */
		await this.clearProxy();
	}

	async loadSettings() {
		this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
	}

	async saveSettings() {
		await this.saveData(this.settings);
	}

	/**
	 * Builds a proxyRules string in Chromium's recognized format.
	 *
	 * Chromium documentation:
	 *   https://www.chromium.org/developers/design-documents/network-settings/#proxy-configuration
	 *
	 * Format:
	 *   [scheme://[user:pass@]]host:port
	 *
	 * Schemes:
	 *   http   → HTTP/HTTPS proxy (Chromium routes both protocols)
	 *   socks5 → SOCKS5 proxy (DNS resolution happens on the proxy side)
	 */
	buildProxyRules(): string {
		const { proxyType, host, port, username, password } = this.settings;

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
	 * Applies proxy configuration to the default Electron session.
	 *
	 * Key call: session.defaultSession.setProxy()
	 *   - config argument: { proxyRules, proxyBypassRules }
	 *   - proxyRules: routing string (see buildProxyRules)
	 *   - proxyBypassRules: domains that bypass the proxy
	 *     (empty = all traffic goes through proxy)
	 *
	 * After setProxy, Chromium updates the route for new TCP connections.
	 */
	async applyProxy(): Promise<boolean> {
		const rules = this.buildProxyRules();
		if (!rules) {
			new Notice("Global Proxy: host and port are required");
			return false;
		}

		try {
			/**
			 * Access the Electron session.
			 *
			 * In Obsidian, Electron API access goes through:
			 *   (window as any).require('electron')
			 *
			 * remote.session is the Session object of the current BrowserWindow.
			 * We use defaultSession which serves Obsidian's main renderer.
			 */
			const electron = (window as any).require("electron");
			const session: ElectronSession =
				electron.remote?.session?.defaultSession ??
				electron.session?.defaultSession;

			if (!session) {
				new Notice("Global Proxy: cannot access Electron session");
				return false;
			}

			await session.setProxy({
				proxyRules: rules,
				proxyBypassRules: "",
			});

			new Notice(
				`Global Proxy: ON (${this.settings.proxyType}://${this.settings.host}:${this.settings.port})`
			);
			return true;
		} catch (err) {
			console.error("Global Proxy apply error:", err);
			new Notice(
				`Global Proxy: error applying proxy — ${err.message ?? err}`
			);
			return false;
		}
	}

	/**
	 * Clears proxy configuration — all traffic returns to direct.
	 *
	 * Calling setProxy({ proxyRules: "" }) clears routing rules,
	 * and Chromium reverts to direct connections (DIRECT).
	 */
	async clearProxy(): Promise<void> {
		try {
			const electron = (window as any).require("electron");
			const session: ElectronSession =
				electron.remote?.session?.defaultSession ??
				electron.session?.defaultSession;

			if (session) {
				await session.setProxy({ proxyRules: "", proxyBypassRules: "" });
			}
		} catch (err) {
			console.error("Global Proxy clear error:", err);
		}
	}

	/**
	 * Enable proxy: apply rules + persist enabled flag.
	 */
	async enableProxy(): Promise<void> {
		const ok = await this.applyProxy();
		this.settings.enabled = ok;
		await this.saveSettings();
	}

	/**
	 * Disable proxy: clear rules + persist enabled=false.
	 * User can toggle proxy off on the fly with a single click.
	 */
	async disableProxy(): Promise<void> {
		await this.clearProxy();
		this.settings.enabled = false;
		await this.saveSettings();
		new Notice("Global Proxy: OFF — direct connection restored");
	}

	/**
	 * Connection check via the current proxy.
	 *
	 * Makes a GET request to https://api.ipify.org?format=json
	 * through Obsidian's requestUrl() — which internally uses fetch,
	 * which in Electron goes through session proxy rules.
	 *
	 * If proxy is applied, the request goes through the proxy,
	 * and ipify returns the proxy's IP instead of the user's real IP.
	 */
	async checkConnection(): Promise<{ ip: string } | null> {
		try {
			const resp = await requestUrl({
				url: "https://api.ipify.org?format=json",
				method: "GET",
			});
			return resp.json as { ip: string };
		} catch (err) {
			console.error("Global Proxy check error:", err);
			return null;
		}
	}
}

/**
 * Modal dialog for displaying proxy check results.
 */
class ProxyCheckModal extends Modal {
	result: { ip: string } | null;
	error: string | null;
	isProxyOn: boolean;

	constructor(
		app: App,
		result: { ip: string } | null,
		error: string | null,
		isProxyOn: boolean
	) {
		super(app);
		this.result = result;
		this.error = error;
		this.isProxyOn = isProxyOn;
	}

	onOpen() {
		const { contentEl } = this;
		contentEl.empty();
		contentEl.addClass("global-proxy-check-modal");

		contentEl.createEl("h2", { text: "Proxy Connection Check" });

		if (!this.isProxyOn) {
			contentEl.createEl("p", {
				text: "Proxy is currently OFF. The IP below is your real IP (direct connection).",
				cls: "global-proxy-check-result",
			});
		}

		if (this.error) {
			contentEl.createEl("p", {
				text: `Error: ${this.error}`,
				cls: "global-proxy-check-result",
				attr: {
					style:
						"background: var(--background-modifier-error); color: var(--text-error);",
				},
			});
			contentEl.createEl("p", {
				text: "The proxy server is unreachable or the credentials are incorrect. Click the toggle to disable the proxy and restore direct connection.",
			});
		} else if (this.result) {
			contentEl.createEl("p", {
				text: `Current outgoing IP: ${this.result.ip}`,
				cls: "global-proxy-check-result",
				attr: {
					style:
						"background: var(--background-modifier-success); color: var(--text-success);",
				},
			});
			if (this.isProxyOn) {
				contentEl.createEl("p", {
					text: "This IP belongs to your proxy server. Connection is working correctly.",
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
 * Plugin settings tab.
 *
 * Builds the UI under Settings → Community Plugins → Global Proxy.
 */
class ProxySettingTab extends PluginSettingTab {
	plugin: ProxyPlugin;
	statusEl: HTMLElement | null = null;

	constructor(app: App, plugin: ProxyPlugin) {
		super(app, plugin);
		this.plugin = plugin;
	}

	display(): void {
		const { containerEl } = this;
		containerEl.empty();
		containerEl.addClass("global-proxy-settings");

		containerEl.createEl("h2", { text: "Global Proxy Settings" });

		/**
		 * Status bar: visual indicator showing whether proxy is active.
		 */
		this.statusEl = containerEl.createEl("div", {
			cls: `global-proxy-status ${this.plugin.settings.enabled ? "active" : "inactive"}`,
			text: this.plugin.settings.enabled
				? `Proxy ON — ${this.plugin.settings.proxyType}://${this.plugin.settings.host}:${this.plugin.settings.port}`
				: "Proxy OFF — direct connection",
		});

		/**
		 * Main toggle: enable/disable proxy on the fly.
		 * Toggling instantly applies or clears proxy rules.
		 */
		new Setting(containerEl)
			.setName("Enable proxy")
			.setDesc("Toggle proxy on/off without restarting Obsidian")
			.addToggle((toggle) =>
				toggle
					.setValue(this.plugin.settings.enabled)
					.onChange(async (val) => {
						if (val) {
							await this.plugin.enableProxy();
						} else {
							await this.plugin.disableProxy();
						}
						this.refreshStatus();
					})
			);

		/**
		 * Proxy type selector: HTTP or SOCKS5.
		 * Chromium supports both types through different schemes in proxyRules.
		 */
		new Setting(containerEl)
			.setName("Proxy type")
			.setDesc(
				"HTTP proxy handles HTTP/HTTPS traffic. SOCKS5 proxies all TCP with DNS resolution on the proxy side."
			)
			.addDropdown((dd) =>
				dd
					.addOption("http", "HTTP")
					.addOption("socks5", "SOCKS5")
					.setValue(this.plugin.settings.proxyType)
					.onChange(async (val: string) => {
						this.plugin.settings.proxyType = val as "http" | "socks5";
						await this.plugin.saveSettings();
						if (this.plugin.settings.enabled) {
							await this.plugin.enableProxy();
							this.refreshStatus();
						}
					})
			);

		/**
		 * Proxy server IP address.
		 */
		new Setting(containerEl)
			.setName("Host")
			.setDesc("IP address or hostname of the proxy server")
			.addText((text) =>
				text
					.setPlaceholder("e.g. 127.0.0.1")
					.setValue(this.plugin.settings.host)
					.onChange(async (val) => {
						this.plugin.settings.host = val.trim();
						await this.plugin.saveSettings();
					})
			);

		/**
		 * Proxy server port.
		 */
		new Setting(containerEl)
			.setName("Port")
			.setDesc("Port number of the proxy server")
			.addText((text) =>
				text
					.setPlaceholder("e.g. 8080")
					.setValue(this.plugin.settings.port)
					.onChange(async (val) => {
						this.plugin.settings.port = val.trim();
						await this.plugin.saveSettings();
					})
			);

		/**
		 * Proxy authentication username (optional).
		 * Embedded in URL: http://user:pass@host:port
		 */
		new Setting(containerEl)
			.setName("Username")
			.setDesc("Leave empty if proxy does not require authentication")
			.addText((text) =>
				text
					.setPlaceholder("optional")
					.setValue(this.plugin.settings.username)
					.onChange(async (val) => {
						this.plugin.settings.username = val;
						await this.plugin.saveSettings();
					})
			);

		/**
		 * Proxy authentication password (optional).
		 */
		new Setting(containerEl)
			.setName("Password")
			.setDesc("Leave empty if proxy does not require authentication")
			.addText((text) => {
				text.inputEl.type = "password";
				text
					.setPlaceholder("optional")
					.setValue(this.plugin.settings.password)
					.onChange(async (val) => {
						this.plugin.settings.password = val;
						await this.plugin.saveSettings();
					});
			});

		/**
		 * "Check Connection" button — Proxy Checker.
		 *
		 * Makes a GET request to ipify through the current proxy and shows
		 * the IP address or an error. This lets the user verify the proxy
		 * works before relying on it.
		 */
		new Setting(containerEl)
			.setName("Check Connection")
			.setDesc(
				"Requests https://api.ipify.org through the current proxy to verify connectivity"
			)
			.addButton((btn) =>
				btn.setButtonText("Check Connection").onClick(async () => {
					btn.setButtonText("Checking...");
					btn.setDisabled(true);

					const result = await this.plugin.checkConnection();
					const error =
						result === null
							? "Connection failed — proxy may be unreachable"
							: null;

					btn.setButtonText("Check Connection");
					btn.setDisabled(false);

					/**
					 * Show result in a modal dialog.
					 * Also emit a brief Notice for quick feedback.
					 */
					if (error) {
						new Notice("Global Proxy: connection check failed", 5000);
					} else if (result) {
						new Notice(
							`Global Proxy: outgoing IP is ${result.ip}`,
							5000
						);
					}

					const modal = new ProxyCheckModal(
						this.app,
						result,
						error,
						this.plugin.settings.enabled
					);
					modal.open();
				})
			);

		/**
		 * Emergency disable button — "Kill Switch".
		 * Useful when proxy is broken and Obsidian "lost network":
		 * one click clears all proxy rules.
		 */
		new Setting(containerEl)
			.setName("Emergency Disable")
			.setDesc(
				"Instantly clear proxy rules and restore direct connection"
			)
			.addButton((btn) =>
				btn.setButtonText("Disable Proxy Now").onClick(async () => {
					await this.plugin.disableProxy();
					this.refreshStatus();
				})
			);
	}

	refreshStatus() {
		if (!this.statusEl) return;
		this.statusEl.className = `global-proxy-status ${this.plugin.settings.enabled ? "active" : "inactive"}`;
		this.statusEl.textContent = this.plugin.settings.enabled
			? `Proxy ON — ${this.plugin.settings.proxyType}://${this.plugin.settings.host}:${this.plugin.settings.port}`
			: "Proxy OFF — direct connection";
	}
}
