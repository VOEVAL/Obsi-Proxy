declare module "electron" {
	interface ProxyConfig {
		mode?: "direct" | "auto_detect" | "pac_script" | "fixed_servers" | "system";
		proxyRules: string;
		proxyBypassRules: string;
	}
	interface ElectronSession {
		setProxy(config: ProxyConfig): Promise<void>;
		resolveProxy(url: string): Promise<string>;
	}
}
