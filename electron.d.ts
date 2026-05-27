declare module "electron" {
	interface ProxyConfig {
		proxyRules: string;
		proxyBypassRules: string;
	}
	interface ElectronSession {
		setProxy(config: ProxyConfig): Promise<void>;
	}
}
