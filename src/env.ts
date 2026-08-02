import { isRedirectTargetAllowed } from './redirect-target';

export type CipherlinkEnv = Env & {
	PRIVATE_KEY_RAW?: string;
	URL_BASE?: string;
};

export type BaseConfiguredEnv = CipherlinkEnv & {
	URL_BASE: string;
};

export type PrivateKeyConfiguredEnv = CipherlinkEnv & {
	PRIVATE_KEY_RAW: string;
};

export function hasRequiredBaseConfiguration(env: CipherlinkEnv): env is BaseConfiguredEnv {
	return isRedirectTargetAllowed(env.URL_BASE);
}

export function hasRequiredPrivateKey(env: CipherlinkEnv): env is PrivateKeyConfiguredEnv {
	return typeof env.PRIVATE_KEY_RAW === 'string' && env.PRIVATE_KEY_RAW.length > 0;
}
