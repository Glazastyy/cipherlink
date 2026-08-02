import { InvalidTargetError } from './errors';

export function isRedirectTargetAllowed(value: unknown) {
	if (typeof value !== 'string') {
		return false;
	}

	try {
		const url = new URL(value);
		return url.protocol === 'https:' || url.protocol === 'http:';
	} catch {
		return false;
	}
}

export function ensureRedirectTarget(value: string) {
	if (!isRedirectTargetAllowed(value)) {
		throw new InvalidTargetError();
	}

	return value;
}
