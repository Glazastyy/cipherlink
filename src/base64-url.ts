import { InvalidPayloadError } from './errors';

export function bytesToBase64Url(bytes: Uint8Array) {
	let value = '';

	for (const byte of bytes) {
		value += String.fromCharCode(byte);
	}

	return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(value: string) {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) {
		throw new InvalidPayloadError();
	}

	const normalized = value
		.replace(/-/g, '+')
		.replace(/_/g, '/')
		.padEnd(Math.ceil(value.length / 4) * 4, '=');

	try {
		return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
	} catch {
		throw new InvalidPayloadError();
	}
}
