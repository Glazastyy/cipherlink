import { describe, expect, it } from 'vitest';
import worker from '../src/index';

const URL_BASE = 'https://example.com/';

type TestEnv = {
	PRIVATE_KEY_RAW?: string;
	URL_BASE?: string;
};

type X25519DeriveParams = SubtleCryptoDeriveKeyAlgorithm & {
	public: CryptoKey;
};

function assertCryptoKeyPair(value: CryptoKey | CryptoKeyPair): asserts value is CryptoKeyPair {
	if (!('privateKey' in value) || !('publicKey' in value)) {
		throw new TypeError('Expected a CryptoKeyPair');
	}
}

async function exportKeyBytes(format: 'raw' | 'pkcs8', key: CryptoKey) {
	const exported = await crypto.subtle.exportKey(format, key);

	if (!(exported instanceof ArrayBuffer)) {
		throw new TypeError('Expected binary key export');
	}

	return new Uint8Array(exported);
}

function bytesToBase64Url(bytes: Uint8Array) {
	let value = '';

	for (const byte of bytes) {
		value += String.fromCharCode(byte);
	}

	return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function createKeyMaterial() {
	const receiver = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
	assertCryptoKeyPair(receiver);
	const privateKeyPkcs8 = await exportKeyBytes('pkcs8', receiver.privateKey);
	const publicKeyRaw = await exportKeyBytes('raw', receiver.publicKey);

	return {
		privateKeyRawBase64Url: bytesToBase64Url(privateKeyPkcs8.slice(-32)),
		publicKeyRaw,
	};
}

async function encryptTarget(target: string, receiverPublicKeyRaw: Uint8Array) {
	const eph = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
	assertCryptoKeyPair(eph);
	const receiverKey = await crypto.subtle.importKey('raw', receiverPublicKeyRaw, { name: 'X25519' }, false, []);
	const deriveParams: X25519DeriveParams = { name: 'X25519', public: receiverKey };
	const shared = await crypto.subtle.deriveBits(deriveParams, eph.privateKey, 256);
	const keyMaterial = await crypto.subtle.digest('SHA-256', shared);
	const aesKey = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt']);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(target)));
	const ephPublicKeyRaw = await exportKeyBytes('raw', eph.publicKey);
	const payload = new Uint8Array(ephPublicKeyRaw.length + iv.length + encrypted.length);

	payload.set(ephPublicKeyRaw, 0);
	payload.set(iv, ephPublicKeyRaw.length);
	payload.set(encrypted, ephPublicKeyRaw.length + iv.length);

	return bytesToBase64Url(payload);
}

async function fetchWorker(url: string, env: TestEnv) {
	return worker.fetch(new Request(url), env as Env);
}

describe('cipherlink worker', () => {
	it('redirects to URL_BASE when ref is absent', async () => {
		const response = await fetchWorker('https://cipherlink.test/', { URL_BASE });

		expect(response.status).toBe(302);
		expect(response.headers.get('Location')).toBe(URL_BASE);
	});

	it('decrypts a valid ref and redirects to the target URL', async () => {
		const keyMaterial = await createKeyMaterial();
		const target = 'https://target.example/path?q=1#section';
		const ref = await encryptTarget(target, keyMaterial.publicKeyRaw);
		const response = await fetchWorker(`https://cipherlink.test/?ref=${encodeURIComponent(ref)}`, {
			PRIVATE_KEY_RAW: keyMaterial.privateKeyRawBase64Url,
			URL_BASE,
		});

		expect(response.status).toBe(302);
		expect(response.headers.get('Location')).toBe(target);
	});

	it('rejects malformed encrypted refs', async () => {
		const keyMaterial = await createKeyMaterial();
		const response = await fetchWorker('https://cipherlink.test/?ref=invalid', {
			PRIVATE_KEY_RAW: keyMaterial.privateKeyRawBase64Url,
			URL_BASE,
		});

		expect(response.status).toBe(400);
		expect(await response.text()).toBe('Invalid encrypted payload');
	});

	it('rejects decrypted targets with unsafe protocols', async () => {
		const keyMaterial = await createKeyMaterial();
		const ref = await encryptTarget('javascript:alert(1)', keyMaterial.publicKeyRaw);
		const response = await fetchWorker(`https://cipherlink.test/?ref=${encodeURIComponent(ref)}`, {
			PRIVATE_KEY_RAW: keyMaterial.privateKeyRawBase64Url,
			URL_BASE,
		});

		expect(response.status).toBe(400);
		expect(await response.text()).toBe('Invalid redirect target');
	});

	it('fails closed when required configuration is missing', async () => {
		const response = await fetchWorker('https://cipherlink.test/', {});

		expect(response.status).toBe(500);
		expect(await response.text()).toBe('Service misconfigured');
	});
});
