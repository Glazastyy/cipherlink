import { base64UrlToBytes } from './base64-url';
import { InvalidPayloadError } from './errors';

const PKCS8_X25519_HEADER = Uint8Array.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32]);
const X25519_KEY_SIZE_BYTES = 32;
const AES_GCM_IV_SIZE_BYTES = 12;
const AES_GCM_TAG_SIZE_BYTES = 16;
const ENCRYPTED_PAYLOAD_MIN_SIZE_BYTES = X25519_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES + AES_GCM_TAG_SIZE_BYTES;

type X25519DeriveParams = SubtleCryptoDeriveKeyAlgorithm & {
	public: CryptoKey;
};

export function x25519RawToPkcs8(raw: Uint8Array) {
	if (raw.length !== X25519_KEY_SIZE_BYTES) {
		throw new InvalidPayloadError();
	}

	const out = new Uint8Array(PKCS8_X25519_HEADER.length + raw.length);
	out.set(PKCS8_X25519_HEADER, 0);
	out.set(raw, PKCS8_X25519_HEADER.length);
	return out;
}

export async function decryptPayload(payload: string, privateKeyRawBase64Url: string) {
	const privateKeyRaw = base64UrlToBytes(privateKeyRawBase64Url);
	const privateKeyPkcs8 = x25519RawToPkcs8(privateKeyRaw);
	const buffer = base64UrlToBytes(payload);

	if (buffer.length < ENCRYPTED_PAYLOAD_MIN_SIZE_BYTES) {
		throw new InvalidPayloadError();
	}

	const ephPublicKeyRaw = buffer.slice(0, X25519_KEY_SIZE_BYTES);
	const iv = buffer.slice(X25519_KEY_SIZE_BYTES, X25519_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES);
	const encrypted = buffer.slice(X25519_KEY_SIZE_BYTES + AES_GCM_IV_SIZE_BYTES);
	const receiverPrivateKey = await crypto.subtle.importKey('pkcs8', privateKeyPkcs8, { name: 'X25519' }, false, ['deriveBits']);
	const ephPublicKey = await crypto.subtle.importKey('raw', ephPublicKeyRaw, { name: 'X25519' }, false, []);
	const deriveParams: X25519DeriveParams = { name: 'X25519', public: ephPublicKey };
	const shared = await crypto.subtle.deriveBits(deriveParams, receiverPrivateKey, 256);
	const aesKey = await crypto.subtle.importKey(
		'raw',
		new Uint8Array(await crypto.subtle.digest('SHA-256', shared)),
		{ name: 'AES-GCM' },
		false,
		['decrypt'],
	);
	const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encrypted);

	return new TextDecoder().decode(decrypted);
}
