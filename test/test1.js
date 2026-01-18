const BASE = 'https://h4f.me/url?ref=';
const SKIP_SCHEMES = ['mailto:', 'tel:', 'sms:', 'whatsapp:', 'tg:', 'skype:', 'javascript:'];
const RECEIVER_PUBLIC_KEY = 'B_lo6bv4ROCzB4fRmUMQlPfyoIWeQSGZx8QGpIoZW3c';

function b64uToBuf(s) {
	s = s.replace(/-/g, '+').replace(/_/g, '/');
	s = s.padEnd(Math.ceil(s.length / 4) * 4, '=');
	return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

function bufToB64u(b) {
	return btoa(String.fromCharCode(...b))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

async function encrypt(message) {
	const receiverKeyRaw = b64uToBuf(RECEIVER_PUBLIC_KEY);
	const eph = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
	const receiverKey = await crypto.subtle.importKey('raw', receiverKeyRaw, { name: 'X25519' }, false, []);
	const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: receiverKey }, eph.privateKey, 256);
	const keyMaterial = await crypto.subtle.digest('SHA-256', shared);
	const aesKey = await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt']);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(message)));
	const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
	const payload = new Uint8Array(ephPubRaw.length + iv.length + encrypted.length);
	payload.set(ephPubRaw, 0);
	payload.set(iv, 32);
	payload.set(encrypted, 44);
	return bufToB64u(payload);
}

console.log(await encrypt('https://google.com/'));
