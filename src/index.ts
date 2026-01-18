function x25519RawToPkcs8(raw) {
	const header = Uint8Array.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32]);
	const out = new Uint8Array(header.length + raw.length);
	out.set(header, 0);
	out.set(raw, header.length);
	return out;
}

function base64UrlToUint8Array(value: string) {
	const normalized = value
		.replace(/-/g, '+')
		.replace(/_/g, '/')
		.padEnd(Math.ceil(value.length / 4) * 4, '=');

	return Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0));
}

export default {
	async fetch(request: { url: string | URL }, env: { PRIVATE_KEY_RAW: string, URL_BASE: string }) {
		const url = new URL(request.url);
		const payload = url.searchParams.get('ref');

		if (!payload) {
			return Response.redirect(env.URL_BASE, 302);
		}

		try {
			const PRIVATE_KEY_RAW = base64UrlToUint8Array(env.PRIVATE_KEY_RAW);
			const PRIVATE_KEY_PKCS8 = x25519RawToPkcs8(PRIVATE_KEY_RAW);
			const target = await decrypt(payload, PRIVATE_KEY_PKCS8);
			return Response.redirect(target, 302);
		} catch {
			return new Response('Invalid encrypted payload', { status: 400 });
		}
	},
};

async function decrypt(payload: string, PRIVATE_KEY_PKCS8: ArrayBuffer | Uint8Array<any> | ArrayBufferView<ArrayBufferLike> | JsonWebKey) {
	const normalized = payload
		.replace(/-/g, '+')
		.replace(/_/g, '/')
		.padEnd(Math.ceil(payload.length / 4) * 4, '=');

	const buffer = Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0));

	if (buffer.length < 60) throw new Error();

	const ephPublicKeyRaw = buffer.slice(0, 32);
	const iv = buffer.slice(32, 44);
	const encrypted = buffer.slice(44);

	const receiverPrivateKey = await crypto.subtle.importKey('pkcs8', PRIVATE_KEY_PKCS8, { name: 'X25519' }, false, ['deriveBits']);

	const ephPublicKey = await crypto.subtle.importKey('raw', ephPublicKeyRaw, { name: 'X25519' }, false, []);

	const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: ephPublicKey }, receiverPrivateKey, 256);

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
