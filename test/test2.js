function x25519RawToPkcs8(raw) {
	const header = Uint8Array.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32]);
	const out = new Uint8Array(header.length + raw.length);
	out.set(header, 0);
	out.set(raw, header.length);
	return out;
}

const PRIVATE_KEY_RAW = Uint8Array.from(
	atob('6MJOsX0QxqW-wFAkfu04NyewQQZoD_Tc2hmywsRHeHo'.replace(/-/g, '+').replace(/_/g, '/').padEnd(44, '=')),
	(c) => c.charCodeAt(0),
);

const PRIVATE_KEY_PKCS8 = x25519RawToPkcs8(PRIVATE_KEY_RAW);

async function decrypt(payload) {
	const normalized = payload
		.replace(/-/g, '+')
		.replace(/_/g, '/')
		.padEnd(Math.ceil(payload.length / 4) * 4, '=');

	const buffer = Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0));

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

console.log(await decrypt('4X4KwqOglkKggX9vvSkrmlEWYEiiil5r8G5tnF-o7QLGOJW-lZACL_KKHLlwwzgSd1wRcNtxKUmprJLbvpJiDXLuhmexqrFt5wLOp7RO5g'));
