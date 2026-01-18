const crypto = require('crypto');
const fs = require('fs');

const receiver = crypto.generateKeyPairSync('x25519');

const publicKeyRaw = receiver.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const privateKeyRaw = receiver.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);

fs.writeFileSync('public_key.txt', publicKeyRaw.toString('base64url'));
fs.writeFileSync('private_key.txt', privateKeyRaw.toString('base64url'));

const encrypt = (message, receiverPublicKeyRaw) => {
	const eph = crypto.generateKeyPairSync('x25519');

	const receiverPublicKey = crypto.createPublicKey({
		key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), receiverPublicKeyRaw]),
		format: 'der',
		type: 'spki',
	});

	const sharedSecret = crypto.diffieHellman({
		privateKey: eph.privateKey,
		publicKey: receiverPublicKey,
	});

	const key = crypto.createHash('sha256').update(sharedSecret).digest();
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
	const tag = cipher.getAuthTag();

	return Buffer.concat([eph.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32), iv, tag, encrypted]).toString('base64url');
};

const decrypt = (payload, receiverPrivateKeyRaw) => {
	const buffer = Buffer.from(payload, 'base64url');

	const ephPublicKeyRaw = buffer.subarray(0, 32);
	const iv = buffer.subarray(32, 44);
	const tag = buffer.subarray(44, 60);
	const encrypted = buffer.subarray(60);

	const ephPublicKey = crypto.createPublicKey({
		key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), ephPublicKeyRaw]),
		format: 'der',
		type: 'spki',
	});

	const receiverPrivateKey = crypto.createPrivateKey({
		key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), receiverPrivateKeyRaw]),
		format: 'der',
		type: 'pkcs8',
	});

	const sharedSecret = crypto.diffieHellman({
		privateKey: receiverPrivateKey,
		publicKey: ephPublicKey,
	});

	const key = crypto.createHash('sha256').update(sharedSecret).digest();
	const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
	decipher.setAuthTag(tag);

	return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
};

const url = 'https://exemplo.com/produto?id=123&ref=abc';

const encrypted = encrypt(url, publicKeyRaw);
const decrypted = decrypt(encrypted, privateKeyRaw);

console.log('URL_ORIGINAL:');
console.log(url);
console.log('URL_CRIPTOGRAFADA:');
console.log(encrypted);
console.log('URL_DESCRIPTOGRAFADA:');
console.log(decrypted);
