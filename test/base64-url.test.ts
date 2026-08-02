import { describe, expect, it } from 'vitest';
import { InvalidPayloadError } from '../src/errors';
import { bytesToBase64Url, base64UrlToBytes } from '../src/base64-url';

describe('base64-url', () => {
	it('encodes and decodes bytes without padding', () => {
		const bytes = Uint8Array.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
		const encoded = bytesToBase64Url(bytes);

		expect(encoded).not.toContain('=');
		expect(encoded).not.toContain('+');
		expect(encoded).not.toContain('/');
		expect(base64UrlToBytes(encoded)).toEqual(bytes);
	});

	it('rejects malformed base64url input', () => {
		expect(() => base64UrlToBytes('abc=')).toThrow(InvalidPayloadError);
		expect(() => base64UrlToBytes('abc+')).toThrow(InvalidPayloadError);
		expect(() => base64UrlToBytes('')).toThrow(InvalidPayloadError);
	});
});
