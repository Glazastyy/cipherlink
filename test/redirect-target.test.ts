import { describe, expect, it } from 'vitest';
import { InvalidTargetError } from '../src/errors';
import { ensureRedirectTarget, isRedirectTargetAllowed } from '../src/redirect-target';

describe('redirect-target', () => {
	it('allows absolute http and https targets', () => {
		expect(isRedirectTargetAllowed('https://example.com/path?q=1')).toBe(true);
		expect(isRedirectTargetAllowed('http://example.com/')).toBe(true);
		expect(ensureRedirectTarget('https://example.com/')).toBe('https://example.com/');
	});

	it('rejects relative and unsafe targets', () => {
		expect(isRedirectTargetAllowed('/relative')).toBe(false);
		expect(isRedirectTargetAllowed('javascript:alert(1)')).toBe(false);
		expect(isRedirectTargetAllowed('mailto:user@example.com')).toBe(false);
		expect(() => ensureRedirectTarget('/relative')).toThrow(InvalidTargetError);
	});
});
