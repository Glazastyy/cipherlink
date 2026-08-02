import { decryptPayload } from './cipher';
import { hasRequiredBaseConfiguration, hasRequiredPrivateKey, type CipherlinkEnv } from './env';
import { InvalidTargetError } from './errors';
import { invalidEncryptedPayloadResponse, invalidRedirectTargetResponse, serviceMisconfiguredResponse } from './http-responses';
import { ensureRedirectTarget } from './redirect-target';

export default {
	async fetch(request: Request, env: CipherlinkEnv) {
		if (!hasRequiredBaseConfiguration(env)) {
			return serviceMisconfiguredResponse.clone();
		}

		const url = new URL(request.url);
		const payload = url.searchParams.get('ref');

		if (!payload) {
			return Response.redirect(env.URL_BASE, 302);
		}

		if (!hasRequiredPrivateKey(env)) {
			return serviceMisconfiguredResponse.clone();
		}

		try {
			const target = await decryptPayload(payload, env.PRIVATE_KEY_RAW);
			return Response.redirect(ensureRedirectTarget(target), 302);
		} catch (error) {
			if (error instanceof InvalidTargetError) {
				return invalidRedirectTargetResponse.clone();
			}

			return invalidEncryptedPayloadResponse.clone();
		}
	},
};
