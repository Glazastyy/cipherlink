# cipherlink

`cipherlink` is a Cloudflare Worker that receives an encrypted `ref` query parameter, decrypts it with X25519 plus AES-GCM, and redirects to the decrypted destination.

## Behavior

- Requests without `ref` redirect to `URL_BASE`.
- Valid encrypted payloads redirect to absolute `http` or `https` URLs.
- Malformed payloads return `400 Invalid encrypted payload`.
- Decrypted targets with unsupported protocols return `400 Invalid redirect target`.
- Missing or invalid required configuration returns `500 Service misconfigured`.

## Configuration

Set these bindings before running or deploying:

- `URL_BASE`: fallback absolute `http` or `https` URL.
- `PRIVATE_KEY_RAW`: X25519 private key encoded as Base64URL raw 32-byte key material.

Use Wrangler secrets for `PRIVATE_KEY_RAW`:

```bash
bunx wrangler secret put PRIVATE_KEY_RAW
```

## Development

Install dependencies:

```bash
bun install
```

Run the full local verification:

```bash
bun run check
```

Start the Worker locally:

```bash
bun run dev
```

Deploy:

```bash
bun run deploy
```

Regenerate Cloudflare Worker types after changing `wrangler.jsonc`:

```bash
bun run cf-typegen
```

## License

MIT
