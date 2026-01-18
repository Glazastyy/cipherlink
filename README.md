# 🔐 cipherlink

`cipherlink` is a lightweight, secure URL redirection service built on **Cloudflare Workers**. It uses end-to-end encryption to protect destination URLs until they are decrypted by the worker at runtime.

## 🚀 How it works

The service listens for requests with an encrypted `ref` parameter. It then:
1. Performs an **X25519** Diffie-Hellman key exchange using a private key stored in its environment.
2. Derives a shared secret.
3. Decrypts the destination URL using **AES-256-GCM**.
4. Redirects the user to the decrypted URL.

This ensures that the final destination of a link is hidden from intermediate layers (like logs or analytics) until the moment of redirection.

## ✨ Features

- **X25519 Key Exchange**: Robust asymmetric encryption for shared secret derivation.
- **AES-GCM**: High-performance symmetric encryption for the payload.
- **Cloudflare Workers**: Global distribution and low latency.
- **Privacy Oriented**: Destination URLs are never stored or transmitted in plain text.

## 🛠️ Setup

### Environment Variables

You need to configure the following environment variables in your Cloudflare dashboard or `wrangler.jsonc`:

- `PRIVATE_KEY_RAW`: Your X25519 private key in Base64Url format.
- `URL_BASE`: The default URL to redirect to if no `ref` parameter is provided.

### Deployment

```bash
npm install
npm run deploy
```

## 💻 Development

### Key Scripts

- `npm run dev`: Start a local development server using `wrangler`.
- `npm run test`: Run the test suite using `vitest`.
- `npm run cf-typegen`: Generate TypeScript types for your environment bindings.

## 📄 License

MIT.
