# wasm-crypto-box 🛡️

Browser-safe WASM wrapper around ed25519 for use in web apps and extensions.

## Features
- ed25519 keypair generation (uses browser RNG via `getrandom`)
- Message signing and verification
- WASM-friendly types (Uint8Array for keys and signatures)

## Quickstart (Web)
1. Build with `wasm-pack`:

```bash
wasm-pack build --target web
```

2. In your web app (after bundling the `pkg` output):

```js
import init, { generate_keypair, sign, verify } from './pkg/wasm_crypto_box.js';

await init();

const { secretKey, publicKey } = generate_keypair(); // Uint8Array fields
const msg = new TextEncoder().encode('hello');
const sig = sign(msg, secretKey);
const ok = verify(msg, sig, publicKey);
console.log('verified?', ok);
```

## Security Notes
- Keep secret keys confidential — do not send or expose them to untrusted contexts.
- This crate does not implement an authenticated key store; integrate with WebCrypto or extension secure storage for production.

## Development
- Run `cargo check` / `cargo test` (native tests)
- Use `wasm-pack build --target web` to generate `pkg/` for browser usage

## Publishing to crates.io
Before publishing, update `Cargo.toml` with your `repository` and `homepage` fields (if needed) and set an appropriate `authors` field.

Validate packaging locally:

```bash
cargo publish --dry-run
```

When ready, publish:

```bash
cargo publish
```

You can automate publishing on GitHub by setting a `CARGO_REGISTRY_TOKEN` secret and using the included `.github/workflows/publish.yml` which triggers on `v*` tags.

## License
MIT
