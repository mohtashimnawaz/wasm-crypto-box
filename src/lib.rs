//! wasm-crypto-box — Browser-safe WebAssembly wrapper for ed25519
//!
//! This crate exposes a tiny set of helpers for generating ed25519 keypairs
//! and performing signing/verification from JavaScript via `wasm-bindgen`.
//!
//! Example (JS):
//!
//! ```js
//! import init, { generate_keypair, sign, verify } from './pkg/wasm_crypto_box.js';
//! await init();
//! const { secretKey, publicKey } = generate_keypair();
//! const msg = new TextEncoder().encode('hello');
//! const sig = sign(msg, secretKey);
//! console.log('verified:', verify(msg, sig, publicKey));
//! ```

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use getrandom::getrandom;
use ed25519_dalek::{PublicKey, SecretKey, Signature, Verifier, ExpandedSecretKey};

#[wasm_bindgen]
pub fn generate_keypair() -> Result<js_sys::Object, JsValue> {
    // 32 bytes seed for an ed25519 secret key
    let mut seed = [0u8; 32];
    getrandom(&mut seed).map_err(|e| JsValue::from_str(&format!("rng error: {}", e)))?;

    let secret = SecretKey::from_bytes(&seed).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let public = PublicKey::from(&secret);

    let sk_arr = Uint8Array::from(&secret.to_bytes()[..]);
    let pk_arr = Uint8Array::from(&public.to_bytes()[..]);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("secretKey"), &sk_arr.into())?;
    js_sys::Reflect::set(&obj, &JsValue::from_str("publicKey"), &pk_arr.into())?;

    Ok(obj)
}

#[wasm_bindgen]
pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Uint8Array, JsValue> {
    if secret_key.len() != 32 {
        return Err(JsValue::from_str("secret_key must be 32 bytes"));
    }

    let secret = SecretKey::from_bytes(secret_key).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let public = PublicKey::from(&secret);
    let expanded = ExpandedSecretKey::from(&secret);

    let sig: Signature = expanded.sign(message, &public);
    Ok(Uint8Array::from(&sig.to_bytes()[..]))
}

#[wasm_bindgen]
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, JsValue> {
    if signature.len() != 64 {
        return Err(JsValue::from_str("signature must be 64 bytes"));
    }
    if public_key.len() != 32 {
        return Err(JsValue::from_str("public_key must be 32 bytes"));
    }

    let sig = Signature::from_bytes(signature).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let public = PublicKey::from_bytes(public_key).map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(public.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut seed = [0u8; 32];
        getrandom(&mut seed).expect("rng");
        let secret = SecretKey::from_bytes(&seed).unwrap();
        let public = PublicKey::from(&secret);
        let message = b"hello wasm";

        let expanded = ExpandedSecretKey::from(&secret);
        let sig = expanded.sign(message, &public);

        assert!(public.verify(message, &sig).is_ok());
    }
}
