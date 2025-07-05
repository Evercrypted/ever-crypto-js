#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

use ever_crypto::{
    XChaChaCrypto, XChaChaKey, XChaChaNonce,
    KyberCrypto, KyberPublicKey, KyberSecretKey,
    kyber::KyberCiphertext,
    CryptoError,
};

// Error handling helper function
fn crypto_error_to_napi(err: CryptoError) -> napi::Error {
    napi::Error::from_reason(err.to_string())
}

// Constants
#[napi]
pub const XCHACHA_KEY_SIZE: u32 = 32;

#[napi]
pub const XCHACHA_NONCE_SIZE: u32 = 24;

#[napi]
pub const XCHACHA_MAC_SIZE: u32 = 16;

#[napi]
pub const KYBER_PUBLIC_KEY_SIZE: u32 = 1568;

#[napi]
pub const KYBER_SECRET_KEY_SIZE: u32 = 3168;

#[napi]
pub const KYBER_CIPHERTEXT_SIZE: u32 = 1568;

#[napi]
pub const KYBER_SHARED_SECRET_SIZE: u32 = 32;

// XChaCha20Poly1305 functions

/// Generate a random 32-byte encryption key for XChaCha20Poly1305
#[napi]
pub fn generate_xchacha_key() -> Buffer {
    let key = XChaChaKey::generate();
    Buffer::from(key.as_bytes().to_vec())
}

/// Generate a random 24-byte nonce for XChaCha20Poly1305
#[napi]
pub fn generate_xchacha_nonce() -> Buffer {
    let nonce = XChaChaNonce::generate();
    Buffer::from(nonce.as_bytes().to_vec())
}

/// Encrypt plaintext with XChaCha20Poly1305 authenticated encryption
#[napi]
pub fn xchacha_encrypt(
    key: Buffer,
    nonce: Buffer,
    plaintext: Buffer,
    associated_data: Option<Buffer>,
) -> Result<Buffer> {
    // Validate inputs
    if key.len() != XCHACHA_KEY_SIZE as usize {
        return Err(napi::Error::from_reason(format!(
            "Invalid key length: expected {}, got {}",
            XCHACHA_KEY_SIZE,
            key.len()
        )));
    }

    if nonce.len() != XCHACHA_NONCE_SIZE as usize {
        return Err(napi::Error::from_reason(format!(
            "Invalid nonce length: expected {}, got {}",
            XCHACHA_NONCE_SIZE,
            nonce.len()
        )));
    }

    // Convert to ever-crypto types
    let key = XChaChaKey::from_bytes(&key).map_err(crypto_error_to_napi)?;
    let nonce = XChaChaNonce::from_bytes(&nonce).map_err(crypto_error_to_napi)?;

    // Handle associated data
    let ad = associated_data.as_ref().map(|ad| ad.as_ref());

    // Encrypt
    let ciphertext = XChaChaCrypto::encrypt(&key, &nonce, &plaintext, ad).map_err(crypto_error_to_napi)?;

    Ok(Buffer::from(ciphertext))
}

/// Decrypt ciphertext with XChaCha20Poly1305 authenticated decryption
#[napi]
pub fn xchacha_decrypt(
    key: Buffer,
    nonce: Buffer,
    ciphertext: Buffer,
    associated_data: Option<Buffer>,
) -> Result<Buffer> {
    // Validate inputs
    if key.len() != XCHACHA_KEY_SIZE as usize {
        return Err(napi::Error::from_reason(format!(
            "Invalid key length: expected {}, got {}",
            XCHACHA_KEY_SIZE,
            key.len()
        )));
    }

    if nonce.len() != XCHACHA_NONCE_SIZE as usize {
        return Err(napi::Error::from_reason(format!(
            "Invalid nonce length: expected {}, got {}",
            XCHACHA_NONCE_SIZE,
            nonce.len()
        )));
    }

    // Convert to ever-crypto types
    let key = XChaChaKey::from_bytes(&key).map_err(crypto_error_to_napi)?;
    let nonce = XChaChaNonce::from_bytes(&nonce).map_err(crypto_error_to_napi)?;

    // Handle associated data
    let ad = associated_data.as_ref().map(|ad| ad.as_ref());

    // Decrypt
    let plaintext = XChaChaCrypto::decrypt(&key, &nonce, &ciphertext, ad).map_err(crypto_error_to_napi)?;

    Ok(Buffer::from(plaintext))
}

// Kyber1024 functions

/// Kyber1024 key pair structure for JavaScript
#[napi(object)]
pub struct KyberKeyPair {
    pub public_key: Buffer,
    pub secret_key: Buffer,
}

/// Kyber1024 encapsulation result for JavaScript
#[napi(object)]
pub struct KyberEncapsulation {
    pub ciphertext: Buffer,
    pub shared_secret: Buffer,
}

/// Generate a new Kyber1024 key pair for key encapsulation
#[napi]
pub fn generate_kyber_keypair() -> KyberKeyPair {
    let keypair = KyberCrypto::generate_keypair();
    KyberKeyPair {
        public_key: Buffer::from(keypair.public_key.as_bytes().to_vec()),
        secret_key: Buffer::from(keypair.secret_key.as_bytes().to_vec()),
    }
}

/// Encapsulate a shared secret using a Kyber1024 public key
#[napi]
pub fn kyber_encapsulate(public_key: Buffer) -> Result<KyberEncapsulation> {
    // Validate public key length
    if public_key.len() != KYBER_PUBLIC_KEY_SIZE as usize {
        return Err(napi::Error::from_reason(format!(
            "Invalid public key length: expected {}, got {}",
            KYBER_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    // Convert to ever-crypto type
    let public_key = KyberPublicKey::from_bytes(&public_key).map_err(crypto_error_to_napi)?;

    // Encapsulate
    let (shared_secret, ciphertext) = KyberCrypto::encapsulate(&public_key);

    Ok(KyberEncapsulation {
        ciphertext: Buffer::from(ciphertext.as_bytes().to_vec()),
        shared_secret: Buffer::from(shared_secret.as_bytes().to_vec()),
    })
}

/// Decapsulate the shared secret using a Kyber1024 secret key and ciphertext
#[napi]
pub fn kyber_decapsulate(secret_key: Buffer, ciphertext: Buffer) -> Result<Buffer> {
    // Validate secret key length
    if secret_key.len() != KYBER_SECRET_KEY_SIZE as usize {
        return Err(napi::Error::from_reason(format!(
            "Invalid secret key length: expected {}, got {}",
            KYBER_SECRET_KEY_SIZE,
            secret_key.len()
        )));
    }

    // Validate ciphertext length
    if ciphertext.len() != KYBER_CIPHERTEXT_SIZE as usize {
        return Err(napi::Error::from_reason(format!(
            "Invalid ciphertext length: expected {}, got {}",
            KYBER_CIPHERTEXT_SIZE,
            ciphertext.len()
        )));
    }

    // Convert to ever-crypto types
    let secret_key = KyberSecretKey::from_bytes(&secret_key).map_err(crypto_error_to_napi)?;
    let ciphertext = KyberCiphertext::from_bytes(&ciphertext).map_err(crypto_error_to_napi)?;

    // Decapsulate
    let shared_secret = KyberCrypto::decapsulate(&ciphertext, &secret_key);

    Ok(Buffer::from(shared_secret.as_bytes().to_vec()))
} 