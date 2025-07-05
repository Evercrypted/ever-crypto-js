# Ever-Crypto-JS

> Node.js native addon for the ever-crypto library - Post-quantum cryptography made simple

[![npm version](https://badge.fury.io/js/ever-crypto-js.svg)](https://badge.fury.io/js/ever-crypto-js)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Ever-Crypto-JS is a Node.js native addon that provides JavaScript bindings for the [ever-crypto](https://crates.io/crates/ever-crypto) Rust library, offering high-performance post-quantum cryptographic algorithms.

### Features

- **XChaCha20Poly1305** - Authenticated encryption with extended nonces
- **Kyber1024** - Post-quantum key encapsulation mechanism
- **Native Performance** - Rust-powered native addon for maximum speed
- **Memory Safe** - Built with Rust's memory safety guarantees
- **Cross-platform** - Works on Linux, macOS, and Windows
- **TypeScript** - Full type definitions included

## Installation

```bash
npm install ever-crypto-js
```

### Requirements

- **Node.js**: 10.0.0 or later
- **Platform**: Linux (x64, ARM64), macOS (x64, ARM64), Windows (x64, ARM64)

## Quick Start

```javascript
const {
  generateXchachaKey,
  generateXchachaNonce,
  xchachaEncrypt,
  xchachaDecrypt,
  generateKyberKeypair,
  kyberEncapsulate,
  kyberDecapsulate
} = require('ever-crypto-js');

// Generate encryption key and nonce
const key = generateXchachaKey();
const nonce = generateXchachaNonce();

// Encrypt a message
const plaintext = Buffer.from('Hello, post-quantum world!');
const ciphertext = xchachaEncrypt(key, nonce, plaintext);

// Decrypt the message
const decrypted = xchachaDecrypt(key, nonce, ciphertext);
console.log(decrypted.toString()); // "Hello, post-quantum world!"
```

## API Reference

### Constants

```javascript
const {
  XCHACHA_KEY_SIZE,      // 32 bytes
  XCHACHA_NONCE_SIZE,    // 24 bytes
  XCHACHA_MAC_SIZE,      // 16 bytes
  KYBER_PUBLIC_KEY_SIZE, // 1568 bytes
  KYBER_SECRET_KEY_SIZE, // 3168 bytes
  KYBER_CIPHERTEXT_SIZE, // 1568 bytes
  KYBER_SHARED_SECRET_SIZE // 32 bytes
} = require('ever-crypto-js');
```

### XChaCha20Poly1305 - Authenticated Encryption

#### `generateXchachaKey(): Buffer`

Generate a random 32-byte encryption key.

```javascript
const key = generateXchachaKey();
console.log(key.length); // 32
```

#### `generateXchachaNonce(): Buffer`

Generate a random 24-byte nonce.

```javascript
const nonce = generateXchachaNonce();
console.log(nonce.length); // 24
```

#### `xchachaEncrypt(key, nonce, plaintext, associatedData?): Buffer`

Encrypt plaintext with authenticated encryption.

- `key` - 32-byte encryption key (Buffer)
- `nonce` - 24-byte nonce (Buffer)
- `plaintext` - Data to encrypt (Buffer)
- `associatedData` - Optional associated data for authentication (Buffer)

Returns encrypted ciphertext with authentication tag.

```javascript
const key = generateXchachaKey();
const nonce = generateXchachaNonce();
const plaintext = Buffer.from('Secret message');
const associatedData = Buffer.from('metadata');

const ciphertext = xchachaEncrypt(key, nonce, plaintext, associatedData);
```

#### `xchachaDecrypt(key, nonce, ciphertext, associatedData?): Buffer`

Decrypt ciphertext with authenticated decryption.

- `key` - 32-byte encryption key (Buffer)
- `nonce` - 24-byte nonce (Buffer)
- `ciphertext` - Data to decrypt (Buffer)
- `associatedData` - Optional associated data for authentication (Buffer)

Returns decrypted plaintext.

```javascript
const decrypted = xchachaDecrypt(key, nonce, ciphertext, associatedData);
```

### Kyber1024 - Post-Quantum Key Exchange

#### `generateKyberKeypair(): KyberKeyPair`

Generate a new key pair for key encapsulation.

```javascript
const keyPair = generateKyberKeypair();
// keyPair.publicKey: Buffer (1568 bytes)
// keyPair.secretKey: Buffer (3168 bytes)
```

#### `kyberEncapsulate(publicKey): KyberEncapsulation`

Encapsulate a shared secret using a public key.

- `publicKey` - 1568-byte public key (Buffer)

Returns an object with:
- `ciphertext` - 1568-byte ciphertext (Buffer)
- `sharedSecret` - 32-byte shared secret (Buffer)

```javascript
const encapsulation = kyberEncapsulate(keyPair.publicKey);
// encapsulation.ciphertext: Buffer (1568 bytes)
// encapsulation.sharedSecret: Buffer (32 bytes)
```

#### `kyberDecapsulate(secretKey, ciphertext): Buffer`

Decapsulate the shared secret using a secret key and ciphertext.

- `secretKey` - 3168-byte secret key (Buffer)
- `ciphertext` - 1568-byte ciphertext (Buffer)

Returns 32-byte shared secret (Buffer).

```javascript
const sharedSecret = kyberDecapsulate(keyPair.secretKey, encapsulation.ciphertext);
// sharedSecret: Buffer (32 bytes)
```

## Complete Example: Post-Quantum Secure Communication

```javascript
const {
  generateXchachaKey,
  generateXchachaNonce,
  xchachaEncrypt,
  xchachaDecrypt,
  generateKyberKeypair,
  kyberEncapsulate,
  kyberDecapsulate
} = require('ever-crypto-js');

// Alice and Bob scenario
function secureCommuncation() {
  // 1. Alice generates a key pair
  const aliceKeyPair = generateKyberKeypair();
  
  // 2. Bob wants to send a message to Alice
  const message = Buffer.from('Secret message for Alice');
  
  // 3. Bob encapsulates a shared secret using Alice's public key
  const encapsulation = kyberEncapsulate(aliceKeyPair.publicKey);
  
  // 4. Bob encrypts the message using the shared secret
  const nonce = generateXchachaNonce();
  const ciphertext = xchachaEncrypt(
    encapsulation.sharedSecret,
    nonce,
    message
  );
  
  // 5. Bob sends to Alice: encapsulation.ciphertext, nonce, ciphertext
  
  // 6. Alice decapsulates the shared secret
  const aliceSharedSecret = kyberDecapsulate(
    aliceKeyPair.secretKey,
    encapsulation.ciphertext
  );
  
  // 7. Alice decrypts the message
  const decryptedMessage = xchachaDecrypt(
    aliceSharedSecret,
    nonce,
    ciphertext
  );
  
  console.log('Decrypted message:', decryptedMessage.toString());
  // Output: "Secret message for Alice"
}

secureCommuncation();
```

## TypeScript Support

The package includes full TypeScript definitions:

```typescript
import {
  generateXchachaKey,
  xchachaEncrypt,
  generateKyberKeypair,
  KyberKeyPair,
  KyberEncapsulation
} from 'ever-crypto-js';

const key: Buffer = generateXchachaKey();
const keyPair: KyberKeyPair = generateKyberKeypair();
```

## Security Considerations

- **Quantum Resistance**: Kyber1024 is designed to be secure against both classical and quantum attacks
- **Key Management**: Always generate keys using the provided functions and store them securely
- **Nonce Reuse**: Never reuse nonces with the same key in XChaCha20Poly1305
- **Associated Data**: Use associated data for additional authentication context when needed
- **Memory Safety**: The underlying Rust implementation provides memory safety guarantees
- **MAC Verification**: XChaCha20Poly1305 automatically includes and verifies a 16-byte Poly1305 MAC

## Performance

The library uses a native Rust addon for high-performance cryptographic operations:

- **XChaCha20Poly1305**: ~500 MB/s encryption/decryption throughput
- **Kyber1024**: ~5000 key exchanges per second
- **Native Code**: Near-native performance with minimal JavaScript overhead

## Building from Source

```bash
# Clone the repository
git clone https://github.com/evercrypto/ever-crypto-js.git
cd ever-crypto-js

# Install dependencies
npm install

# Build the native addon
npm run build

# Run tests
npm test
```

### Requirements for Building

- **Rust**: 1.70.0 or later
- **Node.js**: 16.0.0 or later for development
- **Python**: 3.7+ (for node-gyp)
- **C++ Compiler**: Platform-appropriate C++ build tools

## Testing

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [ever-crypto](https://crates.io/crates/ever-crypto) - Original Rust library
- [flutter_ever_crypto](https://pub.dev/packages/flutter_ever_crypto) - Flutter plugin

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for details about changes and updates.

## Support

- 📧 Email: support@evercrypto.dev
- 🐛 Issues: [GitHub Issues](https://github.com/evercrypto/ever-crypto-js/issues)
- 📖 Docs: [Documentation](https://github.com/evercrypto/ever-crypto-js/wiki) 