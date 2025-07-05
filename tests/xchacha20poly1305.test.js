const {
  XCHACHA_KEY_SIZE,
  XCHACHA_NONCE_SIZE,
  XCHACHA_MAC_SIZE,
  generateXchachaKey,
  generateXchachaNonce,
  xchachaEncrypt,
  xchachaDecrypt
} = require('../index.js');

describe('XChaCha20Poly1305', () => {
  describe('Constants', () => {
    test('should have correct key size', () => {
      expect(XCHACHA_KEY_SIZE).toBe(32);
    });

    test('should have correct nonce size', () => {
      expect(XCHACHA_NONCE_SIZE).toBe(24);
    });

    test('should have correct MAC size', () => {
      expect(XCHACHA_MAC_SIZE).toBe(16);
    });
  });

  describe('Key Generation', () => {
    test('should generate key of correct size', () => {
      const key = generateXchachaKey();
      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(XCHACHA_KEY_SIZE);
    });

    test('should generate different keys', () => {
      const key1 = generateXchachaKey();
      const key2 = generateXchachaKey();
      expect(key1).not.toEqual(key2);
    });
  });

  describe('Nonce Generation', () => {
    test('should generate nonce of correct size', () => {
      const nonce = generateXchachaNonce();
      expect(nonce).toBeInstanceOf(Buffer);
      expect(nonce.length).toBe(XCHACHA_NONCE_SIZE);
    });

    test('should generate different nonces', () => {
      const nonce1 = generateXchachaNonce();
      const nonce2 = generateXchachaNonce();
      expect(nonce1).not.toEqual(nonce2);
    });
  });

  describe('Encryption', () => {
    test('should encrypt successfully', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Hello, World!');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext);
      expect(ciphertext).toBeInstanceOf(Buffer);
      expect(ciphertext.length).toBe(plaintext.length + XCHACHA_MAC_SIZE); // includes MAC
    });

    test('should encrypt with associated data', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Hello, World!');
      const associatedData = Buffer.from('metadata');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext, associatedData);
      expect(ciphertext).toBeInstanceOf(Buffer);
      expect(ciphertext.length).toBe(plaintext.length + XCHACHA_MAC_SIZE);
    });

    test('should throw error for invalid key size', () => {
      const invalidKey = Buffer.alloc(16); // Wrong size
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Hello, World!');

      expect(() => {
        xchachaEncrypt(invalidKey, nonce, plaintext);
      }).toThrow('Invalid key length');
    });

    test('should throw error for invalid nonce size', () => {
      const key = generateXchachaKey();
      const invalidNonce = Buffer.alloc(12); // Wrong size
      const plaintext = Buffer.from('Hello, World!');

      expect(() => {
        xchachaEncrypt(key, invalidNonce, plaintext);
      }).toThrow('Invalid nonce length');
    });
  });

  describe('Decryption', () => {
    test('should decrypt successfully', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Hello, World!');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext);
      const decrypted = xchachaDecrypt(key, nonce, ciphertext);

      expect(decrypted).toEqual(plaintext);
    });

    test('should decrypt with associated data', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Hello, World!');
      const associatedData = Buffer.from('metadata');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext, associatedData);
      const decrypted = xchachaDecrypt(key, nonce, ciphertext, associatedData);

      expect(decrypted).toEqual(plaintext);
    });

    test('should fail with wrong associated data', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Hello, World!');
      const associatedData = Buffer.from('metadata');
      const wrongAssociatedData = Buffer.from('wrong');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext, associatedData);

      expect(() => {
        xchachaDecrypt(key, nonce, ciphertext, wrongAssociatedData);
      }).toThrow();
    });

    test('should throw error for invalid key size', () => {
      const invalidKey = Buffer.alloc(16); // Wrong size
      const nonce = generateXchachaNonce();
      const ciphertext = Buffer.alloc(32);

      expect(() => {
        xchachaDecrypt(invalidKey, nonce, ciphertext);
      }).toThrow('Invalid key length');
    });

    test('should throw error for invalid nonce size', () => {
      const key = generateXchachaKey();
      const invalidNonce = Buffer.alloc(12); // Wrong size
      const ciphertext = Buffer.alloc(32);

      expect(() => {
        xchachaDecrypt(key, invalidNonce, ciphertext);
      }).toThrow('Invalid nonce length');
    });
  });

  describe('MAC Verification', () => {
    test('should fail with tampered ciphertext', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Secret message');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext);
      
      // Tamper with the ciphertext
      const tamperedCiphertext = Buffer.from(ciphertext);
      tamperedCiphertext[0] = tamperedCiphertext[0] ^ 0x01;

      expect(() => {
        xchachaDecrypt(key, nonce, tamperedCiphertext);
      }).toThrow();
    });

    test('should fail with wrong key', () => {
      const key1 = generateXchachaKey();
      const key2 = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Secret message');

      const ciphertext = xchachaEncrypt(key1, nonce, plaintext);

      expect(() => {
        xchachaDecrypt(key2, nonce, ciphertext);
      }).toThrow();
    });

    test('should fail with wrong nonce', () => {
      const key = generateXchachaKey();
      const nonce1 = generateXchachaNonce();
      const nonce2 = generateXchachaNonce();
      const plaintext = Buffer.from('Secret message');

      const ciphertext = xchachaEncrypt(key, nonce1, plaintext);

      expect(() => {
        xchachaDecrypt(key, nonce2, ciphertext);
      }).toThrow();
    });
  });

  describe('Round-trip encryption/decryption', () => {
    test('should handle empty message', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.alloc(0);

      const ciphertext = xchachaEncrypt(key, nonce, plaintext);
      const decrypted = xchachaDecrypt(key, nonce, ciphertext);

      expect(decrypted).toEqual(plaintext);
    });

    test('should handle large message', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.alloc(10000, 'A');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext);
      const decrypted = xchachaDecrypt(key, nonce, ciphertext);

      expect(decrypted).toEqual(plaintext);
    });

    test('should handle unicode text', () => {
      const key = generateXchachaKey();
      const nonce = generateXchachaNonce();
      const plaintext = Buffer.from('Hello, 世界! 🌍 Привет мир!', 'utf8');

      const ciphertext = xchachaEncrypt(key, nonce, plaintext);
      const decrypted = xchachaDecrypt(key, nonce, ciphertext);

      expect(decrypted).toEqual(plaintext);
      expect(decrypted.toString('utf8')).toBe('Hello, 世界! 🌍 Привет мир!');
    });
  });
}); 