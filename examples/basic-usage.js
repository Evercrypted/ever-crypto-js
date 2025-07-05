const {
  generateXchachaKey,
  generateXchachaNonce,
  xchachaEncrypt,
  xchachaDecrypt,
  generateKyberKeypair,
  kyberEncapsulate,
  kyberDecapsulate
} = require('../index.js');

console.log('🔐 Ever-Crypto-JS Basic Usage Example\n');

// Example 1: Simple XChaCha20Poly1305 encryption
console.log('1. Simple Encryption with XChaCha20Poly1305:');
const key = generateXchachaKey();
const nonce = generateXchachaNonce();
const message = Buffer.from('Hello, post-quantum world!');

console.log(`   Original: "${message.toString()}"`);

const ciphertext = xchachaEncrypt(key, nonce, message);
console.log(`   Encrypted: ${ciphertext.length} bytes`);

const decrypted = xchachaDecrypt(key, nonce, ciphertext);
console.log(`   Decrypted: "${decrypted.toString()}"`);
console.log(`   Match: ${message.equals(decrypted) ? '✅' : '❌'}\n`);

// Example 2: Kyber1024 key exchange
console.log('2. Post-Quantum Key Exchange with Kyber1024:');
const keyPair = generateKyberKeypair();
console.log(`   Generated key pair (pub: ${keyPair.publicKey.length}, sec: ${keyPair.secretKey.length} bytes)`);

const encapsulation = kyberEncapsulate(keyPair.publicKey);
console.log(`   Encapsulated shared secret (${encapsulation.sharedSecret.length} bytes)`);

const decapsulatedSecret = kyberDecapsulate(keyPair.secretKey, encapsulation.ciphertext);
console.log(`   Decapsulated shared secret (${decapsulatedSecret.length} bytes)`);
console.log(`   Secrets match: ${encapsulation.sharedSecret.equals(decapsulatedSecret) ? '✅' : '❌'}\n`);

// Example 3: Complete secure communication
console.log('3. Complete Post-Quantum Secure Communication:');
console.log('   Alice generates key pair...');
const aliceKeyPair = generateKyberKeypair();

console.log('   Bob wants to send a secret message to Alice...');
const bobMessage = Buffer.from('This is a confidential message from Bob!');

console.log('   Bob encapsulates shared secret using Alice\'s public key...');
const bobEncapsulation = kyberEncapsulate(aliceKeyPair.publicKey);

console.log('   Bob encrypts message using shared secret...');
const messageNonce = generateXchachaNonce();
const encryptedMessage = xchachaEncrypt(bobEncapsulation.sharedSecret, messageNonce, bobMessage);

console.log('   Alice receives the encrypted data and decapsulates shared secret...');
const aliceSharedSecret = kyberDecapsulate(aliceKeyPair.secretKey, bobEncapsulation.ciphertext);

console.log('   Alice decrypts Bob\'s message...');
const aliceDecryptedMessage = xchachaDecrypt(aliceSharedSecret, messageNonce, encryptedMessage);

console.log(`   Alice reads: "${aliceDecryptedMessage.toString()}"`);
console.log(`   Communication successful: ${bobMessage.equals(aliceDecryptedMessage) ? '✅' : '❌'}\n`);

console.log('🎉 All examples completed successfully!'); 