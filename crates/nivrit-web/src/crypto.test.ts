import { describe, expect, test } from 'bun:test';
import {
  decryptPrivateKey,
  decryptValue,
  decapsulateProjectKey,
  encapsulateProjectKey,
  encryptValue,
  generateUserKeypair,
  initCrypto,
} from './crypto';

describe('WASM crypto', () => {
  test('initCrypto loads the WASM module', async () => {
    await expect(initCrypto()).resolves.toBeUndefined();
  });

  test('generateUserKeypair returns expected fields', async () => {
    const kp = await generateUserKeypair('correct horse battery staple');
    expect(kp.public_key).toBeTruthy();
    expect(kp.encrypted_private_key).toBeTruthy();
    expect(kp.private_key_nonce).toBeTruthy();
    expect(kp.private_key_algorithm).toBe('aes256gcm-v1');
  });

  test('decryptPrivateKey recovers the private key', async () => {
    const kp = await generateUserKeypair('correct horse battery staple');
    const recovered = await decryptPrivateKey(
      kp.encrypted_private_key,
      kp.private_key_nonce,
      'correct horse battery staple'
    );
    expect(recovered).toBeTruthy();
    expect(typeof recovered).toBe('string');
  });

  test('decryptPrivateKey fails with wrong password', async () => {
    const kp = await generateUserKeypair('correct horse battery staple');
    await expect(
      decryptPrivateKey(kp.encrypted_private_key, kp.private_key_nonce, 'wrong password')
    ).rejects.toThrow();
  });
});

describe('hybrid key encapsulation', () => {
  test('encapsulate/decapsulate roundtrip', async () => {
    const owner = await generateUserKeypair('owner password');
    const privateKey = await decryptPrivateKey(
      owner.encrypted_private_key,
      owner.private_key_nonce,
      'owner password'
    );
    const projectKey = crypto.getRandomValues(new Uint8Array(32));
    const projectKeyB64 = btoa(String.fromCharCode(...projectKey));

    const encapsulated = await encapsulateProjectKey(projectKeyB64, owner.public_key);
    expect(encapsulated.suite).toBe('hybrid_x25519_ml_kem_768_aes256gcm_v1');
    expect(encapsulated.ciphertext.length).toBeGreaterThan(0);

    const recovered = await decapsulateProjectKey(encapsulated, privateKey);
    expect(recovered).toBe(projectKeyB64);
  });
});

describe('AES-GCM encryption', () => {
  test('encrypt/decrypt roundtrip', async () => {
    const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const plaintext = 'hello post-quantum world';
    const { ciphertext, nonce } = await encryptValue(plaintext, key);
    expect(ciphertext).not.toBe('');
    expect(nonce).not.toBe('');
    expect(ciphertext).not.toBe(plaintext);
    const decrypted = await decryptValue(ciphertext, nonce, key);
    expect(decrypted).toBe(plaintext);
  });

  test('decryption fails with wrong key', async () => {
    const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const otherKey = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const { ciphertext, nonce } = await encryptValue('secret', key);
    await expect(decryptValue(ciphertext, nonce, otherKey)).rejects.toThrow();
  });

  test('decryption fails with tampered ciphertext', async () => {
    const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const { ciphertext, nonce } = await encryptValue('secret', key);
    const tampered = btoa(atob(ciphertext) + 'x');
    await expect(decryptValue(tampered, nonce, key)).rejects.toThrow();
  });

  test('nonces are unique', async () => {
    const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const nonces = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const { nonce } = await encryptValue('x', key);
      expect(nonces.has(nonce)).toBe(false);
      nonces.add(nonce);
    }
  });
});
