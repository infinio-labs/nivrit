import { describe, expect, test } from 'vitest';
import {
  decryptPrivateKey,
  decryptValue,
  decapsulateProjectKey,
  encapsulateProjectKey,
  encryptValue,
  generateRegistrationMaterial,
  generateUserKeypair,
  initCrypto,
  resetPasswordMaterial,
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

describe('password reset', () => {
  // Registration + reset + two decrypts is four Argon2id runs in WASM -
  // slower than the default 5s test timeout allows.
  test(
    're-wraps the same private key under the new password',
    async () => {
      const email = 'reset-test@example.com';
      const reg = await generateRegistrationMaterial('old password', email);
      const originalPrivateKey = await decryptPrivateKey(
        reg.encrypted_private_key,
        reg.private_key_nonce,
        'old password'
      );

      const reset = await resetPasswordMaterial(
        reg.encrypted_private_key_recovery,
        reg.private_key_recovery_nonce,
        reg.recovery_code,
        email,
        'new password'
      );

      const recoveredPrivateKey = await decryptPrivateKey(
        reset.encrypted_private_key,
        reset.private_key_nonce,
        'new password'
      );
      expect(recoveredPrivateKey).toBe(originalPrivateKey);
    },
    20000
  );

  // Chains three password resets, each running Argon2id in WASM - slower than
  // the default 5s test timeout allows.
  test(
    'mints a fresh recovery code and retires the old one',
    async () => {
      const email = 'reset-test-2@example.com';
      const reg = await generateRegistrationMaterial('old password', email);

      const reset = await resetPasswordMaterial(
        reg.encrypted_private_key_recovery,
        reg.private_key_recovery_nonce,
        reg.recovery_code,
        email,
        'new password'
      );
      expect(reset.recovery_code).not.toBe(reg.recovery_code);
      expect(reset.encrypted_private_key_recovery).not.toBe(reg.encrypted_private_key_recovery);

      // The new recovery blob must actually work with the new code - chain a
      // second reset through it as the check.
      const secondReset = await resetPasswordMaterial(
        reset.encrypted_private_key_recovery,
        reset.private_key_recovery_nonce,
        reset.recovery_code,
        email,
        'third password'
      );
      const originalPrivateKey = await decryptPrivateKey(
        reg.encrypted_private_key,
        reg.private_key_nonce,
        'old password'
      );
      const finalPrivateKey = await decryptPrivateKey(
        secondReset.encrypted_private_key,
        secondReset.private_key_nonce,
        'third password'
      );
      expect(finalPrivateKey).toBe(originalPrivateKey);

      // The old recovery code must not unlock the new blob.
      await expect(
        resetPasswordMaterial(
          reset.encrypted_private_key_recovery,
          reset.private_key_recovery_nonce,
          reg.recovery_code,
          email,
          'nope'
        )
      ).rejects.toThrow();
    },
    20000
  );
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
