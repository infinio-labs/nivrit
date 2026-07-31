import { beforeAll, describe, expect, test } from 'vitest';
import { initCrypto } from './crypto';
import { assertAcceptablePassword, assessPassword } from './password-policy';

/**
 * The rules themselves are specified and tested in Rust
 * (`nivrit-crypto/src/password_policy.rs`). What is worth testing here is that
 * the browser actually reaches that implementation and gets the same answers —
 * if the binding broke, the UI would silently accept anything.
 */
describe('password policy binding', () => {
  beforeAll(async () => {
    await initCrypto();
  });

  test('rejects a password below the minimum length', () => {
    const result = assessPassword('short');
    expect(result.acceptable).toBe(false);
    expect(result.strength).toBe('weak');
    expect(result.message).toMatch(/at least 12 characters/i);
  });

  test('rejects an obvious password that is long enough', () => {
    expect(assessPassword('correcthorsebatterystaple').acceptable).toBe(false);
  });

  test('rejects a password built from the email local part', () => {
    expect(assessPassword('jsmith-and-more-text', 'jsmith@example.com').acceptable).toBe(false);
  });

  test('accepts a long passphrase and reports it strong', () => {
    const result = assessPassword('ferry unicorn glacier tuesday');
    expect(result.acceptable).toBe(true);
    expect(result.strength).toBe('strong');
  });

  test('accepts but nudges an adequate password', () => {
    const result = assessPassword('sp1nach-wagon');
    expect(result.acceptable).toBe(true);
    expect(result.strength).toBe('fair');
    expect(result.message).toBeTruthy();
  });

  test('treats an empty password as unacceptable without a message', () => {
    const result = assessPassword('');
    expect(result.acceptable).toBe(false);
    expect(result.message).toBeUndefined();
  });

  test('assertAcceptablePassword throws with a usable message', () => {
    expect(() => assertAcceptablePassword('short')).toThrow(/at least 12 characters/i);
    expect(() => assertAcceptablePassword('ferry unicorn glacier tuesday')).not.toThrow();
  });
});
