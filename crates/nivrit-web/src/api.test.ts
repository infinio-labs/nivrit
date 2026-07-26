import { afterEach, beforeEach, describe, expect, vi, test } from 'vitest';
import { SessionExpiredError, getSecret, login, setSecret } from './api';

describe('login', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('returns token and user on success', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ status: 'Success', token: 'abc123', user: { email: 'a@b.com' } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    ) as unknown as typeof globalThis.fetch;

    const result = await login('a@b.com', 'password');
    expect(result.status).toBe('Success');
    if (result.status === 'Success') {
      expect(result.token).toBe('abc123');
      expect(result.user.email).toBe('a@b.com');
    }
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  // 401 is the one status the UI must react to structurally rather than by
  // showing a message: the stored session is gone, so it signs the user out.
  test('maps 401 to SessionExpiredError', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response('unauthorized', { status: 401 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(login('a@b.com', 'password')).rejects.toBeInstanceOf(SessionExpiredError);
  });

  test('surfaces the server error message rather than a generic string', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ error: 'auth_hash must be 32 bytes' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    ) as unknown as typeof globalThis.fetch;

    await expect(login('a@b.com', 'password')).rejects.toThrow('auth_hash must be 32 bytes');
  });

  test('explains a 403 from the rate limiter', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response('', { status: 403 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(login('a@b.com', 'password')).rejects.toThrow(/too many attempts/i);
  });

  test('falls back to the generic message when the body is not JSON', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response('<html>502 Bad Gateway</html>', { status: 502 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(login('a@b.com', 'password')).rejects.toThrow('login failed');
  });
});

describe('setSecret', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('resolves on success', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response(null, { status: 201 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(
      setSecret('token', 'project', 'env', 'key', 'cipher', 'nonce')
    ).resolves.toBeUndefined();

    const call = (globalThis.fetch as any).mock.calls[0];
    const [url, init] = call;
    expect(url).toContain('/projects/project/secrets');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer token');
  });

  test('throws on non-ok response', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response('bad request', { status: 400 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(
      setSecret('token', 'project', 'env', 'key', 'cipher', 'nonce')
    ).rejects.toThrow('set secret failed');
  });
});

describe('getSecret', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('returns encrypted secret on success', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ encrypted_value: 'cipher', nonce: 'nonce' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    ) as unknown as typeof globalThis.fetch;

    const result = await getSecret('token', 'project', 'env', 'key');
    expect(result.encrypted_value).toBe('cipher');
    expect(result.nonce).toBe('nonce');

    const call = (globalThis.fetch as any).mock.calls[0];
    const [url] = call;
    expect(url).toContain('/projects/project/secrets/key');
    expect(url).toContain('environment_id=env');
  });

  test('throws on non-ok response', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response('not found', { status: 404 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(getSecret('token', 'project', 'env', 'key')).rejects.toThrow('get secret failed');
  });
});
