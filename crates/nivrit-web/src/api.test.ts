import { afterEach, beforeEach, describe, expect, vi, test } from 'vitest';
import {
  SessionExpiredError,
  getSecret,
  listProjectKeyVersions,
  listProjectMembers,
  login,
  rotateProjectKey,
  setSecret,
} from './api';

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

  // ADR 0008: a secret write must say which project-key version encrypted it.
  test('includes project_key_version in the request body', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response(null, { status: 201 }))
    ) as unknown as typeof globalThis.fetch;

    await setSecret('token', 'project', 'env', 'key', 'cipher', 'nonce', null, 2);

    const call = (globalThis.fetch as any).mock.calls[0];
    const [, init] = call;
    const body = JSON.parse(init.body);
    expect(body.project_key_version).toBe(2);
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

  // ADR 0008: the caller needs to know which key version to decrypt with.
  test('returns project_key_version', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({ encrypted_value: 'cipher', nonce: 'nonce', project_key_version: 3 }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      )
    ) as unknown as typeof globalThis.fetch;

    const result = await getSecret('token', 'project', 'env', 'key');
    expect(result.project_key_version).toBe(3);
  });
});

// ADR 0008: versioned project keys

describe('listProjectMembers', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('returns the roster', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify([{ user_id: 'u1', public_key: 'pk1' }]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    ) as unknown as typeof globalThis.fetch;

    const members = await listProjectMembers('token', 'project');
    expect(members).toEqual([{ user_id: 'u1', public_key: 'pk1' }]);

    const [url] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toContain('/projects/project/members');
  });

  test('throws on non-ok response', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response('forbidden', { status: 403 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(listProjectMembers('token', 'project')).rejects.toThrow();
  });
});

describe('listProjectKeyVersions', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('returns every version the caller holds', async () => {
    const versions = [
      { version: 1, encrypted_project_key: 'a', project_key_nonce: '', project_key_algorithm: 'x' },
      { version: 2, encrypted_project_key: 'b', project_key_nonce: '', project_key_algorithm: 'x' },
    ];
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify(versions), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    ) as unknown as typeof globalThis.fetch;

    const result = await listProjectKeyVersions('token', 'project');
    expect(result).toHaveLength(2);
    expect(result.map((v) => v.version)).toEqual([1, 2]);

    const [url] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toContain('/projects/project/key-versions');
  });
});

describe('rotateProjectKey', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test('posts grants and returns the new version', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ version: 2 }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
    ) as unknown as typeof globalThis.fetch;

    const grants = [
      {
        user_id: 'u1',
        encrypted_project_key: 'enc',
        project_key_nonce: '',
        project_key_algorithm: 'x',
      },
    ];
    const result = await rotateProjectKey('token', 'project', grants);
    expect(result.version).toBe(2);

    const [url, init] = (globalThis.fetch as any).mock.calls[0];
    expect(url).toContain('/projects/project/rotate-key');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body).grants).toEqual(grants);
  });

  test('throws when the server rejects a mismatched roster', async () => {
    globalThis.fetch = vi.fn(() =>
      Promise.resolve(new Response(JSON.stringify({ error: 'roster mismatch' }), { status: 400 }))
    ) as unknown as typeof globalThis.fetch;

    await expect(rotateProjectKey('token', 'project', [])).rejects.toThrow('roster mismatch');
  });
});
