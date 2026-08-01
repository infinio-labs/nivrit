import { afterEach, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest';
import { encapsulateProjectKey, generateUserKeypair, initCrypto } from './crypto';
import {
  clearSession,
  getEncryptedSecret,
  getSession,
  loginSession,
  rotateProjectKeySession,
} from './session';

const PASSWORD = 'correct horse battery staple';
const PROJECT_ID = 'proj-1';

function randomKeyB64(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

/** Mock fetch that serves whatever URL/method combination a test registers. */
function mockFetch(handlers: Record<string, unknown>) {
  return vi.fn((url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET';
    const key = `${method} ${new URL(url).pathname}`;
    const body = handlers[key];
    if (body === undefined) {
      throw new Error(`unmocked request: ${key}`);
    }
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );
  }) as unknown as typeof globalThis.fetch;
}

describe('versioned project keys (ADR 0008)', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeAll(async () => {
    await initCrypto();
  });

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    clearSession();
  });

  test('buildSession recovers every granted version, not just the latest', async () => {
    const keypair = await generateUserKeypair(PASSWORD);

    const projectKeyV1 = randomKeyB64();
    const projectKeyV2 = randomKeyB64();
    const encapsulatedV1 = await encapsulateProjectKey(projectKeyV1, keypair.public_key);
    const encapsulatedV2 = await encapsulateProjectKey(projectKeyV2, keypair.public_key);

    globalThis.fetch = mockFetch({
      'POST /auth/login': {
        status: 'Success',
        token: 'tok',
        user: {
          id: 'user-1',
          email: 'a@example.com',
          public_key: keypair.public_key,
          encrypted_private_key: keypair.encrypted_private_key,
          private_key_nonce: keypair.private_key_nonce,
          private_key_algorithm: keypair.private_key_algorithm,
        },
      },
      'GET /users/me/projects': [{ project_id: PROJECT_ID, role: 'admin' }],
      [`GET /projects/${PROJECT_ID}/key-versions`]: [
        {
          version: 1,
          encrypted_project_key: btoa(JSON.stringify(encapsulatedV1)),
          project_key_nonce: '',
          project_key_algorithm: encapsulatedV1.suite,
        },
        {
          version: 2,
          encrypted_project_key: btoa(JSON.stringify(encapsulatedV2)),
          project_key_nonce: '',
          project_key_algorithm: encapsulatedV2.suite,
        },
      ],
    });

    await loginSession('a@example.com', PASSWORD);
    const s = getSession();
    expect(s).not.toBeNull();
    const state = s!.projects.get(PROJECT_ID);
    expect(state).toBeDefined();
    expect(state!.currentVersion).toBe(2);
    expect(state!.versions.size).toBe(2);
    expect(state!.versions.get(1)).toBe(projectKeyV1);
    expect(state!.versions.get(2)).toBe(projectKeyV2);
  });

  test('getEncryptedSecret decrypts with the version the server says the secret used, not the current one', async () => {
    const keypair = await generateUserKeypair(PASSWORD);
    const projectKeyV1 = randomKeyB64();
    const projectKeyV2 = randomKeyB64();
    const encapsulatedV1 = await encapsulateProjectKey(projectKeyV1, keypair.public_key);
    const encapsulatedV2 = await encapsulateProjectKey(projectKeyV2, keypair.public_key);

    // Encrypt a value under v1 directly via the same primitive setEncryptedSecret
    // uses, so this test doesn't need to reach into crypto internals.
    const { encryptValue } = await import('./crypto');
    const encryptedUnderV1 = await encryptValue('pre-rotation-secret', projectKeyV1);

    globalThis.fetch = mockFetch({
      'POST /auth/login': {
        status: 'Success',
        token: 'tok',
        user: {
          id: 'user-1',
          email: 'a@example.com',
          public_key: keypair.public_key,
          encrypted_private_key: keypair.encrypted_private_key,
          private_key_nonce: keypair.private_key_nonce,
          private_key_algorithm: keypair.private_key_algorithm,
        },
      },
      'GET /users/me/projects': [{ project_id: PROJECT_ID, role: 'admin' }],
      [`GET /projects/${PROJECT_ID}/key-versions`]: [
        {
          version: 1,
          encrypted_project_key: btoa(JSON.stringify(encapsulatedV1)),
          project_key_nonce: '',
          project_key_algorithm: encapsulatedV1.suite,
        },
        {
          version: 2,
          encrypted_project_key: btoa(JSON.stringify(encapsulatedV2)),
          project_key_nonce: '',
          project_key_algorithm: encapsulatedV2.suite,
        },
      ],
      [`GET /projects/${PROJECT_ID}/secrets/OLD_SECRET`]: {
        encrypted_value: encryptedUnderV1.ciphertext,
        nonce: encryptedUnderV1.nonce,
        project_key_version: 1,
      },
    });

    await loginSession('a@example.com', PASSWORD);
    const value = await getEncryptedSecret(PROJECT_ID, 'env-1', 'OLD_SECRET');
    expect(value).toBe('pre-rotation-secret');
  });

  test('rotateProjectKeySession mints the next version, grants only the current roster, and updates local state', async () => {
    const keypair = await generateUserKeypair(PASSWORD);
    const projectKeyV1 = randomKeyB64();
    const encapsulatedV1 = await encapsulateProjectKey(projectKeyV1, keypair.public_key);

    let rotateCallBody: any = null;
    globalThis.fetch = vi.fn((url: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET';
      const path = new URL(url).pathname;

      if (method === 'POST' && path === '/auth/login') {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              status: 'Success',
              token: 'tok',
              user: {
                id: 'user-1',
                email: 'a@example.com',
                public_key: keypair.public_key,
                encrypted_private_key: keypair.encrypted_private_key,
                private_key_nonce: keypair.private_key_nonce,
                private_key_algorithm: keypair.private_key_algorithm,
              },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          )
        );
      }
      if (method === 'GET' && path === '/users/me/projects') {
        return Promise.resolve(
          new Response(JSON.stringify([{ project_id: PROJECT_ID, role: 'admin' }]), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        );
      }
      if (method === 'GET' && path === `/projects/${PROJECT_ID}/key-versions`) {
        return Promise.resolve(
          new Response(
            JSON.stringify([
              {
                version: 1,
                encrypted_project_key: btoa(JSON.stringify(encapsulatedV1)),
                project_key_nonce: '',
                project_key_algorithm: encapsulatedV1.suite,
              },
            ]),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          )
        );
      }
      if (method === 'GET' && path === `/projects/${PROJECT_ID}/members`) {
        return Promise.resolve(
          new Response(
            JSON.stringify([{ user_id: 'user-1', public_key: keypair.public_key }]),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          )
        );
      }
      if (method === 'POST' && path === `/projects/${PROJECT_ID}/rotate-key`) {
        rotateCallBody = JSON.parse(init!.body as string);
        return Promise.resolve(
          new Response(JSON.stringify({ version: 2 }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        );
      }
      throw new Error(`unmocked request: ${method} ${path}`);
    }) as unknown as typeof globalThis.fetch;

    await loginSession('a@example.com', PASSWORD);
    const result = await rotateProjectKeySession(PROJECT_ID);

    expect(result.version).toBe(2);
    expect(result.grantedTo).toBe(1);
    // Grants exactly the current roster -- the one member returned by
    // GET /projects/{id}/members -- matching what the server independently
    // re-verifies (ADR 0008).
    expect(rotateCallBody.grants).toHaveLength(1);
    expect(rotateCallBody.grants[0].user_id).toBe('user-1');

    const s = getSession();
    const state = s!.projects.get(PROJECT_ID);
    expect(state!.currentVersion).toBe(2);
    // The old version stays cached -- rotation doesn't forget history.
    expect(state!.versions.has(1)).toBe(true);
    expect(state!.versions.has(2)).toBe(true);
  });
});
