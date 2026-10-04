const assert = require('node:assert/strict');
const { NivritClient } = require('../src');

async function main() {
  let seen;
  global.fetch = async (url, init) => {
    seen = { url, init };
    return { ok: true, status: 204, text: async () => '' };
  };

  const client = new NivritClient('https://example.test///', 'token');
  assert.equal(await client.request('/users/me'), undefined);
  assert.equal(seen.url, 'https://example.test/users/me');
  assert.equal(seen.init.headers.Authorization, 'Bearer token');
  assert.ok(seen.init.signal);

  global.fetch = async () => ({
    ok: false,
    status: 401,
    text: async () => 'unauthorized',
  });
  await assert.rejects(() => client.request('/users/me'), /401: unauthorized/);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
