#!/usr/bin/env node
/**
 * Verifies the browser's wire protocol against a running API.
 *
 * The Playwright suite drives the UI and `test-stack.sh` drives the CLI, but
 * neither exercised the HTTP contract the browser actually speaks — which is
 * where the split-derivation auth lives. This covers registration, login, and
 * the two-step password reset, using the same WASM module the browser loads,
 * and asserts that a credential derived by the CLI helper is accepted for an
 * account created in the browser. If those two ever diverge, an account made in
 * one client silently cannot log in from the other.
 *
 * Usage:
 *   NIVRIT_API=http://127.0.0.1:4000 \
 *   NIVRIT_API_LOG=/path/to/api.log \
 *   node scripts/verify-web-protocol.mjs
 *
 * The API must run with NIVRIT_EMAIL_MODE=log at info level: the reset token is
 * read back out of its log, because there is no inbox to read in a test.
 */

const ROOT = new URL('..', import.meta.url).pathname;
const API = process.env.NIVRIT_API ?? 'http://127.0.0.1:4000';
const API_LOG = process.env.NIVRIT_API_LOG ?? `${ROOT}target/api-e2e.log`;
const wasm = await import(`${ROOT}crates/nivrit-web/src/wasm/pkg-node/nivrit_web_crypto.js`);

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  <- ' + detail}`);
  if (!ok) failures++;
};

async function post(path, body, token) {
  const res = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

const email = `web-e2e-${Date.now()}@example.com`;
const password = 'browser-glacier-tuesday-vault';

// --- register, exactly as session.ts does ---
const material = wasm.generate_registration_material(password, email);
const reg = await post('/auth/register', {
  email,
  auth_hash: material.auth_hash,
  name: 'WebE2E',
  public_key: material.public_key,
  encrypted_private_key: material.encrypted_private_key,
  private_key_nonce: material.private_key_nonce,
  private_key_algorithm: material.private_key_algorithm,
  recovery_auth_hash: material.recovery_auth_hash,
  encrypted_private_key_recovery: material.encrypted_private_key_recovery,
  private_key_recovery_nonce: material.private_key_recovery_nonce,
  private_key_recovery_algorithm: material.private_key_recovery_algorithm,
});
check('browser register', reg.status === 200, `${reg.status} ${JSON.stringify(reg.body)}`);
check('register does not return the recovery code', reg.body && !('recovery_code' in reg.body));

// --- login ---
const login = await post('/auth/login', { email, auth_hash: wasm.derive_auth_hash(password, email) });
check('browser login', login.status === 200 && login.body?.status === 'Success', `${login.status}`);

// --- the password is never accepted in place of the hash ---
const bad = await post('/auth/login', { email, auth_hash: password });
check('raw password rejected as credential', bad.status === 400, `got ${bad.status}`);

// --- wrong password rejected ---
const wrong = await post('/auth/login', { email, auth_hash: wasm.derive_auth_hash('wrong-password-entirely', email) });
check('wrong password rejected', wrong.status === 401, `got ${wrong.status}`);

// --- CLI/browser interop: the CLI helper must derive the same credential ---
const { spawnSync } = await import('node:child_process');
const helperPath = process.env.NIVRIT_CRYPTO_HELPER ?? `${ROOT}target/release/nivrit-crypto-helper`;
const helper = spawnSync(helperPath, [], {
  input: JSON.stringify({ op: 'derive_auth_hash', password, email }), encoding: 'utf-8',
});
const helperHash = JSON.parse(helper.stdout.trim()).result.auth_hash;
const cliLogin = await post('/auth/login', { email, auth_hash: helperHash });
check('account made in browser accepts a CLI-derived credential',
  cliLogin.status === 200, `${cliLogin.status}`);

// --- two-step password reset ---
const forgot = await post('/auth/forgot-password', { email });
check('forgot-password always reports sent', forgot.status === 200 && forgot.body?.sent === true);

// Pull the reset token out of the API log, which is where EmailConfig::Log puts it.
const { readFileSync } = await import('node:fs');
const log = readFileSync(API_LOG, 'utf-8');
const m = [...log.matchAll(/token=([A-Za-z0-9+/=]+)/g)].pop();
if (!m) {
  check('reset token recoverable from log', false, 'no token in api log');
} else {
  const token = decodeURIComponent(m[1]);
  const verify = await fetch(`${API}/auth/reset-password/verify?token=${encodeURIComponent(token)}`);
  const verifyBody = await verify.json().catch(() => null);
  check('reset token verifies and returns the email',
    verify.status === 200 && verifyBody?.email === email, JSON.stringify(verifyBody));

  const recoveryAuthHash = wasm.derive_recovery_auth_hash(material.recovery_code, email);

  const begin = await post('/auth/reset-password/begin', { token, recovery_auth_hash: recoveryAuthHash });
  check('reset step 1 returns the recovery blob',
    begin.status === 200 && !!begin.body?.encrypted_private_key_recovery, `${begin.status}`);

  const wrongCode = await post('/auth/reset-password/begin', {
    token, recovery_auth_hash: wasm.derive_recovery_auth_hash('WRON-GCOD-EXXX', email),
  });
  check('reset step 1 rejects a wrong recovery code', wrongCode.status === 401, `got ${wrongCode.status}`);

  const newPassword = 'a-brand-new-glacier-passphrase';
  const reset = wasm.reset_password_material(
    begin.body.encrypted_private_key_recovery,
    begin.body.private_key_recovery_nonce,
    material.recovery_code, email, newPassword);

  const done = await post('/auth/reset-password', {
    token,
    recovery_auth_hash: recoveryAuthHash,
    new_auth_hash: reset.auth_hash,
    encrypted_private_key: reset.encrypted_private_key,
    private_key_nonce: reset.private_key_nonce,
    private_key_algorithm: reset.private_key_algorithm,
  });
  check('reset step 2 completes', done.status === 200, `${done.status} ${JSON.stringify(done.body)}`);

  const after = await post('/auth/login', { email, auth_hash: wasm.derive_auth_hash(newPassword, email) });
  check('login with the new password', after.status === 200, `${after.status}`);

  const old = await post('/auth/login', { email, auth_hash: wasm.derive_auth_hash(password, email) });
  check('old password no longer works', old.status === 401, `got ${old.status}`);

  const replay = await post('/auth/reset-password', {
    token, recovery_auth_hash: recoveryAuthHash, new_auth_hash: reset.auth_hash,
    encrypted_private_key: reset.encrypted_private_key,
    private_key_nonce: reset.private_key_nonce,
    private_key_algorithm: reset.private_key_algorithm,
  });
  check('reset token cannot be replayed', replay.status === 401, `got ${replay.status}`);

  // The private key must survive the reset unchanged, or project keys break.
  const me = await fetch(`${API}/users/me`, { headers: { Authorization: `Bearer ${after.body.token}` } });
  const meBody = await me.json();
  const before = wasm.decrypt_private_key(material.encrypted_private_key, material.private_key_nonce, password);
  const afterKey = wasm.decrypt_private_key(meBody.encrypted_private_key, meBody.private_key_nonce, newPassword);
  check('private key is preserved across the reset', before.private_key === afterKey.private_key);
}

console.log(failures === 0 ? '\nALL BROWSER-PROTOCOL CHECKS PASSED' : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
