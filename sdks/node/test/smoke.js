const { HelperCrypto, NivritClient, NivritSession } = require('../src');
const crypto = require('crypto');

const API_URL = process.env.NIVRIT_API_URL || 'http://localhost:4000';
const EMAIL = `sdk-node-${Date.now()}@example.com`;
const PASSWORD = 'Correct-Horse-Battery-Staple!';

async function request(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  return text ? JSON.parse(text) : undefined;
}

async function main() {
  const helper = new HelperCrypto();
  const material = helper.generateRegistrationMaterial(PASSWORD, EMAIL);

  const reg = await request('POST', '/auth/register', {
    email: EMAIL,
    auth_hash: material.auth_hash,
    name: 'Node SDK Test',
    public_key: material.public_key,
    encrypted_private_key: material.encrypted_private_key,
    private_key_nonce: material.private_key_nonce,
    private_key_algorithm: material.private_key_algorithm,
    recovery_auth_hash: material.recovery_auth_hash,
    encrypted_private_key_recovery: material.encrypted_private_key_recovery,
    private_key_recovery_nonce: material.private_key_recovery_nonce,
    private_key_recovery_algorithm: material.private_key_recovery_algorithm,
  });
  console.log('registered', reg.user.email);

  const pat = await request('POST', '/auth/pat', { name: 'node-sdk-test' }, reg.token);
  console.log('created PAT');

  const session = await NivritSession.fromPat(API_URL, pat.token, PASSWORD, helper);
  console.log('session user', session.user.email);

  const org = await session.client.createOrg({ name: 'Node SDK Org', slug: `node-sdk-org-${Date.now()}` });
  console.log('created org', org.name);

  const projectKey = crypto.randomBytes(32).toString('base64');
  const encapsulated = helper.encapsulateProjectKey(projectKey, session.user.public_key);
  const encryptedProjectKey = Buffer.from(JSON.stringify(encapsulated)).toString('base64');
  const project = await session.client.createProject({
    org_id: org.id,
    name: 'Node SDK Project',
    slug: `node-sdk-project-${Date.now()}`,
    encrypted_project_key: encryptedProjectKey,
    project_key_nonce: crypto.randomBytes(12).toString('base64'),
    project_key_algorithm: 'hybrid_x25519_ml_kem_768_aes256gcm_v1',
  });
  console.log('created project', project.name);

  const env = await session.client.createEnvironment(project.id, { name: 'Dev', slug: 'dev' });
  console.log('created environment', env.name);

  const encrypted = helper.encryptValue('hello-node-sdk', projectKey);
  await session.client.createSecret(project.id, {
    environment_id: env.id,
    key: 'GREETING',
    encrypted_value: encrypted.ciphertext,
    nonce: encrypted.nonce,
    algorithm: 'aes256gcm-v1',
  });
  console.log('created secret');

  const secrets = await session.listSecrets(project.id, env.id);
  if (secrets.length !== 1 || secrets[0].value !== 'hello-node-sdk') {
    throw new Error(`unexpected secrets: ${JSON.stringify(secrets)}`);
  }
  console.log('decrypted secret:', secrets[0].value);

  await request('DELETE', `/auth/pats/${pat.id}`, undefined, reg.token);
  console.log('revoked PAT');
  console.log('Node SDK smoke test passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
