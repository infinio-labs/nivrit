const { HelperCrypto, NivritClient, NivritSession } = require('../src');
const crypto = require('crypto');

const API_URL = process.env.NIVRIT_API_URL || 'http://localhost:4000';
const EMAIL = `sdk-node-${Date.now()}@example.com`;
const EMAIL_B = `sdk-node-b-${Date.now()}@example.com`;
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

  // --- versioned project-key rotation (ADR 0008) ---------------------------
  const materialB = helper.generateRegistrationMaterial(PASSWORD, EMAIL_B);
  const regB = await request('POST', '/auth/register', {
    email: EMAIL_B,
    auth_hash: materialB.auth_hash,
    name: 'Node SDK Test B',
    public_key: materialB.public_key,
    encrypted_private_key: materialB.encrypted_private_key,
    private_key_nonce: materialB.private_key_nonce,
    private_key_algorithm: materialB.private_key_algorithm,
    recovery_auth_hash: materialB.recovery_auth_hash,
    encrypted_private_key_recovery: materialB.encrypted_private_key_recovery,
    private_key_recovery_nonce: materialB.private_key_recovery_nonce,
    private_key_recovery_algorithm: materialB.private_key_recovery_algorithm,
  });
  console.log('registered second user', regB.user.email);

  // Invited before the rotation: starts out holding only version 1.
  await session.inviteMember(project.id, EMAIL_B, 'member');
  console.log('invited second user to project');

  const patB = await request('POST', '/auth/pat', { name: 'node-sdk-test-b' }, regB.token);
  const sessionB = await NivritSession.fromPat(API_URL, patB.token, PASSWORD, helper);
  const preRotation = await sessionB.getSecret(project.id, env.id, 'GREETING');
  if (preRotation.value !== 'hello-node-sdk') {
    throw new Error(`second user could not decrypt pre-rotation secret: ${JSON.stringify(preRotation)}`);
  }
  console.log('second user decrypted pre-rotation secret');

  const rotated = await session.rotateProjectKey(project.id);
  if (rotated.version !== 2 || rotated.grantedTo !== 2) {
    throw new Error(`unexpected rotation result: ${JSON.stringify(rotated)}`);
  }
  console.log(`rotated project key to version ${rotated.version} (granted to ${rotated.grantedTo} members)`);

  const currentVersion = await session.currentProjectKeyVersion(project.id);
  const currentKey = await session.getProjectKey(project.id);
  const encryptedPostRotation = helper.encryptValue('hello-after-rotation', currentKey);
  await session.client.createSecret(project.id, {
    environment_id: env.id,
    key: 'POST_ROTATION',
    encrypted_value: encryptedPostRotation.ciphertext,
    nonce: encryptedPostRotation.nonce,
    algorithm: 'aes256gcm-v1',
    project_key_version: currentVersion,
  });
  console.log('created post-rotation secret under version', currentVersion);

  // Second user was a current member at rotation time, so they automatically
  // received the new version -- confirm without a fresh login, proving
  // rotateProjectKey's cache update on the rotating side and the grant on
  // the receiving side both worked.
  await sessionB.loadProjectKeys(project.id);
  const postRotationForB = await sessionB.getSecret(project.id, env.id, 'POST_ROTATION');
  if (postRotationForB.value !== 'hello-after-rotation') {
    throw new Error(`second user could not decrypt post-rotation secret: ${JSON.stringify(postRotationForB)}`);
  }
  const preRotationAgainForB = await sessionB.getSecret(project.id, env.id, 'GREETING');
  if (preRotationAgainForB.value !== 'hello-node-sdk') {
    throw new Error(`second user lost access to pre-rotation secret after rotation: ${JSON.stringify(preRotationAgainForB)}`);
  }
  console.log('second user decrypted both pre- and post-rotation secrets after rotation');

  await request('DELETE', `/auth/pats/${patB.id}`, undefined, regB.token);
  await request('DELETE', `/auth/pats/${pat.id}`, undefined, reg.token);
  console.log('revoked PATs');
  console.log('Node SDK smoke test passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
