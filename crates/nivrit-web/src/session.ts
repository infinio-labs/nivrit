import {
  deriveAuthHash,
  deriveRecoveryAuthHash,
  generateRegistrationMaterial,
  resetPasswordMaterial,
  decryptPrivateKey,
  decryptValue,
  decapsulateProjectKey,
  encapsulateProjectKey,
  encryptValue,
  hybridSuiteId,
} from './crypto';
import {
  createEnvironment,
  createOrg,
  createProject,
  deleteSecret,
  disableTotp,
  forgotPassword,
  getMyOrgs,
  getMyProjects,
  getPublicKey,
  getSecret,
  inviteMember,
  listEnvironments,
  listOrgProjects,
  listSecrets,
  login,
  loginTotp,
  oauthCallback,
  oauthSetup,
  register,
  resetPassword,
  resetPasswordBegin,
  setSecret,
  setupTotp,
  verifyResetToken,
  verifyTotp,
  type LoginResult,
  type OAuthCallbackResult,
} from './api';

export interface SecretEntry {
  id: string;
  key: string;
  value: string;
  version: number;
}

export interface Session {
  token: string;
  userId: string;
  email: string;
  publicKey: string;
  privateKey: string;
  projects: Map<string, string>; // project_id -> base64 project key
}

let session: Session | null = null;

export function getSession(): Session | null {
  return session;
}

export function clearSession(): void {
  session = null;
}

async function buildSession(
  response: { token: string; user: { id: string; email: string; public_key: string; encrypted_private_key: string; private_key_nonce: string; private_key_algorithm: string } },
  password: string
): Promise<Session> {
  const privateKey = await decryptPrivateKey(
    response.user.encrypted_private_key,
    response.user.private_key_nonce,
    password
  );

  const projects = new Map<string, string>();
  const memberships = await getMyProjects(response.token);
  for (const membership of memberships) {
    if (!membership.encrypted_project_key) continue;
    try {
      const projectKey = await decapsulateProjectKey(
        JSON.parse(atob(membership.encrypted_project_key)),
        privateKey
      );
      projects.set(membership.project_id, projectKey);
    } catch (e) {
      console.warn(`failed to decrypt project key for ${membership.project_id}:`, e);
    }
  }

  const s: Session = {
    token: response.token,
    userId: response.user.id,
    email: response.user.email,
    publicKey: response.user.public_key,
    privateKey,
    projects,
  };
  // Token is kept in memory only. localStorage is XSS-readable; persisting the
  // bearer token there would let injected script steal an authenticated session.
  // The private key already lives in memory only, so a refresh re-prompts for
  // the password regardless — nothing to gain from persisting the token.
  session = s;
  return s;
}

export async function loginSession(email: string, password: string): Promise<LoginResult> {
  // The password is used twice locally and sent never: once to derive the
  // opaque credential the server checks, once (inside buildSession) to unwrap
  // the private key.
  const result = await login(email, await deriveAuthHash(password, email));
  if (result.status === 'MfaRequired') {
    return result;
  }
  await buildSession(result, password);
  return { status: 'Success', token: result.token, user: result.user };
}

export async function loginTotpSession(tempToken: string, code: string, password: string): Promise<Session> {
  const response = await loginTotp(tempToken, code);
  return buildSession(response, password);
}

export async function registerSession(
  email: string,
  password: string,
  name?: string
): Promise<{ session: Session; recoveryCode: string }> {
  // One WASM call produces the keypair, both wrapped copies of the private key,
  // and both opaque credentials. The recovery code is generated here, not by
  // the server, and is returned for one-time display to the user.
  const material = await generateRegistrationMaterial(password, email);
  const response = await register({
    email,
    auth_hash: material.auth_hash,
    name,
    public_key: material.public_key,
    encrypted_private_key: material.encrypted_private_key,
    private_key_nonce: material.private_key_nonce,
    private_key_algorithm: material.private_key_algorithm,
    recovery_auth_hash: material.recovery_auth_hash,
    encrypted_private_key_recovery: material.encrypted_private_key_recovery,
    private_key_recovery_nonce: material.private_key_recovery_nonce,
    private_key_recovery_algorithm: material.private_key_recovery_algorithm,
  });

  const s = await buildSession(response, password);
  return { session: s, recoveryCode: material.recovery_code };
}

export async function forgotPasswordSession(email: string): Promise<{ sent: boolean }> {
  return forgotPassword(email);
}

export async function resetPasswordSession(
  token: string,
  recoveryCode: string,
  newPassword: string
): Promise<Session> {
  // The email comes back with the token check: both derivations are salted with
  // it, and the user does not have to retype it on the reset form.
  const { email } = await verifyResetToken(token);
  const recoveryAuthHash = await deriveRecoveryAuthHash(recoveryCode, email);

  // Fetch the recovery blob, then unwrap and re-wrap the private key locally.
  // The server sees neither the recovery code nor either password.
  const blob = await resetPasswordBegin(token, recoveryAuthHash);
  const material = await resetPasswordMaterial(
    blob.encrypted_private_key_recovery,
    blob.private_key_recovery_nonce,
    recoveryCode,
    email,
    newPassword
  );

  const response = await resetPassword({
    token,
    recovery_auth_hash: recoveryAuthHash,
    new_auth_hash: material.auth_hash,
    encrypted_private_key: material.encrypted_private_key,
    private_key_nonce: material.private_key_nonce,
    private_key_algorithm: material.private_key_algorithm,
  });
  return buildSession(response, newPassword);
}

// OAuth

export async function processOAuthCallback(
  provider: string,
  code: string,
  state: string,
  masterPassword: string
): Promise<{ session: Session; recoveryCode?: string }> {
  const result: OAuthCallbackResult = await oauthCallback(provider, code, state);
  if (result.status === 'Existing') {
    const s = await buildSession(result, masterPassword);
    return { session: s };
  }

  const material = await generateRegistrationMaterial(masterPassword, result.email);
  const setup = await oauthSetup({
    setup_token: result.setup_token,
    auth_hash: material.auth_hash,
    public_key: material.public_key,
    encrypted_private_key: material.encrypted_private_key,
    private_key_nonce: material.private_key_nonce,
    private_key_algorithm: material.private_key_algorithm,
    recovery_auth_hash: material.recovery_auth_hash,
    encrypted_private_key_recovery: material.encrypted_private_key_recovery,
    private_key_recovery_nonce: material.private_key_recovery_nonce,
    private_key_recovery_algorithm: material.private_key_recovery_algorithm,
  });
  const s = await buildSession(setup, masterPassword);
  return { session: s, recoveryCode: material.recovery_code };
}

// TOTP

export async function setupTotpSession(
  token: string,
  reauth?: { email: string; password: string }
): Promise<{ secret: string; uri: string }> {
  // Replacing an existing authenticator requires the password, so a stolen
  // session token is not enough on its own.
  const authHash = reauth ? await deriveAuthHash(reauth.password, reauth.email) : undefined;
  return setupTotp(token, authHash);
}

export async function verifyTotpSession(token: string, code: string): Promise<boolean> {
  const res = await verifyTotp(token, code);
  return res.enabled;
}

export async function disableTotpSession(
  token: string,
  email: string,
  password: string,
  code: string
): Promise<boolean> {
  const res = await disableTotp(token, await deriveAuthHash(password, email), code);
  return res.disabled;
}

// Core resource helpers

export async function getMyOrgsSession(): Promise<{ id: string; name: string; slug: string }[]> {
  const s = getSessionOrThrow();
  return getMyOrgs(s.token);
}

export async function createOrgSession(name: string, slug: string) {
  const s = getSessionOrThrow();
  return createOrg(s.token, name, slug);
}

export async function listOrgProjectsSession(orgId: string) {
  const s = getSessionOrThrow();
  return listOrgProjects(s.token, orgId);
}

function generateProjectKey(): string {
  // No Math.random fallback: a non-cryptographic key would be guessable and
  // compromise every secret in the project. getRandomValues exists in every
  // browser and worker; if it's missing, refuse rather than downgrade.
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new Error('secure random number generator unavailable');
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

export async function createProjectSession(
  orgId: string,
  name: string,
  slug: string
): Promise<{ id: string; org_id: string; name: string; slug: string }> {
  const s = getSessionOrThrow();
  const projectKey = generateProjectKey();
  const encapsulated = await encapsulateProjectKey(projectKey, s.publicKey);
  const encryptedProjectKeyJson = JSON.stringify(encapsulated);
  const encryptedProjectKey = btoa(encryptedProjectKeyJson);

  const project = await createProject(s.token, {
    org_id: orgId,
    name,
    slug,
    encrypted_project_key: encryptedProjectKey,
    project_key_nonce: btoa(''),
    project_key_algorithm: hybridSuiteId(),
  });

  s.projects.set(project.id, projectKey);
  return project;
}

export async function createEnvironmentSession(
  projectId: string,
  name: string,
  slug: string
) {
  const s = getSessionOrThrow();
  return createEnvironment(s.token, projectId, name, slug);
}

export async function setEncryptedSecret(
  projectId: string,
  environmentId: string,
  key: string,
  value: string
): Promise<void> {
  const s = getSessionOrThrow();
  const projectKey = s.projects.get(projectId);
  if (!projectKey) throw new Error('project key not available');
  const encrypted = await encryptValue(value, projectKey);
  await setSecret(s.token, projectId, environmentId, key, encrypted.ciphertext, encrypted.nonce);
}

export async function getEncryptedSecret(
  projectId: string,
  environmentId: string,
  key: string
): Promise<string> {
  const s = getSessionOrThrow();
  const projectKey = s.projects.get(projectId);
  if (!projectKey) throw new Error('project key not available');
  const data = await getSecret(s.token, projectId, environmentId, key);
  return decryptValue(data.encrypted_value, data.nonce, projectKey);
}

export async function listEncryptedSecrets(
  projectId: string,
  environmentId: string
): Promise<SecretEntry[]> {
  const s = getSessionOrThrow();
  const projectKey = s.projects.get(projectId);
  if (!projectKey) throw new Error('project key not available');
  const items = await listSecrets(s.token, projectId, environmentId);
  const entries: SecretEntry[] = [];
  for (const item of items) {
    try {
      const value = await decryptValue(item.encrypted_value, item.nonce, projectKey);
      entries.push({ id: item.id, key: item.key, value, version: item.version });
    } catch (e) {
      console.warn(`failed to decrypt secret ${item.key}:`, e);
      entries.push({ id: item.id, key: item.key, value: '[decryption failed]', version: item.version });
    }
  }
  return entries;
}

export async function deleteEncryptedSecret(
  projectId: string,
  environmentId: string,
  key: string
): Promise<void> {
  const s = getSessionOrThrow();
  await deleteSecret(s.token, projectId, environmentId, key);
}

export async function getProjectEnvironments(projectId: string) {
  const s = getSessionOrThrow();
  return listEnvironments(s.token, projectId);
}

export async function inviteProjectMember(
  projectId: string,
  email: string,
  role: 'admin' | 'member' | 'viewer'
): Promise<void> {
  const s = getSessionOrThrow();
  const projectKey = s.projects.get(projectId);
  if (!projectKey) throw new Error('project key not available');
  const recipient = await getPublicKey(s.token, email);
  const encapsulated = await encapsulateProjectKey(projectKey, recipient.public_key);
  await inviteMember(s.token, projectId, { email, role, encrypted_project_key: encapsulated });
}

function getSessionOrThrow(): Session {
  if (!session) throw new Error('not logged in');
  return session;
}

export { hybridSuiteId };
