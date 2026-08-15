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
  listFolders,
  createFolder,
  deleteFolder,
  listImports,
  createImport,
  deleteImport,
  listProjectMembers,
  listProjectKeyVersions,
  rotateProjectKey,
  listEnvironmentOverrides,
  setEnvironmentOverride,
  removeEnvironmentOverride,
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
  createPat,
  listPats,
  revokePat,
  listSecretVersions,
  restoreSecretVersion,
  listAuditLogs,
  verifyAuditLog,
  refreshSession,
  logout,
  getMe,
  type AuditLogEntry,
  type CreatedPat,
  type LoginResult,
  type OAuthCallbackResult,
  type Folder,
  type PatMetadata,
  type SecretImport,
  type SecretVersion,
  type EnvironmentOverride,
  type EnvironmentRole,
} from './api';
import { assertAcceptablePassword } from './password-policy';

export interface SecretEntry {
  id: string;
  key: string;
  value: string;
  version: number;
  /**
   * Set when the secret came from an imported scope rather than this one.
   * Inherited entries are shown but cannot be edited in place — writing the key
   * here creates a local value that shadows the import.
   */
  inheritedFrom?: string;
}

/**
 * Every project-key version this account has been granted (ADR 0008), plus
 * which one is current -- i.e. the one new secret writes should use. A
 * project that's never been rotated has exactly one entry.
 */
export interface ProjectKeyState {
  currentVersion: number;
  versions: Map<number, string>; // version -> base64 project key
}

export interface Session {
  token: string;
  userId: string;
  email: string;
  publicKey: string;
  privateKey: string;
  projects: Map<string, ProjectKeyState>;
}

let session: Session | null = null;

export function getSession(): Session | null {
  return session;
}

export function clearSession(): void {
  session = null;
}

/**
 * A freshly-refreshed access token awaiting a password to rebuild the session
 * (the unlock flow): after a reload the auth cookie is still valid, so we can
 * skip the full login and only ask for the master password, which is the one
 * thing that can unwrap the private key.
 */
let pendingToken: string | null = null;

export function getPendingToken(): string | null {
  return pendingToken;
}

export function clearPendingToken(): void {
  pendingToken = null;
}

/**
 * Silently renew the access token from the httpOnly refresh cookie. When a
 * live session exists its token is swapped in place (transparent 401 retry);
 * otherwise the token is staged for `unlockSession`.
 */
export async function tryRefreshSession(): Promise<boolean> {
  try {
    const { token } = await refreshSession();
    if (session) {
      session.token = token;
    } else {
      pendingToken = token;
    }
    return true;
  } catch {
    pendingToken = null;
    return false;
  }
}

/** Rebuild a full session from a staged refresh token + master password. */
export async function unlockSession(password: string): Promise<Session> {
  const token = pendingToken;
  if (!token) throw new Error('No session to unlock — please sign in again.');
  const user = await getMe(token);
  const s = await buildSession({ token, user }, password);
  pendingToken = null;
  return s;
}

/** Sign out everywhere: revoke the refresh token server-side, then drop keys. */
export async function logoutSession(): Promise<void> {
  await logout();
  clearSession();
  pendingToken = null;
}

/** The key new writes should use for a project. Throws if the caller isn't a
 * member (or the session predates login) rather than returning undefined, so
 * call sites don't have to null-check on every secret operation. */
function currentProjectKey(s: Session, projectId: string): { version: number; key: string } {
  const state = s.projects.get(projectId);
  if (!state) throw new Error('project key not available');
  const key = state.versions.get(state.currentVersion);
  if (!key) throw new Error('project key not available');
  return { version: state.currentVersion, key };
}

/** A specific project-key version's plaintext -- for decrypting a secret or
 * secret-version written under an older version than current (ADR 0008). */
function projectKeyForVersion(s: Session, projectId: string, version: number): string {
  const state = s.projects.get(projectId);
  const key = state?.versions.get(version);
  if (!key) {
    throw new Error(
      `no cached key for project ${projectId} version ${version}; sign in again to pick up any versions granted since your last login`
    );
  }
  return key;
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

  const projects = new Map<string, ProjectKeyState>();
  const memberships = await getMyProjects(response.token);
  for (const membership of memberships) {
    // Every version this account has ever been granted, oldest first -- not
    // just the current one -- so pre-rotation secret history stays
    // decryptable. A project that's never been rotated returns exactly one
    // entry, so this is a strict superset of the old single-key recovery.
    let entries;
    try {
      entries = await listProjectKeyVersions(response.token, membership.project_id);
    } catch (e) {
      console.warn(`failed to list key versions for ${membership.project_id}:`, e);
      continue;
    }
    const versions = new Map<number, string>();
    let currentVersion = 0;
    for (const entry of entries) {
      if (!entry.encrypted_project_key) continue;
      try {
        const projectKey = await decapsulateProjectKey(
          JSON.parse(atob(entry.encrypted_project_key)),
          privateKey
        );
        versions.set(entry.version, projectKey);
        currentVersion = Math.max(currentVersion, entry.version);
      } catch (e) {
        console.warn(
          `failed to decrypt project key for ${membership.project_id} v${entry.version}:`,
          e
        );
      }
    }
    if (versions.size > 0) {
      projects.set(membership.project_id, { currentVersion, versions });
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
  // Enforced here rather than in the form, so every caller is covered, and here
  // rather than on the server, which under split derivation only ever sees a
  // fixed-width hash and cannot judge the password behind it.
  assertAcceptablePassword(password, email);

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
): Promise<{ session: Session; recoveryCode: string }> {
  // The email comes back with the token check: both derivations are salted with
  // it, and the user does not have to retype it on the reset form.
  const { email } = await verifyResetToken(token);
  assertAcceptablePassword(newPassword, email);
  const recoveryAuthHash = await deriveRecoveryAuthHash(recoveryCode, email);

  // Fetch the recovery blob, then unwrap and re-wrap the private key locally.
  // The server sees neither the recovery code nor either password. This also
  // mints a fresh recovery code to replace the one just used - a reset is
  // often needed because the old one may be compromised, so leaving it valid
  // would defeat the point. The new code is returned for one-time display,
  // same as at registration.
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
    new_recovery_auth_hash: material.recovery_auth_hash,
    new_encrypted_private_key_recovery: material.encrypted_private_key_recovery,
    new_private_key_recovery_nonce: material.private_key_recovery_nonce,
    new_private_key_recovery_algorithm: material.private_key_recovery_algorithm,
  });
  const s = await buildSession(response, newPassword);
  return { session: s, recoveryCode: material.recovery_code };
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

  assertAcceptablePassword(masterPassword, result.email);

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

  s.projects.set(project.id, {
    currentVersion: 1,
    versions: new Map([[1, projectKey]]),
  });
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
  value: string,
  folderId: string | null = null
): Promise<void> {
  const s = getSessionOrThrow();
  const { version, key: projectKey } = currentProjectKey(s, projectId);
  const encrypted = await encryptValue(value, projectKey);
  // The folder is part of a secret's identity here: writing without it would
  // land in the environment root, where the folder view would not show it.
  await setSecret(
    s.token,
    projectId,
    environmentId,
    key,
    encrypted.ciphertext,
    encrypted.nonce,
    folderId,
    version
  );
}

export async function getEncryptedSecret(
  projectId: string,
  environmentId: string,
  key: string
): Promise<string> {
  const s = getSessionOrThrow();
  const data = await getSecret(s.token, projectId, environmentId, key);
  // Decrypt with whichever key version this specific ciphertext was written
  // under (ADR 0008) -- not necessarily this project's current version, if
  // it predates a rotation.
  const projectKey = projectKeyForVersion(s, projectId, data.project_key_version ?? 1);
  return decryptValue(data.encrypted_value, data.nonce, projectKey);
}

async function decryptEntries(
  projectId: string,
  environmentId: string,
  folderId: string | null,
  inheritedFrom?: string
): Promise<SecretEntry[]> {
  const s = getSessionOrThrow();
  // Fail fast if we're not even a member, rather than only discovering that
  // once the first item tries to resolve a key version.
  if (!s.projects.has(projectId)) throw new Error('project key not available');

  const items = await listSecrets(s.token, projectId, environmentId, folderId);
  const entries: SecretEntry[] = [];
  for (const item of items) {
    try {
      // Each secret may have been written under a different project-key
      // version (ADR 0008); decrypt with whichever one it actually used.
      const projectKey = projectKeyForVersion(s, projectId, item.project_key_version ?? 1);
      const value = await decryptValue(item.encrypted_value, item.nonce, projectKey);
      entries.push({ id: item.id, key: item.key, value, version: item.version, inheritedFrom });
    } catch (e) {
      console.warn(`failed to decrypt secret ${item.key}:`, e);
      entries.push({
        id: item.id,
        key: item.key,
        value: '[decryption failed]',
        version: item.version,
        inheritedFrom,
      });
    }
  }
  return entries;
}

/**
 * Every secret visible in a scope, including those inherited through imports.
 *
 * Mirrors the CLI's `resolve_env_map`: imported scopes are merged first, then
 * local secrets, so a local value shadows an inherited one of the same key.
 * The merge happens here because the server only stores the import *link* — it
 * never sees a value, so it cannot resolve inheritance itself.
 *
 * Like the CLI, this follows one level of imports. An imported environment that
 * itself imports another does not chain.
 */
export async function listEncryptedSecrets(
  projectId: string,
  environmentId: string,
  folderId: string | null = null,
  environmentNames: Map<string, string> = new Map()
): Promise<SecretEntry[]> {
  const s = getSessionOrThrow();

  const byKey = new Map<string, SecretEntry>();

  // Imports first: lowest precedence.
  let imports: SecretImport[] = [];
  try {
    imports = await listImports(s.token, projectId, environmentId, folderId);
  } catch (e) {
    // An unreachable import list should not hide the local secrets.
    console.warn('failed to list imports:', e);
  }

  for (const imp of imports) {
    try {
      const label = environmentNames.get(imp.source_environment_id) ?? 'another environment';
      const inherited = await decryptEntries(
        projectId,
        imp.source_environment_id,
        imp.source_folder_id,
        label
      );
      for (const entry of inherited) byKey.set(entry.key, entry);
    } catch (e) {
      console.warn(`failed to resolve import ${imp.id}:`, e);
    }
  }

  // Local last, so it overrides.
  for (const entry of await decryptEntries(projectId, environmentId, folderId)) {
    byKey.set(entry.key, entry);
  }

  return [...byKey.values()].sort((a, b) => a.key.localeCompare(b.key));
}

export async function deleteEncryptedSecret(
  projectId: string,
  environmentId: string,
  key: string,
  folderId: string | null = null
): Promise<void> {
  const s = getSessionOrThrow();
  await deleteSecret(s.token, projectId, environmentId, key, folderId);
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
  // Grants whichever version is current; the server records that as the
  // invitee's starting grant, not a hardcoded version 1, so an invite after a
  // rotation doesn't hand out a superseded key (ADR 0008).
  const { key: projectKey } = currentProjectKey(s, projectId);
  const recipient = await getPublicKey(s.token, email, projectId);
  const encapsulated = await encapsulateProjectKey(projectKey, recipient.public_key);
  await inviteMember(s.token, projectId, { email, role, encrypted_project_key: encapsulated });
}

/**
 * Mint a new project-key version and grant it to exactly the project's
 * current members (ADR 0008). No existing secret is touched. A removed
 * member simply never receives this grant, so they're locked out of
 * everything created from this point forward.
 */
export async function rotateProjectKeySession(
  projectId: string
): Promise<{ version: number; grantedTo: number }> {
  const s = getSessionOrThrow();
  // Proves we hold a valid key for this project before bothering to mint the
  // next version; the actual replacement key is generated fresh below.
  currentProjectKey(s, projectId);

  const members = await listProjectMembers(s.token, projectId);
  const newKey = generateProjectKey();
  const grants = await Promise.all(
    members.map(async (member) => {
      const encapsulated = await encapsulateProjectKey(newKey, member.public_key);
      return {
        user_id: member.user_id,
        encrypted_project_key: btoa(JSON.stringify(encapsulated)),
        project_key_nonce: btoa(''),
        project_key_algorithm: encapsulated.suite,
      };
    })
  );

  const result = await rotateProjectKey(s.token, projectId, grants);

  const state = s.projects.get(projectId);
  const versions = state ? new Map(state.versions) : new Map<number, string>();
  versions.set(result.version, newKey);
  s.projects.set(projectId, { currentVersion: result.version, versions });

  return { version: result.version, grantedTo: grants.length };
}

// Environment-scoped RBAC overrides (ADR 0009/0010). Pure authorization --
// no project-key material is involved, unlike invite/rotate above.

export async function listEnvironmentOverridesSession(
  projectId: string,
  environmentId: string
): Promise<EnvironmentOverride[]> {
  return listEnvironmentOverrides(getSessionOrThrow().token, projectId, environmentId);
}

/** Grant (or replace) a member's role override for one environment, resolving
 * the target by email the same way an invite does. `role: 'none'` denies the
 * environment outright. */
export async function setEnvironmentOverrideSession(
  projectId: string,
  environmentId: string,
  email: string,
  role: EnvironmentRole
): Promise<EnvironmentOverride> {
  const s = getSessionOrThrow();
  const target = await getPublicKey(s.token, email, projectId);
  return setEnvironmentOverride(s.token, projectId, environmentId, target.id, role);
}

export async function removeEnvironmentOverrideSession(
  projectId: string,
  environmentId: string,
  userId: string
): Promise<void> {
  const s = getSessionOrThrow();
  await removeEnvironmentOverride(s.token, projectId, environmentId, userId);
}

function getSessionOrThrow(): Session {
  if (!session) throw new Error('not logged in');
  return session;
}

export { hybridSuiteId };


// Personal access tokens
//
// The only way an account created in the browser can obtain a credential for
// the CLI, the SDKs, or the VS Code extension.

export async function listPatsSession(): Promise<PatMetadata[]> {
  return listPats(getSessionOrThrow().token);
}

export async function createPatSession(
  name: string,
  expiresInDays?: number
): Promise<CreatedPat> {
  return createPat(getSessionOrThrow().token, name, expiresInDays);
}

export async function revokePatSession(tokenId: string): Promise<void> {
  return revokePat(getSessionOrThrow().token, tokenId);
}

// Secret version history

export interface DecryptedSecretVersion {
  version: number;
  value: string;
  createdAt: string;
}

/**
 * Version history for one secret, decrypted locally.
 *
 * The server returns ciphertext per version and has no idea what any of it says;
 * the project key never leaves this device.
 */
export async function listSecretVersionsSession(
  projectId: string,
  environmentId: string,
  key: string
): Promise<DecryptedSecretVersion[]> {
  const s = getSessionOrThrow();
  if (!s.projects.has(projectId)) throw new Error('project key unavailable; sign in again');

  const versions = await listSecretVersions(s.token, projectId, environmentId, key);
  return Promise.all(
    versions.map(async (v: SecretVersion) => {
      // Each historical version may have been written under a different
      // project-key version (ADR 0008); decrypt with whichever one it used.
      const projectKey = projectKeyForVersion(s, projectId, v.project_key_version ?? 1);
      return {
        version: v.version,
        value: await decryptValue(v.encrypted_value, v.nonce, projectKey),
        createdAt: v.created_at,
      };
    })
  );
}

export async function restoreSecretVersionSession(
  projectId: string,
  environmentId: string,
  key: string,
  version: number
): Promise<void> {
  return restoreSecretVersion(getSessionOrThrow().token, projectId, environmentId, key, version);
}

// Audit log

export async function listAuditLogsSession(projectId: string): Promise<AuditLogEntry[]> {
  return listAuditLogs(getSessionOrThrow().token, projectId);
}

export async function verifyAuditLogSession(
  projectId: string,
  logId: string
): Promise<{ valid: boolean; reason: string | null }> {
  return verifyAuditLog(getSessionOrThrow().token, projectId, logId);
}


// Folders

export async function listFoldersSession(
  projectId: string,
  environmentId: string
): Promise<Folder[]> {
  return listFolders(getSessionOrThrow().token, projectId, environmentId);
}

export async function createFolderSession(
  projectId: string,
  environmentId: string,
  name: string
): Promise<Folder> {
  // The API takes a name and a path separately; a flat single-level path keeps
  // the two consistent without inventing a nesting UI nobody asked for.
  const trimmed = name.trim();
  return createFolder(getSessionOrThrow().token, projectId, environmentId, trimmed, `/${trimmed}`);
}

export async function deleteFolderSession(projectId: string, folderId: string): Promise<void> {
  return deleteFolder(getSessionOrThrow().token, projectId, folderId);
}

// Imports

export async function listImportsSession(
  projectId: string,
  environmentId: string,
  folderId: string | null = null
): Promise<SecretImport[]> {
  return listImports(getSessionOrThrow().token, projectId, environmentId, folderId);
}

export async function createImportSession(
  projectId: string,
  environmentId: string,
  sourceEnvironmentId: string,
  folderId: string | null = null
): Promise<SecretImport> {
  return createImport(
    getSessionOrThrow().token,
    projectId,
    environmentId,
    sourceEnvironmentId,
    folderId
  );
}

export async function deleteImportSession(projectId: string, importId: string): Promise<void> {
  return deleteImport(getSessionOrThrow().token, projectId, importId);
}
