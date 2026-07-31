/// <reference types="vite/client" />
const API_URL =
  (typeof import.meta.env !== 'undefined' && import.meta.env.VITE_API_URL) ||
  'http://localhost:4000';

/** Raised when the server rejects the session; the UI signs the user out. */
export class SessionExpiredError extends Error {
  constructor() {
    super('Your session has expired. Please sign in again.');
    this.name = 'SessionExpiredError';
  }
}

/**
 * Turn a failed response into an Error carrying the server's message.
 *
 * Every call site used to throw a fixed string like 'set secret failed', which
 * meant a user hitting a validation rule or a rate limit saw the same opaque
 * text as someone hitting a network fault.
 */
async function failure(res: Response, fallback: string): Promise<Error> {
  if (res.status === 401) return new SessionExpiredError();
  let detail = '';
  try {
    const body = await res.json();
    if (body && typeof body.error === 'string') detail = body.error;
  } catch {
    // Non-JSON body (proxy error page, empty 502); fall back to the generic text.
  }
  if (res.status === 403 && !detail) {
    detail = 'Too many attempts. Please wait a few minutes and try again.';
  }
  return new Error(detail || fallback);
}

export interface LoginResponse {
  token: string;
  user: {
    id: string;
    email: string;
    public_key: string;
    encrypted_private_key: string;
    private_key_nonce: string;
    private_key_algorithm: string;
  };
}

// The recovery code is generated on the client, so it is not in the response.
export type RegisterResponse = LoginResponse;

export type LoginResult =
  | { status: 'Success' } & LoginResponse
  | { status: 'MfaRequired'; temp_token: string };

// No password field: the server receives an opaque auth_hash derived in WASM,
// plus ciphertext it cannot open. See crypto.ts.
export interface RegisterRequest {
  email: string;
  auth_hash: string;
  name?: string;
  public_key: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
  recovery_auth_hash: string;
  encrypted_private_key_recovery: string;
  private_key_recovery_nonce: string;
  private_key_recovery_algorithm: string;
}

export async function login(email: string, authHash: string): Promise<LoginResult> {
  const res = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, auth_hash: authHash }),
  });
  if (!res.ok) throw await failure(res, 'login failed');
  return res.json();
}

export async function loginTotp(tempToken: string, code: string): Promise<LoginResponse> {
  const res = await fetch(`${API_URL}/auth/login/totp`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ temp_token: tempToken, code }),
  });
  if (!res.ok) throw await failure(res, 'TOTP login failed');
  return res.json();
}

export async function register(body: RegisterRequest): Promise<RegisterResponse> {
  const res = await fetch(`${API_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw await failure(res, 'registration failed');
  return res.json();
}

export async function forgotPassword(email: string): Promise<{ sent: boolean }> {
  const res = await fetch(`${API_URL}/auth/forgot-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) throw new Error('request failed');
  return res.json();
}

export async function verifyResetToken(
  token: string
): Promise<{ valid: boolean; email: string }> {
  const res = await fetch(`${API_URL}/auth/reset-password/verify?token=${encodeURIComponent(token)}`);
  if (!res.ok) throw new Error('invalid token');
  return res.json();
}

export interface RecoveryBlob {
  encrypted_private_key_recovery: string;
  private_key_recovery_nonce: string;
  private_key_recovery_algorithm: string;
}

/// Step 1: prove possession of the recovery code and fetch the recovery blob.
/// The blob is ciphertext only the recovery code can open, so the server learns
/// nothing by handing it over.
export async function resetPasswordBegin(
  token: string,
  recoveryAuthHash: string
): Promise<RecoveryBlob> {
  const res = await fetch(`${API_URL}/auth/reset-password/begin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, recovery_auth_hash: recoveryAuthHash }),
  });
  if (!res.ok) throw await failure(res, 'invalid reset token or recovery code');
  return res.json();
}

export interface ResetPasswordRequest {
  token: string;
  recovery_auth_hash: string;
  new_auth_hash: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
  new_recovery_auth_hash: string;
  new_encrypted_private_key_recovery: string;
  new_private_key_recovery_nonce: string;
  new_private_key_recovery_algorithm: string;
}

/// Step 2: upload the private key re-wrapped under the new password.
export async function resetPassword(body: ResetPasswordRequest): Promise<LoginResponse> {
  const res = await fetch(`${API_URL}/auth/reset-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw await failure(res, 'reset failed');
  return res.json();
}

// OAuth

export async function oauthAuthorizeUrl(provider: 'google' | 'github'): Promise<{ url: string; state: string }> {
  const res = await fetch(`${API_URL}/auth/oauth/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider }),
  });
  if (!res.ok) throw await failure(res, 'oauth authorize failed');
  return res.json();
}

export type OAuthCallbackResult =
  | ({ status: 'Existing' } & LoginResponse)
  | {
      status: 'SetupRequired';
      // provider/email/name are display-only; setup_token is the signed,
      // server-issued proof of the OAuth identity that setup must echo back.
      provider: string;
      email: string;
      name?: string;
      setup_token: string;
    };

export async function oauthCallback(
  provider: string,
  code: string,
  state: string
): Promise<OAuthCallbackResult> {
  const res = await fetch(`${API_URL}/auth/oauth/callback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, code, state }),
  });
  if (!res.ok) throw await failure(res, 'oauth callback failed');
  return res.json();
}

export interface OAuthSetupRequest {
  // Signed identity token from the callback. Replaces the old client-supplied
  // provider/provider_user_id/email/name (which allowed account pre-hijacking).
  setup_token: string;
  auth_hash: string;
  public_key: string;
  encrypted_private_key: string;
  private_key_nonce: string;
  private_key_algorithm: string;
  recovery_auth_hash: string;
  encrypted_private_key_recovery: string;
  private_key_recovery_nonce: string;
  private_key_recovery_algorithm: string;
}

export async function oauthSetup(body: OAuthSetupRequest): Promise<RegisterResponse> {
  const res = await fetch(`${API_URL}/auth/oauth/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw await failure(res, 'oauth setup failed');
  return res.json();
}

// TOTP

export interface TotpSetupResponse {
  secret: string;
  uri: string;
}

// authHash is required only when replacing an existing TOTP secret, so that a
// stolen session token alone cannot re-enrol a new authenticator.
export async function setupTotp(token: string, authHash?: string): Promise<TotpSetupResponse> {
  const res = await fetch(`${API_URL}/auth/totp/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ auth_hash: authHash ?? null }),
  });
  if (!res.ok) throw await failure(res, 'totp setup failed');
  return res.json();
}

export async function verifyTotp(token: string, code: string): Promise<{ enabled: boolean }> {
  const res = await fetch(`${API_URL}/auth/totp/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw await failure(res, 'totp verify failed');
  return res.json();
}

export async function disableTotp(
  token: string,
  authHash: string,
  code: string
): Promise<{ disabled: boolean }> {
  const res = await fetch(`${API_URL}/auth/totp/disable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ auth_hash: authHash, code }),
  });
  if (!res.ok) throw await failure(res, 'totp disable failed');
  return res.json();
}

// Core resources

export interface MyProject {
  project_id: string;
  role: string;
  encrypted_project_key: string;
  project_key_nonce: string;
  project_key_algorithm: string;
}

export async function getMyProjects(token: string): Promise<MyProject[]> {
  const res = await fetch(`${API_URL}/users/me/projects`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('failed to fetch projects');
  return res.json();
}

export interface Org {
  id: string;
  name: string;
  slug: string;
}

export async function getMyOrgs(token: string): Promise<Org[]> {
  const res = await fetch(`${API_URL}/users/me/orgs`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('failed to fetch orgs');
  return res.json();
}

export async function createOrg(token: string, name: string, slug: string): Promise<Org> {
  const res = await fetch(`${API_URL}/orgs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ name, slug }),
  });
  if (!res.ok) throw new Error('create org failed');
  return res.json();
}

export interface Project {
  id: string;
  org_id: string;
  name: string;
  slug: string;
}

export async function listOrgProjects(token: string, orgId: string): Promise<Project[]> {
  const res = await fetch(`${API_URL}/orgs/${orgId}/projects`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('failed to fetch org projects');
  return res.json();
}

export interface CreateProjectRequest {
  org_id: string;
  name: string;
  slug: string;
  encrypted_project_key: string;
  project_key_nonce: string;
  project_key_algorithm: string;
}

export async function createProject(
  token: string,
  body: CreateProjectRequest
): Promise<Project> {
  const res = await fetch(`${API_URL}/projects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('create project failed');
  return res.json();
}

export async function createEnvironment(
  token: string,
  projectId: string,
  name: string,
  slug: string
): Promise<Environment> {
  const res = await fetch(`${API_URL}/projects/${projectId}/environments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ name, slug }),
  });
  if (!res.ok) throw new Error('create environment failed');
  return res.json();
}

export interface PublicKeyResponse {
  id: string;
  email: string;
  public_key: string;
}

export async function getPublicKey(
  token: string,
  email: string,
  projectId: string
): Promise<PublicKeyResponse> {
  const res = await fetch(
    `${API_URL}/users/public-key?email=${encodeURIComponent(email)}&project_id=${encodeURIComponent(projectId)}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw new Error('failed to fetch public key');
  return res.json();
}

export async function setSecret(
  token: string,
  projectId: string,
  environmentId: string,
  key: string,
  ciphertext: string,
  nonce: string,
  folderId?: string | null
): Promise<void> {
  const res = await fetch(`${API_URL}/projects/${projectId}/secrets`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      environment_id: environmentId,
      folder_id: folderId ?? null,
      key,
      encrypted_value: ciphertext,
      nonce,
    }),
  });
  if (!res.ok) throw await failure(res, 'set secret failed');
}

export async function getSecret(
  token: string,
  projectId: string,
  environmentId: string,
  key: string
): Promise<{ encrypted_value: string; nonce: string }> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets/${encodeURIComponent(key)}?environment_id=${environmentId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw await failure(res, 'get secret failed');
  return res.json();
}

export interface SecretListItem {
  id: string;
  project_id: string;
  environment_id: string;
  folder_id: string | null;
  key: string;
  encrypted_value: string;
  nonce: string;
  algorithm: string;
  version: number;
}

/**
 * List secrets in one scope.
 *
 * `folderId` matters: the server matches `folder_id IS NOT DISTINCT FROM`, so
 * omitting it returns only root-level secrets. Leaving it out is why secrets
 * filed into folders used to be invisible here.
 */
export async function listSecrets(
  token: string,
  projectId: string,
  environmentId: string,
  folderId?: string | null
): Promise<SecretListItem[]> {
  const query = new URLSearchParams({ environment_id: environmentId });
  if (folderId) query.set('folder_id', folderId);
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets?${query}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw await failure(res, 'list secrets failed');
  return res.json();
}

export async function deleteSecret(
  token: string,
  projectId: string,
  environmentId: string,
  key: string,
  folderId?: string | null
): Promise<void> {
  const query = new URLSearchParams({ environment_id: environmentId });
  if (folderId) query.set('folder_id', folderId);
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets/${encodeURIComponent(key)}?${query}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    }
  );
  if (!res.ok) throw await failure(res, 'delete secret failed');
}

export interface Environment {
  id: string;
  project_id: string;
  name: string;
  slug: string;
}

export async function listEnvironments(
  token: string,
  projectId: string
): Promise<Environment[]> {
  const res = await fetch(`${API_URL}/projects/${projectId}/environments`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('list environments failed');
  return res.json();
}

export interface InviteMemberRequest {
  email: string;
  role: string;
  encrypted_project_key: object;
}

export async function inviteMember(
  token: string,
  projectId: string,
  body: InviteMemberRequest
): Promise<void> {
  const res = await fetch(`${API_URL}/projects/${projectId}/members`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('invite failed');
}


// Personal access tokens
//
// Required for the CLI, the SDKs, and the VS Code extension: an account created
// in the browser has no other way to obtain a credential for them.

export interface PatMetadata {
  id: string;
  name: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

export interface CreatedPat extends PatMetadata {
  /** Returned exactly once, at creation. */
  token: string;
}

export async function listPats(token: string): Promise<PatMetadata[]> {
  const res = await fetch(`${API_URL}/auth/pats`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw await failure(res, 'could not list access tokens');
  return res.json();
}

export async function createPat(
  token: string,
  name: string,
  expiresInDays?: number
): Promise<CreatedPat> {
  const res = await fetch(`${API_URL}/auth/pat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ name, expires_in_days: expiresInDays ?? null }),
  });
  if (!res.ok) throw await failure(res, 'could not create access token');
  return res.json();
}

export async function revokePat(token: string, tokenId: string): Promise<void> {
  const res = await fetch(`${API_URL}/auth/pats/${tokenId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw await failure(res, 'could not revoke access token');
}

// Secret version history

export interface SecretVersion {
  version: number;
  encrypted_value: string;
  nonce: string;
  algorithm: string;
  created_at: string;
}

export async function listSecretVersions(
  token: string,
  projectId: string,
  environmentId: string,
  key: string
): Promise<SecretVersion[]> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets/${encodeURIComponent(key)}/versions?environment_id=${environmentId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw await failure(res, 'could not load version history');
  return res.json();
}

export async function restoreSecretVersion(
  token: string,
  projectId: string,
  environmentId: string,
  key: string,
  version: number
): Promise<void> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/secrets/${encodeURIComponent(key)}/restore`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ environment_id: environmentId, version }),
    }
  );
  if (!res.ok) throw await failure(res, 'could not restore that version');
}

// Audit log

export interface AuditLogEntry {
  id: string;
  project_id: string;
  environment_id: string | null;
  secret_id: string | null;
  user_id: string;
  action: string;
  key: string;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  /** Present when the server was configured with an ML-DSA-65 signing seed. */
  signature_algorithm: string | null;
  signature: string | null;
  signing_public_key: string | null;
}

/** Requires the Admin role on the project; the API returns 403 otherwise. */
export async function listAuditLogs(
  token: string,
  projectId: string,
  limit = 100
): Promise<AuditLogEntry[]> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/audit-logs?limit=${limit}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw await failure(res, 'could not load the audit log');
  return res.json();
}

export async function verifyAuditLog(
  token: string,
  projectId: string,
  logId: string
): Promise<{ valid: boolean; reason: string | null }> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/audit-logs/${logId}/verify`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw await failure(res, 'could not verify that entry');
  return res.json();
}


// Folders
//
// Organisational metadata only. Names and paths are stored in plaintext, like
// environment names — there is nothing secret about "database" as a folder name,
// and the values inside stay end-to-end encrypted regardless.

export interface Folder {
  id: string;
  project_id: string;
  environment_id: string;
  name: string;
  path: string;
}

export async function listFolders(
  token: string,
  projectId: string,
  environmentId: string
): Promise<Folder[]> {
  const res = await fetch(
    `${API_URL}/projects/${projectId}/folders?environment_id=${environmentId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw await failure(res, 'could not load folders');
  return res.json();
}

export async function createFolder(
  token: string,
  projectId: string,
  environmentId: string,
  name: string,
  path: string
): Promise<Folder> {
  const res = await fetch(`${API_URL}/projects/${projectId}/folders`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ environment_id: environmentId, name, path }),
  });
  if (!res.ok) throw await failure(res, 'could not create the folder');
  return res.json();
}

export async function deleteFolder(
  token: string,
  projectId: string,
  folderId: string
): Promise<void> {
  const res = await fetch(`${API_URL}/projects/${projectId}/folders/${folderId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw await failure(res, 'could not delete the folder');
}

// Imports
//
// A link saying "this scope also pulls in that one". The server stores only the
// link; the client fetches both scopes and merges them locally, so inheritance
// costs the server no visibility into any value.

export interface SecretImport {
  id: string;
  project_id: string;
  environment_id: string;
  folder_id: string | null;
  source_environment_id: string;
  source_folder_id: string | null;
  position: number;
}

export async function listImports(
  token: string,
  projectId: string,
  environmentId: string,
  folderId?: string | null
): Promise<SecretImport[]> {
  const query = new URLSearchParams({ environment_id: environmentId });
  if (folderId) query.set('folder_id', folderId);
  const res = await fetch(`${API_URL}/projects/${projectId}/imports?${query}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw await failure(res, 'could not load imports');
  return res.json();
}

export async function createImport(
  token: string,
  projectId: string,
  environmentId: string,
  sourceEnvironmentId: string,
  folderId?: string | null,
  sourceFolderId?: string | null
): Promise<SecretImport> {
  const res = await fetch(`${API_URL}/projects/${projectId}/imports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({
      environment_id: environmentId,
      folder_id: folderId ?? null,
      source_environment_id: sourceEnvironmentId,
      source_folder_id: sourceFolderId ?? null,
      position: 0,
    }),
  });
  if (!res.ok) throw await failure(res, 'could not create the import');
  return res.json();
}

export async function deleteImport(
  token: string,
  projectId: string,
  importId: string
): Promise<void> {
  const res = await fetch(`${API_URL}/projects/${projectId}/imports/${importId}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw await failure(res, 'could not delete the import');
}
